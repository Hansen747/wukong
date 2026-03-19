"""Taint analyzer agent — LLM-driven taint analysis for SQLI, RCE, XXE, SSRF.

Re-implements the core taint analysis approach from Pecker as a native
LLM agent within the wukong framework.  Instead of invoking Pecker as an
external subprocess, this agent uses the LLM to perform **forward tracing**
from web entry points (sources) toward dangerous function calls (sinks):

1. Start from web entry points discovered by route_mapper
2. At each method: check if it contains a dangerous sink, AND identify
   sub-functions worth tracing deeper (the "next_call" step)
3. Recursively trace into sub-functions up to a configurable depth
4. When a sink is found, verify with multi-judge checks (sink_check,
   sanitizer_check, input_check, taint_check, etc.)

This mirrors Pecker's producer/consumer architecture where each method
is both analysed for sinks and expanded for deeper call tracing.

**Architecture (v2 — route-group parallelism):**

The coordinator splits routes into groups of ``config.taint_group_size``
(default 10), pre-scans the codebase for global sink patterns (zero LLM
cost), then launches independent ``AuditAgent`` sessions for each group
via ``asyncio.gather`` with a semaphore of ``config.taint_max_concurrent``.

Each group agent receives:
  - Only its subset of routes (reduced context)
  - Pre-scanned global sink locations (grep results)
  - The full system prompt with analysis methodology

Findings from all groups are merged and deduplicated at the end.

Layer 1 agent, depends on ``route_mapper``.
Produces ``{"findings": [Finding...]}``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from ..config import AuditConfig
from ..tools.registry import ToolRegistry
from ..tools.file_tools import grep_content as grep_content_fn
from ..tools.code_resolver import create_resolver
from .base import AuditAgent, create_llm_client
from .registry import register_agent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Embedded sink patterns (derived from Pecker sink definitions)
# ---------------------------------------------------------------------------

SQLI_SINKS = """
## SQL Injection Sinks (Java)
- java.sql.Statement: executeQuery, executeUpdate, addBatch, executeLargeUpdate
- java.sql.Connection: prepareStatement, prepareCall, nativeSQL
- javax.persistence.EntityManager: createQuery, createNativeQuery
- JdbcTemplate: batchUpdate, execute, update, queryForList, queryForObject, query*
- Hibernate Session/SharedSessionContract: createQuery, createSQLQuery, createNativeQuery
- MyBatis XML mapper: ${...} patterns (dollar-sign interpolation, NOT #{...})
- InfluxDB: query
- PageHelper: orderBy, setOrderBy
- Ebean: createSqlQuery, createSqlUpdate
- ClickHouse DataSource constructor
- Any raw SQL string concatenation with + operator
- String.format() used to build SQL
"""

RCE_SINKS = """
## Remote Code Execution Sinks (Java)
- java.lang.Runtime: exec()
- java.lang.ProcessBuilder: constructor, start()
- javax.script.ScriptEngine: eval()
- Spring SpEL: Expression.getValue(), ExpressionParser.parseExpression()
- Server-side template injection (Velocity, FreeMarker, Thymeleaf with user input)
- Reflection: Class.forName() + Method.invoke() with user-controlled class/method names
"""

XXE_SINKS = """
## XML External Entity (XXE) Sinks (Java)
- org.dom4j.DocumentHelper: parseText
- org.dom4j.io.SAXReader: read
- DocumentBuilder: parse
- XMLInputFactory: createXMLStreamReader
- SAXParser: parse
- SAXBuilder/SAXEngine: build
- javax.xml.transform.Transformer: transform
- XPathExpression: evaluate
- javax.xml.bind.Unmarshaller: unmarshal
- XMLReader: parse
- Digester: parse, asyncParse
- javax.xml.validation.Validator: validate
- javax.xml.validation.SchemaFactory: newSchema
- org.apache.poi.xssf.extractor.XSSFExportToXml: exportToXML
- Any XML parser WITHOUT explicit disabling of external entities
  (http://apache.org/xml/features/disallow-doctype-decl = true)
"""

SSRF_SINKS = """
## Server-Side Request Forgery (SSRF) Sinks (Java)
- java.net.URL: openConnection, openStream
- java.net.HttpURLConnection: connect
- org.apache.http.client.HttpClient: execute
- RestTemplate: getForObject, postForObject, exchange
- WebClient: get, post, put, delete
- OkHttp: newCall
- Any HTTP client where the URL is constructed from user input
"""

# ---------------------------------------------------------------------------
# Multi-judge verification prompts (adapted from Pecker)
# ---------------------------------------------------------------------------

MULTI_JUDGE_CHECKS = {
    "sqli": {
        "sink_check": (
            "Analyze the code and determine: Are the SQL queries constructed using "
            "ONLY parameterized queries (PreparedStatement with ?, MyBatis #{}, "
            "JPA :param)? If ALL SQL is parameterized -> safe (no vuln). "
            "If ANY SQL uses string concatenation (+), String.format(), "
            "MyBatis ${}, or dynamic table/column names -> unsafe (vuln exists). "
            "Return True if safe (no vulnerability), False if unsafe."
        ),
        "sanitizer_check": (
            "Analyze the code for SQL injection sanitization. Check if ALL "
            "user-controlled variables that reach SQL queries are validated via: "
            "whitelist validation, enum constraints, strict regex, or type casting "
            "to numeric types. Return True if effective sanitization exists for "
            "ALL risky variables, False otherwise."
        ),
        "input_check": (
            "Determine if the route/endpoint method receives external user input. "
            "If it does NOT receive user input, return True (safe). "
            "If ALL user input parameters are numeric types (int, long, boolean, "
            "float, double, Integer, Long), return True (safe). "
            "If ANY parameter is a non-numeric type (String, Object, Map, etc.), "
            "return False (potentially unsafe)."
        ),
        "taint_check": (
            "Trace the flow of user input through the code. Does any non-numeric "
            "user-controlled parameter flow into a SQL sink (directly or through "
            "intermediate method calls)? Consider parameter passing, field access, "
            "and method chaining. Return True if taint does NOT reach the sink "
            "(safe), False if it does reach the sink (vulnerable)."
        ),
    },
    "rce": {
        "sink_check": (
            "Determine if the code calls command execution functions: "
            "Runtime.getRuntime().exec(), ProcessBuilder, or third-party "
            "command execution utilities (e.g., RuntimeUtil.exec()). "
            "If such functions are called, return False (dangerous sink exists). "
            "Otherwise return True (no dangerous sink)."
        ),
        "input_check": (
            "Determine if the route/endpoint method receives external user input. "
            "If no user input is received, return True (safe). "
            "If ALL inputs are numeric types, return True (safe). "
            "Otherwise return False."
        ),
        "sanitizer_check": (
            "Check if there are authorization functions, validation logic, or "
            "whitelist/blacklist checks that would prevent malicious command "
            "injection. If strict validation exists, return True. "
            "If only simple null checks or no validation, return False."
        ),
        "taint_check": (
            "Trace user input flow: does any user-controlled parameter reach "
            "the command execution sink? Consider direct and indirect flows "
            "(through method calls, string concatenation, etc.). "
            "Return True if taint does NOT reach the sink, False if it does."
        ),
    },
    "xxe": {
        "sink_check": (
            "Check if the code uses known XXE-vulnerable XML parsing libraries: "
            "DocumentBuilderFactory, SAXParserFactory, DOM4J, XMLInputFactory, "
            "TransformerFactory, Validator, SchemaFactory, SAXReader, SAXBuilder, "
            "Unmarshaller, XPathExpression, XMLDecoder. "
            "If such a library is used, return False (dangerous sink). "
            "Otherwise return True."
        ),
        "feature_check": (
            "Check if the XML parser has explicit security features configured: "
            "- disallow-doctype-decl = true "
            "- external-general-entities = false "
            "- external-parameter-entities = false "
            "If security features are properly configured, return True (safe). "
            "Otherwise return False."
        ),
        "input_check": (
            "Determine if the XML content being parsed comes from user input "
            "(HTTP request body, uploaded file, user-provided URL). "
            "If the XML is from a trusted internal source only, return True (safe). "
            "If user can control the XML content, return False."
        ),
        "taint_check": (
            "Trace whether user-controlled XML data reaches the XML parsing sink. "
            "Return True if user input does NOT reach the parser, False if it does."
        ),
    },
    "ssrf": {
        "sink_check": (
            "Check if the code makes HTTP/network requests using: "
            "URL.openConnection(), HttpURLConnection, HttpClient, RestTemplate, "
            "WebClient, OkHttp, or similar. "
            "If such functions are used, return False. Otherwise return True."
        ),
        "input_check": (
            "Determine if the URL/host/port used in the network request comes "
            "from user input. If the URL is entirely hardcoded or from trusted "
            "config, return True (safe). If user can influence the URL, return False."
        ),
        "sanitizer_check": (
            "Check if there is URL validation: domain whitelist, IP blacklist "
            "(blocking 127.0.0.1, 169.254.x.x, 10.x.x.x, etc.), protocol "
            "restriction (only http/https). If robust validation exists, "
            "return True. Otherwise return False."
        ),
        "taint_check": (
            "Trace user input flow to the network request sink. Does user input "
            "reach the URL construction? Return True if not, False if yes."
        ),
    },
}

# ---------------------------------------------------------------------------
# Sink grep patterns for pre-scanning (zero LLM cost)
# ---------------------------------------------------------------------------

SINK_GREP_PATTERNS = {
    "sqli": r"executeQuery|executeUpdate|createQuery|\.query\(|\$\{|\.execute\(|JdbcTemplate|createNativeQuery|prepareStatement|prepareCall|addBatch|nativeSQL|createSQLQuery|queryForList|queryForObject|batchUpdate|orderBy|setOrderBy|createSqlQuery|createSqlUpdate",
    "rce": r"Runtime\..*exec|ProcessBuilder|ScriptEngine\.eval|Expression\.getValue|parseExpression|Class\.forName.*invoke",
    "xxe": r"DocumentBuilder|SAXReader|XMLInputFactory|SAXParser|SAXBuilder|Unmarshaller|Transformer\.transform|DocumentHelper|XMLReader|Digester|SchemaFactory|XSSFExportToXml|XMLDecoder",
    "ssrf": r"URL\(|openConnection|HttpClient|RestTemplate|WebClient|OkHttp|openStream|HttpURLConnection",
    "mybatis_dollar": r"\$\{",
}

# ---------------------------------------------------------------------------
# System prompt template for group agents
# ---------------------------------------------------------------------------

GROUP_AGENT_PROMPT = """\
You are an expert security researcher specializing in taint analysis for \
vulnerability detection. Your task is to perform deep taint analysis on a \
codebase, tracing user-controlled input from web entry points (sources) to \
dangerous function calls (sinks) to find real, exploitable vulnerabilities.

## Target Project
{project_path}

## Output Directory
{output_dir}

## Your Assigned Routes (Group {group_id})
You are responsible for analyzing ONLY these {route_count} routes:
```json
{routes_json}
```

## Pre-Scanned Sink Locations (from grep — zero LLM cost)
The following files contain potential dangerous sink patterns. Use this \
to prioritize your analysis — if a call chain leads into one of these \
files, it is more likely to contain a real vulnerability.

{global_sinks_summary}

## Known Dangerous Sinks

{sqli_sinks}

{rce_sinks}

{xxe_sinks}

{ssrf_sinks}

## Analysis Methodology

You MUST follow this systematic approach, which mirrors Pecker's \
forward-tracing producer/consumer architecture. The key insight is that \
you start from web entry points (sources) and trace FORWARD through the \
call graph toward dangerous sinks — NOT backward from sinks to sources.

You act as both a "sink finder" and a "next-call identifier" at each \
method you analyse. Think of yourself as processing a work queue: you \
read a method, check it for sinks, then decide which sub-functions to \
trace deeper.

### Phase 1: Read Your Entry Points

1. Use `read_file` to read the handler method for each of your assigned \
routes. These handlers are your **initial work queue**.
2. Cross-reference with the pre-scanned sink locations above to know \
which files/classes are worth deeper investigation.

IMPORTANT: Always pass `path="{project_path}"` to grep_content and glob_files.

### Available Code Resolution Tools

In addition to read_file, grep_content, glob_files, and write_file, you have \
these specialized code resolution tools:
- **find_definition(symbol, context_file?)**: Find where a method/class is defined
- **find_references(symbol, context_file?)**: Find all references to a symbol
- **extract_function_calls(file_path, method_name)**: List all function calls in a method \
(with internal/external classification — focus on "internal" calls for next-call expansion)
- **get_type_info(symbol, context_file)**: Check if a variable is numeric/string/collection

Use these tools to efficiently trace call chains instead of manually grepping.

### Phase 2: Forward Tracing — Process Each Method (Sink Check + Next-Call)

Process each method from your work queue. For each method, perform TWO tasks:

**Task A — Sink Check ("first_sink_chat" equivalent):**
1. Read the method's source code (with imports, fields, and class context)
2. Pre-filter: does this method contain ANY calls to known sink functions \
listed in the sink patterns above? If not, skip to Task B.
3. If potential sinks exist, determine:
   - What type of vulnerability? (SQLI / RCE / XXE / SSRF)
   - Which specific function call is the sink?
   - What data flows into the sink? Is it user-controlled?
   - Confidence score (0-10)
4. If confidence > 0 and a real sink is found, record it as a candidate \
finding and proceed to Phase 3 (Multi-Judge Verification) for this finding.

**Task B — Next-Call Expansion ("second_vulnerability_chat" equivalent):**
Regardless of whether a sink was found, analyse the current method for \
interesting sub-function calls worth tracing deeper:
1. Identify calls to project-internal methods (not stdlib/framework methods)
2. For each interesting callee:
   a. Use `grep_content` to find the callee's definition in the codebase
   b. Use `read_file` to read its source code
   c. Add it to your work queue for further analysis
3. Continue tracing into sub-functions up to **6 levels deep** from the \
original entry point handler
4. **Duplicate detection**: Do NOT re-analyse a method you have already \
analysed in the current call chain (track by file + method name)

**Priority guidance for next-call expansion:**
- Prioritise methods that receive string/object parameters from the parent
- Skip methods that only receive numeric primitives (int, long, boolean)
- Skip standard library and framework utility methods
- Focus on DAO/repository methods, service methods, and any method that \
constructs SQL, executes commands, parses XML, or makes HTTP requests

### Phase 3: Multi-Judge Verification

For each potential vulnerability found in Phase 2, apply ALL relevant \
checks in order. This is an early-termination pipeline — if ANY check \
returns True (safe), STOP and discard the finding as a false positive.

**For SQLI vulnerabilities (Java):**
1. sink_check: {sqli_sink_check}
2. input_check: {sqli_input_check}
3. sanitizer_check: {sqli_sanitizer_check}
4. taint_check: {sqli_taint_check}

**For RCE vulnerabilities:**
1. sink_check: {rce_sink_check}
2. input_check: {rce_input_check}
3. sanitizer_check: {rce_sanitizer_check}
4. taint_check: {rce_taint_check}

**For XXE vulnerabilities:**
1. sink_check: {xxe_sink_check}
2. feature_check: {xxe_feature_check}
3. input_check: {xxe_input_check}
4. taint_check: {xxe_taint_check}

**For SSRF vulnerabilities:**
1. sink_check: {ssrf_sink_check}
2. input_check: {ssrf_input_check}
3. sanitizer_check: {ssrf_sanitizer_check}
4. taint_check: {ssrf_taint_check}

A finding is CONFIRMED only if ALL checks return False (unsafe). If ANY \
check returns True (safe), the finding is a false positive — discard it.

### Phase 4: Backward Taint Verification for XML/MyBatis Sinks (Optional)

If a confirmed finding involves a MyBatis XML mapper with `${{...}}` \
interpolation (dynamic SQL):
1. Extract the taint variables from the `${{...}}` patterns in the XML
2. Map each taint variable back to the mapper interface method's parameters
3. Walk BACKWARD through the accumulated call chain to verify that user \
input actually reaches the taint variable at each hop:
   - Check parameter types: numeric types (int, long, Integer, Long, etc.) \
cannot carry injection payloads → mark as safe
   - Check for type sensitivity: Map (key-sensitive), class (field-sensitive), \
List (index-sensitive) — the specific key/field/index must match
   - Check for sanitization at each hop
4. If backward verification shows taint does NOT propagate → override the \
multi-judge result and discard the finding

This backward step is ONLY needed for XML/MyBatis sinks. For direct Java \
sinks, the forward-tracing + multi-judge checks are sufficient.

### Phase 5: Report Findings

Submit findings using submit_findings with the result_json parameter.

If results are large, write to file first:
write_file("{output_dir}/taint-findings-group-{group_id}.json", '<complete JSON>')
submit_findings(file_path="{output_dir}/taint-findings-group-{group_id}.json")

Each finding MUST have this structure:
{{
  "id": "TAINT-{group_id}-001",
  "type": "sqli" | "rce" | "xxe" | "ssrf",
  "severity": "critical" | "high" | "medium" | "low",
  "title": "SQL Injection in UserController.search() via 'keyword' parameter",
  "file_path": "/absolute/path/to/File.java",
  "line_number": 42,
  "source": "request.queryParams('keyword')",
  "sink": "statement.executeQuery(sql)",
  "call_chain": [
    {{"method": "search", "file": "UserController.java", "line": 15, \
"code": "String keyword = request.queryParams(\\"keyword\\")"}},
    {{"method": "findByKeyword", "file": "UserDao.java", "line": 42, \
"code": "stmt.executeQuery(\\"SELECT * FROM users WHERE name = '\\" + keyword + \\"'\\")"}}
  ],
  "code_snippet": "the vulnerable code with context",
  "description": "Detailed explanation of the vulnerability, how user input \
reaches the sink, and why existing mitigations are insufficient.",
  "poc": "curl 'http://target/search?keyword=admin%27+OR+1%3D1--'",
  "remediation": "Use PreparedStatement with parameterized queries."
}}

Use ID prefix TAINT-{group_id}-xxx for all findings.

If you find NO vulnerabilities after thorough analysis, submit:
{{"findings": []}}

### Severity Guidelines
- **critical**: Direct SQL injection, RCE, or XXE with no sanitization, \
reachable from unauthenticated endpoints
- **high**: Same as critical but behind authentication, or with partial \
mitigation that can be bypassed
- **medium**: Indirect taint flow, requires specific conditions to exploit
- **low**: Theoretical vulnerability, significant mitigation in place

### Key Analysis Principles
1. Do NOT guess — read the actual code using read_file and grep_content
2. FORWARD trace: start from entry-point handlers, trace into callees, \
check each method for sinks. Do NOT start from sinks and trace backward.
3. At each method, always do BOTH: (a) check for sinks, (b) identify \
sub-functions to trace next — even if no sink is found in the current method
4. Check for sanitization at EVERY hop in the call chain
5. For MyBatis: #{{param}} is safe (parameterized), ${{param}} is unsafe (interpolated)
6. Numeric type parameters (int, long, Integer, Long) cannot carry string \
injection payloads
7. Framework-level ORM methods (JPA Criteria API, MyBatis-Plus eq/ne/like) \
are generally safe unless they accept raw SQL fragments
8. Track the full call chain from entry point to current method — this is \
needed for multi-judge verification and for the final finding report
9. Respect depth limits (max 6 levels) and avoid re-analysing methods \
already visited in the current call chain
"""


# ---------------------------------------------------------------------------
# Pre-scan: grep for global sink locations (zero LLM cost)
# ---------------------------------------------------------------------------

def _scan_global_sinks(project_path: str) -> dict[str, str]:
    """Grep the codebase for known sink patterns — returns category→results.

    This is a zero-LLM-cost pre-scan that helps each group agent know
    which files contain potential sinks, so it can prioritize its analysis.
    """
    results: dict[str, str] = {}

    for category, pattern in SINK_GREP_PATTERNS.items():
        file_type = "xml" if category == "mybatis_dollar" else "java"
        try:
            grep_result = grep_content_fn(
                pattern=pattern,
                path=project_path,
                file_type=file_type,
            )
            # Only include non-empty results
            if grep_result and "No matches found" not in grep_result:
                results[category] = grep_result
                logger.info(
                    "[taint_analyzer] pre-scan %s: %d matches",
                    category,
                    grep_result.count("\n") + 1,
                )
            else:
                logger.debug("[taint_analyzer] pre-scan %s: no matches", category)
        except Exception as exc:
            logger.warning("[taint_analyzer] pre-scan %s failed: %s", category, exc)

    return results


def _format_sink_summary(global_sinks: dict[str, str]) -> str:
    """Format pre-scanned sink results into a concise summary for the prompt."""
    if not global_sinks:
        return "(No sink patterns found in codebase via grep pre-scan)"

    parts: list[str] = []
    for category, grep_output in global_sinks.items():
        lines = grep_output.strip().split("\n")
        # Limit to 50 lines per category to keep prompt manageable
        if len(lines) > 50:
            display = "\n".join(lines[:50])
            display += f"\n... ({len(lines) - 50} more matches)"
        else:
            display = grep_output.strip()
        parts.append(f"### {category.upper()} sink locations\n```\n{display}\n```")

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Group agent runner
# ---------------------------------------------------------------------------

async def _analyze_route_group(
    config: AuditConfig,
    group_id: int,
    routes: list[dict],
    global_sinks: dict[str, str],
    semaphore: asyncio.Semaphore,
    output_dir: str,
) -> dict:
    """Run taint analysis on a single group of routes.

    Creates an independent AuditAgent session with its own context,
    containing only its subset of routes + global sink scan results.
    """
    async with semaphore:
        t0 = time.monotonic()
        logger.info(
            "[taint_analyzer] group %d starting — %d routes",
            group_id,
            len(routes),
        )

        client = create_llm_client(config.provider, config.api_key, config.base_url)

        # Create code resolver based on config
        resolver = create_resolver(
            project_path=config.project_path,
            resolver_type=config.resolver,
            lsp_cmd=config.lsp_cmd,
        )
        registry = ToolRegistry.for_llm_agent(resolver=resolver)

        prompt = GROUP_AGENT_PROMPT.format(
            project_path=config.project_path,
            output_dir=output_dir,
            group_id=group_id,
            route_count=len(routes),
            routes_json=json.dumps(routes, indent=2),
            global_sinks_summary=_format_sink_summary(global_sinks),
            sqli_sinks=SQLI_SINKS,
            rce_sinks=RCE_SINKS,
            xxe_sinks=XXE_SINKS,
            ssrf_sinks=SSRF_SINKS,
            sqli_sink_check=MULTI_JUDGE_CHECKS["sqli"]["sink_check"],
            sqli_sanitizer_check=MULTI_JUDGE_CHECKS["sqli"]["sanitizer_check"],
            sqli_input_check=MULTI_JUDGE_CHECKS["sqli"]["input_check"],
            sqli_taint_check=MULTI_JUDGE_CHECKS["sqli"]["taint_check"],
            rce_sink_check=MULTI_JUDGE_CHECKS["rce"]["sink_check"],
            rce_input_check=MULTI_JUDGE_CHECKS["rce"]["input_check"],
            rce_sanitizer_check=MULTI_JUDGE_CHECKS["rce"]["sanitizer_check"],
            rce_taint_check=MULTI_JUDGE_CHECKS["rce"]["taint_check"],
            xxe_sink_check=MULTI_JUDGE_CHECKS["xxe"]["sink_check"],
            xxe_feature_check=MULTI_JUDGE_CHECKS["xxe"]["feature_check"],
            xxe_input_check=MULTI_JUDGE_CHECKS["xxe"]["input_check"],
            xxe_taint_check=MULTI_JUDGE_CHECKS["xxe"]["taint_check"],
            ssrf_sink_check=MULTI_JUDGE_CHECKS["ssrf"]["sink_check"],
            ssrf_input_check=MULTI_JUDGE_CHECKS["ssrf"]["input_check"],
            ssrf_sanitizer_check=MULTI_JUDGE_CHECKS["ssrf"]["sanitizer_check"],
            ssrf_taint_check=MULTI_JUDGE_CHECKS["ssrf"]["taint_check"],
        )

        agent = AuditAgent(
            client=client,
            model=config.model,
            system_prompt=prompt,
            tool_registry=registry,
            name=f"taint_analyzer_g{group_id}",
            max_turns=config.agent_max_turns or 80,
            provider=config.provider,
            context_window_turns=20,  # sliding window: keep last 20 turns
        )

        result = await agent.run(
            f"Perform forward-tracing taint analysis on your assigned group "
            f"of {len(routes)} routes in the project at {config.project_path}. "
            f"Start from each route handler, trace forward into sub-functions "
            f"(up to 6 levels deep), check each method for SQLI/RCE/XXE/SSRF "
            f"sinks, and verify each finding with multi-judge checks. "
            f"Report only confirmed vulnerabilities. "
            f"If you find NO vulnerabilities, submit {{\"findings\": []}}."
        )

        elapsed = time.monotonic() - t0
        findings = _extract_findings(result)
        logger.info(
            "[taint_analyzer] group %d finished in %.1fs — %d findings",
            group_id,
            elapsed,
            len(findings),
        )
        return {"group_id": group_id, "findings": findings, "elapsed": elapsed}


def _extract_findings(result: dict) -> list[dict]:
    """Extract findings list from an agent result dict."""
    if "findings" in result:
        findings = result["findings"]
        if isinstance(findings, list):
            return findings
    if isinstance(result.get("data"), dict):
        findings = result["data"].get("findings", [])
        if isinstance(findings, list):
            return findings
    return []


# ---------------------------------------------------------------------------
# Merge findings from all groups
# ---------------------------------------------------------------------------

def _merge_findings(group_results: list[dict | BaseException]) -> list[dict]:
    """Merge and deduplicate findings from all route groups.

    Deduplication is based on (file_path, line_number, type) to avoid
    reporting the same vulnerability from overlapping call chains.
    """
    all_findings: list[dict] = []
    seen: set[tuple] = set()

    for result in group_results:
        if isinstance(result, BaseException):
            logger.error("[taint_analyzer] group failed: %s", result)
            continue
        if not isinstance(result, dict):
            continue

        for finding in result.get("findings", []):
            # Dedup key: (file, line, type)
            key = (
                finding.get("file_path", ""),
                finding.get("line_number", 0),
                finding.get("type", ""),
            )
            if key in seen:
                logger.debug("[taint_analyzer] dedup: %s", key)
                continue
            seen.add(key)
            all_findings.append(finding)

    # Re-number IDs sequentially
    for idx, finding in enumerate(all_findings, start=1):
        finding["id"] = f"TAINT-{idx:03d}"

    return all_findings


# ---------------------------------------------------------------------------
# Coordinator: registered agent entry point
# ---------------------------------------------------------------------------

@register_agent(
    name="taint_analyzer",
    layer=1,
    depends_on=["route_mapper"],
    timeout=3600,  # increased for multi-group parallelism
    description="LLM-driven taint analysis for SQLI, RCE, XXE, SSRF vulnerabilities (route-group parallelism)",
)
async def run_taint_analyzer(config: AuditConfig, inputs: dict) -> dict:
    """Coordinator: split routes into groups and run parallel taint analysis.

    1. Extract routes from route_mapper output
    2. Pre-scan codebase for global sink patterns (zero LLM cost)
    3. Split routes into groups of config.taint_group_size
    4. Launch independent AuditAgent sessions per group via asyncio.gather
    5. Merge and deduplicate findings from all groups
    """
    output_dir = config.output_dir or "/tmp/audit"
    os.makedirs(output_dir, exist_ok=True)

    # 1. Extract routes
    routes_data = inputs.get("route_mapper", {})
    routes = routes_data.get("routes", [])

    if not routes:
        logger.warning("[taint_analyzer] no routes from route_mapper — skipping")
        return {"findings": []}

    logger.info("[taint_analyzer] %d routes to analyze", len(routes))

    # 2. Pre-scan for global sinks (zero LLM cost)
    t0 = time.monotonic()
    global_sinks = _scan_global_sinks(config.project_path)
    prescan_elapsed = time.monotonic() - t0
    logger.info(
        "[taint_analyzer] pre-scan completed in %.1fs — %d categories with matches",
        prescan_elapsed,
        len(global_sinks),
    )

    # 3. Split routes into groups
    group_size = config.taint_group_size
    groups: list[list[dict]] = [
        routes[i : i + group_size]
        for i in range(0, len(routes), group_size)
    ]
    logger.info(
        "[taint_analyzer] split into %d groups (size=%d, max_concurrent=%d)",
        len(groups),
        group_size,
        config.taint_max_concurrent,
    )

    # 4. Launch parallel analysis
    semaphore = asyncio.Semaphore(config.taint_max_concurrent)
    tasks = [
        _analyze_route_group(config, group_id, group, global_sinks, semaphore, output_dir)
        for group_id, group in enumerate(groups, start=1)
    ]
    group_results = await asyncio.gather(*tasks, return_exceptions=True)

    # 5. Merge findings
    findings = _merge_findings(list(group_results))

    # Log summary
    total_elapsed = time.monotonic() - t0
    successful_groups = sum(
        1 for r in group_results if isinstance(r, dict)
    )
    failed_groups = sum(
        1 for r in group_results if isinstance(r, BaseException)
    )
    logger.info(
        "[taint_analyzer] completed in %.1fs — %d groups (%d ok, %d failed), %d findings",
        total_elapsed,
        len(groups),
        successful_groups,
        failed_groups,
        len(findings),
    )

    # Write merged findings to output
    findings_path = os.path.join(output_dir, "taint-findings.json")
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump({"findings": findings}, f, indent=2, ensure_ascii=False)
    logger.info("[taint_analyzer] findings written to %s", findings_path)

    return {"findings": findings}
