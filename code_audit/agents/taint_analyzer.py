"""Taint analyzer agent — LLM-driven taint analysis for SQLI, RCE, XXE, SSRF.

Re-implements the core taint analysis approach from Pecker as a native
LLM agent within the wukong framework.  Instead of invoking Pecker as an
external subprocess, this agent uses the LLM to:

1. Locate dangerous sinks in code reachable from web entry points
2. Trace taint (user input) backward from sink to source
3. Verify findings with multi-judge checks (sink_check, sanitizer_check,
   input_check, taint_check, etc.)

Layer 1 agent, depends on ``route_mapper``.
Produces ``{"findings": [Finding...]}``.
"""

from __future__ import annotations

import json
import logging
import os

from ..config import AuditConfig
from ..tools.registry import ToolRegistry
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
# System prompt
# ---------------------------------------------------------------------------

TAINT_ANALYZER_PROMPT = """\
You are an expert security researcher specializing in taint analysis for \
vulnerability detection. Your task is to perform deep taint analysis on a \
codebase, tracing user-controlled input from web entry points (sources) to \
dangerous function calls (sinks) to find real, exploitable vulnerabilities.

## Target Project
{project_path}

## Output Directory
{output_dir}

## Routes discovered by route_mapper
```json
{routes_json}
```

## Known Dangerous Sinks

{sqli_sinks}

{rce_sinks}

{xxe_sinks}

{ssrf_sinks}

## Analysis Methodology

You MUST follow this systematic 4-phase approach:

### Phase 1: Identify Entry Points and Locate Sinks

For each route/entry point discovered by route_mapper:
1. Use `read_file` to read the handler method for each route
2. Use `grep_content` to search for dangerous sink patterns in the codebase:
   - SQL sinks: grep for patterns like `executeQuery|executeUpdate|createQuery|\\.query\\(|\\$\\{{|\\.execute\\(|JdbcTemplate|createNativeQuery`
   - RCE sinks: grep for `Runtime\\..*exec|ProcessBuilder|ScriptEngine\\.eval`
   - XXE sinks: grep for `DocumentBuilder|SAXReader|XMLInputFactory|SAXParser|SAXBuilder|Unmarshaller|Transformer\\.transform|DocumentHelper`
   - SSRF sinks: grep for `URL\\(|openConnection|HttpClient|RestTemplate|WebClient|OkHttp`
3. For MyBatis projects, search XML mapper files: grep for `\\$\\{{` in xml files
4. Read each file containing a sink to understand the full context

IMPORTANT: Always pass `path="{project_path}"` to grep_content and glob_files.

### Phase 2: Trace Taint from Source to Sink

For each sink found in Phase 1:
1. Read the method containing the sink call
2. Identify the parameters that flow into the dangerous function
3. Trace backward through the call chain:
   a. Does the parameter come from the method's own parameters?
   b. If yes, find all callers of this method (use grep_content to search for \
method name invocations)
   c. Read each caller and check if the argument passed comes from user input
   d. Continue tracing up to 4 levels deep
4. For each level, check:
   - Is the parameter a numeric type (int, long, boolean)? If so, it cannot \
carry SQL injection taint — skip it
   - Is the parameter sanitized/filtered before being passed?
   - Does the parameter originate from HTTP request parameters, headers, \
body, or path variables?

### Phase 3: Multi-Judge Verification

For each potential vulnerability found in Phase 2, apply ALL relevant checks:

**For SQLI vulnerabilities:**
1. sink_check: {sqli_sink_check}
2. sanitizer_check: {sqli_sanitizer_check}
3. input_check: {sqli_input_check}
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

### Phase 4: Report Findings

Submit findings using submit_findings with the result_json parameter.

If results are large, write to file first:
write_file("{output_dir}/taint-findings.json", '<complete JSON>')
submit_findings(file_path="{output_dir}/taint-findings.json")

Each finding MUST have this structure:
{{
  "id": "TAINT-001",
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

Use ID prefix TAINT-xxx for all findings.

### Severity Guidelines
- **critical**: Direct SQL injection, RCE, or XXE with no sanitization, \
reachable from unauthenticated endpoints
- **high**: Same as critical but behind authentication, or with partial \
mitigation that can be bypassed
- **medium**: Indirect taint flow, requires specific conditions to exploit
- **low**: Theoretical vulnerability, significant mitigation in place

### Key Analysis Principles
1. Do NOT guess — read the actual code using read_file and grep_content
2. Trace the COMPLETE path from user input to sink
3. Check for sanitization at EVERY hop in the call chain
4. For MyBatis: #{{param}} is safe (parameterized), ${{param}} is unsafe (interpolated)
5. Numeric type parameters (int, long, Integer, Long) cannot carry string \
injection payloads
6. Framework-level ORM methods (JPA Criteria API, MyBatis-Plus eq/ne/like) \
are generally safe unless they accept raw SQL fragments
7. Consider BOTH direct routes AND internal/service methods called from routes
"""


@register_agent(
    name="taint_analyzer",
    layer=1,
    depends_on=["route_mapper"],
    timeout=1800,
    description="LLM-driven taint analysis for SQLI, RCE, XXE, SSRF vulnerabilities",
)
async def run_taint_analyzer(config: AuditConfig, inputs: dict) -> dict:
    """Execute taint analysis using LLM-driven source-to-sink tracing."""
    os.makedirs(config.output_dir, exist_ok=True)

    routes_data = inputs.get("route_mapper", {})
    routes_json = json.dumps(routes_data.get("routes", []), indent=2)

    client = create_llm_client(config.provider, config.api_key, config.base_url)

    registry = ToolRegistry.for_llm_agent()

    prompt = TAINT_ANALYZER_PROMPT.format(
        project_path=config.project_path,
        output_dir=config.output_dir,
        routes_json=routes_json,
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
        name="taint_analyzer",
        max_turns=config.agent_max_turns or 80,
        provider=config.provider,
    )

    result = await agent.run(
        f"Perform taint analysis on the project at {config.project_path}. "
        f"There are {len(routes_data.get('routes', []))} routes discovered. "
        f"Search for SQLI, RCE, XXE, and SSRF sinks, trace taint from user "
        f"input sources to those sinks, and verify each finding with "
        f"multi-judge checks. Report only confirmed vulnerabilities."
    )

    # Normalise output
    if "findings" not in result:
        if isinstance(result.get("data"), dict):
            result["findings"] = result["data"].get("findings", [])
        else:
            result["findings"] = []

    logger.info(
        "[taint_analyzer] %d findings",
        len(result.get("findings", [])),
    )
    return result
