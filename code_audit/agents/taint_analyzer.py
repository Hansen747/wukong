"""Taint analyzer agent — LLM-driven taint analysis for SQLI, RCE, XXE, SSRF, Path Traversal.

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
from ..prompts.multi_judge import FUNCTION_CHECK, MULTI_JUDGE_CHECK_ORDERS, MULTI_JUDGE_CHECKS
from ..prompts.sinks import (
    PATH_TRAVERSAL_SINKS,
    RCE_SINKS,
    SINK_GREP_PATTERNS,
    SQLI_SINKS,
    SSRF_SINKS,
    STRUCTURED_SINKS,
    XXE_SINKS,
)
from ..prompts.taint_analyzer import GROUP_AGENT_PROMPT
from ..tools.registry import ToolRegistry
from ..tools.file_tools import grep_content as grep_content_fn
from ..tools.code_resolver import create_resolver
from .base import AuditAgent, create_llm_client
from .registry import register_agent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Context compression summary factory — taint-analysis-aware
# ---------------------------------------------------------------------------

def _taint_compression_summary(dropped_msgs: list[dict]) -> str:
    """Generate a taint-analysis-aware summary of about-to-be-dropped messages.

    Scans the compressed messages to extract:
    - Files/symbols already analyzed via read_file / find_definition / etc.
    - Candidate vulnerability types (SQLI, RCE, XXE, SSRF) mentioned alongside
      analysis keywords (confidence, sink, finding, taint).

    The result is injected as the context-bridge so the LLM knows:
    (1) which files/methods NOT to re-analyze, and
    (2) what tentative findings were identified before the window rolled forward.
    """
    visited_files: set[str] = set()
    vuln_types_seen: set[str] = set()

    _analysis_tools = {
        "read_file", "find_definition", "extract_function_calls", "find_references",
    }

    def _extract_tool_call(block: object) -> tuple[str, dict]:
        """Return (tool_name, input_args) from an Anthropic or OpenAI tool block."""
        if isinstance(block, dict):
            if block.get("type") == "tool_use":
                return block.get("name", ""), block.get("input") or {}
        else:
            # Anthropic SDK model object
            if getattr(block, "type", None) == "tool_use":
                return getattr(block, "name", ""), getattr(block, "input", {}) or {}
        return "", {}

    def _extract_text(block: object) -> str:
        """Return text content from a dict/SDK content block."""
        if isinstance(block, dict):
            return block.get("text", "") if block.get("type") == "text" else ""
        return getattr(block, "text", "") if getattr(block, "type", None) == "text" else ""

    def _record_file(fp: str) -> None:
        if not fp:
            return
        basename = fp.replace("\\", "/").split("/")[-1]
        # Accept filenames (have extension) or method signatures (have parenthesis)
        if "." in basename or "(" in basename:
            visited_files.add(basename)

    def _scan_for_vulns(text: str) -> None:
        tu = text.upper()
        # Only flag when analysis-context keywords are also present
        context_kw = {"CONFIDENCE", "SINK", "FINDING", "VULNERABILITY", "TAINT", "CONFIRMED"}
        if not any(kw in tu for kw in context_kw):
            return
        for vtype, keywords in (
            ("SQLI", {"SQLI", "SQL INJECTION"}),
            ("RCE", {"RCE", "REMOTE CODE EXECUTION", "COMMAND INJECTION"}),
            ("XXE", {"XXE", "XML EXTERNAL ENTITY"}),
            ("SSRF", {"SSRF", "SERVER-SIDE REQUEST FORGERY", "SERVER SIDE REQUEST FORGERY"}),
            ("PATH_TRAVERSAL", {"PATH TRAVERSAL", "DIRECTORY TRAVERSAL", "CWE-22", "PATH_TRAVERSAL"}),
        ):
            if any(kw in tu for kw in keywords):
                vuln_types_seen.add(vtype)

    for msg in dropped_msgs:
        role = msg.get("role", "")
        content = msg.get("content")

        if role != "assistant":
            continue

        # --- OpenAI format: tool_calls is a list of plain dicts ---
        for tc in (msg.get("tool_calls") or []):
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") or {}
            fname = fn.get("name", "")
            if fname in _analysis_tools:
                fargs_str = fn.get("arguments", "{}")
                try:
                    args = json.loads(fargs_str) if isinstance(fargs_str, str) else fargs_str
                except Exception:  # noqa: BLE001
                    args = {}
                _record_file(args.get("file_path") or args.get("symbol", ""))

        # OpenAI text content
        if isinstance(content, str) and content:
            _scan_for_vulns(content)

        # --- Anthropic format: content is a list of blocks (SDK objs or dicts) ---
        if isinstance(content, list):
            for block in content:
                fname, args = _extract_tool_call(block)
                if fname in _analysis_tools:
                    _record_file(args.get("file_path") or args.get("symbol", ""))
                text = _extract_text(block)
                if text:
                    _scan_for_vulns(text)

    # Build summary string
    n = len(dropped_msgs)
    parts: list[str] = [f"[Context compressed: {n} earlier messages removed."]

    if visited_files:
        preview = sorted(visited_files)[:20]
        extra = len(visited_files) - len(preview)
        files_str = ", ".join(preview)
        if extra > 0:
            files_str += f" (+{extra} more)"
        parts.append(f" Already-analyzed files: {files_str}.")

    if vuln_types_seen:
        parts.append(
            f" Tentative vulnerability types identified: {', '.join(sorted(vuln_types_seen))}."
        )

    parts.append(
        " Continue forward-tracing taint analysis on remaining unvisited routes/methods."
        " Do NOT re-read or re-analyze files already listed above."
        " Maintain call-depth counter (max 8 hops from entry point; +2 for MyBatis XML)."
        " Apply full multi-judge pipeline (all checks must return False) before confirming."
        " Track visited method signatures to avoid duplicate work.]"
    )

    return "".join(parts)


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


def _format_structured_sinks() -> str:
    """Format STRUCTURED_SINKS into a readable text for the prompt."""
    parts: list[str] = []
    for category, class_methods in STRUCTURED_SINKS.items():
        lines = [f"### {category.upper()}"]
        for class_name, methods in class_methods.items():
            methods_str = ", ".join(methods)
            lines.append(f"- {class_name}#{methods_str}")
        parts.append("\n".join(lines))
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
            structured_sinks_text=_format_structured_sinks(),
            sqli_sinks=SQLI_SINKS,
            rce_sinks=RCE_SINKS,
            xxe_sinks=XXE_SINKS,
            ssrf_sinks=SSRF_SINKS,
            path_traversal_sinks=PATH_TRAVERSAL_SINKS,
            sqli_sink_check=MULTI_JUDGE_CHECKS["sqli"]["sink_check"],
            sqli_xml_taint_num_check=MULTI_JUDGE_CHECKS["sqli"]["xml_taint_num_check"],
            sqli_sink_taint_fixed_check=MULTI_JUDGE_CHECKS["sqli"]["sink_taint_fixed_check"],
            sqli_sink_taint_exist_check=MULTI_JUDGE_CHECKS["sqli"]["sink_taint_exist_check"],
            sqli_sanitizer_check=MULTI_JUDGE_CHECKS["sqli"]["sanitizer_check"],
            sqli_taint_check=MULTI_JUDGE_CHECKS["sqli"]["taint_check"],
            rce_sink_check=MULTI_JUDGE_CHECKS["rce"]["sink_check"],
            rce_input_check=MULTI_JUDGE_CHECKS["rce"]["input_check"],
            rce_sanitizer_check=MULTI_JUDGE_CHECKS["rce"]["sanitizer_check"],
            rce_taint_check=MULTI_JUDGE_CHECKS["rce"]["taint_check"],
            xxe_sink_check=MULTI_JUDGE_CHECKS["xxe"]["sink_check"],
            xxe_input_check=MULTI_JUDGE_CHECKS["xxe"]["input_check"],
            xxe_feature_check=MULTI_JUDGE_CHECKS["xxe"]["feature_check"],
            xxe_taint_check=MULTI_JUDGE_CHECKS["xxe"]["taint_check"],
            ssrf_sink_check=MULTI_JUDGE_CHECKS["ssrf"]["sink_check"],
            ssrf_input_check=MULTI_JUDGE_CHECKS["ssrf"]["input_check"],
            ssrf_sanitizer_check=MULTI_JUDGE_CHECKS["ssrf"]["sanitizer_check"],
            ssrf_taint_check=MULTI_JUDGE_CHECKS["ssrf"]["taint_check"],
            pt_sink_check=MULTI_JUDGE_CHECKS["path_traversal"]["sink_check"],
            pt_input_check=MULTI_JUDGE_CHECKS["path_traversal"]["input_check"],
            pt_canonicalization_check=MULTI_JUDGE_CHECKS["path_traversal"]["canonicalization_check"],
            pt_sanitizer_check=MULTI_JUDGE_CHECKS["path_traversal"]["sanitizer_check"],
            pt_taint_check=MULTI_JUDGE_CHECKS["path_traversal"]["taint_check"],
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
            compression_summary_factory=_taint_compression_summary,
        )

        result = await agent.run(
            f"Perform forward-tracing taint analysis on your assigned group "
            f"of {len(routes)} routes in the project at {config.project_path}. "
            f"Start from each route handler, trace forward into sub-functions "
            f"(up to 8 levels deep), check each method for SQLI/RCE/XXE/SSRF/"
            f"Path Traversal sinks, and verify each finding with the full "
            f"multi-judge check pipeline (6 checks for Java SQLI, 5 checks for "
            f"Path Traversal, 4 checks for other types). "
            f"Include multi_judge_results and confidence_score in each finding. "
            f"Report only confirmed vulnerabilities (ALL checks return False). "
            f"Also check pom.xml/build.gradle for framework versions with known "
            f"CVEs in static file serving or path handling. "
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

    Deduplication uses two keys to catch duplicates:
    1. (file_path, line_number, type) — same sink location
    2. (sink_method, type) — same sink function name across files
       (e.g., different call chains reaching the same DAO method)
    """
    all_findings: list[dict] = []
    seen_location: set[tuple] = set()
    seen_sink: set[tuple] = set()

    for result in group_results:
        if isinstance(result, BaseException):
            logger.error("[taint_analyzer] group failed: %s", result)
            continue
        if not isinstance(result, dict):
            continue

        for finding in result.get("findings", []):
            # Dedup key 1: (file, line, type) — exact location
            loc_key = (
                finding.get("file_path", ""),
                finding.get("line_number", 0),
                finding.get("type", ""),
            )
            if loc_key in seen_location:
                logger.debug("[taint_analyzer] dedup (location): %s", loc_key)
                continue

            # Dedup key 2: (sink description, type) — same logical sink
            sink_key = (
                finding.get("sink", ""),
                finding.get("type", ""),
            )
            if sink_key and sink_key in seen_sink:
                logger.debug("[taint_analyzer] dedup (sink): %s", sink_key)
                continue

            seen_location.add(loc_key)
            if sink_key[0]:  # only track non-empty sinks
                seen_sink.add(sink_key)
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
    description="LLM-driven taint analysis for SQLI, RCE, XXE, SSRF, Path Traversal vulnerabilities (route-group parallelism)",
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
