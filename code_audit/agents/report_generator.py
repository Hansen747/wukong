"""Report generator — assembles the final audit report.

Layer 3 agent, depends on all upstream stages.
Pure template rendering — no LLM calls.
Produces ``{"report_path": str, "output_dir": str, "stats": dict}``.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from typing import Any

from ..config import AuditConfig
from .registry import register_agent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Markdown templates
# ---------------------------------------------------------------------------

REPORT_TEMPLATE = """\
# Security Audit Report

**Project**: `{project_path}`
**Date**: {date}
**Output**: `{output_dir}`

---

## Summary

| Metric | Count |
|--------|-------|
| Total routes discovered | {total_routes} |
| Total findings | {total_findings} |
| Confirmed vulnerabilities | {confirmed} |
| False positives | {false_positives} |
| Downgraded | {downgraded} |
| Needs review | {needs_review} |

### Severity distribution

| Severity | Count |
|----------|-------|
| Critical | {sev_critical} |
| High | {sev_high} |
| Medium | {sev_medium} |
| Low | {sev_low} |

### Vulnerability types

{type_table}

---

## Confirmed Vulnerabilities

{confirmed_section}

## Needs Review

{needs_review_section}

## Downgraded

{downgraded_section}

## False Positives

{false_positive_section}

---

## Routes

Total: {total_routes}

{routes_section}
"""

FINDING_TEMPLATE = """\
### {id}: {title}

- **Severity**: {severity}
- **Type**: {type}
- **File**: `{file_path}:{line_number}`
- **Source**: {source}
- **Sink**: {sink}

{description}

{call_chain_section}

{verification_section}

{poc_section}

{remediation_section}

---
"""


def _render_call_chain(chain: list) -> str:
    """Render a call chain as a markdown list."""
    if not chain:
        return ""
    lines = ["**Call chain:**"]
    for i, node in enumerate(chain):
        if isinstance(node, dict):
            lines.append(
                f"{i + 1}. `{node.get('method', '')}` "
                f"at `{node.get('file', '')}:{node.get('line', 0)}`"
            )
        else:
            lines.append(f"{i + 1}. {node}")
    return "\n".join(lines)


def _render_finding(finding: dict, verification: dict | None = None) -> str:
    """Render a single finding as Markdown."""
    call_chain_section = _render_call_chain(finding.get("call_chain", []))

    verification_section = ""
    if verification:
        status = verification.get("status", "unknown")
        reason = verification.get("reason", "")
        adj_sev = verification.get("adjusted_severity")
        verification_section = f"**Verification**: {status}"
        if adj_sev:
            verification_section += f" (severity adjusted to {adj_sev})"
        if reason:
            verification_section += f"\n\n> {reason}"

    poc_section = ""
    if finding.get("poc"):
        poc_section = f"**POC:**\n```http\n{finding['poc']}\n```"

    remediation_section = ""
    if finding.get("remediation"):
        remediation_section = f"**Remediation:** {finding['remediation']}"

    return FINDING_TEMPLATE.format(
        id=finding.get("id", "?"),
        title=finding.get("title", "Untitled"),
        severity=finding.get("severity", "unknown"),
        type=finding.get("type", "unknown"),
        file_path=finding.get("file_path", "?"),
        line_number=finding.get("line_number", 0),
        source=finding.get("source", "N/A"),
        sink=finding.get("sink", "N/A"),
        description=finding.get("description", ""),
        call_chain_section=call_chain_section,
        verification_section=verification_section,
        poc_section=poc_section,
        remediation_section=remediation_section,
    )


@register_agent(
    name="report_generator",
    layer=3,
    depends_on=[
        "vuln_verifier",
        "auth_auditor",
        "taint_analyzer",
        "hardcoded_auditor",
        "route_mapper",
    ],
    timeout=120,
    description="Assemble final audit report from all upstream data",
)
async def run_report_generator(config: AuditConfig, inputs: dict) -> dict:
    """Assemble the final audit report (pure template rendering)."""
    import datetime

    os.makedirs(config.output_dir, exist_ok=True)

    # ---- Collect upstream data ----
    routes = inputs.get("route_mapper", {}).get("routes", [])
    verifications = inputs.get("vuln_verifier", {}).get("verifications", [])

    all_findings: list[dict] = []
    for stage in ("auth_auditor", "taint_analyzer", "hardcoded_auditor"):
        stage_data = inputs.get(stage, {})
        if isinstance(stage_data, dict):
            all_findings.extend(stage_data.get("findings", []))

    # ---- Build verification map ----
    verification_map: dict[str, dict] = {}
    for v in verifications:
        fid = v.get("finding_id", "")
        if fid:
            verification_map[fid] = v

    # ---- Classify findings ----
    confirmed: list[dict] = []
    false_positives: list[dict] = []
    downgraded: list[dict] = []
    needs_review: list[dict] = []

    for f in all_findings:
        fid = f.get("id", "")
        v = verification_map.get(fid)
        if v:
            status = v.get("status", "needs_review")
            if status == "confirmed":
                confirmed.append(f)
            elif status == "false_positive":
                false_positives.append(f)
            elif status == "downgraded":
                downgraded.append(f)
            else:
                needs_review.append(f)
        else:
            # Not verified — treat as needs_review
            needs_review.append(f)

    # ---- Severity & type stats ----
    severity_counter: Counter = Counter()
    type_counter: Counter = Counter()
    for f in all_findings:
        v = verification_map.get(f.get("id", ""))
        if v and v.get("status") == "false_positive":
            continue  # exclude false positives from stats
        sev = f.get("severity", "unknown")
        if v and v.get("adjusted_severity"):
            sev = v["adjusted_severity"]
        severity_counter[sev] += 1
        type_counter[f.get("type", "unknown")] += 1

    # ---- Render type table ----
    type_lines = ["| Type | Count |", "|------|-------|"]
    for t, cnt in type_counter.most_common():
        type_lines.append(f"| {t} | {cnt} |")
    type_table = "\n".join(type_lines) if type_counter else "No vulnerabilities found."

    # ---- Render finding sections ----
    def render_section(findings: list[dict]) -> str:
        if not findings:
            return "_None_\n"
        parts = []
        for f in findings:
            v = verification_map.get(f.get("id", ""))
            parts.append(_render_finding(f, v))
        return "\n".join(parts)

    # ---- Render routes section ----
    route_lines = []
    for r in routes[:50]:  # Cap display at 50
        method = r.get("method", "?")
        path = r.get("path", "?")
        handler = r.get("handler_method", "?")
        route_lines.append(f"- `{method} {path}` → `{handler}`")
    if len(routes) > 50:
        route_lines.append(f"- ... and {len(routes) - 50} more")
    routes_section = "\n".join(route_lines) if route_lines else "_None discovered_"

    # ---- Render report ----
    report_md = REPORT_TEMPLATE.format(
        project_path=config.project_path,
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        output_dir=config.output_dir,
        total_routes=len(routes),
        total_findings=len(all_findings),
        confirmed=len(confirmed),
        false_positives=len(false_positives),
        downgraded=len(downgraded),
        needs_review=len(needs_review),
        sev_critical=severity_counter.get("critical", 0),
        sev_high=severity_counter.get("high", 0),
        sev_medium=severity_counter.get("medium", 0),
        sev_low=severity_counter.get("low", 0),
        type_table=type_table,
        confirmed_section=render_section(confirmed),
        needs_review_section=render_section(needs_review),
        downgraded_section=render_section(downgraded),
        false_positive_section=render_section(false_positives),
        routes_section=routes_section,
    )

    # ---- Write output files ----
    report_path = os.path.join(config.output_dir, "security-audit-report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_md)

    # Structured JSON report
    report_data = {
        "project_path": config.project_path,
        "total_routes": len(routes),
        "total_findings": len(all_findings),
        "confirmed_findings": len(confirmed),
        "false_positives": len(false_positives),
        "routes": routes,
        "findings": all_findings,
        "verifications": verifications,
        "summary_by_severity": dict(severity_counter),
        "summary_by_type": dict(type_counter),
    }

    for fname, data in [
        ("report.json", report_data),
        ("routes.json", routes),
        ("findings.json", all_findings),
        ("verified.json", verifications),
    ]:
        fpath = os.path.join(config.output_dir, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    stats = {
        "total_routes": len(routes),
        "total_findings": len(all_findings),
        "confirmed": len(confirmed),
        "false_positives": len(false_positives),
        "downgraded": len(downgraded),
        "needs_review": len(needs_review),
    }

    logger.info("[report_generator] report written to %s", report_path)
    logger.info("[report_generator] stats: %s", stats)

    return {
        "report_path": report_path,
        "output_dir": config.output_dir,
        "stats": stats,
    }
