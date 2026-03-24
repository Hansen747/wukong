"""Markdown templates for the report_generator agent (Layer 3)."""

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
