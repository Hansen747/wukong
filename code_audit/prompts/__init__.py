"""Centralised prompt definitions for the wukong code audit framework.

All prompt constants used by agents are defined here and imported by the
agent modules.  This makes prompts easier to review, test, and maintain
in a single location.

Submodules
----------
- route_mapper       : ROUTE_MAPPER_PROMPT
- auth_auditor       : AUTH_AUDITOR_PROMPT
- hardcoded_auditor  : HARDCODED_AUDITOR_PROMPT
- vuln_verifier      : VULN_VERIFIER_PROMPT
- pecker_agent       : PECKER_SYSTEM_PROMPT
- taint_analyzer     : GROUP_AGENT_PROMPT
- sinks              : SQLI_SINKS, RCE_SINKS, XXE_SINKS, SSRF_SINKS,
                        PATH_TRAVERSAL_SINKS, STRUCTURED_SINKS, SINK_GREP_PATTERNS
- multi_judge        : MULTI_JUDGE_CHECKS, MULTI_JUDGE_CHECK_ORDERS, FUNCTION_CHECK
- report_templates   : REPORT_TEMPLATE, FINDING_TEMPLATE
- base               : COMPRESSION_FALLBACK_TEMPLATE, COMPRESSION_BRIDGE_USER_MESSAGE
"""

# -- Agent system prompts --
from .route_mapper import ROUTE_MAPPER_PROMPT
from .auth_auditor import AUTH_AUDITOR_PROMPT
from .hardcoded_auditor import HARDCODED_AUDITOR_PROMPT
from .vuln_verifier import VULN_VERIFIER_PROMPT
from .pecker_agent import PECKER_SYSTEM_PROMPT
from .taint_analyzer import GROUP_AGENT_PROMPT

# -- Sink knowledge --
from .sinks import (
    SQLI_SINKS,
    RCE_SINKS,
    XXE_SINKS,
    SSRF_SINKS,
    PATH_TRAVERSAL_SINKS,
    STRUCTURED_SINKS,
    SINK_GREP_PATTERNS,
)

# -- Multi-judge verification --
from .multi_judge import (
    MULTI_JUDGE_CHECKS,
    MULTI_JUDGE_CHECK_ORDERS,
    FUNCTION_CHECK,
)

# -- Report templates --
from .report_templates import REPORT_TEMPLATE, FINDING_TEMPLATE

# -- Base agent prompt fragments --
from .base import COMPRESSION_FALLBACK_TEMPLATE, COMPRESSION_BRIDGE_USER_MESSAGE

__all__ = [
    "ROUTE_MAPPER_PROMPT",
    "AUTH_AUDITOR_PROMPT",
    "HARDCODED_AUDITOR_PROMPT",
    "VULN_VERIFIER_PROMPT",
    "PECKER_SYSTEM_PROMPT",
    "GROUP_AGENT_PROMPT",
    "SQLI_SINKS",
    "RCE_SINKS",
    "XXE_SINKS",
    "SSRF_SINKS",
    "PATH_TRAVERSAL_SINKS",
    "STRUCTURED_SINKS",
    "SINK_GREP_PATTERNS",
    "MULTI_JUDGE_CHECKS",
    "MULTI_JUDGE_CHECK_ORDERS",
    "FUNCTION_CHECK",
    "REPORT_TEMPLATE",
    "FINDING_TEMPLATE",
    "COMPRESSION_FALLBACK_TEMPLATE",
    "COMPRESSION_BRIDGE_USER_MESSAGE",
]
