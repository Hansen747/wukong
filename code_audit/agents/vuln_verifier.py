"""Vulnerability verifier agent — independently verifies upstream findings.

Layer 2 agent, depends on ``auth_auditor``, ``taint_analyzer``,
and ``hardcoded_auditor``.
Produces ``{"verifications": [VerificationResult...]}``.
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
# System prompt
# ---------------------------------------------------------------------------

VULN_VERIFIER_PROMPT = """\
You are a vulnerability verification expert. You will receive a list of \
potential vulnerabilities discovered by upstream scanners (auth_auditor, \
taint_analyzer, hardcoded_auditor). Your job is to \
independently verify each finding by reading the actual source code.

## Project path
{project_path}

## Output directory
{output_dir}

## Findings to verify
```json
{findings_json}
```

## Instructions

For EACH finding listed above, perform the following verification steps:

### 1. Verify the Source exists and is user-controllable
- Use `read_file` to read the file at the specified path and line
- Confirm the alleged source (user input point) actually exists
- Check if the input is truly user-controllable (HTTP param, header, body, etc.)

### 2. Verify the Sink exists and is dangerous
- Confirm the dangerous function call exists at the reported location
- Check if the function is actually dangerous in context (e.g. File I/O, \
SQL execution, command execution, deserialization)

### 3. Trace the data flow
- Verify that data flows from Source to Sink
- Check each hop in the call chain
- Look for intermediate transformations

### 4. Check for sanitisation
- Look for input validation, encoding, or sanitisation between Source and Sink
- Examples: PreparedStatement (for SQL), whitelist validation, HTML encoding, \
path canonicalisation, type casting to non-string types
- If effective sanitisation exists, the finding is a false positive

### 5. Assign verification status
- **confirmed**: Source→Sink path complete, no effective sanitisation
- **false_positive**: Source/Sink absent, path broken, or effective sanitisation
- **downgraded**: Vulnerability exists but severity should be lower (partial sanitisation)
- **needs_review**: Cannot determine automatically

### Key principles
- Do NOT trust any claims from the upstream scanners — verify everything \
from source code
- Read the ACTUAL code, not just the file name
- Check surrounding code context (±30 lines) for sanitisation
- A finding with an incorrect file path or line number may still be valid \
if the vulnerability exists elsewhere in the file

### Output
Write results to {output_dir}/verifications.json, then submit.

Output format:
{{
  "verifications": [
    {{
      "finding_id": "PECKER-001",
      "status": "confirmed",
      "original_severity": "high",
      "adjusted_severity": null,
      "reason": "Verified: user input from request.queryParams('file') flows \
directly to new File() without path canonicalisation or whitelist validation."
    }}
  ]
}}
"""

# Maximum number of findings to send to the verifier
MAX_FINDINGS_TO_VERIFY = 30


@register_agent(
    name="vuln_verifier",
    layer=2,
    depends_on=["auth_auditor", "taint_analyzer", "hardcoded_auditor"],
    timeout=1800,
    description="Independently verify upstream vulnerability findings",
)
async def run_vuln_verifier(config: AuditConfig, inputs: dict) -> dict:
    """Execute vulnerability verification."""
    os.makedirs(config.output_dir, exist_ok=True)

    # Merge all upstream findings
    all_findings = []
    for stage_name in ("auth_auditor", "taint_analyzer", "hardcoded_auditor"):
        stage_data = inputs.get(stage_name, {})
        if isinstance(stage_data, dict):
            findings = stage_data.get("findings", [])
            all_findings.extend(findings)

    if not all_findings:
        logger.info("[vuln_verifier] no findings to verify")
        return {"verifications": []}

    # Limit findings to avoid overwhelming the verifier
    if len(all_findings) > MAX_FINDINGS_TO_VERIFY:
        logger.info(
            "[vuln_verifier] truncating %d findings to %d",
            len(all_findings),
            MAX_FINDINGS_TO_VERIFY,
        )
        # Prioritise by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_findings.sort(
            key=lambda f: severity_order.get(f.get("severity", "low"), 4)
        )
        all_findings = all_findings[:MAX_FINDINGS_TO_VERIFY]

    findings_json = json.dumps(all_findings, indent=2)

    client = create_llm_client(config.provider, config.api_key, config.base_url)

    registry = ToolRegistry.for_llm_agent()

    prompt = VULN_VERIFIER_PROMPT.format(
        project_path=config.project_path,
        output_dir=config.output_dir,
        findings_json=findings_json,
    )

    agent = AuditAgent(
        client=client,
        model=config.model,
        system_prompt=prompt,
        tool_registry=registry,
        name="vuln_verifier",
        max_turns=config.agent_max_turns or 80,
        provider=config.provider,
    )

    result = await agent.run(
        f"Verify the {len(all_findings)} findings listed in the system "
        f"prompt by reading the source code at {config.project_path}."
    )

    if "verifications" not in result:
        result = {
            "verifications": result.get("data", {}).get("verifications", [])
        }

    logger.info(
        "[vuln_verifier] %d verifications",
        len(result.get("verifications", [])),
    )
    return result
