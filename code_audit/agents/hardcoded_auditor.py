"""Hardcoded secrets auditor — searches for hardcoded credentials and keys.

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
# System prompt
# ---------------------------------------------------------------------------

HARDCODED_AUDITOR_PROMPT = """\
You are a hardcoded secrets and credentials audit expert. Your task is to \
search the project for hardcoded passwords, API keys, encryption keys, \
database credentials, and other sensitive values.

## Project path
{project_path}

## Output directory
{output_dir}

## Instructions

### Step 1 — Search for hardcoded secrets
Use `grep_content` to search for these patterns (case insensitive):
- Passwords: password, passwd, pwd, secret, credential
- API keys: apikey, api_key, access_key, secret_key, token, api.key
- Database URLs: jdbc:, mongodb://, redis://, mysql://, postgresql://
- Encryption keys: AES, DES, RSA, Base64 encoded keys, SecretKeySpec
- Shiro default key: kPH+bIxk5D2deZiIxcaaaA (known Shiro 1.x default)
- JWT signing: signWith, secretKey, HMAC, HS256, HS384, HS512
- Private keys: BEGIN RSA PRIVATE KEY, BEGIN EC PRIVATE KEY
- AWS credentials: AKIA, aws_access_key_id, aws_secret_access_key

### Step 2 — Examine configuration files
Use `glob_files` to find:
- application.properties, application.yml, application.yaml
- web.xml, shiro.ini, persistence.xml
- pom.xml (check for hardcoded credentials in plugin configs)
- .env, config.properties, bootstrap.yml
- Any file named *secret*, *credential*, *password*

Read each file and check for hardcoded sensitive values.

### Step 3 — Classify each finding
For each potential hardcoded secret, determine:
- Is it a REAL credential or a placeholder/example? (e.g. "changeme", "xxx", "TODO")
- Is it in production code or test code?
- What is the impact if exposed?

Only report findings that are likely real secrets, not placeholders.

### Step 4 — Output results
Write your findings to {output_dir}/hardcoded-findings.json, then submit.

Output format:
{{
  "findings": [
    {{
      "id": "HC-001",
      "type": "hardcoded",
      "severity": "high",
      "title": "Hardcoded database password in application.properties",
      "file_path": "/path/to/file",
      "line_number": 15,
      "code_snippet": "db.password=s3cret123",
      "description": "...",
      "remediation": "Move to environment variable or secrets vault"
    }}
  ]
}}

Use ID prefix HC-xxx for all findings.
"""


@register_agent(
    name="hardcoded_auditor",
    layer=1,
    depends_on=["route_mapper"],
    timeout=1800,
    description="Search for hardcoded passwords, API keys, and secrets",
)
async def run_hardcoded_auditor(config: AuditConfig, inputs: dict) -> dict:
    """Execute hardcoded secrets audit."""
    os.makedirs(config.output_dir, exist_ok=True)

    client = create_llm_client(config.provider, config.api_key, config.base_url)

    registry = ToolRegistry.for_llm_agent()

    prompt = HARDCODED_AUDITOR_PROMPT.format(
        project_path=config.project_path,
        output_dir=config.output_dir,
    )

    agent = AuditAgent(
        client=client,
        model=config.model,
        system_prompt=prompt,
        tool_registry=registry,
        name="hardcoded_auditor",
        max_turns=config.agent_max_turns or 80,
        provider=config.provider,
    )

    result = await agent.run(
        f"Search the project at {config.project_path} for hardcoded "
        f"credentials, API keys, and secrets."
    )

    if "findings" not in result:
        result = {"findings": result.get("data", {}).get("findings", [])}

    # Persist findings to file (consistent with other Layer 1 agents)
    findings_path = os.path.join(config.output_dir, "hardcoded-findings.json")
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump(
            {"findings": result.get("findings", [])},
            f, indent=2, ensure_ascii=False,
        )

    logger.info(
        "[hardcoded_auditor] %d findings", len(result.get("findings", []))
    )
    return result
