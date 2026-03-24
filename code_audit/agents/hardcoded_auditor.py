"""Hardcoded secrets auditor — searches for hardcoded credentials and keys.

Layer 1 agent, depends on ``route_mapper``.
Produces ``{"findings": [Finding...]}``.
"""

from __future__ import annotations

import json
import logging
import os

from ..config import AuditConfig
from ..prompts.hardcoded_auditor import HARDCODED_AUDITOR_PROMPT
from ..tools.registry import ToolRegistry
from .base import AuditAgent, create_llm_client
from .registry import register_agent

logger = logging.getLogger(__name__)


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
