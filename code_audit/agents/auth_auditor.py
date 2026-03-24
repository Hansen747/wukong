"""Auth auditor agent — analyses authentication/authorisation mechanisms.

Layer 1 agent, depends on ``route_mapper``.
Produces ``{"findings": [Finding...], "route_updates": [AuthRouteUpdate...]}``.
"""

from __future__ import annotations

import json
import logging
import os

from ..config import AuditConfig
from ..prompts.auth_auditor import AUTH_AUDITOR_PROMPT
from ..tools.registry import ToolRegistry
from .base import AuditAgent, create_llm_client
from .registry import register_agent

logger = logging.getLogger(__name__)


@register_agent(
    name="auth_auditor",
    layer=1,
    depends_on=["route_mapper"],
    timeout=1800,
    description="Analyse authentication mechanisms and find auth bypass vulns",
)
async def run_auth_auditor(config: AuditConfig, inputs: dict) -> dict:
    """Execute authentication audit."""
    os.makedirs(config.output_dir, exist_ok=True)

    routes_data = inputs.get("route_mapper", {})
    routes_json = json.dumps(routes_data.get("routes", []), indent=2)

    client = create_llm_client(config.provider, config.api_key, config.base_url)

    registry = ToolRegistry.for_llm_agent()

    prompt = AUTH_AUDITOR_PROMPT.format(
        project_path=config.project_path,
        output_dir=config.output_dir,
        routes_json=routes_json,
    )

    agent = AuditAgent(
        client=client,
        model=config.model,
        system_prompt=prompt,
        tool_registry=registry,
        name="auth_auditor",
        max_turns=config.agent_max_turns or 80,
        provider=config.provider,
    )

    result = await agent.run(
        f"Analyse the authentication mechanisms in {config.project_path} "
        f"and identify any auth bypass vulnerabilities."
    )

    # Normalise
    if "findings" not in result:
        result["findings"] = result.get("data", {}).get("findings", [])
    if "route_updates" not in result:
        result["route_updates"] = result.get("data", {}).get("route_updates", [])

    logger.info(
        "[auth_auditor] %d findings, %d route updates",
        len(result.get("findings", [])),
        len(result.get("route_updates", [])),
    )
    return result
