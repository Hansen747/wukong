"""Route mapper agent — extracts HTTP routes from the target project.

Layer 0 agent with no dependencies.  Produces ``{"routes": [RouteEntry...]}``
for downstream agents.
"""

from __future__ import annotations

import json
import logging
import os

from ..config import AuditConfig
from ..prompts.route_mapper import ROUTE_MAPPER_PROMPT
from ..tools.registry import ToolRegistry
from .base import AuditAgent, create_llm_client
from .registry import register_agent

logger = logging.getLogger(__name__)


@register_agent(
    name="route_mapper",
    layer=0,
    depends_on=[],
    timeout=1800,
    description="Extract HTTP routes/API endpoints from the project",
)
async def run_route_mapper(config: AuditConfig, inputs: dict) -> dict:
    """Execute route mapping analysis."""
    os.makedirs(config.output_dir, exist_ok=True)

    client = create_llm_client(config.provider, config.api_key, config.base_url)

    registry = ToolRegistry.for_llm_agent()

    prompt = ROUTE_MAPPER_PROMPT.format(
        project_path=config.project_path,
        output_dir=config.output_dir,
    )

    agent = AuditAgent(
        client=client,
        model=config.model,
        system_prompt=prompt,
        tool_registry=registry,
        name="route_mapper",
        max_turns=config.agent_max_turns or 80,
        provider=config.provider,
    )

    result = await agent.run(
        f"Please analyse the project at {config.project_path} and extract all "
        f"HTTP routes.  Write results to {config.output_dir}/routes.json."
    )

    # Normalise output
    if "routes" not in result:
        # Try to find routes in nested structure
        for key in ("data", "result"):
            if key in result and isinstance(result[key], dict):
                if "routes" in result[key]:
                    result = result[key]
                    break
        if "routes" not in result:
            result = {"routes": []}

    logger.info(
        "[route_mapper] extracted %d routes", len(result.get("routes", []))
    )
    return result
