"""Route mapper agent — extracts HTTP routes from the target project.

Layer 0 agent with no dependencies.  Produces ``{"routes": [RouteEntry...]}``
for downstream agents.
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
# System prompt (embedded, not loaded from file)
# ---------------------------------------------------------------------------

ROUTE_MAPPER_PROMPT = """\
You are a web application route analysis expert. Your task is to extract ALL \
HTTP routes / API endpoints from the given project.

## Project path
{project_path}

## Output directory
{output_dir}

## Instructions

1. Use `glob_files` to find source files that typically define routes:
   - Java:  **/*Controller*.java, **/*Servlet*.java, **/*Resource*.java, \
**/*Router*.java, **/*Routes*.java, **/*Handler*.java, **/*Endpoint*.java, \
**/web.xml
   - Spark Java: Look for calls to get(), post(), put(), delete(), before(), \
after(), path() in Spark.java or similar files.
   - Spring: @RequestMapping, @GetMapping, @PostMapping, @PutMapping, @DeleteMapping
   - JAX-RS: @Path, @GET, @POST, @PUT, @DELETE
   - Servlet: @WebServlet, url-pattern in web.xml

2. Use `read_file` to examine each candidate file and extract:
   - HTTP method (GET / POST / PUT / DELETE / ANY)
   - Route path (e.g. /api/users/:id)
   - Controller/handler class name
   - Handler method name
   - File path (absolute)
   - Line number
   - Parameters (name, type, location: query/path/body/header/cookie)

3. For Spark Java projects specifically:
   - The framework defines routes via static methods: Spark.get(), Spark.post(), etc.
   - Route handlers are often lambda expressions or Route implementations
   - Look for staticFiles.location() / staticFiles.externalLocation() for static file serving
   - Look for before() / after() filters

4. Output your results using the incremental write strategy:
    a. write_file("{output_dir}/routes.json", '{{"routes": [')
   b. For each batch of routes (keep each batch < 3000 chars):
      append_file("{output_dir}/routes.json", '<batch as JSON>')
   c. append_file("{output_dir}/routes.json", ']}}')
   d. submit_result(file_path="{output_dir}/routes.json")

Each route object must have these fields:
{{
  "method": "GET",
  "path": "/api/example",
  "controller": "ExampleController",
  "handler_method": "handleExample",
  "file_path": "/absolute/path/to/File.java",
  "line_number": 42,
  "params": [
    {{"name": "id", "type": "String", "location": "path", "required": true}}
  ]
}}

Be thorough — missing a route means missing potential vulnerabilities.
"""


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
