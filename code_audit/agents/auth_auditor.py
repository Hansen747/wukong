"""Auth auditor agent — analyses authentication/authorisation mechanisms.

Layer 1 agent, depends on ``route_mapper``.
Produces ``{"findings": [Finding...], "route_updates": [AuthRouteUpdate...]}``.
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

AUTH_AUDITOR_PROMPT = """\
You are a Java authentication and authorisation audit expert. Your task is to \
identify the authentication framework used by the project, analyse every \
route's auth status, and find auth bypass vulnerabilities.

## Project path
{project_path}

## Output directory
{output_dir}

## Routes discovered by route_mapper
```json
{routes_json}
```

## Instructions

### Step 1 — Identify the auth framework
Use `grep_content` and `read_file` to search for:
- **Shiro**: shiro.ini, @RequiresAuthentication, @RequiresPermissions, \
SecurityUtils, ShiroFilter
- **Spring Security**: @EnableWebSecurity, SecurityFilterChain, \
@PreAuthorize, @Secured, WebSecurityConfigurerAdapter
- **JWT**: io.jsonwebtoken, JwtParser, Bearer, Authorization header parsing
- **Filter/Interceptor**: implements Filter, implements HandlerInterceptor, \
doFilter, preHandle
- **Custom annotations**: @Auth, @Login, @RequireLogin, etc.
- **Spark Java before() filters**: before("/path", ...) filters that check auth

### Step 2 — Analyse each route
For each route from the route_mapper output:
1. Determine if authentication is required
2. Identify the auth mechanism (shiro / spring_security / jwt / filter / none)
3. Check for bypass risks:
   - Path traversal bypasses (e.g. /..;/admin)
   - HTTP method mismatch (GET allowed but only POST checked)
   - Missing auth on sensitive endpoints
   - Default credentials
   - Known CVEs in auth framework versions

### Step 3 — Output results
Write your findings to {output_dir}/auth-findings.json using the incremental \
write strategy, then submit via submit_findings(file_path=...).

Output format:
{{
  "findings": [
    {{
      "id": "AUTH-001",
      "type": "auth_bypass",
      "severity": "high",
      "title": "Missing authentication on /admin endpoint",
      "file_path": "/path/to/file.java",
      "line_number": 42,
      "description": "...",
      "remediation": "..."
    }}
  ],
  "route_updates": [
    {{
      "path": "/api/users",
      "method": "GET",
      "auth_required": true,
      "auth_mechanism": "jwt",
      "notes": ""
    }}
  ]
}}

Use ID prefix AUTH-xxx for all findings.
"""


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
