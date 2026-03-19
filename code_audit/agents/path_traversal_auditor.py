"""Path traversal / directory traversal auditor agent.

Layer 1 agent, depends on ``route_mapper``.
Produces ``{"findings": [Finding...]}``.

Targets CVE-2018-9159 and similar path traversal vulnerabilities where
user-controlled input reaches file system operations without adequate
path normalisation or sandbox checks.
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

PATH_TRAVERSAL_PROMPT = """\
You are a security expert specialising in path traversal / directory traversal \
vulnerabilities (CWE-22, CWE-23, CWE-36).  Your task is to find ALL instances \
where user-controlled input can influence file system paths without adequate \
sanitisation.

## Project path
{project_path}

## Output directory
{output_dir}

## Routes discovered by route_mapper
```json
{routes_json}
```

## Instructions

### Step 1 — Find dangerous sinks (file system operations)

Use `grep_content` with `path="{project_path}"` to search for file I/O \
operations that could be path traversal sinks.  Run ALL of these searches:

1. **Java File constructors & paths**:
   grep_content(pattern="new File\\\\(|new FileInputStream\\\\(|new FileOutputStream\\\\(|new FileReader\\\\(|new FileWriter\\\\(|Paths\\\\.get\\\\(|Path\\\\.of\\\\(", path="{project_path}", file_type="java")

2. **NIO / IO streams**:
   grep_content(pattern="Files\\\\.(read|write|copy|move|delete|exists|newInput|newOutput|lines|walk|list)", path="{project_path}", file_type="java")

3. **Static file serving**:
   grep_content(pattern="(staticFile|externalLocation|staticFileLocation|ClassPathResource|getResource|getResourceAsStream)", path="{project_path}", file_type="java")

4. **Path manipulation**:
   grep_content(pattern="(getCanonicalPath|toRealPath|normalize|resolve|relativize|startsWith)", path="{project_path}", file_type="java")

5. **Servlet file access**:
   grep_content(pattern="(getServletContext\\\\(\\\\)\\\\.getRealPath|getServletContext\\\\(\\\\)\\\\.getResource|ServletContext\\\\.getResource)", path="{project_path}", file_type="java")

6. **URL / URI path decoding**:
   grep_content(pattern="(URLDecoder\\\\.decode|URI\\\\.getPath|getRequestURI|getPathInfo|getServletPath)", path="{project_path}", file_type="java")

7. **Directory traversal defences** (to assess existing mitigations):
   grep_content(pattern="(\\.\\\\.\\\\.|\\\\.\\\\./|\\\\.\\\\.\\\\\\\\|DirectoryTraversal|pathTraversal|sanitize|canonicali)", path="{project_path}", file_type="java")

IMPORTANT: Always pass `path="{project_path}"` to grep_content and glob_files. \
Do NOT use the default path ".".

### Step 2 — Trace from source to sink

For each dangerous sink found in Step 1:
1. Use `read_file` to read the full method containing the sink
2. Trace backward to find if ANY of these sources reach the sink:
   - HTTP request parameters: request.queryParams(), request.params(), \
request.splat(), getParameter(), getPathInfo()
   - URL path components: request.uri(), request.url(), request.pathInfo(), \
getRequestURI(), getServletPath()
   - HTTP headers: request.headers(), getHeader()
   - File upload names: getPart(), getSubmittedFileName()
   - Any other user-controlled string
3. Check ALL intermediate methods in the call chain — a sink in a utility \
method is still vulnerable if called with user input

### Step 3 — Evaluate mitigations

For each source→sink path, check if ANY of these mitigations exist:
- **Path canonicalisation**: getCanonicalPath() FOLLOWED BY startsWith() \
check against an allowed base directory
- **Whitelist validation**: comparing against a fixed set of allowed filenames
- **Null byte check**: rejecting paths containing \\x00
- **Traversal sequence rejection**: rejecting "..", but ONLY if it handles \
URL-encoded variants (%2e%2e, %2f, etc.) AND double-encoding
- **chroot / sandbox**: file operations restricted to a specific directory

A mitigation is INEFFECTIVE if:
- It only checks for ".." but not URL-encoded variants
- It normalises the path but doesn't verify the result is within bounds
- It uses a blacklist instead of a whitelist approach
- The check can be bypassed via null bytes, double encoding, or \
path separator differences

### Step 4 — Examine static file serving configuration

This is CRITICAL for web frameworks.  Look for:
- Static file directory configuration (staticFiles.location, \
staticFiles.externalLocation, resource handlers)
- How the framework resolves requested paths to actual files
- Whether the framework's built-in static file serving has known CVEs \
(e.g., CVE-2018-9159 in SparkJava 2.7.1 — path traversal via encoded \
characters in static file requests)
- Check the framework version in pom.xml or build.gradle for known vulns

### Step 5 — Output results

Submit findings using submit_findings with the result_json parameter.

Example:
submit_findings(result_json='{{"findings": [<your findings array>]}}')

If the result is large, write it to a file first:
write_file("{output_dir}/path-traversal-findings.json", '<complete JSON>')
submit_findings(file_path="{output_dir}/path-traversal-findings.json")

Each finding must have:
{{
  "id": "PT-001",
  "type": "path_traversal",
  "severity": "critical" or "high" or "medium" or "low",
  "title": "Path traversal in static file serving via encoded characters",
  "file_path": "/absolute/path/to/File.java",
  "line_number": 42,
  "source": "HTTP request URI path",
  "sink": "new File(staticFilesFolder, path)",
  "call_chain": [
    {{"method": "handleRequest", "file": "File.java", "line": 42, "code": "..."}}
  ],
  "code_snippet": "the vulnerable code",
  "description": "Detailed explanation of the vulnerability...",
  "poc": "GET /static/..%2f..%2f..%2fetc/passwd HTTP/1.1\\nHost: target:4567",
  "remediation": "How to fix..."
}}

Use ID prefix PT-xxx for all findings.

### Key considerations
- Path traversal is often exploitable even WITHOUT explicit routes — static \
file serving is a prime target
- Check pom.xml / build.gradle for framework versions with known CVEs
- Look for BOTH direct file access (new File(userInput)) AND indirect access \
via framework resource loading
- URL encoding bypass: %2e%2e%2f = ../,  %252e%252e%252f = double-encoded
- Spark Java CVE-2018-9159: the static file handler does not properly \
canonicalise paths before serving, allowing /../ traversal
"""


@register_agent(
    name="path_traversal_auditor",
    layer=1,
    depends_on=["route_mapper"],
    timeout=1800,
    description="Find path traversal / directory traversal vulnerabilities (CWE-22)",
)
async def run_path_traversal_auditor(config: AuditConfig, inputs: dict) -> dict:
    """Execute path traversal vulnerability audit."""
    os.makedirs(config.output_dir, exist_ok=True)

    routes_data = inputs.get("route_mapper", {})
    routes_json = json.dumps(routes_data.get("routes", []), indent=2)

    client = create_llm_client(config.provider, config.api_key, config.base_url)

    registry = ToolRegistry.for_llm_agent()

    prompt = PATH_TRAVERSAL_PROMPT.format(
        project_path=config.project_path,
        output_dir=config.output_dir,
        routes_json=routes_json,
    )

    agent = AuditAgent(
        client=client,
        model=config.model,
        system_prompt=prompt,
        tool_registry=registry,
        name="path_traversal_auditor",
        max_turns=config.agent_max_turns or 80,
        provider=config.provider,
    )

    result = await agent.run(
        f"Analyse the project at {config.project_path} for path traversal "
        f"vulnerabilities.  Check static file serving configuration, file "
        f"I/O operations, and the framework version for known CVEs."
    )

    # Normalise
    if "findings" not in result:
        result["findings"] = result.get("data", {}).get("findings", [])

    logger.info(
        "[path_traversal_auditor] %d findings",
        len(result.get("findings", [])),
    )
    return result
