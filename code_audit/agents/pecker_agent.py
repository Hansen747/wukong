"""Pecker agent — tool-free LLM agent that embeds Pecker 3.0 detection methodology.

Layer 1 agent, depends on ``route_mapper``.
Encapsulates Pecker's multi-step vulnerability detection pipeline (sink
identification, multi-judge verification, taint analysis) entirely within
the LLM system prompt.  Does NOT use any tools — the LLM performs all
analysis natively based on the source code provided in context.

Produces ``{"findings": [Finding...]}``.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

from ..config import AuditConfig
from ..prompts.pecker_agent import PECKER_SYSTEM_PROMPT
from .base import create_llm_client
from .registry import register_agent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Max source code characters to include in a single LLM call
_MAX_CODE_CHARS = 120_000

# File extensions we care about per language
_JAVA_EXTS = {".java", ".xml"}
_GO_EXTS = {".go"}
_PYTHON_EXTS = {".py"}
_ALL_EXTS = _JAVA_EXTS | _GO_EXTS | _PYTHON_EXTS

# Routes per LLM batch (to stay within context window limits)
_ROUTES_PER_BATCH = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_language(project_path: str) -> str:
    """Heuristically detect the primary language of the project."""
    java_count = go_count = py_count = 0
    for root, _dirs, files in os.walk(project_path):
        # Skip hidden dirs and common non-source dirs
        parts = root.split(os.sep)
        if any(p.startswith(".") or p in ("node_modules", "vendor", "__pycache__", "target", "build") for p in parts):
            continue
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in _JAVA_EXTS:
                java_count += 1
            elif ext in _GO_EXTS:
                go_count += 1
            elif ext in _PYTHON_EXTS:
                py_count += 1
    counts = {"java": java_count, "go": go_count, "python": py_count}
    return max(counts, key=counts.get)


def _collect_source_files(project_path: str, extensions: set[str], max_chars: int) -> str:
    """Collect source file contents up to *max_chars* total."""
    parts: list[str] = []
    total = 0
    for root, _dirs, files in os.walk(project_path):
        rel_root = os.path.relpath(root, project_path)
        # Skip hidden/build dirs
        if any(p.startswith(".") or p in ("node_modules", "vendor", "__pycache__", "target", "build", ".git") for p in rel_root.split(os.sep)):
            continue
        for fname in sorted(files):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in extensions:
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, project_path)
            try:
                content = Path(fpath).read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            chunk = f"\n--- FILE: {rel_path} ---\n{content}\n"
            if total + len(chunk) > max_chars:
                # Try to include at least part of the file
                remaining = max_chars - total
                if remaining > 200:
                    parts.append(chunk[:remaining] + "\n... [truncated]")
                    total = max_chars
                break
            parts.append(chunk)
            total += len(chunk)
        if total >= max_chars:
            break
    return "".join(parts)


def _collect_route_relevant_files(
    project_path: str,
    routes: list[dict],
    language: str,
    max_chars: int,
) -> str:
    """Collect source files that are likely relevant to the given routes.

    Prioritises files mentioned in routes, then collects remaining files
    up to *max_chars*.
    """
    exts = {
        "java": _JAVA_EXTS,
        "go": _GO_EXTS,
        "python": _PYTHON_EXTS,
    }.get(language, _ALL_EXTS)

    # Extract file paths mentioned in routes
    route_files: set[str] = set()
    for route in routes:
        fp = route.get("file_path") or route.get("file") or route.get("source_file") or ""
        if fp:
            route_files.add(fp)
        # Also look for class_name hints
        cls = route.get("class_name") or route.get("handler") or ""
        if cls:
            # Convert com.foo.Bar → com/foo/Bar.java
            cls_path = cls.replace(".", os.sep)
            for ext in exts:
                route_files.add(cls_path + ext)

    parts: list[str] = []
    total = 0
    seen: set[str] = set()

    # Phase 1: files explicitly referenced by routes
    for rf in sorted(route_files):
        candidates = [
            os.path.join(project_path, rf),
            rf,  # absolute path
        ]
        for fpath in candidates:
            if os.path.isfile(fpath) and fpath not in seen:
                seen.add(fpath)
                rel_path = os.path.relpath(fpath, project_path)
                try:
                    content = Path(fpath).read_text(encoding="utf-8", errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                chunk = f"\n--- FILE: {rel_path} ---\n{content}\n"
                if total + len(chunk) > max_chars:
                    remaining = max_chars - total
                    if remaining > 200:
                        parts.append(chunk[:remaining] + "\n... [truncated]")
                        total = max_chars
                    break
                parts.append(chunk)
                total += len(chunk)
                break
        if total >= max_chars:
            break

    # Phase 2: fill remaining budget with other source files
    if total < max_chars:
        remaining_code = _collect_source_files(project_path, exts, max_chars - total)
        # Filter out already-seen files
        for block in remaining_code.split("\n--- FILE: "):
            if not block.strip():
                continue
            # Re-add prefix for parsing
            full_block = "\n--- FILE: " + block if not block.startswith("\n--- FILE:") else block
            # Extract the file path from the block
            m = re.match(r"\n--- FILE: (.+?) ---\n", full_block)
            if m:
                rel = m.group(1)
                abs_path = os.path.join(project_path, rel)
                if abs_path in seen:
                    continue
            if total + len(full_block) > max_chars:
                break
            parts.append(full_block)
            total += len(full_block)

    return "".join(parts)


async def _call_llm(
    client: Any,
    provider: str,
    model: str,
    system_prompt: str,
    user_message: str,
    max_tokens: int = 16384,
) -> str:
    """Make a single LLM call and return the text response."""
    if provider == "openai":
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            max_tokens=max_tokens,
            temperature=0.0,
        )
        return resp.choices[0].message.content or ""
    else:
        # Anthropic
        resp = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_message},
            ],
            temperature=0.0,
        )
        # Anthropic returns content blocks
        return "".join(
            block.text for block in resp.content if hasattr(block, "text")
        )


def _extract_findings_json(text: str) -> list[dict]:
    """Extract the findings JSON array from LLM response text."""
    # Try ```json fenced block first
    m = re.search(r"```json\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(1))
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "findings" in data:
                return data["findings"]
            return [data] if data else []
        except json.JSONDecodeError:
            pass

    # Try to find a JSON array
    idx = text.find("[")
    if idx != -1:
        depth = 0
        for i in range(len(text) - 1, idx - 1, -1):
            if text[i] == "]":
                depth += 1
            elif text[i] == "[":
                depth -= 1
            if depth == 0 and i >= idx:
                try:
                    data = json.loads(text[idx : i + 1])
                    if isinstance(data, list):
                        return data
                except json.JSONDecodeError:
                    break

    # Try to find a JSON object with "findings" key
    idx = text.find("{")
    if idx != -1:
        depth = 0
        for i in range(len(text) - 1, idx - 1, -1):
            if text[i] == "}":
                depth += 1
            elif text[i] == "{":
                depth -= 1
            if depth == 0 and i >= idx:
                try:
                    data = json.loads(text[idx : i + 1])
                    if isinstance(data, dict) and "findings" in data:
                        return data["findings"]
                    if isinstance(data, dict):
                        return [data]
                except json.JSONDecodeError:
                    break

    return []


# ---------------------------------------------------------------------------
# Agent entry point
# ---------------------------------------------------------------------------

@register_agent(
    name="pecker_agent",
    layer=1,
    depends_on=["route_mapper"],
    timeout=1800,
    description=(
        "Tool-free Pecker 3.0 agent — embeds multi-step vulnerability "
        "detection methodology (sink identification, multi-judge verification, "
        "taint analysis) entirely in the LLM prompt for SQLI/RCE/XXE detection"
    ),
)
async def run_pecker_agent(config: AuditConfig, inputs: dict) -> dict:
    """Execute the Pecker vulnerability detection pipeline via pure LLM analysis."""
    os.makedirs(config.output_dir, exist_ok=True)

    # ---- Gather inputs from upstream route_mapper ----
    routes_data = inputs.get("route_mapper", {})
    routes: list[dict] = routes_data.get("routes", [])

    if not routes:
        logger.warning("[pecker_agent] No routes received from route_mapper; scanning full project")

    # ---- Detect language ----
    language = _detect_language(config.project_path)
    logger.info("[pecker_agent] Detected primary language: %s", language)

    # ---- Create LLM client ----
    client = create_llm_client(config.provider, config.api_key, config.base_url)

    # ---- Process routes in batches ----
    all_findings: list[dict] = []
    finding_counter = 0

    # Split routes into batches
    if routes:
        batches = [
            routes[i : i + _ROUTES_PER_BATCH]
            for i in range(0, len(routes), _ROUTES_PER_BATCH)
        ]
    else:
        # No routes — do a single full-project scan
        batches = [None]  # type: ignore[list-item]

    for batch_idx, batch in enumerate(batches):
        logger.info(
            "[pecker_agent] Processing batch %d/%d (%s routes)",
            batch_idx + 1,
            len(batches),
            len(batch) if batch else "full-project",
        )

        # Collect relevant source code
        if batch:
            source_code = _collect_route_relevant_files(
                config.project_path, batch, language, _MAX_CODE_CHARS
            )
        else:
            exts = {
                "java": _JAVA_EXTS,
                "go": _GO_EXTS,
                "python": _PYTHON_EXTS,
            }.get(language, _ALL_EXTS)
            source_code = _collect_source_files(
                config.project_path, exts, _MAX_CODE_CHARS
            )

        if not source_code.strip():
            logger.warning("[pecker_agent] No source code collected for batch %d", batch_idx + 1)
            continue

        # Build user message
        routes_section = ""
        if batch:
            routes_json = json.dumps(batch, indent=2, ensure_ascii=False)
            routes_section = f"""
## Routes to analyse (from route_mapper)
```json
{routes_json}
```
"""

        user_message = f"""\
## Project Information
- **Project path**: {config.project_path}
- **Primary language**: {language}
{routes_section}
## Source Code
{source_code}

## Task
Analyse the source code above following the Pecker Detection Methodology \
described in your instructions. For each route entry point (or for the \
entire codebase if no routes are provided):

1. Identify all potential SQLI / RCE / XXE sinks
2. Run multi-judge verification on each sink
3. Perform taint backtracing for confirmed vulnerabilities
4. Output your findings as a JSON array

Be thorough but precise — only report vulnerabilities that survive ALL \
multi-judge checks. Explain your reasoning for each check.
"""

        try:
            response_text = await _call_llm(
                client=client,
                provider=config.provider,
                model=config.model,
                system_prompt=PECKER_SYSTEM_PROMPT,
                user_message=user_message,
                max_tokens=16384,
            )
        except Exception as exc:
            logger.error("[pecker_agent] LLM call failed for batch %d: %s", batch_idx + 1, exc)
            continue

        # Extract findings
        batch_findings = _extract_findings_json(response_text)

        # Re-number findings with global counter
        for finding in batch_findings:
            finding_counter += 1
            finding["id"] = f"PECKER-{finding_counter:03d}"
            all_findings.append(finding)

        logger.info(
            "[pecker_agent] Batch %d/%d: %d findings",
            batch_idx + 1,
            len(batches),
            len(batch_findings),
        )

    # ---- Write results to output file ----
    output_path = os.path.join(config.output_dir, "pecker-findings.json")
    result = {"findings": all_findings}
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        logger.info("[pecker_agent] Results written to %s", output_path)
    except OSError as exc:
        logger.error("[pecker_agent] Failed to write results: %s", exc)

    logger.info("[pecker_agent] Total findings: %d", len(all_findings))
    return result
