"""Pecker scanner agent — runs Pecker as a subprocess for taint analysis.

This replaces the original Joern scanner from DESIGN.md.  Pecker is invoked
via ``python3 entry.py`` as a subprocess (never imported as a package).

Layer 1 agent, depends on ``route_mapper``.
Produces ``{"findings": [Finding...]}`` in the standard Finding schema.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from typing import Any

from ..config import AuditConfig
from .registry import register_agent

logger = logging.getLogger(__name__)

# Pecker vuln_type -> our normalised type
_VULN_TYPE_MAP = {
    "RCE": "rce",
    "SQLI": "sqli",
    "XXE": "xxe",
    "LFI": "path_traversal",
    "XSS": "xss",
    "SSRF": "ssrf",
    "AFO": "file_write",
    "IDOR": "idor",
}

# Pecker risk_level -> our severity
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    # Pecker may also emit numeric scores; handle in code
}


def _map_severity(risk_level: str, score: float = 0.0) -> str:
    """Map Pecker risk_level / score to our severity enum."""
    if risk_level and risk_level.lower() in _SEVERITY_MAP:
        return _SEVERITY_MAP[risk_level.lower()]
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _convert_pecker_finding(idx: int, detail: dict) -> dict:
    """Convert a single Pecker VulnDetail dict to our Finding schema."""
    vuln_type = _VULN_TYPE_MAP.get(
        detail.get("vul_type", ""), detail.get("vul_type", "unknown")
    )

    # Build call chain from call_sites
    call_chain = []
    for site in detail.get("call_sites", []):
        call_chain.append(
            {
                "method": site.get("signature", ""),
                "file": site.get("file_name", ""),
                "line": 0,  # Pecker doesn't always give line numbers
                "code": (site.get("method_body", "") or "")[:500],
            }
        )

    # Determine primary file from first call site or entry
    primary_file = ""
    if call_chain:
        primary_file = call_chain[0]["file"]
    entry = detail.get("entry", "")

    score = 0.0
    try:
        score = float(detail.get("confidence_score", 0))
    except (ValueError, TypeError):
        pass

    severity = _map_severity(detail.get("risk_level", ""), score)

    finding = {
        "id": f"PECKER-{idx:03d}",
        "type": vuln_type,
        "severity": severity,
        "title": f"{vuln_type.upper()}: {detail.get('sink', entry)[:80]}",
        "file_path": primary_file,
        "line_number": 0,
        "source": entry,
        "sink": detail.get("sink", ""),
        "call_chain": call_chain,
        "code_snippet": "",
        "description": (detail.get("original_analysis", "") or "")[:2000],
        "poc": detail.get("poc", ""),
        "remediation": "",
    }

    return finding


def _run_pecker_subprocess(
    pecker_path: str,
    project_path: str,
    output_path: str,
    model_type: str = "qwen-inner",
    model_name: str = "Qwen2.5-Coder-32B-Instruct",
    score_threshold: float = 5.0,
    timeout: int = 1800,
) -> str:
    """Run Pecker via entry.py and return stdout+stderr."""

    # Build input JSON for entry.py
    input_data = {
        "scanPath": project_path,
        "modelName": model_name,
        "timeFile": os.path.join(
            os.path.dirname(output_path), "pecker-time.json"
        ),
        "scoreThreshold": score_threshold,
    }

    input_file = os.path.join(os.path.dirname(output_path), "pecker-input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        json.dump(input_data, f)

    entry_py = os.path.join(pecker_path, "entry.py")
    if not os.path.isfile(entry_py):
        # Fallback to main.py invocation
        cmd = [
            "python3",
            os.path.join(pecker_path, "main.py"),
            "-r", project_path,
            "-n", "4",
            "-s", str(score_threshold),
            "-sink-llm", model_type,
            "-sink-llm-model", model_name,
            "-next-call", model_type,
            "-next-call-model", model_name,
            "-mm", model_type,
            "-mmn", model_name,
            "-ro", output_path,
            "--log-file", os.path.join(
                os.path.dirname(output_path), "pecker.log"
            ),
            "-tf", os.path.join(
                os.path.dirname(output_path), "pecker-time.json"
            ),
        ]
    else:
        cmd = [
            "python3",
            entry_py,
            "--input", input_file,
            "--output", output_path,
        ]

    logger.info("[pecker_scanner] running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=pecker_path,
        )
        output = result.stdout + result.stderr
        if result.returncode != 0:
            output += f"\n[exit code: {result.returncode}]"
        return output
    except subprocess.TimeoutExpired:
        return f"Error: Pecker timed out after {timeout}s"
    except Exception as e:
        return f"Error running Pecker: {e}"


@register_agent(
    name="pecker_scanner",
    layer=1,
    depends_on=["route_mapper"],
    timeout=1800,
    description="Run Pecker taint analysis scanner as subprocess",
)
async def run_pecker_scanner(config: AuditConfig, inputs: dict) -> dict:
    """Execute Pecker scanner and convert results to Finding schema."""
    if not config.pecker_path:
        logger.warning("[pecker_scanner] pecker_path not configured, skipping")
        return {"findings": []}

    pecker_path = os.path.abspath(config.pecker_path)
    if not os.path.isdir(pecker_path):
        logger.error("[pecker_scanner] pecker_path not found: %s", pecker_path)
        return {"findings": []}

    os.makedirs(config.output_dir, exist_ok=True)
    output_path = os.path.join(config.output_dir, "pecker-output.json")

    # Run Pecker in a thread to avoid blocking the event loop
    import asyncio

    loop = asyncio.get_running_loop()
    stdout = await loop.run_in_executor(
        None,
        _run_pecker_subprocess,
        pecker_path,
        config.project_path,
        output_path,
        config.pecker_model_type,
        config.pecker_model_name,
        5.0,  # score threshold
        1500,  # subprocess timeout (leave margin for stage timeout)
    )

    logger.info("[pecker_scanner] subprocess output: %s", stdout[:500])

    # Parse output JSON
    findings = []

    if os.path.isfile(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                pecker_result = json.load(f)

            details = pecker_result.get("detail", [])
            logger.info(
                "[pecker_scanner] Pecker found %d raw results (res_cnt=%s)",
                len(details),
                pecker_result.get("res_cnt", "?"),
            )

            for idx, detail in enumerate(details, start=1):
                # Skip results that Pecker itself judged as false
                re_judge = detail.get("re_judge_result", "")
                if re_judge == "False":
                    logger.debug(
                        "[pecker_scanner] skipping finding %d (re_judge=False)",
                        idx,
                    )
                    continue

                finding = _convert_pecker_finding(idx, detail)
                findings.append(finding)

        except (json.JSONDecodeError, IOError) as exc:
            logger.error("[pecker_scanner] failed to parse output: %s", exc)
    else:
        logger.warning("[pecker_scanner] output file not found: %s", output_path)

    logger.info("[pecker_scanner] produced %d findings", len(findings))
    return {"findings": findings}
