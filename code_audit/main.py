"""
Wukong Code Audit - CLI Entry Point

Usage::

    python -m code_audit <project_path> [options]

Example::

    python -m code_audit /path/to/project \\
        --provider openai \\
        --api-key "$QWEN_BAILIAN" \\
        --base-url "https://dashscope.aliyuncs.com/compatible-mode/v1" \\
        --model qwen-plus \\
        -o /tmp/my-audit \\
        -v
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time

from code_audit.config import AuditConfig
from code_audit.pipeline.dag import DAGScheduler
from code_audit.pipeline.stage import Stage
from code_audit.agents.registry import agent_registry

logger = logging.getLogger("code_audit")


# ------------------------------------------------------------------
# Import all agent modules so @register_agent decorators fire
# ------------------------------------------------------------------

def _import_agents() -> None:
    """Import every agent module to trigger @register_agent decorators."""
    import code_audit.agents.route_mapper       # noqa: F401
    import code_audit.agents.taint_analyzer     # noqa: F401
    import code_audit.agents.auth_auditor       # noqa: F401
    import code_audit.agents.hardcoded_auditor  # noqa: F401
    import code_audit.agents.path_traversal_auditor  # noqa: F401
    import code_audit.agents.vuln_verifier      # noqa: F401
    import code_audit.agents.report_generator   # noqa: F401


# ------------------------------------------------------------------
# DAG builder
# ------------------------------------------------------------------

def build_dag(config: AuditConfig) -> list[Stage]:
    """Query the agent registry and build Stage objects for the DAG."""
    stages: list[Stage] = []

    for meta in agent_registry.all():
        # Use agent-level timeout if set, else fall back to config-level
        timeout = meta.timeout
        if config.agent_timeout > 0:
            timeout = config.agent_timeout

        stages.append(
            Stage(
                name=meta.name,
                agent_factory=meta.factory,
                depends_on=list(meta.depends_on),
                timeout=timeout,
            )
        )

    # Log the stages we will run
    for s in stages:
        logger.debug(
            "Stage: %-20s depends_on=%-30s timeout=%ds",
            s.name,
            s.depends_on or "(none)",
            s.timeout,
        )

    return stages


# ------------------------------------------------------------------
# Pipeline runner
# ------------------------------------------------------------------

async def run_pipeline(config: AuditConfig) -> dict:
    """Build the DAG from the registry, execute it, and return results."""
    stages = build_dag(config)

    if not stages:
        logger.error("No agents registered; nothing to run.")
        return {}

    def on_stage_update(name: str, status: str) -> None:
        if status == "running":
            logger.info("[STAGE] %s  >>>  RUNNING", name)
        elif status == "success":
            logger.info("[STAGE] %s  >>>  SUCCESS", name)
        elif status == "failed":
            logger.error("[STAGE] %s  >>>  FAILED", name)
        elif status == "skipped":
            logger.warning("[STAGE] %s  >>>  SKIPPED", name)

    scheduler = DAGScheduler(stages, config, on_stage_update=on_stage_update)

    logger.info(
        "Starting pipeline with %d stages for project: %s",
        len(stages),
        config.project_path,
    )

    t0 = time.monotonic()
    results = await scheduler.run()
    elapsed = time.monotonic() - t0

    # Summary
    success = sum(1 for r in results.values() if r.status == "success")
    failed = sum(1 for r in results.values() if r.status == "failed")
    skipped = sum(1 for r in results.values() if r.status == "skipped")

    logger.info(
        "Pipeline finished in %.1fs — %d success, %d failed, %d skipped",
        elapsed,
        success,
        failed,
        skipped,
    )

    for name, result in results.items():
        if result.status == "failed":
            logger.error("  FAILED %s: %s", name, result.error)

    return results


# ------------------------------------------------------------------
# CLI argument parsing
# ------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="code_audit",
        description="Wukong (悟空) - DAG-based code vulnerability scanner",
    )

    parser.add_argument(
        "project_path",
        help="Root path of the project to audit",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="Output directory for audit results (default: /tmp/<project>-audit)",
    )

    parser.add_argument(
        "--provider",
        choices=["anthropic", "openai"],
        default="anthropic",
        help="LLM provider: 'anthropic' or 'openai' (default: anthropic)",
    )

    parser.add_argument(
        "-m",
        "--model",
        default=None,
        help="LLM model name (default: claude-sonnet-4-20250514 for anthropic, gpt-4o for openai)",
    )

    parser.add_argument(
        "--api-key",
        default=None,
        help="API key for the LLM provider (default: from env ANTHROPIC_API_KEY or OPENAI_API_KEY)",
    )

    parser.add_argument(
        "--base-url",
        default=None,
        help="Base URL for the LLM API (default: from env ANTHROPIC_BASE_URL or OPENAI_BASE_URL)",
    )

    parser.add_argument(
        "--max-turns",
        type=int,
        default=0,
        help="Max LLM turns per agent, 0=unlimited (default: 0)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Per-agent timeout in seconds, 0=use agent default (default: 0)",
    )

    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=3,
        help="Max concurrent agents within a DAG layer (default: 3)",
    )

    parser.add_argument(
        "--taint-group-size",
        type=int,
        default=10,
        help="Number of routes per taint analysis group (default: 10)",
    )

    parser.add_argument(
        "--taint-max-concurrent",
        type=int,
        default=3,
        help="Max concurrent taint analysis groups (default: 3)",
    )

    parser.add_argument(
        "--resolver",
        choices=["grep", "tree-sitter", "lsp"],
        default="grep",
        help="Code resolver backend: grep (default), tree-sitter, or lsp",
    )

    parser.add_argument(
        "--lsp-cmd",
        default=None,
        help="LSP server command (only used with --resolver lsp)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging",
    )

    return parser.parse_args(argv)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    """CLI entry point for ``python -m code_audit``."""
    args = parse_args(argv)

    # Logging setup
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Validate project path
    project_path = os.path.abspath(args.project_path)
    if not os.path.isdir(project_path):
        logger.error("Project path does not exist: %s", project_path)
        sys.exit(1)

    # Determine default model based on provider
    provider = args.provider
    model = args.model
    if model is None:
        model = "gpt-4o" if provider == "openai" else "claude-sonnet-4-20250514"

    # Build config
    config = AuditConfig(
        project_path=project_path,
        output_dir=args.output_dir,
        provider=provider,
        model=model,
        api_key=args.api_key,
        base_url=args.base_url,
        max_concurrent_agents=args.max_concurrent,
        agent_max_turns=args.max_turns,
        agent_timeout=args.timeout,
        taint_group_size=args.taint_group_size,
        taint_max_concurrent=args.taint_max_concurrent,
        resolver=args.resolver,
        lsp_cmd=args.lsp_cmd,
    )

    # Ensure output directory exists
    output_dir: str = config.output_dir or f"/tmp/{os.path.basename(config.project_path)}-audit"
    config.output_dir = output_dir
    os.makedirs(output_dir, exist_ok=True)

    logger.info("=" * 60)
    logger.info("  Wukong (悟空) Code Audit")
    logger.info("=" * 60)
    logger.info("  Project:     %s", config.project_path)
    logger.info("  Output:      %s", config.output_dir)
    logger.info("  Provider:    %s", config.provider)
    logger.info("  Model:       %s", config.model)
    logger.info("=" * 60)

    # Import agents (triggers @register_agent decorators)
    _import_agents()

    logger.info(
        "Registered agents: %s",
        ", ".join(agent_registry.names()),
    )

    # Run the pipeline
    asyncio.run(run_pipeline(config))


if __name__ == "__main__":
    main()
