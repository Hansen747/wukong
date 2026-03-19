from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .stage import Stage

logger = logging.getLogger(__name__)


@dataclass
class StageResult:
    """Result produced by a single DAG stage."""

    name: str
    status: str  # "success" | "failed" | "skipped"
    data: Any = None
    error: str = ""


class DAGScheduler:
    """Execute a DAG of *Stage* objects respecting dependency order.

    Stages within the same topological layer run concurrently via
    ``asyncio.gather``.  A stage whose dependency failed is automatically
    skipped.
    """

    def __init__(
        self,
        stages: list[Stage],
        config: Any,
        on_stage_update: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._stages: dict[str, Stage] = {s.name: s for s in stages}
        self._config = config
        self._on_stage_update = on_stage_update
        self._results: dict[str, StageResult] = {}

    # ------------------------------------------------------------------
    # Callback helper
    # ------------------------------------------------------------------

    async def _notify(self, name: str, status: str) -> None:
        """Invoke the optional *on_stage_update* callback safely."""
        if self._on_stage_update is None:
            return
        try:
            ret = self._on_stage_update(name, status)
            if asyncio.iscoroutine(ret):
                await ret
        except Exception:
            logger.warning("on_stage_update callback raised for %s", name, exc_info=True)

    # ------------------------------------------------------------------
    # Topological sort – Kahn's algorithm
    # ------------------------------------------------------------------

    def _topo_layers(self) -> list[list[str]]:
        """Return stages grouped into topological layers.

        Each inner list contains stage names that may execute in parallel
        (all their dependencies belong to earlier layers).

        Raises ``ValueError`` if the graph contains a cycle.
        """
        in_degree: dict[str, int] = {name: 0 for name in self._stages}
        dependents: dict[str, list[str]] = defaultdict(list)

        for name, stage in self._stages.items():
            for dep in stage.depends_on:
                if dep not in self._stages:
                    raise ValueError(
                        f"Stage '{name}' depends on unknown stage '{dep}'"
                    )
                dependents[dep].append(name)
                in_degree[name] += 1

        queue: deque[str] = deque(
            name for name, deg in in_degree.items() if deg == 0
        )
        layers: list[list[str]] = []

        while queue:
            layer = list(queue)
            queue.clear()
            layers.append(layer)
            for name in layer:
                for child in dependents[name]:
                    in_degree[child] -= 1
                    if in_degree[child] == 0:
                        queue.append(child)

        scheduled = sum(len(l) for l in layers)
        if scheduled != len(self._stages):
            raise ValueError("DAG contains a cycle")

        return layers

    # ------------------------------------------------------------------
    # Single-stage runner
    # ------------------------------------------------------------------

    async def _run_stage(self, name: str) -> StageResult:
        """Execute one stage after verifying its dependencies succeeded."""
        stage = self._stages[name]

        # Check that every dependency completed successfully.
        for dep in stage.depends_on:
            dep_result = self._results.get(dep)
            if dep_result is None or dep_result.status != "success":
                reason = (
                    f"dependency '{dep}' "
                    f"{'not executed' if dep_result is None else dep_result.status}"
                )
                logger.info("Skipping stage '%s': %s", name, reason)
                result = StageResult(
                    name=name,
                    status="skipped",
                    error=f"Skipped because {reason}",
                )
                self._results[name] = result
                await self._notify(name, result.status)
                return result

        # Gather input data from dependencies.
        inputs: dict[str, Any] = {
            dep: self._results[dep].data for dep in stage.depends_on
        }

        await self._notify(name, "running")

        try:
            data = await asyncio.wait_for(
                stage.agent_factory(self._config, inputs),
                timeout=stage.timeout,
            )
            result = StageResult(name=name, status="success", data=data)
        except asyncio.TimeoutError:
            msg = f"Stage '{name}' timed out after {stage.timeout}s"
            logger.error(msg)
            result = StageResult(name=name, status="failed", error=msg)
        except Exception as exc:
            msg = f"Stage '{name}' raised {type(exc).__name__}: {exc}"
            logger.error(msg, exc_info=True)
            result = StageResult(name=name, status="failed", error=msg)

        self._results[name] = result
        await self._notify(name, result.status)
        return result

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> dict[str, StageResult]:
        """Execute the full DAG, layer by layer.

        Returns a mapping of stage name -> ``StageResult``.
        """
        layers = self._topo_layers()

        for layer in layers:
            await asyncio.gather(*(self._run_stage(name) for name in layer))

        return dict(self._results)
