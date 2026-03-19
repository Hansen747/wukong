"""Extensible agent plugin registry.

Agents register themselves via the ``@register_agent`` decorator or by
calling ``AgentRegistry.register()`` directly.  The DAG builder in
``main.py`` queries the registry to look up agent factory functions by
name, making it trivial to add new detection modules without touching
the pipeline code.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Coroutine, Dict, Optional

logger = logging.getLogger(__name__)

# Type alias for an agent factory: async def (config, inputs) -> dict
AgentFactory = Callable[..., Coroutine[Any, Any, dict]]


class _AgentMeta:
    """Metadata about a registered agent."""

    __slots__ = ("name", "factory", "layer", "depends_on", "timeout", "description")

    def __init__(
        self,
        name: str,
        factory: AgentFactory,
        layer: int = 1,
        depends_on: Optional[list[str]] = None,
        timeout: int = 1800,
        description: str = "",
    ) -> None:
        self.name = name
        self.factory = factory
        self.layer = layer
        self.depends_on = depends_on or []
        self.timeout = timeout
        self.description = description


class AgentRegistry:
    """Global singleton registry for audit agents.

    Usage::

        from code_audit.agents.registry import agent_registry, register_agent

        @register_agent(
            name="my_checker",
            layer=1,
            depends_on=["route_mapper"],
            timeout=900,
            description="Custom checker for XYZ",
        )
        async def run_my_checker(config, inputs):
            ...
            return {"findings": [...]}

    Then in ``main.py``::

        meta = agent_registry.get("my_checker")
        stages.append(Stage(
            name=meta.name,
            agent_factory=meta.factory,
            depends_on=meta.depends_on,
            timeout=meta.timeout,
        ))
    """

    def __init__(self) -> None:
        self._agents: Dict[str, _AgentMeta] = {}

    def register(
        self,
        name: str,
        factory: AgentFactory,
        *,
        layer: int = 1,
        depends_on: Optional[list[str]] = None,
        timeout: int = 1800,
        description: str = "",
    ) -> None:
        """Register an agent factory function under *name*."""
        if name in self._agents:
            logger.warning("Overwriting existing agent registration: %s", name)
        self._agents[name] = _AgentMeta(
            name=name,
            factory=factory,
            layer=layer,
            depends_on=depends_on,
            timeout=timeout,
            description=description,
        )
        logger.debug("Registered agent: %s (layer=%d)", name, layer)

    def get(self, name: str) -> Optional[_AgentMeta]:
        """Look up a registered agent by *name*."""
        return self._agents.get(name)

    def all(self) -> list[_AgentMeta]:
        """Return all registered agents sorted by (layer, name)."""
        return sorted(self._agents.values(), key=lambda m: (m.layer, m.name))

    def names(self) -> list[str]:
        """Return all registered agent names."""
        return list(self._agents.keys())

    def by_layer(self, layer: int) -> list[_AgentMeta]:
        """Return agents registered at a specific layer."""
        return [m for m in self._agents.values() if m.layer == layer]


# ---------------------------------------------------------------------------
# Module-level singleton and decorator
# ---------------------------------------------------------------------------

agent_registry = AgentRegistry()


def register_agent(
    name: str,
    *,
    layer: int = 1,
    depends_on: Optional[list[str]] = None,
    timeout: int = 1800,
    description: str = "",
) -> Callable[[AgentFactory], AgentFactory]:
    """Decorator that registers an async agent factory function.

    Example::

        @register_agent("my_agent", layer=1, depends_on=["route_mapper"])
        async def run_my_agent(config, inputs):
            ...
    """

    def _decorator(fn: AgentFactory) -> AgentFactory:
        agent_registry.register(
            name=name,
            factory=fn,
            layer=layer,
            depends_on=depends_on,
            timeout=timeout,
            description=description,
        )
        return fn

    return _decorator
