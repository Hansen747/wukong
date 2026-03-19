from dataclasses import dataclass, field
from typing import Any


@dataclass
class Stage:
    """A single execution stage in the DAG."""

    name: str  # Globally unique stage name
    agent_factory: Any  # async callable(config, inputs) -> dict
    depends_on: list[str] = field(default_factory=list)
    timeout: int = 600  # Timeout in seconds, default 10 min
