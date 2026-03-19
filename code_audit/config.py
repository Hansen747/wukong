"""
Wukong Code Audit - Global Configuration

All agents and the pipeline share this configuration.
Supports CLI argument injection and environment variable fallback.
"""

import os
from typing import Literal, Optional

from pydantic import BaseModel


class AuditConfig(BaseModel):
    """
    Audit pipeline configuration shared by all agents and the pipeline.
    """
    # [Required] Project source code root path
    project_path: str

    # Output directory for audit results
    output_dir: Optional[str] = None

    # LLM provider: "anthropic" or "openai"
    provider: Literal["anthropic", "openai"] = "anthropic"

    # LLM model name
    model: str = "claude-sonnet-4-20250514"

    # API Key (works for both providers)
    api_key: Optional[str] = None

    # API base URL (works for both providers)
    base_url: Optional[str] = None

    # Max concurrent agents
    max_concurrent_agents: int = 3

    # Agent max LLM turns, 0 = unlimited
    agent_max_turns: int = 0

    # Agent timeout seconds, 0 = no timeout
    agent_timeout: int = 0

    def model_post_init(self, __context):
        """
        Post-init hook:
        1. Resolve API key from env if not passed
        2. Resolve base URL from env if not passed
        3. Auto-generate output_dir if not passed
        """
        if not self.api_key:
            if self.provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY")
            else:
                self.api_key = (
                    os.environ.get("ANTHROPIC_API_KEY")
                    or os.environ.get("ANTHROPIC_AUTH_TOKEN")
                )
        if not self.base_url:
            if self.provider == "openai":
                self.base_url = os.environ.get("OPENAI_BASE_URL")
            else:
                self.base_url = os.environ.get("ANTHROPIC_BASE_URL")
        if not self.output_dir:
            project_name = os.path.basename(self.project_path.rstrip("/"))
            self.output_dir = os.path.join("/tmp", f"{project_name}-audit")
