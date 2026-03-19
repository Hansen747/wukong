"""Tool registry for agent tool management."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from .file_tools import append_file, glob_files, grep_content, read_file, write_file
from .bash_tools import run_command


class ToolRegistry:
    """Registry that stores tool definitions (Anthropic format) and handler functions.

    Provides factory classmethods to create pre-configured registries for
    different agent roles.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, dict] = {}
        self._handlers: Dict[str, Callable[..., str]] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: dict,
        handler: Callable[..., str],
    ) -> None:
        """Register a tool with its Anthropic-format definition and handler.

        Args:
            name: Unique tool name.
            description: Human-readable description of the tool.
            input_schema: JSON Schema dict describing the tool's parameters.
            handler: Callable that implements the tool logic.
        """
        self._tools[name] = {
            "name": name,
            "description": description,
            "input_schema": input_schema,
        }
        self._handlers[name] = handler

    def get_tools(self) -> List[dict]:
        """Return list of Anthropic-format tool definitions."""
        return list(self._tools.values())

    def execute(self, name: str, args: Dict[str, Any]) -> str:
        """Dispatch a tool call to its registered handler.

        Args:
            name: Name of the tool to execute.
            args: Keyword arguments to pass to the handler.

        Returns:
            String result from the handler, or an error message if the
            tool is not found or execution fails.
        """
        handler = self._handlers.get(name)
        if handler is None:
            return f"Error: unknown tool '{name}'"
        try:
            return handler(**args)
        except Exception as e:
            return f"Error executing tool '{name}': {e}"

    # ------------------------------------------------------------------
    # Factory classmethods
    # ------------------------------------------------------------------

    @classmethod
    def for_llm_agent(cls) -> ToolRegistry:
        """Return a registry pre-loaded with file operation tools only.

        Includes: read_file, glob_files, grep_content, write_file, append_file.
        """
        registry = cls()

        registry.register(
            name="read_file",
            description="Read a file's contents with line numbers. Supports offset and limit for large files.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to read.",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Number of lines to skip from the beginning (default 0).",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of lines to return (default 2000).",
                    },
                },
                "required": ["path"],
            },
            handler=read_file,
        )

        registry.register(
            name="glob_files",
            description="Find files matching a glob pattern recursively. Returns up to 200 results.",
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern to match (e.g. '**/*.java').",
                    },
                    "path": {
                        "type": "string",
                        "description": "Root directory to search from (default '.').",
                    },
                },
                "required": ["pattern"],
            },
            handler=glob_files,
        )

        registry.register(
            name="grep_content",
            description="Search file contents using a regular expression (case-insensitive). Skips .git, node_modules, target, build, .idea, and __pycache__ directories.",
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Root directory to search from (default '.').",
                    },
                    "file_type": {
                        "type": "string",
                        "description": "Optional file type filter (e.g. 'java', 'xml', 'py'). If empty, all files are searched.",
                    },
                },
                "required": ["pattern"],
            },
            handler=grep_content,
        )

        registry.register(
            name="write_file",
            description="Write content to a file. Parent directories are created automatically.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Destination file path.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write to the file.",
                    },
                },
                "required": ["path", "content"],
            },
            handler=write_file,
        )

        registry.register(
            name="append_file",
            description="Append content to a file. Parent directories are created automatically.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Destination file path.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to append to the file.",
                    },
                },
                "required": ["path", "content"],
            },
            handler=append_file,
        )

        return registry

    @classmethod
    def for_scanner_agent(cls) -> ToolRegistry:
        """Return a registry pre-loaded with file tools and shell execution.

        Includes everything from ``for_llm_agent`` plus ``run_command``.
        """
        registry = cls.for_llm_agent()

        registry.register(
            name="run_command",
            description="Execute a shell command and return stdout and stderr. Used primarily by pecker_scanner for running external analysis tools.",
            input_schema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Maximum execution time in seconds (default 120).",
                    },
                },
                "required": ["command"],
            },
            handler=run_command,
        )

        return registry
