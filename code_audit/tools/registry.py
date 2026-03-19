"""Tool registry for agent tool management."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from .file_tools import append_file, glob_files, grep_content, read_file, write_file
from .bash_tools import run_command
from .code_resolver import CodeResolver


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
    def for_llm_agent(cls, resolver: Optional[CodeResolver] = None) -> ToolRegistry:
        """Return a registry pre-loaded with file operation tools.

        Includes: read_file, glob_files, grep_content, write_file, append_file.
        If a CodeResolver is provided, also registers find_definition,
        find_references, extract_function_calls, and get_type_info tools.

        Args:
            resolver: Optional CodeResolver instance for code symbol resolution.
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

        # Register CodeResolver tools if a resolver is provided
        if resolver is not None:
            _register_resolver_tools(registry, resolver)

        return registry

    @classmethod
    def for_scanner_agent(cls, resolver: Optional[CodeResolver] = None) -> ToolRegistry:
        """Return a registry pre-loaded with file tools and shell execution.

        Includes everything from ``for_llm_agent`` plus ``run_command``.
        """
        registry = cls.for_llm_agent(resolver=resolver)

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


# ---------------------------------------------------------------------------
# Resolver tool registration helpers
# ---------------------------------------------------------------------------

def _register_resolver_tools(registry: ToolRegistry, resolver: CodeResolver) -> None:
    """Register CodeResolver-backed tools on a ToolRegistry.

    These tools wrap the async CodeResolver methods as synchronous
    handlers. Since tool handlers are called from within an async
    event loop (AuditAgent.run), we use a dedicated thread with its
    own event loop to run the async resolver methods.
    """
    import asyncio
    import concurrent.futures

    # Thread pool for running async resolver methods from sync context
    _executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    def _run_async_sync(coro):
        """Run an async coroutine synchronously, even from within an async context.

        Creates a new event loop in a background thread to avoid
        'cannot call asyncio.run() from a running event loop' errors.
        """
        def _run():
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

        try:
            # Check if we're in an async context
            asyncio.get_running_loop()
            # We are — run in a thread with its own event loop
            future = _executor.submit(_run)
            return future.result(timeout=30)
        except RuntimeError:
            # No running loop — safe to use asyncio.run
            return asyncio.run(coro)

    def find_definition(symbol: str, context_file: str = "") -> str:
        """Find definition(s) of a code symbol."""
        try:
            results = _run_async_sync(resolver.find_definition(symbol, context_file))
            if not results:
                return f"No definitions found for '{symbol}'"
            output_lines = []
            for d in results:
                output_lines.append(
                    f"{d.file_path}:{d.line_number} [{d.kind}]: {d.code_snippet}"
                )
            return "\n".join(output_lines)
        except Exception as e:
            return f"Error finding definition: {e}"

    def find_references(symbol: str, context_file: str = "") -> str:
        """Find all references to a symbol."""
        try:
            results = _run_async_sync(resolver.find_references(symbol, context_file))
            if not results:
                return f"No references found for '{symbol}'"
            output_lines = []
            for r in results[:100]:  # limit output
                output_lines.append(
                    f"{r.file_path}:{r.line_number}: {r.code_snippet}"
                )
            if len(results) > 100:
                output_lines.append(f"... ({len(results) - 100} more references)")
            return "\n".join(output_lines)
        except Exception as e:
            return f"Error finding references: {e}"

    def extract_function_calls(file_path: str, method_name: str) -> str:
        """Extract function calls from a method body."""
        try:
            results = _run_async_sync(
                resolver.extract_function_calls(file_path, method_name)
            )
            if not results:
                return f"No function calls found in {method_name}"
            output_lines = []
            for fc in results:
                prefix = f"{fc.callee_class}." if fc.callee_class else ""
                internal = "internal" if fc.is_project_internal else "external"
                output_lines.append(
                    f"  L{fc.line_number}: {prefix}{fc.callee_name}() [{internal}]"
                    f"  // {fc.code_snippet}"
                )
            return "\n".join(output_lines)
        except Exception as e:
            return f"Error extracting function calls: {e}"

    def get_type_info(symbol: str, context_file: str = "") -> str:
        """Get type information for a symbol."""
        try:
            result = _run_async_sync(resolver.get_type_info(symbol, context_file))
            if result is None:
                return f"Could not determine type for '{symbol}'"
            info = {
                "symbol": result.symbol,
                "type": result.type_name,
                "is_numeric": result.is_numeric,
                "is_string": result.is_string,
                "is_collection": result.is_collection,
            }
            return json.dumps(info, indent=2)
        except Exception as e:
            return f"Error getting type info: {e}"

    # Register each tool
    registry.register(
        name="find_definition",
        description=(
            "Find the definition(s) of a code symbol (method, class, field) "
            "in the project. Returns file paths and line numbers."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "Name of the symbol to find (e.g. 'getUserById', 'UserService').",
                },
                "context_file": {
                    "type": "string",
                    "description": "Optional file path for disambiguation (helps find definitions in the same package).",
                },
            },
            "required": ["symbol"],
        },
        handler=find_definition,
    )

    registry.register(
        name="find_references",
        description=(
            "Find all locations where a symbol is referenced in the project. "
            "Returns file paths and line numbers."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "Name of the symbol to find references for.",
                },
                "context_file": {
                    "type": "string",
                    "description": "Optional file path for context.",
                },
            },
            "required": ["symbol"],
        },
        handler=find_references,
    )

    registry.register(
        name="extract_function_calls",
        description=(
            "Extract all function calls within a method body. Returns each "
            "call with its line number, receiver class, and whether it is "
            "project-internal or external (stdlib/framework). Useful for "
            "identifying which sub-functions to trace deeper."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the source file containing the method.",
                },
                "method_name": {
                    "type": "string",
                    "description": "Name of the method to analyze.",
                },
            },
            "required": ["file_path", "method_name"],
        },
        handler=extract_function_calls,
    )

    registry.register(
        name="get_type_info",
        description=(
            "Get type information for a variable or parameter. Returns whether "
            "it is numeric (safe from string injection), a collection, or a "
            "string type."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "Name of the variable or parameter.",
                },
                "context_file": {
                    "type": "string",
                    "description": "File path where the variable is used.",
                },
            },
            "required": ["symbol"],
        },
        handler=get_type_info,
    )
