"""CodeResolver abstraction layer — pluggable symbol resolution backends.

Provides a unified interface for resolving code symbols (definitions,
references, function calls, type info) with three backend implementations:

- **GrepResolver**: regex-based search (current default, zero dependencies)
- **TreeSitterResolver**: AST-level parsing with sink pre-filtering
- **LSPResolver**: compiler-level resolution (most precise, needs running LSP)

The resolver is selected via the ``--resolver`` CLI flag and configured in
``AuditConfig.resolver``.  Each resolver implements the same ``CodeResolver``
ABC, so agents can use whichever backend is available without changing their
logic.

Usage::

    resolver = create_resolver(config)
    defs = await resolver.find_definition("getUserById", "UserService.java")
    calls = await resolver.extract_function_calls("/path/to/File.java", "handleRequest")
"""

from __future__ import annotations

import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .file_tools import grep_content as grep_content_fn, read_file as read_file_fn

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Definition:
    """A resolved symbol definition."""
    symbol: str
    file_path: str
    line_number: int
    code_snippet: str
    kind: str = "unknown"  # "method", "class", "field", "variable"


@dataclass
class Reference:
    """A location where a symbol is referenced."""
    symbol: str
    file_path: str
    line_number: int
    code_snippet: str


@dataclass
class FunctionCall:
    """A function call extracted from a method body."""
    callee_name: str
    callee_class: str = ""
    arguments: list[str] = field(default_factory=list)
    line_number: int = 0
    code_snippet: str = ""
    is_project_internal: bool = True  # vs stdlib/framework


@dataclass
class TypeInfo:
    """Type information for a symbol."""
    symbol: str
    type_name: str
    is_numeric: bool = False  # int, long, Integer, Long, etc.
    is_collection: bool = False  # List, Map, Set, etc.
    is_string: bool = False


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class CodeResolver(ABC):
    """Abstract base class for code symbol resolution backends.

    All methods are async to support LSP (which involves I/O), even though
    grep and tree-sitter resolvers are synchronous under the hood.
    """

    def __init__(self, project_path: str) -> None:
        self.project_path = project_path

    @abstractmethod
    async def find_definition(
        self, symbol: str, context_file: str = ""
    ) -> list[Definition]:
        """Find definition(s) of a symbol in the codebase.

        Args:
            symbol: Name of the symbol to find (method name, class name, etc.)
            context_file: Optional file path providing context for disambiguation

        Returns:
            List of matching definitions, ordered by relevance.
        """
        ...

    @abstractmethod
    async def find_references(
        self, symbol: str, context_file: str = ""
    ) -> list[Reference]:
        """Find all references to a symbol in the codebase.

        Args:
            symbol: Name of the symbol to find references for
            context_file: Optional file path providing context

        Returns:
            List of locations where the symbol is referenced.
        """
        ...

    @abstractmethod
    async def extract_function_calls(
        self, file_path: str, method_name: str
    ) -> list[FunctionCall]:
        """Extract all function calls within a method body.

        Args:
            file_path: Path to the source file
            method_name: Name of the method to analyze

        Returns:
            List of function calls found in the method body.
        """
        ...

    @abstractmethod
    async def get_type_info(
        self, symbol: str, context_file: str = ""
    ) -> Optional[TypeInfo]:
        """Get type information for a symbol.

        Args:
            symbol: Name of the symbol
            context_file: File path providing context for type resolution

        Returns:
            TypeInfo if the type can be determined, None otherwise.
        """
        ...


# ---------------------------------------------------------------------------
# GrepResolver — regex-based (zero dependencies)
# ---------------------------------------------------------------------------

# Common Java numeric types
_NUMERIC_TYPES = {
    "int", "long", "short", "byte", "float", "double", "boolean",
    "Integer", "Long", "Short", "Byte", "Float", "Double", "Boolean",
    "BigInteger", "BigDecimal",
}

# Common Java collection types
_COLLECTION_TYPES = {
    "List", "ArrayList", "LinkedList", "Set", "HashSet", "TreeSet",
    "Map", "HashMap", "TreeMap", "LinkedHashMap", "ConcurrentHashMap",
    "Collection", "Queue", "Deque", "Vector", "Stack",
}

# Patterns for Java method definitions
_JAVA_METHOD_DEF_PATTERN = re.compile(
    r"(?:public|private|protected|static|final|abstract|synchronized|native|\s)*"
    r"\s+\w+(?:<[^>]+>)?\s+{method}\s*\(",
    re.MULTILINE,
)

# Pattern for Java class definitions
_JAVA_CLASS_DEF_PATTERN = re.compile(
    r"(?:public|private|protected|abstract|final|\s)*"
    r"\s*(?:class|interface|enum)\s+{symbol}",
    re.MULTILINE,
)


class GrepResolver(CodeResolver):
    """Regex-based symbol resolution using grep and file reading.

    This is the simplest resolver with zero external dependencies.
    It uses regex patterns to find definitions and references.
    Accuracy is lower than tree-sitter or LSP, but it works everywhere.
    """

    async def find_definition(
        self, symbol: str, context_file: str = ""
    ) -> list[Definition]:
        """Find definitions using regex grep patterns."""
        results: list[Definition] = []

        # Try method definition pattern
        method_pattern = (
            r"(?:public|private|protected|static|final|abstract|synchronized|native|\s)"
            rf".*\s+\w+(?:<[^>]+>)?\s+{re.escape(symbol)}\s*\("
        )
        grep_result = grep_content_fn(
            pattern=method_pattern,
            path=self.project_path,
            file_type="java",
        )

        if grep_result and "No matches found" not in grep_result:
            for line in grep_result.strip().split("\n"):
                parsed = self._parse_grep_line(line)
                if parsed:
                    file_path, line_no, snippet = parsed
                    results.append(
                        Definition(
                            symbol=symbol,
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            kind="method",
                        )
                    )

        # If no method matches, try class definition
        if not results:
            class_pattern = (
                r"(?:public|private|protected|abstract|final|\s)*"
                rf"\s*(?:class|interface|enum)\s+{re.escape(symbol)}"
            )
            grep_result = grep_content_fn(
                pattern=class_pattern,
                path=self.project_path,
                file_type="java",
            )
            if grep_result and "No matches found" not in grep_result:
                for line in grep_result.strip().split("\n"):
                    parsed = self._parse_grep_line(line)
                    if parsed:
                        file_path, line_no, snippet = parsed
                        results.append(
                            Definition(
                                symbol=symbol,
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                kind="class",
                            )
                        )

        # Sort by relevance: prefer matches in same package as context_file
        if context_file and len(results) > 1:
            context_dir = os.path.dirname(context_file)
            results.sort(
                key=lambda d: (
                    0 if d.file_path.startswith(context_dir) else 1,
                    d.file_path,
                )
            )

        return results

    async def find_references(
        self, symbol: str, context_file: str = ""
    ) -> list[Reference]:
        """Find references using simple grep for symbol name."""
        results: list[Reference] = []

        # Simple grep for the symbol name (will have false positives)
        grep_result = grep_content_fn(
            pattern=rf"\b{re.escape(symbol)}\b",
            path=self.project_path,
            file_type="java",
        )

        if grep_result and "No matches found" not in grep_result:
            for line in grep_result.strip().split("\n"):
                if line.startswith("..."):
                    break
                parsed = self._parse_grep_line(line)
                if parsed:
                    file_path, line_no, snippet = parsed
                    results.append(
                        Reference(
                            symbol=symbol,
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                        )
                    )

        return results

    async def extract_function_calls(
        self, file_path: str, method_name: str
    ) -> list[FunctionCall]:
        """Extract function calls from a method body using regex.

        This is a best-effort extraction. It reads the method body
        and finds patterns like ``obj.method(`` or ``method(``.
        """
        results: list[FunctionCall] = []

        # Read the file
        file_content = read_file_fn(file_path)
        if file_content.startswith("Error"):
            return results

        # Find the method body
        lines = file_content.split("\n")
        method_start = -1
        for i, line in enumerate(lines):
            # Strip line number prefix
            content = line.split(": ", 1)[1] if ": " in line else line
            if re.search(rf"\b{re.escape(method_name)}\s*\(", content):
                # Check it looks like a definition (has return type before it)
                if re.search(
                    r"(?:public|private|protected|static|void|\w+(?:<[^>]+>)?)\s+"
                    rf"{re.escape(method_name)}\s*\(",
                    content,
                ):
                    method_start = i
                    break

        if method_start < 0:
            return results

        # Extract method body (find matching braces)
        brace_depth = 0
        in_body = False
        body_lines: list[tuple[int, str]] = []

        for i in range(method_start, len(lines)):
            content = lines[i].split(": ", 1)[1] if ": " in lines[i] else lines[i]
            for ch in content:
                if ch == "{":
                    brace_depth += 1
                    in_body = True
                elif ch == "}":
                    brace_depth -= 1

            if in_body:
                body_lines.append((i + 1, content))  # 1-based line number

            if in_body and brace_depth == 0:
                break

        # Extract function call patterns from body
        call_pattern = re.compile(
            r"(?:(\w+)\.)?(\w+)\s*\("
        )
        seen: set[str] = set()

        for line_no, content in body_lines:
            for match in call_pattern.finditer(content):
                receiver = match.group(1) or ""
                callee = match.group(2)

                # Skip common non-function patterns
                if callee in ("if", "for", "while", "switch", "catch", "return",
                              "new", "throw", "assert", "synchronized"):
                    continue

                call_key = f"{receiver}.{callee}" if receiver else callee
                if call_key in seen:
                    continue
                seen.add(call_key)

                # Determine if it's likely project-internal
                is_internal = self._is_likely_internal(receiver, callee)

                results.append(
                    FunctionCall(
                        callee_name=callee,
                        callee_class=receiver,
                        line_number=line_no,
                        code_snippet=content.strip(),
                        is_project_internal=is_internal,
                    )
                )

        return results

    async def get_type_info(
        self, symbol: str, context_file: str = ""
    ) -> Optional[TypeInfo]:
        """Get type info by searching for variable/parameter declarations."""
        if not context_file:
            return None

        file_content = read_file_fn(context_file)
        if file_content.startswith("Error"):
            return None

        # Look for parameter or variable declarations
        # Pattern: Type symbol or Type<Generic> symbol
        pattern = re.compile(
            rf"(\w+(?:<[^>]+>)?)\s+{re.escape(symbol)}\b"
        )

        for line in file_content.split("\n"):
            content = line.split(": ", 1)[1] if ": " in line else line
            m = pattern.search(content)
            if m:
                type_name = m.group(1)
                base_type = type_name.split("<")[0]  # strip generics
                return TypeInfo(
                    symbol=symbol,
                    type_name=type_name,
                    is_numeric=base_type in _NUMERIC_TYPES,
                    is_collection=base_type in _COLLECTION_TYPES,
                    is_string=base_type in ("String", "CharSequence", "StringBuilder", "StringBuffer"),
                )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_grep_line(line: str) -> Optional[tuple[str, int, str]]:
        """Parse a grep output line: 'file:line: content' -> (file, line, content)."""
        # Format: /path/to/file.java:42: code here
        m = re.match(r"^(.+?):(\d+):\s*(.*)$", line)
        if m:
            return m.group(1), int(m.group(2)), m.group(3)
        return None

    @staticmethod
    def _is_likely_internal(receiver: str, callee: str) -> bool:
        """Heuristic: is a function call likely project-internal?"""
        # Common framework/stdlib receivers
        external_receivers = {
            "System", "String", "Integer", "Long", "Math", "Arrays",
            "Collections", "Objects", "Optional", "Stream",
            "Logger", "log", "logger", "LOG",
            "response", "request", "req", "res", "resp",
        }
        if receiver.lower() in {r.lower() for r in external_receivers}:
            return False

        # Common framework methods
        external_methods = {
            "toString", "equals", "hashCode", "valueOf", "parseInt",
            "parseLong", "parseDouble", "format", "println", "print",
            "debug", "info", "warn", "error", "trace",
            "get", "set", "put", "add", "remove", "contains",
            "size", "isEmpty", "length", "trim", "split",
            "toLowerCase", "toUpperCase", "substring", "replace",
            "startsWith", "endsWith", "matches", "append",
            "close", "flush",
        }
        if callee in external_methods:
            return False

        return True


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------

def create_resolver(project_path: str, resolver_type: str = "grep", **kwargs) -> CodeResolver:
    """Create a CodeResolver instance based on the resolver type.

    Args:
        project_path: Root path of the project to analyze
        resolver_type: "grep", "tree-sitter", or "lsp"
        **kwargs: Additional arguments for specific resolvers
            - lsp_cmd: LSP server command (for "lsp" resolver)

    Returns:
        A CodeResolver instance.

    Raises:
        ValueError: If the resolver type is unknown.
        ImportError: If required dependencies are not installed.
    """
    if resolver_type == "grep":
        return GrepResolver(project_path)

    elif resolver_type == "tree-sitter":
        try:
            from .tree_sitter_resolver import TreeSitterResolver
            return TreeSitterResolver(project_path)
        except ImportError:
            logger.warning(
                "tree-sitter not installed, falling back to GrepResolver. "
                "Install with: pip install tree-sitter tree-sitter-java"
            )
            return GrepResolver(project_path)

    elif resolver_type == "lsp":
        try:
            from .lsp_resolver import LSPResolver
            lsp_cmd = kwargs.get("lsp_cmd")
            if not lsp_cmd:
                raise ValueError("--lsp-cmd is required when using --resolver lsp")
            return LSPResolver(project_path, lsp_cmd=lsp_cmd)
        except ImportError:
            logger.warning(
                "LSP resolver dependencies not available, falling back to GrepResolver."
            )
            return GrepResolver(project_path)

    else:
        raise ValueError(f"Unknown resolver type: {resolver_type!r}")
