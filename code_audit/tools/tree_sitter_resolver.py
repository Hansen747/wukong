"""TreeSitterResolver — AST-level code symbol resolution using tree-sitter.

Provides more accurate symbol resolution than GrepResolver by parsing
source code into ASTs. Key advantages over grep:

1. **Exact method body extraction**: correctly handles nested braces,
   comments, and string literals
2. **Sink pre-filtering**: uses AST node types to identify function calls
   matching sink patterns (zero LLM cost)
3. **Accurate function call extraction**: parses method invocations
   from the AST rather than regex matching

Requires: ``pip install tree-sitter tree-sitter-java``

Falls back to GrepResolver if tree-sitter is not installed.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Optional

from .code_resolver import (
    CodeResolver,
    Definition,
    FunctionCall,
    Reference,
    TypeInfo,
    _NUMERIC_TYPES,
    _COLLECTION_TYPES,
)
from .file_tools import grep_content as grep_content_fn

logger = logging.getLogger(__name__)

try:
    import tree_sitter
    from tree_sitter import Language, Parser

    _HAS_TREE_SITTER = True
except ImportError:
    _HAS_TREE_SITTER = False
    logger.debug("tree-sitter not installed")

try:
    import tree_sitter_java

    _HAS_TS_JAVA = True
except ImportError:
    _HAS_TS_JAVA = False
    logger.debug("tree-sitter-java not installed")


# ---------------------------------------------------------------------------
# Sink pattern database for pre-filtering (mirrors Pecker's sink_*.txt)
# ---------------------------------------------------------------------------

# Format: "ClassName#MethodRegex" — if ClassName is empty, match any receiver
SINK_PATTERNS_JAVA = {
    "sqli": [
        ("Statement", r"executeQuery|executeUpdate|addBatch|executeLargeUpdate"),
        ("Connection", r"prepareStatement|prepareCall|nativeSQL"),
        ("EntityManager", r"createQuery|createNativeQuery"),
        ("JdbcTemplate", r"batchUpdate|execute|update|queryForList|queryForObject|query"),
        ("Session", r"createQuery|createSQLQuery|createNativeQuery"),
        ("SharedSessionContract", r"createQuery|createSQLQuery|createNativeQuery"),
        ("PageHelper", r"orderBy|setOrderBy"),
        ("Ebean", r"createSqlQuery|createSqlUpdate"),
        ("InfluxDB", r"query"),
    ],
    "rce": [
        ("Runtime", r"exec"),
        ("ProcessBuilder", r"__init__|start|command"),
        ("ScriptEngine", r"eval"),
        ("Expression", r"getValue"),
        ("ExpressionParser", r"parseExpression"),
    ],
    "xxe": [
        ("DocumentHelper", r"parseText"),
        ("SAXReader", r"read"),
        ("DocumentBuilder", r"parse"),
        ("XMLInputFactory", r"createXMLStreamReader"),
        ("SAXParser", r"parse"),
        ("SAXBuilder", r"build"),
        ("Transformer", r"transform"),
        ("XPathExpression", r"evaluate"),
        ("Unmarshaller", r"unmarshal"),
        ("XMLReader", r"parse"),
        ("Digester", r"parse|asyncParse"),
        ("Validator", r"validate"),
        ("SchemaFactory", r"newSchema"),
    ],
    "ssrf": [
        ("URL", r"openConnection|openStream"),
        ("HttpURLConnection", r"connect"),
        ("HttpClient", r"execute"),
        ("RestTemplate", r"getForObject|postForObject|exchange"),
        ("WebClient", r"get|post|put|delete"),
        ("OkHttpClient", r"newCall"),
    ],
}


class TreeSitterResolver(CodeResolver):
    """AST-level code symbol resolution using tree-sitter.

    Parses Java source files into syntax trees and provides accurate
    symbol resolution, function call extraction, and sink pre-filtering.
    """

    def __init__(self, project_path: str) -> None:
        super().__init__(project_path)

        if not _HAS_TREE_SITTER or not _HAS_TS_JAVA:
            raise ImportError(
                "tree-sitter and tree-sitter-java are required. "
                "Install with: pip install tree-sitter tree-sitter-java"
            )

        # Initialize Java parser
        self._java_language = Language(tree_sitter_java.language())
        self._parser = Parser(self._java_language)

        # Cache parsed files: file_path -> (mtime, tree)
        self._cache: dict[str, tuple[float, tree_sitter.Tree]] = {}

    # ------------------------------------------------------------------
    # File parsing with cache
    # ------------------------------------------------------------------

    def _parse_file(self, file_path: str) -> Optional[tree_sitter.Tree]:
        """Parse a Java file into a tree-sitter Tree, with caching."""
        if not os.path.isfile(file_path):
            return None

        mtime = os.path.getmtime(file_path)
        cached = self._cache.get(file_path)
        if cached and cached[0] == mtime:
            return cached[1]

        try:
            with open(file_path, "rb") as f:
                source = f.read()
            tree = self._parser.parse(source)
            self._cache[file_path] = (mtime, tree)
            return tree
        except Exception as exc:
            logger.debug("Failed to parse %s: %s", file_path, exc)
            return None

    def _read_source(self, file_path: str) -> Optional[bytes]:
        """Read source bytes for a file."""
        try:
            with open(file_path, "rb") as f:
                return f.read()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # AST query helpers
    # ------------------------------------------------------------------

    def _find_method_nodes(
        self, tree: tree_sitter.Tree, method_name: str
    ) -> list[tree_sitter.Node]:
        """Find method_declaration nodes matching the given name."""
        results = []
        query_text = f'(method_declaration name: (identifier) @name (#eq? @name "{method_name}"))'
        try:
            query = self._java_language.query(query_text)
            matches = query.matches(tree.root_node)
            for match in matches:
                for node_name, nodes in match[1].items():
                    for node in nodes:
                        # Get the parent method_declaration node
                        parent = node.parent
                        if parent and parent.type == "method_declaration":
                            results.append(parent)
        except Exception as exc:
            logger.debug("Query failed for method %s: %s", method_name, exc)
        return results

    def _find_class_nodes(
        self, tree: tree_sitter.Tree, class_name: str
    ) -> list[tree_sitter.Node]:
        """Find class_declaration nodes matching the given name."""
        results = []
        query_text = f'(class_declaration name: (identifier) @name (#eq? @name "{class_name}"))'
        try:
            query = self._java_language.query(query_text)
            matches = query.matches(tree.root_node)
            for match in matches:
                for node_name, nodes in match[1].items():
                    for node in nodes:
                        parent = node.parent
                        if parent and parent.type == "class_declaration":
                            results.append(parent)
        except Exception as exc:
            logger.debug("Query failed for class %s: %s", class_name, exc)
        return results

    def _extract_method_invocations(
        self, node: tree_sitter.Node, source: bytes
    ) -> list[FunctionCall]:
        """Extract all method invocation nodes from an AST subtree."""
        results = []
        seen: set[str] = set()

        query_text = "(method_invocation) @call"
        try:
            query = self._java_language.query(query_text)
            matches = query.matches(node)
            for match in matches:
                for _, call_nodes in match[1].items():
                    for call_node in call_nodes:
                        fc = self._parse_method_invocation(call_node, source)
                        if fc:
                            key = f"{fc.callee_class}.{fc.callee_name}"
                            if key not in seen:
                                seen.add(key)
                                results.append(fc)
        except Exception as exc:
            logger.debug("Failed to extract invocations: %s", exc)

        return results

    def _parse_method_invocation(
        self, node: tree_sitter.Node, source: bytes
    ) -> Optional[FunctionCall]:
        """Parse a method_invocation AST node into a FunctionCall."""
        try:
            # Get method name
            name_node = node.child_by_field_name("name")
            if not name_node:
                return None
            callee_name = source[name_node.start_byte:name_node.end_byte].decode("utf-8")

            # Get receiver (object)
            receiver = ""
            object_node = node.child_by_field_name("object")
            if object_node:
                receiver = source[object_node.start_byte:object_node.end_byte].decode("utf-8")
                # Simplify chains like "a.b.c" -> take last part
                if "." in receiver:
                    receiver = receiver.rsplit(".", 1)[-1]

            # Get arguments
            args_node = node.child_by_field_name("arguments")
            arguments = []
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ","):
                        arg_text = source[child.start_byte:child.end_byte].decode("utf-8")
                        arguments.append(arg_text)

            # Get line number
            line_number = node.start_point[0] + 1  # 0-indexed -> 1-indexed

            # Get code snippet (the full invocation line)
            code_snippet = source[node.start_byte:node.end_byte].decode("utf-8").strip()

            # Determine if internal
            is_internal = self._is_likely_internal(receiver, callee_name)

            return FunctionCall(
                callee_name=callee_name,
                callee_class=receiver,
                arguments=arguments,
                line_number=line_number,
                code_snippet=code_snippet,
                is_project_internal=is_internal,
            )
        except Exception:
            return None

    @staticmethod
    def _is_likely_internal(receiver: str, callee: str) -> bool:
        """Heuristic: is a function call likely project-internal?"""
        external_receivers = {
            "system", "string", "integer", "long", "math", "arrays",
            "collections", "objects", "optional", "stream",
            "logger", "log", "response", "request", "req", "res",
        }
        if receiver.lower() in external_receivers:
            return False

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

    # ------------------------------------------------------------------
    # Sink pre-filtering (zero LLM cost)
    # ------------------------------------------------------------------

    def pre_filter_sinks(
        self, file_path: str, method_name: str
    ) -> list[dict]:
        """Check if a method contains any known sink patterns.

        Returns a list of matched sinks with their vulnerability type.
        This is a zero-LLM-cost operation using only AST analysis.
        """
        tree = self._parse_file(file_path)
        if not tree:
            return []

        source = self._read_source(file_path)
        if not source:
            return []

        # Find the method
        method_nodes = self._find_method_nodes(tree, method_name)
        if not method_nodes:
            return []

        results = []
        for method_node in method_nodes:
            invocations = self._extract_method_invocations(method_node, source)
            for fc in invocations:
                for vuln_type, patterns in SINK_PATTERNS_JAVA.items():
                    for class_pattern, method_regex in patterns:
                        # Check class match (if receiver is available)
                        class_matches = (
                            not fc.callee_class
                            or fc.callee_class.endswith(class_pattern)
                            or class_pattern in fc.callee_class
                        )
                        # Check method match
                        method_matches = bool(
                            re.match(method_regex, fc.callee_name)
                        )
                        if class_matches and method_matches:
                            results.append({
                                "vuln_type": vuln_type,
                                "sink_class": class_pattern,
                                "sink_method": fc.callee_name,
                                "receiver": fc.callee_class,
                                "line_number": fc.line_number,
                                "code_snippet": fc.code_snippet,
                            })

        return results

    # ------------------------------------------------------------------
    # CodeResolver interface implementation
    # ------------------------------------------------------------------

    async def find_definition(
        self, symbol: str, context_file: str = ""
    ) -> list[Definition]:
        """Find definitions using AST parsing of Java files."""
        results: list[Definition] = []

        # Walk project for Java files
        for root, dirs, files in os.walk(self.project_path):
            # Skip excluded dirs
            dirs[:] = [
                d for d in dirs
                if d not in {".git", "node_modules", "target", "build", ".idea", "__pycache__"}
            ]
            for fname in files:
                if not fname.endswith(".java"):
                    continue
                file_path = os.path.join(root, fname)
                tree = self._parse_file(file_path)
                if not tree:
                    continue

                source = self._read_source(file_path)
                if not source:
                    continue

                # Try as method
                method_nodes = self._find_method_nodes(tree, symbol)
                for node in method_nodes:
                    line = node.start_point[0] + 1
                    snippet = source[node.start_byte:min(node.start_byte + 200, node.end_byte)].decode("utf-8", errors="replace")
                    # Take just the signature line
                    snippet = snippet.split("\n")[0].strip()
                    results.append(
                        Definition(
                            symbol=symbol,
                            file_path=file_path,
                            line_number=line,
                            code_snippet=snippet,
                            kind="method",
                        )
                    )

                # Try as class
                if not results or len(results) < 3:
                    class_nodes = self._find_class_nodes(tree, symbol)
                    for node in class_nodes:
                        line = node.start_point[0] + 1
                        snippet = source[node.start_byte:min(node.start_byte + 200, node.end_byte)].decode("utf-8", errors="replace")
                        snippet = snippet.split("\n")[0].strip()
                        results.append(
                            Definition(
                                symbol=symbol,
                                file_path=file_path,
                                line_number=line,
                                code_snippet=snippet,
                                kind="class",
                            )
                        )

        # Sort by relevance to context file
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
        """Find references by searching for identifier nodes in the AST."""
        results: list[Reference] = []

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [
                d for d in dirs
                if d not in {".git", "node_modules", "target", "build", ".idea", "__pycache__"}
            ]
            for fname in files:
                if not fname.endswith(".java"):
                    continue
                file_path = os.path.join(root, fname)
                tree = self._parse_file(file_path)
                if not tree:
                    continue

                source = self._read_source(file_path)
                if not source:
                    continue

                # Search for identifier nodes matching the symbol
                query_text = f'(identifier) @id (#eq? @id "{symbol}")'
                try:
                    query = self._java_language.query(query_text)
                    matches = query.matches(tree.root_node)
                    for match in matches:
                        for _, nodes in match[1].items():
                            for node in nodes:
                                line = node.start_point[0] + 1
                                # Get the full line
                                line_start = source.rfind(b"\n", 0, node.start_byte) + 1
                                line_end = source.find(b"\n", node.end_byte)
                                if line_end == -1:
                                    line_end = len(source)
                                snippet = source[line_start:line_end].decode("utf-8", errors="replace").strip()
                                results.append(
                                    Reference(
                                        symbol=symbol,
                                        file_path=file_path,
                                        line_number=line,
                                        code_snippet=snippet,
                                    )
                                )
                except Exception:
                    pass

            # Limit results
            if len(results) > 500:
                break

        return results

    async def extract_function_calls(
        self, file_path: str, method_name: str
    ) -> list[FunctionCall]:
        """Extract function calls from a method using AST parsing."""
        tree = self._parse_file(file_path)
        if not tree:
            return []

        source = self._read_source(file_path)
        if not source:
            return []

        method_nodes = self._find_method_nodes(tree, method_name)
        if not method_nodes:
            return []

        all_calls: list[FunctionCall] = []
        for method_node in method_nodes:
            calls = self._extract_method_invocations(method_node, source)
            all_calls.extend(calls)

        return all_calls

    async def get_type_info(
        self, symbol: str, context_file: str = ""
    ) -> Optional[TypeInfo]:
        """Get type info by finding variable/parameter declarations in the AST."""
        if not context_file:
            return None

        tree = self._parse_file(context_file)
        if not tree:
            return None

        source = self._read_source(context_file)
        if not source:
            return None

        # Search for formal_parameter or local_variable_declaration with the symbol
        # formal_parameter: type name
        queries = [
            f'(formal_parameter type: (_) @type name: (identifier) @name (#eq? @name "{symbol}"))',
            f'(local_variable_declaration type: (_) @type declarator: (variable_declarator name: (identifier) @name (#eq? @name "{symbol}")))',
            f'(field_declaration type: (_) @type declarator: (variable_declarator name: (identifier) @name (#eq? @name "{symbol}")))',
        ]

        for query_text in queries:
            try:
                query = self._java_language.query(query_text)
                matches = query.matches(tree.root_node)
                for match in matches:
                    type_nodes = match[1].get("type", [])
                    if type_nodes:
                        type_node = type_nodes[0]
                        type_name = source[type_node.start_byte:type_node.end_byte].decode("utf-8")
                        base_type = type_name.split("<")[0].strip()
                        return TypeInfo(
                            symbol=symbol,
                            type_name=type_name,
                            is_numeric=base_type in _NUMERIC_TYPES,
                            is_collection=base_type in _COLLECTION_TYPES,
                            is_string=base_type in ("String", "CharSequence", "StringBuilder", "StringBuffer"),
                        )
            except Exception:
                continue

        return None
