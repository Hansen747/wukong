"""LSPResolver — Compiler-level code symbol resolution via Language Server Protocol.

Provides the most precise symbol resolution by communicating with a running
LSP server (e.g., jdtls for Java, gopls for Go). This resolver:

1. Starts an LSP server subprocess
2. Sends textDocument/definition, textDocument/references queries
3. Gets compiler-accurate results including type information

Requires a running LSP server binary. Configure via ``--lsp-cmd``.

Example::

    # For Java (Eclipse JDT Language Server):
    python -m code_audit /path/to/project \\
        --resolver lsp \\
        --lsp-cmd "jdtls -data /tmp/jdtls-workspace"

    # For Go:
    python -m code_audit /path/to/project \\
        --resolver lsp \\
        --lsp-cmd "gopls"
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
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
from .file_tools import read_file as read_file_fn

logger = logging.getLogger(__name__)


class LSPResolver(CodeResolver):
    """Compiler-level symbol resolution via Language Server Protocol.

    Communicates with an LSP server subprocess using JSON-RPC over stdio.
    Provides the most accurate symbol resolution but requires:
    1. An LSP server binary installed (e.g., jdtls, gopls)
    2. The project to be buildable (dependencies resolved)

    The resolver lazily initializes the LSP server on first use and
    shuts it down when the resolver is garbage collected.
    """

    def __init__(self, project_path: str, lsp_cmd: str) -> None:
        super().__init__(project_path)
        self._lsp_cmd = lsp_cmd
        self._process: Optional[subprocess.Popen] = None
        self._request_id = 0
        self._initialized = False
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # LSP lifecycle
    # ------------------------------------------------------------------

    async def _ensure_initialized(self) -> bool:
        """Start and initialize the LSP server if not already running."""
        async with self._lock:
            if self._initialized:
                return True

            try:
                logger.info("[LSPResolver] Starting LSP server: %s", self._lsp_cmd)

                # Split command into parts
                cmd_parts = self._lsp_cmd.split()

                self._process = subprocess.Popen(
                    cmd_parts,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=self.project_path,
                )

                # Send initialize request
                init_result = await self._send_request("initialize", {
                    "processId": os.getpid(),
                    "rootUri": f"file://{os.path.abspath(self.project_path)}",
                    "capabilities": {
                        "textDocument": {
                            "definition": {"dynamicRegistration": False},
                            "references": {"dynamicRegistration": False},
                            "hover": {"dynamicRegistration": False},
                        }
                    },
                    "workspaceFolders": [
                        {
                            "uri": f"file://{os.path.abspath(self.project_path)}",
                            "name": os.path.basename(self.project_path),
                        }
                    ],
                })

                if init_result is None:
                    logger.error("[LSPResolver] Initialize failed")
                    return False

                # Send initialized notification
                await self._send_notification("initialized", {})

                self._initialized = True
                logger.info("[LSPResolver] LSP server initialized successfully")
                return True

            except FileNotFoundError:
                logger.error(
                    "[LSPResolver] LSP server command not found: %s",
                    self._lsp_cmd,
                )
                return False
            except Exception as exc:
                logger.error("[LSPResolver] Failed to start LSP server: %s", exc)
                return False

    def _shutdown(self) -> None:
        """Shut down the LSP server."""
        if self._process:
            try:
                # Send shutdown request
                self._request_id += 1
                msg = self._encode_message({
                    "jsonrpc": "2.0",
                    "id": self._request_id,
                    "method": "shutdown",
                    "params": None,
                })
                self._process.stdin.write(msg)
                self._process.stdin.flush()

                # Send exit notification
                msg = self._encode_message({
                    "jsonrpc": "2.0",
                    "method": "exit",
                    "params": None,
                })
                self._process.stdin.write(msg)
                self._process.stdin.flush()

                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                if self._process:
                    self._process.kill()
            finally:
                self._process = None
                self._initialized = False

    def __del__(self):
        self._shutdown()

    # ------------------------------------------------------------------
    # JSON-RPC communication
    # ------------------------------------------------------------------

    @staticmethod
    def _encode_message(obj: dict) -> bytes:
        """Encode a JSON-RPC message with Content-Length header."""
        body = json.dumps(obj).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        return header + body

    def _read_message(self) -> Optional[dict]:
        """Read a JSON-RPC message from the LSP server stdout."""
        if not self._process or not self._process.stdout:
            return None

        try:
            # Read headers
            headers = {}
            while True:
                line = self._process.stdout.readline()
                if not line:
                    return None
                line = line.decode("ascii").strip()
                if not line:
                    break  # empty line = end of headers
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()

            content_length = int(headers.get("Content-Length", 0))
            if content_length == 0:
                return None

            body = self._process.stdout.read(content_length)
            return json.loads(body.decode("utf-8"))
        except Exception as exc:
            logger.debug("[LSPResolver] Error reading message: %s", exc)
            return None

    async def _send_request(self, method: str, params: dict) -> Optional[dict]:
        """Send a JSON-RPC request and wait for the response."""
        if not self._process:
            return None

        self._request_id += 1
        request_id = self._request_id

        msg = self._encode_message({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        })

        try:
            self._process.stdin.write(msg)
            self._process.stdin.flush()

            # Read responses until we get ours (skip notifications)
            for _ in range(100):  # timeout after 100 messages
                response = await asyncio.get_event_loop().run_in_executor(
                    None, self._read_message
                )
                if response is None:
                    return None
                if response.get("id") == request_id:
                    return response.get("result")
                # Skip notifications and other responses
        except Exception as exc:
            logger.debug("[LSPResolver] Request error: %s", exc)

        return None

    async def _send_notification(self, method: str, params: dict) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        if not self._process:
            return

        msg = self._encode_message({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        })

        try:
            self._process.stdin.write(msg)
            self._process.stdin.flush()
        except Exception as exc:
            logger.debug("[LSPResolver] Notification error: %s", exc)

    # ------------------------------------------------------------------
    # Helper: file URI / position conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _file_uri(path: str) -> str:
        """Convert a file path to a file:// URI."""
        return f"file://{os.path.abspath(path)}"

    @staticmethod
    def _uri_to_path(uri: str) -> str:
        """Convert a file:// URI to a file path."""
        if uri.startswith("file://"):
            return uri[7:]
        return uri

    def _find_symbol_position(
        self, file_path: str, symbol: str
    ) -> Optional[tuple[int, int]]:
        """Find the (line, column) of a symbol in a file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f):
                    col = line.find(symbol)
                    if col >= 0:
                        return (line_no, col)  # 0-indexed
        except Exception:
            pass
        return None

    def _get_line_content(self, file_path: str, line_no: int) -> str:
        """Get the content of a specific line (1-indexed)."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, start=1):
                    if i == line_no:
                        return line.strip()
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    # CodeResolver interface implementation
    # ------------------------------------------------------------------

    async def find_definition(
        self, symbol: str, context_file: str = ""
    ) -> list[Definition]:
        """Find definitions using LSP textDocument/definition."""
        if not await self._ensure_initialized():
            logger.warning("[LSPResolver] Not initialized, falling back to grep")
            from .code_resolver import GrepResolver
            fallback = GrepResolver(self.project_path)
            return await fallback.find_definition(symbol, context_file)

        if not context_file:
            # Without a context file, we can't send a position-based query
            from .code_resolver import GrepResolver
            fallback = GrepResolver(self.project_path)
            return await fallback.find_definition(symbol, context_file)

        pos = self._find_symbol_position(context_file, symbol)
        if not pos:
            return []

        # Open the document first
        await self._send_notification("textDocument/didOpen", {
            "textDocument": {
                "uri": self._file_uri(context_file),
                "languageId": "java",
                "version": 1,
                "text": open(context_file, "r", encoding="utf-8").read(),
            }
        })

        result = await self._send_request("textDocument/definition", {
            "textDocument": {"uri": self._file_uri(context_file)},
            "position": {"line": pos[0], "character": pos[1]},
        })

        definitions: list[Definition] = []
        if result:
            # Result can be a single Location or a list of Locations
            locations = result if isinstance(result, list) else [result]
            for loc in locations:
                if isinstance(loc, dict):
                    uri = loc.get("uri", "")
                    file_path = self._uri_to_path(uri)
                    range_info = loc.get("range", {})
                    start = range_info.get("start", {})
                    line = start.get("line", 0) + 1  # 0-indexed -> 1-indexed
                    snippet = self._get_line_content(file_path, line)
                    definitions.append(
                        Definition(
                            symbol=symbol,
                            file_path=file_path,
                            line_number=line,
                            code_snippet=snippet,
                            kind="method",  # LSP doesn't always tell us
                        )
                    )

        return definitions

    async def find_references(
        self, symbol: str, context_file: str = ""
    ) -> list[Reference]:
        """Find references using LSP textDocument/references."""
        if not await self._ensure_initialized():
            from .code_resolver import GrepResolver
            fallback = GrepResolver(self.project_path)
            return await fallback.find_references(symbol, context_file)

        if not context_file:
            from .code_resolver import GrepResolver
            fallback = GrepResolver(self.project_path)
            return await fallback.find_references(symbol, context_file)

        pos = self._find_symbol_position(context_file, symbol)
        if not pos:
            return []

        result = await self._send_request("textDocument/references", {
            "textDocument": {"uri": self._file_uri(context_file)},
            "position": {"line": pos[0], "character": pos[1]},
            "context": {"includeDeclaration": True},
        })

        references: list[Reference] = []
        if result and isinstance(result, list):
            for loc in result:
                if isinstance(loc, dict):
                    uri = loc.get("uri", "")
                    file_path = self._uri_to_path(uri)
                    range_info = loc.get("range", {})
                    start = range_info.get("start", {})
                    line = start.get("line", 0) + 1
                    snippet = self._get_line_content(file_path, line)
                    references.append(
                        Reference(
                            symbol=symbol,
                            file_path=file_path,
                            line_number=line,
                            code_snippet=snippet,
                        )
                    )

        return references

    async def extract_function_calls(
        self, file_path: str, method_name: str
    ) -> list[FunctionCall]:
        """Extract function calls — falls back to regex for this operation.

        LSP doesn't have a native "extract function calls" operation,
        so we use regex extraction from the method body.
        """
        # For this operation, tree-sitter or regex is more appropriate
        from .code_resolver import GrepResolver
        fallback = GrepResolver(self.project_path)
        return await fallback.extract_function_calls(file_path, method_name)

    async def get_type_info(
        self, symbol: str, context_file: str = ""
    ) -> Optional[TypeInfo]:
        """Get type info using LSP textDocument/hover."""
        if not await self._ensure_initialized():
            from .code_resolver import GrepResolver
            fallback = GrepResolver(self.project_path)
            return await fallback.get_type_info(symbol, context_file)

        if not context_file:
            return None

        pos = self._find_symbol_position(context_file, symbol)
        if not pos:
            return None

        result = await self._send_request("textDocument/hover", {
            "textDocument": {"uri": self._file_uri(context_file)},
            "position": {"line": pos[0], "character": pos[1]},
        })

        if result and isinstance(result, dict):
            contents = result.get("contents", {})
            # Extract type from hover info
            hover_text = ""
            if isinstance(contents, dict):
                hover_text = contents.get("value", "")
            elif isinstance(contents, str):
                hover_text = contents
            elif isinstance(contents, list):
                hover_text = " ".join(
                    c.get("value", "") if isinstance(c, dict) else str(c)
                    for c in contents
                )

            if hover_text:
                # Try to extract type from hover text
                # Common patterns: "Type symbol", "method Type.method(params)"
                type_match = re.search(r"\b(\w+(?:<[^>]+>)?)\s+" + re.escape(symbol), hover_text)
                if type_match:
                    type_name = type_match.group(1)
                    base_type = type_name.split("<")[0]
                    return TypeInfo(
                        symbol=symbol,
                        type_name=type_name,
                        is_numeric=base_type in _NUMERIC_TYPES,
                        is_collection=base_type in _COLLECTION_TYPES,
                        is_string=base_type in ("String", "CharSequence", "StringBuilder", "StringBuffer"),
                    )

        # Fall back to regex
        from .code_resolver import GrepResolver
        fallback = GrepResolver(self.project_path)
        return await fallback.get_type_info(symbol, context_file)
