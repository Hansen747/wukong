"""Generic vulnerability finding schema."""

from typing import Literal, Optional

from pydantic import BaseModel


class CallChainNode(BaseModel):
    """A node in the call chain: Source -> propagation -> Sink."""
    method: str
    file: str
    line: int
    code: str


class Finding(BaseModel):
    """
    Generic vulnerability finding used by all audit agents.
    ID prefix distinguishes source: AUTH-xxx / PECKER-xxx / HC-xxx
    """
    id: str
    type: str  # sqli / cmdi / rce / xxe / deser / hardcoded / auth_bypass / path_traversal / ...
    severity: Literal["critical", "high", "medium", "low"]
    title: str
    file_path: str
    line_number: int = 0
    source: Optional[str] = None       # taint source (user input)
    sink: Optional[str] = None         # dangerous function (execution point)
    call_chain: list[CallChainNode] = []
    code_snippet: str = ""
    description: str = ""
    poc: Optional[str] = None          # Burp-format POC request
    remediation: str = ""
