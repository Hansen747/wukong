"""Vulnerability verification result schema."""

from typing import Literal, Optional

from pydantic import BaseModel

from .finding import CallChainNode


class VerificationResult(BaseModel):
    """
    Independent verification result for a single Finding.
    Produced by vuln_verifier after reading source code.
    """
    finding_id: str
    status: Literal[
        "confirmed",       # Source->Sink path complete, no effective sanitization
        "false_positive",  # Source/Sink absent, path broken, or effective sanitization
        "downgraded",      # Vuln exists but severity was too high
        "needs_review"     # Cannot auto-determine
    ]
    original_severity: str
    adjusted_severity: Optional[str] = None
    reason: str
    verified_call_chain: Optional[list[CallChainNode]] = None
