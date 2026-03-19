"""Authentication audit result schemas."""

from typing import Optional

from pydantic import BaseModel

from .finding import Finding


class AuthRouteUpdate(BaseModel):
    """Route auth status update produced by auth_auditor."""
    path: str
    method: str
    auth_required: bool
    auth_mechanism: Optional[str] = None  # shiro / spring_security / jwt / filter / none
    notes: str = ""


class AuthFinding(BaseModel):
    """Complete auth audit output."""
    findings: list[Finding] = []
    route_updates: list[AuthRouteUpdate] = []
