"""Final audit report schema."""

from pydantic import BaseModel

from .finding import Finding
from .route import RouteEntry
from .verification import VerificationResult


class AuditReport(BaseModel):
    """Complete audit report assembled by report_generator."""
    project_path: str
    total_routes: int = 0
    total_findings: int = 0
    confirmed_findings: int = 0
    false_positives: int = 0
    routes: list[RouteEntry] = []
    findings: list[Finding] = []
    verifications: list[VerificationResult] = []
    summary_by_severity: dict[str, int] = {}
    summary_by_type: dict[str, int] = {}
