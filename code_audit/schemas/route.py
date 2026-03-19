"""Route analysis result schemas."""

from typing import Optional

from pydantic import BaseModel


class ParamEntry(BaseModel):
    """A single request parameter."""
    name: str
    type: str = "String"
    location: str = "query"  # query / path / body / header / cookie
    required: bool = False
    default_value: Optional[str] = None


class RouteEntry(BaseModel):
    """One HTTP route."""
    method: str                            # GET/POST/PUT/DELETE
    path: str                              # /api/v1/users
    controller: str                        # UserController
    handler_method: str                    # getUser
    file_path: str                         # source file absolute path
    line_number: int                       # method line number
    params: list[ParamEntry] = []
    auth_required: Optional[bool] = None   # filled by auth_auditor later
    burp_template: str = ""                # Burp Suite request template
