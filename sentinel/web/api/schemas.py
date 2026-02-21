"""
Pydantic models for the Sentinel Web API.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class AuditMode(str, Enum):
    GITHUB_URL = "github_url"
    CODE_PASTE = "code_paste"


class AuditRequest(BaseModel):
    mode: AuditMode
    github_url: Optional[str] = None
    code: Optional[str] = None
    filename: str = "Contract.sol"
    depth: Literal["fast", "standard", "deep"] = "standard"
    model: str = "claude-sonnet-4-20250514"


class AuditResponse(BaseModel):
    job_id: str
    ws_url: str
    status: str = "started"


class JobStatus(BaseModel):
    job_id: str
    status: Literal["pending", "running", "complete", "error"]
    phase: Optional[str] = None
    total_findings: int = 0
    cost: float = 0.0
    error: Optional[str] = None


class WSMessage(BaseModel):
    type: Literal[
        "phase_start",
        "phase_complete",
        "log",
        "finding",
        "cost_update",
        "error",
        "complete",
        "artifact",
    ]
    timestamp: datetime = Field(default_factory=datetime.now)
    data: dict[str, Any] = Field(default_factory=dict)


class FindingSummary(BaseModel):
    id: str
    title: str
    severity: str
    vulnerability_type: str
    contract: str
    function: Optional[str] = None
    description: str
    impact: str = ""
    recommendation: str = ""
    confidence: float = 0.0
    validated: bool = False
    poc_code: Optional[str] = None
    poc_output: Optional[str] = None


class AuditReport(BaseModel):
    job_id: str
    report_markdown: str
    findings: list[FindingSummary]
    testing_diagram: Optional[str] = None
    test_setup: Optional[str] = None
    input_source: Optional[str] = None
    cost: float = 0.0
    duration_seconds: float = 0.0
