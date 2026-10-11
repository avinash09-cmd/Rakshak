from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high", "critical"]


class AlertIn(BaseModel):
    """Inbound alert. Every string here is untrusted input."""

    source: str = Field(min_length=1, max_length=64)
    rule_name: str = Field(min_length=1, max_length=2000)
    timestamp: Optional[datetime] = None
    host: Optional[str] = Field(default=None, max_length=20000)
    user: Optional[str] = Field(default=None, max_length=20000)
    src_ip: Optional[str] = Field(default=None, max_length=64)
    dst_ip: Optional[str] = Field(default=None, max_length=64)
    process: Optional[str] = Field(default=None, max_length=20000)
    command_line: Optional[str] = Field(default=None, max_length=20000)
    raw_message: Optional[str] = Field(default=None, max_length=20000)
    vendor_severity: Optional[Severity] = None
    asset_criticality: Optional[Severity] = None
    threat_intel_match: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)


class TechniqueRef(BaseModel):
    id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = Field(min_length=1, max_length=120)


class LLMTriageOutput(BaseModel):
    """Strict schema the model's JSON must satisfy. Extra keys are rejected."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=1200)
    techniques: list[TechniqueRef] = Field(max_length=5)
    rationale: str = Field(min_length=1, max_length=1500)
    recommended_severity: Severity
    confidence: float = Field(ge=0, le=1)
    suspected_injection: bool = False


class ReviewIn(BaseModel):
    analyst: str = Field(min_length=1, max_length=128)
    decision: Literal["accept", "override", "false_positive"]
    final_severity: Optional[Severity] = None
    approve_lowering: bool = False
    notes: Optional[str] = Field(default=None, max_length=4000)
