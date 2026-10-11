from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    source: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)


class TriageResult(Base):
    __tablename__ = "triage_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    prompt_version: Mapped[str] = mapped_column(String(16))
    model: Mapped[str] = mapped_column(String(64))
    llm_skipped: Mapped[bool] = mapped_column(Boolean, default=False)
    injection_flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    injection_findings: Mapped[list] = mapped_column(JSON)
    llm_output: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    verified_techniques: Mapped[list] = mapped_column(JSON)
    dropped_techniques: Mapped[list] = mapped_column(JSON)
    rule_floor: Mapped[str] = mapped_column(String(16))
    rule_reasons: Mapped[list] = mapped_column(JSON)
    floor_raised_llm: Mapped[bool] = mapped_column(Boolean, default=False)
    recommended_severity: Mapped[str] = mapped_column(String(16))
    error: Mapped[Optional[str]] = mapped_column(String(600), nullable=True)


class AnalystReview(Base):
    __tablename__ = "analyst_reviews"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    triage_id: Mapped[int] = mapped_column(ForeignKey("triage_results.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    analyst: Mapped[str] = mapped_column(String(128))
    decision: Mapped[str] = mapped_column(String(32))
    final_severity: Mapped[str] = mapped_column(String(16))
    approved_lowering: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_now)
    actor: Mapped[str] = mapped_column(String(128))
    event: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSON)
