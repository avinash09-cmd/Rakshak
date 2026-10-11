from sqlalchemy.orm import Session

from .models import AuditLog


def audit(db: Session, alert_id: int, actor: str, event: str, detail: dict | None = None) -> None:
    """Append-only audit record, committed immediately so a crash can't lose it."""
    db.add(AuditLog(alert_id=alert_id, actor=actor, event=event, detail=detail or {}))
    db.commit()
