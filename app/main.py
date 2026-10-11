from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .audit import audit
from .config import Settings, get_settings
from .db import Base, make_engine
from .guards.attack import AttackCatalog
from .guards.severity import rank
from .models import Alert, AnalystReview, AuditLog, TriageResult
from .schemas import AlertIn, ReviewIn
from .triage.llm import TriageClient, build_client
from .triage.service import triage_alert

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))  # autoescape on for .html


def _triage_dict(t: TriageResult | None) -> dict | None:
    if t is None:
        return None
    return {
        "id": t.id, "model": t.model, "prompt_version": t.prompt_version,
        "llm_skipped": t.llm_skipped, "injection_flagged": t.injection_flagged,
        "injection_findings": t.injection_findings, "llm_output": t.llm_output,
        "verified_techniques": t.verified_techniques, "dropped_techniques": t.dropped_techniques,
        "rule_floor": t.rule_floor, "rule_reasons": t.rule_reasons,
        "floor_raised_llm": t.floor_raised_llm,
        "recommended_severity": t.recommended_severity, "error": t.error,
    }


def _review_dict(r: AnalystReview) -> dict:
    return {"id": r.id, "analyst": r.analyst, "decision": r.decision, "final_severity": r.final_severity,
            "approved_lowering": r.approved_lowering, "notes": r.notes, "created_at": r.created_at.isoformat()}


def create_app(settings: Settings | None = None, client: TriageClient | None = None,
               catalog: AttackCatalog | None = None) -> FastAPI:
    settings = settings or get_settings()
    catalog = catalog or AttackCatalog.from_stix(settings.stix_path)  # fail fast if STIX missing
    client = client or build_client(settings)
    engine = make_engine(settings.database_url)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(engine, expire_on_commit=False)

    app = FastAPI(title="Rakshak", version="0.1.0",
                  description="LLM-assisted SOC alert triage with prompt-injection defenses.")

    def get_db():
        with SessionLocal() as session:
            yield session

    def _load(db: Session, alert_id: int) -> tuple[Alert, TriageResult | None]:
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(404, "alert not found")
        triage = db.scalars(select(TriageResult).where(TriageResult.alert_id == alert_id)
                            .order_by(TriageResult.id.desc()).limit(1)).first()
        return alert, triage

    def _detail(db: Session, alert_id: int) -> dict:
        alert, triage = _load(db, alert_id)
        reviews = db.scalars(select(AnalystReview).where(AnalystReview.alert_id == alert_id)
                             .order_by(AnalystReview.id)).all()
        return {"id": alert.id, "status": alert.status, "received_at": alert.received_at.isoformat(),
                "source": alert.source, "payload": alert.payload, "triage": _triage_dict(triage),
                "reviews": [_review_dict(r) for r in reviews]}

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "model": client.name, "attack_techniques_loaded": len(catalog.techniques)}

    @app.post("/alerts", status_code=201)
    def ingest(body: AlertIn, db: Session = Depends(get_db)):
        alert = Alert(source=body.source, payload=body.model_dump(mode="json"), status="new")
        db.add(alert)
        db.commit()
        db.refresh(alert)
        audit(db, alert.id, "ingest", "alert_received", {"source": body.source})
        triage_alert(db, alert, client, catalog, settings)
        return _detail(db, alert.id)

    @app.get("/alerts")
    def list_alerts(status: str | None = None, limit: int = 100, db: Session = Depends(get_db)):
        q = select(Alert).order_by(Alert.id.desc()).limit(min(limit, 500))
        if status:
            q = q.where(Alert.status == status)
        out = []
        for a in db.scalars(q):
            t = db.scalars(select(TriageResult).where(TriageResult.alert_id == a.id)
                           .order_by(TriageResult.id.desc()).limit(1)).first()
            out.append({"id": a.id, "status": a.status, "source": a.source,
                        "rule_name": a.payload.get("rule_name"), "host": a.payload.get("host"),
                        "recommended_severity": t.recommended_severity if t else None,
                        "injection_flagged": t.injection_flagged if t else None})
        return out

    @app.get("/alerts/{alert_id}")
    def get_alert(alert_id: int, db: Session = Depends(get_db)):
        return _detail(db, alert_id)

    @app.get("/alerts/{alert_id}/audit")
    def get_audit(alert_id: int, db: Session = Depends(get_db)):
        _load(db, alert_id)
        rows = db.scalars(select(AuditLog).where(AuditLog.alert_id == alert_id).order_by(AuditLog.id)).all()
        return [{"ts": r.ts.isoformat(), "actor": r.actor, "event": r.event, "detail": r.detail} for r in rows]

    @app.post("/alerts/{alert_id}/review")
    def review(alert_id: int, body: ReviewIn, db: Session = Depends(get_db)):
        alert, triage = _load(db, alert_id)
        if triage is None:
            raise HTTPException(409, "alert has no triage result yet")
        if alert.status == "reviewed":
            raise HTTPException(409, "alert already reviewed")

        if body.decision == "accept":
            final = triage.recommended_severity
        elif body.decision == "false_positive":
            final = "low"
        else:
            if body.final_severity is None:
                raise HTTPException(422, "final_severity is required for 'override'")
            final = body.final_severity

        # Human-in-the-loop gate: going below the rule-based floor needs explicit approval + a reason.
        lowering = rank(final) < rank(triage.rule_floor)
        if lowering and not (body.approve_lowering and (body.notes or "").strip()):
            raise HTTPException(409, f"'{final}' is below the rule-based floor '{triage.rule_floor}' "
                                     f"({'; '.join(triage.rule_reasons)}). Set approve_lowering=true and give notes.")

        rev = AnalystReview(alert_id=alert_id, triage_id=triage.id, analyst=body.analyst,
                            decision=body.decision, final_severity=final,
                            approved_lowering=lowering, notes=body.notes)
        db.add(rev)
        alert.status = "reviewed"
        db.commit()
        audit(db, alert_id, body.analyst, "analyst_review",
              {"decision": body.decision, "final_severity": final, "approved_lowering": lowering,
               "recommended_was": triage.recommended_severity, "notes": body.notes})
        return _detail(db, alert_id)

    # ---- minimal analyst UI ----
    @app.get("/", response_class=HTMLResponse)
    def ui_queue(request: Request, db: Session = Depends(get_db)):
        return TEMPLATES.TemplateResponse(request, "queue.html", {"alerts": list_alerts(None, 100, db)})

    @app.get("/ui/alerts/{alert_id}", response_class=HTMLResponse)
    def ui_detail(alert_id: int, request: Request, db: Session = Depends(get_db)):
        audit_rows = get_audit(alert_id, db)
        return TEMPLATES.TemplateResponse(request, "detail.html", {"a": _detail(db, alert_id), "audit": audit_rows})

    return app
