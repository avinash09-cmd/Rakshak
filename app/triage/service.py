"""The triage pipeline: prefilter -> LLM -> schema -> STIX check -> severity floor."""
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings
from ..guards.attack import AttackCatalog
from ..guards.prefilter import normalize, scan_alert
from ..guards.severity import compute_floor, max_sev, rank
from ..models import Alert, TriageResult
from .llm import TriageClient, parse_llm_output
from .prompt import PROMPT_VERSION, SYSTEM_PROMPT, build_user_message

# If the LLM is skipped or fails, never recommend below this (fail safe).
FAIL_SAFE_SEVERITY = "medium"
MAX_ATTEMPTS = 2


def triage_alert(db: Session, alert: Alert, client: TriageClient,
                 catalog: AttackCatalog, settings: Settings) -> TriageResult:
    payload = alert.payload
    audit(db, alert.id, "system", "triage_started", {"prompt_version": PROMPT_VERSION, "model": client.name})

    # 1. injection pre-filter
    pf = scan_alert(payload, settings.max_field_chars)
    audit(db, alert.id, "prefilter", "prefilter_scan",
          {"flagged": pf.flagged, "block_llm": pf.block_llm, "findings": pf.findings})

    # 2-3. LLM call + strict schema validation (skipped for high-confidence injections)
    llm_out, error, skipped = None, None, False
    if pf.block_llm:
        skipped = True
        audit(db, alert.id, "system", "llm_skipped",
              {"reason": "high-confidence injection pattern in untrusted fields"})
    else:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            raw = None
            try:
                raw = client.complete(SYSTEM_PROMPT, build_user_message(payload))
                llm_out = parse_llm_output(raw)
                error = None
                audit(db, alert.id, "llm", "llm_output_valid", {"attempt": attempt, "raw": raw[:8000]})
                break
            except Exception as exc:  # malformed output, API failure, schema violation
                error = f"{type(exc).__name__}: {exc}"[:550]
                audit(db, alert.id, "llm", "llm_output_rejected",
                      {"attempt": attempt, "error": error, "raw": (raw or "")[:8000]})

    # Output guard: model free-text must not repeat flagged attacker content.
    echoed = False
    if llm_out and pf.findings:
        out_text = normalize(llm_out.summary + " " + llm_out.rationale).lower()
        echoed = any(len(f["excerpt"]) >= 12 and normalize(f["excerpt"]).lower() in out_text
                     for f in pf.findings)
        if echoed:
            llm_out = llm_out.model_copy(update={
                "summary": "[redacted: model output repeated flagged alert content]",
                "rationale": "[redacted: model output repeated flagged alert content]"})
            audit(db, alert.id, "output-guard", "output_echo_redacted", {})

    suspected = pf.flagged or bool(llm_out and llm_out.suspected_injection)

    # 4. verify technique IDs against the official STIX dataset
    verified: list[dict] = []
    dropped: list[dict] = []
    if llm_out:
        for t in llm_out.techniques:
            status, canonical = catalog.verify(t.id, t.name)
            if status == "ok":
                verified.append({"id": t.id, "name": canonical})
            else:
                dropped.append({"id": t.id, "name": t.name, "reason": status})
        audit(db, alert.id, "attack-verifier", "techniques_verified",
              {"verified": verified, "dropped": dropped})

    # 5. rule-based severity floor (LLM can raise above it, never lower below it)
    floor = compute_floor(payload, injection_suspected=suspected)
    if llm_out:
        recommended = max_sev(floor.floor, llm_out.recommended_severity)
        floor_raised = rank(floor.floor) > rank(llm_out.recommended_severity)
    else:
        recommended = max_sev(floor.floor, FAIL_SAFE_SEVERITY)
        floor_raised = False
    audit(db, alert.id, "severity-floor", "severity_computed",
          {"floor": floor.floor, "reasons": floor.reasons, "llm": llm_out.recommended_severity if llm_out else None,
           "recommended": recommended, "floor_raised_llm": floor_raised})

    result = TriageResult(
        alert_id=alert.id, prompt_version=PROMPT_VERSION, model=client.name,
        llm_skipped=skipped, injection_flagged=suspected, injection_findings=pf.findings,
        llm_output=llm_out.model_dump() if llm_out else None,
        verified_techniques=verified, dropped_techniques=dropped,
        rule_floor=floor.floor, rule_reasons=floor.reasons, floor_raised_llm=floor_raised,
        recommended_severity=recommended, error=error,
    )
    db.add(result)
    alert.status = "pending_review"
    db.commit()
    db.refresh(result)
    audit(db, alert.id, "system", "triage_completed",
          {"triage_id": result.id, "recommended_severity": recommended, "awaiting": "analyst_review"})
    return result
