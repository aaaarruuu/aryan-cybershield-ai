from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import PROJECT_AUTHOR, PROJECT_NAME, PROJECT_SUBTITLE, get_settings
from app.database.session import get_db
from app.models.entities import (ApprovalRequest, ApprovalStatus, AuditLog, Incident, IncidentStatus, Investigation, KnowledgeDocument,
                                 MLPrediction, SecurityEvent, Severity, ThreatIndicator, User)
from app.security.auth import require_admin, require_analyst
from app.services import reports

router = APIRouter(prefix="/api", tags=["dashboard"])


def _count(db, stmt) -> int:
    return db.scalar(stmt) or 0


@router.get("/dashboard/stats")
def stats(days: int = Query(14, ge=1, le=90), _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    """All figures are computed from the database on each call - nothing is hardcoded."""
    E, I = SecurityEvent, Incident
    since = datetime.now(timezone.utc) - timedelta(days=days)
    by_sev = {s.value: 0 for s in Severity}
    for sev, n in db.execute(select(I.severity, func.count(I.id)).group_by(I.severity)):
        by_sev[sev.value] = n
    by_status = {s.value: 0 for s in IncidentStatus}
    for st, n in db.execute(select(I.status, func.count(I.id)).group_by(I.status)):
        by_status[st.value] = n
    trend: dict[str, dict] = {}
    for d, n in db.execute(select(func.date(E.timestamp), func.count(E.id)).where(E.is_suspicious.is_(True), E.timestamp >= since).group_by(func.date(E.timestamp))):
        trend.setdefault(str(d), {"date": str(d), "suspicious_events": 0, "incidents": 0})["suspicious_events"] = n
    for d, n in db.execute(select(func.date(I.detected_at), func.count(I.id)).where(I.detected_at >= since).group_by(func.date(I.detected_at))):
        trend.setdefault(str(d), {"date": str(d), "suspicious_events": 0, "incidents": 0})["incidents"] = n
    recent = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(12)).all()
    return {
        "total_events": _count(db, select(func.count(E.id))),
        "suspicious_events": _count(db, select(func.count(E.id)).where(E.is_suspicious.is_(True))),
        "total_incidents": sum(by_status.values()),
        "incidents_by_severity": by_sev, "incidents_by_status": by_status,
        "phishing_detections": _count(db, select(func.count(MLPrediction.id)).where(MLPrediction.model_name == "phishing_analysis", MLPrediction.label == "phishing")),
        "suspicious_emails": _count(db, select(func.count(MLPrediction.id)).where(MLPrediction.model_name == "phishing_analysis", MLPrediction.label == "suspicious")),
        "suspicious_login_attempts": _count(db, select(func.count(E.id)).where(E.event_type == "login", E.outcome == "failure", E.is_suspicious.is_(True))),
        "malicious_indicators": _count(db, select(func.count(ThreatIndicator.id)).where(ThreatIndicator.verdict == "malicious")),
        "malicious_indicators_demo": _count(db, select(func.count(ThreatIndicator.id)).where(ThreatIndicator.verdict == "malicious", ThreatIndicator.source == "demo-sample-data")),
        "active_investigations": by_status["under_investigation"] + by_status["awaiting_approval"],
        "running_ai_investigations": _count(db, select(func.count(Investigation.id)).where(Investigation.status.in_(["queued", "running"]))),
        "resolved_incidents": by_status["resolved"] + by_status["closed"],
        "pending_approvals": _count(db, select(func.count(ApprovalRequest.id)).where(ApprovalRequest.status == ApprovalStatus.pending)),
        "trend": sorted(trend.values(), key=lambda r: r["date"]),
        "recent_activity": [{"action": a.action, "actor": a.actor_email, "entity": a.entity, "entity_id": a.entity_id, "at": a.created_at.isoformat()} for a in recent],
        "demo_mode": get_settings().demo_mode,
    }


@router.get("/audit")
def audit_logs(action: str | None = None, limit: int = Query(100, le=500), offset: int = 0, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    q = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    if action:
        q = q.where(AuditLog.action.like(f"{action}%"))
    return [{"id": a.id, "at": a.created_at.isoformat(), "actor": a.actor_email, "action": a.action, "entity": a.entity, "entity_id": a.entity_id,
             "detail": a.detail, "ip": a.ip} for a in db.scalars(q)]


@router.get("/admin/settings")
def admin_settings(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = get_settings()
    return {"environment": s.app_env, "demo_mode": s.demo_mode, "virustotal_configured": bool(s.virustotal_api_key),   # booleans only, never the key
            "analysis_engine": "deterministic rules + scikit-learn (no LLM)", "upload_max_mb": s.upload_max_mb, "access_token_minutes": s.access_token_expire_minutes,
            "cors_origins": s.cors_list, "users": _count(db, select(func.count(User.id))), "knowledge_documents": _count(db, select(func.count(KnowledgeDocument.id))),
            "response_execution_mode": "simulation-only"}


@router.get("/about")
def about():
    return {"name": PROJECT_NAME, "subtitle": PROJECT_SUBTITLE, "developed_by": PROJECT_AUTHOR, "version": "1.0.0"}


@router.get("/reports/investigations/{inv_id}")
def investigation_report(inv_id: int, format: str = Query("pdf", pattern="^(pdf|csv)$"), _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    inv = db.get(Investigation, inv_id)
    if not inv or inv.status != "completed":
        raise HTTPException(404, "Completed investigation not found")
    if format == "pdf":
        return Response(reports.investigation_pdf(inv.report), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="investigation-{inv.id}.pdf"'})
    return Response(reports.investigation_csv(inv.report), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="investigation-{inv.id}.csv"'})


@router.get("/reports/incidents.csv")
def incidents_report(_: User = Depends(require_analyst), db: Session = Depends(get_db)):
    rows = [{"incident_uid": i.incident_uid, "title": i.title, "severity": i.severity.value, "status": i.status.value, "category": i.category,
             "source": i.source, "detected_at": i.detected_at.isoformat(), "related_indicators": i.related_indicators, "resolution_notes": i.resolution_notes}
            for i in db.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(5000))]
    return Response(reports.incidents_csv(rows), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="incidents.csv"'})
