from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import SessionLocal, get_db
from app.models.entities import Investigation, SecurityEvent, User
from app.schemas.common import InvestigationIn
from app.security.auth import audit, require_analyst
from app.services import investigations as svc

router = APIRouter(prefix="/api/investigations", tags=["investigations"])


def _job(inv_id: int, user_id: int, request: dict):
    """Background job with its own DB session (sessions are not shared across threads)."""
    db = SessionLocal()
    try:
        inv = db.get(Investigation, inv_id)
        user = db.get(User, user_id)
        svc.execute(db, inv, user_id, request, actor=user)
    finally:
        db.close()


def _summary(i: Investigation) -> dict:
    return {"id": i.id, "title": i.title, "status": i.status, "risk_level": i.risk_level, "risk_score": i.risk_score,
            "created_at": i.created_at.isoformat(), "completed_at": i.completed_at.isoformat() if i.completed_at else None}


@router.post("", status_code=202)
def start(body: InvestigationIn, background: BackgroundTasks, request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    req = body.model_dump()
    if not (req["phishing"] or req["indicators"] or req["log_batch_id"]):
        raise HTTPException(422, "Provide an email, indicators, or a log batch to investigate")
    if req["log_batch_id"] and not db.scalar(select(SecurityEvent.id).where(SecurityEvent.batch_id == req["log_batch_id"]).limit(1)):
        raise HTTPException(404, "Log batch not found")
    inv = Investigation(title=body.title or "Investigation", request=req, status="queued", created_by_id=user.id)
    db.add(inv)
    db.commit()
    audit(db, "investigation.started", user, "investigation", inv.id, {"has_email": bool(req["phishing"]), "indicators": len(req["indicators"]),
                                                                       "log_batch": req["log_batch_id"]}, request)
    background.add_task(_job, inv.id, user.id, req)
    return _summary(inv)


@router.get("")
def list_all(limit: int = 50, _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    return [_summary(i) for i in db.scalars(select(Investigation).order_by(Investigation.created_at.desc()).limit(min(limit, 200)))]


@router.get("/{inv_id}")
def detail(inv_id: int, _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return {**_summary(inv), "request": {k: v for k, v in inv.request.items() if k != "phishing"} | ({"phishing": {"sender": inv.request["phishing"].get("sender"), "subject": inv.request["phishing"].get("subject")}} if inv.request.get("phishing") else {}),
            "report": inv.report,
            "agent_runs": [{"agent": a.agent_name, "status": a.status, "attempts": a.attempts, "duration_ms": a.duration_ms, "error": a.error}
                           for a in inv.agent_runs]}
