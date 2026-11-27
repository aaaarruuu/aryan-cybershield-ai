from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.entities import Incident, IncidentHistory, IncidentStatus, Severity, User
from app.schemas.common import HistoryIn, IncidentCreate, IncidentDetail, IncidentOut, IncidentUpdate
from app.security.auth import audit, require_analyst
from app.services.investigations import new_incident_uid

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

# Allowed status transitions (prevents e.g. re-opening a closed incident by accident).
TRANSITIONS = {
    IncidentStatus.open: {IncidentStatus.under_investigation, IncidentStatus.resolved, IncidentStatus.closed},
    IncidentStatus.under_investigation: {IncidentStatus.awaiting_approval, IncidentStatus.resolved, IncidentStatus.closed},
    IncidentStatus.awaiting_approval: {IncidentStatus.under_investigation, IncidentStatus.resolved},
    IncidentStatus.resolved: {IncidentStatus.closed, IncidentStatus.under_investigation},
    IncidentStatus.closed: set(),
}


@router.post("", response_model=IncidentOut, status_code=201)
def create(body: IncidentCreate, request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    inc = Incident(incident_uid=new_incident_uid(), **body.model_dump(), created_by_id=user.id, assigned_to_id=user.id)
    db.add(inc)
    db.flush()
    db.add(IncidentHistory(incident_id=inc.id, actor_id=user.id, action="created", note="Created manually"))
    db.commit()
    audit(db, "incident.created", user, "incident", inc.incident_uid, {"severity": inc.severity.value}, request)
    return inc


@router.get("", response_model=list[IncidentOut])
def list_incidents(status: IncidentStatus | None = None, severity: Severity | None = None, q: str | None = Query(None, max_length=100),
                   limit: int = Query(100, le=500), offset: int = 0, _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    stmt = select(Incident).order_by(Incident.created_at.desc()).limit(limit).offset(offset)
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Incident.title.ilike(like), Incident.incident_uid.ilike(like), Incident.description.ilike(like)))
    return db.scalars(stmt).all()


@router.get("/{inc_id}", response_model=IncidentDetail)
def get(inc_id: int, _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    inc = db.get(Incident, inc_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    return inc


@router.patch("/{inc_id}", response_model=IncidentDetail)
def update(inc_id: int, body: IncidentUpdate, request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    inc = db.get(Incident, inc_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    changes = body.model_dump(exclude_unset=True)
    if "assigned_to_id" in changes and changes["assigned_to_id"] is not None and not db.get(User, changes["assigned_to_id"]):
        raise HTTPException(422, "Assignee not found")
    if "status" in changes and changes["status"] != inc.status:
        if changes["status"] not in TRANSITIONS[inc.status]:
            raise HTTPException(409, f"Cannot move from '{inc.status.value}' to '{changes['status'].value}'")
        if changes["status"] in (IncidentStatus.resolved, IncidentStatus.closed) and not (changes.get("resolution_notes") or inc.resolution_notes):
            raise HTTPException(422, "Resolution notes are required to resolve or close an incident")
    for k, v in changes.items():
        old = getattr(inc, k)
        if old != v:
            setattr(inc, k, v)
            db.add(IncidentHistory(incident_id=inc.id, actor_id=user.id, action=f"{k}_changed",
                                   note=f"{getattr(old, 'value', old)} -> {getattr(v, 'value', v)}"[:500] if k not in ("resolution_notes", "recommended_response") else f"{k} updated"))
    db.commit()
    audit(db, "incident.updated", user, "incident", inc.incident_uid, {k: str(getattr(v, "value", v))[:80] for k, v in changes.items()}, request)
    return inc


@router.post("/{inc_id}/history", response_model=IncidentDetail, status_code=201)
def add_note(inc_id: int, body: HistoryIn, request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    inc = db.get(Incident, inc_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    db.add(IncidentHistory(incident_id=inc.id, actor_id=user.id, action="note", note=body.note))
    db.commit()
    audit(db, "incident.note_added", user, "incident", inc.incident_uid, {}, request)
    db.refresh(inc)
    return inc
