from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.entities import ApprovalRequest, ApprovalStatus, User
from app.schemas.common import ApprovalRequestIn, DecisionIn
from app.security.auth import require_analyst
from app.services import approvals as svc

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


def _get(db: Session, ap_id: int) -> ApprovalRequest:
    ap = db.get(ApprovalRequest, ap_id)
    if not ap:
        raise HTTPException(404, "Approval request not found")
    return ap


@router.get("")
def list_all(status: ApprovalStatus | None = None, incident_id: int | None = None, _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    q = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc()).limit(300)
    if status:
        q = q.where(ApprovalRequest.status == status)
    if incident_id:
        q = q.where(ApprovalRequest.incident_id == incident_id)
    return [svc.serialise(a) for a in db.scalars(q)]


@router.post("", status_code=201)
def create(body: ApprovalRequestIn, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    try:
        return svc.serialise(svc.request_action(db, user, body.incident_id, body.action_type, body.target, body.rationale))
    except svc.ApprovalError as e:
        raise HTTPException(422, str(e))


def _decide(ap_id: int, approve: bool, body: DecisionIn, user: User, db: Session):
    ap = _get(db, ap_id)
    try:
        return svc.serialise(svc.decide(db, ap, user, approve, body.note))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except svc.ApprovalError as e:
        raise HTTPException(409, str(e))


@router.post("/{ap_id}/approve")
def approve(ap_id: int, body: DecisionIn, request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    return _decide(ap_id, True, body, user, db)


@router.post("/{ap_id}/reject")
def reject(ap_id: int, body: DecisionIn, request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    return _decide(ap_id, False, body, user, db)


@router.post("/{ap_id}/rollback")
def rollback(ap_id: int, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    ap = _get(db, ap_id)
    try:
        svc.rollback(db, ap, user)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except svc.ApprovalError as e:
        raise HTTPException(409, str(e))
    db.refresh(ap)
    return svc.serialise(ap)
