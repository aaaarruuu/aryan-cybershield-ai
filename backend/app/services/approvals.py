"""Human-approved response management. Execution is SIMULATED only: no real firewall, directory or endpoint
integration exists, so nothing outside this application's database is ever changed.

Flow: PENDING -> (authorised human) APPROVED/REJECTED -> validate -> simulated execute -> verify -> (optional) rollback.
"""
import ipaddress
import re
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.entities import (ApprovalRequest, ApprovalStatus, ExecStatus, Incident, IncidentHistory, IncidentStatus,
                                 ResponseAction, Role, User)
from app.security.auth import audit
from app.services.threat_intel import detect_type

# Who may approve what. Disruptive account/endpoint actions are admin-only.
APPROVER_ROLES = {
    "block_indicator": {Role.admin, Role.analyst},
    "investigate_access": {Role.admin, Role.analyst},
    "escalate_incident": {Role.admin, Role.analyst},
    "reset_password": {Role.admin},
    "revoke_sessions": {Role.admin},
    "isolate_endpoint": {Role.admin},
}
ROLLBACKABLE = {"block_indicator", "isolate_endpoint"}
USER_RE = re.compile(r"^[A-Za-z0-9._@\-]{1,120}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-_]{0,252}$")


class ApprovalError(ValueError):
    pass


def validate_target(action_type: str, target: str) -> None:
    t = target.strip()
    if action_type == "block_indicator":
        if detect_type(t) is None:
            raise ApprovalError("block_indicator target must be an IP, domain, URL or file hash")
        try:
            ip = ipaddress.ip_address(t)
        except ValueError:
            ip = None  # not an IP (domain/URL/hash)
        if ip is not None and (ip.is_loopback or ip.is_unspecified or ip.is_multicast):
            raise ApprovalError("Refusing to block a loopback/unspecified/multicast address")
    elif action_type in ("reset_password", "revoke_sessions", "investigate_access"):
        if not (USER_RE.match(t) or detect_type(t) == "ip"):
            raise ApprovalError(f"{action_type} target must be a username/email{' or IP' if action_type == 'investigate_access' else ''}")
    elif action_type == "isolate_endpoint":
        if not HOST_RE.match(t):
            raise ApprovalError("isolate_endpoint target must be a hostname or IP")
    elif action_type == "escalate_incident":
        if not t or len(t) > 255:
            raise ApprovalError("escalate_incident needs a target team or contact")


def request_action(db: Session, user: User | None, incident_id: int | None, action_type: str, target: str, rationale: str,
                   requested_by: str = "analyst") -> ApprovalRequest:
    validate_target(action_type, target)
    if incident_id is not None and not db.get(Incident, incident_id):
        raise ApprovalError("Incident not found")
    ap = ApprovalRequest(incident_id=incident_id, action_type=action_type, target=target.strip(), rationale=rationale,
                         requested_by=requested_by if user is None else user.email)
    db.add(ap)
    if incident_id is not None:
        inc = db.get(Incident, incident_id)
        if inc.status in (IncidentStatus.open, IncidentStatus.under_investigation):
            inc.status = IncidentStatus.awaiting_approval
        db.add(IncidentHistory(incident_id=incident_id, actor_id=user.id if user else None, action="approval_requested",
                               note=f"{action_type} on {target}"))
    db.commit()
    audit(db, "approval.requested", user, "approval", ap.id, {"action_type": action_type, "target": target})
    return ap


def _simulate(ap: ApprovalRequest) -> tuple[dict, dict, dict]:
    msgs = {"block_indicator": f"[SIMULATION] Added {ap.target} to the simulated blocklist",
            "reset_password": f"[SIMULATION] Forced password reset for {ap.target}",
            "revoke_sessions": f"[SIMULATION] Revoked all active sessions for {ap.target}",
            "isolate_endpoint": f"[SIMULATION] Isolated endpoint {ap.target} from the network",
            "investigate_access": f"[SIMULATION] Opened an access investigation task for {ap.target}",
            "escalate_incident": f"[SIMULATION] Escalated to {ap.target}"}
    result = {"simulated": True, "message": msgs[ap.action_type], "real_world_change": False}
    verification = {"verified": True, "method": "simulated state check", "detail": "Simulated state reflects the requested change. No external system was contacted."}
    rollback = ({"available": True, "plan": {"block_indicator": f"Remove {ap.target} from the simulated blocklist",
                                             "isolate_endpoint": f"Restore network connectivity for {ap.target}"}[ap.action_type]}
                if ap.action_type in ROLLBACKABLE else {"available": False, "reason": "Action is not reversible by this system"})
    return result, verification, rollback


def decide(db: Session, ap: ApprovalRequest, user: User, approve: bool, note: str = "") -> ApprovalRequest:
    if ap.status != ApprovalStatus.pending:
        raise ApprovalError(f"Request already {ap.status.value}")
    if user.role not in APPROVER_ROLES[ap.action_type]:
        raise PermissionError(f"Role '{user.role.value}' may not decide '{ap.action_type}' requests")
    ap.status = ApprovalStatus.approved if approve else ApprovalStatus.rejected
    ap.decided_by_id, ap.decision_note, ap.decided_at = user.id, note, datetime.now(timezone.utc)
    audit(db, "approval.approved" if approve else "approval.rejected", user, "approval", ap.id, {"action_type": ap.action_type, "target": ap.target, "note": note[:200]})
    if approve:
        act = ResponseAction(approval_id=ap.id, simulated=True)
        db.add(act)
        try:
            validate_target(ap.action_type, ap.target)            # re-validate at execution time
            act.result, act.verification, act.rollback = _simulate(ap)
            act.exec_status, act.executed_at = ExecStatus.executed_simulated, datetime.now(timezone.utc)
        except Exception as e:  # noqa: BLE001 - failure handling: record, never crash
            act.exec_status, act.result = ExecStatus.failed, {"error": str(e)[:300], "simulated": True}
        audit(db, "response.executed_simulated" if act.exec_status == ExecStatus.executed_simulated else "response.failed", user, "approval", ap.id,
              {"status": act.exec_status.value})
    if ap.incident_id:
        db.add(IncidentHistory(incident_id=ap.incident_id, actor_id=user.id, action="approved" if approve else "rejected",
                               note=f"{ap.action_type} on {ap.target}. {note}"[:2000]))
        pending = db.scalar(select(func.count(ApprovalRequest.id)).where(ApprovalRequest.incident_id == ap.incident_id,
                                                                         ApprovalRequest.status == ApprovalStatus.pending, ApprovalRequest.id != ap.id))
        inc = db.get(Incident, ap.incident_id)
        if not pending and inc.status == IncidentStatus.awaiting_approval:
            inc.status = IncidentStatus.under_investigation
    db.commit()
    return ap


def rollback(db: Session, ap: ApprovalRequest, user: User) -> ResponseAction:
    act = ap.action
    if not act or act.exec_status != ExecStatus.executed_simulated:
        raise ApprovalError("Only executed actions can be rolled back")
    if not act.rollback.get("available"):
        raise ApprovalError(act.rollback.get("reason", "Rollback not available"))
    if user.role not in APPROVER_ROLES[ap.action_type]:
        raise PermissionError("Insufficient permissions to roll back this action")
    act.exec_status = ExecStatus.rolled_back
    act.result = {**act.result, "rolled_back_at": datetime.now(timezone.utc).isoformat(), "message": "[SIMULATION] " + act.rollback["plan"]}
    if ap.incident_id:
        db.add(IncidentHistory(incident_id=ap.incident_id, actor_id=user.id, action="rolled_back", note=f"{ap.action_type} on {ap.target}"))
    db.commit()
    audit(db, "response.rolled_back", user, "approval", ap.id, {"action_type": ap.action_type})
    return act


def serialise(ap: ApprovalRequest) -> dict:
    a = ap.action
    return {"id": ap.id, "incident_id": ap.incident_id, "investigation_id": ap.investigation_id, "action_type": ap.action_type,
            "target": ap.target, "rationale": ap.rationale, "status": ap.status.value, "requested_by": ap.requested_by,
            "decided_by_id": ap.decided_by_id, "decision_note": ap.decision_note, "created_at": ap.created_at.isoformat(),
            "decided_at": ap.decided_at.isoformat() if ap.decided_at else None,
            "approver_roles": sorted(r.value for r in APPROVER_ROLES[ap.action_type]),
            "execution": {"status": a.exec_status.value, "simulated": a.simulated, "result": a.result, "verification": a.verification,
                          "rollback": a.rollback, "executed_at": a.executed_at.isoformat() if a.executed_at else None} if a else None}
