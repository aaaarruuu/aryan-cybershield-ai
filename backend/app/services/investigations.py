"""Run an investigation, persist every artefact, create incident + PENDING approvals, audit it."""
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.agents.orchestrator import run_investigation
from app.agents.tools import ToolBox
from app.models.entities import (AgentRun, ApprovalRequest, ApprovalStatus, Evidence, Incident, IncidentHistory,
                                 IncidentStatus, Investigation, Severity)
from app.security.auth import audit
from app.services import logs as log_service

SEVERITY_MAP = {"low": Severity.low, "medium": Severity.medium, "high": Severity.high, "critical": Severity.critical}


def new_incident_uid() -> str:
    return "INC-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:6].upper()


def executive_summary(state: dict) -> str:
    risk = state.get("risk")
    if not risk:
        return "No investigable evidence was produced; no risk assessment was made."
    parts = [f"Overall risk: {risk['risk_level'].upper()} ({risk['risk_score']}/100)."]
    if state.get("log"):
        parts.append(f"{len([a for a in state['log']['alerts'] if a['source'] == 'rule'])} rule-based log alert(s).")
    if state.get("phishing"):
        parts.append(f"Email classified {state['phishing']['classification']}.")
    if state.get("intel"):
        bad = [r["indicator"] for r in state["intel"]["results"] if r["verdict"] in ("malicious", "suspicious")]
        parts.append(f"{len(bad)} indicator(s) rated malicious/suspicious." if bad else "No indicators rated malicious/suspicious.")
    resp = state.get("response")
    if resp and resp["actions"]:
        parts.append(f"{len(resp['actions'])} response action(s) proposed, awaiting human approval.")
    return " ".join(parts)


def build_report(inv: Investigation, state: dict, incident: Incident | None, approvals: list[ApprovalRequest]) -> dict:
    risk, resp = state.get("risk"), state.get("response")
    return {
        "investigation_id": inv.id, "title": inv.title, "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident_summary": executive_summary(state),
        "incident_id": incident.incident_uid if incident else None,
        "threat_classification": (state.get("phishing") or {}).get("classification") or ("log-based activity" if state.get("log") else "indicator-based"),
        "risk_level": risk["risk_level"] if risk else None, "risk_score": risk["risk_score"] if risk else None,
        "risk_explanation": risk["explanation"] if risk else "",
        "verified_findings": risk["confirmed_facts"] if risk else [],
        "ai_hypotheses": risk["hypotheses"] if risk else [],
        "evidence": {"phishing": state.get("phishing"), "threat_intel": state.get("intel"), "log_analysis": state.get("log")},
        "suspicious_indicators": [r["indicator"] for r in (state.get("intel") or {"results": []})["results"] if r["verdict"] in ("malicious", "suspicious")],
        "related_events_timeline": (state.get("investigation") or {}).get("timeline", []),
        "correlations": (state.get("investigation") or {}).get("correlations", []),
        "possible_attack_techniques": _techniques(state),
        "recommended_actions": [{**a} for a in resp["actions"]] if resp else [],
        "knowledge_note": resp["knowledge_note"] if resp else "No response guidance generated.",
        "knowledge_citations": resp["knowledge_citations"] if resp else [],
        "approval_requests": [{"id": a.id, "action_type": a.action_type, "target": a.target, "status": a.status.value} for a in approvals],
        "agent_execution": [{"agent": t["agent"], "status": t["status"], "attempts": t["attempts"], "duration_ms": t["duration_ms"], "error": t["error"],
                             "note": t["output"].get("reason") if t["status"] == "skipped" else None} for t in state["trace"]],
        "tool_calls": state.get("tool_calls", []),
        "conclusion": ("Findings above are split into verified facts and AI/heuristic hypotheses. Hypotheses require analyst confirmation. "
                       "No response action has been executed; all proposed actions await explicit human approval."),
    }


def _techniques(state: dict) -> list[dict]:
    m = {"brute_force": ("T1110", "Brute Force"), "password_spraying": ("T1110.003", "Password Spraying"),
         "unusual_access_time": ("T1078", "Valid Accounts"), "new_source_ip": ("T1078", "Valid Accounts"),
         "sensitive_activity_off_hours": ("T1078", "Valid Accounts")}
    out, seen = [], set()
    for a in (state.get("log") or {"alerts": []})["alerts"]:
        if a["type"] in m and m[a["type"]][0] not in seen:
            seen.add(m[a["type"]][0])
            out.append({"id": m[a["type"]][0], "name": m[a["type"]][1], "basis": f"mapped from alert type '{a['type']}'", "verified": False})
    if (state.get("phishing") or {}).get("classification") == "phishing":
        out.append({"id": "T1566", "name": "Phishing", "basis": "email classified phishing", "verified": False})
    return out


def execute(db: Session, inv: Investigation, user_id: int | None, request: dict, actor=None) -> Investigation:
    inv.status = "running"
    db.commit()
    tb = ToolBox(db, log_loader=lambda b: log_service.load_batch(db, b))
    try:
        state = run_investigation(tb, request)
    except Exception as e:  # noqa: BLE001
        inv.status, inv.report = "failed", {"error": f"{type(e).__name__}"}
        db.commit()
        audit(db, "investigation.failed", actor, "investigation", inv.id, {"error": type(e).__name__})
        return inv
    for t in state["trace"]:
        db.add(AgentRun(investigation_id=inv.id, agent_name=t["agent"], status=t["status"], attempts=t["attempts"],
                        output=t["output"], error=t["error"], duration_ms=t["duration_ms"]))
    risk, resp = state.get("risk"), state.get("response")
    if risk:
        for f in risk["confirmed_facts"]:
            db.add(Evidence(investigation_id=inv.id, kind="finding", summary=f[:2000], verified=True, source="agents"))
        for h in risk["hypotheses"]:
            db.add(Evidence(investigation_id=inv.id, kind="hypothesis", summary=h[:2000], verified=False, source="agents"))
    inv.risk_level, inv.risk_score = (risk["risk_level"], risk["risk_score"]) if risk else (None, None)
    incident = None
    if request.get("create_incident") and risk and risk["risk_level"] != "low":
        indicators = sorted({r["indicator"] for r in (state.get("intel") or {"results": []})["results"] if r["verdict"] in ("malicious", "suspicious")})
        incident = Incident(incident_uid=new_incident_uid(), title=inv.title[:200] or "Investigation", description=executive_summary(state),
                            source="ai_investigation", category=(state.get("phishing") or {}).get("classification", "log_alert") if state.get("phishing") else "log_alert",
                            severity=SEVERITY_MAP[risk["risk_level"]], status=IncidentStatus.under_investigation, related_indicators=indicators,
                            recommended_response="; ".join(f"{a['action_type']}:{a['target']}" for a in (resp["actions"] if resp else []))[:5000],
                            investigation_id=inv.id, created_by_id=user_id)
        db.add(incident)
        db.flush()
        db.add(IncidentHistory(incident_id=incident.id, actor_id=user_id, action="created", note=f"Created from investigation #{inv.id}"))
    approvals = []
    if resp:
        for a in resp["actions"]:
            ap = ApprovalRequest(incident_id=incident.id if incident else None, investigation_id=inv.id, action_type=a["action_type"],
                                 target=a["target"][:255], rationale=(a["rationale"] + (" Sources: " + "; ".join(a["citations"]) if a["citations"] else ""))[:5000],
                                 status=ApprovalStatus.pending, requested_by="response_agent")
            db.add(ap)
            approvals.append(ap)
        if incident and approvals:
            incident.status = IncidentStatus.awaiting_approval
    db.flush()
    inv.report = build_report(inv, state, incident, approvals)
    inv.status, inv.completed_at = "completed", datetime.now(timezone.utc)
    db.commit()
    audit(db, "investigation.completed", actor, "investigation", inv.id,
          {"risk_level": inv.risk_level, "incident": incident.incident_uid if incident else None, "approvals_created": len(approvals)})
    return inv
