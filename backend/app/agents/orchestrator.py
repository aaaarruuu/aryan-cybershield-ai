"""Multi-agent investigation engine (LangGraph).

                 planner
               /         \\            <- independent: run in parallel
        phishing        log_analysis
               \\         /
              threat_intel              <- needs URLs/domains/IPs found above
                   |
              investigation             <- correlation + timeline
                   |
             risk_assessment            <- deterministic, evidence-based scoring
                   |  (skipped when nothing to act on)
               response                 <- RAG-backed *proposals* only

Guarantees enforced in code: tool allow-lists (tools.py), validated structured outputs with bounded retries
(`_run`), severity computed from evidence (never from an LLM), responses are proposals (PENDING approvals).
"""
import ipaddress
import operator
import re
import time
from typing import Annotated, Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ValidationError

from app.agents import schemas as S
from app.agents.tools import ToolBox

MAX_ATTEMPTS = 2
MAX_INTEL_INDICATORS = 15
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]
SEV_POINTS = {"critical": 40, "high": 25, "medium": 10, "low": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class State(TypedDict, total=False):
    request: dict
    plan: dict
    phishing: dict
    log: dict
    intel: dict
    investigation: dict
    risk: dict
    response: dict
    trace: Annotated[list, operator.add]


def _is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False  # not an IP (domain/URL/hash): never "internal"
    return any(a in n for n in PRIVATE_NETS) if a.version == 4 else (a.is_loopback or a.is_link_local)


def _run(name: str, fn: Callable[[], dict], model: type[BaseModel]) -> tuple[dict | None, dict]:
    """Run one agent with output validation and bounded retries. Never raises."""
    t0, err, attempts = time.perf_counter(), None, 0
    for attempts in range(1, MAX_ATTEMPTS + 1):
        try:
            out = model.model_validate(fn()).model_dump()
            return out, {"agent": name, "status": "success", "attempts": attempts, "output": out, "error": None,
                         "duration_ms": int((time.perf_counter() - t0) * 1000)}
        except (ValidationError, Exception) as e:  # noqa: BLE001 - agent failure must not crash the investigation
            err = f"{type(e).__name__}: {str(e)[:300]}"
    return None, {"agent": name, "status": "failed", "attempts": attempts, "output": {}, "error": err,
                  "duration_ms": int((time.perf_counter() - t0) * 1000)}


def _skipped(name: str, why: str) -> dict:
    return {"agent": name, "status": "skipped", "attempts": 0, "output": {"reason": why}, "error": None, "duration_ms": 0}


def _domain_of(url_or_domain: str) -> str:
    from urllib.parse import urlparse
    v = url_or_domain if "://" in url_or_domain else "http://" + url_or_domain
    return (urlparse(v).hostname or "").lower()


# ------------------------------------------------------------------ agents (pure functions of state + toolbox)
def plan_agent(request: dict) -> dict:
    agents, reasons = [], []
    if request.get("phishing"):
        agents.append("phishing"); reasons.append("email content supplied")
    if request.get("log_batch_id"):
        agents.append("log_analysis"); reasons.append("log batch supplied")
    if request.get("indicators") or request.get("phishing") or request.get("log_batch_id"):
        agents.append("threat_intel"); reasons.append("indicators may be extracted/looked up")
    return {"agents": agents, "reason": "; ".join(reasons) or "no investigable input supplied"}


def phishing_agent(tb: ToolBox, req: dict) -> dict:
    p = req["phishing"]
    out = tb.call("phishing", "phishing.analyse", subject=p.get("subject", ""), sender=p.get("sender", ""),
                  body=p.get("body", ""), urls=p.get("urls", []), metadata=p.get("metadata", {}))
    out["sender"] = p.get("sender", "")
    return out


def log_agent(tb: ToolBox, req: dict) -> dict:
    res = tb.call("log_analysis", "log.analyse", batch_id=req["log_batch_id"])
    times = tb._log_loader(req["log_batch_id"])["timestamp"]
    alerts = []
    for a in res["alerts"]:
        ets = sorted({str(times.iloc[i]) for i in a["event_idx"] if i < len(times)})
        alerts.append({**{k: a[k] for k in ("type", "severity", "title", "description", "src_ip", "usernames", "evidence", "source")},
                       "event_times": ets[:20]})
    return {"summary": res["summary"], "alerts": alerts, "ml_meta": res["ml_meta"]}


def intel_agent(tb: ToolBox, req: dict, phishing: dict | None, log: dict | None) -> dict:
    cand: list[str] = list(req.get("indicators") or [])
    if phishing:
        from app.services.phishing import registrable
        for u in phishing.get("urls_analysed", []):
            host = _domain_of(u)
            cand.append(host)
            if host and not host.replace(".", "").isdigit():
                cand.append(registrable(host))     # reputation is tracked per registrable domain
        m = re.search(r"@([A-Za-z0-9.\-]+)", phishing.get("sender", ""))
        if m:
            cand.append(m.group(1).lower())
    if log:
        cand += [a["src_ip"] for a in log["alerts"] if a.get("src_ip") and a["source"] == "rule"]
    seen, results, skipped = set(), [], []
    for c in cand:
        c = c.strip()
        if not c or c in seen:
            continue
        seen.add(c)
        if _is_internal(c):
            skipped.append(f"{c}: internal address, external reputation not applicable")
            continue
        if len(results) >= MAX_INTEL_INDICATORS:
            skipped.append(f"{c}: lookup cap ({MAX_INTEL_INDICATORS}) reached")
            continue
        try:
            results.append(tb.call("threat_intel", "threat_intel.lookup", value=c))
        except ValueError as e:
            skipped.append(f"{c}: {e}")
    return {"results": results, "unavailable": [r["indicator"] for r in results if r["verdict"] == "unavailable"], "skipped": skipped}


def investigation_agent(phishing, log, intel) -> dict:
    timeline, sources_by_ind = [], {}

    def note(ind, src):
        if ind:
            sources_by_ind.setdefault(ind, set()).add(src)

    if log:
        for a in log["alerts"]:
            ts = a["event_times"][0] if a["event_times"] else None
            timeline.append({"time": ts, "source": "log_analysis", "verified": a["source"] == "rule",
                             "description": f"[{a['severity'].upper()}] {a['title']}" + ("" if a["source"] == "rule" else " (ML anomaly signal, unconfirmed)")})
            note(a.get("src_ip"), "log_analysis")
            for u in a["usernames"]:
                note(f"user:{u}", "log_analysis")
    if phishing:
        timeline.append({"time": None, "source": "phishing", "verified": True,
                         "description": f"Email analysed: classified {phishing['classification']} (risk {phishing['risk_level']})"})
        for u in phishing.get("urls_analysed", []):
            note(_domain_of(u), "phishing")
        m = re.search(r"@([A-Za-z0-9.\-]+)", phishing.get("sender", ""))
        note(m.group(1).lower() if m else None, "phishing")
    if intel:
        for r in intel["results"]:
            note(r["indicator"], "threat_intel")
            if r["verdict"] in ("malicious", "suspicious"):
                timeline.append({"time": r["looked_up_at"], "source": "threat_intel", "verified": not r["demo"],
                                 "description": f"{r['indicator']} rated {r['verdict']} by {r['source']}" + (" (DEMO data)" if r["demo"] else "")})
    timeline.sort(key=lambda e: (e["time"] is None, e["time"] or ""))
    shared = sorted(i for i, s in sources_by_ind.items() if len(s) >= 2 and not i.startswith("user:"))
    corr = [{"indicator": i, "sources": sorted(sources_by_ind[i]),
             "statement": f"{i} appears in {' and '.join(sorted(sources_by_ind[i]))}"} for i in shared]
    # account-level correlation: same user in multiple distinct alert types
    if log:
        by_user: dict[str, set] = {}
        for a in log["alerts"]:
            if a["source"] != "rule":
                continue
            for u in a["usernames"]:
                by_user.setdefault(u, set()).add(a["type"])
        for u, types in by_user.items():
            if len(types) >= 2:
                corr.append({"indicator": f"user:{u}", "sources": ["log_analysis"],
                             "statement": f"Account '{u}' is involved in multiple alert types: {', '.join(sorted(types))}"})
    return {"timeline": timeline, "correlations": corr, "shared_indicators": shared}


def risk_agent(phishing, log, intel, inv) -> dict:
    factors, facts, hyps, ml_signals = [], [], [], []
    log_pts = 0
    if log:
        for a in log["alerts"]:
            if a["source"] == "ml":
                ml_signals.append(a)
                continue
            pts = SEV_POINTS[a["severity"]]
            log_pts += pts
            factors.append({"source": "log_analysis", "reason": a["title"], "points": pts})
            facts.append(f"{a['description']}")
            if a["evidence"].get("success_after_failures"):
                hyps.append(f"Account(s) {', '.join(a['usernames'])} may be compromised: a successful login from {a['src_ip']} followed the failures (inference, verify).")
    log_pts = min(log_pts, 60)
    top_ml = sorted(ml_signals, key=lambda a: -a["evidence"].get("anomaly_score", 0))[:3]
    for a in top_ml:
        hyps.append(f"ML anomaly signal for {a['src_ip']} (unconfirmed, unsupervised, relative to this batch)")
    if len(ml_signals) > len(top_ml):
        hyps.append(f"{len(ml_signals) - len(top_ml)} further lower-ranked ML anomaly signal(s) omitted; see the log analysis evidence.")
    ph_pts = 0
    if phishing:
        if phishing["classification"] == "phishing":
            ph_pts = min(40, 20 + int(phishing["risk_score"] * 0.2))
        elif phishing["classification"] == "suspicious":
            ph_pts = 10
        if ph_pts:
            factors.append({"source": "phishing", "reason": f"Email classified {phishing['classification']}", "points": ph_pts})
        for i in phishing["indicators"][:6]:
            facts.append(f"Email indicator: {i['summary']} ({i['evidence'][:80]})")
        if phishing["classification"] == "phishing":
            hyps.append("The email may be part of a credential-harvesting attempt (inference from indicators).")
    ti_pts, mal, sus = 0, 0, 0
    if intel:
        for r in intel["results"]:
            tag = " [DEMO data]" if r["demo"] else ""
            if r["verdict"] == "malicious":
                mal += 1
                facts.append(f"{r['indicator']} is rated malicious by {r['source']}{tag}")
            elif r["verdict"] == "suspicious":
                sus += 1
                facts.append(f"{r['indicator']} is rated suspicious by {r['source']}{tag}")
        ti_pts = min(40, 20 * mal) + min(16, 8 * sus)
        if ti_pts:
            factors.append({"source": "threat_intel", "reason": f"{mal} malicious and {sus} suspicious indicator(s)", "points": ti_pts})
    bad = {r["indicator"] for r in (intel or {"results": []})["results"] if r["verdict"] in ("malicious", "suspicious")}
    corroborated = [i for i in (inv["shared_indicators"] if inv else []) if i in bad]   # observed in an artefact AND rated bad
    corr_pts = 10 if corroborated else 0
    if corr_pts:
        factors.append({"source": "investigation", "reason": f"Malicious/suspicious indicator corroborated across sources: {', '.join(corroborated[:4])}", "points": corr_pts})
    score = min(100, log_pts + ph_pts + ti_pts + corr_pts)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    caveats = []
    if intel and intel["unavailable"]:
        caveats.append(f"Threat intelligence was unavailable for: {', '.join(intel['unavailable'])} (not scored).")
    if intel and any(r["demo"] for r in intel["results"]):
        caveats.append("Some intelligence comes from the bundled DEMO dataset, not a live service.")
    expl = (f"Risk score {score}/100 ({level}), computed from {len(factors)} evidence-based factor(s): "
            + ("; ".join(f"{f['reason']} (+{f['points']})" for f in factors) or "no scoring evidence found") + ". "
            + " ".join(caveats))
    return {"risk_score": score, "risk_level": level, "factors": factors, "confirmed_facts": facts, "hypotheses": hyps, "explanation": expl.strip()}


def response_agent(tb: ToolBox, phishing, log, intel, risk) -> dict:
    acts: dict[tuple, dict] = {}

    def add(t, target, why, q):
        if (t, target) not in acts and len(acts) < 10:
            acts[(t, target)] = {"action_type": t, "target": target, "rationale": why, "_q": q}

    if log:
        for a in log["alerts"]:
            if a["source"] != "rule":
                continue
            if a["type"] in ("brute_force", "password_spraying") and a.get("src_ip"):
                add("block_indicator", a["src_ip"], f"{a['title']}.", "brute force failed logins contain block source IP")
            if a["evidence"].get("success_after_failures"):
                for u in a["usernames"][:3]:
                    add("reset_password", u, f"Successful login followed {a['evidence']['failed_attempts']} failures; treat account as potentially compromised.", "compromised account reset password revoke sessions")
                    add("revoke_sessions", u, "Invalidate sessions that may belong to the attacker.", "compromised account reset password revoke sessions")
            if a["type"] in ("sensitive_activity_off_hours", "unusual_access_time"):
                for u in a["usernames"][:3]:
                    add("investigate_access", u, a["title"] + ".", "compromised account unusual access investigate timeline")
    if intel:
        for r in intel["results"]:
            if r["verdict"] == "malicious":
                add("block_indicator", r["indicator"], f"Rated malicious by {r['source']}" + (" (DEMO data)" if r["demo"] else "") + ".", "malicious indicator block ip domain hash")
    if phishing and phishing["classification"] == "phishing":
        m = re.search(r"@([A-Za-z0-9.\-]+)", phishing.get("sender", ""))
        if m:
            add("block_indicator", m.group(1).lower(), "Sender domain used in an email classified as phishing.", "phishing email quarantine block sender domain")
    if risk["risk_level"] in ("critical", "high"):
        add("escalate_incident", "security-team", f"Risk level {risk['risk_level']} ({risk['risk_score']}/100).", "escalate incident response")
    cites, guidance, queries_done = [], [], {}
    for a in acts.values():
        q = a.pop("_q")
        if q not in queries_done:
            queries_done[q] = tb.call("response", "rag.search", query=q, k=2)
        hits = queries_done[q]["results"]
        a["citations"] = [h["citation"] for h in hits]
        for h in hits:
            if h["citation"] not in cites:
                cites.append(h["citation"])
                guidance.append({"citation": h["citation"], "excerpt": h["text"][:300], "untrusted_source": True})
    note = ("Recommendations are supported by retrieved knowledge-base excerpts." if cites else
            "No relevant guidance was found in the knowledge base; these recommendations are rule-based and not backed by documents.")
    return {"actions": list(acts.values()), "knowledge_citations": cites, "knowledge_note": note, "guidance": guidance}


# ------------------------------------------------------------------ graph
def build_graph(tb: ToolBox):
    def planner(state: State):
        plan = plan_agent(state["request"])
        out, tr = _run("planner", lambda: plan, S.PlanOut)
        return {"plan": out or {"agents": [], "reason": "planner failed"}, "trace": [tr]}

    def phishing_node(state: State):
        if "phishing" not in state["plan"]["agents"]:
            return {"trace": [_skipped("phishing", "no email content supplied")]}
        out, tr = _run("phishing", lambda: phishing_agent(tb, state["request"]), S.PhishingOut)
        return {"phishing": out, "trace": [tr]} if out else {"trace": [tr]}

    def log_node(state: State):
        if "log_analysis" not in state["plan"]["agents"]:
            return {"trace": [_skipped("log_analysis", "no log batch supplied")]}
        out, tr = _run("log_analysis", lambda: log_agent(tb, state["request"]), S.LogOut)
        return {"log": out, "trace": [tr]} if out else {"trace": [tr]}

    def intel_node(state: State):
        if "threat_intel" not in state["plan"]["agents"]:
            return {"trace": [_skipped("threat_intel", "nothing to look up")]}
        out, tr = _run("threat_intel", lambda: intel_agent(tb, state["request"], state.get("phishing"), state.get("log")), S.IntelOut)
        return {"intel": out, "trace": [tr]} if out else {"trace": [tr]}

    def investigation_node(state: State):
        if not any(state.get(k) for k in ("phishing", "log", "intel")):
            return {"trace": [_skipped("investigation", "no evidence to correlate")]}
        out, tr = _run("investigation", lambda: investigation_agent(state.get("phishing"), state.get("log"), state.get("intel")), S.InvestigationOut)
        return {"investigation": out, "trace": [tr]} if out else {"trace": [tr]}

    def risk_node(state: State):
        if not any(state.get(k) for k in ("phishing", "log", "intel")):
            return {"trace": [_skipped("risk_assessment", "no evidence to assess")]}
        out, tr = _run("risk_assessment", lambda: risk_agent(state.get("phishing"), state.get("log"), state.get("intel"), state.get("investigation")), S.RiskOut)
        return {"risk": out, "trace": [tr]} if out else {"trace": [tr]}

    def response_node(state: State):
        out, tr = _run("response", lambda: response_agent(tb, state.get("phishing"), state.get("log"), state.get("intel"), state["risk"]), S.ResponseOut)
        return {"response": out, "trace": [tr]} if out else {"trace": [tr]}

    def no_action_node(state: State):
        return {"trace": [_skipped("response", "risk is low with no scoring evidence; no response action warranted")]}

    def route_after_risk(state: State):
        r = state.get("risk")
        return "response" if r and (r["risk_level"] != "low" or r["factors"]) else "done"

    g = StateGraph(State)
    for name, fn in [("planner", planner), ("phishing", phishing_node), ("log_analysis", log_node), ("threat_intel", intel_node),
                     ("investigation", investigation_node), ("risk_assessment", risk_node), ("response", response_node), ("no_action", no_action_node)]:
        g.add_node(name, fn)
    g.add_edge(START, "planner")
    g.add_edge("planner", "phishing")
    g.add_edge("planner", "log_analysis")          # parallel fan-out (independent agents)
    g.add_edge(["phishing", "log_analysis"], "threat_intel")  # join
    g.add_edge("threat_intel", "investigation")
    g.add_edge("investigation", "risk_assessment")
    g.add_conditional_edges("risk_assessment", route_after_risk, {"response": "response", "done": "no_action"})
    g.add_edge("response", END)
    g.add_edge("no_action", END)
    return g.compile()


def run_investigation(tb: ToolBox, request: dict) -> dict:
    """Execute the graph and return the final shared state."""
    final = build_graph(tb).invoke({"request": request, "trace": []})
    final["tool_calls"] = tb.calls
    return final
