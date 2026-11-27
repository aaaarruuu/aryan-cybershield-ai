"""Controlled tool access for agents. Agents can ONLY call tools on their allow-list.

There is deliberately no shell, file-write, network-write or database-write tool. Consequential actions are
proposed as data and become PENDING approval requests; nothing here can execute them.
"""
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.rag import store as rag
from app.services import phishing as phishing_service
from app.services import threat_intel

ALLOWED_TOOLS: dict[str, set[str]] = {
    "phishing": {"phishing.analyse"},
    "threat_intel": {"threat_intel.lookup"},
    "log_analysis": {"log.analyse"},
    "investigation": set(),            # pure reasoning over state, no tools
    "risk_assessment": set(),
    "response": {"rag.search"},
}


class ToolPermissionError(PermissionError):
    pass


class ToolBox:
    def __init__(self, db: Session, log_loader: Callable[[str], Any] | None = None):
        self.db = db
        self._log_loader = log_loader
        self.calls: list[dict] = []   # traceability: every tool call is recorded

    def call(self, agent: str, tool: str, **kwargs):
        if tool not in ALLOWED_TOOLS.get(agent, set()):
            self.calls.append({"agent": agent, "tool": tool, "allowed": False})
            raise ToolPermissionError(f"Agent '{agent}' is not permitted to use tool '{tool}'")
        self.calls.append({"agent": agent, "tool": tool, "allowed": True})
        if tool == "phishing.analyse":
            return phishing_service.analyse(**kwargs)
        if tool == "threat_intel.lookup":
            return threat_intel.lookup(self.db, **kwargs)
        if tool == "rag.search":
            return rag.search(**kwargs)
        if tool == "log.analyse":
            from app.ml.log_analysis import analyse
            return analyse(self._log_loader(kwargs["batch_id"]))
        raise ToolPermissionError(f"Unknown tool '{tool}'")
