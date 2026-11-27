"""Pydantic contracts for every agent's output. Output that fails validation is retried, then recorded as failed."""
from typing import Any, List, Literal, Optional

from pydantic import BaseModel, Field

Sev = Literal["low", "medium", "high", "critical"]


class PlanOut(BaseModel):
    agents: List[Literal["phishing", "threat_intel", "log_analysis"]]
    reason: str


class PhishingOut(BaseModel):
    classification: Literal["phishing", "suspicious", "legitimate"]
    confidence: float = Field(ge=0, le=1)
    risk_level: Sev
    risk_score: int = Field(ge=0, le=100)
    indicators: List[dict]
    explanation: str
    recommended_next_steps: List[str]
    urls_analysed: List[str] = []
    sender: str = ""
    ml: dict = {}
    deterministic_score: int = 0
    limitations: str = ""


class IntelItem(BaseModel):
    indicator: str
    type: str
    verdict: Literal["malicious", "suspicious", "clean", "unknown", "unavailable"]
    score: Optional[float] = None
    source: str
    demo: bool
    details: dict
    looked_up_at: str
    cached: bool = False
    is_ioc: bool = False


class IntelOut(BaseModel):
    results: List[IntelItem]
    unavailable: List[str] = []
    skipped: List[str] = []


class LogAlert(BaseModel):
    type: str
    severity: Sev
    title: str
    description: str
    src_ip: Optional[str]
    usernames: List[str]
    evidence: dict
    event_times: List[str] = []
    source: str = "rule"


class LogOut(BaseModel):
    summary: dict
    alerts: List[LogAlert]
    ml_meta: dict = {}


class TimelineEntry(BaseModel):
    time: Optional[str]
    source: str
    description: str
    verified: bool = True


class InvestigationOut(BaseModel):
    timeline: List[TimelineEntry]
    correlations: List[dict]
    shared_indicators: List[str]


class RiskOut(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: Sev
    factors: List[dict]
    confirmed_facts: List[str]
    hypotheses: List[str]
    explanation: str


class RecAction(BaseModel):
    action_type: Literal["block_indicator", "reset_password", "revoke_sessions", "isolate_endpoint", "investigate_access", "escalate_incident"]
    target: str
    rationale: str
    citations: List[str] = []


class ResponseOut(BaseModel):
    actions: List[RecAction]
    knowledge_citations: List[str]
    knowledge_note: str
    guidance: List[dict] = []


class AgentTrace(BaseModel):
    agent: str
    status: Literal["success", "failed", "skipped"]
    attempts: int = 1
    output: dict[str, Any] = {}
    error: Optional[str] = None
    duration_ms: int = 0
