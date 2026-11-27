from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.entities import ApprovalStatus, IncidentStatus, Role, Severity

ACTION_TYPES = ["block_indicator", "reset_password", "revoke_sessions",
                "isolate_endpoint", "investigate_access", "escalate_incident"]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RegisterIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=10, max_length=128)

    @field_validator("password")
    @classmethod
    def strong(cls, v: str) -> str:
        if not (any(c.isalpha() for c in v) and any(c.isdigit() for c in v)):
            raise ValueError("Password must contain letters and digits")
        return v


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserOut(ORM):
    id: int
    email: str
    full_name: str
    role: Role
    is_active: bool
    created_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    password: Optional[str] = Field(default=None, min_length=10, max_length=128)


class RoleUpdate(BaseModel):
    role: Role
    is_active: bool = True


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=10000)
    source: str = Field(default="manual", max_length=60)
    category: str = Field(default="uncategorized", max_length=60)
    severity: Severity = Severity.low
    related_indicators: List[str] = Field(default_factory=list, max_length=100)


class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    severity: Optional[Severity] = None
    assigned_to_id: Optional[int] = None
    resolution_notes: Optional[str] = Field(default=None, max_length=10000)
    recommended_response: Optional[str] = Field(default=None, max_length=10000)


class HistoryIn(BaseModel):
    note: str = Field(min_length=1, max_length=5000)


class HistoryOut(ORM):
    id: int
    action: str
    note: str
    actor_id: Optional[int]
    created_at: datetime


class IncidentOut(ORM):
    id: int
    incident_uid: str
    title: str
    description: str
    source: str
    category: str
    severity: Severity
    status: IncidentStatus
    related_indicators: list
    detected_at: datetime
    assigned_to_id: Optional[int]
    recommended_response: str
    resolution_notes: str
    investigation_id: Optional[int]
    created_at: datetime


class IncidentDetail(IncidentOut):
    history: List[HistoryOut] = []


class PhishingIn(BaseModel):
    subject: str = Field(default="", max_length=500)
    sender: str = Field(default="", max_length=320)
    body: str = Field(default="", max_length=50000)
    urls: List[str] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IndicatorIn(BaseModel):
    value: str = Field(min_length=1, max_length=512)
    indicator_type: Optional[str] = Field(default=None, pattern="^(ip|domain|url|hash)$")


class InvestigationIn(BaseModel):
    title: str = Field(default="Investigation", max_length=200)
    phishing: Optional[PhishingIn] = None
    indicators: List[str] = Field(default_factory=list, max_length=50)
    log_batch_id: Optional[str] = Field(default=None, max_length=40)
    create_incident: bool = True


class ApprovalOut(ORM):
    id: int
    incident_id: Optional[int]
    investigation_id: Optional[int]
    action_type: str
    target: str
    rationale: str
    status: ApprovalStatus
    requested_by: str
    decided_by_id: Optional[int]
    decision_note: str
    created_at: datetime
    decided_at: Optional[datetime]


class ApprovalRequestIn(BaseModel):
    incident_id: Optional[int] = None
    action_type: str
    target: str = Field(min_length=1, max_length=255)
    rationale: str = Field(default="", max_length=5000)

    @field_validator("action_type")
    @classmethod
    def valid_action(cls, v: str) -> str:
        if v not in ACTION_TYPES:
            raise ValueError(f"action_type must be one of {ACTION_TYPES}")
        return v


class DecisionIn(BaseModel):
    note: str = Field(default="", max_length=2000)
