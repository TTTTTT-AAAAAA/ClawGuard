from datetime import datetime
from pydantic import BaseModel, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class LoginRequest(BaseModel):
    username: str
    password: str


class ChallengeRequest(BaseModel):
    uid: str
    purpose: str = "login"


class ChallengeResponse(BaseModel):
    uid: str
    nonce: str
    timestamp: int
    message: str


class CFLLoginRequest(BaseModel):
    uid: str
    nonce: str
    timestamp: int
    signature: str


class TaskCreateRequest(BaseModel):
    action: str
    params: dict = Field(default_factory=dict)
    input_text: str | None = None
    signature: str | None = None
    nonce: str | None = None
    timestamp: int | None = None


class ReviewCaptureRequest(BaseModel):
    action: str
    params: dict = Field(default_factory=dict)
    input_text: str | None = None
    source: str = "openclaw"


class ReviewUpdateRequest(BaseModel):
    action: str | None = None
    params: dict | None = None
    input_text: str | None = None
    note: str | None = None


class ReviewDecisionRequest(BaseModel):
    note: str | None = None
    action: str | None = None
    params: dict | None = None
    input_text: str | None = None


class ReviewResponse(BaseModel):
    review_id: str
    uid: str
    action: str
    params: dict
    input_text: str | None
    status: str
    recommendation: str
    filter_decision: str
    command_allow: bool
    analysis: dict
    job_id: str | None = None
    created_at: datetime
    updated_at: datetime
    reviewed_at: datetime | None = None


class TaskResponse(BaseModel):
    job_id: str
    status: str
    message: str


class TaskStatusResponse(BaseModel):
    job_id: str
    action: str
    status: str
    exit_code: int | None = None
    created_at: datetime
    finished_at: datetime | None = None
    error_message: str | None = None


class AuditItem(BaseModel):
    timestamp: datetime
    uid: str | None
    event_type: str
    result: str
    risk_level: str
    message: str
    job_id: str | None = None
