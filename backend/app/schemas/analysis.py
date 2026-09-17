from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


AnalysisType = Literal["url", "message", "email"]

RiskCategory = Literal[
    "unknown",
    "low",
    "medium",
    "high",
    "critical",
]


class URLAnalysisRequest(BaseModel):
    url: HttpUrl = Field(
        ...,
        description="Public job posting or recruitment URL to analyze.",
    )


class MessageAnalysisRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=10,
        max_length=20_000,
        description="Recruitment-related message text to analyze.",
    )

    
class EmailAnalysisRequest(BaseModel):
    subject: str = Field(
        default="",
        max_length=500,
        description="Email subject line.",
    )
    sender: str = Field(
        default="",
        max_length=320,
        description="Sender email address.",
    )
    reply_to: str = Field(
        default="",
        max_length=320,
        description="Reply-To email address.",
    )
    body: str = Field(
        ...,
        min_length=10,
        max_length=30_000,
        description="Recruitment-related email body text.",
    )



class EvidenceItem(BaseModel):
    category: str
    signal: str
    explanation: str
    severity: RiskCategory


class AnalysisResponse(BaseModel):
    analysis_id: str
    analysis_type: AnalysisType
    status: Literal["queued", "processing", "completed", "failed"]
    risk_category: RiskCategory
    risk_score: int = Field(ge=0, le=100)
    summary: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)