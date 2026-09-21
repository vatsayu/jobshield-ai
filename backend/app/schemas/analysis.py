from typing import Literal

from pydantic import BaseModel, Field, field_validator , HttpUrl


AnalysisType = Literal["url", "message", "email"]

RiskCategory = Literal[
    "unknown",
    "low",
    "medium",
    "high",
    "critical",
]

AnalysisStatus = Literal[
    "queued",
    "processing",
    "completed",
    "failed",
]

EvidenceStatus = Literal[
    "detected",
    "not_detected",
    "unknown",
]

EvidenceSource = Literal[
    "deterministic_analysis",
    "external_lookup",
    "ai_analysis",
    "user_provided",
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
    """
    Normalized security finding shared by URL, message, and email analysis.

    Evidence must describe an observable signal. It must not claim
    certainty beyond what the available evidence supports.
    """

    category: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Broad finding category.",
    )

    signal: str = Field(
        ...,
        min_length=1,
        max_length=150,
        description="Stable machine-readable signal identifier.",
    )

    explanation: str = Field(
        ...,
        min_length=1,
        max_length=2_000,
        description="Human-readable explanation of the finding.",
    )

    severity: RiskCategory = Field(
        ...,
        description="Risk severity associated with this finding.",
    )

    status: EvidenceStatus = Field(
        default="detected",
        description="Whether the signal was detected or remains unknown.",
    )

    source: EvidenceSource = Field(
        default="deterministic_analysis",
        description="Origin of the evidence.",
    )

    @field_validator("category", "signal", "explanation")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        """Reject strings containing only whitespace."""

        cleaned_value = value.strip()

        if not cleaned_value:
            raise ValueError("Value must not be blank.")

        return cleaned_value


class AnalysisResponse(BaseModel):
    """
    Common response contract for all JobShield AI analysis types.
    """

    analysis_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    analysis_type: AnalysisType

    status: AnalysisStatus

    risk_category: RiskCategory

    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
    )

    summary: str = Field(
        ...,
        min_length=1,
        max_length=5_000,
    )

    evidence: list[EvidenceItem] = Field(
        default_factory=list,
    )

    recommended_actions: list[str] = Field(
        default_factory=list,
        max_length=20,
    )

    @field_validator("summary")
    @classmethod
    def reject_blank_summary(cls, value: str) -> str:
        """Ensure the response always includes a meaningful summary."""

        cleaned_value = value.strip()

        if not cleaned_value:
            raise ValueError("Summary must not be blank.")

        return cleaned_value

    @field_validator("recommended_actions")
    @classmethod
    def clean_recommended_actions(
        cls,
        actions: list[str],
    ) -> list[str]:
        """Remove blank actions and duplicate recommendations."""

        cleaned_actions: list[str] = []
        seen_actions: set[str] = set()

        for action in actions:
            cleaned_action = action.strip()

            if not cleaned_action:
                continue

            normalized_action = cleaned_action.casefold()

            if normalized_action in seen_actions:
                continue

            seen_actions.add(normalized_action)
            cleaned_actions.append(cleaned_action)

        return cleaned_actions