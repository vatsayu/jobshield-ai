from typing import Literal

from pydantic import BaseModel, Field

from backend.app.schemas.analysis import AnalysisType
from backend.app.schemas.analysis import EvidenceItem


class AIAnalysisRequest(BaseModel):
    """
    Evidence-grounded input provided to the AI analysis service.

    The AI must explain the available evidence rather than inventing
    independent findings.
    """

    analysis_type: AnalysisType

    input_summary: str = Field(
        ...,
        min_length=1,
        max_length=5000,
    )

    risk_category: Literal[
        "unknown",
        "low",
        "medium",
        "high",
        "critical",
    ]

    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
    )

    evidence: list[EvidenceItem] = Field(
        default_factory=list,
        max_length=100,
    )

    recommended_actions: list[str] = Field(
        default_factory=list,
        max_length=20,
    )