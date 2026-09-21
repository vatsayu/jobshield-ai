from typing import Literal

from pydantic import BaseModel, Field


class AIAnalysisResponse(BaseModel):
    """
    Structured response returned by the AI analysis service.

    The response is explanatory and advisory. It does not establish
    that a recruiter, organization, or job posting is fraudulent.
    """

    summary: str = Field(
        ...,
        min_length=1,
        max_length=3000,
    )

    confidence: Literal[
        "low",
        "medium",
        "high",
        "unknown",
    ] = "unknown"

    findings: list[str] = Field(
        default_factory=list,
        max_length=20,
    )

    recommended_actions: list[str] = Field(
        default_factory=list,
        max_length=20,
    )

    limitations: list[str] = Field(
        default_factory=list,
        max_length=20,
    )

    disclaimer: str = (
        "This AI-assisted explanation is based on the available "
        "evidence and does not establish that a recruiter, "
        "organization, or job posting is fraudulent."
    )