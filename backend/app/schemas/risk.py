from typing import Literal

from pydantic import BaseModel, Field


RiskCategory = Literal[
    "unknown",
    "low",
    "medium",
    "high",
    "critical",
]


class RiskContribution(BaseModel):
    signal: str
    points: int
    explanation: str


class RiskAssessment(BaseModel):
    risk_category: RiskCategory
    risk_score: int = Field(ge=0, le=100)
    confidence: Literal[
        "low",
        "medium",
        "high",
    ]
    contributions: list[RiskContribution] = Field(
        default_factory=list
    )
    rationale: str