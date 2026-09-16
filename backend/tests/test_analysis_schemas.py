import pytest
from pydantic import ValidationError

from backend.app.schemas.analysis import (
    AnalysisResponse,
    EvidenceItem,
    URLAnalysisRequest,
)


def test_valid_url_analysis_request() -> None:
    request = URLAnalysisRequest(
        url="https://example.com/jobs/security-analyst"
    )

    assert str(request.url) == "https://example.com/jobs/security-analyst"


def test_invalid_url_scheme_is_rejected() -> None:
    with pytest.raises(ValidationError):
        URLAnalysisRequest(url="ftp://example.com/file")


def test_invalid_url_text_is_rejected() -> None:
    with pytest.raises(ValidationError):
        URLAnalysisRequest(url="not-a-url")


def test_analysis_response_contract() -> None:
    response = AnalysisResponse(
        analysis_id="analysis-test-001",
        analysis_type="url",
        status="completed",
        risk_category="medium",
        risk_score=45,
        summary="Preliminary analysis completed.",
        evidence=[
            EvidenceItem(
                category="domain",
                signal="Example signal",
                explanation="Example explanation",
                severity="medium",
            )
        ],
        recommended_actions=[
            "Verify the employer through an independent source."
        ],
    )

    assert response.risk_score == 45
    assert response.risk_category == "medium"
    assert len(response.evidence) == 1