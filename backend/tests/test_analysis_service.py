from unittest.mock import Mock

from backend.app.schemas.analysis import (
    AnalysisResponse,
    EmailAnalysisRequest,
    MessageAnalysisRequest,
    URLAnalysisRequest,
)
from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.analysis_service import AnalysisService


def build_response(
    analysis_type: str,
) -> AnalysisResponse:
    return AnalysisResponse(
        analysis_id="test-analysis-id",
        analysis_type=analysis_type,
        status="completed",
        risk_category="low",
        risk_score=0,
        summary="Test analysis response.",
        evidence=[],
        recommended_actions=[],
    )


def test_message_analysis_is_routed_to_message_builder(
    monkeypatch,
) -> None:
    expected_response = build_response("message")

    monkeypatch.setattr(
        "backend.app.services.analysis_service."
        "build_message_analysis_response",
        lambda message: expected_response,
    )

    service = AnalysisService()

    request = MessageAnalysisRequest(
        message=(
            "Your interview is scheduled for Monday "
            "at 11 AM. Please bring your resume."
        )
    )

    response = service.analyze_message(request)

    assert response == expected_response


def test_email_analysis_is_routed_to_email_builder(
    monkeypatch,
) -> None:
    expected_response = build_response("email")

    monkeypatch.setattr(
        "backend.app.services.analysis_service."
        "build_email_analysis_response",
        lambda **kwargs: expected_response,
    )

    service = AnalysisService()

    request = EmailAnalysisRequest(
        subject="Interview invitation",
        sender="recruiter@example.com",
        reply_to="recruiter@example.com",
        body=(
            "Your interview is scheduled for Monday "
            "at 11 AM."
        ),
    )

    response = service.analyze_email(request)

    assert response == expected_response


def test_url_analysis_uses_url_analyzer(
    monkeypatch,
) -> None:
    expected_response = build_response("url")

    fake_signals = Mock(spec=URLTechnicalSignals)

    fake_analyzer = Mock()
    fake_analyzer.analyze.return_value = fake_signals

    monkeypatch.setattr(
        "backend.app.services.analysis_service."
        "build_url_analysis_response",
        lambda signals: expected_response,
    )

    service = AnalysisService(
        url_analyzer=fake_analyzer,
    )

    request = URLAnalysisRequest(
        url="https://example.com/jobs"
    )

    response = service.analyze_url(request)

    fake_analyzer.analyze.assert_called_once_with(
        "https://example.com/jobs"
    )

    assert response == expected_response