from backend.app.schemas.ai.requests import AIAnalysisRequest
from backend.app.schemas.ai.responses import AIAnalysisResponse
from backend.app.services.ai.provider import AIProvider
from backend.app.services.ai.service import AIAnalysisService
from backend.app.services.ai.provider import AIProviderError

def make_request() -> AIAnalysisRequest:
    return AIAnalysisRequest(
        analysis_type="message",
        input_summary="A recruiter requested an upfront registration payment.",
        risk_category="high",
        risk_score=80,
        evidence=[],
        recommended_actions=[
            "Do not send money before independently verifying the opportunity.",
        ],
    )


def test_ai_service_returns_fallback_when_disabled() -> None:
    service = AIAnalysisService(
        provider=None,
        enabled=False,
    )

    result = service.analyze(make_request())

    assert isinstance(result, AIAnalysisResponse)
    assert result.confidence == "unknown"
    assert "unavailable" in result.summary.lower()
    assert result.recommended_actions == [
        "Do not send money before independently verifying the opportunity.",
    ]


def test_ai_service_returns_fallback_without_provider() -> None:
    service = AIAnalysisService(
        provider=None,
        enabled=True,
    )

    result = service.analyze(make_request())

    assert result.confidence == "unknown"
    assert any(
        "No AI provider was available" in limitation
        for limitation in result.limitations
    )


class FailingProvider(AIProvider):
    def analyze(
        self,
        request: AIAnalysisRequest,
    ) -> AIAnalysisResponse:
        raise AIProviderError("Simulated provider failure")


def test_ai_service_falls_back_when_provider_fails() -> None:
    service = AIAnalysisService(
        provider=FailingProvider(),
        enabled=True,
    )

    result = service.analyze(make_request())

    assert isinstance(result, AIAnalysisResponse)
    assert result.confidence == "unknown"
    assert "unavailable" in result.summary.lower()

class SuccessfulProvider(AIProvider):
    def analyze(
        self,
        request: AIAnalysisRequest,
    ) -> AIAnalysisResponse:
        return AIAnalysisResponse(
            summary="Provider successfully analyzed the supplied evidence.",
            confidence="medium",
            findings=["The provider returned a structured finding."],
            recommended_actions=[
                "Independently verify the opportunity."
            ],
            limitations=[
                "The provider did not independently verify the organization."
            ],
        )


def test_ai_service_delegates_to_successful_provider() -> None:
    service = AIAnalysisService(
        provider=SuccessfulProvider(),
        enabled=True,
    )

    result = service.analyze(make_request())

    assert result.confidence == "medium"
    assert (
        result.summary
        == "Provider successfully analyzed the supplied evidence."
    )
    assert result.findings == [
        "The provider returned a structured finding."
    ]