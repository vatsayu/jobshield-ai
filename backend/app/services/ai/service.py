from backend.app.schemas.ai.requests import AIAnalysisRequest
from backend.app.schemas.ai.responses import AIAnalysisResponse
from backend.app.services.ai.provider import (
    AIProvider,
    AIProviderError,
)


class AIAnalysisService:
    """
    Coordinates AI analysis while preserving safe fallback behavior.

    AI is optional. Deterministic analysis remains the source of the
    existing risk score and evidence.
    """

    def __init__(
        self,
        provider: AIProvider | None = None,
        enabled: bool = False,
    ) -> None:
        self.provider = provider
        self.enabled = enabled

    def analyze(
        self,
        request: AIAnalysisRequest,
    ) -> AIAnalysisResponse:
        """
        Return an AI explanation or a safe fallback response.

        Expected provider failures are converted into a transparent
        fallback response. Unexpected programming errors are allowed
        to propagate instead of being silently hidden.
        """

        if not self.enabled or self.provider is None:
            return self._fallback_response(request)

        try:
            return self.provider.analyze(request)
        except AIProviderError:
            return self._fallback_response(request)

    @staticmethod
    def _fallback_response(
        request: AIAnalysisRequest,
    ) -> AIAnalysisResponse:
        """Create a transparent response when AI is unavailable."""

        return AIAnalysisResponse(
            summary=(
                "AI-assisted explanation is currently unavailable. "
                "The displayed risk assessment is based on the "
                "deterministic analysis engine."
            ),
            confidence="unknown",
            findings=[
                evidence.explanation
                for evidence in request.evidence
            ],
            recommended_actions=request.recommended_actions,
            limitations=[
                "No AI provider was available for this analysis.",
                (
                    "The deterministic evidence should be reviewed "
                    "before taking action."
                ),
            ],
        )