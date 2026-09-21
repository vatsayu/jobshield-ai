from abc import ABC, abstractmethod

from backend.app.schemas.ai.requests import AIAnalysisRequest
from backend.app.schemas.ai.responses import AIAnalysisResponse


class AIProviderError(Exception):
    """Raised when an AI provider cannot complete a request."""


class AIProvider(ABC):
    """Abstract interface for evidence-grounded AI providers."""

    @abstractmethod
    def analyze(
        self,
        request: AIAnalysisRequest,
    ) -> AIAnalysisResponse:
        """
        Analyze existing evidence and return a structured explanation.

        Implementations must not invent evidence or claim certainty
        beyond the supplied information.
        """
        raise NotImplementedError