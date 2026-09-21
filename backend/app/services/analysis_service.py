from __future__ import annotations

from backend.app.schemas.analysis import (
    AnalysisResponse,
    EmailAnalysisRequest,
    MessageAnalysisRequest,
    URLAnalysisRequest,
)
from backend.app.services.analysis_response_builder import (
    build_url_analysis_response,
)
from backend.app.services.email_analysis_response_builder import (
    build_email_analysis_response,
)
from backend.app.services.message_analysis_response_builder import (
    build_message_analysis_response,
)
from backend.app.services.url_analyzer import URLAnalyzer


class AnalysisService:
    """Unified entry point for supported analysis workflows."""

    def __init__(
        self,
        url_analyzer: URLAnalyzer | None = None,
    ) -> None:
        self.url_analyzer = url_analyzer or URLAnalyzer()

    def analyze_url(
        self,
        request: URLAnalysisRequest,
    ) -> AnalysisResponse:
        """Run URL analysis through the existing URL pipeline."""

        technical_signals = self.url_analyzer.analyze(
            str(request.url)
        )

        return build_url_analysis_response(
            technical_signals
        )

    def analyze_message(
        self,
        request: MessageAnalysisRequest,
    ) -> AnalysisResponse:
        """Run message analysis through the existing pipeline."""

        return build_message_analysis_response(
            request.message
        )

    def analyze_email(
        self,
        request: EmailAnalysisRequest,
    ) -> AnalysisResponse:
        """Run email analysis through the existing pipeline."""

        return build_email_analysis_response(
            subject=request.subject,
            sender=request.sender,
            reply_to=request.reply_to,
            body=request.body,
        )