from uuid import uuid4

from fastapi import APIRouter, HTTPException, status

from backend.app.schemas.analysis import (
    AnalysisResponse,
    URLAnalysisRequest,
)
from backend.app.services.url_analyzer import URLAnalyzer
from backend.app.services.url_normalizer import URLNormalizationError


router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"],
)

url_analyzer = URLAnalyzer()


@router.post(
    "/url",
    response_model=AnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def analyze_url(request: URLAnalysisRequest) -> AnalysisResponse:
    try:
        technical_signals = url_analyzer.analyze(str(request.url))
    except URLNormalizationError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    return AnalysisResponse(
        analysis_id=str(uuid4()),
        analysis_type="url",
        status="completed",
        risk_category="unknown",
        risk_score=0,
        summary=(
            "URL was normalized and passed deterministic technical "
            "validation. Full security analysis is not implemented yet."
        ),
        evidence=[
            {
                "category": "url_validation",
                "signal": "normalized_url",
                "explanation": (
                    f"Normalized URL: {technical_signals.normalized_url}"
                ),
                "severity": "unknown",
            }
        ],
        recommended_actions=[
            "Do not share sensitive information until full analysis "
            "is complete."
        ],
    )