from fastapi import APIRouter, HTTPException, status

from backend.app.schemas.analysis import (
    AnalysisResponse,
    MessageAnalysisRequest,
    URLAnalysisRequest,
)
from backend.app.services.analysis_response_builder import (
    build_url_analysis_response,
)
from backend.app.services.message_analysis_response_builder import (
    build_message_analysis_response,
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

    return build_url_analysis_response(technical_signals)


@router.post(
    "/message",
    response_model=AnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def analyze_message(
    request: MessageAnalysisRequest,
) -> AnalysisResponse:
    return build_message_analysis_response(request.message)