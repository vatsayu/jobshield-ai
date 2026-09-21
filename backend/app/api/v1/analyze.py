from fastapi import APIRouter, HTTPException, status

from backend.app.schemas.analysis import (
    AnalysisResponse,
    EmailAnalysisRequest,
    MessageAnalysisRequest,
    URLAnalysisRequest,
)
from backend.app.services.analysis_service import AnalysisService
from backend.app.services.url_analyzer import URLAnalyzer
from backend.app.services.url_normalizer import (
    URLNormalizationError,
)


router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"],
)


# Shared analyzer instance.
#
# Keeping this module-level object preserves compatibility with
# existing tests that patch:
#
# backend.app.api.v1.analyze.url_analyzer.analyze
#
# The same instance is injected into AnalysisService so that
# patched behavior is used by the API endpoint.
url_analyzer = URLAnalyzer()

analysis_service = AnalysisService(
    url_analyzer=url_analyzer,
)


@router.post(
    "/url",
    response_model=AnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def analyze_url(
    request: URLAnalysisRequest,
) -> AnalysisResponse:
    try:
        return analysis_service.analyze_url(request)

    except URLNormalizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


@router.post(
    "/message",
    response_model=AnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def analyze_message(
    request: MessageAnalysisRequest,
) -> AnalysisResponse:
    return analysis_service.analyze_message(request)


@router.post(
    "/email",
    response_model=AnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def analyze_email(
    request: EmailAnalysisRequest,
) -> AnalysisResponse:
    return analysis_service.analyze_email(request)