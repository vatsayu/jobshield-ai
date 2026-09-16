from uuid import uuid4

from fastapi import APIRouter, status

from backend.app.schemas.analysis import (
    AnalysisResponse,
    URLAnalysisRequest,
)

router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"],
)


@router.post(
    "/url",
    response_model=AnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def analyze_url(request: URLAnalysisRequest) -> AnalysisResponse:
    return AnalysisResponse(
        analysis_id=str(uuid4()),
        analysis_type="url",
        status="queued",
        risk_category="unknown",
        risk_score=0,
        summary=(
            "URL received successfully. Detailed security analysis "
            "has not been implemented yet."
        ),
        evidence=[],
        recommended_actions=[
            "Do not share sensitive information until analysis is complete."
        ],
    )