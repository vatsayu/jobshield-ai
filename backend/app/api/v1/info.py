from fastapi import APIRouter

from backend.app.core.config import get_settings
from backend.app.schemas.common import APIInfoResponse

router = APIRouter(tags=["System"])


@router.get("/info", response_model=APIInfoResponse)
def api_info() -> APIInfoResponse:
    settings = get_settings()

    return APIInfoResponse(
        name=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        description=(
            "AI-assisted security analysis platform for "
            "job postings and recruitment communications."
        ),
    )