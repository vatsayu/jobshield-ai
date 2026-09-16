from fastapi import APIRouter

from backend.app.core.config import get_settings
from backend.app.schemas.common import HealthResponse

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    settings = get_settings()

    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version="0.1.0",
    )
