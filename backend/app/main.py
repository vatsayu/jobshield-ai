from fastapi import FastAPI

from backend.app.api.v1.router import api_router
from backend.app.core.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description=(
        "AI-assisted recruitment fraud and job security analysis API."
    ),
)

app.include_router(api_router, prefix=settings.api_v1_prefix)
