from fastapi import APIRouter

from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.info import router as info_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(info_router)