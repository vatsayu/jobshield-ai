import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError


from backend.app.api.v1.analyze import router as analyze_router
from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.info import router as info_router
from backend.app.core.config import get_settings
from backend.app.core.exceptions import JobShieldException
from backend.app.core.logging import configure_logging
from backend.app.core.middleware import RequestIDMiddleware

configure_logging()

logger = logging.getLogger(__name__)
settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "AI-assisted security analysis platform for "
        "job postings and recruitment communications."
    ),
)

app.add_middleware(RequestIDMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)

    logger.warning(
        "Request validation error | request_id=%s | errors=%s",
        request_id,
        exc.errors(),
    )

    return JSONResponse(
        status_code=422,
        content={
            "error": "VALIDATION_ERROR",
            "message": "Request data failed validation.",
            "request_id": request_id,
        },
    )


@app.exception_handler(JobShieldException)
async def jobshield_exception_handler(
    request: Request,
    exc: JobShieldException,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)

    logger.warning(
        "Handled application error | error_code=%s | request_id=%s",
        exc.error_code,
        request_id,
    )

    return JSONResponse(
        status_code=400,
        content={
            "error": exc.error_code,
            "message": exc.message,
            "request_id": request_id,
        },
    )


@app.get("/", tags=["System"])
def root() -> dict[str, str]:
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "ok",
    }


app.include_router(
    health_router,
    prefix=settings.api_v1_prefix,
)

app.include_router(
    info_router,
    prefix=settings.api_v1_prefix,
)

app.include_router(
    analyze_router,
    prefix=settings.api_v1_prefix,
)