from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.app.api.v1.router import api_router
from backend.app.core.config import get_settings
from backend.app.core.exceptions import JobShieldException

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description=(
        "AI-assisted recruitment fraud and job security analysis API."
    ),
)


@app.exception_handler(JobShieldException)
async def jobshield_exception_handler(
    request: Request,
    exc: JobShieldException,
) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={
            "error": exc.error_code,
            "message": exc.message,
        },
    )


app.include_router(api_router, prefix=settings.api_v1_prefix)