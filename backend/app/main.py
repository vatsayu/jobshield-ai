from fastapi import FastAPI

app = FastAPI(
    title="JobShield AI API",
    version="0.1.0",
    description="AI-assisted recruitment fraud and job security analysis API.",
)


@app.get("/api/v1/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "jobshield-api",
        "version": "0.1.0",
    }
