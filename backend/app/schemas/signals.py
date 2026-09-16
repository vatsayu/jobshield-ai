from pydantic import BaseModel, Field


class URLTechnicalSignals(BaseModel):
    normalized_url: str
    hostname: str
    scheme: str
    port: int | None = None
    has_https: bool
    redirect_count: int = Field(ge=0)
    final_url: str | None = None
    domain_age_days: int | None = None
    suspicious_keywords: list[str] = Field(default_factory=list)