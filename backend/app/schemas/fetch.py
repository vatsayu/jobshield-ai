from typing import Literal

from pydantic import BaseModel, Field


FetchStatus = Literal[
    "success",
    "failed",
    "blocked",
]


class URLFetchResult(BaseModel):
    requested_url: str
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    redirect_count: int = Field(default=0, ge=0)
    response_size_bytes: int = Field(default=0, ge=0)
    status: FetchStatus
    error: str | None = None