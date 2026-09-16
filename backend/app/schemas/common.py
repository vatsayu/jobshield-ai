from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str


class APIInfoResponse(BaseModel):
    name: str
    version: str
    environment: str
    description: str