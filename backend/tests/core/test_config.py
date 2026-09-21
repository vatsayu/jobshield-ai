import pytest
from pydantic import ValidationError

from backend.app.core.config import Settings


def test_default_ai_configuration() -> None:
    settings = Settings()

    assert settings.ai_enabled is False
    assert settings.ai_provider == "none"
    assert settings.ai_timeout_seconds == 20.0


def test_ai_provider_is_normalized() -> None:
    settings = Settings(ai_provider=" OPENAI ")

    assert settings.ai_provider == "openai"


def test_unsupported_ai_provider_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(ai_provider="unsupported-provider")


@pytest.mark.parametrize(
    "timeout",
    [0, -1, 121, 500],
)
def test_invalid_ai_timeout_is_rejected(timeout: float) -> None:
    with pytest.raises(ValidationError):
        Settings(ai_timeout_seconds=timeout)


def test_valid_ai_timeout_is_accepted() -> None:
    settings = Settings(ai_timeout_seconds=60)

    assert settings.ai_timeout_seconds == 60
