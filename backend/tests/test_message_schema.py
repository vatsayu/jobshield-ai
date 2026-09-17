import pytest
from pydantic import ValidationError

from backend.app.schemas.analysis import MessageAnalysisRequest


def test_valid_message_is_accepted() -> None:
    request = MessageAnalysisRequest(
        message="Please attend the interview tomorrow at 10 AM."
    )

    assert request.message.startswith("Please attend")


def test_message_must_not_be_empty() -> None:
    with pytest.raises(ValidationError):
        MessageAnalysisRequest(message="")


def test_message_minimum_length_is_enforced() -> None:
    with pytest.raises(ValidationError):
        MessageAnalysisRequest(message="short")


def test_message_maximum_length_is_enforced() -> None:
    with pytest.raises(ValidationError):
        MessageAnalysisRequest(message="A" * 20_001)


def test_message_whitespace_is_not_automatically_removed() -> None:
    request = MessageAnalysisRequest(
        message="  Please attend the interview tomorrow.  "
    )

    assert request.message.startswith("  ")