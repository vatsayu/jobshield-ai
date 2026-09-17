from unittest.mock import patch

import httpx
import pytest

from backend.app.services.url_fetcher import (
    URLFetchError,
    URLFetcher,
)


def build_response(
    *,
    status_code: int = 200,
    url: str = "https://example.com/jobs",
    headers: dict[str, str] | None = None,
    content: bytes = b"<html>job posting</html>",
) -> httpx.Response:
    request = httpx.Request("GET", url)

    return httpx.Response(
        status_code=status_code,
        headers=headers or {
            "content-type": "text/html",
            "content-length": str(len(content)),
        },
        content=content,
        request=request,
    )


def test_fetcher_returns_success_metadata() -> None:
    fetcher = URLFetcher()

    response = build_response()

    with patch(
        "backend.app.services.url_fetcher.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 0),
            )
        ],
    ), patch.object(
        httpx.Client,
        "get",
        return_value=response,
    ):
        result = fetcher.fetch(
            "https://example.com/jobs"
        )

    assert result["status"] == "success"
    assert result["status_code"] == 200
    assert result["final_url"] == "https://example.com/jobs"
    assert result["redirect_count"] == 0
    assert result["response_size_bytes"] > 0
    assert result["content_type"] == "text/html"


def test_fetcher_rejects_private_resolved_ip() -> None:
    fetcher = URLFetcher()

    with patch(
        "backend.app.services.url_fetcher.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("192.168.1.10", 0),
            )
        ],
    ):
        with pytest.raises(URLFetchError, match="unsafe IP"):
            fetcher.fetch(
                "https://example.com/jobs"
            )


def test_fetcher_rejects_loopback_resolved_ip() -> None:
    fetcher = URLFetcher()

    with patch(
        "backend.app.services.url_fetcher.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("127.0.0.1", 0),
            )
        ],
    ):
        with pytest.raises(URLFetchError, match="unsafe IP"):
            fetcher.fetch(
                "https://example.com/jobs"
            )


def test_fetcher_rejects_cloud_metadata_resolved_ip() -> None:
    fetcher = URLFetcher()

    with patch(
        "backend.app.services.url_fetcher.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("169.254.169.254", 0),
            )
        ],
    ):
        with pytest.raises(URLFetchError, match="unsafe IP"):
            fetcher.fetch(
                "https://example.com/jobs"
            )


def test_fetcher_rejects_unsupported_scheme() -> None:
    fetcher = URLFetcher()

    with pytest.raises(URLFetchError, match="HTTP and HTTPS"):
        fetcher.fetch(
            "ftp://example.com/file"
        )


def test_fetcher_rejects_embedded_credentials() -> None:
    fetcher = URLFetcher()

    with pytest.raises(URLFetchError, match="embedded credentials"):
        fetcher.fetch(
            "https://user:password@example.com/jobs"
        )


def test_fetcher_rejects_oversized_content_length() -> None:
    fetcher = URLFetcher()

    oversized_response = build_response(
        headers={
            "content-type": "text/html",
            "content-length": str(
                URLFetcher.MAX_RESPONSE_BYTES + 1
            ),
        }
    )

    with patch(
        "backend.app.services.url_fetcher.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 0),
            )
        ],
    ), patch.object(
        httpx.Client,
        "get",
        return_value=oversized_response,
    ):
        with pytest.raises(
            URLFetchError,
            match="maximum allowed size",
        ):
            fetcher.fetch(
                "https://example.com/jobs"
            )


def test_fetcher_rejects_oversized_body() -> None:
    fetcher = URLFetcher()

    oversized_body = b"x" * (
        URLFetcher.MAX_RESPONSE_BYTES + 1
    )

    oversized_response = build_response(
        headers={
            "content-type": "text/html",
        },
        content=oversized_body,
    )

    with patch(
        "backend.app.services.url_fetcher.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 0),
            )
        ],
    ), patch.object(
        httpx.Client,
        "get",
        return_value=oversized_response,
    ):
        with pytest.raises(
            URLFetchError,
            match="maximum allowed size",
        ):
            fetcher.fetch(
                "https://example.com/jobs"
            )


def test_fetcher_rejects_redirect_to_private_ip() -> None:
    fetcher = URLFetcher()

    redirect_response = build_response(
        status_code=302,
        url="https://example.com/start",
        headers={
            "location": "http://127.0.0.1:8000/admin",
        },
        content=b"",
    )

    with patch(
        "backend.app.services.url_fetcher.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 0),
            )
        ],
    ), patch.object(
        httpx.Client,
        "get",
        return_value=redirect_response,
    ):
        with pytest.raises(URLFetchError, match="unsafe IP"):
            fetcher.fetch(
                "https://example.com/start"
            )


def test_fetcher_rejects_redirect_loop() -> None:
    fetcher = URLFetcher()

    redirect_response = build_response(
        status_code=302,
        url="https://example.com/start",
        headers={
            "location": "https://example.com/next",
        },
        content=b"",
    )

    with patch(
        "backend.app.services.url_fetcher.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 0),
            )
        ],
    ), patch.object(
        httpx.Client,
        "get",
        return_value=redirect_response,
    ):
        with pytest.raises(
            URLFetchError,
            match="Maximum redirect limit",
        ):
            fetcher.fetch(
                "https://example.com/start"
            )


def test_fetcher_handles_timeout() -> None:
    fetcher = URLFetcher()

    with patch(
        "backend.app.services.url_fetcher.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 0),
            )
        ],
    ), patch.object(
        httpx.Client,
        "get",
        side_effect=httpx.ReadTimeout(
            "request timed out"
        ),
    ):
        with pytest.raises(
            URLFetchError,
            match="timed out",
        ):
            fetcher.fetch(
                "https://example.com/jobs"
            )