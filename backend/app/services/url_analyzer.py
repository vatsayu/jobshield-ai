from __future__ import annotations

from urllib.parse import urlparse

from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.url_fetcher import (
    URLFetchError,
    URLFetcher,
)
from backend.app.services.url_normalizer import normalize_url


class URLAnalyzer:
    """Performs deterministic URL normalization and safe fetching."""

    def __init__(
        self,
        fetcher: URLFetcher | None = None,
    ) -> None:
        self.fetcher = fetcher or URLFetcher()

    def analyze(self, url: str) -> URLTechnicalSignals:
        normalized_url = normalize_url(url)
        parsed = urlparse(normalized_url)

        try:
            fetch_result = self.fetcher.fetch(normalized_url)
        except URLFetchError as exc:
            return URLTechnicalSignals(
                normalized_url=normalized_url,
                hostname=parsed.hostname or "",
                scheme=parsed.scheme,
                port=parsed.port,
                has_https=parsed.scheme.lower() == "https",
                redirect_count=0,
                final_url=None,
                status_code=None,
                content_type=None,
                content_length=None,
                response_size_bytes=0,
                fetch_status="failed",
                fetch_error=str(exc),
                domain_age_days=None,
                suspicious_keywords=[],
            )

        return URLTechnicalSignals(
            normalized_url=normalized_url,
            hostname=parsed.hostname or "",
            scheme=parsed.scheme,
            port=parsed.port,
            has_https=parsed.scheme.lower() == "https",
            redirect_count=fetch_result["redirect_count"],
            final_url=fetch_result["final_url"],
            status_code=fetch_result["status_code"],
            content_type=fetch_result["content_type"],
            content_length=fetch_result["content_length"],
            response_size_bytes=fetch_result["response_size_bytes"],
            fetch_status=fetch_result["status"],
            fetch_error=fetch_result["error"],
            domain_age_days=None,
            suspicious_keywords=[],
        )