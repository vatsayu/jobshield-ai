from urllib.parse import urlparse

from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.url_normalizer import normalize_url


class URLAnalyzer:
    """Performs safe, deterministic URL-level analysis."""

    def analyze(self, url: str) -> URLTechnicalSignals:
        normalized_url = normalize_url(url)
        parsed = urlparse(normalized_url)

        return URLTechnicalSignals(
            normalized_url=normalized_url,
            hostname=parsed.hostname or "",
            scheme=parsed.scheme,
            port=parsed.port,
            has_https=parsed.scheme.lower() == "https",
            redirect_count=0,
            final_url=normalized_url,
            domain_age_days=None,
            suspicious_keywords=[],
        )