from urllib.parse import urlparse

from backend.app.schemas.signals import URLTechnicalSignals


class URLAnalyzer:
    """Performs safe, deterministic URL-level analysis."""

    def analyze(self, url: str) -> URLTechnicalSignals:
        parsed = urlparse(url)

        return URLTechnicalSignals(
            normalized_url=url,
            hostname=parsed.hostname or "",
            scheme=parsed.scheme,
            port=parsed.port,
            has_https=parsed.scheme.lower() == "https",
            redirect_count=0,
            final_url=url,
            suspicious_keywords=[],
        )