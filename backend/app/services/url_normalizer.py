from urllib.parse import SplitResult, urlsplit, urlunsplit


ALLOWED_SCHEMES = {"http", "https"}


class URLNormalizationError(ValueError):
    """Raised when a URL cannot be safely normalized."""


def normalize_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise URLNormalizationError("URL must be a non-empty string.")

    raw_url = url.strip()
    parsed = urlsplit(raw_url)

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname

    if scheme not in ALLOWED_SCHEMES:
        raise URLNormalizationError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not hostname:
        raise URLNormalizationError(
            "URL must contain a valid hostname."
        )

    normalized_hostname = hostname.rstrip(".").lower()

    try:
        port = parsed.port
    except ValueError as exc:
        raise URLNormalizationError(
            "URL contains an invalid port."
        ) from exc

    if port is None:
        normalized_netloc = normalized_hostname
    else:
        is_default_port = (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        )

        normalized_netloc = (
            normalized_hostname
            if is_default_port
            else f"{normalized_hostname}:{port}"
        )

    normalized = SplitResult(
        scheme=scheme,
        netloc=normalized_netloc,
        path=parsed.path or "/",
        query=parsed.query,
        fragment="",
    )

    return urlunsplit(normalized)