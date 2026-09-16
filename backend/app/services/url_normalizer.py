from ipaddress import ip_address
from urllib.parse import SplitResult, urlsplit, urlunsplit


ALLOWED_SCHEMES = {"http", "https"}


class URLNormalizationError(ValueError):
    """Raised when a URL cannot be safely normalized."""


def _validate_hostname(hostname: str) -> str:
    normalized_hostname = hostname.rstrip(".").lower()

    if not normalized_hostname:
        raise URLNormalizationError(
            "URL must contain a valid hostname."
        )

    if any(character.isspace() for character in normalized_hostname):
        raise URLNormalizationError(
            "URL hostname must not contain whitespace."
        )

    return normalized_hostname


def _validate_ip_target(hostname: str) -> None:
    try:
        address = ip_address(hostname)
    except ValueError:
        return

    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise URLNormalizationError(
            "Private, local, reserved, or otherwise unsafe IP targets "
            "are not allowed."
        )


def normalize_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise URLNormalizationError(
            "URL must be a non-empty string."
        )

    raw_url = url.strip()
    parsed = urlsplit(raw_url)

    scheme = parsed.scheme.lower()

    if scheme not in ALLOWED_SCHEMES:
        raise URLNormalizationError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if parsed.username is not None or parsed.password is not None:
        raise URLNormalizationError(
            "URLs containing embedded credentials are not allowed."
        )

    hostname = parsed.hostname

    if not hostname:
        raise URLNormalizationError(
            "URL must contain a valid hostname."
        )

    normalized_hostname = _validate_hostname(hostname)
    _validate_ip_target(normalized_hostname)

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