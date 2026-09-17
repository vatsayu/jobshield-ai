from __future__ import annotations

from ipaddress import ip_address
from socket import getaddrinfo
from urllib.parse import urlsplit

import httpx

from backend.app.services.url_normalizer import (
    URLNormalizationError,
    normalize_url,
)


class URLFetchError(RuntimeError):
    """Raised when a URL cannot be safely fetched."""


class URLFetcher:
    """Safely fetches public HTTP/HTTPS URLs."""

    MAX_REDIRECTS = 3
    MAX_RESPONSE_BYTES = 1_000_000

    CONNECT_TIMEOUT_SECONDS = 5.0
    READ_TIMEOUT_SECONDS = 10.0
    WRITE_TIMEOUT_SECONDS = 5.0
    POOL_TIMEOUT_SECONDS = 5.0

    def _validate_resolved_ip(self, hostname: str) -> None:
        try:
            addresses = getaddrinfo(
                hostname,
                None,
                type=0,
            )
        except OSError as exc:
            raise URLFetchError(
                "Unable to resolve the URL hostname."
            ) from exc

        checked_ips: set[str] = set()

        for address_info in addresses:
            resolved_ip = address_info[4][0]

            if resolved_ip in checked_ips:
                continue

            checked_ips.add(resolved_ip)

            try:
                address = ip_address(resolved_ip)
            except ValueError as exc:
                raise URLFetchError(
                    "Hostname resolved to an invalid IP address."
                ) from exc

            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or address.is_reserved
            ):
                raise URLFetchError(
                    "URL resolves to a private, local, reserved, "
                    "or otherwise unsafe IP address."
                )

    def _validate_target(self, url: str) -> str:
        try:
            normalized_url = normalize_url(url)
        except URLNormalizationError as exc:
            raise URLFetchError(str(exc)) from exc

        parsed = urlsplit(normalized_url)
        hostname = parsed.hostname

        if not hostname:
            raise URLFetchError(
                "URL must contain a valid hostname."
            )

        self._validate_resolved_ip(hostname)

        return normalized_url

    def fetch(self, url: str) -> dict:
        current_url = self._validate_target(url)
        redirect_count = 0

        timeout = httpx.Timeout(
            connect=self.CONNECT_TIMEOUT_SECONDS,
            read=self.READ_TIMEOUT_SECONDS,
            write=self.WRITE_TIMEOUT_SECONDS,
            pool=self.POOL_TIMEOUT_SECONDS,
        )

        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": "JobShieldAI-SecurityScanner/0.1",
                "Accept": "text/html,application/xhtml+xml",
            },
        ) as client:
            while True:
                current_url = self._validate_target(current_url)

                try:
                    response = client.get(
                        current_url,
                        follow_redirects=False,
                    )
                except httpx.TimeoutException as exc:
                    raise URLFetchError(
                        "URL request timed out."
                    ) from exc
                except httpx.RequestError as exc:
                    raise URLFetchError(
                        "Unable to fetch the URL."
                    ) from exc

                if response.is_redirect:
                    if redirect_count >= self.MAX_REDIRECTS:
                        raise URLFetchError(
                            "Maximum redirect limit exceeded."
                        )

                    location = response.headers.get("location")

                    if not location:
                        raise URLFetchError(
                            "Redirect response did not include a target."
                        )

                    next_url = str(
                        response.url.join(location)
                    )

                    current_url = self._validate_target(next_url)
                    redirect_count += 1
                    continue

                content_length_header = response.headers.get(
                    "content-length"
                )

                content_length: int | None = None

                if content_length_header:
                    try:
                        content_length = int(
                            content_length_header
                        )
                    except ValueError:
                        content_length = None

                    if (
                        content_length is not None
                        and content_length > self.MAX_RESPONSE_BYTES
                    ):
                        raise URLFetchError(
                            "Response exceeds the maximum allowed size."
                        )

                response_bytes = response.content

                if len(response_bytes) > self.MAX_RESPONSE_BYTES:
                    raise URLFetchError(
                        "Response exceeds the maximum allowed size."
                    )

                return {
                    "requested_url": url,
                    "final_url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": response.headers.get(
                        "content-type"
                    ),
                    "content_length": content_length,
                    "redirect_count": redirect_count,
                    "response_size_bytes": len(response_bytes),
                    "status": "success",
                    "error": None,
                }