from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.risk_engine import evaluate_url_risk


def build_signals(
    *,
    normalized_url: str = "https://example.com/jobs",
    hostname: str = "example.com",
    scheme: str = "https",
    port: int | None = None,
    has_https: bool = True,
    redirect_count: int = 0,
    status_code: int | None = 200,
    fetch_status: str = "success",
) -> URLTechnicalSignals:
    return URLTechnicalSignals(
        normalized_url=normalized_url,
        hostname=hostname,
        scheme=scheme,
        port=port,
        has_https=has_https,
        redirect_count=redirect_count,
        final_url=normalized_url,
        status_code=status_code,
        content_type="text/html",
        content_length=128,
        response_size_bytes=128,
        fetch_status=fetch_status,
        fetch_error=None,
        domain_age_days=None,
        suspicious_keywords=[],
    )


def test_clean_https_url_has_low_risk() -> None:
    result = evaluate_url_risk(build_signals())

    assert result.risk_score == 0
    assert result.risk_category == "low"
    assert result.confidence == "medium"
    assert result.contributions == []


def test_http_url_adds_missing_https_points() -> None:
    result = evaluate_url_risk(
        build_signals(
            normalized_url="http://example.com/jobs",
            scheme="http",
            has_https=False,
        )
    )

    assert result.risk_score == 15
    assert result.risk_category == "low"

    signals = [
        item.signal for item in result.contributions
    ]

    assert "missing_https" in signals


def test_non_standard_port_adds_points() -> None:
    result = evaluate_url_risk(
        build_signals(port=8080)
    )

    assert result.risk_score == 10

    signals = [
        item.signal for item in result.contributions
    ]

    assert "non_standard_port" in signals


def test_single_redirect_adds_five_points() -> None:
    result = evaluate_url_risk(
        build_signals(redirect_count=1)
    )

    assert result.risk_score == 5

    signals = [
        item.signal for item in result.contributions
    ]

    assert "redirect" in signals


def test_multiple_redirects_add_ten_points() -> None:
    result = evaluate_url_risk(
        build_signals(redirect_count=3)
    )

    assert result.risk_score == 10

    signals = [
        item.signal for item in result.contributions
    ]

    assert "multiple_redirects" in signals


def test_suspicious_hostname_keyword_adds_points() -> None:
    result = evaluate_url_risk(
        build_signals(
            hostname="secure-login.example.com",
            normalized_url=(
                "https://secure-login.example.com/jobs"
            ),
        )
    )

    assert result.risk_score == 25
    assert result.risk_category == "medium"

    signals = [
        item.signal for item in result.contributions
    ]

    assert "suspicious_hostname_keyword" in signals
    assert "suspicious_url_keyword" in signals

def test_suspicious_url_keyword_adds_points() -> None:
    result = evaluate_url_risk(
        build_signals(
            normalized_url=(
                "https://example.com/payment-verification"
            ),
        )
    )

    assert result.risk_score == 10

    signals = [
        item.signal for item in result.contributions
    ]

    assert "suspicious_url_keyword" in signals


def test_client_error_adds_points() -> None:
    result = evaluate_url_risk(
        build_signals(status_code=404)
    )

    assert result.risk_score == 10

    signals = [
        item.signal for item in result.contributions
    ]

    assert "client_error_response" in signals


def test_server_error_adds_points() -> None:
    result = evaluate_url_risk(
        build_signals(status_code=503)
    )

    assert result.risk_score == 15

    signals = [
        item.signal for item in result.contributions
    ]

    assert "server_error_response" in signals


def test_failed_fetch_returns_unknown_without_score() -> None:
    result = evaluate_url_risk(
        build_signals(
            fetch_status="failed",
            status_code=None,
        )
    )

    assert result.risk_score == 0
    assert result.risk_category == "unknown"
    assert result.confidence == "low"
    assert result.contributions == []


def test_score_combines_multiple_signals() -> None:
    result = evaluate_url_risk(
        build_signals(
            normalized_url=(
                "http://secure-login.example.com:8080/payment"
            ),
            hostname="secure-login.example.com",
            scheme="http",
            port=8080,
            has_https=False,
            redirect_count=3,
            status_code=503,
        )
    )

    assert result.risk_score == 75
    assert result.risk_category == "critical"
    assert len(result.contributions) >= 5


def test_score_is_capped_at_one_hundred() -> None:
    result = evaluate_url_risk(
        build_signals(
            normalized_url=(
                "http://secure-login.example.com:8080/"
                "payment-verification"
            ),
            hostname="secure-login.example.com",
            scheme="http",
            port=8080,
            has_https=False,
            redirect_count=3,
            status_code=503,
        )
    )

    assert 0 <= result.risk_score <= 100

def test_suspicious_tld_adds_risk_points() -> None:
    signals = build_signals(
        hostname="jobs.example.xyz",
        normalized_url="https://jobs.example.xyz/jobs",
    )

    assessment = evaluate_url_risk(signals)

    assert assessment.risk_score == 5
    assert assessment.risk_category == "low"

    matching = [
        contribution
        for contribution in assessment.contributions
        if contribution.signal == "suspicious_tld"
    ]

    assert len(matching) == 1
    assert matching[0].points == 5

def test_suspicious_encoding_adds_risk_points() -> None:
    signals = build_signals(
        hostname="example.com",
        normalized_url="https://example.com/%41%42%43%44",
    )

    assessment = evaluate_url_risk(signals)

    assert assessment.risk_score == 5
    assert assessment.risk_category == "low"

    matching = [
        contribution
        for contribution in assessment.contributions
        if contribution.signal == "suspicious_encoding"
    ]

    assert len(matching) == 1
    assert matching[0].points == 5