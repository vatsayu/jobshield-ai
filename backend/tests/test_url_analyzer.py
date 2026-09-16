from backend.app.services.url_analyzer import URLAnalyzer


def test_url_analyzer_extracts_basic_url_signals() -> None:
    analyzer = URLAnalyzer()

    result = analyzer.analyze(
        "https://example.com/jobs/security-analyst"
    )

    assert result.hostname == "example.com"
    assert result.scheme == "https"
    assert result.has_https is True
    assert result.redirect_count == 0
    assert result.final_url == "https://example.com/jobs/security-analyst"


def test_url_analyzer_detects_http() -> None:
    analyzer = URLAnalyzer()

    result = analyzer.analyze("http://example.com/job")

    assert result.scheme == "http"
    assert result.has_https is False