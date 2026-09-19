from __future__ import annotations

from backend.app.schemas.risk import (
    RiskAssessment,
    RiskContribution,
)
from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.url_signal_detector import (
    detect_url_structural_signals,
)


SUSPICIOUS_HOSTNAME_KEYWORDS = {
    "verify",
    "secure-login",
    "account-confirm",
    "urgent",
    "claim-prize",
    "free-money",
    "job-offer",
    "hr-verify",
}

SUSPICIOUS_URL_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "payment",
    "fee",
    "registration-fee",
    "processing-fee",
    "crypto",
    "wallet",
    "password",
}


def _category_for_score(score: int) -> str:
    if score >= 70:
        return "critical"

    if score >= 40:
        return "high"

    if score >= 20:
        return "medium"

    return "low"


def evaluate_url_risk(
    signals: URLTechnicalSignals,
) -> RiskAssessment:
    contributions: list[RiskContribution] = []
    score = 0

    if not signals.has_https:
        contributions.append(
            RiskContribution(
                signal="missing_https",
                points=15,
                explanation=(
                    "The URL uses HTTP instead of HTTPS. "
                    "Transport encryption could not be verified."
                ),
            )
        )
        score += 15

    if signals.port is not None:
        contributions.append(
            RiskContribution(
                signal="non_standard_port",
                points=10,
                explanation=(
                    f"The URL uses non-default port "
                    f"{signals.port}."
                ),
            )
        )
        score += 10

    if signals.redirect_count >= 3:
        contributions.append(
            RiskContribution(
                signal="multiple_redirects",
                points=10,
                explanation=(
                    "The URL required three or more validated "
                    "redirects before reaching its final location."
                ),
            )
        )
        score += 10

    elif signals.redirect_count > 0:
        contributions.append(
            RiskContribution(
                signal="redirect",
                points=5,
                explanation=(
                    "The URL required one or more redirects."
                ),
            )
        )
        score += 5

    hostname_lower = signals.hostname.lower()
    normalized_url_lower = signals.normalized_url.lower()

    matched_hostname_keywords = [
        keyword
        for keyword in SUSPICIOUS_HOSTNAME_KEYWORDS
        if keyword in hostname_lower
    ]

    if matched_hostname_keywords:
        contributions.append(
            RiskContribution(
                signal="suspicious_hostname_keyword",
                points=15,
                explanation=(
                    "The hostname contains potentially suspicious "
                    "keyword(s): "
                    + ", ".join(matched_hostname_keywords)
                    + "."
                ),
            )
        )
        score += 15

    matched_url_keywords = [
        keyword
        for keyword in SUSPICIOUS_URL_KEYWORDS
        if keyword in normalized_url_lower
    ]

    if matched_url_keywords:
        contributions.append(
            RiskContribution(
                signal="suspicious_url_keyword",
                points=10,
                explanation=(
                    "The URL contains potentially sensitive or "
                    "suspicious keyword(s): "
                    + ", ".join(matched_url_keywords)
                    + "."
                ),
            )
        )
        score += 10

    structural_signals = detect_url_structural_signals(signals)

    if "ip_address_hostname" in structural_signals:
        contributions.append(
            RiskContribution(
                signal="ip_address_hostname",
                points=15,
                explanation=(
                    "The URL uses a literal IP address instead "
                    "of a conventional domain name."
                ),
            )
        )
        score += 15

    if "excessive_subdomains" in structural_signals:
        contributions.append(
            RiskContribution(
                signal="excessive_subdomains",
                points=5,
                explanation=(
                    "The hostname contains an unusually large "
                    "number of nested subdomains."
                ),
            )
        )
        score += 5

    if "long_url" in structural_signals:
        contributions.append(
            RiskContribution(
                signal="long_url",
                points=5,
                explanation=(
                    "The URL is unusually long and may contain "
                    "complex or obfuscated path/query data."
                ),
            )
        )
        score += 5

    if "suspicious_tld" in structural_signals:
        contributions.append(
            RiskContribution(
                signal="suspicious_tld",
                points=5,
                explanation=(
                    "The domain uses a top-level domain that "
                    "warrants additional verification. This alone "
                    "does not establish malicious activity."
                ),
            )
        )
        score += 5

    if "suspicious_encoding" in structural_signals:
        contributions.append(
            RiskContribution(
                signal="suspicious_encoding",
                points=5,
                explanation=(
                    "The URL contains percent-encoded or obfuscated "
                    "characters that make the destination harder to inspect. "
                    "This is a heuristic indicator and does not alone establish "
                    "malicious activity."
                ),
            )
        )
        score += 5
    if "userinfo_in_url" in structural_signals:
        contributions.append(
            RiskContribution(
                signal="userinfo_in_url",
                points=10,
                explanation=(
                    "The URL contains embedded user information before "
                    "the hostname, which can make the destination harder "
                    "to interpret. This is a heuristic indicator and does "
                    "not alone establish malicious activity."
                ),
            )
        )
        score += 10

    if signals.status_code is not None:
        if 400 <= signals.status_code <= 499:
            contributions.append(
                RiskContribution(
                    signal="client_error_response",
                    points=10,
                    explanation=(
                        f"The server returned HTTP status "
                        f"{signals.status_code}."
                    ),
                )
            )
            score += 10

        elif 500 <= signals.status_code <= 599:
            contributions.append(
                RiskContribution(
                    signal="server_error_response",
                    points=15,
                    explanation=(
                        f"The server returned HTTP status "
                        f"{signals.status_code}."
                    ),
                )
            )
            score += 15

    score = min(score, 100)

    if signals.fetch_status == "failed":
        return RiskAssessment(
            risk_category="unknown",
            risk_score=0,
            confidence="low",
            contributions=[],
            rationale=(
                "The URL could not be safely fetched. "
                "There is insufficient evidence to calculate "
                "a meaningful risk score."
            ),
        )

    category = _category_for_score(score)

    if score == 0:
        confidence = "medium"
        rationale = (
            "No significant deterministic technical risk signals "
            "were identified. This does not prove legitimacy."
        )
    elif score < 40:
        confidence = "medium"
        rationale = (
            "A small number of technical risk indicators were "
            "identified. Further verification is recommended."
        )
    else:
        confidence = "high"
        rationale = (
            "Multiple deterministic technical risk indicators "
            "were identified. Additional verification is strongly "
            "recommended before sharing sensitive information."
        )

    return RiskAssessment(
        risk_category=category,
        risk_score=score,
        confidence=confidence,
        contributions=contributions,
        rationale=rationale,
    )