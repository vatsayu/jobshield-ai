from __future__ import annotations

from uuid import uuid4

from backend.app.schemas.analysis import (
    AnalysisResponse,
    EvidenceItem,
)
from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.risk_engine import evaluate_url_risk


def _build_technical_evidence(
    signals: URLTechnicalSignals,
) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []

    # Transport security evidence
    if signals.has_https:
        evidence.append(
            EvidenceItem(
                category="transport_security",
                signal="https_enabled",
                explanation=(
                    "The URL uses HTTPS for transport encryption."
                ),
                severity="unknown",
            )
        )
    else:
        evidence.append(
            EvidenceItem(
                category="transport_security",
                signal="https_missing",
                explanation=(
                    "The URL uses HTTP rather than HTTPS. "
                    "Transport encryption is not verified."
                ),
                severity="medium",
            )
        )

    # Non-standard port evidence
    if signals.port is not None:
        evidence.append(
            EvidenceItem(
                category="network",
                signal="port_non_standard",
                explanation=(
                    f"The URL uses non-default port "
                    f"{signals.port}."
                ),
                severity="medium",
            )
        )

    # HTTP response evidence
    if signals.status_code is not None:
        if 200 <= signals.status_code <= 299:
            evidence.append(
                EvidenceItem(
                    category="http_response",
                    signal="successful_http_response",
                    explanation=(
                        f"The server returned HTTP status "
                        f"{signals.status_code}."
                    ),
                    severity="unknown",
                )
            )

        elif 400 <= signals.status_code <= 499:
            evidence.append(
                EvidenceItem(
                    category="http_response",
                    signal="http_status_4xx",
                    explanation=(
                        f"The server returned client-error "
                        f"HTTP status {signals.status_code}."
                    ),
                    severity="medium",
                )
            )

        elif 500 <= signals.status_code <= 599:
            evidence.append(
                EvidenceItem(
                    category="http_response",
                    signal="http_status_5xx",
                    explanation=(
                        f"The server returned server-error "
                        f"HTTP status {signals.status_code}."
                    ),
                    severity="high",
                )
            )

    return evidence


def build_url_analysis_response(
    signals: URLTechnicalSignals,
) -> AnalysisResponse:
    risk_assessment = evaluate_url_risk(signals)

    evidence: list[EvidenceItem] = [
        EvidenceItem(
            category="url_validation",
            signal="normalized_url",
            explanation=(
                f"Normalized URL: {signals.normalized_url}"
            ),
            severity="unknown",
        )
    ]

    # Add technical evidence
    evidence.extend(
        _build_technical_evidence(signals)
    )

    recommended_actions: list[str] = [
        "Do not share sensitive information until the "
        "recruitment source is verified."
    ]

    if signals.fetch_status == "success":
        evidence.append(
            EvidenceItem(
                category="http_fetch",
                signal="response_received",
                explanation=(
                    f"Server returned HTTP status "
                    f"{signals.status_code} from "
                    f"{signals.final_url}."
                ),
                severity="unknown",
            )
        )

        if signals.content_type:
            evidence.append(
                EvidenceItem(
                    category="http_fetch",
                    signal="content_type",
                    explanation=(
                        f"Response content type: "
                        f"{signals.content_type}."
                    ),
                    severity="unknown",
                )
            )

        if signals.redirect_count > 0:
            evidence.append(
                EvidenceItem(
                    category="http_fetch",
                    signal="redirects",
                    explanation=(
                        f"URL followed "
                        f"{signals.redirect_count} "
                        "validated redirect(s)."
                    ),
                    severity="unknown",
                )
            )

        summary = (
            "The URL was technically reachable and "
            "deterministic risk indicators were evaluated. "
            "This is not proof that the job posting or recruiter "
            "is legitimate."
        )

        if risk_assessment.risk_score > 0:
            recommended_actions.extend(
                [
                    "Review each listed technical risk indicator "
                    "before proceeding.",
                    "Verify the employer and recruiter through "
                    "independent trusted sources.",
                ]
            )

    elif signals.fetch_status == "failed":
        evidence.append(
            EvidenceItem(
                category="http_fetch",
                signal="fetch_failed",
                explanation=(
                    "The URL passed normalization, but the "
                    "server could not be safely fetched."
                ),
                severity="unknown",
            )
        )

        summary = (
            "The URL passed basic validation, but its content "
            "could not be safely retrieved. There is insufficient "
            "evidence to assess legitimacy."
        )

        recommended_actions.extend(
            [
                "Verify the domain through an independent "
                "trusted source.",
                "Do not download files or submit personal "
                "documents from this URL yet.",
            ]
        )

    else:
        summary = (
            "The URL produced an unexpected fetch state. "
            "There is insufficient evidence for a security "
            "assessment."
        )

    # Add deterministic risk contributions as user-visible evidence.
    for contribution in risk_assessment.contributions:
        evidence.append(
            EvidenceItem(
                category="deterministic_risk",
                signal=contribution.signal,
                explanation=contribution.explanation,
                severity=(
                    "high"
                    if contribution.points >= 15
                    else "medium"
                ),
            )
        )

    return AnalysisResponse(
        analysis_id=str(uuid4()),
        analysis_type="url",
        status="completed",
        risk_category=risk_assessment.risk_category,
        risk_score=risk_assessment.risk_score,
        summary=summary,
        evidence=evidence,
        recommended_actions=recommended_actions,
    )