from __future__ import annotations

from uuid import uuid4

from backend.app.schemas.analysis import (
    AnalysisResponse,
    EvidenceItem,
)
from backend.app.schemas.signals import URLTechnicalSignals


def build_url_analysis_response(
    signals: URLTechnicalSignals,
) -> AnalysisResponse:
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
                        f"URL followed {signals.redirect_count} "
                        "validated redirect(s)."
                    ),
                    severity="unknown",
                )
            )

        summary = (
            "The URL passed deterministic validation and returned "
            "an HTTP response. This is not proof that the job "
            "posting or recruiter is legitimate."
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
                "Verify the domain through an independent trusted "
                "source.",
                "Do not download files or submit personal documents "
                "from this URL yet.",
            ]
        )

    else:
        summary = (
            "The URL produced an unexpected fetch state. "
            "There is insufficient evidence for a security "
            "assessment."
        )

    return AnalysisResponse(
        analysis_id=str(uuid4()),
        analysis_type="url",
        status="completed",
        risk_category="unknown",
        risk_score=0,
        summary=summary,
        evidence=evidence,
        recommended_actions=recommended_actions,
    )