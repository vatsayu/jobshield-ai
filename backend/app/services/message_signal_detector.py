from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MessageSignal:
    category: str
    signal: str
    explanation: str
    severity: str


PAYMENT_PATTERNS = (
    "registration fee",
    "processing fee",
    "security deposit",
    "refundable fee",
    "pay to apply",
    "pay for interview",
    "payment required",
    "send money",
    "transfer money",
    "training fee",
    "joining fee",
    "verification fee",
    "pay for registration",
    "registration payment",
    "registration charge",
    "registration amount",
    "pay before your interview",
    "pay before interview",
    "payment before interview",
    "pay rs",
    "pay inr",
)

CREDENTIAL_PATTERNS = (
    "otp",
    "one time password",
    "password",
    "login credentials",
    "cvv",
    "pin",
    "bank account",
    "bank details",
    "upi pin",
)

DOCUMENT_PATTERNS = (
    "aadhaar",
    "aadhar",
    "pan card",
    "pancard",
    "passport",
    "driving license",
    "driving licence",
    "bank statement",
    "salary slip",
)

URGENCY_PATTERNS = (
    "urgent",
    "immediately",
    "act now",
    "within 1 hour",
    "within one hour",
    "today only",
    "last chance",
    "offer expires",
    "respond now",
    "failure to respond",
)

EXTERNAL_CONTACT_PATTERNS = (
    "telegram",
    "whatsapp",
    "signal app",
    "contact me privately",
    "personal number",
    "message my personal",
    "dm me",
)

SUSPICIOUS_RECRUITMENT_PATTERNS = (
    "guaranteed job",
    "guaranteed placement",
    "no interview",
    "instant joining",
    "work from home salary",
    "limited vacancies",
    "selected without interview",
    "pay and get job",
)


def _find_matches(
    text: str,
    patterns: tuple[str, ...],
) -> list[str]:
    return [pattern for pattern in patterns if pattern in text]

def _find_payment_matches(text: str) -> list[str]:
    matches = _find_matches(text, PAYMENT_PATTERNS)

    currency_payment_patterns = (
        r"\bpay\s+(?:₹|rs\.?|inr|\$|usd)\s*[\d,]+(?:\.\d+)?",
        r"(?:₹|rs\.?|inr|\$|usd)\s*[\d,]+(?:\.\d+)?",
        r"\b(?:pay|payment|transfer|send)\b.{0,40}\b(?:registration|interview|joining|job|selection)\b",
    )

    for pattern in currency_payment_patterns:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            cleaned_match = " ".join(match.split())

            if cleaned_match and cleaned_match not in matches:
                matches.append(cleaned_match)

    return matches


def detect_message_signals(message: str) -> list[MessageSignal]:
    """
    Detect deterministic security-relevant indicators in recruitment messages.

    This function does not determine whether a message is fraudulent.
    It only identifies observable text patterns for later risk assessment.
    """
    normalized = " ".join(message.lower().split())
    signals: list[MessageSignal] = []

    payment_matches = _find_payment_matches(normalized)
    if payment_matches:
        signals.append(
            MessageSignal(
                category="financial_request",
                signal="payment_request",
                explanation=(
                    "The message contains payment-related language: "
                    + ", ".join(payment_matches)
                    + "."
                ),
                severity="high",
            )
        )

    credential_matches = _find_matches(normalized, CREDENTIAL_PATTERNS)
    if credential_matches:
        signals.append(
            MessageSignal(
                category="credential_request",
                signal="sensitive_credential_request",
                explanation=(
                    "The message requests or references sensitive credentials: "
                    + ", ".join(credential_matches)
                    + "."
                ),
                severity="critical",
            )
        )

    document_matches = _find_matches(normalized, DOCUMENT_PATTERNS)
    if document_matches:
        signals.append(
            MessageSignal(
                category="document_request",
                signal="identity_document_request",
                explanation=(
                    "The message references identity or financial documents: "
                    + ", ".join(document_matches)
                    + "."
                ),
                severity="high",
            )
        )

    urgency_matches = _find_matches(normalized, URGENCY_PATTERNS)
    if urgency_matches:
        signals.append(
            MessageSignal(
                category="urgency",
                signal="pressure_or_urgency",
                explanation=(
                    "The message uses pressure or urgency language: "
                    + ", ".join(urgency_matches)
                    + "."
                ),
                severity="medium",
            )
        )

    external_contact_matches = _find_matches(
        normalized,
        EXTERNAL_CONTACT_PATTERNS,
    )
    if external_contact_matches:
        signals.append(
            MessageSignal(
                category="contact_redirection",
                signal="external_contact_redirection",
                explanation=(
                    "The message redirects communication to external or personal "
                    "channels: "
                    + ", ".join(external_contact_matches)
                    + "."
                ),
                severity="medium",
            )
        )

    recruitment_matches = _find_matches(
        normalized,
        SUSPICIOUS_RECRUITMENT_PATTERNS,
    )
    if recruitment_matches:
        signals.append(
            MessageSignal(
                category="recruitment_claim",
                signal="suspicious_recruitment_claim",
                explanation=(
                    "The message contains potentially suspicious recruitment claims: "
                    + ", ".join(recruitment_matches)
                    + "."
                ),
                severity="high",
            )
        )

    return signals