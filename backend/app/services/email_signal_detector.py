from __future__ import annotations

from dataclasses import dataclass
from email.utils import parseaddr


@dataclass(frozen=True)
class EmailSignal:
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

ATTACHMENT_PATTERNS = (
    "open the attachment",
    "download the attachment",
    "enable macros",
    "enable content",
    "run this file",
    "install this software",
    ".exe",
    ".scr",
    ".js attachment",
    ".zip attachment",
)

FREE_EMAIL_DOMAINS = (
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
)

SUSPICIOUS_DOMAIN_TERMS = (
    "career",
    "careers",
    "recruitment",
    "recruiter",
    "hr",
    "jobs",
    "joboffer",
    "talent",
    "workforce",
)


def _normalize(value: str) -> str:
    return " ".join(value.lower().split())


def _find_matches(text: str, patterns: tuple[str, ...]) -> list[str]:
    return [pattern for pattern in patterns if pattern in text]


def _extract_email_address(value: str) -> str:
    _, address = parseaddr(value.strip())
    return address.lower()


def _domain_from_email(value: str) -> str:
    address = _extract_email_address(value)
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1]


def detect_email_signals(
    *,
    subject: str,
    sender: str,
    reply_to: str,
    body: str,
) -> list[EmailSignal]:
    normalized_subject = _normalize(subject)
    normalized_body = _normalize(body)
    combined_text = f"{normalized_subject} {normalized_body}".strip()

    signals: list[EmailSignal] = []

    payment_matches = _find_matches(combined_text, PAYMENT_PATTERNS)
    if payment_matches:
        signals.append(
            EmailSignal(
                category="financial_request",
                signal="payment_request",
                explanation=(
                    "The email contains payment-related language: "
                    + ", ".join(payment_matches)
                    + "."
                ),
                severity="high",
            )
        )

    credential_matches = _find_matches(combined_text, CREDENTIAL_PATTERNS)
    if credential_matches:
        signals.append(
            EmailSignal(
                category="credential_request",
                signal="sensitive_credential_request",
                explanation=(
                    "The email references sensitive credentials: "
                    + ", ".join(credential_matches)
                    + "."
                ),
                severity="critical",
            )
        )

    document_matches = _find_matches(combined_text, DOCUMENT_PATTERNS)
    if document_matches:
        signals.append(
            EmailSignal(
                category="document_request",
                signal="identity_document_request",
                explanation=(
                    "The email references identity or financial documents: "
                    + ", ".join(document_matches)
                    + "."
                ),
                severity="high",
            )
        )

    urgency_matches = _find_matches(combined_text, URGENCY_PATTERNS)
    if urgency_matches:
        signals.append(
            EmailSignal(
                category="urgency",
                signal="pressure_or_urgency",
                explanation=(
                    "The email uses pressure or urgency language: "
                    + ", ".join(urgency_matches)
                    + "."
                ),
                severity="medium",
            )
        )

    external_contact_matches = _find_matches(
        combined_text,
        EXTERNAL_CONTACT_PATTERNS,
    )
    if external_contact_matches:
        signals.append(
            EmailSignal(
                category="contact_redirection",
                signal="external_contact_redirection",
                explanation=(
                    "The email redirects communication to external or personal "
                    "channels: "
                    + ", ".join(external_contact_matches)
                    + "."
                ),
                severity="medium",
            )
        )

    recruitment_matches = _find_matches(
        combined_text,
        SUSPICIOUS_RECRUITMENT_PATTERNS,
    )
    if recruitment_matches:
        signals.append(
            EmailSignal(
                category="recruitment_claim",
                signal="suspicious_recruitment_claim",
                explanation=(
                    "The email contains potentially suspicious recruitment claims: "
                    + ", ".join(recruitment_matches)
                    + "."
                ),
                severity="high",
            )
        )

    attachment_matches = _find_matches(
        combined_text,
        ATTACHMENT_PATTERNS,
    )
    if attachment_matches:
        signals.append(
            EmailSignal(
                category="attachment_risk",
                signal="suspicious_attachment_instruction",
                explanation=(
                    "The email contains potentially risky attachment or file "
                    "instructions: "
                    + ", ".join(attachment_matches)
                    + "."
                ),
                severity="high",
            )
        )

    sender_domain = _domain_from_email(sender)
    reply_to_domain = _domain_from_email(reply_to)

    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        signals.append(
            EmailSignal(
                category="email_routing",
                signal="sender_reply_to_domain_mismatch",
                explanation=(
                    "The sender domain "
                    f"'{sender_domain}' differs from the Reply-To domain "
                    f"'{reply_to_domain}'."
                ),
                severity="high",
            )
        )

    if sender_domain in FREE_EMAIL_DOMAINS:
        signals.append(
            EmailSignal(
                category="sender_identity",
                signal="free_email_sender",
                explanation=(
                    f"The sender uses a public email provider domain: "
                    f"'{sender_domain}'. This is not proof of fraud, but "
                    "independent verification is recommended."
                ),
                severity="low",
            )
        )

    if sender_domain and any(
        term in sender_domain for term in SUSPICIOUS_DOMAIN_TERMS
    ):
        signals.append(
            EmailSignal(
                category="sender_identity",
                signal="recruitment_keyword_domain",
                explanation=(
                    f"The sender domain '{sender_domain}' contains recruitment-"
                    "related terms and should be independently verified."
                ),
                severity="medium",
            )
        )

    return signals