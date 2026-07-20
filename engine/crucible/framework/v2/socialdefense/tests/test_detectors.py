"""Tests for socialdefense.detectors — inbound phishing assessment."""

from __future__ import annotations

from ..detectors import assess_message
from ..models import MessageArtifact, RiskBand


def _kinds(a: object) -> set[str]:
    return {s.kind for s in a.signals}  # type: ignore[attr-defined]


def test_benign_message_is_minimal() -> None:
    msg = MessageArtifact(
        body="Hi team, here are the notes from today's standup. Thanks!",
        subject="Standup notes",
        sender_display="Alice",
        sender_address="alice@example.com",
    )
    a = assess_message(msg)
    assert a.band is RiskBand.MINIMAL
    assert a.score < 0.15


def test_classic_credential_phish_is_high() -> None:
    msg = MessageArtifact(
        subject="Urgent: your account will be suspended",
        body="We detected unusual sign-in activity. Verify your password "
        "immediately or your account will be locked.",
        sender_display="Microsoft Account Team",
        sender_address="security@account-verify.tk",
        urls=["https://microsoft.account-verify.tk/login"],
    )
    a = assess_message(msg)
    assert a.band in (RiskBand.HIGH, RiskBand.CRITICAL)
    assert "urgency" in _kinds(a)
    assert "credential_harvest" in _kinds(a)
    assert "lookalike_domain" in _kinds(a)


def test_bec_wire_transfer_with_secrecy() -> None:
    msg = MessageArtifact(
        subject="Quick favor",
        body="This is your CEO. I need you to process a wire transfer today. "
        "Keep this confidential until it's done.",
        sender_display="CEO",
        sender_address="ceo@example.com",
        reply_to="ceo.private@gmail.com",
    )
    a = assess_message(msg)
    assert "financial_request" in _kinds(a)
    assert "secrecy_request" in _kinds(a)
    assert "authority_impersonation" in _kinds(a)
    assert "reply_to_mismatch" in _kinds(a)
    assert a.band in (RiskBand.HIGH, RiskBand.CRITICAL)


def test_punycode_lookalike() -> None:
    msg = MessageArtifact(
        body="Click here", urls=["https://xn--paypl-2qa.com/login"]
    )
    a = assess_message(msg)
    assert "lookalike_domain" in _kinds(a)


def test_display_name_brand_mismatch() -> None:
    msg = MessageArtifact(
        body="Your invoice is ready.",
        sender_display="PayPal Service",
        sender_address="billing@totally-not-paypal.test",
    )
    a = assess_message(msg)
    assert "display_name_mismatch" in _kinds(a)


def test_dangerous_attachment() -> None:
    msg = MessageArtifact(body="See attached.", attachments=["invoice.docm"])
    a = assess_message(msg)
    assert "suspicious_attachment" in _kinds(a)


def test_score_is_bounded_and_noisy_or() -> None:
    # Many signals must not push the score above 1.0.
    msg = MessageArtifact(
        subject="urgent final notice",
        body="verify your password. wire transfer. keep this confidential. "
        "this is your CEO.",
        sender_display="PayPal",
        sender_address="x@evil.test",
        reply_to="y@other.test",
        urls=["https://paypal.evil.test/login"],
        attachments=["x.exe"],
    )
    a = assess_message(msg)
    assert 0.0 <= a.score <= 1.0
    assert a.band is RiskBand.CRITICAL


def test_recommendation_present() -> None:
    a = assess_message(MessageArtifact(body="hello"))
    assert a.recommendation
