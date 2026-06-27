"""
socialdefense.detectors — the inbound social-engineering indicator engine.

Deterministic heuristics over a message. Each detector emits at most one
`PhishingSignal`; the overall score is a noisy-OR over signal weights, so
multiple weak signals accumulate without ever exceeding 1.0. These are
*leads for a human or a downstream classifier*, not verdicts — phishing
detection is probabilistic, and the recommendation says so.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import (
    MessageArtifact,
    PhishingAssessment,
    PhishingSignal,
    RiskBand,
)

# Brands commonly impersonated. Used for lookalike-domain and
# display-name-mismatch checks.
_BRANDS: dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "microsoft.com",
    "apple": "apple.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "docusign": "docusign.com",
    "dhl": "dhl.com",
}

_DANGEROUS_EXT = frozenset({
    ".exe", ".scr", ".js", ".vbs", ".jse", ".wsf", ".lnk", ".iso",
    ".docm", ".xlsm", ".pptm", ".jar", ".bat", ".cmd", ".html", ".htm",
})

_URGENCY = re.compile(
    r"\b(act now|immediately|within \d+ hours?|urgent|as soon as possible|"
    r"account (?:will be )?(?:suspended|closed|locked|disabled)|final notice|"
    r"expires? (?:today|soon)|right away|do not delay)\b",
    re.IGNORECASE,
)
_CREDENTIAL = re.compile(
    r"\b(verify your (?:account|password|identity|login)|confirm your "
    r"(?:credentials|password|account)|re-?activate your account|"
    r"unusual (?:sign-?in|login|activity)|update your password|"
    r"validate your account|sign in to (?:avoid|prevent|restore))\b",
    re.IGNORECASE,
)
_AUTHORITY = re.compile(
    r"\b(this is your (?:ceo|cfo|manager|boss)|from (?:it|help ?desk|"
    r"support|security) team|account (?:team|services)|on behalf of the "
    r"(?:ceo|director)|your bank|payroll department)\b",
    re.IGNORECASE,
)
_FINANCIAL = re.compile(
    r"\b(wire transfer|bank transfer|gift cards?|update (?:your )?payment|"
    r"change (?:the )?bank (?:details|account)|outstanding invoice|"
    r"process (?:this |the )?payment|send (?:the )?funds|crypto(?:currency)?|"
    r"bitcoin)\b",
    re.IGNORECASE,
)
_SECRECY = re.compile(
    r"\b(keep this (?:confidential|between us|quiet)|do (?:not|n't) tell|"
    r"strictly confidential|don'?t share this|handle this discreetly)\b",
    re.IGNORECASE,
)


def _domain(address_or_host: str) -> str:
    s = address_or_host.strip().lower()
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if "://" in s or "/" in s:
        s = urlparse(s if "://" in s else "https://" + s).hostname or s
    return s.strip().rstrip(".")


def _registrable(host: str) -> str:
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _sig(kind: str, weight: float, evidence: str) -> PhishingSignal:
    return PhishingSignal(kind=kind, weight=weight, evidence=evidence[:160])


def _scan_text(msg: MessageArtifact) -> list[PhishingSignal]:
    text = f"{msg.subject}\n{msg.body}"
    signals: list[PhishingSignal] = []
    has_url = bool(msg.urls)

    if m := _URGENCY.search(text):
        signals.append(_sig("urgency", 0.35, f"urgency cue: {m.group(0)!r}"))
    if m := _CREDENTIAL.search(text):
        # Credential cue plus a link is the classic harvest pattern.
        w = 0.6 if has_url else 0.4
        signals.append(_sig("credential_harvest", w, f"credential cue: {m.group(0)!r}"))
    if m := _AUTHORITY.search(text):
        signals.append(_sig("authority_impersonation", 0.45, f"authority cue: {m.group(0)!r}"))
    if m := _FINANCIAL.search(text):
        signals.append(_sig("financial_request", 0.6, f"financial cue: {m.group(0)!r}"))
    if m := _SECRECY.search(text):
        signals.append(_sig("secrecy_request", 0.4, f"secrecy cue: {m.group(0)!r}"))
    return signals


def _scan_sender(msg: MessageArtifact) -> list[PhishingSignal]:
    signals: list[PhishingSignal] = []
    sender_dom = _domain(msg.sender_address) if msg.sender_address else ""

    # Reply-To pointing to a different domain than From.
    if msg.reply_to and sender_dom:
        reply_dom = _domain(msg.reply_to)
        if reply_dom and reply_dom != sender_dom:
            signals.append(_sig(
                "reply_to_mismatch", 0.45,
                f"reply-to {reply_dom!r} differs from sender {sender_dom!r}",
            ))

    # Display name claims a brand the sender domain does not belong to.
    display = msg.sender_display.lower()
    if sender_dom:
        reg = _registrable(sender_dom)
        for brand, brand_dom in _BRANDS.items():
            if brand in display and reg != brand_dom:
                signals.append(_sig(
                    "display_name_mismatch", 0.5,
                    f"display name claims {brand!r} but sender domain is {reg!r}",
                ))
                break
    return signals


def _scan_urls(msg: MessageArtifact) -> list[PhishingSignal]:
    signals: list[PhishingSignal] = []
    for url in msg.urls:
        host = _domain(url)
        if not host:
            continue
        if "xn--" in host:
            signals.append(_sig("lookalike_domain", 0.55, f"punycode host {host!r}"))
            break
        reg = _registrable(host)
        flagged = False
        for brand, brand_dom in _BRANDS.items():
            if brand in host and reg != brand_dom:
                signals.append(_sig(
                    "lookalike_domain", 0.55,
                    f"host {host!r} embeds brand {brand!r} but is not {brand_dom!r}",
                ))
                flagged = True
                break
        if flagged:
            break
    return signals


def _scan_attachments(msg: MessageArtifact) -> list[PhishingSignal]:
    for name in msg.attachments:
        lower = name.lower()
        for ext in _DANGEROUS_EXT:
            if lower.endswith(ext):
                return [_sig("suspicious_attachment", 0.5, f"dangerous attachment {name!r}")]
    return []


def _band(score: float) -> RiskBand:
    if score >= 0.85:
        return RiskBand.CRITICAL
    if score >= 0.60:
        return RiskBand.HIGH
    if score >= 0.35:
        return RiskBand.ELEVATED
    if score >= 0.15:
        return RiskBand.LOW
    return RiskBand.MINIMAL


def _recommendation(band: RiskBand) -> str:
    if band in (RiskBand.CRITICAL, RiskBand.HIGH):
        return (
            "Quarantine and report to the security team. Do not click links, "
            "open attachments, or act on requests. Verify any payment/credential "
            "request out-of-band through a known channel."
        )
    if band is RiskBand.ELEVATED:
        return (
            "Treat with suspicion. Verify the sender out-of-band before acting; "
            "do not enter credentials via links in this message."
        )
    if band is RiskBand.LOW:
        return "Some indicators present; apply normal caution and verify if acting."
    return "No strong indicators. Standard vigilance applies (this is a heuristic, not proof)."


def assess_message(msg: MessageArtifact) -> PhishingAssessment:
    """Score one inbound message for social-engineering indicators."""
    signals: list[PhishingSignal] = []
    signals += _scan_text(msg)
    signals += _scan_sender(msg)
    signals += _scan_urls(msg)
    signals += _scan_attachments(msg)

    survival = 1.0
    for s in signals:
        survival *= 1.0 - s.weight
    score = round(1.0 - survival, 6)
    band = _band(score)
    return PhishingAssessment(
        score=score, band=band, signals=signals, recommendation=_recommendation(band),
    )
