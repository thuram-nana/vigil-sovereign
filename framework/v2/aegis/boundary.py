"""
aegis.boundary — the untrusted-input ingest boundary.

AEGIS ingests its own app's telemetry AND the attacker-controlled content inside it (user
turns, model output, requested paths). The boundary treats ALL of it as hostile and fails
closed:

  * bounded envelope size (reject oversized) + depth cap (reject deeply-nested) + per-field
    length caps — no unbounded work on adversarial input;
  * STRICT safe parse — ``json.loads`` only, NEVER eval / exec / pickle / object
    deserialization; an unknown key is rejected by the models' ``extra="forbid"``;
  * hidden-unicode normalization — zero-width / format (Cf) characters stripped so a
    smuggled instruction cannot hide from the marker/canary scanners;
  * PII pseudonymisation — a KEYED HMAC (per-deployment secret, PR2) over identifiers and a
    /24 (v4) / /48 (v6) IP coarsening, so an identifier is pseudonymous-under-key, not a
    brute-forceable bare hash;
  * ReDoS-safe matchers (PR3) — the structural-override marker scan is LINEAR substring
    matching over a length-capped input; no regex backtracking on adversarial output.

Nothing here trusts the content it inspects; AEGIS's own detectors must not be injectable by
the telemetry they judge.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import unicodedata
from typing import Any

from .models import (
    ActorRef,
    AegisConfig,
    AuthActivity,
    AuthEvent,
    LLMInteraction,
    TelemetryEnvelope,
)


class BoundaryError(ValueError):
    """A fail-closed rejection at the ingest boundary (oversized / too deep / malformed).
    The caller renders it as a refusal / HTTP 400 — never as a silent pass."""


# --- hidden-unicode normalization -----------------------------------------------------

# Zero-width and BOM-like characters attackers use to hide instructions from a scanner.
_ZERO_WIDTH = {
    "​", "‌", "‍", "⁠", "﻿", "᠎", "‎", "‏",
}


def normalize_text(s: str, *, max_chars: int) -> str:
    """Strip hidden-unicode + Cf (format) category chars, NFKC-normalise, and length-cap.
    Total + deterministic. The cap makes every downstream scan linear-bounded (PR3)."""
    if not isinstance(s, str):
        s = str(s)
    if len(s) > max_chars:
        s = s[:max_chars]
    out = []
    for ch in s:
        if ch in _ZERO_WIDTH:
            continue
        if unicodedata.category(ch) == "Cf":   # format chars (incl. other zero-widths)
            continue
        out.append(ch)
    return unicodedata.normalize("NFKC", "".join(out))


# --- ReDoS-safe PII redaction (linear over a length-capped input) ----------------------

# Bounded, non-backtracking patterns. Applied only AFTER length-capping, so no catastrophic
# backtracking is reachable. Emails and long digit runs are the two obvious in-band PII kinds;
# a high-entropy canary sentinel (alnum, no '@', short digit runs) survives redaction intact.
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}")
_LONG_DIGITS = re.compile(r"\d{9,32}")


def redact_text(s: str, *, max_chars: int) -> str:
    """Normalise + length-cap + redact obvious in-band PII (emails, long digit runs). Pure."""
    s = normalize_text(s, max_chars=max_chars)
    s = _EMAIL.sub("<email>", s)
    s = _LONG_DIGITS.sub("<digits>", s)
    return s


# --- keyed identifier pseudonymisation (PR2) ------------------------------------------


def hmac_id(value: str, *, secret: str) -> str:
    """Keyed HMAC-SHA256 of an identifier (truncated) — pseudonymous UNDER the key, not a
    brute-forceable bare hash. Empty in → empty out."""
    if not value:
        return ""
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def coarsen_ip(ip: str) -> str:
    """Coarsen an IP to its /24 (v4) or /48 (v6) network before hashing — so the pseudonym
    can never re-identify a single host. Non-IP / empty → ''."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return ""
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{addr}/24", strict=False))
    return str(ipaddress.ip_network(f"{addr}/48", strict=False))


def redact_actor(actor: ActorRef, *, secret: str) -> ActorRef:
    """Return a pseudonymised ActorRef: the IP coarsened-then-HMAC'd, session/principal
    HMAC'd (PR2). Deterministic under the deployment key."""
    ip_net = coarsen_ip(actor.ip)
    return ActorRef(
        ip=hmac_id(ip_net, secret=secret) if ip_net else "",
        session=hmac_id(actor.session, secret=secret),
        principal=hmac_id(actor.principal, secret=secret),
    )


def pseudonymize_source(value: str, *, secret: str) -> str:
    """Pseudonymise an auth-event source identifier (PR2): coarsen to its /24 (v4) / /48 (v6)
    network then keyed-HMAC if it parses as an IP — so a NAT/CGNAT egress collapses to ONE
    pseudonym (the benign twin's shared source) — else HMAC the raw token (a session/device id).
    Empty in → empty out. Deterministic under the deployment key."""
    if not value:
        return ""
    net = coarsen_ip(value)
    return hmac_id(net, secret=secret) if net else hmac_id(value, secret=secret)


# --- structural-override markers (LEAD signals; ReDoS-safe substring scan) --------------

# Lowercased literal markers. Matched by linear substring search over a length-capped input —
# no regex, no backtracking. A hit is a LEAD (it raises belief), NEVER a confirmation; only
# the control-vs-treatment oracle confirms `prompt_injection`.
_OVERRIDE_MARKERS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore the above",
    "disregard previous",
    "disregard all previous",
    "forget your instructions",
    "you are now",
    "reveal your instructions",
    "reveal your system prompt",
    "print your system prompt",
    "repeat the words above",
    "<|im_start|>",
    "<|im_end|>",
    "### system",
    "### instruction",
    "system:",
    "assistant:",
    "developer mode",
    "do anything now",
)


def structural_override_markers(text: str, *, max_chars: int) -> list[str]:
    """Return the structural-override markers present in ``text`` (linear substring scan over
    a normalised, length-capped copy). ReDoS-safe (PR3). A LEAD signal, never a confirmation."""
    hay = normalize_text(text, max_chars=max_chars).lower()
    return [m for m in _OVERRIDE_MARKERS if m in hay]


# --- depth cap -------------------------------------------------------------------------


def _check_depth(obj: Any, *, max_depth: int, _depth: int = 0) -> None:
    if _depth > max_depth:
        raise BoundaryError(f"envelope nesting exceeds depth cap ({max_depth})")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(v, max_depth=max_depth, _depth=_depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check_depth(v, max_depth=max_depth, _depth=_depth + 1)


# --- the boundary ----------------------------------------------------------------------


def ingest(raw: Any, config: AegisConfig) -> TelemetryEnvelope:
    """Parse + harden + redact untrusted telemetry into a ``TelemetryEnvelope``.

    ``raw`` is a ``dict`` (SDK path) or ``str``/``bytes`` JSON (HTTP path). Fails closed on
    oversize / over-depth / malformed / unknown-key input. The returned envelope carries
    PSEUDONYMISED actor identifiers and a REDACTED, length-capped ``llm_output`` — so the
    retained certificate never holds raw PII."""
    # 1. size cap (before any structural work).
    import json

    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw)
        if len(raw) > config.max_envelope_bytes:
            raise BoundaryError(f"envelope exceeds size cap ({config.max_envelope_bytes} bytes)")
        try:
            data = json.loads(raw.decode("utf-8"))       # STRICT safe parse — never eval/pickle
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise BoundaryError(f"envelope is not valid UTF-8 JSON: {e}") from None
    elif isinstance(raw, str):
        if len(raw.encode("utf-8")) > config.max_envelope_bytes:
            raise BoundaryError(f"envelope exceeds size cap ({config.max_envelope_bytes} bytes)")
        try:
            data = json.loads(raw)                        # STRICT safe parse — never eval/pickle
        except json.JSONDecodeError as e:
            raise BoundaryError(f"envelope is not valid JSON: {e}") from None
    elif isinstance(raw, dict):
        data = raw
        try:
            if len(json.dumps(data).encode("utf-8")) > config.max_envelope_bytes:
                raise BoundaryError(f"envelope exceeds size cap ({config.max_envelope_bytes} bytes)")
        except (TypeError, ValueError) as e:
            raise BoundaryError(f"envelope is not JSON-serialisable: {e}") from None
    else:
        raise BoundaryError(f"envelope must be dict / str / bytes, got {type(raw).__name__}")

    if not isinstance(data, dict):
        raise BoundaryError("envelope must decode to a JSON object")

    # 2. depth cap.
    _check_depth(data, max_depth=config.max_depth)

    # 3. strict schema parse — extra="forbid" rejects unknown keys (fail-closed).
    try:
        env = TelemetryEnvelope.model_validate(data)
    except Exception as e:   # pydantic ValidationError
        raise BoundaryError(f"envelope failed strict validation: {e}") from None

    # 4. redact / pseudonymise. Actor identifiers → keyed HMAC (PR2); llm_output → PII-redacted
    #    + length-capped; requested_path normalised. The canary is left verbatim (the guard
    #    supplied a dedicated random token; the oracle must substring-match it).
    actor = redact_actor(env.actor, secret=config.deployment_secret)
    llm = env.llm
    if llm is not None:
        llm = LLMInteraction(
            system_prompt_id=llm.system_prompt_id,
            canary=llm.canary,
            user_input=normalize_text(llm.user_input, max_chars=config.max_field_chars),
            llm_output=redact_text(llm.llm_output, max_chars=config.max_field_chars),
            control_behavior=llm.control_behavior,
            treatment_behavior=llm.treatment_behavior,
        )
    requested_path = (
        normalize_text(env.requested_path, max_chars=config.max_field_chars)
        if env.requested_path is not None else None
    )
    # 5. AUTH surface — bound the window and pseudonymise every identifier. An empty source
    #    defaults to the actor's own pseudonym (single-source window); a provided source is
    #    coarsened+HMAC'd so a NAT/CGNAT egress collapses to one pseudonym. No raw PII survives.
    auth = env.auth
    if auth is not None:
        default_source = actor.stable_key
        red_events = []
        for e in auth.events[: config.max_auth_events]:
            acct_raw = normalize_text(e.account, max_chars=config.max_field_chars)
            src_raw = normalize_text(e.source, max_chars=config.max_field_chars)
            red_events.append(AuthEvent(
                account=hmac_id(acct_raw, secret=config.deployment_secret) if acct_raw else "",
                source=(pseudonymize_source(src_raw, secret=config.deployment_secret)
                        if src_raw else default_source),
                success=e.success,
            ))
        benign = [
            pseudonymize_source(normalize_text(s, max_chars=config.max_field_chars),
                                secret=config.deployment_secret)
            for s in auth.benign_sources if s
        ]
        auth = AuthActivity(events=red_events, benign_sources=benign)
    return env.model_copy(update={"actor": actor, "llm": llm, "requested_path": requested_path, "auth": auth})
