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

import difflib
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .models import OracleKind, OracleSignal


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
# 2. Achieved state — an unauthorized record/state became reachable
# ---------------------------------------------------------------------------


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
# 5. Out-of-band callback — inbound interaction against a unique token
# ---------------------------------------------------------------------------


def oob_callback_oracle(hits: Any) -> OracleSignal:
    """Fire when the out-of-band receiver logged >=1 inbound interaction
    against a correlation token. An inbound hit on a per-finding unique token
    is close to unforgeable evidence of blind execution (SSRF, OOB SQLi,
    blind XXE, deserialization callbacks). `hits` is whatever `oob.poll()`
    returned — a list of hit records/objects."""
    hit_list = list(hits or [])
    if not hit_list:
        return OracleSignal(
            kind=OracleKind.OOB_CALLBACK, fired=False, confidence=0.0,
            evidence="no out-of-band interaction observed", observed={"hit_count": 0})

    first = hit_list[0]
    summary = _hit_summary(first)
    return OracleSignal(
        kind=OracleKind.OOB_CALLBACK,
        fired=True,
        confidence=0.95,
        evidence=f"{len(hit_list)} out-of-band interaction(s); first: {summary}",
        observed={"hit_count": len(hit_list), "first": summary},
    )


def _hit_summary(hit: Any) -> str:
    if isinstance(hit, Mapping):
        return f"{hit.get('method', '?')} {hit.get('path', '?')} from {hit.get('client_ip', '?')}"
    method = getattr(hit, "method", "?")
    path = getattr(hit, "path", "?")
    client = getattr(hit, "client_ip", "?")
    return f"{method} {path} from {client}"
