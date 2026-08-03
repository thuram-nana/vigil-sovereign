"""
eval.recall_baseline — a DETERMINISTIC, signed, reproducible recall baseline.

The signed ``benchmark-results.json`` scorecard (see :mod:`eval.benchmark_run`)
bundles NON-deterministic fields — wall-clock ``elapsed_s``, ``peak_rss_mb``,
per-host ``incumbent_versions`` — into the bytes it signs, so it can never be
re-derived byte-identically in CI: two honest runs disagree on timing, and the
signature is only meaningful for the exact run that produced it.

This module carves out the part that IS deterministic — the ACCURACY CORE — and
makes it a committed, re-derivable, offline-verifiable baseline:

  * :func:`build_accuracy_core` runs the CRUCIBLE-only deterministic benchmark
    adapter over the planted loopback corpus and emits a document with ONLY the
    accuracy facts: corpus name + count, matcher description, the planted-class
    list, and per-tool ``tp/fp/fn/precision/recall/f1`` + ``ground_truth_count``.
    No timing, no RSS, no host versions, no wall-clock, no RNG — the same bytes
    every time. ``vigil_core.canonical_json`` fixes the serialization.
  * :func:`write_accuracy_core` writes that document to disk.
  * :func:`accuracy_core_is_reproducible` builds the core TWICE and confirms the
    canonical bytes are byte-identical (the determinism check the CI test drives).

Honest scope: this measures the recall of the DETERMINISTIC SCANNER (no LLM, no
out-of-band collaborator) on a PLANTED loopback corpus, for the on-path classes
the response-visible oracles confirm. It is NOT LLM-``engage`` recall, and it is
NOT a claim of finding everything. A miss is reported as a true recall < 1.0.

Signing reuses :func:`eval.benchmark_run.sign_scorecard` /
:func:`~eval.benchmark_run.verify_scorecard`: an m-of-n Ed25519 signature over the
canonical bytes, checkable offline; a single flipped number breaks it. The private
key is NEVER written by this module into the repo — a caller signs with a pinned
key it holds out-of-band and commits only the public authorizer + fingerprint.
"""

from __future__ import annotations

from pathlib import Path

from vigil_core import canonical_json

from .benchmark_app import benchmark_corpus
from .benchmark_run import BenchmarkCrucibleAdapter, run_benchmark_measured, verify_scorecard
from .validation import MeasuredBoard

# The committed accuracy-core baseline + its detached signature + trust-root pin.
ACCURACY_CORE_PATH: Path = Path(__file__).resolve().parent / "baselines" / "recall-accuracy-core.json"

# ---------------------------------------------------------------------------
# The OUT-OF-BAND trust-root pin.
#
# This is the sha256 over the canonical authorizer set (key_id + public key) that is
# authorized to sign this baseline — the SAME value committed to
# ``recall-accuracy-core.fingerprint.txt``, but held HERE as a source-code constant so
# verification does NOT derive the trust root from the (rewritable) ``.sig.json``.
#
# Why this matters: the Ed25519 signature only proves origin against whoever the trust
# root names. If the verifier read that root straight out of the signature file, a
# repo-write / forked-bundle / malicious-PR adversary would just re-sign a tampered
# baseline with a FRESH key, embed that key as the authorizer, and pass. Pinning the
# fingerprint in source turns rewriting the baseline into a SOURCE-CODE change to this
# constant — visible in review — rather than a silent data-file swap. Honest residual: no
# in-repo pin can stop an adversary who also rewrites THIS line; defeating that needs a pin
# held off-repo. What this DOES close is the sig-file-only forgery (re-sign with a fresh key).
TRUST_ROOT_FINGERPRINT: str = "sha256:6cd32e143135d03cd8bdad8037ebd7c63ca668f1531cc52d8de13415a0875747"

# The stable schema tag the verifier and tests key on.
SCHEMA = "vigil-recall-accuracy-core/1"

# The matcher description — a fixed string, part of the signed bytes so a silent
# change to the scoring rule is tamper-evident too.
MATCHER = (
    "(normalized bug_class family, path+parameter); greedy 1-1; off-manifest "
    "detections are false positives by construction"
)

# The honest one-line scope statement, carried in the signed document so a reader
# of the committed JSON cannot mistake it for LLM-engage or find-everything recall.
SCOPE = (
    "recall of the DETERMINISTIC scanner (no LLM, no OOB collaborator) on a planted "
    "loopback corpus, for the on-path classes the response-visible oracles confirm"
)


def _planted_classes() -> list[str]:
    """The sorted, de-duplicated planted-class list from the ground-truth manifest —
    derived from the manifest itself so the baseline can never disagree with it."""
    corpus = benchmark_corpus("http://127.0.0.1:0")
    return sorted({e.bug_class for e in corpus.expected})


def _ground_truth_count() -> int:
    """Every planted bug in the manifest — the recall denominator."""
    return len(benchmark_corpus("http://127.0.0.1:0").expected)


def build_accuracy_core(measured: list[MeasuredBoard] | None = None) -> dict:
    """Build the DETERMINISTIC accuracy-core document (a plain dict).

    Runs the CRUCIBLE-only deterministic benchmark adapter (``incumbents=False``)
    unless ``measured`` boards are supplied (the tests pass a pre-run set to avoid a
    second scan). Emits ONLY accuracy facts — no timing/RSS/versions/wallclock — so
    two runs of the same deterministic scanner produce byte-identical canonical JSON.
    """
    if measured is None:
        measured = run_benchmark_measured(use_browser=False, incumbents=False)
    gt = _ground_truth_count()
    results = []
    for mb in sorted(measured, key=lambda m: m.scoreboard.tool):
        s = mb.scoreboard
        results.append({
            "tool": s.tool,
            "tp": s.true_positives,
            "fp": s.false_positives,
            "fn": s.false_negatives,
            "precision": s.precision,
            "recall": s.recall,
            "f1": s.f1,
            "ground_truth_count": gt,
        })
    return {
        "schema": SCHEMA,
        "corpus": "crucible-benchmark-app",
        "scope": SCOPE,
        "matcher": MATCHER,
        "planted_classes": _planted_classes(),
        "ground_truth_count": gt,
        "results": results,
    }


def canonical_bytes(core: dict) -> bytes:
    """The exact bytes a signer signs and a verifier re-derives — the canonical JSON
    of the accuracy-core document."""
    return canonical_json(core)


def write_accuracy_core(path: str | Path, core: dict) -> Path:
    """Write ``core`` to ``path`` as canonical JSON (the exact signed bytes on disk),
    so the committed file, the signature, and a re-derivation all agree byte-for-byte."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(canonical_bytes(core))
    return p


def accuracy_core_is_reproducible() -> tuple[bool, bytes, bytes]:
    """Build the accuracy core TWICE (two independent deterministic scans) and return
    ``(identical, bytes_run1, bytes_run2)`` — the reproducibility proof the baseline
    stakes its credibility on."""
    b1 = canonical_bytes(build_accuracy_core())
    b2 = canonical_bytes(build_accuracy_core())
    return (b1 == b2, b1, b2)


def crucible_recall(core: dict) -> float:
    """The CRUCIBLE tool's recall from an accuracy-core document (0.0 if absent)."""
    for r in core.get("results", []):
        if r.get("tool") == "crucible":
            return float(r.get("recall", 0.0))
    return 0.0


def verify_committed_recall_baseline(
    core_path: str | Path | None = None,
    sig_env: dict | None = None,
) -> bool:
    """Offline-verify the committed recall baseline AGAINST THE PINNED trust root.

    This is the verify path the M1 "signed and offline-verifiable" claim rests on: it
    enforces :data:`TRUST_ROOT_FINGERPRINT` (a source-held pin), so a signature made under
    any other authorizer set — e.g. a forger who re-signs a tampered baseline with a fresh
    key and embeds it in the ``.sig.json`` — is rejected before its signature is even
    checked. Defaults to the committed JSON + its committed ``.sig.json``.
    """
    import json as _json

    p = Path(core_path) if core_path is not None else ACCURACY_CORE_PATH
    if sig_env is None:
        sig_env = _json.loads(p.with_suffix(".sig.json").read_bytes())
    return verify_scorecard(p, sig_env, trust_root_fingerprint=TRUST_ROOT_FINGERPRINT)
