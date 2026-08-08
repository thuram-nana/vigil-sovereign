"""
verify.coverage_oracle — a SIGNED, offline-verifiable COVERAGE / COMPLETENESS certificate.

CRUCIBLE's oracle layer proves what it FOUND. This module proves what it EXERCISED:
for each (surface, param, class) the active audit reached, it retains whether an
applicable oracle actually RAN over observed data and rendered a verdict. That turns a
silent surface from *merely-untested* into *provably-tested-clean* — the M2 goal.

The three verdicts (from :func:`scanner.engine.probe_verdict`, the honesty rule):

  * ``finding``      — an applicable oracle FIRED (a fact; also in active_findings).
  * ``clean``        — an applicable oracle RAN and did NOT fire (exercised-and-clean).
  * ``inconclusive`` — the payload was sent but NO oracle adjudicated. NOT clean.

HONEST SCOPE (baked verbatim into the signed bytes): this certifies coverage of the
surfaces the scanner REACHED and probed — it is NOT a proof of surface completeness.
Undiscovered endpoints/parameters are a DISCOVERY/RECALL question (M1/H3), not a
coverage one. The denominator is the reached surface, bounded by the discovery caps
(``max_pages`` / ``max_depth`` / ``frontier.truncated`` / audit budget) — all cited in
the document so a reader cannot mistake the certificate's reach for the whole app.

DETERMINISM: the document carries no timing, no rng, and no volatile host:port — each
surface is normalised to its path+query, and the host is recorded without its port — so
two scans of the same app produce byte-identical canonical JSON.

SIGNING reuses :func:`eval.benchmark_run.sign_scorecard` /
:func:`~eval.benchmark_run.verify_scorecard`: an m-of-n Ed25519 signature over the
canonical bytes, checkable offline. The trust root is pinned OUT OF BAND (a caller-held
``sha256:`` fingerprint), so a forger who re-signs a tampered certificate with a FRESH
key is rejected before any signature is checked — the same pin idiom as the M1 recall
baseline. This certificate is PER-SCAN (not a committed baseline), so nothing is golden;
the deliverable is the build+sign+verify machinery.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from vigil_core import canonical_json

# NOTE: eval.benchmark_run (sign_scorecard / verify_scorecard) is imported LAZILY inside
# the sign/verify helpers below — eval imports scanner which imports this `verify` package,
# so a module-top import here would risk an import cycle. Building the certificate needs no
# eval, so only the crypto helpers pay the lazy import.

SCHEMA = "vigil-coverage-certificate/1"

# The honest scope statement — carried IN the signed bytes so a reader of the JSON
# cannot mistake reached-surface coverage for surface completeness.
SCOPE = (
    "Coverage of the surfaces the scanner REACHED and probed — for each (surface, "
    "param, class) an applicable oracle actually ran and rendered a verdict. This is "
    "NOT proof of surface completeness: undiscovered endpoints/parameters are "
    "discovery/recall (M1/H3), not coverage. Denominator = the reached surface, "
    "bounded by max_pages/max_depth/frontier.truncated/budget (all cited)."
)


def _surface(endpoint: str) -> str:
    """Normalise an endpoint to a port-INDEPENDENT surface key: its path (+query).

    Strips scheme + host + volatile ephemeral port so two scans of the same app —
    which bind different ports each run — yield identical certificate bytes. An empty
    or hostless endpoint (a request-level anchor) collapses to its path, or ``/``."""
    parts = urlsplit(endpoint or "")
    surface = parts.path or "/"
    if parts.query:
        surface = f"{surface}?{parts.query}"
    return surface


def _target_host(target: str) -> str:
    """The target's host WITHOUT its port (the port is a per-run ephemeral for the
    loopback fixtures, so it must not enter the signed bytes)."""
    return urlsplit(target or "").hostname or ""


def tested_bug_classes(probes: Iterable[Any]) -> list[str]:
    """The sorted, de-duplicated bug classes an applicable oracle actually ADJUDICATED
    (verdict ``clean`` or ``finding``) — the honest ``tested_bug_classes`` input to
    ``report.standards.coverage_matrix`` so a probed-clean class can grade
    ``tested_clear``. An ``inconclusive`` probe is EXCLUDED: no oracle adjudicated it,
    so it was not tested clean. Accepts ProbeRecord objects or their serialised dicts."""
    out: set[str] = set()
    for p in probes:
        verdict = p.get("verdict") if isinstance(p, dict) else getattr(p, "verdict", None)
        bug_class = p.get("bug_class") if isinstance(p, dict) else getattr(p, "bug_class", None)
        if verdict in ("clean", "finding") and bug_class:
            out.add(str(bug_class))
    return sorted(out)


def build_coverage_certificate(
    report: Any,
    *,
    frontier_truncated: int = 0,
    max_pages: int,
    max_depth: int,
    budget_exhausted: bool,
) -> dict:
    """Build the DETERMINISTIC coverage certificate document (a plain dict).

    ``report`` is a ``scanner.campaign.ScanReport`` (its ``exercised_probes`` are the
    retained per-probe adjudications). The discovery caps are passed IN by the caller —
    the certificate CITES them as the denominator's bound (an honest reader can see the
    reach was capped) — never a claim the whole app was covered. No timing / rng /
    host:port, so the canonical bytes are byte-identical across two scans of one app."""
    probes = list(getattr(report, "exercised_probes", []) or [])

    rows: list[dict[str, Any]] = []
    for p in probes:
        row = {
            "surface": _surface(p.endpoint),
            "insertion_point": p.insertion_point,
            "param": p.param,
            "check_id": p.check_id,
            "class": p.bug_class,
            "verdict": p.verdict,
            "oracle_kinds_run": list(p.oracle_kinds_run),
        }
        # OPT-IN re-executable-tier evidence (Proof-of-Posture): emitted ONLY when a probe actually
        # retained it (AuditEngine.retain_evidence), so a certificate scanned without retention is
        # byte-identical to before — the make-gate invariant. Present ⇒ a VIGIL-free verifier re-runs the
        # pure predicate oracle over these values to re-derive the verdict producer-independently.
        evidence = getattr(p, "evidence", None)
        if evidence:
            row["evidence"] = evidence
        rows.append(row)
    # Stable sort on the normalised surface identity so the port-normalisation cannot
    # reorder rows between two runs.
    rows.sort(key=lambda r: (r["surface"], r["insertion_point"], r["check_id"], r["class"]))

    n_finding = sum(1 for r in rows if r["verdict"] == "finding")
    n_clean = sum(1 for r in rows if r["verdict"] == "clean")
    n_inconclusive = sum(1 for r in rows if r["verdict"] == "inconclusive")

    surfaces_reached = len({r["surface"] for r in rows})
    insertion_points_probed = len({(r["surface"], r["insertion_point"]) for r in rows})
    distinct_classes_probed = len({r["class"] for r in rows})

    return {
        "schema": SCHEMA,
        "scope": SCOPE,
        "target_host": _target_host(getattr(report, "target", "")),
        "denominator": {
            "surfaces_reached": surfaces_reached,
            "insertion_points_probed": insertion_points_probed,
            "distinct_classes_probed": distinct_classes_probed,
            "frontier_truncated": int(frontier_truncated),
            "max_pages": int(max_pages),
            "max_depth": int(max_depth),
            "budget_exhausted": bool(budget_exhausted),
        },
        "probes": rows,
        "summary": {
            "n_finding": n_finding,
            "n_clean": n_clean,
            "n_inconclusive": n_inconclusive,
        },
    }


def canonical_cert_bytes(cert: dict) -> bytes:
    """The exact bytes a signer signs and a verifier re-derives — the canonical JSON
    of the coverage certificate."""
    return canonical_json(cert)


def write_coverage_certificate(path: str | Path, cert: dict) -> Path:
    """Write ``cert`` to ``path`` as canonical JSON (the exact signed bytes on disk), so
    the file, its signature, and a re-derivation all agree byte-for-byte."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(canonical_cert_bytes(cert))
    return p


def sign_coverage_certificate(
    cert: dict,
    path: str | Path,
    *,
    signers: list[tuple[str, str]],
    authorizers: list[dict],
    threshold: int,
) -> dict:
    """Write ``cert`` to ``path`` and sign it (m-of-n Ed25519 over the canonical bytes),
    reusing :func:`eval.benchmark_run.sign_scorecard`. Writes ``<path>.sig.json`` +
    ``<path>.fingerprint.txt`` beside it and returns the signature envelope. Keys are
    passed IN (no key provisioning here)."""
    from ..eval.benchmark_run import sign_scorecard
    p = write_coverage_certificate(path, cert)
    return sign_scorecard(p, signers=signers, authorizers=authorizers, threshold=threshold)


def verify_coverage_certificate(
    path: str | Path,
    sig_env: dict,
    *,
    trust_root_fingerprint: str | None = None,
) -> bool:
    """Offline-verify a signed coverage certificate, reusing
    :func:`eval.benchmark_run.verify_scorecard`. Re-derives the canonical digest from the
    JSON on disk and checks an m-of-n threshold of DISTINCT authorizers over those bytes;
    a flipped byte breaks it. Pass ``trust_root_fingerprint`` (a ``sha256:`` pin the
    caller holds OUT OF BAND) to reject a forger who re-signs a tampered certificate with
    a fresh key — the authorizer set embedded in ``sig_env`` must hash to exactly that
    pin, else fail-closed (the M1 pinning idiom)."""
    from ..eval.benchmark_run import verify_scorecard
    return verify_scorecard(path, sig_env, trust_root_fingerprint=trust_root_fingerprint)
