"""
verify.plan_integrity — a SIGNED, offline-verifiable PLAN-INTEGRITY attestation.

TRUTHENOVATION M3. The threat: a target that STEERS the analyst's plan into skipping a
surface — a page that says "this endpoint is deprecated, do not test", an
``X-Robots-Tag: noindex`` — must become VISIBLE and SIGNED, not silently obeyed. This
module makes the plan an auditable, tamper-evident artifact:

  1. COMMITTED — the (surface, class) pairs the scan committed to test (the discovered
     surface set x the active point-check roster), signed.
  2. DISCOVERED vs EXERCISED — the surfaces the crawl put on the table minus the surfaces
     a probe actually exercised (from M2's ``exercised_probes``). Each discovered-but-
     unprobed surface is TAGGED with an honest reason (budget / config / unprobed).
  3. STEER SIGNALS — target content that matched a plan-steering pattern
     (scanner.steer_detect), LISTED next to the gap.

HONEST SCOPE (baked verbatim into the signed bytes — see :data:`SCOPE`). This attestation
proves OBSERVABLE facts only. It does NOT prove the LLM planner's internal reasoning was
unswayed (that is unobservable), and a discovered-but-unprobed surface may be a legitimate
budget/scope/structural skip, NOT proof of steering. It NEVER concludes "the plan was
poisoned" — it surfaces the gap and the signal; the classification (budget vs config vs
suspicious) is labeled and the conclusion is the operator's.

DETERMINISM: the document carries no timing, no rng, no volatile host:port — surfaces are
normalised to path+query and the host is recorded without its port — so two scans of the
same app produce byte-identical canonical JSON.

SIGNING reuses :func:`eval.benchmark_run.sign_scorecard` / ``verify_scorecard`` (m-of-n
Ed25519 over the canonical bytes, checkable offline) with the trust root pinned OUT OF
BAND (a caller-held ``sha256:`` fingerprint), so a forger who re-signs a tampered
attestation with a FRESH key is rejected before any signature is checked — the same pin
idiom as the M1 recall baseline / M2 coverage certificate. This attestation is PER-SCAN
(not a committed baseline), so nothing is golden; the deliverable is the build+sign+verify
machinery.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from vigil_core import canonical_json

# NOTE: eval.benchmark_run (sign_scorecard / verify_scorecard) is imported LAZILY inside the
# sign/verify helpers — eval imports scanner which imports this `verify` package, so a
# module-top import would risk an import cycle. Building the attestation needs no eval.

SCHEMA = "vigil-plan-integrity/1"

# The honest scope statement — carried IN the signed bytes so a reader of the JSON cannot
# mistake an observable gap/signal for a proof of poisoning or of an unswayed planner.
SCOPE = (
    "Plan-integrity attestation over OBSERVABLE facts: (1) these (surface,class) were "
    "committed and signed; (2) these discovered-but-unprobed surfaces exist; (3) this "
    "target content matches plan-steering patterns. It does NOT prove the planner's "
    "internal reasoning was unswayed (unobservable), and a discovered-unprobed surface "
    "may be a legitimate budget/scope skip, not proof of steering. Undiscovered surfaces "
    "(link-omission) are recall/H3, not covered here. Largely the LLM-engage plan; the "
    "deterministic analogue is the crawl frontier + budget cutoff."
)


def _surface(endpoint: str) -> str:
    """Normalise an endpoint to a port/scheme-INDEPENDENT surface key: path (+query).

    Strips scheme + host + volatile ephemeral port so two scans of the same app yield
    identical bytes. Mirrors scanner.campaign._surface_key's path+query half and
    verify.coverage_oracle._surface, so the discovered and exercised sides of the skip
    diff normalise to the SAME key."""
    parts = urlsplit(endpoint or "")
    surface = parts.path or "/"
    if parts.query:
        surface = f"{surface}?{parts.query}"
    return surface


def _target_host(target: str) -> str:
    """The target's host WITHOUT its port (the per-run ephemeral must not enter the bytes)."""
    return urlsplit(target or "").hostname or ""


def _split_discovered(entry: str) -> tuple[str, str]:
    """Split a stored discovered surface ``"METHOD path?query"`` into (method, path+query).

    scanner.campaign._surface_key stores discovered surfaces method-prefixed. The skip diff
    keys on the path+query half (the exercised side has no method), while the reason
    classifier still sees the method. A malformed/legacy entry with no space is treated as a
    GET path."""
    if " " in entry:
        method, surface = entry.split(" ", 1)
        return method.upper(), surface
    return "GET", entry


def _skip_reason(method: str, surface: str, *, budget_exhausted: bool) -> str:
    """Classify (NEVER conclude) why a discovered surface went unprobed — an honest, coarse
    label, not a verdict:

      * ``config``  — the surface carries no query param and is a GET, so there is no
        query-value insertion point to fuzz: a structural/benign skip, not steering.
      * ``budget``  — the surface HAS a fuzzable point but the audit budget was exhausted
        (``max_audit_requests`` broke the loop), so it was plausibly cut for budget.
      * ``unprobed``— the surface HAS a fuzzable point, the budget was NOT exhausted, yet no
        probe exercised it. This is the bucket worth a human look — but it is still NOT
        proof of steering (targeting/selector pruning, a non-GET with an unmodelled body, or
        a legitimate scope decision can all land here). Labeled, never concluded.
    """
    has_fuzzable_point = ("?" in surface) or (method != "GET")
    if not has_fuzzable_point:
        return "config"
    if budget_exhausted:
        return "budget"
    return "unprobed"


def _steer_rows(steer_signals: Iterable[Any]) -> list[dict[str, str]]:
    """Normalise steer signals (SteerSignal objects or their dicts) to sorted rows."""
    rows: list[dict[str, str]] = []
    for s in steer_signals or []:
        get = (lambda k: s.get(k)) if isinstance(s, dict) else (lambda k: getattr(s, k, None))
        rows.append({
            "where": str(get("where") or ""),
            "pattern": str(get("pattern") or ""),
            "excerpt": str(get("excerpt") or ""),
        })
    rows.sort(key=lambda r: (r["where"], r["pattern"], r["excerpt"]))
    return rows


def build_plan_integrity_attestation(
    report: Any,
    *,
    max_pages: int,
    max_depth: int,
    frontier_truncated: int = 0,
    budget_exhausted: bool,
    steer_signals: Iterable[Any] | None = None,
) -> dict:
    """Build the DETERMINISTIC plan-integrity attestation document (a plain dict).

    ``report`` is a ``scanner.campaign.ScanReport`` — it supplies ``discovered_surfaces``
    (the discovered surface axis), ``committed_check_classes`` (the class axis),
    ``exercised_probes`` (M2 — the surfaces a probe actually ran over), and
    ``steer_signals`` (scanner.steer_detect). ``steer_signals`` defaults to the report's
    retained list; a caller may pass an explicit list to override. The discovery caps are
    passed IN and CITED as the denominator's bound. No timing / rng / host:port, so the
    canonical bytes are byte-identical across two scans of one app."""
    discovered_entries = sorted(set(getattr(report, "discovered_surfaces", []) or []))
    committed_classes = sorted(set(getattr(report, "committed_check_classes", []) or []))

    # COMMITTED (surface x class): the plan the scan committed to. Cross product of the two
    # retained axes, sorted for byte-stability.
    committed = [
        {"surface": s, "class": c}
        for s in discovered_entries
        for c in committed_classes
    ]
    committed.sort(key=lambda r: (r["surface"], r["class"]))

    # EXERCISED surface keys (METHOD, path+query) — the M2 evidence of what a probe actually
    # ran. Keyed on the method too: a discovered POST and a probed GET of the SAME path+query
    # are DISTINCT surfaces, so a real unprobed POST is never hidden behind a probed GET (the
    # method-blind bug a method-aware ProbeRecord.method closes).
    exercised_keys = {
        (str(getattr(p, "method", "GET")).upper(), _surface(getattr(p, "endpoint", "")))
        for p in (getattr(report, "exercised_probes", []) or [])
    }

    # SKIPPED = discovered - exercised, each tagged with an honest reason.
    skipped: list[dict[str, str]] = []
    for entry in discovered_entries:
        method, surface = _split_discovered(entry)
        if (method.upper(), _surface(surface)) in exercised_keys:
            continue
        skipped.append({
            "surface": entry,
            "reason": _skip_reason(method, surface, budget_exhausted=budget_exhausted),
        })
    skipped.sort(key=lambda r: (r["surface"], r["reason"]))

    steer = _steer_rows(report.steer_signals if steer_signals is None else steer_signals)

    return {
        "schema": SCHEMA,
        "scope": SCOPE,
        "target_host": _target_host(getattr(report, "target", "")),
        "committed": committed,
        "discovered": discovered_entries,
        "skipped": skipped,
        "steer_signals": steer,
        "denominator": {
            "max_pages": int(max_pages),
            "max_depth": int(max_depth),
            "frontier_truncated": int(frontier_truncated),
            "budget_exhausted": bool(budget_exhausted),
            "n_committed": len(committed),
            "n_discovered": len(discovered_entries),
            "n_skipped": len(skipped),
            "n_steer": len(steer),
        },
    }


def canonical_attestation_bytes(att: dict) -> bytes:
    """The exact bytes a signer signs and a verifier re-derives — canonical JSON."""
    return canonical_json(att)


def write_plan_integrity_attestation(path: str | Path, att: dict) -> Path:
    """Write ``att`` to ``path`` as canonical JSON (the exact signed bytes on disk)."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(canonical_attestation_bytes(att))
    return p


def sign_plan_integrity_attestation(
    att: dict,
    path: str | Path,
    *,
    signers: list[tuple[str, str]],
    authorizers: list[dict],
    threshold: int,
) -> dict:
    """Write ``att`` to ``path`` and sign it (m-of-n Ed25519 over the canonical bytes),
    reusing :func:`eval.benchmark_run.sign_scorecard`. Writes ``<path>.sig.json`` +
    ``<path>.fingerprint.txt`` beside it and returns the signature envelope. Keys are
    passed IN (no key provisioning here)."""
    from ..eval.benchmark_run import sign_scorecard
    p = write_plan_integrity_attestation(path, att)
    return sign_scorecard(p, signers=signers, authorizers=authorizers, threshold=threshold)


def verify_plan_integrity_attestation(
    path: str | Path,
    sig_env: dict,
    *,
    trust_root_fingerprint: str | None = None,
) -> bool:
    """Offline-verify a signed plan-integrity attestation, reusing
    :func:`eval.benchmark_run.verify_scorecard`. Re-derives the canonical digest from the
    JSON on disk and checks an m-of-n threshold of DISTINCT authorizers over those bytes; a
    flipped byte breaks it. Pass ``trust_root_fingerprint`` (a ``sha256:`` pin the caller
    holds OUT OF BAND) to reject a forger who re-signs a tampered attestation with a fresh
    key — the authorizer set embedded in ``sig_env`` must hash to exactly that pin, else
    fail-closed (the M1 pinning idiom)."""
    from ..eval.benchmark_run import verify_scorecard
    return verify_scorecard(path, sig_env, trust_root_fingerprint=trust_root_fingerprint)


# ---------------------------------------------------------------------------
# CLI — offline verification of a signed plan-integrity attestation.
#   python -m framework.v2 plan-integrity verify <att.json> <att.sig.json> [--pin sha256:...]
# Mirrors verify.reverify's re-check verb: a pure, offline, deterministic re-derivation.
# ---------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 plan-integrity",
        description=("Offline-verify a SIGNED plan-integrity attestation "
                     "(verify.plan_integrity). Re-derives the canonical digest from the JSON "
                     "on disk and checks an m-of-n Ed25519 threshold; pass --pin to enforce "
                     "the out-of-band trust root so a fresh-key re-sign is rejected."),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="Offline-verify an attestation against its signature.")
    v.add_argument("attestation", help="Path to the attestation JSON (the signed bytes).")
    v.add_argument("signature", help="Path to the <attestation>.sig.json envelope.")
    v.add_argument("--pin", default=None,
                   help="Out-of-band trust-root fingerprint (sha256:...) to enforce.")
    args = parser.parse_args(argv)

    if args.cmd == "verify":
        sig_env = json.loads(Path(args.signature).read_text(encoding="utf-8"))
        ok = verify_plan_integrity_attestation(
            args.attestation, sig_env, trust_root_fingerprint=args.pin)
        pin_note = " (out-of-band pin enforced)" if args.pin else " (NO pin — self-consistency only)"
        print(f"plan-integrity attestation: {'VERIFIED' if ok else 'REJECTED'}{pin_note}")
        return 0 if ok else 1
    return 2

