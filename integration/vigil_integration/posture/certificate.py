"""posture.certificate — the signed, deterministic PostureCertificate (Certificate of Non-Exploitability).

A PostureCertificate is a PROJECTION of a coverage certificate (``verify.coverage_oracle``) into a
posture vocabulary, bound to a target and carrying its coverage denominator + honest residual. It is
the first machine-verifiable, third-party-offline-re-verifiable proof of EARNED ABSENCE of
exploitability: each CLOSED claim is minted ONLY because an applicable deterministic oracle had a live
channel to the real target and did not fire.

THE LOAD-BEARING HONESTY RULE (the M2 lesson, re-checked at verify): a claim is CLOSED iff, for its
``(surface, param, class)``, at least one probe's coverage verdict is ``clean`` AND that clean probe
names a non-empty ``oracle_kinds_run`` (the conclusive oracle(s) that adjudicated it) AND no probe
fired. ``clean`` already means "a conclusive oracle had a channel and did not fire" (see
``scanner.engine.probe_verdict``); a ``clean`` row with an EMPTY ``oracle_kinds_run`` is a tampered /
forged coverage certificate and is refused. UNPROVEN never counts as CLOSED — that is the difference
between a sound negative and an omniscience lie.

DETERMINISM: the certificate carries no wall-clock / rng / host:port (the embedded coverage cert is
already port-normalised). Freshness (RFC3161 anchor) and witness co-signatures are SIDECARS added to
the certificate's digest at the bundle layer — never in these signed bytes — so two scans of one app
produce byte-identical certificates.

FATAL-2: imports only vigil_core + stdlib; the m-of-n signing envelope
(``eval.benchmark_run.sign_scorecard`` / ``verify_scorecard`` — the same idiom the coverage/M1/benchmark
certs use) is imported FUNCTION-LOCALLY inside sign/verify, so importing this module co-loads zero
framework modules.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vigil_core import canonical_json
from vigil_core.capability import (
    CapabilityError,
    IdentityAttestation,
    identity_matches,
    verify_identity_attestation,
)

POSTURE_SCHEMA = "vigil-posture-certificate/1"

# The honest scope/residual — carried IN the signed bytes so a reader cannot mistake a bounded,
# oracle-family, reached-surface negative for "provably secure against everything".
POSTURE_RESIDUAL = (
    "Non-exploitability BY THE DETERMINISTIC ORACLE FAMILY, over the REACHED surface, as of the "
    "certificate's freshness bound. A CLOSED claim means an applicable oracle had a LIVE channel to "
    "the real target and did not fire — NOT a proof of security against all attacks. Undiscovered "
    "endpoints/parameters are discovery/recall (out of the denominator), NOT covered. Freshness is "
    "only as current as the last scan (see the bundle's time anchor). A standalone verifier re-checks "
    "signatures / target-binding / coverage-projection / denominator / freshness / witnesses OFFLINE "
    "with no VIGIL installed. Each CLOSED claim carries a verification TIER: a RE-EXECUTABLE claim "
    "embeds the oracle's retained input (a pure predicate + the observed values) and the standalone "
    "verifier RE-RUNS the oracle over it to re-derive the negative producer-INDEPENDENTLY (trusting no "
    "producer); a BINDING claim is re-checked against the signed coverage verdict, but re-firing its "
    "oracle needs VIGIL (`python -m framework.v2 evidence verify` / a coverage re-run) — the honest H4 "
    "residual that applies only to binding-tier claims."
)

_CLOSED, _OPEN, _UNPROVEN = "CLOSED", "OPEN", "UNPROVEN"
_BINDING, _REEXECUTABLE = "binding", "re-executable"


class PostureError(Exception):
    """A malformed / forged / unbindable posture certificate — always fail-closed."""


# --------------------------------------------------------------------------------------------------
# The re-executable posture tier (Proof-of-Posture): a VIGIL-free verifier RE-RUNS the deterministic
# predicate oracle over the retained observed values and re-derives the verdict itself — the sound
# NEGATIVE made producer-INDEPENDENT (it no longer trusts the signed verdict, it recomputes it). The
# kernel is a pure JSON-AST evaluator — a byte-faithful port of ``verify.oracles._eval_predicate`` /
# ``predicate_oracle`` (a byte-parity test pins it to the real oracle). vigil_core + stdlib only.
# --------------------------------------------------------------------------------------------------


def _probe_reexec_evidence(probe: dict) -> dict | None:
    """The re-execution kernel input a coverage-cert probe row carries, or ``None``. Well-formed iff it
    holds a JSON-AST ``predicate`` (a dict) and an ``observed_evidence`` (a dict) — the exact pair the
    ``predicate_oracle`` re-derives. This function (identical in the standalone ``verify_vf``) DEFINES
    which probes are re-executable, so the tier projection and the re-execution agree by construction."""
    ev = probe.get("evidence")
    if not isinstance(ev, dict):
        return None
    pred, obs = ev.get("predicate"), ev.get("observed_evidence")
    if isinstance(pred, dict) and isinstance(obs, dict):
        return {"predicate": pred, "observed_evidence": obs}
    return None


def _reexec_resolve_operand(operand: Any, observed: dict) -> Any:
    """Port of ``oracles._resolve_operand``: ``{"var": name}`` → observed value; else a literal."""
    if isinstance(operand, dict) and set(operand.keys()) == {"var"}:
        return observed.get(operand["var"])
    return operand


def _reexec_eval_predicate(pred: Any, observed: dict) -> bool:
    """Port of ``oracles._eval_predicate`` (the ``fired`` half only): evaluate the pure JSON-AST predicate
    over the observed values. Ops: all/any/not, eq/ieq, contains/icontains, in, min_len, gt/ge. Raises
    ``PostureError`` on a malformed node (the oracle treats a malformed predicate as NOT fired and
    non-conclusive — a non-conclusive probe is never ``clean``, so a malformed re-exec kernel can never
    UPHOLD a CLOSED claim; we fail-closed and refuse rather than silently pass)."""
    if not isinstance(pred, dict) or len(pred) != 1:
        raise PostureError(f"malformed re-execution predicate node: {pred!r}")
    op, args = next(iter(pred.items()))
    if op == "all":
        return all(_reexec_eval_predicate(p, observed) for p in args)
    if op == "any":
        return any(_reexec_eval_predicate(p, observed) for p in args)
    if op == "not":
        return not _reexec_eval_predicate(args, observed)
    a = _reexec_resolve_operand(args[0], observed)
    b = _reexec_resolve_operand(args[1], observed) if len(args) > 1 else None
    if op == "eq":
        return a == b
    if op == "ieq":
        return str(a).lower() == str(b).lower()
    if op == "contains":
        return bool(a) and bool(b) and str(b) in str(a)
    if op == "icontains":
        return bool(a) and bool(b) and str(b).lower() in str(a).lower()
    if op == "in":
        return a in (b or [])
    if op == "min_len":
        return len(str(a or "")) >= int(b)
    if op == "gt":
        return a is not None and b is not None and a > b
    if op == "ge":
        return a is not None and b is not None and a >= b
    raise PostureError(f"unknown re-execution predicate op {op!r}")


def reexecute_posture_claims(cert: dict) -> None:
    """RE-RUN the oracle over every re-executable probe's retained evidence and refuse on disagreement —
    the producer-independent soundness check behind the ``re-executable`` tier. Fail-closed (raises
    ``PostureError``) if:

      * a probe recorded ``clean`` (evidence for a CLOSED claim) whose predicate ACTUALLY FIRES over its
        own retained values — a forged negative;  OR
      * a probe recorded ``finding`` whose predicate does NOT fire over its retained values — a forged
        positive.

    Only probes carrying a well-formed re-execution kernel are re-run; ``binding``-tier probes are left
    to the signature/projection checks (the honest H4 residual). This is the SAME logic the standalone
    ``verify_vf`` runs with no VIGIL installed."""
    coverage = cert.get("coverage") or {}
    for probe in coverage.get("probes") or []:
        if not isinstance(probe, dict):
            continue
        kernel = _probe_reexec_evidence(probe)
        if kernel is None:
            continue
        fired = _reexec_eval_predicate(kernel["predicate"], dict(kernel["observed_evidence"]))
        verdict = probe.get("verdict")
        if verdict == "clean" and fired:
            raise PostureError(
                "re-execution REFUTED a CLOSED claim: the predicate fires over the probe's own retained "
                f"values (surface={probe.get('surface')!r} param={probe.get('param')!r} "
                f"class={probe.get('class')!r}) — a forged negative")
        if verdict == "finding" and not fired:
            raise PostureError(
                "re-execution REFUTED an OPEN claim: the predicate does not fire over the probe's own "
                f"retained values (surface={probe.get('surface')!r} class={probe.get('class')!r}) — a "
                "forged positive")


def _as_identity(att: IdentityAttestation | dict) -> IdentityAttestation:
    return att if isinstance(att, IdentityAttestation) else IdentityAttestation(**att)


def project_posture_claims(coverage_cert: dict) -> list[dict]:
    """Deterministically project a coverage certificate's per-probe rows into per-(surface, param,
    class) posture claims. This is the SOLE derivation of ``posture_claims``; the verifier re-runs it
    over the embedded coverage cert and demands byte-equality, so a claim cannot be forged apart from
    its coverage evidence.

    Fail-closed: a ``clean`` probe carrying an EMPTY ``oracle_kinds_run`` is a tampered coverage cert
    (``probe_verdict`` never returns ``clean`` without a conclusive oracle) and raises PostureError.
    """
    probes = coverage_cert.get("probes")
    if not isinstance(probes, list):
        raise PostureError("coverage certificate has no probes list")

    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for p in probes:
        if not isinstance(p, dict):
            raise PostureError("malformed probe row")
        verdict = p.get("verdict")
        kinds = p.get("oracle_kinds_run") or []
        if verdict == "clean" and not kinds:
            raise PostureError(
                "coverage certificate is INVALID: a 'clean' probe carries no oracle_kinds_run "
                "(a clean verdict is earned only by a conclusive oracle) — refusing to mint CLOSED"
            )
        key = (str(p.get("surface", "")), str(p.get("param", "")), str(p.get("class", "")))
        g = groups.setdefault(
            key, {"finding": 0, "clean": 0, "inconclusive": 0, "kinds": set(), "n": 0, "clean_reexec": 0})
        g["n"] += 1
        if verdict in ("finding", "clean", "inconclusive"):
            g[verdict] += 1
        if verdict == "clean":
            g["kinds"].update(str(k) for k in kinds)
            # Count clean probes that carry a well-formed re-execution kernel (predicate + observed
            # values). A CLOSED claim is the RE-EXECUTABLE tier only when EVERY clean probe backing it is
            # re-runnable — so the whole negative is producer-independently re-derivable, not just part.
            if _probe_reexec_evidence(p) is not None:
                g["clean_reexec"] += 1

    claims: list[dict] = []
    for (surface, param, cls), g in groups.items():
        if g["finding"] > 0:
            status, kinds = _OPEN, []
        elif g["clean"] > 0:
            status, kinds = _CLOSED, sorted(g["kinds"])
        else:
            status, kinds = _UNPROVEN, []
        # verification TIER (honest, in the signed bytes, computed IDENTICALLY here and in the standalone
        # verify_vf mirror so posture_claims re-project byte-for-byte):
        #   "re-executable" — a CLOSED claim whose EVERY clean probe carries a re-execution kernel
        #                     (predicate + observed values); a VIGIL-FREE verifier re-runs the oracle over
        #                     those values and re-derives the NEGATIVE itself (producer-INDEPENDENT).
        #   "binding"       — the verifier re-checks the signed coverage verdict + projection offline, but
        #                     re-firing the oracle needs VIGIL (the H4 residual). The default when no
        #                     re-execution evidence was retained (retain_evidence off) — byte-identical.
        if status == _CLOSED and g["clean"] > 0 and g["clean_reexec"] == g["clean"]:
            verification = _REEXECUTABLE
        else:
            verification = _BINDING
        claims.append({
            "surface": surface,
            "param": param,
            "class": cls,
            "status": status,
            "verification": verification,
            "evidence_oracle_kinds": kinds,
            "n_probes": g["n"],
        })
    claims.sort(key=lambda c: (c["surface"], c["param"], c["class"]))
    return claims


def build_posture_certificate(
    coverage_cert: dict,
    *,
    target_identity: IdentityAttestation | dict,
    target_sample: dict,
    residual: str = POSTURE_RESIDUAL,
) -> dict:
    """Build the DETERMINISTIC posture certificate document (a plain dict).

    ``coverage_cert`` is a ``verify.coverage_oracle`` certificate dict (built offense-side; this
    function is pure). ``target_identity`` is the owner-signed ``IdentityAttestation`` binding the
    proof to a target; ``target_sample`` is the observed identity of the scanned target (e.g.
    ``{"host": "127.0.0.1"}``) — the verifier checks it satisfies the attestation's policy, closing
    target-swap. No wall-clock / rng: byte-identical across two scans of one app."""
    att = _as_identity(target_identity)
    claims = project_posture_claims(coverage_cert)
    n_closed = sum(1 for c in claims if c["status"] == _CLOSED)
    n_open = sum(1 for c in claims if c["status"] == _OPEN)
    n_unproven = sum(1 for c in claims if c["status"] == _UNPROVEN)
    # How much of the negative is producer-independently RE-EXECUTABLE vs binding-only (honest count).
    n_reexecutable = sum(1 for c in claims if c["status"] == _CLOSED and c.get("verification") == "re-executable")
    n_binding = sum(1 for c in claims if c["status"] == _CLOSED and c.get("verification") != "re-executable")
    return {
        "schema": POSTURE_SCHEMA,
        "target_identity": att.model_dump(mode="json"),
        "target_sample": {str(k): str(v) for k, v in dict(target_sample).items()},
        "coverage": coverage_cert,
        "denominator": coverage_cert.get("denominator", {}),
        "scope": coverage_cert.get("scope", ""),
        "posture_claims": claims,
        "summary": {
            "n_closed": n_closed, "n_open": n_open, "n_unproven": n_unproven,
            "n_closed_re_executable": n_reexecutable, "n_closed_binding_only": n_binding,
        },
        "residual": residual,
    }


def canonical_posture_bytes(cert: dict) -> bytes:
    """The exact bytes a signer signs and a verifier re-derives — canonical JSON of the certificate."""
    return canonical_json(cert)


def write_posture_certificate(path: str | Path, cert: dict) -> Path:
    """Write ``cert`` as canonical JSON (the exact signed bytes), so file / signature / re-derivation
    all agree byte-for-byte."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(canonical_posture_bytes(cert))
    return p


def sign_posture_certificate(
    cert: dict,
    path: str | Path,
    *,
    signers: list[tuple[str, str]],
    authorizers: list[dict],
    threshold: int,
) -> dict:
    """Write ``cert`` to ``path`` and sign it (m-of-n Ed25519 over the canonical bytes), reusing the
    scorecard-signature idiom (the same one the coverage / M1 / benchmark certs use). Writes
    ``<path>.sig.json`` + ``<path>.fingerprint.txt`` and returns the signature envelope. Keys are
    passed IN (no provisioning here). The import is FUNCTION-LOCAL — importing this module co-loads no
    framework."""
    from framework.v2.eval.benchmark_run import sign_scorecard  # noqa: PLC0415 (FATAL-2: function-local)

    p = write_posture_certificate(path, cert)
    return sign_scorecard(p, signers=signers, authorizers=authorizers, threshold=threshold)


def _reproject_matches(cert: dict) -> None:
    """Fail-closed: the certificate's ``posture_claims`` MUST equal the projection re-derived from its
    embedded coverage cert (so a forged claim, detached from its coverage evidence, is refused)."""
    embedded = cert.get("posture_claims")
    rederived = project_posture_claims(cert.get("coverage", {}))
    if embedded != rederived:
        raise PostureError("posture_claims do not match the projection of the embedded coverage certificate")
    # Structural CLOSED invariant (defence in depth): every CLOSED names >=1 conclusive oracle.
    for c in rederived:
        if c["status"] == _CLOSED and not c.get("evidence_oracle_kinds"):
            raise PostureError("a CLOSED claim names no conclusive oracle — refusing")


def verify_posture_certificate(
    path: str | Path,
    sig_env: dict,
    *,
    trust_root_fingerprint: str | None = None,
    owner_pubkey: str,
    engagement: str,
    now: int,
) -> bool:
    """Offline-verify a signed posture certificate (the IN-TREE verifier the standalone ``verify_vf.py``
    mirrors byte-for-byte). Checks, fail-closed:

      1. AUTHENTICITY — the m-of-n governance signature over the canonical bytes, with the out-of-band
         ``trust_root_fingerprint`` pin (a forger who re-signs a tampered cert with a fresh key is
         rejected before any signature check — the M1 idiom).
      2. COVERAGE BINDING — ``posture_claims`` re-project byte-identically from the embedded coverage
         cert, and every CLOSED names a conclusive oracle.
      3. TARGET BINDING — the embedded ``IdentityAttestation`` is signed by the pinned owner key for
         ``engagement`` and not expired at ``now``, and the certificate's ``target_sample`` satisfies
         its policy (closes target-swap).

    It does NOT re-fire the oracle — that is the honest residual (re-firing needs VIGIL). Returns True
    iff every check holds; raises PostureError on a target-binding failure, returns False on a bad
    signature/pin."""
    from framework.v2.eval.benchmark_run import verify_scorecard  # noqa: PLC0415 (FATAL-2: function-local)

    p = Path(path).expanduser()
    cert = _loads(p)

    # 1. authenticity + out-of-band pin
    if not verify_scorecard(p, sig_env, trust_root_fingerprint=trust_root_fingerprint):
        return False

    # 2. coverage binding (the claims cannot drift from their evidence)
    _reproject_matches(cert)

    # 2b. RE-EXECUTION (the re-executable tier): re-run the oracle over every re-executable probe's
    #     retained values and refuse a forged negative/positive. Producer-independent; the standalone
    #     verify_vf runs the identical check with no VIGIL. Binding-tier probes carry no kernel and are
    #     left to the signature/projection checks (the honest H4 residual).
    reexecute_posture_claims(cert)

    # 3. target binding (closes target-swap) — present a uniform PostureError for any binding failure
    att = _as_identity(cert.get("target_identity", {}))
    try:
        verify_identity_attestation(att, trusted_owner_pubkey=owner_pubkey, now=int(now), engagement=engagement)
    except CapabilityError as e:
        raise PostureError(f"target identity attestation is not trusted/valid: {e}") from e
    sample = cert.get("target_sample", {})
    if not identity_matches(att.policy, sample):
        raise PostureError(f"target_sample {sample!r} does not satisfy the owner's identity policy")
    return True


def _loads(p: Path) -> dict:
    import json

    return json.loads(p.read_text(encoding="utf-8"))
