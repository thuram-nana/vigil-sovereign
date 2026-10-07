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
    "with no VIGIL installed. Each CLOSED claim carries a verification TIER. A RE-EXECUTABLE claim "
    "embeds the oracle's retained input (a pure predicate + the observed values) and the standalone "
    "verifier RE-DERIVES the verdict by re-running the oracle over it — confirming the verdict is the "
    "correct function of the retained evidence WITHOUT trusting the producer's asserted verdict "
    "(tamper-evidence stronger than binding). HONEST BOUND: the retained values are still "
    "PRODUCER-SUPPLIED, so re-execution does NOT prove they reflect the live target; trusting the "
    "negative reflects reality — for BOTH tiers — still requires a live VIGIL re-run "
    "(`python -m framework.v2 evidence verify` / a coverage re-run) or trust in the operator's signed "
    "capture. True independence of the OBSERVATION from the producer requires a channel-bound live capture."
)

_CLOSED, _OPEN, _UNPROVEN = "CLOSED", "OPEN", "UNPROVEN"
_BINDING, _REEXECUTABLE = "binding", "re-executable"


class PostureError(Exception):
    """A malformed / forged / unbindable posture certificate — always fail-closed."""


# --------------------------------------------------------------------------------------------------
# The re-executable posture tier (Proof-of-Posture). A VIGIL-free verifier RE-DERIVES each claim's verdict
# by re-running the deterministic predicate oracle over the RETAINED observed values — so a relying party
# confirms the recorded verdict is the correct function of the retained evidence, WITHOUT trusting the
# producer's asserted verdict. HONEST BOUND (red-pen BLOCK): the retained values are still PRODUCER-SUPPLIED
# — re-execution proves the verdict↔evidence binding (tamper-evidence stronger than the binding tier), NOT
# that the evidence reflects the live target. Trusting the negative reflects reality still needs a live
# re-run (or trust in the operator's signed capture); TRUE producer-independence of the OBSERVATION requires
# a channel-bound live capture (the runner-owned `capture_handshake`/`capture_tls_handshake` pattern). The
# kernel is a pure JSON-AST evaluator faithful to ``verify.oracles._eval_predicate`` / ``predicate_oracle``
# (eager evaluation + the same exception→non-conclusive semantics; a byte-parity test pins it to the real
# oracle). vigil_core + stdlib only.
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
        kernel = {"predicate": pred, "observed_evidence": obs}
        # Lane S: the provenance-ref slot is part of the oracle INPUT the structural grammar gate reads, so a
        # faithful re-execution carries it when present (``reexecutable_evidence`` retains it). Absent it the
        # kernel is the two-key dict as before. Identical in the standalone ``verify_vf``, so the tier
        # projection and the re-execution agree by construction.
        pref = ev.get("provenance_refs")
        if isinstance(pref, dict) and pref:
            kernel["provenance_refs"] = pref
        return kernel
    return None


def _reexec_resolve_operand(operand: Any, observed: dict) -> Any:
    """Port of ``oracles._resolve_operand``: ``{"var": name}`` → observed value; else a literal."""
    if isinstance(operand, dict) and set(operand.keys()) == {"var"}:
        return observed.get(operand["var"])
    return operand


def _reexec_eval_predicate(pred: Any, observed: dict) -> bool:
    """Port of ``oracles._eval_predicate`` (the ``fired`` half). EAGERLY evaluates all/any children (like
    the real oracle — no short-circuit), so a type error in ANY child surfaces exactly as it does upstream.
    Raises on a malformed node / bad operand (ValueError/TypeError/IndexError/KeyError); the caller
    (:func:`_reexec_fired_conclusive`) turns any such raise into a NON-CONCLUSIVE result, matching
    ``predicate_oracle``'s ``except (ValueError, TypeError) -> conclusive=False``."""
    if not isinstance(pred, dict) or len(pred) != 1:
        raise ValueError(f"malformed re-execution predicate node: {pred!r}")
    op, args = next(iter(pred.items()))
    if op == "all":
        return all([_reexec_eval_predicate(p, observed) for p in args])   # eager, matches the oracle
    if op == "any":
        return any([_reexec_eval_predicate(p, observed) for p in args])   # eager, matches the oracle
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
    raise ValueError(f"unknown re-execution predicate op {op!r}")


# --------------------------------------------------------------------------------------------------
# Lane S (S1, re-slice) — the STRUCTURAL FACT-ELIGIBILITY GRAMMAR, ported BYTE-FAITHFULLY from
# ``verify.oracles._fact_eligible`` (+ its helpers) and the ``_predicate_binds_and_const`` pre-gate, so this
# stdlib kernel renders the IDENTICAL ``(fired, conclusive)`` verdict ``predicate_oracle`` mints over the SAME
# ``(predicate, observed, provenance_refs)`` — not merely RAW predicate truth. Without this gate a bare shape
# (``eq[a,b]`` with ``a==b``, ``contains[body, LIT]``, ``in[status, [3xx]]``, ``min_len[tok,3]``,
# ``ge[n,5]``, ``not(eq[a,b])``, the canary-less ``open_redirect`` all/any) RE-DERIVES ``True`` here while the
# grammar-gated oracle REFUSES it — a divergence that breaks the byte-parity the re-executable tier rests on.
#
# A predicate is FACT-eligible only when every firing path carries a POSITIVE DISCRIMINATOR sound by SHAPE:
#   PD2  var-vs-provenance-ref canary (a positive-match op, one PR operand + one CV operand, order-insensitive);
#   PD3  ``gt[PR, int>=0]`` — a strict reduction floor (``ge``/``min_len`` at the floor is vacuous, refused);
#   PD-NUM ``gt``/``ge`` over two DISTINCT captured vars (a measured relation);
#   PD-VALUE ``eq``/``gt`` of a captured var vs a NUMERIC/BOOL non-status literal (an achieved-STATE value);
#   PD4  a present/absent DIFFERENTIAL at an ``all`` — ``pos(CV_a, needle)`` AND ``not(pos(CV_b, needle))`` over
#        DISTINCT captured bodies sharing one DISTINCTIVE needle (a LIT needle >= the distinctiveness floor).
# ``provenance_refs`` names the observed_evidence keys that are VIGIL-injected (a PR the producer cannot
# author); a var NOT listed there but present+non-None in ``observed`` is a captured var (CV); any other inline
# value is a producer literal (LIT). ``all`` ⇒ ANY child eligible OR a PD4 pair; ``any`` ⇒ EVERY child
# eligible; ``not`` ⇒ never a positive fire-driver. Pure stdlib + vigil_core — no framework import.
# --------------------------------------------------------------------------------------------------

_DISTINCTIVENESS_MIN_LEN = 6
_POSITIVE_MATCH_OPS = frozenset({"eq", "ieq", "contains", "icontains", "in"})
_PROTOCOL_STATUS_CONSTANTS = frozenset({100, 200, 300, 301, 302, 303, 307, 308, 400, 401, 403})
_REFLEXIVE_TRUE_OPS = frozenset({"eq", "ieq", "ge", "contains", "icontains", "in"})
_REFLEXIVE_FALSE_OPS = frozenset({"gt"})


def _is_var_operand(operand: Any) -> bool:
    return isinstance(operand, dict) and set(operand.keys()) == {"var"}


def _operand_is_provenance_ref(operand: Any, provenance_refs: dict) -> bool:
    """A ``{"var": k}`` whose key is declared in ``provenance_refs`` — a VIGIL-injected canary/reduction."""
    return _is_var_operand(operand) and operand["var"] in (provenance_refs or {})


def _operand_is_captured_var(operand: Any, observed: dict, provenance_refs: dict) -> bool:
    """A ``{"var": k}`` bound to a real captured value in ``observed`` and NOT a declared provenance-ref."""
    return (_is_var_operand(operand) and operand["var"] not in (provenance_refs or {})
            and observed.get(operand["var"]) is not None)


def _operand_binds_captured(operand: Any, observed: dict) -> bool:
    """A ``{"var": k}`` reference whose key resolves to a REAL captured value in ``observed`` (present + not
    None). A literal, or a var with an absent/None key, binds NOTHING (mirrors ``oracles._operand_binds_captured``)."""
    if _is_var_operand(operand):
        return observed.get(operand["var"]) is not None
    return False


def _needle_sig(operand: Any) -> tuple:
    if _is_var_operand(operand):
        return ("var", operand["var"])
    try:
        hash(operand)
        return ("lit", operand)
    except TypeError:
        return ("lit", repr(operand))


def _needle_is_distinctive(sig: tuple) -> bool:
    kind, val = sig
    if kind == "var":
        return True
    return isinstance(val, str) and len(val) >= _DISTINCTIVENESS_MIN_LEN


def _is_scalar_value_literal(operand: Any) -> bool:
    """An inline NUMERIC or BOOLEAN literal of an achieved-STATE value comparison. EXCLUDES a string literal
    (producer-authorable text match) AND a protocol-status constant (a gate-B corroborator, never a PD)."""
    if isinstance(operand, bool):
        return True
    if isinstance(operand, (int, float)) and not isinstance(operand, bool):
        return operand not in _PROTOCOL_STATUS_CONSTANTS
    return False


# Auto-check LIVENESS / AVAILABILITY flags (BYTE-FAITHFUL mirror of oracles._LIVENESS_AVAILABILITY_KEYS). A
# captured var of one of these names compared to a scalar literal (eq[body_available,True], gt[probe_count,0],
# eq[reachable,True]) is true for any merely-reachable target and adjudicates NOTHING about a vuln — a
# CORROBORATOR, never a self-sufficient PD-VALUE. It is structurally indistinguishable from a genuine
# achieved-state scalar (bizlogic eq[qty,-5] / eq[checked_out,True] / gt[redeemed_count,1]; gt[qty,0] has the
# SAME shape as gt[probe_count,0]), and the owner-signed-spec authority that would separate them is not
# reachable inside the pure predicate oracle, so this NAMED set is the structural stand-in (mirrors
# _PROTOCOL_STATUS_CONSTANTS). A leaf over one of these keys is FACT-eligible only when the enclosing predicate
# ALSO carries a real PD (PR canary/reduction or a PD4 differential). Matched case-insensitively.
_LIVENESS_AVAILABILITY_KEYS = frozenset({
    "body_available", "body_semantically_available",
    "reachable", "available", "responsive", "responded",
    "alive", "is_alive", "is_live",
    "host_up", "online", "port_open",
    "probe_count", "probes", "response_count", "reply_count",
})


def _operand_is_liveness_flag(operand: Any, observed: dict, provenance_refs: dict) -> bool:
    """A captured var whose KEY is a known auto-check liveness/availability flag — a gate corroborator, NEVER
    a self-sufficient PD-VALUE."""
    return (_operand_is_captured_var(operand, observed, provenance_refs)
            and str(operand["var"]).lower() in _LIVENESS_AVAILABILITY_KEYS)


def _leaf_is_self_sufficient_pd(op: str, args: Any, observed: dict, provenance_refs: dict) -> bool:
    if not isinstance(args, (list, tuple)) or len(args) != 2:
        return False
    a, b = args[0], args[1]
    if op in _POSITIVE_MATCH_OPS:
        if (_operand_is_provenance_ref(a, provenance_refs)
                and _operand_is_captured_var(b, observed, provenance_refs)):
            return True
        if (_operand_is_provenance_ref(b, provenance_refs)
                and _operand_is_captured_var(a, observed, provenance_refs)):
            return True
        if op in ("eq", "ieq"):
            if (_operand_is_captured_var(a, observed, provenance_refs)
                    and not _operand_is_liveness_flag(a, observed, provenance_refs)
                    and _is_scalar_value_literal(b)):
                return True
            if (_operand_is_captured_var(b, observed, provenance_refs)
                    and not _operand_is_liveness_flag(b, observed, provenance_refs)
                    and _is_scalar_value_literal(a)):
                return True
        return False
    if op == "gt" and _operand_is_provenance_ref(a, provenance_refs) and isinstance(b, int) \
            and not isinstance(b, bool) and b >= 0:
        return True
    if op in ("gt", "ge") and _operand_is_captured_var(a, observed, provenance_refs) \
            and _operand_is_captured_var(b, observed, provenance_refs) and a != b:
        return True
    if op == "gt":
        if (_operand_is_captured_var(a, observed, provenance_refs)
                and not _operand_is_liveness_flag(a, observed, provenance_refs)
                and _is_scalar_value_literal(b)):
            return True
        if (_operand_is_captured_var(b, observed, provenance_refs)
                and not _operand_is_liveness_flag(b, observed, provenance_refs)
                and _is_scalar_value_literal(a)):
            return True
    return False


def _collect_match_relations(pred: Any, observed: dict, provenance_refs: dict,
                             negated: bool, pos: set, neg: set) -> None:
    if not isinstance(pred, dict) or len(pred) != 1:
        return
    op, args = next(iter(pred.items()))
    if op in ("all", "any"):
        if isinstance(args, (list, tuple)):
            for c in args:
                _collect_match_relations(c, observed, provenance_refs, negated, pos, neg)
        return
    if op == "not":
        _collect_match_relations(args, observed, provenance_refs, not negated, pos, neg)
        return
    if op in _POSITIVE_MATCH_OPS and isinstance(args, (list, tuple)) and len(args) == 2:
        body, needle = args[0], args[1]
        if _operand_is_captured_var(body, observed, provenance_refs):
            (neg if negated else pos).add((body["var"], _needle_sig(needle)))


def _pd4_present(pred: Any, observed: dict, provenance_refs: dict) -> bool:
    pos: set = set()
    neg: set = set()
    _collect_match_relations(pred, observed, provenance_refs, False, pos, neg)
    for a_key, a_needle in pos:
        if not _needle_is_distinctive(a_needle):
            continue
        for b_key, b_needle in neg:
            if b_needle == a_needle and b_key != a_key:
                return True
    return False


def _fact_eligible(pred: Any, observed: dict, provenance_refs: dict) -> bool:
    """Decidable FACT-eligibility over the frozen predicate AST — BYTE-IDENTICAL to
    ``oracles._fact_eligible``: leaf ⇒ a self-sufficient PD; ``all`` ⇒ ANY child eligible OR a PD4 pair;
    ``any`` ⇒ EVERY disjunct eligible; ``not`` ⇒ False."""
    if not isinstance(pred, dict) or len(pred) != 1:
        return False
    op, args = next(iter(pred.items()))
    if op == "all":
        if not isinstance(args, (list, tuple)) or not args:
            return False
        if any(_fact_eligible(c, observed, provenance_refs) for c in args):
            return True
        return _pd4_present(pred, observed, provenance_refs)
    if op == "any":
        if not isinstance(args, (list, tuple)) or not args:
            return False
        return all(_fact_eligible(c, observed, provenance_refs) for c in args)
    if op == "not":
        return False
    return _leaf_is_self_sufficient_pd(op, args, observed, provenance_refs)


def _predicate_binds_and_const(pred: Any, observed: dict) -> tuple[bool, bool, bool]:
    """``(binds_captured, constant_true, constant_false)`` over the AST — BYTE-IDENTICAL to
    ``oracles._predicate_binds_and_const``. Raises ``ValueError`` on a malformed node (the caller funnels
    that into the non-conclusive malformed branch, as ``predicate_oracle`` does)."""
    if not isinstance(pred, dict) or len(pred) != 1:
        raise ValueError(f"predicate node must be a single-op mapping, got {pred!r}")
    op, args = next(iter(pred.items()))
    if op in ("all", "any"):
        if not isinstance(args, (list, tuple)) or not args:
            raise ValueError(f"{op!r} requires a non-empty list of sub-predicates")
        binds = False
        child_true: list[bool] = []
        child_false: list[bool] = []
        for p in args:
            b, ct, cf = _predicate_binds_and_const(p, observed)
            binds = binds or b
            child_true.append(ct)
            child_false.append(cf)
        if op == "all":
            return binds, all(child_true), any(child_false)
        return binds, any(child_true), all(child_false)
    if op == "not":
        b, ct, cf = _predicate_binds_and_const(args, observed)
        return b, cf, ct
    if op not in ("eq", "ieq", "contains", "icontains", "in", "min_len", "gt", "ge"):
        raise ValueError(f"unknown predicate op {op!r}")
    if not isinstance(args, (list, tuple)) or not args:
        raise ValueError(f"{op!r} requires operand(s)")
    has_second = len(args) > 1
    left, right = args[0], (args[1] if has_second else None)
    identical = has_second and left == right
    const_true = identical and op in _REFLEXIVE_TRUE_OPS
    const_false = identical and op in _REFLEXIVE_FALSE_OPS
    binds = _operand_binds_captured(left, observed) or (has_second and _operand_binds_captured(right, observed))
    return binds, const_true, const_false


def _reexec_fired_conclusive(pred: Any, observed: dict, provenance_refs: dict | None = None) -> tuple[bool, bool]:
    """Re-run the predicate → ``(fired, conclusive)``, mirroring ``predicate_oracle``'s decision sequence
    EXACTLY so the verdict is byte-identical over the SAME ``(predicate, observed, provenance_refs)``:

      1. a malformed predicate (the binds/const walk raises) is NON-conclusive (the oracle's malformed branch);
      2. a predicate that is NOT FACT-eligible under the structural grammar is REFUSED — non-firing,
         NON-conclusive (the S1 soundness gate: no positive discriminator adjudicates nothing SOUND);
      3. a constant-true tautology, or a predicate binding no captured value, is REFUSED (non-conclusive);
      4. otherwise the predicate is evaluated — a well-formed evaluation is conclusive; ANY evaluation error
         (malformed node / bad operand types) is ``(False, False)`` — non-conclusive, never a silent pass.

    Fail-closed by construction."""
    prefs = dict(provenance_refs or {})
    try:
        binds_captured, constant_true, _constant_false = _predicate_binds_and_const(pred, observed)
    except Exception:  # noqa: BLE001 — a malformed predicate is NON-CONCLUSIVE (predicate_oracle's malformed branch)
        return False, False
    if not _fact_eligible(pred, observed, prefs):
        return False, False
    if constant_true or not binds_captured:
        return False, False
    try:
        return bool(_reexec_eval_predicate(pred, observed)), True
    except Exception:  # noqa: BLE001 — a malformed/ill-typed kernel is NON-CONCLUSIVE, never fired-clean
        return False, False


def reexecute_posture_claims(cert: dict) -> None:
    """RE-DERIVE the verdict of every re-executable probe from its retained evidence and refuse on
    disagreement — the tamper-check behind the ``re-executable`` tier (it confirms the verdict is the
    correct function of the retained values; it does NOT prove the values are live — see the module note).
    Fail-closed (raises ``PostureError``) if, for a probe carrying a well-formed re-execution kernel:

      * it is recorded ``clean`` (a CLOSED claim) but the predicate FIRES, or the re-derivation is
        NON-CONCLUSIVE over its own retained values — the retained evidence does not support the recorded
        conclusive-clean (a forged / unsupported negative); OR
      * it is recorded ``finding`` (an OPEN claim) but the predicate does NOT fire — a forged positive.

    Probes without a kernel are left to the signature/projection checks. Same logic the standalone
    ``verify_vf`` runs with no VIGIL installed."""
    coverage = cert.get("coverage") or {}
    for probe in coverage.get("probes") or []:
        if not isinstance(probe, dict):
            continue
        kernel = _probe_reexec_evidence(probe)
        if kernel is None:
            continue
        fired, conclusive = _reexec_fired_conclusive(kernel["predicate"], dict(kernel["observed_evidence"]),
                                                     kernel.get("provenance_refs"))
        verdict = probe.get("verdict")
        if verdict == "clean" and (fired or not conclusive):
            raise PostureError(
                "re-execution REFUTED a CLOSED claim: the retained values do not support a conclusive "
                f"non-firing verdict (fired={fired}, conclusive={conclusive}; "
                f"surface={probe.get('surface')!r} param={probe.get('param')!r} "
                f"class={probe.get('class')!r}) — a forged / unsupported negative")
        if verdict == "finding" and not (fired and conclusive):
            raise PostureError(
                "re-execution REFUTED an OPEN claim: the predicate does not conclusively fire over the "
                f"probe's own retained values (surface={probe.get('surface')!r} "
                f"class={probe.get('class')!r}) — a forged positive")


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
        if not isinstance(kinds, (list, tuple)):
            raise PostureError(
                "coverage certificate is INVALID: oracle_kinds_run is not a list — refusing (fail-closed)")
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
            # re-runnable — so the whole verdict is re-derivable from the retained evidence, not just part.
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
        #                     those retained values and re-derives the verdict WITHOUT trusting the
        #                     producer's asserted verdict (tamper-evidence stronger than binding). The
        #                     values are still producer-supplied — trusting the negative reflects the live
        #                     target still needs a live re-run (see POSTURE_RESIDUAL).
        #   "binding"       — the verifier re-checks the signed coverage verdict + projection offline, but
        #                     does not re-derive it; re-firing the oracle needs VIGIL. The default when no
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


# --------------------------------------------------------------------------------------------------
# COVERAGE-INCOMPLETE disclosure (S9c). A posture certificate projects CLOSED/OPEN/UNPROVEN purely from
# the coverage cert's per-probe verdicts — the REACHED WEB surface. A run may ALSO have declared a
# non-web surface (cloud / K8s) that a fusion sensor could NOT assess (INCONCLUSIVE — a missing
# prerequisite meant NOTHING was assessed there). Left unsaid, an all-CLOSED web cert reads as a clean
# whole-target close while silent about that unassessed surface — the exact silent-CLEAN a sound-negative
# a government acts on must never make.
#
# So the builder CARRIES the unassessed surfaces (fed in as data — the framework writes them to
# ``<run_dir>/_inconclusive.json`` and a caller that holds the run dir reads them via the ONE shared
# stdlib parser) into an explicit ``coverage_incomplete`` disclosure IN the signed bytes, appends a
# NOT-ASSESSED clause to the residual naming each surface + its missing prerequisite, and downgrades the
# certificate's overall verdict away from a clean whole-target CLOSED. It NEVER fabricates a CLOSED/OPEN
# claim about the unassessed surface — it discloses it only as NOT-ASSESSED.
#
# HONEST BOUND: the disclosure is producer-supplied and lives in the signed bytes, so it is tamper-evident
# via the out-of-band fingerprint pin exactly like every other field — a forger who STRIPS it must re-sign,
# which changes the fingerprint the relying party pinned out of band and is rejected before any check. The
# verifier cannot independently RECONSTRUCT a stripped disclosure (the run-dir manifest is not shipped in
# the bundle); that is the same residual as the producer-supplied observed values (see POSTURE_RESIDUAL).

_OVERALL_OPEN = "OPEN"                       # a finding fired — exploitable dominates everything
_OVERALL_INCOMPLETE = "COVERAGE_INCOMPLETE"  # a declared surface went UNASSESSED — NOT a clean whole-target close
_OVERALL_CLOSED = "CLOSED"                   # every assessed (surface,param,class) earned a clean negative; nothing left unproven
_OVERALL_PARTIAL = "PARTIAL"                 # some CLOSED, some UNPROVEN — a bounded negative, not whole-target
_OVERALL_UNPROVEN = "UNPROVEN"              # nothing was earned CLOSED

# The disclosure clause appended to the residual so a reader of the signed bytes cannot miss it.
_INCOMPLETE_RESIDUAL_PREFIX = (
    " COVERAGE INCOMPLETE — this certificate's CLOSED claims cover ONLY the REACHED web surface; the "
    "following DECLARED surface(s) were NOT ASSESSED (a fusion sensor's prerequisite was missing, so "
    "NOTHING was looked at there) and are neither CLOSED nor OPEN, only NOT-ASSESSED: "
)


def _normalize_incomplete(coverage_incomplete: Any) -> list[dict]:
    """Coerce the caller's unassessed-surface disclosure to a DETERMINISTIC (sorted, deduped) list of
    ``{"sensor", "missing_prerequisite"}``. Accepts a list of dicts or ``(sensor, missing)`` pairs; a
    None/empty/uncoercible input yields ``[]`` (no disclosure -> byte-identical certificate)."""
    seen: set[tuple[str, str]] = set()
    for item in coverage_incomplete or ():
        try:
            if isinstance(item, dict):
                sensor = str(item.get("sensor") or "").strip()
                missing = str(item.get("missing_prerequisite") or "").strip()
            else:
                sensor, missing = item
                sensor, missing = str(sensor or "").strip(), str(missing or "").strip()
        except Exception:
            continue
        if sensor:
            seen.add((sensor, missing))
    return [{"sensor": s, "missing_prerequisite": m} for (s, m) in sorted(seen)]


def posture_overall_verdict(claims: list[dict], unassessed: list[dict]) -> str:
    """The certificate's SINGLE overall verdict — deterministic function of the projected claims + the
    coverage-incomplete disclosure, re-derivable by a verifier. An OPEN claim (a finding) dominates; else
    an unassessed declared surface DOWNGRADES a would-be whole-target CLOSED to ``COVERAGE_INCOMPLETE``;
    else CLOSED iff every assessed claim earned a clean negative with nothing left unproven, PARTIAL if some
    were unproven, UNPROVEN if none were earned."""
    if any(c.get("status") == _OPEN for c in claims):
        return _OVERALL_OPEN
    if unassessed:
        return _OVERALL_INCOMPLETE
    n_closed = sum(1 for c in claims if c.get("status") == _CLOSED)
    n_unproven = sum(1 for c in claims if c.get("status") == _UNPROVEN)
    if n_closed and not n_unproven:
        return _OVERALL_CLOSED
    if n_closed:
        return _OVERALL_PARTIAL
    return _OVERALL_UNPROVEN


def build_posture_certificate(
    coverage_cert: dict,
    *,
    target_identity: IdentityAttestation | dict,
    target_sample: dict,
    residual: str = POSTURE_RESIDUAL,
    coverage_incomplete: Any = None,
) -> dict:
    """Build the DETERMINISTIC posture certificate document (a plain dict).

    ``coverage_cert`` is a ``verify.coverage_oracle`` certificate dict (built offense-side; this
    function is pure). ``target_identity`` is the owner-signed ``IdentityAttestation`` binding the
    proof to a target; ``target_sample`` is the observed identity of the scanned target (e.g.
    ``{"host": "127.0.0.1"}``) — the verifier checks it satisfies the attestation's policy, closing
    target-swap. No wall-clock / rng: byte-identical across two scans of one app.

    ``coverage_incomplete`` (S9c, OPTIONAL) is the run's UNASSESSED declared surfaces — a list of
    ``{"sensor", "missing_prerequisite"}`` (or ``(sensor, missing)`` pairs) a fusion sensor returned
    INCONCLUSIVE for. When non-empty the certificate CARRIES them in an explicit ``coverage_incomplete``
    disclosure, appends a NOT-ASSESSED clause to the residual, and downgrades the overall verdict away
    from a clean whole-target CLOSED — WITHOUT ever fabricating a CLOSED/OPEN claim about the unassessed
    surface. None/empty (the loopback web demo, and every pre-S9c caller) => the certificate is
    BYTE-IDENTICAL to before (no disclosure block, no overall field, residual unchanged)."""
    att = _as_identity(target_identity)
    claims = project_posture_claims(coverage_cert)
    n_closed = sum(1 for c in claims if c["status"] == _CLOSED)
    n_open = sum(1 for c in claims if c["status"] == _OPEN)
    n_unproven = sum(1 for c in claims if c["status"] == _UNPROVEN)
    # How much of the negative is RE-EXECUTABLE (verdict re-derivable from the retained values) vs binding-only.
    n_reexecutable = sum(1 for c in claims if c["status"] == _CLOSED and c.get("verification") == "re-executable")
    n_binding = sum(1 for c in claims if c["status"] == _CLOSED and c.get("verification") != "re-executable")
    summary = {
        "n_closed": n_closed, "n_open": n_open, "n_unproven": n_unproven,
        "n_closed_re_executable": n_reexecutable, "n_closed_binding_only": n_binding,
    }
    cert = {
        "schema": POSTURE_SCHEMA,
        "target_identity": att.model_dump(mode="json"),
        "target_sample": {str(k): str(v) for k, v in dict(target_sample).items()},
        "coverage": coverage_cert,
        "denominator": coverage_cert.get("denominator", {}),
        "scope": coverage_cert.get("scope", ""),
        "posture_claims": claims,
        "summary": summary,
        "residual": residual,
    }
    # S9c: a coverage-incomplete run carries the unassessed surfaces + a downgraded overall verdict + a
    # residual clause naming them. Only when there IS an unassessed surface, so the web-only demo and every
    # pre-S9c caller stay byte-identical. NEVER a fabricated CLOSED/OPEN — the surface is disclosed NOT-ASSESSED.
    unassessed = _normalize_incomplete(coverage_incomplete)
    if unassessed:
        summary["overall"] = posture_overall_verdict(claims, unassessed)
        cert["coverage_incomplete"] = {"incomplete": True, "unassessed_surfaces": unassessed}
        named = "; ".join(f"{u['sensor']} (missing prerequisite: {u['missing_prerequisite'] or 'unknown'})"
                          for u in unassessed)
        cert["residual"] = residual + _INCOMPLETE_RESIDUAL_PREFIX + named + "."
    return cert


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


def _verify_coverage_disclosure(cert: dict) -> None:
    """S9c fail-closed: if the certificate declares an UNASSESSED surface (``coverage_incomplete``), its
    overall verdict MUST equal the re-derived downgrade and MUST NOT read as a clean whole-target CLOSED —
    so a producer cannot ship a coverage-incomplete cert that still presents a clean close. A cert with NO
    disclosure block is a bounded/clean cert and is left exactly as pre-S9c (byte-identical, nothing to
    enforce)."""
    disc = cert.get("coverage_incomplete")
    if not isinstance(disc, dict) or not disc.get("incomplete"):
        return
    unassessed = _normalize_incomplete(disc.get("unassessed_surfaces"))
    if not unassessed:
        raise PostureError("coverage_incomplete is set but names no unassessed surface — refusing")
    expected = posture_overall_verdict(cert.get("posture_claims") or [], unassessed)
    got = (cert.get("summary") or {}).get("overall")
    if got != expected:
        raise PostureError(f"posture overall verdict {got!r} disagrees with the coverage-incomplete "
                           f"projection {expected!r} — refusing a clean reading over an unassessed surface")
    if got == _OVERALL_CLOSED:
        raise PostureError("a coverage-incomplete certificate must not read CLOSED (whole-target) — refusing")


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

    # 2a. S9c coverage-incomplete disclosure: a cert that declares an UNASSESSED surface must carry the
    #     downgraded overall verdict — it cannot present a clean whole-target close over what it never assessed.
    _verify_coverage_disclosure(cert)

    # 2b. RE-EXECUTION (the re-executable tier): re-run the oracle over every re-executable probe's
    #     retained values and refuse a forged negative/positive (re-derives the verdict, not a liveness proof); the standalone
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
