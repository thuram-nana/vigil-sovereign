"""
veracity.witness_quorum — an OPTIONAL, DEFAULT-OFF, DEMOTE-ONLY N-of-M oracle-witness
quorum admission conjunct for operator-designated "critical" bug classes.

This generalizes the existing non-circular corroboration rule — an EXPLOITABLE label needs
>= 2 INDEPENDENT corroborating oracle kinds (``engage._distinct_confirming_kinds``, used as an
advisory reward signal) — into a configurable ADMISSION conjunct that runs at the mint choke
and the grounding firewall. Where the reward signal only re-ranked, this can WITHHOLD: for a
configured critical class it admits a FACT only when N-or-more INDEPENDENT oracle-witness kinds
RE-FIRE over the retained evidence.

Three properties make it sound rather than just stricter:

  * INDEPENDENT means a DISTINCT :class:`~framework.v2.verify.models.OracleKind`, re-derived by
    RE-EXECUTING the deterministic oracle over the retained ``oracle_context`` — never a claimed
    corroboration set the producer carried. A critic, an RL re-rank, a reflection vote or any LLM
    signal is structurally excluded: those are not oracle signals, so they never appear in the
    re-executed ``VerificationResult.signals`` this module counts. Only a fired oracle witnesses.

  * DEMOTE-ONLY and MONOTONE. The conjunct runs AFTER the deterministic oracle has already
    confirmed, the class is already oracle-mapped, and provenance is already reproduced — i.e. on
    a claim the existing layer would mint a FACT. Below quorum it WITHHOLDS (the claim is returned
    as a LEAD / UNGROUNDED). It can only turn a would-be FACT into a non-FACT; it NEVER promotes a
    LEAD/INCONCLUSIVE into a FACT, and it NEVER runs on the non-confirmed branch. Oracle authority
    is untouched: the oracle remains the sole mint authority, and this only ever subtracts.

  * DEFAULT-OFF and OPERATOR-SET. With no configuration the conjunct is inapplicable to every
    class, so admission is BYTE-IDENTICAL to today (the mint path adds no certificate field and
    takes no new branch). The policy is read from an operator-written config the model cannot set
    (``CRUCIBLE_WITNESS_QUORUM_CONFIG`` → a JSON document), never from model output.

Offline re-verification HONORS a recorded quorum: a certificate minted under a quorum of N records
``witness_quorum_required`` + the ``witness_kinds`` that satisfied it, and ``verify_certificate`` /
``reverify_finding`` re-derive the witnesses over the retained context and refuse the certificate
when fewer than N distinct kinds re-fire or a recorded witness no longer re-fires (a tampered
witness). Pure and deterministic throughout: no wallclock, no global RNG, no network.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

# The env var naming the operator's JSON policy document. Unset (the default) ⇒ the quorum is OFF
# for every class ⇒ admission is byte-identical to today. The value is a filesystem path the operator
# controls; the model never writes it. Kept here as the single source of truth for the config source.
_CONFIG_ENV = "CRUCIBLE_WITNESS_QUORUM_CONFIG"


def _normalize(bug_class: str) -> str:
    """Canonicalise a bug-class token the same way the verifier does, so a critical-class entry and
    the queried class match through aliases. Import is function-local to keep this module import-clean
    (no heavy framework import at module scope → no cycle with the firewall that imports it)."""
    from ..verify.verifier import normalize_bug_class
    return normalize_bug_class(bug_class or "")


@dataclass(frozen=True)
class WitnessQuorumConfig:
    """An operator-set admission policy. Frozen (a policy a run cannot mutate mid-flight).

    * ``enabled`` — the master switch. ``False`` (the default) makes the conjunct inapplicable to
      every class, so the admit path is byte-identical to today.
    * ``quorum_n`` — the number N of DISTINCT independent oracle-witness kinds a critical-class FACT
      must re-fire (>= 1; a quorum of 1 is the pre-existing single-oracle bar, i.e. a no-op demotion).
    * ``critical_classes`` — the normalized bug classes the quorum applies to. A class not listed is
      admitted exactly as today, even when ``enabled``.
    """

    enabled: bool = False
    quorum_n: int = 2
    critical_classes: frozenset[str] = field(default_factory=frozenset)

    def applies_to(self, bug_class: str) -> bool:
        """True iff the quorum must be enforced for ``bug_class`` — the switch is on AND the class is
        designated critical. The sole predicate every caller keys on; when it is False the caller's
        behaviour is unchanged (byte-identical)."""
        return bool(self.enabled) and _normalize(bug_class) in self.critical_classes

    @classmethod
    def from_dict(cls, doc: "dict[str, Any] | None") -> "WitnessQuorumConfig":
        """Build a config from a parsed JSON document. A missing/false ``enabled``, a missing/empty
        ``critical_classes``, or any malformed field yields a DISABLED config (fail-safe to OFF — a
        broken policy must never make admission accidentally stricter in an unintended way, and must
        never be read as ON)."""
        if not isinstance(doc, dict) or not doc.get("enabled"):
            return DISABLED
        try:
            n = int(doc.get("quorum_n", 2))
            raw = doc.get("critical_classes") or []
            classes = frozenset(_normalize(str(c)) for c in raw if str(c).strip())
        except (TypeError, ValueError):
            return DISABLED
        if n < 1 or not classes:
            return DISABLED
        return cls(enabled=True, quorum_n=n, critical_classes=classes)


# The canonical OFF config. A sentinel every default path falls back to so "disabled" is one shared
# object, and `evaluate(..., config=DISABLED)` is the explicit byte-identity baseline the tests pin.
DISABLED = WitnessQuorumConfig(enabled=False, quorum_n=2, critical_classes=frozenset())


@lru_cache(maxsize=8)
def _load_cached(path: str) -> WitnessQuorumConfig:
    """Read + parse one policy path, memoised (the policy is static for a process). A missing or
    unreadable or unparseable file is DISABLED — never an error, never a silent ON."""
    if not path:
        return DISABLED
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return DISABLED
    return WitnessQuorumConfig.from_dict(doc)


def load_quorum_config() -> WitnessQuorumConfig:
    """The ambient operator policy: the JSON document named by ``CRUCIBLE_WITNESS_QUORUM_CONFIG``.
    Unset ⇒ :data:`DISABLED` (the default). This is what the mint choke and the firewall consult when
    a caller passes no explicit config, so a single operator file reaches every admission + render
    path, while leaving every default (no file) byte-identical."""
    return _load_cached((os.environ.get(_CONFIG_ENV) or "").strip())


def resolve(config: "WitnessQuorumConfig | None") -> WitnessQuorumConfig:
    """A caller-supplied config wins; ``None`` falls back to the ambient operator policy. Centralised
    so every wiring point resolves the policy identically."""
    return config if config is not None else load_quorum_config()


def distinct_witness_kinds(
    oracle_context: "dict[str, Any] | None",
    *,
    bug_class: str,
    verifier: Any = None,
) -> "tuple[str, ...]":
    """The DISTINCT independent oracle-witness kinds that RE-FIRE over the retained evidence, as the
    sorted tuple of their canonical ``OracleKind.value`` strings.

    Re-executes the deterministic oracle over ``oracle_context`` under ``bug_class`` and counts the
    distinct kinds whose signal FIRED at or above the verifier's high-confidence threshold — exactly
    the signals that would confirm a finding. Because a critic / RL / reflection / LLM signal is not
    an oracle signal, it never enters ``VerificationResult.signals`` and so can never be a witness.

    Pure and deterministic (the oracle layer is). A context that cannot be adjudicated (malformed /
    unparseable) yields no witnesses, so the quorum fails closed (it can only withhold, never admit)."""
    if not isinstance(oracle_context, dict) or not oracle_context:
        return ()
    from ..verify.confirmation import adjudicate_finding
    from ..verify.verifier import OracleVerifier
    ver = verifier or OracleVerifier()
    try:
        result = adjudicate_finding({"bug_class": bug_class}, oracle_context, ver)
    except Exception:  # noqa: BLE001 — an un-adjudicable context establishes no witness (fail-closed)
        return ()
    kinds = {
        (getattr(s.kind, "value", None) or str(s.kind))
        for s in result.signals
        if s.fired and s.confidence >= ver.high_confidence
    }
    return tuple(sorted(kinds))


@dataclass(frozen=True)
class QuorumOutcome:
    """The verdict of the conjunct over one claim's retained evidence.

    * ``applicable`` — whether the quorum was enforced at all (switch on AND class critical). When
      False the caller must behave exactly as today; ``ok`` is True and ``required`` is 0.
    * ``required`` — N (0 when inapplicable).
    * ``got`` — how many DISTINCT independent witness kinds re-fired.
    * ``kinds`` — those witness kinds (sorted), recorded into the certificate when it mints.
    * ``ok`` — ``got >= required`` (always True when inapplicable). The ONLY thing a caller may act
      on, and it can only ever WITHHOLD a mint — never cause one.
    """

    applicable: bool
    required: int
    got: int
    kinds: "tuple[str, ...]"
    ok: bool
    reason: str


def evaluate(
    oracle_context: "dict[str, Any] | None",
    *,
    bug_class: str,
    config: "WitnessQuorumConfig | None",
    verifier: Any = None,
) -> QuorumOutcome:
    """Apply the quorum conjunct. When it does not apply (disabled, or a non-critical class) the
    outcome is inapplicable + ``ok=True`` so the caller is byte-identical to today. When it applies,
    re-derive the witnesses and require N-or-more distinct kinds.

    This NEVER promotes: it is only ever consulted on a claim the deterministic layer has already
    decided is a FACT, and it returns ``ok=False`` to WITHHOLD when the evidence is corroborated by
    fewer than N independent oracle kinds."""
    cfg = resolve(config)
    if not cfg.applies_to(bug_class):
        return QuorumOutcome(applicable=False, required=0, got=0, kinds=(), ok=True,
                             reason="witness quorum not enforced for this class (disabled or non-critical)")
    kinds = distinct_witness_kinds(oracle_context, bug_class=bug_class, verifier=verifier)
    got = len(kinds)
    required = cfg.quorum_n
    ok = got >= required
    if ok:
        reason = (f"witness quorum met: {got} independent oracle kind(s) re-fired "
                  f"({', '.join(kinds)}) >= required {required}")
    else:
        reason = (f"witness quorum NOT met: only {got} independent oracle kind(s) re-fired "
                  f"({', '.join(kinds) or 'none'}) < required {required} for critical class "
                  f"{_normalize(bug_class)!r} — withheld as a LEAD, not a signed FACT")
    return QuorumOutcome(applicable=True, required=required, got=got, kinds=kinds, ok=ok, reason=reason)


def witnesses_reconfirm(
    oracle_context: "dict[str, Any] | None",
    *,
    bug_class: str,
    required: int,
    expected_kinds: "list[str] | tuple[str, ...] | None",
    verifier: Any = None,
) -> "tuple[bool, tuple[str, ...], str]":
    """Offline re-check of a RECORDED quorum (``required`` N + the ``expected_kinds`` a certificate /
    finding bound at mint). Re-derives the witnesses over the retained context and holds iff at least
    N distinct kinds re-fire AND every recorded witness kind still re-fires (a recorded witness whose
    evidence was altered so it no longer re-fires is rejected). Returns ``(ok, got_kinds, note)``.

    Used by ``verify_certificate`` and ``reverify_finding`` so a cert that required N witnesses
    re-checks all N offline — the demote-only guarantee carried into independent re-execution."""
    got = distinct_witness_kinds(oracle_context, bug_class=bug_class, verifier=verifier)
    want = tuple(sorted({str(k) for k in (expected_kinds or [])}))
    enough = len(got) >= max(1, int(required))
    all_present = set(want) <= set(got)
    ok = enough and all_present
    if ok:
        note = f"witness quorum re-checked: {len(got)} kind(s) re-fired ({', '.join(got)}) >= {required}"
    elif not enough:
        note = (f"witness quorum FAILED offline: only {len(got)} kind(s) re-fired "
                f"({', '.join(got) or 'none'}) < required {required}")
    else:
        missing = tuple(sorted(set(want) - set(got)))
        note = (f"witness quorum FAILED offline: recorded witness kind(s) {', '.join(missing)} no "
                f"longer re-fire over the retained evidence (tampered witness)")
    return ok, got, note
