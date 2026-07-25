"""S5b — the boundary-safe verification VIEW over the offense spine segments.

`vigil verify` needs to attest the offense side's signed records, but the LOCKED two-env boundary forbids a
single process from co-loading the sovereign store and the offense engine (that would trip
``assert_no_offense``). So this verifier is PUBLIC-KEY-ONLY and inert-bytes-only: it reads a spine file and
an owner-signed delegation certificate (both inert data) plus PUBLIC keys, and holds no private key and no
owner authority. It can therefore run offense-side, or in any neutral process that pins the owner's public
key — the boundary is about co-loading code and holding the owner PRIVATE key, neither of which this does.

The owner tie is established by CONSUMING an owner-signed ``OFFENSE_SPINE_ROLE`` delegation — this is the
FIRST live consumer of that role (S5a only made the key delegatable). The delegation is elegant as the trust
bootstrap: it is owner-signed AND its authorizers publish the exact offense-spine public key the owner
blessed, so the verifier derives the trusted key from the delegation itself (no access to the sealed key file
needed) and then checks the spine's chain + signatures verify under that owner-delegated key. Without a
delegation it can still do an integrity-only audit against a pinned pubkey, but reports ``owner_rooted=False``
honestly. Per-segment verdicts; the CRUCIBLE blackboard chain is a DB-projection this byte-reader cannot
verify and is reported as such, never claimed verified.
"""
from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Optional

from vigil_core.delegation import OFFENSE_SPINE_ROLE, DelegationCert, DelegationError, verify_delegation

from .spine_vigilcore import VigilCoreSpine

# Verdict statuses. Only "failed" is an integrity FAILURE (non-zero exit); "absent"/"unverifiable" are
# honest non-failures (nothing to attest, or out of a byte-reader's reach).
VERIFIED = "verified"
FAILED = "failed"
ABSENT = "absent"
UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class SegmentVerdict:
    """One segment's verification result. ``owner_rooted`` is True ONLY when the owner tie was
    cryptographically established (an owner-signed delegation was consumed and the segment verified under the
    owner-delegated key) — never merely because the bytes are internally consistent."""
    segment: str
    status: str          # VERIFIED | FAILED | ABSENT | UNVERIFIABLE
    owner_rooted: bool
    detail: str


def _count_records(spine_path: str) -> int:
    """Count the COMPLETE (newline-terminated) records on a spine file, mirroring the binder's torn-tail
    tolerance (the final split element — a partial or empty tail — is dropped). Total: unreadable → 0."""
    try:
        with open(spine_path, encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        return 0
    return 0 if not content else sum(1 for chunk in content.split("\n")[:-1] if chunk)


def _verify_spine_file(spine_path: str, spine_pubkey: str) -> tuple[bool, int]:
    """Read-only chain+signature audit of a spine file under ``spine_pubkey``. Never mutates the file (the
    ``readonly`` binder skips torn-tail repair). Returns ``(verified, record_count)``. Total — an unreadable
    file / bad key → ``(False, 0)``."""
    try:
        binder = VigilCoreSpine(SimpleNamespace(public_key_b64=spine_pubkey, private_key_b64=""),
                                spine_path, readonly=True)
        ok = binder.verify()
        return ok, (_count_records(spine_path) if ok else 0)
    except Exception:  # noqa: BLE001 — an audit that cannot complete cannot attest integrity → not verified
        return False, 0


def verify_offense_spine(
    *, spine_path: str, owner_pubkey: Optional[str] = None, delegation: Optional[DelegationCert] = None,
    now: Optional[int] = None, scope: str = "*", spine_pubkey: Optional[str] = None,
) -> SegmentVerdict:
    """Verify one offense spine file. Owner-rooted iff an owner-signed ``OFFENSE_SPINE_ROLE`` delegation is
    supplied, is valid, and the spine verifies under a key it authorizes.

    Precedence: (1) if ``delegation`` + ``owner_pubkey`` are given, derive the trusted offense-spine key(s)
    from the owner-signed delegation and require the spine to verify under one → owner_rooted=True; a bad
    delegation or a spine that verifies under no delegated key is ``FAILED``. (2) else if ``spine_pubkey`` is
    pinned, do an integrity-only audit → ``owner_rooted=False`` (honest: no owner tie was proven). (3) else
    the offense-spine key is unrecoverable to this reader → ``UNVERIFIABLE``. An absent file → ``ABSENT``.

    ``now`` (unix seconds) MUST be supplied from a trusted clock when a delegation is checked — its expiry is
    only as sound as that clock, and an ABSENT ``now`` fails CLOSED (never mapped to 0 = valid-forever).

    Scope caveat (honest): the offense-spine key is a SINGLE stable key across all engagements, so ``scope``
    gates WHICH delegation is accepted but the resulting owner tie is NOT per-engagement object-bound — a
    delegation scoped to engagement A verifies engagement B's spine too (both are the same global key). The
    scope is a delegation-selection bound, not a cryptographic per-engagement partition."""
    if not os.path.exists(spine_path):
        return SegmentVerdict("offense-spine", ABSENT, False, f"no spine file at {spine_path}")

    if delegation is not None and owner_pubkey:
        if now is None:
            # Fail CLOSED: without a trusted clock we cannot check the delegation's expiry — and a delegation
            # is a bearer cert whose not_after is its ONLY revocation substitute. Never establish an owner
            # tie fail-open (mapping a missing clock to 0 would make every expiry `0 > not_after` = never).
            return SegmentVerdict("offense-spine", FAILED, False,
                                  "no trusted clock (now) supplied — cannot check the delegation's expiry; "
                                  "refusing to establish an owner tie fail-open")
        try:
            root = verify_delegation(delegation, trusted_owner_pubkey=owner_pubkey, now=int(now),
                                     role=OFFENSE_SPINE_ROLE, scope=scope)
        except DelegationError as exc:
            return SegmentVerdict("offense-spine", FAILED, False,
                                  f"offense-spine delegation invalid — cannot establish owner tie: {exc}")
        # The offense spine is SINGLE-SIGNER (one key signs every line), so a threshold>1 delegation can
        # NEVER be satisfied by the spine. Accepting "any one authorizer" under an m-of-n root would silently
        # downgrade the owner's m-of-n intent to 1-of-n (one compromised owner-blessed key forging the tie).
        # Require threshold==1 (1-of-n over multiple authorizers is the intended shape — key rotation).
        if root.threshold != 1:
            return SegmentVerdict("offense-spine", FAILED, False,
                                  f"offense-spine delegation threshold={root.threshold}, but the spine is "
                                  f"single-signer (a threshold>1 delegation is unsatisfiable) — refusing")
        for auth in root.authorizers:
            ok, count = _verify_spine_file(spine_path, auth.public_key_b64)
            if ok:
                return SegmentVerdict("offense-spine", VERIFIED, True,
                                      f"{count} record(s); chain + signatures verify under owner-delegated "
                                      f"offense-spine key {auth.key_id!r} (owner-rooted via OFFENSE_SPINE_ROLE)")
        return SegmentVerdict("offense-spine", FAILED, False,
                              "spine does not verify under ANY owner-delegated offense-spine key "
                              "(tampered/forged, or signed by an un-delegated key)")

    if spine_pubkey:
        ok, count = _verify_spine_file(spine_path, spine_pubkey)
        return SegmentVerdict(
            "offense-spine", VERIFIED if ok else FAILED, False,
            f"{count} record(s); chain + signatures verify (INTEGRITY ONLY; no owner delegation supplied → "
            f"NOT owner-rooted)" if ok else "chain/signature audit failed under the pinned key")

    if delegation is not None:   # a delegation was passed but no owner pubkey was pinned to check it against
        detail = ("a delegation was supplied but no owner pubkey was pinned (--owner-pubkey) to verify it "
                  "against — cannot establish the owner tie, and no pinned spine pubkey for an integrity check")
    else:
        detail = ("no owner-signed offense-spine delegation and no pinned pubkey — the offense-spine key is "
                  "unrecoverable to this reader, so the spine cannot be verified")
    return SegmentVerdict("offense-spine", UNVERIFIABLE, False, detail)


def verify_offense_ledger(base_dir: str) -> SegmentVerdict:
    """Verify the usage-attestation ledger (segment #4) via its operator key. Offline-verifiable (the
    operator pubkey is recoverable), but the operator key is NOT owner-delegated today, so
    ``owner_rooted=False`` — the same honest treatment the registry gives it (S7 closes the tie)."""
    ledger_path = os.path.join(base_dir, "usage-ledger.jsonl")
    if not os.path.exists(ledger_path):
        return SegmentVerdict("offense-usage-ledger", ABSENT, False, f"no ledger at {ledger_path}")
    try:
        from ..attestation.identity import operator_key_resolver
        from ..attestation.ledger import read_ledger, verify_ledger
        records = read_ledger(ledger_path)
        resolver = operator_key_resolver(keypair_path=os.path.join(base_dir, "operator.key"))
        v = verify_ledger(records, resolve_key=resolver)
    except Exception as exc:  # noqa: BLE001 — an audit that cannot complete cannot attest → FAILED
        return SegmentVerdict("offense-usage-ledger", FAILED, False, f"ledger audit error: {exc}")
    ok = bool(getattr(v, "ok", False))
    return SegmentVerdict("offense-usage-ledger", VERIFIED if ok else FAILED, False,
                          f"{len(records)} records, operator-key chain "
                          f"{'verified (not owner-delegated — S7)' if ok else 'FAILED: ' + str(getattr(v, 'reason', ''))}")


def verify_offense_home(
    base_dir: str, *, owner_pubkey: Optional[str] = None, delegation: Optional[DelegationCert] = None,
    now: Optional[int] = None, scope: str = "*", slug: Optional[str] = None,
) -> list[SegmentVerdict]:
    """The per-segment offense verification view for one engagement base_dir. Verifies every ``{slug}.spine``
    (or just ``{slug}.spine`` when ``slug`` is given) + the usage ledger, and reports the CRUCIBLE blackboard
    chain honestly as unverifiable-by-a-byte-reader. Does NOT verify the sovereign spine — that is a separate
    process/venv (`vigil sigil verify`); co-loading it here would breach the two-env boundary."""
    verdicts: list[SegmentVerdict] = []
    spine_paths = ([os.path.join(base_dir, f"{slug}.spine")] if slug
                   else sorted(glob.glob(os.path.join(base_dir, "*.spine"))))
    if not spine_paths:
        verdicts.append(SegmentVerdict("offense-spine", ABSENT, False, f"no *.spine under {base_dir}"))
    for sp in spine_paths:
        verdicts.append(verify_offense_spine(spine_path=sp, owner_pubkey=owner_pubkey, delegation=delegation,
                                             now=now, scope=scope))
    verdicts.append(verify_offense_ledger(base_dir))
    verdicts.append(SegmentVerdict(
        "crucible-blackboard-chain", UNVERIFIABLE, False,
        "a DB-projection (built from the blackboard), not a file — a public-key-only byte-reader cannot "
        "verify it; it needs the offense DB + framework. Reported honestly, never claimed verified."))
    return verdicts
