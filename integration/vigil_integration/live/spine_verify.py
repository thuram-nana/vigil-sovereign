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
import json
import os
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Optional

from vigil_core import ChainEntry, SignedChainHead
from vigil_core.chain import verify_head
from vigil_core.delegation import (
    OFFENSE_GOVERNANCE_ROLE,
    OFFENSE_SPINE_ROLE,
    DelegationCert,
    DelegationError,
    verify_delegation,
)

from .spine_vigilcore import VigilCoreSpine

# The persisted, inert blackboard-chain artifact names (T3). Written at the end of a live engage run by
# live.wiring._persist_blackboard_chain and DISCOVERED under the run/base dir by the dossier
# (framework.v2.report.dossier._find_spine) — one head + its entry-digest chain, so a public-key-only reader
# re-binds the governance-signed head without the offense DB.
BLACKBOARD_HEAD_FILE = "spine-head.json"
BLACKBOARD_CHAIN_FILE = "spine-chain.json"

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


def verify_blackboard_chain(
    *, head_path: str, chain_path: str, owner_pubkey: Optional[str] = None,
    delegation: Optional[DelegationCert] = None, now: Optional[int] = None, scope: str = "*",
    slug: Optional[str] = None,
) -> SegmentVerdict:
    """T3 — offline-verify the PERSISTED CRUCIBLE blackboard chain (segment #6). PUBLIC-KEYS-ONLY, DB-FREE,
    FRAMEWORK-FREE: it reads ONLY the persisted ``spine-head.json`` (a :class:`SignedChainHead`) + the
    persisted ``spine-chain.json`` (the :class:`ChainEntry` digests), derives the offense-governance TrustRoot
    from an OWNER-SIGNED ``OFFENSE_GOVERNANCE_ROLE`` delegation, and checks the persisted head over the
    persisted entries with :func:`vigil_core.chain.verify_head` — no blackboard, no ``framework``. This is the
    live consumer that makes the segment ``owner_rooted`` (it derives the trusted governance key from the
    owner delegation, exactly as ``finding_receiver.from_delegation`` does for anchor-1).

    Owner-rooted is True ONLY when the owner tie is cryptographically established — an owner-signed governance
    delegation was consumed AND the persisted head verifies (chain integrity + head↔entries binding + m-of-n
    signature) under the owner-delegated governance root. Fail-closed on EVERY axis:

      * artifacts absent → ``UNVERIFIABLE`` (honest: nothing to verify offline, never a fake pass);
      * no delegation / no owner pubkey with artifacts present → ``UNVERIFIABLE`` (the head's governance signer
        pubkey is recoverable ONLY via the owner delegation — there is no pinned-pubkey integrity fallback for
        this segment, unlike the offense spine — so without it the owner tie cannot be established);
      * absent ``now`` → ``FAILED`` (a bearer delegation's expiry cannot be checked without a trusted clock —
        never mapped to 0 = valid-forever);
      * malformed persisted bytes, a bad/wrong-owner/wrong-role/out-of-scope/expired delegation, a
        head↔entries mismatch (a tampered entry / tampered head / truncated chain), or a signature that does
        not meet the delegated threshold → ``FAILED``.

    ``slug`` (when given) additionally binds the persisted head's ``engagement_slug`` — refusing a
    cross-engagement head replay (defense in depth alongside the head signature, which already covers the
    slug). Unlike the single-signer offense spine, the blackboard head is a genuine m-of-n governance head, so
    NO threshold==1 restriction applies here — the delegated root's threshold is honoured as-is."""
    seg = "crucible-blackboard-chain"
    have_head = os.path.exists(head_path)
    have_chain = os.path.exists(chain_path)
    if not (have_head and have_chain):
        return SegmentVerdict(
            seg, UNVERIFIABLE, False,
            f"no persisted blackboard chain ({BLACKBOARD_HEAD_FILE} + {BLACKBOARD_CHAIN_FILE}) under the run "
            f"dir — nothing for a byte-reader to verify offline")

    if delegation is None or not owner_pubkey:
        # Present-but-unrootable: the persisted head names its signer only by key_id, not by pubkey, so the
        # trusted governance key is recoverable ONLY from the owner delegation. Without it we CANNOT establish
        # the owner tie — and there is no honest integrity-only fallback (we have no pinned governance pubkey).
        return SegmentVerdict(
            seg, UNVERIFIABLE, False,
            "persisted blackboard chain present but no owner-signed OFFENSE_GOVERNANCE_ROLE delegation + owner "
            "pubkey supplied — cannot establish the owner tie (no pinned-pubkey integrity fallback here)")

    if now is None:
        return SegmentVerdict(
            seg, FAILED, False,
            "no trusted clock (now) supplied — cannot check the governance delegation's expiry; refusing to "
            "establish an owner tie fail-open")

    # 1. load the inert persisted bytes (fail-closed on any malformed JSON — unparseable bytes cannot attest).
    try:
        with open(head_path, encoding="utf-8") as fh:
            head = SignedChainHead.model_validate_json(fh.read())
        with open(chain_path, encoding="utf-8") as fh:
            raw = json.loads(fh.read())
        if not isinstance(raw, list):
            raise ValueError("chain file is not a JSON array of entries")
        entries = [ChainEntry.model_validate(e) for e in raw]
    except Exception as exc:  # noqa: BLE001 — malformed persisted bytes → not verifiable → FAILED
        return SegmentVerdict(seg, FAILED, False,
                              f"persisted blackboard chain is unreadable/malformed: {exc}")

    # 2. derive the offense-governance TrustRoot from the OWNER-signed delegation (fail-closed on every axis:
    #    wrong owner / wrong role / out of scope / expired / unsigned / malformed / bad threshold).
    try:
        root = verify_delegation(delegation, trusted_owner_pubkey=owner_pubkey, now=int(now),
                                 role=OFFENSE_GOVERNANCE_ROLE, scope=scope)
    except DelegationError as exc:
        return SegmentVerdict(seg, FAILED, False,
                              f"offense-governance delegation invalid — cannot establish owner tie: {exc}")

    # 3. slug binding — refuse a head anchored to a DIFFERENT engagement (no cross-engagement head replay).
    if slug is not None and head.engagement_slug != slug:
        return SegmentVerdict(
            seg, FAILED, False,
            f"head is anchored to engagement {head.engagement_slug!r}, not {slug!r} — refusing a "
            f"cross-engagement head")

    # 4. verify the PERSISTED head over the PERSISTED entries under the owner-delegated governance root:
    #    chain links recompute, head_hash/last_seq/entry_count bind to the entries, and the signatures meet
    #    the delegated m-of-n threshold. Any post-signing tamper (an edited entry digest, a truncated chain, a
    #    rewritten head) or a wrong/under-quorum signer fails here.
    ok, reason = verify_head(head, entries, root)
    if not ok:
        return SegmentVerdict(seg, FAILED, False, f"blackboard chain does not verify: {reason}")
    return SegmentVerdict(
        seg, VERIFIED, True,
        f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}; chain + governance-signed head verify "
        f"under an owner-delegated offense-governance key (owner-rooted via OFFENSE_GOVERNANCE_ROLE)")


def verify_offense_home(
    base_dir: str, *, owner_pubkey: Optional[str] = None, delegation: Optional[DelegationCert] = None,
    now: Optional[int] = None, scope: str = "*", slug: Optional[str] = None,
    governance_delegation: Optional[DelegationCert] = None,
) -> list[SegmentVerdict]:
    """The per-segment offense verification view for one engagement base_dir. Verifies every ``{slug}.spine``
    (or just ``{slug}.spine`` when ``slug`` is given) + the usage ledger + the PERSISTED CRUCIBLE blackboard
    chain (T3, when its ``spine-head.json``/``spine-chain.json`` artifacts are present under ``base_dir`` and a
    ``governance_delegation`` is supplied → owner-rooted; else honestly UNVERIFIABLE). Does NOT verify the
    sovereign spine — that is a separate process/venv (`vigil sigil verify`); co-loading it here would breach
    the two-env boundary.

    ``delegation`` establishes the offense-SPINE owner tie (OFFENSE_SPINE_ROLE); ``governance_delegation`` is
    the SEPARATE owner-signed OFFENSE_GOVERNANCE_ROLE delegation the blackboard head is rooted under (its head
    is m-of-n governance-signed, a DIFFERENT key from the single spine key — so it needs its own delegation,
    never the spine one)."""
    verdicts: list[SegmentVerdict] = []
    spine_paths = ([os.path.join(base_dir, f"{slug}.spine")] if slug
                   else sorted(glob.glob(os.path.join(base_dir, "*.spine"))))
    if not spine_paths:
        verdicts.append(SegmentVerdict("offense-spine", ABSENT, False, f"no *.spine under {base_dir}"))
    for sp in spine_paths:
        verdicts.append(verify_offense_spine(spine_path=sp, owner_pubkey=owner_pubkey, delegation=delegation,
                                             now=now, scope=scope))
    verdicts.append(verify_offense_ledger(base_dir))
    verdicts.append(verify_blackboard_chain(
        head_path=os.path.join(base_dir, BLACKBOARD_HEAD_FILE),
        chain_path=os.path.join(base_dir, BLACKBOARD_CHAIN_FILE),
        owner_pubkey=owner_pubkey, delegation=governance_delegation, now=now, scope=scope, slug=slug))
    return verdicts
