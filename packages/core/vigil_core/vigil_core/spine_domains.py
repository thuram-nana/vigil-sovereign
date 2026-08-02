"""The one registry of VIGIL's signed spine/log domains (unification S5).

VIGIL persists integrity state in several heterogeneous append-only chains split across the two-process
boundary: the SOVEREIGN personal record (owner-key-signed head + anti-rollback floor), the OFFENSE
finding anchor-1 (m-of-n governance signature, owner-delegated per S4), the OFFENSE engagement spine
(checkpoint + exec records + detection certificates), the OFFENSE usage-attestation ledger (operator key),
and the CRUCIBLE blackboard chain (a DB-projection). Before S5 there was no single place that said, for
each of these, WHO legitimately signs it and whether its trust chains to the owner. This module is that
place — pure DATA (no crypto, no I/O), importable in BOTH envs, so a verifier can ROUTE each segment to the
right trust root without hard-coding the map five times.

It is deliberately honest about the limits the S5 understand-phase found:
  * The offense spine and usage ledger sign a raw ``vigil_core`` chain-link hash (no domain-tag prefix);
    the sovereign head/floor/witness/delegation/transparency/destruction segments each use a DISTINCT
    domain-separation prefix (see :data:`DOMAIN_TAGS`) so a signature under one can never replay as another.
  * ``owner_rooted`` states whether a verify path EXISTS TODAY that chains a segment's trust back to the
    owner — the owner key DIRECTLY, or a CONSUMER of an owner-signed delegation (a live ``verify_delegation``
    call). Delegate-ABILITY alone is NOT enough: the offense-spine key is delegatable (``OFFENSE_SPINE_ROLE``)
    but nothing consumes such a delegation yet, so it is ``owner_rooted=False`` today — the identical honest
    treatment the usage ledger gets (its stable operator key is not owner-delegated either). Only
    ``offense-finding-anchor1`` is ``owner_rooted=True`` among the offense segments, because a real consumer
    (``finding_receiver.from_delegation`` → ``verify_delegation``) exists. Closing the spine/ledger ties is
    S6/S7's job; this module does not pretend the tie is enforced before it is.
  * ``file_backed`` states whether the segment is persisted as inert bytes a public-key-only reader can
    verify offline. As of T3 the CRUCIBLE blackboard chain HAS a real persist + offline-verify path: a live
    engage run **that posted events to the blackboard** (e.g. a deployed fireteam wave) persists it as a
    governance-signed ``spine-head.json`` + a ``spine-chain.json`` entry-digest chain under the run dir, and
    ``spine_verify.verify_blackboard_chain`` verifies those inert bytes offline — DB-free and framework-free —
    under an owner-signed ``OFFENSE_GOVERNANCE_ROLE`` delegation, so a byte-reader CAN verify it.
    HONEST LIMIT: the live OODA loop does not itself post to the blackboard (only the fireteam coordination
    path, reached after an approved escalation, does), so a typical OODA-only run persists NO artifacts and the
    segment verdict is honestly ``UNVERIFIABLE`` (never a fake "verified"). Making every engage run populate +
    persist the chain is the disclosed follow-up (T3b); this flag marks the segment's *nature* (it has a real
    file-backed offline-verify path), consistent with the other ``file_backed`` segments that also persist only
    when they hold content.
"""
from __future__ import annotations

from dataclasses import dataclass

# The delegation ROLE strings are owned by vigil_core.delegation (one source of truth); re-exported here
# so the registry and the delegation verifier can never drift to two spellings of the same role.
from .delegation import OFFENSE_GOVERNANCE_ROLE, OFFENSE_SPINE_ROLE

# --- signer roles -----------------------------------------------------------------------------------
# The sovereign 1-of-1 root: the owner key. Signs the spine head (anchor-2), the durable floor, the
# witness roster, owner delegations, transparency checkpoints, and governance events.
OWNER_ROLE = "owner"
# OFFENSE_GOVERNANCE_ROLE ("offense-governance"): the anchor-1 m-of-n finding signer, owner-delegated (S4).
# OFFENSE_SPINE_ROLE ("offense-spine"): the stable offense engagement-spine identity, owner-delegated (S5) —
# one key signing the checkpoint spine, the executor ExecRecords, and the detection PCF certificates.
# The offense usage-attestation (WHO/WHEN/WHAT) ledger signer. Stable + offline-verifiable, but NOT
# owner-delegated today (S7 closes the owner tie).
OFFENSE_OPERATOR_ROLE = "offense-operator"

_ALL_ROLES = frozenset(
    {OWNER_ROLE, OFFENSE_GOVERNANCE_ROLE, OFFENSE_SPINE_ROLE, OFFENSE_OPERATOR_ROLE}
)

# --- trust domains ----------------------------------------------------------------------------------
SOVEREIGN = "sovereign"   # rooted in the owner key, held sovereign-side
OFFENSE = "offense"       # rooted in an owner-DELEGATED (or, for the ledger, a stable offense) key
_ALL_TRUST_DOMAINS = frozenset({SOVEREIGN, OFFENSE})

# --- domain-separation signing prefixes (confirmed in-tree; informational for auditors) -------------
# Each distinct b"...\x00" prefix means a signature computed under one purpose can never verify under
# another. Segments NOT listed here have NO prefix: the offense spine signs bare sha256 hex (its record-hash
# and entry-hash sigs share that shape and are kept apart by sha256 input-independence, NOT by domain — a
# per-purpose tag on each is the natural v2 hardening); the usage ledger signs its own record-hash chain;
# governor authn signs bare canonical_json (a JSON object, disjoint in shape from a hex string).
DOMAIN_TAGS: dict[str, bytes] = {
    "evidence": b"crucible-evidence-v1\x00",                    # evidence certs + signed chain heads
    "floor": b"sigil-floor-v1\x00",                             # sovereign durable anti-rollback floor
    "witness-roster": b"sigil-witness-roster-v1\x00",          # sovereign witness roster
    "delegation": b"vigil-delegation-v1\x00",                  # S4 owner delegation
    "transparency": b"vigil-transparency-checkpoint-v1\x00",   # transparency checkpoint witness
    "destruction": b"vigil-destruction-authorization-v1\x00",  # m-of-n destruction authorization
    "identity": b"vigil-identity-attestation-v1\x00",          # VF owner-attested target identity policy
    "capability": b"vigil-capability-v1\x00",                  # VF re-verification capability (base)
    "attenuation": b"vigil-capability-attenuation-v1\x00",     # VF biscuit-style narrow-only attenuation
    "wielder-pop": b"vigil-capability-wielder-pop-v1\x00",     # VF wielder proof-of-possession over a challenge
}


@dataclass(frozen=True)
class SpineDomain:
    """One signed spine/log segment: who signs it, whether its trust reaches the owner, and whether a
    public-key-only reader can verify it from persisted bytes."""
    name: str            # stable segment id
    trust_domain: str    # SOVEREIGN | OFFENSE
    signer_role: str     # OWNER_ROLE | OFFENSE_GOVERNANCE_ROLE | OFFENSE_SPINE_ROLE | OFFENSE_OPERATOR_ROLE
    owner_rooted: bool   # is there a verify path TODAY that chains this segment's trust to the owner (the
                         # owner key directly, or a CONSUMER of an owner-signed delegation)? Delegate-ABILITY
                         # alone is NOT enough — the tie must be enforced by real code, not merely possible.
    file_backed: bool    # persisted as inert bytes a public-key-only reader can verify offline?
    location: str        # human hint where it lives
    note: str
    owner_tie_consumer: str = ""   # the SPECIFIC code that consumes the owner tie for THIS segment (owner
                                   # key or a verify_delegation call), e.g. "finding_receiver.from_delegation".
                                   # Empty ⟺ no consumer. verify_registration() enforces owner_rooted == bool
                                   # of this per SEGMENT — so a False claim can't ride in on a sibling's role.


DOMAINS: tuple[SpineDomain, ...] = (
    SpineDomain(
        name="sovereign-spine",
        trust_domain=SOVEREIGN, signer_role=OWNER_ROLE, owner_rooted=True, file_backed=True,
        location="apps/sigil/sigil/spine/store.py (+ owner-signed head.json = anchor-2, + floor.py)",
        note="The sovereign personal record; the owner-key head is the trust anchor. Verified by `sigil verify`.",
        owner_tie_consumer="apps/sigil/sigil/spine/checkpoint.py:verify_checkpoint (owner key directly)",
    ),
    SpineDomain(
        name="offense-finding-anchor1",
        trust_domain=OFFENSE, signer_role=OFFENSE_GOVERNANCE_ROLE, owner_rooted=True, file_backed=True,
        location="integration/.../inert_finding.py cert -> apps/sigil/.../inbound/finding_receiver.py",
        note="Anchor-1 m-of-n governance signature over a finding; owner-delegated per S4. The consumer "
             "FUNCTION (from_delegation) is production code; S7b adds the MANUAL owner-tie ceremony "
             "(`vigil identity` -> `sigil delegate-offense`) that mints+publishes the governance delegation; "
             "wiring the receiver to auto-load it in a daemon remains out of scope.",
        owner_tie_consumer="apps/sigil/sigil/inbound/finding_receiver.py:from_delegation -> "
                           "verify_delegation(OFFENSE_GOVERNANCE_ROLE)",
    ),
    SpineDomain(
        name="offense-spine",
        trust_domain=OFFENSE, signer_role=OFFENSE_SPINE_ROLE, owner_rooted=True, file_backed=True,
        location="integration/.../live/spine_vigilcore.py ({slug}.spine) + executor ExecRecords + detection PCF certs",
        note="One stable offense key signs the checkpoint spine, exec records, and detection certs. S5a made "
             "it STABLE + owner-DELEGATABLE (OFFENSE_SPINE_ROLE); S5b's `vigil verify` is the live CONSUMER — it "
             "derives the trusted offense-spine key from an owner-signed delegation and checks the spine under "
             "it. S7b adds the MANUAL owner-tie ceremony (`vigil identity` -> `sigil delegate-offense` -> "
             "`vigil verify --delegation`); genuinely-automatic (daemon) provisioning remains out of scope.",
        owner_tie_consumer="integration/.../live/spine_verify.py:verify_offense_spine -> "
                           "verify_delegation(OFFENSE_SPINE_ROLE)",
    ),
    SpineDomain(
        name="offense-usage-ledger",
        trust_domain=OFFENSE, signer_role=OFFENSE_OPERATOR_ROLE, owner_rooted=False, file_backed=True,
        location="integration/.../attestation/ledger.py (usage-ledger.jsonl)",
        note="WHO/WHEN/WHAT attestation; stable operator key, offline-verifiable, but NOT owner-delegated "
             "today (its own record_hash/prev_hash chain, not the vigil_core ChainEntry construction). S7.",
    ),
    SpineDomain(
        name="continuous-attestation-log",
        trust_domain=OFFENSE, signer_role=OFFENSE_GOVERNANCE_ROLE, owner_rooted=False, file_backed=True,
        location="integration/.../remediation/attestation_log.py (ticks.jsonl + head.json + highwater.json)",
        note="VF-1b Continuous Attestation Log: a monotonic series of signed four-state remediation re-proof "
             "ticks (prove_driver certs), hash-chained via vigil_core.build_chain and anchored by a "
             "governance m-of-n sign_head, with a durable vigil_core.highwater floor (entry_count PRIMARY + "
             "last_seq) refusing a rolled-back/truncated series. File-backed + offline-verifiable via "
             "verify_log, whose trust_root + signer_pubkeys are CALLER-PINNED out-of-band (like the proof "
             "bundle) — there is no owner-delegation consumer that derives them, so it is honestly NOT "
             "owner-rooted today. The durable floor is a LOCAL unsigned file: a same-host attacker rewriting "
             "log+head+floor together defeats the LOCAL verify; the out-of-band witness (VF-1c) closes that.",
    ),
    SpineDomain(
        name="crucible-blackboard-chain",
        trust_domain=OFFENSE, signer_role=OFFENSE_GOVERNANCE_ROLE, owner_rooted=True, file_backed=True,
        location="persisted at end of a live engage run to <base_dir>/spine-head.json + spine-chain.json "
                 "(live/wiring.py:_persist_blackboard_chain, over framework spine_chain.build_spine_chain); "
                 "offline-verified by live/spine_verify.py:verify_blackboard_chain",
        note="T3: a live engage run THAT POSTED EVENTS TO THE BLACKBOARD (e.g. a deployed fireteam wave) SIGNS "
             "+ WRITES the blackboard chain as inert bytes — a governance-signed SignedChainHead "
             "(spine-head.json, binding engagement_slug) + the ChainEntry digests (spine-chain.json), so the "
             "head re-binds WITHOUT the offense DB. verify_blackboard_chain reads ONLY those bytes + PUBLIC keys "
             "(vigil_core.chain.verify_head; no DB, no framework) and DERIVES the governance TrustRoot from an "
             "owner-signed OFFENSE_GOVERNANCE_ROLE delegation — the live owner-tie consumer — so a public-key-"
             "only reader CAN verify it and its trust IS owner-rooted. The head is m-of-n governance-signed with "
             "the SAME key anchor-1 uses; one owner delegation (`vigil identity` -> `sigil delegate-offense`) "
             "covers both. HONEST LIMIT: the live OODA loop does not itself post to the blackboard, so a typical "
             "OODA-only run persists NO artifacts and the verdict is honestly UNVERIFIABLE (making every run "
             "populate+persist is the disclosed T3b follow-up). Fail-closed: absent artifacts / no governance "
             "delegation → honestly UNVERIFIABLE, never a fake verified.",
        owner_tie_consumer="integration/.../live/spine_verify.py:verify_blackboard_chain -> "
                           "verify_delegation(OFFENSE_GOVERNANCE_ROLE)",
    ),
)

_BY_NAME: dict[str, SpineDomain] = {d.name: d for d in DOMAINS}


def domain(name: str) -> SpineDomain:
    """The :class:`SpineDomain` for ``name``. Raises ``KeyError`` on an unregistered segment (fail-closed:
    a verifier must not invent a trust routing for a segment the registry does not know)."""
    return _BY_NAME[name]


def signer_role(name: str) -> str:
    """The signer role required for segment ``name``."""
    return _BY_NAME[name].signer_role


def owner_rooted_segments() -> tuple[str, ...]:
    """Segment names whose trust chains to the owner (directly or via an owner-signed delegation)."""
    return tuple(d.name for d in DOMAINS if d.owner_rooted)


def offline_verifiable_segments() -> tuple[str, ...]:
    """Segment names a public-key-only reader can verify from persisted bytes (file-backed)."""
    return tuple(d.name for d in DOMAINS if d.file_backed)


def verify_registration() -> None:
    """Self-check the registry is internally consistent (defensive, mirrors the S3 detection registry):
    every segment names a KNOWN role and a KNOWN trust domain, names are unique, and — the honesty guard —
    a segment is ``owner_rooted=True`` IF AND ONLY IF it NAMES a specific owner-tie consumer
    (``owner_tie_consumer``). The check is per-SEGMENT, not per-role: two segments can share a role while
    only one has a consumer, so binding the boolean to each segment's OWN named consumer is what stops the
    registry claiming an owner tie the deterministic layer does not enforce (a role-granular check let a
    consumer-less sibling ride in on another segment's role). Raises ``ValueError`` on any violation."""
    names = [d.name for d in DOMAINS]
    if len(set(names)) != len(names):
        raise ValueError("spine-domain registry has duplicate segment names")
    for d in DOMAINS:
        if d.signer_role not in _ALL_ROLES:
            raise ValueError(f"segment {d.name!r} names unknown signer role {d.signer_role!r}")
        if d.trust_domain not in _ALL_TRUST_DOMAINS:
            raise ValueError(f"segment {d.name!r} names unknown trust domain {d.trust_domain!r}")
        # Honesty guard, per segment: owner_rooted ⟺ a named owner-tie consumer. owner_rooted=True with no
        # named consumer overclaims an unenforced tie; a named consumer with owner_rooted=False silently
        # under-claims (and would let a real consumer go unroutable). Either mismatch is refused.
        has_consumer = bool(d.owner_tie_consumer.strip())
        if d.owner_rooted != has_consumer:
            raise ValueError(
                f"segment {d.name!r}: owner_rooted={d.owner_rooted} but owner_tie_consumer="
                f"{d.owner_tie_consumer!r} — owner_rooted must hold IFF a specific consumer is named "
                f"(overclaim/underclaim refused)"
            )
