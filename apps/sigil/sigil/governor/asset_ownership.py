"""Customer ASSET-OWNERSHIP PROOF — the self-serve, infrastructure-bound basis for a later owner-signed
target authority (Slice G0; the billing != testing LINCHPIN).

WHAT THIS SLICE IS: a per-org, owner-signed record that a customer has PROVEN CONTROL of a specific
external host by publishing a VIGIL-issued, unguessable token in that host's own infrastructure — either a
DNS TXT record under a dedicated ``_vigil-challenge.<host>`` name, or an HTTP ``/.well-known`` file served
by that host. Proving control of the DNS zone or the web root of ``apme.cm`` is the legitimate, classic
basis for authorizing a security assessment of ``apme.cm`` — it is control of the asset's OWN
infrastructure, not a claim derived from a login or a payment.

WHY IT MATTERS (the doctrine, stated once, enforced everywhere): a paid account may USE the product; it may
be TESTED against an asset only by a separate, owner-signed, infrastructure-bound authority (billing-authz
!= testing-authz; see ``orgs.OrgRegistry.admit``). This module builds the NECESSARY half of that authority:
the proof of ownership. It is deliberately NOT SUFFICIENT — recording a proof here mints NO engagement
authority and grants NO testing capability. The owner key (or an explicit owner-signed policy) still SIGNS
the ``EngagementAuthority`` separately (``ui.target_authorization``); ``offense_authority`` / ``target_add``
stay at the owner key. A fully paid, verified-owner customer STILL cannot launch an assessment until that
separate authority exists — a tested, end-to-end invariant of Slice G0.

TRUST BOUNDARY (critical): the network observation (the DNS TXT values / the ``/.well-known`` body) is
produced by TRUSTED SOVEREIGN CODE that fetches the customer's published token — NEVER supplied by the
customer. ``verify_and_record`` runs the deterministic verdict ITSELF over that observation and records an
owner-signed proof ONLY when the verdict passes; a proof is never recorded without the verdict firing. The
fetch that produces the observation (and its injection) is a provisioner/edge concern layered on top; this
module stays network-free and so independently testable (the "prove over data the real target produced"
doctrine, with the I/O injected).

ASYMMETRIC AUTHENTICATION (mirrors ``governor.accounts`` / ``governor.orgs``):
  * issue_challenge / record a verified proof = the DANGEROUS direction -> honored only if OWNER-SIGNED
    (``verify_signed``) AND its ``issued_at`` STRICTLY exceeds the per-(org_id, host) high-water.
  * revoke a proof = the SAFE direction -> ``state="revoked"`` honored even UNSIGNED, fixed ``issued_at``
    of 0.0 (a replayed revoke merely re-revokes; gating the fail-safe direction would make it fail OPEN).

ANTI-REPLAY: per-(org_id, host) last-writer-wins high-water (the SAME resurrection guard accounts/orgs
carry). A captured owner-signed active proof cannot resurrect a revoked proof (its ``issued_at`` <=
high-water -> ignored). Independently, every proof carries an OWNER-SIGNED ``expires_at`` so a lapsed proof
cannot be silently extended by a config change — re-proving requires a fresh challenge + a fresh
observation. OWNER-KEY SUCCESSION is honored exactly as ``accounts._fold`` / ``orgs._fold_*`` (each active
grant authenticated under the owner pubkey valid AT ITS SEQ).

FATAL-2: SOVEREIGN-side, ``assert_no_offense()`` at import; imports only the shared ``vigil_core`` (via
``reuse``) + the sovereign governor siblings (``authn`` / ``identity`` / ``key_history``) + the categorical
``vigil_core.hard_guardrail`` floor. No ``framework``/``strix`` import.

DEFERRED (explicitly, to the Slice G snapshot bump): the hard-prune SNAPSHOT SEED. This fold is a
genesis-scan fold (correct over the full live window); it does not yet seed per-(org_id, host) state from
``spine.snapshot.SnapshotState`` the way ``orgs._fold_*`` does, so a hard prune below a revoked proof is not
yet protected by a stranding tripwire. The owner-signed ``expires_at`` bounds the blast radius of any such
replay to the proof's remaining validity. The snapshot-leaf rows + tripwire land with the G schema bump
(``_MAX_SNAPSHOT_SCHEMA`` -> v3), keyed to merge order.
"""
from __future__ import annotations

import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Iterable, Optional, Union

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core.hard_guardrail import HardBlockError, assert_not_hard_blocked  # noqa: E402

from . import key_history as _kh  # noqa: E402  (owner-key succession resolver, mirrors accounts/orgs)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

# Dedicated payload signals under the generic enforced ``kind="event"`` record (mirrors orgs' signals), so a
# NEW kind need not be registered with the write-path guard — the signal disambiguates the fold.
CHALLENGE_SIGNAL = "governor.asset_ownership_challenge"
PROOF_SIGNAL = "governor.asset_ownership_proof"

# The two self-serve proof methods. A DNS TXT record under a dedicated name (proves control of the zone),
# or a file served at a dedicated ``/.well-known`` path (proves control of the web root). Both publish the
# SAME namespaced marker, so the verdict is one comparison.
METHOD_DNS_TXT = "dns-txt"
METHOD_WELL_KNOWN = "well-known"
_METHODS = frozenset({METHOD_DNS_TXT, METHOD_WELL_KNOWN})

# A conservative default proof validity window: ownership can change hands (a domain is sold, a zone is
# transferred), so a proof EXPIRES and must be re-proven. 90 days mirrors common ACME/verification cadences;
# the owner signs the concrete ``expires_at``, so lengthening it is a deliberate owner act, never a config.
_DEFAULT_PROOF_TTL_S: float = 90.0 * 24.0 * 3600.0

# A valid DNS hostname, mirroring ``ui.target_authorization._HOSTNAME_RE`` (kept as a small local copy — a
# governor-layer module must not import the ui layer; a lockstep test asserts the two literals match). 1-63
# char labels (alnum + hyphen, no leading/trailing hyphen), dot-separated, total <= 253. No scheme, path,
# port, wildcard, ".." or whitespace: the host is a single literal the offense scope matcher can match
# exactly, and the DNS-OOB / well-known placement names are unambiguous.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# The marker prefix published in DNS / well-known. Namespacing it means a pre-existing, unrelated TXT record
# (or an attacker-reflected page) cannot accidentally satisfy the verdict — the whole trimmed value must be
# exactly ``vigil-site-verification=<token>``.
_MARKER_PREFIX = "vigil-site-verification="

# org_id / tenant charset — IDENTICAL to orgs._TENANT_RE (replicated, not imported, to keep this module
# independently importable; a lockstep test asserts the literals match). An org_id is one safe path
# component (alphanumeric start then [A-Za-z0-9._-], max 64).
_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# The owner-signed authenticated CORE of each record. ``issued_at`` MUST be inside it (else a captured grant
# could be re-stamped fresh past the high-water without breaking the signature). For a challenge, the token
# is inside it so an owner-signed challenge cannot be re-tokened. For a proof, org_id/host/method/token hash
# /verified_at/expires_at are inside it so a proof for (orgA, apme.cm) can never be re-aimed at another
# org/host, nor have its method/window rewritten.
_CHALLENGE_CORE = ("signal", "org_id", "host", "token", "state", "issued_at")
_PROOF_CORE = ("signal", "org_id", "host", "method", "token_sha256", "verified_at", "expires_at",
               "state", "issued_at")


# ---------------------------------------------------------------------------------------------------
# Placement instructions — deterministic functions of (host, token). The edge hands these to the customer
# verbatim ("publish exactly this"), and the verdict checks for exactly this.
# ---------------------------------------------------------------------------------------------------

def expected_marker(token: str) -> str:
    """The exact string the customer publishes (and the verdict demands), for BOTH methods."""
    return _MARKER_PREFIX + str(token or "")


def dns_txt_name(host: str) -> str:
    """The dedicated DNS name the TXT record lives under: ``_vigil-challenge.<host>``."""
    return "_vigil-challenge." + str(host or "")


def well_known_path() -> str:
    """The dedicated well-known path (a constant); the body must be exactly ``expected_marker(token)``."""
    return "/.well-known/vigil-site-verification.txt"


def well_known_url(host: str) -> str:
    """The https URL the trusted fetcher GETs for the well-known method."""
    return "https://" + str(host or "") + well_known_path()


# ---------------------------------------------------------------------------------------------------
# The deterministic verdict (PURE — no network, no state). Exposed for independent testing; the registry
# calls it inside ``verify_and_record`` so a proof is never recorded without it firing.
# ---------------------------------------------------------------------------------------------------

def _marker_matches(token: str, observed_value: str) -> bool:
    """Constant-time comparison of one observed value (trimmed) against the expected marker. ``compare_digest``
    is defense-in-depth (the token is high-entropy and public once published); it also tolerates arbitrary
    observed bytes without a timing side channel."""
    expected = expected_marker(token)
    return hmac.compare_digest(str(observed_value or "").strip(), expected)


def observation_proves(method: str, token: str, observed: "Union[str, Iterable[str]]") -> bool:
    """``True`` iff ``observed`` proves possession of ``token`` under ``method``. FAIL-CLOSED on any unknown
    method, empty token, or malformed observation (never raises).

      * ``dns-txt``: ``observed`` is the iterable of TXT string values seen at ``dns_txt_name(host)`` — ANY
        value, trimmed, must equal the marker.
      * ``well-known``: ``observed`` is the response BODY string — it, trimmed, must equal the marker
        exactly (an exact match, so a page that merely REFLECTS attacker input or wraps the token in HTML
        does not satisfy it)."""
    tok = str(token or "")
    if not tok or method not in _METHODS:
        return False
    if method == METHOD_DNS_TXT:
        if isinstance(observed, (str, bytes)):
            return False  # a single string is not a TXT value set — require the iterable (fail-closed)
        try:
            values = list(observed)
        except TypeError:
            return False
        return any(isinstance(v, str) and _marker_matches(tok, v) for v in values)
    # METHOD_WELL_KNOWN
    if not isinstance(observed, str):
        return False
    return _marker_matches(tok, observed)


# ---------------------------------------------------------------------------------------------------
# Validation (fail-closed at binding time — a clean ValueError now, never a silent bad record later).
# ---------------------------------------------------------------------------------------------------

def _check_org_id(org_id: str) -> str:
    oid = str(org_id or "").strip()
    if not _TENANT_RE.fullmatch(oid):
        raise ValueError("org_id must be a valid tenant id: an alphanumeric start then [A-Za-z0-9._-], "
                         "max 64 chars, no separators / traversal (org_id == CRUCIBLE_TENANT)")
    return oid


def _check_host(host: str) -> str:
    """A single literal DNS hostname, not categorically hard-blocked, not an IP literal. Fail-closed.

    An IP literal is refused outright: ownership is proven over a DNS NAME (a bare IP has no zone to place a
    TXT record in and a well-known on an IP is not a meaningful ownership signal), and refusing it here also
    keeps the private/internal-literal egress concerns out of the ownership flow entirely. The categorical
    .gov/.mil/.edu/.int (and *.gov.cm-class) floor is enforced HERE too (not only at mint) so a customer
    cannot even BEGIN to prove ownership of a protected domain — fail-closed and honest at the first step."""
    h = str(host or "").strip().lower()
    if not h:
        raise ValueError("a host is required")
    if "://" in h or "/" in h or ":" in h or " " in h:
        raise ValueError("give a bare hostname (e.g. apme.cm), not a URL, path, or host:port")
    if not _HOSTNAME_RE.match(h):
        raise ValueError(f"{h!r} is not a valid hostname")
    import ipaddress as _ip
    try:
        _ip.ip_address(h)
    except ValueError:
        pass
    else:
        raise ValueError(f"{h!r} is an IP literal — ownership is proven over a DNS hostname, not a bare IP")
    try:
        assert_not_hard_blocked(h)
    except HardBlockError as e:
        raise ValueError(f"{h!r} is on the categorical safety floor (.gov/.mil/.edu/.int and *.gov.cm-class): "
                         f"{e}. It cannot be registered for ownership proof.") from None
    return h


def _check_method(method: str) -> str:
    m = str(method or "").strip()
    if m not in _METHODS:
        raise ValueError(f"method must be one of {sorted(_METHODS)}")
    return m


# ---------------------------------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class OwnershipChallenge:
    org_id: str
    host: str
    token: str           # the unguessable nonce the customer must publish (the marker is derived from it)
    issued_at: float     # owner-set anti-replay high-water for this (org_id, host) challenge

    @property
    def marker(self) -> str:
        return expected_marker(self.token)

    @property
    def dns_name(self) -> str:
        return dns_txt_name(self.host)

    @property
    def well_known_url(self) -> str:
        return well_known_url(self.host)


@dataclass(frozen=True)
class OwnershipProof:
    org_id: str
    host: str
    method: str          # METHOD_DNS_TXT | METHOD_WELL_KNOWN
    token_sha256: str    # hash of the token that was verified (ties the proof to a real challenge+observation)
    verified_at: float   # when the verdict fired
    expires_at: float    # owner-signed expiry — re-proving required after this
    issued_at: float     # owner-set anti-replay high-water for this (org_id, host) proof
    state: str           # "active" | "revoked"


# ---------------------------------------------------------------------------------------------------
# The registry — owner-signed challenge + proof grants on the spine. Construction mirrors OrgRegistry /
# AccountsRegistry (owner signing key + trusted pubkey default to the persisted owner identity; tests inject).
# ---------------------------------------------------------------------------------------------------

class AssetOwnershipRegistry:
    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ----------------------------------------------------------------------------
    def issue_challenge(self, org_id: str, host: str, *, issued_at: float,
                        token: Optional[str] = None) -> OwnershipChallenge:
        """Owner-sign a fresh ownership CHALLENGE for (org_id, host) — the DANGEROUS direction, honored only
        if it verifies AND is FRESH (``issued_at`` strictly exceeds the per-(org_id, host) challenge
        high-water). Returns the challenge (token + derived placement instructions) for the edge to hand the
        customer. A new challenge supersedes the prior one (LWW): the customer re-publishes the new token.
        ``token`` is injectable for tests; in production it defaults to a fresh 256-bit URL-safe secret.

        A challenge grants NOTHING on its own — it is only the token store the later verdict checks against."""
        if self.owner_key is None:
            raise ValueError("issuing an ownership challenge requires the owner signing key")
        oid, h = _check_org_id(org_id), _check_host(host)
        tok = str(token) if token is not None else secrets.token_urlsafe(32)
        if not tok or any(ord(c) < 0x20 or ord(c) == 0x7f for c in tok):
            raise ValueError("challenge token must be a non-empty control-char-free string")
        core = {"signal": CHALLENGE_SIGNAL, "org_id": oid, "host": h, "token": tok,
                "state": "active", "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"ownership challenge issued for {h} (org {oid})"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return OwnershipChallenge(org_id=oid, host=h, token=tok, issued_at=float(issued_at))

    def verify_and_record(self, org_id: str, host: str, *, method: str,
                          observed: "Union[str, Iterable[str]]", now: float,
                          ttl_seconds: float = _DEFAULT_PROOF_TTL_S) -> OwnershipProof:
        """Run the deterministic verdict over a TRUSTED observation and, ONLY on success, owner-sign an
        ownership PROOF for (org_id, host). Fail-closed — raises ``ValueError`` on an invalid org/host/method,
        a missing/stale challenge, a non-positive ttl, or a verdict that does not fire; a proof is NEVER
        recorded without the verdict passing.

        ``observed`` is the data the TRUSTED SOVEREIGN FETCHER saw at the customer's published location (the
        TXT value set, or the well-known body) — never customer-supplied. The verdict is checked against the
        CURRENT active challenge's token for (org_id, host); a verification with no outstanding challenge, or
        against a superseded token, refuses. On success the proof carries an owner-signed ``expires_at`` =
        ``now + ttl_seconds`` and the SHA-256 of the verified token (tying the proof to this challenge)."""
        if self.owner_key is None:
            raise ValueError("recording an ownership proof requires the owner signing key")
        oid, h, m = _check_org_id(org_id), _check_host(host), _check_method(method)
        ttl = float(ttl_seconds)
        if not (ttl > 0.0):
            raise ValueError("ttl_seconds must be positive")
        ch = self.challenge(oid, h)
        if ch is None:
            raise ValueError(f"no outstanding ownership challenge for {h} (org {oid}) — issue one first")
        if not observation_proves(m, ch.token, observed):
            raise ValueError(f"the published token was not found for {h} via {m} "
                             f"(publish exactly {expected_marker(ch.token)!r})")
        from ..reuse import sha256_hex
        verified_at = float(now)
        core = {"signal": PROOF_SIGNAL, "org_id": oid, "host": h, "method": m,
                "token_sha256": sha256_hex(ch.token.encode("utf-8")),
                "verified_at": verified_at, "expires_at": verified_at + ttl,
                "state": "active", "issued_at": verified_at}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"ownership of {h} PROVEN by org {oid} via {m} (owner-signed)"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return OwnershipProof(org_id=oid, host=h, method=m, token_sha256=core["token_sha256"],
                              verified_at=verified_at, expires_at=verified_at + ttl,
                              issued_at=verified_at, state="active")

    def revoke_proof(self, org_id: str, host: str) -> int:
        """Revoke an ownership proof — the SAFE direction (honored even unsigned, fixed ``issued_at`` 0.0).
        Idempotent + replay-safe: a replayed revoke merely re-revokes. Used on offboarding / tenant
        decommission or when ownership is known to have lapsed."""
        oid, h = _check_org_id(org_id), _check_host(host)
        core = {"signal": PROOF_SIGNAL, "org_id": oid, "host": h, "method": "", "token_sha256": "",
                "verified_at": 0.0, "expires_at": 0.0, "state": "revoked", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"ownership proof for {h} (org {oid}) REVOKED (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware folds; genesis scan — see DEFERRED snapshot note) ---------
    def _fold(self, signal: str, core_fields):
        """Fold the spine into {(org_id, host): record_dict} for the given signal whose latest state is
        active, authenticating each ``active`` grant under the owner pubkey valid AT ITS SEQ and refusing any
        stale/replayed re-append via the per-(org_id, host) high-water. Revokes (safe direction) are honored
        regardless of signature. Returns the raw winning core dicts (callers build the dataclass)."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: dict[tuple, str] = {}
        issued: dict[tuple, float] = {}
        rows: dict[tuple, dict] = {}
        for r in self.store.iter_records():
            p = r.payload
            if not isinstance(p, dict) or p.get("signal") != signal:
                continue
            org_id = p.get("org_id")
            host = p.get("host")
            if not isinstance(org_id, str) or not org_id or not isinstance(host, str) or not host:
                continue
            key = (org_id, host)
            rec_state = p.get("state")
            if rec_state == "revoked":
                state[key] = "revoked"                 # honor ANY revoke (even unsigned) — safe direction
            elif rec_state == "active":
                if not verify_signed(p, core_fields, resolver.at(r.seq)):
                    continue                           # fail-closed: unsigned/forged/wrong-epoch-key grant
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(key, NO_HIGHWATER):
                    continue                           # REPLAY / stale re-append of an already-honored grant
                issued[key] = at
                state[key] = "active"
                rows[key] = dict(p)
        return {k: row for k, row in rows.items() if state.get(k) == "active"}

    def challenge(self, org_id: str, host: str) -> Optional[OwnershipChallenge]:
        """The current active challenge for (org_id, host), or None (fail-closed). The latest owner-signed,
        non-superseded token."""
        if not isinstance(org_id, str) or not org_id or not isinstance(host, str) or not host:
            return None
        row = self._fold(CHALLENGE_SIGNAL, _CHALLENGE_CORE).get((org_id, host))
        if row is None:
            return None
        return OwnershipChallenge(org_id=org_id, host=host, token=str(row.get("token") or ""),
                                  issued_at=as_issued_at(row.get("issued_at")))

    def proof(self, org_id: str, host: str) -> Optional[OwnershipProof]:
        """The current active proof record for (org_id, host), or None (fail-closed). Does NOT apply the
        expiry filter — use ``has_current_proof`` for the launch/mint gate (which is time-aware)."""
        if not isinstance(org_id, str) or not org_id or not isinstance(host, str) or not host:
            return None
        row = self._fold(PROOF_SIGNAL, _PROOF_CORE).get((org_id, host))
        if row is None:
            return None
        return OwnershipProof(
            org_id=org_id, host=host, method=str(row.get("method") or ""),
            token_sha256=str(row.get("token_sha256") or ""),
            verified_at=float(as_issued_at(row.get("verified_at"))),
            expires_at=float(as_issued_at(row.get("expires_at"))),
            issued_at=as_issued_at(row.get("issued_at")), state="active")

    def has_current_proof(self, org_id: str, host: str, *, now: float) -> bool:
        """The gate the owner-signed target-authority mint (and the later launch gate) calls: True iff
        (org_id, host) has an ACTIVE, UNEXPIRED ownership proof at ``now``. DEFAULT-DENY — no proof, a
        revoked proof, a proof for a DIFFERENT org, or an expired proof all refuse. This answers ONLY the
        ownership question; it is NECESSARY, never SUFFICIENT, for a test (the owner still signs the
        authority separately)."""
        p = self.proof(org_id, host)
        if p is None:
            return False
        return float(now) < p.expires_at

    def proven_hosts(self, org_id: str, *, now: float) -> list[str]:
        """Every host (org_id) currently holds an active, unexpired ownership proof for, in host order."""
        if not isinstance(org_id, str) or not org_id:
            return []
        out = []
        for (o, h), row in self._fold(PROOF_SIGNAL, _PROOF_CORE).items():
            if o == org_id and float(now) < float(as_issued_at(row.get("expires_at"))):
                out.append(h)
        return sorted(out)
