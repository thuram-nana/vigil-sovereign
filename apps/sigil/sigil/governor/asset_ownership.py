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

HARD-PRUNE SNAPSHOT SEED (G0 close-out): the proof fold ``_fold_proofs`` mirrors ``orgs._fold_*`` EXACTLY,
including the snapshot seed — it seeds the per-(org_id, host) state / anti-replay high-water / row from the
committed ``spine.snapshot.SnapshotState`` (v3) and then folds the LIVE window only, so an active proof whose
only grant was hard-pruned SURVIVES (its high-water is never reset) rather than re-opening the LWW
replay-resurrection the G0 red-pen flagged. The owner-signed ``expires_at`` still bounds the blast radius of
any replay to the proof's remaining validity. (The CHALLENGE fold is a plain genesis scan — a pruned,
ephemeral challenge is simply re-requested.)
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
from ..spine.snapshot import SnapshotState  # noqa: E402  (hard-prune seed for the proof fold; mirrors orgs)
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0d — the verified incremental fold)
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402

# Dedicated payload signals under the generic enforced ``kind="event"`` record (mirrors orgs' signals), so a
# NEW kind need not be registered with the write-path guard — the signal disambiguates the fold.
CHALLENGE_SIGNAL = "governor.asset_ownership_challenge"
PROOF_SIGNAL = "governor.asset_ownership_proof"

# The two self-serve proof methods. A DNS TXT record under a dedicated name (proves control of the zone),
# or a file served at a dedicated ``/.well-known`` path (proves control of the web root). Both publish the
# SAME namespaced marker, so the verdict is one comparison.
METHOD_DNS_TXT = "dns-txt"
METHOD_WELL_KNOWN = "well-known"
METHOD_META_TAG = "meta-tag"
_METHODS = frozenset({METHOD_DNS_TXT, METHOD_WELL_KNOWN, METHOD_META_TAG})

# The HTML meta-tag method (the standard Search-Console shape): the customer places
# ``<meta name="vigil-site-verification" content="<token>">`` in their homepage <head>. The ``name``
# attribute namespaces it (a pre-existing meta tag cannot collide — it would need this exact name AND the
# 256-bit token as content), and the token itself is the secret. Distinct from the DNS/well-known MARKER
# form (which carries the ``vigil-site-verification=`` prefix) — a meta tag's content is the bare token.
_META_NAME = "vigil-site-verification"
_MAX_META_TAGS = 64  # anti-DoS bound on meta tags scanned from a (possibly hostile) homepage

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
    """The exact string the customer publishes (and the verdict demands) for the DNS-TXT + well-known
    methods (the meta-tag method's content is the bare token — see :func:`meta_tag`)."""
    return _MARKER_PREFIX + str(token or "")


def meta_tag(token: str) -> str:
    """The exact HTML meta tag the customer places in their homepage ``<head>`` for the meta-tag method."""
    return f'<meta name="{_META_NAME}" content="{str(token or "")}">'


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
    is defense-in-depth (the token is high-entropy and public once published).

    The comparison is over UTF-8 BYTES, not str: ``hmac.compare_digest`` RAISES ``TypeError`` on a non-ASCII
    ``str``, and the observed value is CUSTOMER-CONTROLLED (a BOM, an accented char, or an invalid-UTF-8
    ``U+FFFD`` in the published file), so a str comparison would break ``observation_proves``'s fail-closed
    "never raises" contract and surface as a 500. On bytes it never raises on content and stays constant-time;
    a non-ASCII body simply does not match the marker (a clean fail-closed refusal, not a crash)."""
    expected = expected_marker(token).encode("utf-8")
    observed = str(observed_value or "").strip().encode("utf-8")
    return hmac.compare_digest(observed, expected)


def _token_matches(token: str, observed_value: str) -> bool:
    """Constant-time comparison of a meta-tag ``content`` (trimmed) against the bare token. Over UTF-8 bytes
    (never raises on customer-controlled non-ASCII content — same fail-closed contract as _marker_matches)."""
    return hmac.compare_digest(str(observed_value or "").strip().encode("utf-8"),
                               str(token or "").encode("utf-8"))


def _meta_contents(html: str) -> "list[str]":
    """Every ``content`` value of a ``<meta name="vigil-site-verification" …>`` tag in ``html`` (bounded,
    fail-closed: a parse error yields what was collected so far, never raises). stdlib HTMLParser lowercases
    tag + attr names, so the ``name`` match is case-insensitive; a hostile/malformed homepage is tolerated."""
    from html.parser import HTMLParser

    out: list[str] = []

    class _Scan(HTMLParser):
        def handle_starttag(self, tag: str, attrs: "list[tuple[str, str | None]]") -> None:
            if tag != "meta" or len(out) >= _MAX_META_TAGS:
                return
            a = {k: (v or "") for k, v in attrs}
            if a.get("name", "").strip().lower() == _META_NAME and "content" in a:
                out.append(a["content"])

    try:
        _Scan().feed(str(html or ""))
    except Exception:  # noqa: BLE001 — a malformed homepage is a fail-closed non-match, never a crash
        pass
    return out


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
    if method == METHOD_META_TAG:
        # ``observed`` is the homepage HTML; ANY <meta name="vigil-site-verification"> whose content is the
        # token proves it. The name attribute namespaces it; a reflected page that merely echoes the token
        # in body text does NOT satisfy it (only a real meta tag's content attribute does).
        if not isinstance(observed, str):
            return False
        return any(_token_matches(tok, c) for c in _meta_contents(observed))
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

    @property
    def meta_tag(self) -> str:
        return meta_tag(self.token)


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

#: Sentinel for ``owner_key``: DISTINGUISH "not supplied → load the owner signing key from the vault" (the
#: default, for signing paths) from an EXPLICIT ``owner_key=None`` → "no signing key", a pure-READ
#: construction that must NOT unseal the vault — least-privilege on the sovereign root key on
#: customer-pollable read paths (SS-4 red-pen LOW; reads authenticate under ``trusted_pubkey`` only).
_LOAD_FROM_VAULT = object()


_SKIP = object()          # the shared fold steps: the record touched no (org_id, host)


def _payload_row(p: dict, at: float) -> dict:
    return dict(p)


def _proof_row(p: dict, at: float) -> dict:
    return {"method": p.get("method"), "token_sha256": p.get("token_sha256"), "verified_at": p.get("verified_at"),
            "expires_at": p.get("expires_at"), "issued_at": at}


def _apply_ownership_record(r, resolver, signal: str, core_fields, row_of, state: dict, issued: dict, rows: dict):
    """Fold ONE spine record of `signal` into (state, issued, rows) — THE challenge / proof fold body, shared by
    the full folds and the verified fold cache (Front C S0d) so they can never diverge. Returns the
    (org_id, host) it touched, or `_SKIP`."""
    p = r.payload
    if not isinstance(p, dict) or p.get("signal") != signal:
        return _SKIP
    org_id = p.get("org_id")
    host = p.get("host")
    if not isinstance(org_id, str) or not org_id or not isinstance(host, str) or not host:
        return _SKIP
    key = (org_id, host)
    rec_state = p.get("state")
    if rec_state == "revoked":
        state[key] = "revoked"                 # honor ANY revoke (even unsigned) — safe direction
        return key
    if rec_state == "active":
        if not verify_signed(p, core_fields, resolver.at(r.seq)):
            return _SKIP                       # fail-closed: unsigned/forged/wrong-epoch-key grant
        at = as_issued_at(p.get("issued_at"))
        if at <= issued.get(key, NO_HIGHWATER):
            return _SKIP                       # REPLAY / stale re-append of an already-honored grant
        issued[key] = at
        state[key] = "active"
        rows[key] = row_of(p, at)
        return key
    return _SKIP


class KeyedGrantView:
    """The cached fold of an owner-signed, per-(org_id, host) latest-wins grant line (ownership challenges and
    proofs here; monitoring authority): the full fold's (state, issued, rows) plus `active` — exactly the full
    fold's result — and `by_org` (org_id -> its active hosts), kept in step per touched key, so a tenant's
    reads are O(its own hosts) instead of a scan of the spine."""

    __slots__ = ("state", "issued", "rows", "active", "by_org")

    def __init__(self, state: dict, issued: dict, rows: dict) -> None:
        self.state, self.issued, self.rows = state, issued, rows
        self.active: dict = {}
        self.by_org: "dict[str, set]" = {}
        for key in list(rows):
            self.sync(key)

    def sync(self, key) -> None:
        row = self.rows.get(key) if self.state.get(key) == "active" else None
        org, host = key
        if row is None:
            if self.active.pop(key, None) is not None:
                hosts = self.by_org[org]
                hosts.discard(host)
                if not hosts:
                    del self.by_org[org]
            return
        self.active[key] = row
        self.by_org.setdefault(org, set()).add(host)

    def of_org(self, org_id: str) -> "list[tuple[str, dict]]":
        """[(host, row)] of `org_id`'s active grants, in host order."""
        return [(h, self.active[(org_id, h)]) for h in sorted(self.by_org.get(org_id, ()))]


def _challenge_step(view: KeyedGrantView, r, resolver) -> None:
    key = _apply_ownership_record(r, resolver, CHALLENGE_SIGNAL, _CHALLENGE_CORE, _payload_row,
                                  view.state, view.issued, view.rows)
    if key is not _SKIP:
        view.sync(key)


def _proof_step(view: KeyedGrantView, r, resolver) -> None:
    key = _apply_ownership_record(r, resolver, PROOF_SIGNAL, _PROOF_CORE, _proof_row,
                                  view.state, view.issued, view.rows)
    if key is not _SKIP:
        view.sync(key)


_CHALLENGE_FOLD = FoldCache("governor.asset_ownership_challenge", step=_challenge_step)
_PROOF_FOLD = FoldCache("governor.asset_ownership_proof", step=_proof_step)


class AssetOwnershipRegistry:
    def __init__(self, store, *, owner_key=_LOAD_FROM_VAULT, trusted_pubkey: Optional[str] = None):
        self.store = store
        # Signing paths leave owner_key unset → load it from the vault (a TPM unseal when sealed). A pure-read
        # caller passes owner_key=None explicitly → the owner PRIVATE key is never touched on that path.
        self.owner_key = owner_keypair() if owner_key is _LOAD_FROM_VAULT else owner_key
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
        seq = self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        # Cascade: a monitoring authority minted on this proof must not stay published/verifiable.
        from .monitoring_authority import MonitoringAuthorityRegistry
        MonitoringAuthorityRegistry(self.store, owner_key=self.owner_key,
                                    trusted_pubkey=self.trusted_pubkey).retire(oid, h)
        return seq

    # -- reads (owner-key-succession-aware folds) ---------------------------------------------------
    def _fold(self, signal: str, core_fields):
        """Fold the spine into {(org_id, host): record_dict} for the given signal whose latest state is
        active, authenticating each ``active`` grant under the owner pubkey valid AT ITS SEQ and refusing any
        stale/replayed re-append via the per-(org_id, host) high-water. Revokes (safe direction) are honored
        regardless of signature. Returns the raw winning core dicts (callers build the dataclass). Used for the
        CHALLENGE signal (ephemeral — a plain genesis scan, no snapshot seed; a pruned challenge is re-requested)."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: dict[tuple, str] = {}
        issued: dict[tuple, float] = {}
        rows: dict[tuple, dict] = {}
        for r in self.store.iter_records():
            _apply_ownership_record(r, resolver, signal, core_fields, _payload_row, state, issued, rows)
        return {k: row for k, row in rows.items() if state.get(k) == "active"}

    def _proof_seed(self, snap) -> "tuple[tuple[dict, dict, dict], int]":
        """((state, issued, rows), since): the proof fold's HARD-PRUNE SEED from `snap`, or the empty genesis start
        when the trusted pubkey differs from the snapshot's (see `_fold_proofs`)."""
        if self.trusted_pubkey != snap.trusted_pubkey:
            return ({}, {}, {}), -1
        state = dict(snap.ownership_proof_state_map())           # (org,host) -> "active"|"revoked" (keep revoked)
        issued = dict(snap.ownership_proof_issued_map())         # (org,host) -> per-pair high-water
        rows = {(row[0], row[1]): {"method": row[2], "token_sha256": row[3], "verified_at": row[4],
                                   "expires_at": row[5], "issued_at": issued.get((row[0], row[1]), 0.0)}
                for row in snap.ownership_proof_row}             # rebuild honored-active proofs from the seed
        return (state, issued, rows), snap.base_seq - 1

    def _proofs_cached(self, reader):
        """`reader(view)` over the verified incremental PROOF fold (`fold_read.cached_read`, flag-gated), else
        `_UNCACHED` (the caller then runs the full `_fold_proofs`)."""
        def seed(snap):
            st, since = self._proof_seed(snap)
            return KeyedGrantView(*st), since

        return cached_read(_PROOF_FOLD, self.store, trusted_pubkey=self.trusted_pubkey, seed=seed, reader=reader)

    def _challenges_cached(self, reader):
        """`reader(view)` over the verified incremental CHALLENGE fold, else `_UNCACHED`. The challenge fold is a
        plain scan of the live window (no seed, no snapshot load), so the build starts from genesis and the read
        is a `live_window` one: the snapshot still keys the entry (a prune rebuilds it, exactly as the full scan
        then sees only the live window), and a snapshot that cannot be loaded declines instead of raising."""
        return cached_read(_CHALLENGE_FOLD, self.store, trusted_pubkey=self.trusted_pubkey,
                           seed=lambda snap: (KeyedGrantView({}, {}, {}), -1), reader=reader, live_window=True)

    def _fold_proofs(self) -> dict:
        """Fold the spine into {(org_id, host): proof-field dict} for proofs whose latest state is active —
        the HARD-PRUNE-DURABLE fold the mint / launch gate reads (Slice G0 close-out). Mirrors
        ``orgs._fold_memberships`` EXACTLY, including the snapshot seed: seed the per-(org_id, host) state /
        anti-replay high-water / row from the committed ``SnapshotState`` (v3), then fold the LIVE window only,
        so an active proof whose only grant was pruned SURVIVES and its high-water is NOT reset — else the first
        hard prune below a revoked proof would re-open the LWW replay-resurrection the G0 red-pen flagged. If our
        trusted anchor differs from the snapshot's (rotated key / empty identity) BYPASS the seed and full-scan
        from genesis (byte-identical under an empty snapshot)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (state, issued, rows), since = self._proof_seed(snap)
        for r in self.store.iter_records(since_seq=since):
            _apply_ownership_record(r, resolver, PROOF_SIGNAL, _PROOF_CORE, _proof_row, state, issued, rows)
        return {k: row for k, row in rows.items() if state.get(k) == "active"}

    def challenge(self, org_id: str, host: str) -> Optional[OwnershipChallenge]:
        """The current active challenge for (org_id, host), or None (fail-closed). The latest owner-signed,
        non-superseded token."""
        if not isinstance(org_id, str) or not org_id or not isinstance(host, str) or not host:
            return None
        row = self._challenges_cached(lambda v: v.active.get((org_id, host)))
        if row is _UNCACHED:
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
        row = self._proofs_cached(lambda v: v.active.get((org_id, host)))
        if row is _UNCACHED:
            row = self._fold_proofs().get((org_id, host))
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
        rows = self._proofs_cached(lambda v: v.of_org(org_id))
        if rows is _UNCACHED:
            rows = [(h, row) for (o, h), row in self._fold_proofs().items() if o == org_id]
        out = []
        for h, row in rows:
            if float(now) < float(as_issued_at(row.get("expires_at"))):
                out.append(h)
        return sorted(out)

    def ever_proven_hosts(self, org_id: str) -> list[str]:
        """Every host `org_id` has EVER held an owner-signed, verified proof for (the proof fold's signed issued
        map), whatever its state or expiry now, in host order. Unsigned revokes never add a host here (they only
        touch the state map). Used to pin the trial preview's one reveal across proof expiry and re-proving."""
        if not isinstance(org_id, str) or not org_id:
            return []
        hit = self._proofs_cached(lambda v: sorted(h for (o, h) in v.issued if o == org_id))
        if hit is not _UNCACHED:
            return hit
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (state, issued, rows), since = self._proof_seed(snap)
        for r in self.store.iter_records(since_seq=since):
            _apply_ownership_record(r, resolver, PROOF_SIGNAL, _PROOF_CORE, _proof_row, state, issued, rows)
        return sorted(h for (o, h) in issued if o == org_id)

    def ever_proven_pairs(self) -> "list[tuple[str, str]]":
        """Every (org_id, host) that has EVER held an owner-signed, verified proof (the signed issued map), across
        all orgs. Unsigned revokes never add a pair. Used by the trial domain-history check."""
        hit = self._proofs_cached(lambda v: sorted(v.issued))
        if hit is not _UNCACHED:
            return hit
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (state, issued, rows), since = self._proof_seed(snap)
        for r in self.store.iter_records(since_seq=since):
            _apply_ownership_record(r, resolver, PROOF_SIGNAL, _PROOF_CORE, _proof_row, state, issued, rows)
        return sorted(issued)

    def assets_overview(self, org_id: str, *, now: float) -> list[dict]:
        """Per-host ownership status for ALL of ``org_id``'s assets, in host order — the tenant-scoped read
        behind the customer "Domains" view (SS-4). DEFAULT-DENY to this org: it folds the owner-authenticated
        proof + challenge spines (the SAME folds the mint/launch gate reads) and surfaces ONLY ``(org_id, *)``
        rows, so another tenant's assets are STRUCTURALLY absent — never a client-chosen filter. Each host is:

          * ``verified`` — an active, owner-signed proof that is UNEXPIRED at ``now`` (``now < expires_at``);
          * ``expired``  — an active proof whose owner-signed expiry has passed (re-proving required);
          * ``pending``  — an outstanding challenge with no active proof (not yet verified, or revoked).

        A record carries ``method`` + ``verified_at`` / ``expires_at`` when proven, and the CURRENT challenge's
        placement instructions (``dns``/``well_known``/``meta`` + ``marker``) when a challenge is outstanding,
        so the UI can render retry / re-check steps. Read-only: no lock, no mint, no owner key. ``marker`` is
        the org's OWN challenge value (what they publish), never another tenant's secret."""
        if not isinstance(org_id, str) or not org_id:
            return []
        n = float(now)
        proofs = self._proofs_cached(lambda v: dict(v.of_org(org_id)))
        challenges = _UNCACHED if proofs is _UNCACHED else self._challenges_cached(lambda v: dict(v.of_org(org_id)))
        if proofs is _UNCACHED:
            proofs = {h: row for (o, h), row in self._fold_proofs().items() if o == org_id}
        if challenges is _UNCACHED:
            challenges = {h: row for (o, h), row in self._fold(CHALLENGE_SIGNAL, _CHALLENGE_CORE).items()
                          if o == org_id}
        out: list[dict] = []
        for h in sorted(set(proofs) | set(challenges)):
            prow = proofs.get(h)
            rec: dict = {"host": h}
            if prow is not None:
                exp = float(as_issued_at(prow.get("expires_at")))
                rec.update({"method": str(prow.get("method") or ""),
                            "verified_at": float(as_issued_at(prow.get("verified_at"))),
                            "expires_at": exp,
                            "status": "verified" if n < exp else "expired"})
            else:
                rec["status"] = "pending"
            crow = challenges.get(h)
            if crow is not None:
                tok = str(crow.get("token") or "")
                marker = expected_marker(tok)
                rec["challenge"] = {"dns_name": dns_txt_name(h), "dns_value": marker,
                                    "well_known_url": well_known_url(h), "well_known_body": marker,
                                    "meta_tag": meta_tag(tok), "marker": marker}
            out.append(rec)
        return out


def assets_overview(store, org_id: str, *, now: float) -> dict:
    """Projector for the customer-plane ``/api/customer/assets`` read: the tenant-scoped per-host ownership
    status for ``org_id``. A thin wrapper over :meth:`AssetOwnershipRegistry.assets_overview` so the
    provisioner's ``_customer_read`` gate can call it exactly like ``billing_overview`` / ``assessment_summary``
    (``admit_customer`` has ALREADY authorized ``org_id`` as the session's own tenant before this runs)."""
    return {"assets": AssetOwnershipRegistry(store, owner_key=None).assets_overview(org_id, now=float(now))}
