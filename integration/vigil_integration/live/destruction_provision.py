"""destruction_provision — generate + sign the m-of-n destruction quorum for `vigil patch --open-pr`.

The destructive PR leg needs three provisioned artifacts (see live/trusted_finding.py + destruction_gate.py):
  1. a ``DestructionAuthority`` = a ``TrustRoot`` (the signer PUBLIC keys + an m-of-n threshold) plus the
     MANDATORY signer ids (must include the owner);
  2. a per-action ``SignedDestructionAuthorization`` — the owner (+ any co-signers) sign ONE concrete
     destructive action, inside a short window, with a single-use nonce;
  3. a durable single-use nonce ledger (created on first use by the ledger itself).

This module builds (1) once and signs (2) per patch. It is the "how to get the quorum keys" step behind
`vigil provision-destruction` / `vigil authorize-destruction`. Import-clean: ``vigil_core`` + the offense-
local ``destruction_gate`` only — NO framework/strix/sigil.

SECURITY MODEL (be honest about it):
  * m-of-n means "m of the n registered keys must sign, and the owner MUST be one of them." Its protection
    is real ONLY when the n private keys live in DIFFERENT places — the owner's key here, each co-signer's
    key on their own machine. Then this machine alone cannot authorize a destructive PR.
  * With threshold=1 and only the owner key (the solo default), whoever holds the owner key can authorize —
    still single-use + window-bounded + action-bound + off-by-default, but NOT separation of duties. Use
    ``--signers N --threshold M`` (M>1) and keep co-signer keys off this box for that.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class GeneratedAuthority:
    """The output of provisioning: the public trust-root JSON to keep, the private signing keys to
    distribute (shown ONCE), and the mandatory signer ids to enforce."""

    trust_root_json: str                     # public — safe to store / hand to the offense verifier
    private_keys: tuple[tuple[str, str], ...]  # (key_id, private_key_b64) — SECRET; distribute + then forget
    mandatory_signer_ids: tuple[str, ...]
    threshold: int


def generate_authority(*, threshold: int = 1, worker_count: int = 0, owner_id: str = "owner") -> GeneratedAuthority:
    """Mint a fresh destruction quorum: one owner key + ``worker_count`` co-signer keys, an m-of-n
    ``TrustRoot`` at ``threshold``, and the owner bound as the mandatory signer. Fail-closed on a threshold
    outside ``1..n``. The private keys are returned to be shown once and distributed — never persisted here.

    W9-5: this DEV/solo path mints EVERY private key on ONE host, so it is REFUSED under the production
    posture. In production, generate each signer's key on its OWN host with :func:`build_enrollment`
    (``vigil enroll-cosigner``) and assemble the quorum from PUBLIC enrolment requests with
    :func:`assemble_authority` (``vigil assemble-destruction``) — no co-signer private key ever transits the
    minting box."""
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    from vigil_core.posture import is_production_posture

    if is_production_posture():
        raise ValueError(
            "production posture refuses `provision-destruction`/generate_authority: it mints every private "
            "key on ONE host. Use `vigil enroll-cosigner` (per-host keygen) + `vigil assemble-destruction` "
            "(public enrolment requests only) so no co-signer private key ever transits the minting box.")

    owner_id = str(owner_id or "owner").strip() or "owner"
    n = 1 + max(0, int(worker_count))
    if not (1 <= int(threshold) <= n):
        raise ValueError(f"threshold {threshold} out of range for {n} signer(s)")

    ids = [owner_id] + [f"worker{i + 1}" for i in range(max(0, int(worker_count)))]
    if len(set(ids)) != len(ids):
        raise ValueError("signer ids must be unique (owner id collides with a worker id)")
    keys = {kid: generate_keypair() for kid in ids}
    authorizers = [AuthorizerKey(key_id=kid, name=kid, public_key_b64=keys[kid].public_key_b64) for kid in ids]
    tr = TrustRoot(threshold=int(threshold), authorizers=authorizers)
    return GeneratedAuthority(
        trust_root_json=tr.model_dump_json(),
        private_keys=tuple((kid, keys[kid].private_key_b64) for kid in ids),
        mandatory_signer_ids=(owner_id,),
        threshold=int(threshold),
    )


def sign_action(*, action_id: str, engagement_slug: str, target: str,
                signer_private_keys: "list[tuple[str, str]]", now: float,
                window_s: float = 600.0, nonce: str) -> str:
    """Sign ONE destructive action with the given ``(key_id, private_key_b64)`` signers and return the
    ``{"authorization": {...}, "signatures": [...]}`` JSON that ``load_signed_authorization`` consumes.

    The window is ``[now-30, now+window_s]`` (a small back-skew for clock jitter). ``window_s`` MUST keep the
    total window within the gate's 900s dead-man's-switch — enforced fail-closed here. ``nonce`` must be a
    fresh unguessable value (the caller supplies it so it can also record/track it); a blank nonce is refused.
    """
    from ..destruction_gate import sign_authorization

    if not signer_private_keys:
        raise ValueError("at least one signer private key is required (the owner)")
    auth = _build_authorization(action_id=action_id, engagement_slug=engagement_slug, target=target,
                                now=now, window_s=window_s, nonce=nonce)
    signed = sign_authorization(auth, [(str(kid), str(priv)) for kid, priv in signer_private_keys])
    return json.dumps({
        "authorization": auth.signing_payload(),
        "signatures": [{"key_id": s.key_id, "signature_b64": s.signature_b64} for s in signed.signatures],
    }, sort_keys=True)


def _build_authorization(*, action_id: str, engagement_slug: str, target: str, now: float,
                         window_s: float = 600.0, nonce: str) -> "Any":
    """Construct + validate the SHARED, unsigned destruction authorization (the exact record every signer
    signs). Fail-closed on a blank nonce/action/target or a window that would exceed the 900s dead-man's-
    switch — validated HERE so both the single-box (:func:`sign_action`) and the per-host detached-signature
    (:func:`build_authorization_request`) ceremonies enforce the same bound identically."""
    from ..destruction_gate import DEFAULT_POLICY, DestructionAuthorization

    if not str(nonce or "").strip():
        raise ValueError("a non-empty single-use nonce is required")
    if not str(action_id or "").strip() or not str(target or "").strip():
        raise ValueError("action_id and target are required")
    not_before = float(now) - 30.0
    not_after = float(now) + float(window_s)
    if (not_after - not_before) > DEFAULT_POLICY.max_authorization_lifetime:
        raise ValueError(
            f"window {(not_after - not_before):.0f}s exceeds the {DEFAULT_POLICY.max_authorization_lifetime:.0f}s "
            "dead-man's-switch limit — use a shorter --window-s")
    return DestructionAuthorization(
        action_id=str(action_id), engagement_slug=str(engagement_slug), target=str(target),
        blast_class="destructive", not_before=not_before, not_after=not_after, nonce=str(nonce))


class AuthorizationExistsError(Exception):
    """A single-use signed-authorization file already exists at the target path — refusing to overwrite it.

    The destructive-PR leg treats ``signed-authorization.json`` as a single-use token (one authorization →
    one PR, enforced durably by the nonce ledger at spend time). A second ``authorize-destruction`` that
    clobbered the file in place would silently replace a still-unspent token, or — worse under a TOCTOU —
    let a caller re-mint over a slot another actor is about to spend. Creating the file O_EXCL makes the
    second write FAIL LOUDLY instead (the same single-use-via-exclusive-create discipline as the LAP nonce
    ledger)."""


def write_single_use_authorization(path: str, doc: str) -> None:
    """Write the single-use signed-authorization ``doc`` to ``path`` with ``O_CREAT | O_EXCL`` (owner-only
    0600) so a SECOND authorize-destruction to the SAME path FAILS rather than silently overwriting the
    prior single-use token. Raises :class:`AuthorizationExistsError` if the file already exists — the caller
    must remove/rename the spent authorization to mint a fresh one, which keeps the single-use property the
    destructive-PR leg depends on. stdlib only (import-clean)."""
    import os
    from pathlib import Path

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise AuthorizationExistsError(
            f"a signed authorization already exists at {path} — refusing to overwrite a single-use token "
            f"(remove it to mint a fresh one)") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(doc)


def fresh_nonce() -> str:
    """A fresh, unguessable single-use nonce (stdlib ``secrets``; no wallclock/RNG-on-decision concern —
    this is provisioning, not the deterministic decision path)."""
    import secrets
    return "dn-" + secrets.token_hex(16)


def load_worker_key_file(spec: str) -> "tuple[str, str]":
    """Parse a ``key_id=/path/to/keyfile`` co-signer spec and read the private key from the FILE (never argv,
    so a co-signer key never lands in the process table / shell history). Returns ``(key_id, private_key_b64)``."""
    from pathlib import Path

    s = str(spec or "")
    if "=" not in s:
        raise ValueError(f"--worker-key must be key_id=/path/to/keyfile, got {spec!r}")
    kid, path = s.split("=", 1)
    kid = kid.strip()
    if not kid:
        raise ValueError("--worker-key needs a non-empty key_id before '='")
    try:
        priv = Path(path.strip()).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"could not read worker key file for {kid!r}: {exc}") from exc
    if not priv:
        raise ValueError(f"worker key file for {kid!r} is empty")
    return (kid, priv)


def default_paths(base_dir: str) -> "dict[str, str]":
    """The default provisioning locations under ``base_dir`` that `vigil patch --open-pr` auto-discovers."""
    from pathlib import Path

    base = Path(base_dir)
    return {
        "trust_root": str(base / "destruction-trust-root.json"),
        "signed": str(base / "signed-authorization.json"),
        "ledger": str(base / "destruction-nonces"),
    }


def write_trust_root(base_dir: str, trust_root_json: str) -> str:
    """Persist the PUBLIC trust-root JSON (0644 is fine — no secrets) at the default path; returns the path."""
    from pathlib import Path

    p = Path(default_paths(base_dir)["trust_root"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(trust_root_json, encoding="utf-8")
    return str(p)


def _read_trust_root_ids(trust_root_json: str) -> Optional[Any]:
    """Return the parsed trust root (for the CLI to echo the registered signer ids), or None if unparseable."""
    from vigil_core import TrustRoot

    try:
        return TrustRoot.model_validate_json(trust_root_json)
    except Exception:  # noqa: BLE001 — display helper only
        return None


# ======================================================================================================
# W9-5 — SECURE per-host co-signer provisioning (CSR-style enrolment) + per-host detached signing.
#
# The defect W9-5 closes: the DEV path (generate_authority) mints EVERY private key on ONE box, so an
# m-of-n "quorum" whose members all originated on one host is not a quorum. The secure path below splits
# provisioning into two phases so no co-signer private key ever transits the minting box:
#
#   PHASE 1 (on each signer's OWN host):  build_enrollment  →  keeps a 0600 PRIVATE key on that host and
#            emits a PUBLIC "enrolment request" = {key_id, name, public_key_b64} + a proof-of-possession
#            self-signature (the fresh private key signs the canonical enrolment statement).
#   PHASE 2 (on the MINTING box):         assemble_authority  →  consumes only PUBLIC enrolment requests,
#            VERIFIES every proof-of-possession (a copy-pasted/forged pubkey with no matching self-signature
#            is REFUSED — AC3), refuses duplicate key_ids AND duplicate pubkeys (quorum collapse), and — under
#            the production posture — refuses anything that is not a genuine multi-signer quorum.
#
# Honest boundary on "enrolled on its own host": the proof-of-possession proves the enroller controlled the
# PRIVATE key when the request was produced; it cannot prove WHICH physical host produced it, nor that the
# key was deleted anywhere. The host separation is an operational property the two-phase tooling makes the
# DEFAULT and the easy path (the private key is written 0600 by build_enrollment and never emitted), not a
# fact the cryptography attests. See docs/decisions/W9-5-*.md for the deletion-attestation statement.
# ------------------------------------------------------------------------------------------------------

# Fresh domain tag: a co-signer enrolment proof-of-possession can NEVER be replayed as a destruction
# authorization, an evidence certificate, an owner delegation, or any other signed artifact.
_ENROLLMENT_DOMAIN = b"vigil-destruction-cosigner-enrollment-v1\x00"


@dataclass(frozen=True)
class EnrollmentRequest:
    """A co-signer's PUBLIC-ONLY enrolment request. Carries NO private material — it is exactly what travels
    from a signer's own host to the minting box. ``pop_signature_b64`` is the proof-of-possession: the fresh
    private key's signature over ``enrollment_signing_bytes(key_id, name, public_key_b64)``."""

    key_id: str
    name: str
    public_key_b64: str
    pop_signature_b64: str

    def to_json(self) -> str:
        return json.dumps({"key_id": self.key_id, "name": self.name,
                           "public_key_b64": self.public_key_b64,
                           "pop_signature_b64": self.pop_signature_b64}, sort_keys=True)


def enrollment_signing_bytes(key_id: str, name: str, public_key_b64: str) -> bytes:
    """The canonical, DETERMINISTIC proof-of-possession statement (no wallclock/nonce — the statement binds a
    key_id to a pubkey; the signature proves possession of the matching private key). Domain-separated so it
    can never be replayed as any other signed artifact."""
    from vigil_core import canonical_json

    return _ENROLLMENT_DOMAIN + canonical_json(
        {"key_id": str(key_id), "name": str(name), "public_key_b64": str(public_key_b64)})


def build_enrollment(*, key_id: str, name: str = "") -> "tuple[str, str]":
    """PHASE 1 — run on the CO-SIGNER's (or owner's) OWN host. Generate a fresh Ed25519 keypair LOCALLY and
    return ``(private_key_b64, enrollment_json)``. The PRIVATE key is returned to be stored 0600 ON THIS HOST
    and NEVER transmitted; ``enrollment_json`` carries only PUBLIC material + a proof-of-possession
    self-signature. The minting box consumes only ``enrollment_json`` (see :func:`assemble_authority`)."""
    from vigil_core import generate_keypair, sign

    kid = str(key_id or "").strip()
    if not kid:
        raise ValueError("enrolment needs a non-empty key_id")
    nm = str(name or "").strip() or kid
    kp = generate_keypair()
    pop = sign(kp.private_key_b64, enrollment_signing_bytes(kid, nm, kp.public_key_b64))
    return kp.private_key_b64, EnrollmentRequest(
        key_id=kid, name=nm, public_key_b64=kp.public_key_b64, pop_signature_b64=pop).to_json()


def verify_enrollment(doc: str) -> "Any":
    """PHASE 2 (per request) — parse + VERIFY one co-signer enrolment request; return the ``AuthorizerKey``
    for the trust root. Fail-closed: refuses malformed JSON, missing fields, a weak/non-canonical public key
    (``vigil_core.load_public_key`` bars low-order/non-canonical keys), or a proof-of-possession that does
    NOT verify under the enrolled public key.

    This PoP check is the AC3 control: a pubkey that never proved possession on its own host — a copy-pasted
    or forged pubkey with no matching self-signature — is REFUSED here, so it can never enter a quorum."""
    from vigil_core import AuthorizerKey, verify_one

    try:
        d = json.loads(doc)
    except Exception as exc:  # noqa: BLE001 — unparseable enrolment ⇒ refuse
        raise ValueError(f"enrolment is not valid JSON: {exc}") from exc
    if not isinstance(d, dict):
        raise ValueError("enrolment must be a JSON object")
    kid = str(d.get("key_id", "")).strip()
    nm = str(d.get("name", "")).strip() or kid
    pub = d.get("public_key_b64")
    pop = d.get("pop_signature_b64")
    if not kid or not isinstance(pub, str) or not pub or not isinstance(pop, str) or not pop:
        raise ValueError("enrolment needs key_id, public_key_b64 and pop_signature_b64")
    try:
        ok = verify_one(pub, enrollment_signing_bytes(kid, nm, pub), pop)
    except Exception as exc:  # noqa: BLE001 — malformed/weak key or signature ⇒ refuse (never admit)
        raise ValueError(f"enrolment proof-of-possession for {kid!r} is unverifiable: {exc}") from exc
    if not ok:
        raise ValueError(
            f"enrolment proof-of-possession for {kid!r} did not verify — no proof the enroller controls "
            "this key on its own host (refusing a key that never proved possession)")
    return AuthorizerKey(key_id=kid, name=nm, public_key_b64=pub)


def write_cosigner_private_key(path: str, private_key_b64: str) -> str:
    """Write a freshly generated co-signer PRIVATE key to ``path`` at 0600, ``O_EXCL`` (refuse to clobber an
    existing key). This file MUST stay on the co-signer's own host — it is never sent to the minting box."""
    import os
    from pathlib import Path

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError(f"a key already exists at {path} — refusing to overwrite it (remove it first)") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(str(private_key_b64).strip() + "\n")
    return str(path)


def assemble_authority(*, enrollments: "list[tuple[str, str]]", threshold: int,
                       owner_id: str = "owner") -> GeneratedAuthority:
    """PHASE 2 — run on the MINTING box. Assemble the m-of-n ``TrustRoot`` from VERIFIED public enrolment
    requests (``(key_id_hint, enrollment_json)`` per signer). Verifies every proof-of-possession, refuses a
    file-name hint that disagrees with the PoP-signed key_id, refuses duplicate key_ids AND duplicate PUBLIC
    keys (a duplicate pubkey collapses an m-of-n to one keyholder), binds ``owner_id`` as the mandatory
    signer, and — under the production posture — refuses anything that is not a genuine multi-signer quorum.

    NO private key is read or produced here: the returned ``GeneratedAuthority.private_keys`` is empty. Each
    signer's key stays on its own host."""
    from vigil_core import TrustRoot
    from vigil_core.posture import is_production_posture
    from vigil_core.crypto import load_public_key

    from ..destruction_gate import production_multisigner_reason

    owner_id = str(owner_id or "owner").strip() or "owner"
    if not enrollments:
        raise ValueError("assemble needs at least one enrolment request")
    authorizers = []
    seen_ids: set = set()
    seen_pubs: set = set()
    for kid_hint, doc in enrollments:
        ak = verify_enrollment(doc)
        hint = str(kid_hint or "").strip()
        if hint and hint != ak.key_id:
            raise ValueError(
                f"enrolment file mapped as {hint!r} but its PoP-signed key_id is {ak.key_id!r} (mis-mapped file)")
        if ak.key_id in seen_ids:
            raise ValueError(f"duplicate signer key_id {ak.key_id!r} in the enrolment set")
        # Dedup by the DECODED 32-byte key, NOT the base64 STRING: two enrolments of ONE key under different
        # base64 encodings (malleable trailing pad bits) decode to the SAME Ed25519 point and must count as
        # ONE signer, or a single keyholder could assemble a costume "multi-signer" quorum. verify_enrollment
        # already ran load_public_key (canonical/non-weak), so this decode cannot raise on an admitted key.
        pub_bytes = load_public_key(ak.public_key_b64).public_bytes_raw()
        if pub_bytes in seen_pubs:
            raise ValueError("duplicate signer PUBLIC key in the enrolment set (would collapse the quorum)")
        seen_ids.add(ak.key_id)
        seen_pubs.add(pub_bytes)
        authorizers.append(ak)
    ids = [a.key_id for a in authorizers]
    if owner_id not in ids:
        raise ValueError(f"the mandatory owner id {owner_id!r} is not among the enrolled signers {sorted(ids)}")
    n = len(authorizers)
    if not (1 <= int(threshold) <= n):
        raise ValueError(f"threshold {threshold} out of range for {n} enrolled signer(s)")
    tr = TrustRoot(threshold=int(threshold), authorizers=authorizers)
    if is_production_posture():
        reason = production_multisigner_reason(tr)
        if reason:
            raise ValueError(reason)
    return GeneratedAuthority(
        trust_root_json=tr.model_dump_json(),
        private_keys=(),  # W9-5: NO private material on the minting box
        mandatory_signer_ids=(owner_id,),
        threshold=int(threshold),
    )


# --- per-host detached signing: keep co-signer keys on their own host at AUTHORIZE time too ------------
#
# assemble_authority keeps private keys off the minting box at PROVISION time. This trio keeps them off at
# AUTHORIZE time: one coordinator mints the SHARED unsigned authorization (one nonce/window), each signer
# signs it DETACHED on their own host, and the coordinator combines the detached signatures into the
# single-use signed-authorization.json the PR leg consumes. No signer key co-mingles.

def build_authorization_request(*, action_id: str, engagement_slug: str, target: str, now: float,
                                window_s: float = 600.0, nonce: str) -> str:
    """Coordinator step — mint the SHARED unsigned destruction authorization (the exact bytes every signer
    will sign) as ``{"authorization": {...}}`` JSON. Distribute it to each signer host for detached signing."""
    auth = _build_authorization(action_id=action_id, engagement_slug=engagement_slug, target=target,
                                now=now, window_s=window_s, nonce=nonce)
    return json.dumps({"authorization": auth.signing_payload()}, sort_keys=True)


def _authorization_from_request(request_json: str) -> "Any":
    from ..destruction_gate import DestructionAuthorization

    try:
        d = json.loads(request_json)
        a = d["authorization"]
        return DestructionAuthorization(
            action_id=str(a["action_id"]), engagement_slug=str(a["engagement_slug"]),
            target=str(a["target"]), blast_class=str(a["blast_class"]),
            not_before=float(a["not_before"]), not_after=float(a["not_after"]), nonce=str(a["nonce"]))
    except Exception as exc:  # noqa: BLE001 — malformed request ⇒ refuse
        raise ValueError(f"malformed authorization request: {exc}") from exc


def sign_request_detached(*, request_json: str, key_id: str, private_key_b64: str) -> str:
    """Per-signer step — run on the signer's OWN host. Sign the SHARED authorization request DETACHED with
    THIS host's key and return ``{"key_id", "signature_b64"}`` JSON. The private key never leaves this host;
    only the detached signature travels back to the coordinator."""
    from ..destruction_gate import authorization_signing_bytes
    from vigil_core import sign

    kid = str(key_id or "").strip()
    if not kid:
        raise ValueError("detached signature needs a non-empty key_id")
    if not str(private_key_b64 or "").strip():
        raise ValueError("detached signature needs a private key")
    auth = _authorization_from_request(request_json)
    sig = sign(str(private_key_b64).strip(), authorization_signing_bytes(auth))
    return json.dumps({"key_id": kid, "signature_b64": sig}, sort_keys=True)


def combine_authorization(*, request_json: str, detached_signatures: "list[str]") -> str:
    """Coordinator step — combine per-host DETACHED signatures over the SHARED request into the
    ``{"authorization": {...}, "signatures": [...]}`` JSON the PR leg consumes. Inert assembly only: the
    signatures are re-verified by the gate (``authorize_destruction``), not trusted here. Refuses an empty
    signature set or a malformed detached signature; dedupes nothing (the gate dedups by key_id)."""
    auth = _authorization_from_request(request_json)  # validates the request round-trips
    sigs = []
    for raw in (detached_signatures or []):
        try:
            s = json.loads(raw)
            kid = str(s["key_id"]).strip()
            sig = str(s["signature_b64"]).strip()
        except Exception as exc:  # noqa: BLE001 — malformed detached signature ⇒ refuse
            raise ValueError(f"malformed detached signature: {exc}") from exc
        if not kid or not sig:
            raise ValueError("detached signature needs a non-empty key_id and signature_b64")
        sigs.append({"key_id": kid, "signature_b64": sig})
    if not sigs:
        raise ValueError("at least one detached signature is required")
    return json.dumps({"authorization": auth.signing_payload(), "signatures": sigs}, sort_keys=True)
