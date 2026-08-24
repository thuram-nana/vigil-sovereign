"""witness_provision — stand up an independent transparency-log witness end-to-end, and DECIDE whether a
deployment's witness set is production-fit (W8-3).

WHY THIS EXISTS. A witnessed checkpoint co-signed by ONE witness (the shipped default — see
``apps/sigil/sigil/spine/witness.py:witness_trust_root``, which falls back to owner-only threshold 1) is
rollback DETECTION via off-box retention, NOT split-view PREVENTION. Prevention needs a STRICT MAJORITY of
DISTINCT witnesses (``2*threshold > n`` over n distinct canonical keys), so that any two quorums must share
an honest witness that refuses the second, conflicting fork — the exact property
``transparency.is_split_view_resistant`` already decides. Until W8-3 there was (a) no tooling to provision an
additional independent witness without hand-editing a roster, and (b) no production-posture check that
REFUSED a solo (or a non-distinct) witness set. This module is both.

WHAT IT IS (and, honestly, is NOT):

  * The PRODUCTION WITNESS ROSTER — a small declarative JSON file, ``{schema, threshold, authorizers:
    [{key_id, public_key_b64}, ...]}``, naming the DISTINCT witness keys a production deployment co-signs
    against and the quorum threshold. It lives in the offense/integration runtime dir (``.vigil-live``) or
    at ``$VIGIL_WITNESS_ROSTER``, so the offense-plane production gate can read it WITHOUT importing the
    sovereign plane (FATAL-2). It is the DEPLOYMENT's declaration of its witness set; the cryptographic,
    owner-signed anti-tamper roster on the sovereign side (``sigil.spine.witness.set_roster`` /
    ``load_roster``) and the OFF-BOX witnessed anchor remain the trust-bearing artifacts — this file drives
    the preflight distinctness check, it is not itself a trust root a verifier pins.
  * :func:`roster_posture` — the production-fitness verdict, delegating the distinctness decision to
    ``transparency.is_split_view_resistant`` (REUSED, not re-implemented): ``DISTINCT-QUORUM`` iff the set is
    a strict majority of >=2 DISTINCT canonical keys; ``SOLO`` for an absent / one-witness set; and
    ``NOT-DISTINCT`` when >=2 authorizers collapse to fewer distinct keys (witnesses share a key), the
    threshold is sub-majority, or a key is non-canonical / low-order (fail-closed). The offense doctor's
    ``_posture_witness`` probe and the shared production gate key on this state.
  * :func:`provision_witness` / :func:`register_authorizer` — the tooling: mint a NEW independent witness
    Ed25519 keypair (persistent, 0600, via ``witness_service.load_or_create_witness_key``) and register it
    into the roster, or register a witness whose PUBLIC key was received OUT OF BAND (an independent party's
    ``witness_service serve`` box advertises it at ``GET /pubkey``). Each register REFUSES a duplicate
    canonical key (so tooling can never itself build a non-distinct roster) and RECOMPUTES the strict-majority
    threshold, so after two registrations the roster is split-view-resistant with no hand-editing.

HONEST LIMIT (LOAD-BEARING — mirrors ``transparency`` § and ``witness.guarantee_label``): DISTINCTNESS of
keys is checkable here; INDEPENDENCE of the PARTIES that custody them is NOT. A strict-majority roster whose
keys are all held by one operator is arithmetically split-view-resistant but provides no real independence —
that is a DEPLOYMENT property code cannot verify, and the gate says so. ``provision_witness`` minting a fresh
local key gives a DISTINCT key, not an independent party; a genuinely independent witness runs on someone
else's box and its pubkey is ``register``-ed here out of band. The END-TO-END stand-up against a REAL separate
host (running ``witness_service serve`` over a tunnel) is an infra step this tooling prepares but cannot
perform inside a hermetic check — see the module ``witness_service`` for the transport and the W8-3 decision
doc for the residual.

Import-clean + sovereign-safe (FATAL-2): module level pulls ONLY ``vigil_core`` + ``.transparency`` (both
``vigil_core``-only). Key MINTING lazily imports ``.witness_service`` (also ``vigil_core``-only) inside the
provisioning path, so the read-only :func:`roster_posture` the production gate calls drags in nothing more
than the distinctness primitive. NEVER imports ``framework`` / ``strix`` / ``sigil``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Mapping, Optional

from vigil_core import AuthorizerKey, IntegrityError, TrustRoot
from vigil_core.crypto import load_public_key

from .transparency import is_split_view_resistant

# The env override + default location of the production witness roster. The default sits in the
# offense/integration runtime dir (`.vigil-live`, which `vigil up` provisions and `doctor` already knows is
# writable) so a standard deploy needs no extra flags; an operator may relocate it with $VIGIL_WITNESS_ROSTER.
ROSTER_ENV = "VIGIL_WITNESS_ROSTER"
_ROSTER_BASENAME = "witness-roster.json"
_ROSTER_SCHEMA = 1

# The posture states this module reports; only DISTINCT-QUORUM is production-fit (kept in step with the
# `witness` good-set in vigil_core.doctor.REQUIRED_CONTROLS).
STATE_DISTINCT_QUORUM = "DISTINCT-QUORUM"
STATE_SOLO = "SOLO"
STATE_NOT_DISTINCT = "NOT-DISTINCT"
STATE_UNKNOWN = "UNKNOWN"


class RosterError(ValueError):
    """The production witness roster is malformed, or a provisioning request is invalid. Fail-closed:
    every load/register path raises this rather than silently trusting or silently building a bad roster."""


# --------------------------------------------------------------------------------------------------------
# roster location + (de)serialisation
# --------------------------------------------------------------------------------------------------------
def default_roster_path(repo: "str | os.PathLike") -> Path:
    """The default production-roster path under a repo's ``.vigil-live`` runtime dir."""
    return Path(repo) / ".vigil-live" / _ROSTER_BASENAME


def roster_path(repo: "Optional[str | os.PathLike]" = None,
                env: "Optional[Mapping[str, str]]" = None) -> Path:
    """Resolve the roster path: ``$VIGIL_WITNESS_ROSTER`` if set (the operator's chosen location), else the
    repo default. ``env`` is injectable for tests; ``repo`` defaults to the cwd when None."""
    e = os.environ if env is None else env
    override = (e.get(ROSTER_ENV) or "").strip()
    if override:
        return Path(override).expanduser()
    return default_roster_path(Path(repo) if repo is not None else Path.cwd())


def strict_majority_threshold(n: int) -> int:
    """The smallest threshold that is a STRICT MAJORITY of ``n`` witnesses (``2*t > n``): ``n // 2 + 1``.
    For n=1 → 1, n=2 → 2, n=3 → 2, n=4 → 3 — exactly the quorum ``is_split_view_resistant`` requires so a
    freshly-provisioned >=2-witness roster is split-view-resistant with no hand-tuning of the threshold."""
    if n < 1:
        raise RosterError("a witness roster needs at least one authorizer")
    return n // 2 + 1


def _parse_authorizers(raw: object) -> "list[dict]":
    if not isinstance(raw, list) or not raw:
        raise RosterError("witness roster has no authorizers")
    out: "list[dict]" = []
    seen_ids: set = set()
    for a in raw:
        if not isinstance(a, dict):
            raise RosterError("a witness authorizer is not an object")
        kid = a.get("key_id")
        pub = a.get("public_key_b64")
        if not isinstance(kid, str) or not kid or not isinstance(pub, str) or not pub:
            raise RosterError("a witness authorizer is missing key_id / public_key_b64")
        if kid in seen_ids:
            raise RosterError(f"duplicate witness key_id {kid!r} in the roster")
        seen_ids.add(kid)
        out.append({"key_id": kid, "public_key_b64": pub})
    return out


def load_roster(path: "str | os.PathLike") -> "Optional[dict]":
    """Load + strictly validate the production witness roster, or return ``None`` if none is configured
    (an ABSENT roster is the shipped solo default, not an error — :func:`roster_posture` reports it SOLO).
    Fail-closed: a present-but-corrupt/malformed roster RAISES :class:`RosterError`, never a silent pass."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise RosterError(f"corrupt witness roster {p}: {e}") from e
    if not isinstance(obj, dict):
        raise RosterError("witness roster is not a JSON object")
    authorizers = _parse_authorizers(obj.get("authorizers"))
    thr = obj.get("threshold")
    if not isinstance(thr, int) or isinstance(thr, bool) or thr < 1:
        raise RosterError("witness roster threshold must be an integer >= 1")
    if thr > len(authorizers):
        raise RosterError(f"threshold {thr} exceeds the {len(authorizers)} configured witnesses")
    return {"schema": _ROSTER_SCHEMA, "threshold": int(thr), "authorizers": authorizers}


def roster_trust_root(roster: dict) -> TrustRoot:
    """Build the :class:`vigil_core.TrustRoot` the witness signatures verify against — the exact object
    :func:`transparency.is_split_view_resistant` consumes. Same shape as
    ``sigil.spine.witness.witness_trust_root`` so the distinctness verdict is identical on both planes."""
    return TrustRoot(
        threshold=int(roster["threshold"]),
        authorizers=[AuthorizerKey(key_id=a["key_id"], name=a["key_id"], public_key_b64=a["public_key_b64"])
                     for a in roster["authorizers"]],
    )


def _distinct_key_count(tr: TrustRoot) -> "Optional[int]":
    """The number of DISTINCT canonical Ed25519 keys among the authorizers (dedup over the decoded 32-byte
    point, matching ``is_split_view_resistant``), or ``None`` if any key is non-canonical / low-order /
    malformed (fail-closed). Message-only — the pass/fail decision stays with ``is_split_view_resistant``."""
    try:
        return len({load_public_key(a.public_key_b64).public_bytes_raw() for a in tr.authorizers})
    except IntegrityError:
        return None


def _why_not_distinct(tr: TrustRoot) -> str:
    """A specific human reason a >=2-authorizer set is NOT a distinct strict-majority quorum. Called only
    AFTER ``is_split_view_resistant`` has already returned False, so it merely explains the verdict."""
    n = len(tr.authorizers)
    distinct = _distinct_key_count(tr)
    if distinct is None:
        return ("a configured witness key is non-canonical / low-order / malformed — rejected fail-closed "
                "(such a key admits a keyless signature forgery)")
    if distinct != n:
        return (f"{n} witnesses collapse to {distinct} distinct canonical key(s) — witnesses SHARE a key, "
                f"which defeats quorum intersection (two disjoint quorums could each sign a different fork). "
                f"Register witnesses with DISTINCT keys.")
    return (f"threshold {tr.threshold} is not a STRICT MAJORITY of {n} distinct witnesses "
            f"(need 2*threshold > {n}, i.e. threshold >= {strict_majority_threshold(n)})")


def roster_posture(path: "str | os.PathLike") -> "tuple[str, str]":
    """The production-fitness verdict of the configured witness set, as ``(state, detail)``.

    DELEGATES the distinctness decision to ``transparency.is_split_view_resistant`` (the strict-majority-of-
    distinct-canonical-keys rule already merged in the transparency log — REUSED, not copied):

      * ``DISTINCT-QUORUM`` — a strict majority of >=2 DISTINCT witnesses (production-fit; split-view
        resistant IFF those keys are held by INDEPENDENT parties, which code cannot verify);
      * ``SOLO`` — no roster configured (the shipped default is a solo self-witness) or exactly one witness:
        detection via retention, NOT prevention;
      * ``NOT-DISTINCT`` — >=2 authorizers that share a canonical key, a sub-majority threshold, or a
        non-canonical / low-order key (fail-closed);
      * ``UNKNOWN`` — the roster is present but unreadable / malformed (fail-closed, never treated as good).

    Only ``DISTINCT-QUORUM`` satisfies the production gate. Never raises."""
    try:
        roster = load_roster(path)
    except RosterError as e:
        return STATE_UNKNOWN, f"witness roster present but unreadable: {e}"
    if roster is None:
        return STATE_SOLO, (
            f"no production witness roster at {path} — the shipped default is a SOLO self-witness "
            f"(rollback DETECTION via off-box retention, NOT split-view prevention). Provision >=2 DISTINCT "
            f"witnesses: `python -m vigil_integration.witness_provision add` (mint one), or `register "
            f"--pubkey <B64> --key-id <id>` (an out-of-band independent witness).")
    tr = roster_trust_root(roster)
    n = len(tr.authorizers)
    # THE authority for pass/fail: the transparency log's strict-majority-of-distinct-keys rule.
    resistant = is_split_view_resistant(tr)
    if resistant and n >= 2:
        return STATE_DISTINCT_QUORUM, (
            f"{n} DISTINCT witnesses, threshold {tr.threshold} (a strict majority) — split-view RESISTANT "
            f"IFF the keys are held by INDEPENDENT parties (independence is a deployment property this check "
            f"cannot verify).")
    if n <= 1:
        return STATE_SOLO, (
            f"only {n} witness configured — a solo self-witness is rollback DETECTION, not split-view "
            f"prevention. Register at least one more DISTINCT witness to reach a strict-majority quorum.")
    return STATE_NOT_DISTINCT, _why_not_distinct(tr)


# --------------------------------------------------------------------------------------------------------
# provisioning — mint / register a witness, RECOMPUTE the strict-majority threshold, persist atomically
# --------------------------------------------------------------------------------------------------------
def _write_roster_atomic(path: Path, threshold: int, authorizers: "list[dict]") -> dict:
    core = {"schema": _ROSTER_SCHEMA, "threshold": int(threshold),
            "authorizers": [{"key_id": str(a["key_id"]), "public_key_b64": str(a["public_key_b64"])}
                            for a in authorizers]}
    payload = json.dumps(core, sort_keys=True, indent=2).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    # 0600 — the roster names the deployment's trusted witnesses; write it owner-only + atomically so a
    # concurrent reader (the doctor probe) never sees a half-written roster.
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(str(tmp), str(path))
    return core


def write_roster(path: "str | os.PathLike", threshold: int, authorizers: "list[dict]") -> dict:
    """Validate + atomically persist a roster (0600). Rejects an empty set, a sub-1 or over-n threshold,
    a duplicate key_id, and a malformed authorizer — the same fail-closed rules as :func:`load_roster`."""
    auths = _parse_authorizers(authorizers)
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise RosterError("threshold must be an integer >= 1")
    if threshold > len(auths):
        raise RosterError(f"threshold {threshold} exceeds the {len(auths)} configured witnesses")
    return _write_roster_atomic(Path(path), threshold, auths)


def register_authorizer(path: "str | os.PathLike", *, key_id: str, public_key_b64: str) -> dict:
    """Add witness ``(key_id, public_key_b64)`` to the roster at ``path`` (creating it if absent) and
    RECOMPUTE the strict-majority threshold. Returns the new roster core.

    Fail-closed on a NON-DISTINCT registration: a public key whose canonical bytes already appear in the
    roster (any base64 encoding, any key_id) is REFUSED — so the tooling can never itself build a roster
    that ``is_split_view_resistant`` would reject. A malformed / low-order / non-canonical key is likewise
    refused (validated via ``load_public_key``)."""
    if not isinstance(key_id, str) or not key_id.strip():
        raise RosterError("a witness needs a non-empty key_id")
    key_id = key_id.strip()
    try:
        new_bytes = load_public_key(public_key_b64).public_bytes_raw()
    except (IntegrityError, ValueError, TypeError) as e:
        raise RosterError(f"witness public key is malformed / non-canonical / low-order: {e}") from e
    existing = load_roster(path)
    authorizers = list(existing["authorizers"]) if existing else []
    for a in authorizers:
        if a["key_id"] == key_id:
            raise RosterError(f"a witness with key_id {key_id!r} is already registered")
        # Compare on CANONICAL bytes (dedup like is_split_view_resistant). A stored entry that no longer
        # parses is itself a fault surfaced here — kept in its OWN try so it never swallows the distinct-key
        # RosterError below (RosterError subclasses ValueError, so a broad except would eat it).
        try:
            existing_bytes = load_public_key(a["public_key_b64"]).public_bytes_raw()
        except (IntegrityError, ValueError, TypeError) as e:
            raise RosterError(f"an existing roster entry {a['key_id']!r} has an unparseable key — "
                              f"repair the roster before registering more witnesses") from e
        if existing_bytes == new_bytes:
            raise RosterError(
                f"that public key is already registered (as {a['key_id']!r}); a witness roster must be "
                f"DISTINCT — quorum intersection needs distinct canonical keys")
    authorizers.append({"key_id": key_id, "public_key_b64": public_key_b64})
    return _write_roster_atomic(Path(path), strict_majority_threshold(len(authorizers)), authorizers)


def provision_witness(*, key_path: "str | os.PathLike", roster_path: "str | os.PathLike",
                      key_id: str = "") -> dict:
    """Stand up a NEW local witness end-to-end: MINT a persistent Ed25519 keypair at ``key_path`` (0600, on
    first run) and REGISTER its public key in the roster at ``roster_path`` with a recomputed strict-majority
    threshold — no hand-editing. Returns ``{key_id, public_key_b64, key_path, roster, posture}``.

    HONEST: a freshly-minted local key is a DISTINCT key, not an INDEPENDENT PARTY. Two local ``add``s make
    the roster arithmetically split-view-resistant, but genuine independence needs the second witness on a
    DIFFERENT operator's box — mint the key THERE (or `witness_service serve` it there) and `register` its
    advertised pubkey here out of band."""
    from .witness_service import load_or_create_witness_key  # lazy: mint path only, keeps the probe light
    kid, kp = load_or_create_witness_key(key_path, key_id=key_id)
    core = register_authorizer(roster_path, key_id=kid, public_key_b64=kp.public_key_b64)
    state, detail = roster_posture(roster_path)
    return {"key_id": kid, "public_key_b64": kp.public_key_b64, "key_path": str(key_path),
            "roster": core, "posture": {"state": state, "detail": detail}}


# --------------------------------------------------------------------------------------------------------
# CLI — `python -m vigil_integration.witness_provision {add,register,status}`
# --------------------------------------------------------------------------------------------------------
def _resolve_roster_arg(args: argparse.Namespace) -> Path:
    if getattr(args, "roster", ""):
        return Path(args.roster).expanduser()
    return roster_path(getattr(args, "repo", None) or None)


def _print_status(path: Path) -> None:
    state, detail = roster_posture(path)
    print(f"roster   : {path}")
    print(f"posture  : {state}")
    print(f"           {detail}")
    try:
        roster = load_roster(path)
    except RosterError as e:
        print(f"witnesses: (unreadable: {e})")
        return
    if roster is None:
        print("witnesses: (none — solo default)")
        return
    print(f"threshold: {roster['threshold']} of {len(roster['authorizers'])} "
          f"(strict majority needs 2*threshold > {len(roster['authorizers'])})")
    for a in roster["authorizers"]:
        print(f"  - {a['key_id']}  {a['public_key_b64'][:16]}…")


def _cmd_add(args: argparse.Namespace) -> int:
    path = _resolve_roster_arg(args)
    res = provision_witness(key_path=args.key, roster_path=path, key_id=args.key_id)
    print(f"minted witness key : {res['key_id']}  ({res['key_path']}, 0600)")
    print(f"public key         : {res['public_key_b64']}")
    print(f"registered into    : {path}")
    _print_status(path)
    return 0


def _cmd_register(args: argparse.Namespace) -> int:
    path = _resolve_roster_arg(args)
    try:
        register_authorizer(path, key_id=args.key_id, public_key_b64=args.pubkey)
    except RosterError as e:
        print(f"register REFUSED (fail-closed): {e}", file=sys.stderr)
        return 2
    print(f"registered witness {args.key_id!r} into {path}")
    _print_status(path)
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    _print_status(_resolve_roster_arg(args))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vigil-witness-provision",
        description="W8-3 — provision transparency-log witnesses and check production witness-set posture")
    p.add_argument("--repo", default="",
                   help="repo root (default: cwd) — locates the default roster under <repo>/.vigil-live/")
    p.add_argument("--roster", default="",
                   help=f"roster path override (else ${ROSTER_ENV}, else <repo>/.vigil-live/{_ROSTER_BASENAME})")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("add", help="MINT a new local witness key (0600) and register it (recompute quorum)")
    pa.add_argument("--key", required=True, help="path to the new witness's persistent key file (minted 0600)")
    pa.add_argument("--key-id", default="", help="override the witness key id (default: derived from pubkey)")
    pa.set_defaults(func=_cmd_add)

    pr = sub.add_parser("register",
                        help="register an OUT-OF-BAND independent witness by its advertised public key")
    pr.add_argument("--key-id", required=True, help="the witness's key id (a label; trust is the pinned key)")
    pr.add_argument("--pubkey", required=True, help="the witness's base64 Ed25519 public key (from GET /pubkey)")
    pr.set_defaults(func=_cmd_register)

    ps = sub.add_parser("status", help="show the roster + its production-fitness posture verdict")
    ps.set_defaults(func=_cmd_status)
    return p


def main(argv: "Optional[list[str]]" = None) -> int:
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
