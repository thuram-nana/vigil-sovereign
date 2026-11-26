"""AS-26 (OPS-1) — the Z3R relay security guards, as pure, deterministic, OFFLINE logic.

The Z3R relay (spec §4.1 zone Z3R, §5) is a KEYLESS file mover: Z3 pulls reports into fixed LANDING DIRS
and pushes grants/leases/releases into read-only per-tenant dirs, with a PINNED rsync client, regular files
only (``--no-links``), and never a connection initiated the other way (B-1). The relay HOLDS NOTHING (R3):
it cannot read the owner vault, and a compromised relay can at most DELAY reports (showing STALE), never
forge or escalate (spec §4.3).

This module is the enforceable core of that posture, written so every rule is checkable WITHOUT a live AWS
account, a running rsync, or a network. The shell relay (``tools/z3r/z3r-relay.sh``) shells out to the CLI
here before it moves a byte, and ``integration/tests/test_aegis_relay_guard.py`` exercises the same pure
functions. Four acceptance guards (spec §9.3 AS-26 row) live here:

  * relay EACCES on the vault — the relay refuses a source that resolves into a forbidden root (the owner
    vault), and when a real read is attempted against an unreadable path the PermissionError is surfaced,
    never swallowed into a silent success;
  * hostile file names harmless — a path-traversal / absolute / control-char / odd-encoding file name can
    never escape the fixed landing dir; it is contained inside it or refused;
  * unauthenticated transport refused — the relay refuses any transport that is not mutually authenticated
    (an anonymous rsync daemon URL, a bare ``host::module`` daemon path, or ssh with host-key checking
    turned off);
  * CloudFront bypass refused — a request that reaches the origin without the per-tenant edge secret that
    CloudFront injects (a direct-to-origin / foreign-distribution request) is refused as ``shared_actor``.

STDLIB ONLY — no sigil, no framework, no vigil_core import (FATAL-2). Pure path/text analysis; it never
raises on bad input except as a typed :class:`RelayRefused`. Runnable as a CLI
(``python -m vigil_integration.aegis_relay_guard <subcommand>``; exit 1 on refusal, 0 when allowed), so it
can back ``tools/z3r/z3r-relay.sh``, the ``aegis-infra`` advisory job, and the deterministic offline tests.
"""
from __future__ import annotations

import hmac
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import PurePosixPath

# The rsync flags the relay MUST pin and MUST NOT carry. ``--no-links`` covers ONE threat only — a symlink
# in the transferred set is skipped, not followed — so a hostile symlink cannot redirect a write out of the
# landing dir. It does NOT make a hostile file NAME harmless: a path-traversal name (``../../x``) in the
# transferred set is a RECEIVER-SIDE concern handled by (a) rsync >= MIN_RSYNC_VERSION's client-side
# received-name sanitization (enforced by :func:`require_min_rsync_version`, fail-closed) and (b) the
# explicit lexical containment check :func:`contain_in_landing`. The forbidden flags re-open the holes the
# guards close.
REQUIRED_RSYNC_FLAGS: frozenset[str] = frozenset({"--no-links"})

# The minimum rsync the relay will run. rsync 3.2.5 added client-side sanitization of the file NAMES a
# (possibly hostile) sender supplies — without it the receiver trusts sender-chosen paths, which is exactly
# the hostile-filename threat. The relay FAILS CLOSED below this version (spec §4.3 relay-is-untrusted).
MIN_RSYNC_VERSION: tuple[int, int, int] = (3, 2, 5)
FORBIDDEN_RSYNC_FLAGS: frozenset[str] = frozenset({
    "--links", "-l", "--copy-links", "-L", "--copy-unsafe-links", "--keep-dirlinks", "-K",
    "-a", "--archive",            # -a implies -l (links); the relay enumerates flags explicitly instead
    "-e",                         # transport is chosen by the guard, never by a free-form --rsh/-e here
    "--rsh",
})

# Default forbidden source roots — the owner vault and sealed-key stores the keyless relay must never read.
# A caller passes its own set; these are the conservative defaults (R3 / spec §4.3 "owner and release roots").
DEFAULT_FORBIDDEN_ROOTS: tuple[str, ...] = (
    "/var/lib/vigil/vault",
    "/etc/vigil/vault",
    "secrets",
    "vault",
    ".sigil",
)

_EDGE_SECRET_HEADER = "X-Vigil-Edge-Secret"
_DISTRIBUTION_HEADER = "X-Amz-Cf-Id"   # present on a genuine CloudFront request; absent on direct-to-origin


class RelayRefused(ValueError):
    """A relay action is refused, fail-closed. Carries a stable ``reason`` token for logs and tests."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


# ==================================================================================================
# Guard 1 — hostile file names cannot escape the fixed landing dir.
# ==================================================================================================
def contain_in_landing(landing_dir: str, name: str) -> str:
    """Resolve ``name`` INSIDE ``landing_dir`` and return the contained absolute path, or raise
    :class:`RelayRefused`. A name is refused when it is empty, absolute, carries a NUL or other control
    byte, or — after normalisation — would resolve to anything outside the landing dir (``..`` traversal,
    a drive/UNC prefix, or a normalised path that climbs out). The landing dir itself is normalised first,
    so the containment check is against a canonical base. No filesystem access is performed, so the check
    is deterministic and safe to run on an untrusted name before any byte is written."""
    if not isinstance(name, str) or name == "":
        raise RelayRefused("empty file name", reason="empty_name")
    if "\x00" in name:
        raise RelayRefused("NUL byte in file name", reason="nul_byte")
    # Any C0 control character (newline, CR, tab, ...) in a transferred name is hostile — refuse it rather
    # than try to sanitise it. A legitimate report/grant name never contains one.
    if any(ord(ch) < 0x20 for ch in name):
        raise RelayRefused("control character in file name", reason="control_char")
    # A Windows-style drive or UNC prefix, or a leading slash, is an absolute path — never contained.
    if name.startswith(("/", "\\")) or (len(name) >= 2 and name[1] == ":"):
        raise RelayRefused(f"absolute file name refused: {name!r}", reason="absolute_name")
    base = PurePosixPath(os.path.normpath(landing_dir))
    # Normalise the candidate within the base and verify the result is still under the base. os.path.normpath
    # collapses ``a/../../b`` etc. WITHOUT touching the filesystem (no symlink following — that is rsync's
    # --no-links job), so this is a pure lexical containment check.
    candidate = PurePosixPath(os.path.normpath(str(base / name)))
    if candidate != base and base not in candidate.parents:
        raise RelayRefused(f"file name escapes the landing dir: {name!r}", reason="escapes_landing")
    if candidate == base:
        raise RelayRefused(f"file name resolves to the landing dir itself: {name!r}", reason="is_landing")
    return str(candidate)


# ==================================================================================================
# Guard 2 — the keyless relay refuses to read the vault (and surfaces a real EACCES).
# ==================================================================================================
def _normalise(path: str) -> PurePosixPath:
    return PurePosixPath(os.path.normpath(path))


def assert_source_not_forbidden(source: str, forbidden_roots: "tuple[str, ...]" = DEFAULT_FORBIDDEN_ROOTS) -> None:
    """Refuse a relay SOURCE that is, or lives under, a forbidden root (the owner vault / sealed-key store).
    The relay is keyless (R3): it must never even attempt to read those paths. An absolute forbidden root
    matches by path prefix; a bare segment (``vault`` / ``secrets`` / ``.sigil``) matches if it appears as
    any component of the source, so a vault nested anywhere in the source tree is caught. Fail-closed: an
    unparseable source is refused."""
    if not isinstance(source, str) or source == "":
        raise RelayRefused("empty source", reason="empty_source")
    src = _normalise(source)
    src_parts = set(src.parts)
    for root in forbidden_roots:
        if root.startswith("/"):
            base = _normalise(root)
            if src == base or base in src.parents:
                raise RelayRefused(f"source is under the forbidden vault root {root!r}", reason="vault_source")
        elif root in src_parts:
            raise RelayRefused(f"source contains a forbidden component {root!r}", reason="vault_component")


def read_source_or_eacces(path: str) -> int:
    """Attempt to enumerate ``path`` as the relay would before transferring it, letting a real EACCES
    surface. Returns the entry count on success; re-raises the underlying :class:`PermissionError` as a
    :class:`RelayRefused` (reason ``eacces``) so an unreadable vault is a REFUSAL, never a silent empty
    success. This is the live half of guard 2 — the offline test points it at a ``chmod 000`` directory and
    asserts the refusal, without any AWS."""
    try:
        if os.path.isdir(path):
            return len(os.listdir(path))
        with open(path, "rb") as fh:   # noqa: PTH123 (stdlib-only by design)
            fh.read(1)
        return 1
    except PermissionError as exc:
        raise RelayRefused(f"EACCES reading relay source {path!r}", reason="eacces") from exc
    except FileNotFoundError as exc:
        raise RelayRefused(f"relay source not found {path!r}", reason="missing_source") from exc


# ==================================================================================================
# Guard 3 — unauthenticated transport is refused.
# ==================================================================================================
@dataclass
class TransportSpec:
    """A relay transport. ``kind`` is ``ssh`` (the only authenticated option) or a daemon/anonymous form.
    For ssh, ``strict_host_key_checking`` must be on AND a pinned ``known_hosts`` + an ``identity`` must be
    present — anything less is unauthenticated."""

    kind: str
    strict_host_key_checking: bool = False
    known_hosts: str = ""
    identity: str = ""
    raw: str = ""


def parse_transport(spec: str) -> TransportSpec:
    """Classify a transport string. An ``rsync://`` URL or a ``host::module`` path is the anonymous rsync
    DAEMON protocol (unauthenticated). Anything else is treated as an ssh target; its authentication is
    judged by :func:`require_authenticated_transport` from the fields the caller sets."""
    s = (spec or "").strip()
    if s.startswith("rsync://"):
        return TransportSpec(kind="rsync_daemon_url", raw=s)
    if "::" in s:
        return TransportSpec(kind="rsync_daemon_module", raw=s)
    return TransportSpec(kind="ssh", raw=s)


def require_authenticated_transport(spec: TransportSpec) -> None:
    """Refuse any transport that is not mutually authenticated. The anonymous rsync daemon protocol
    (``rsync://`` or ``host::module``) is refused outright. An ssh transport is accepted ONLY when host-key
    checking is on, a pinned ``known_hosts`` file is named, and an ``identity`` (key) is named — so a MITM
    (``StrictHostKeyChecking=no``) or an unauthenticated pull is refused (T-TR)."""
    if spec.kind in ("rsync_daemon_url", "rsync_daemon_module"):
        raise RelayRefused(
            f"anonymous rsync daemon transport refused ({spec.kind}): {spec.raw!r}",
            reason="unauthenticated_daemon")
    if spec.kind != "ssh":
        raise RelayRefused(f"unknown transport kind {spec.kind!r}", reason="unknown_transport")
    if not spec.strict_host_key_checking:
        raise RelayRefused("ssh host-key checking is off (MITM risk)", reason="no_host_key_check")
    if not spec.known_hosts:
        raise RelayRefused("no pinned known_hosts for the ssh transport", reason="no_known_hosts")
    if not spec.identity:
        raise RelayRefused("no ssh identity (key) for the transport", reason="no_identity")


# ==================================================================================================
# Guard 4 — a CloudFront bypass (direct-to-origin / foreign distribution) is refused.
# ==================================================================================================
def _header(headers: "dict[str, str]", name: str) -> str:
    """Case-insensitive header lookup; '' when absent."""
    low = name.lower()
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == low:
            return v if isinstance(v, str) else ""
    return ""


def assert_cloudfront_not_bypassed(
    headers: "dict[str, str]",
    expected_edge_secret: str,
    *,
    allowed_distribution_ids: "frozenset[str] | None" = None,
) -> None:
    """Refuse a request that reaches the VPC origin WITHOUT the per-tenant edge secret CloudFront injects.
    A direct-to-origin request carries no ``X-Vigil-Edge-Secret`` (or a wrong one) and is refused as
    ``shared_actor`` (T-PXY / CloudFront-bypass). The secret is compared in constant time. When
    ``allowed_distribution_ids`` is given, a genuine CloudFront request whose distribution id is not in the
    tenant's allow-set is also refused (a FOREIGN distribution fronting the origin). Fail-closed: a blank
    expected secret refuses everything (misconfiguration must not open the origin)."""
    if not expected_edge_secret:
        raise RelayRefused("no expected edge secret configured (fail closed)", reason="no_expected_secret")
    presented = _header(headers, _EDGE_SECRET_HEADER)
    if not presented:
        raise RelayRefused("direct-to-origin request: edge secret absent", reason="edge_secret_absent")
    if not hmac.compare_digest(presented, expected_edge_secret):
        raise RelayRefused("edge secret mismatch (bypass / forged)", reason="edge_secret_mismatch")
    if allowed_distribution_ids is not None:
        dist = _header(headers, "X-Vigil-Distribution-Id")
        if dist not in allowed_distribution_ids:
            raise RelayRefused(f"foreign distribution {dist!r} fronting the origin", reason="foreign_distribution")


# ==================================================================================================
# rsync argv pinning — the shell relay builds its command through here.
# ==================================================================================================
def validate_rsync_flags(flags: "list[str]") -> None:
    """Refuse an rsync invocation that drops a required flag (``--no-links``) or carries a forbidden one
    (anything that would follow links or let a free-form transport in). Fail-closed."""
    present = set(flags)
    missing = REQUIRED_RSYNC_FLAGS - present
    if missing:
        raise RelayRefused(f"rsync is missing required flags: {sorted(missing)}", reason="missing_flag")
    bad = present & FORBIDDEN_RSYNC_FLAGS
    if bad:
        raise RelayRefused(f"rsync carries forbidden flags: {sorted(bad)}", reason="forbidden_flag")


def parse_rsync_version(version_line: str) -> "tuple[int, int, int] | None":
    """Extract the (major, minor, patch) version from an ``rsync --version`` first line
    (e.g. ``rsync  version 3.2.7  protocol version 31``), or None when it cannot be parsed."""
    m = re.search(r"version\s+(\d+)\.(\d+)\.(\d+)", version_line or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def require_min_rsync_version(version_line: str, minimum: "tuple[int, int, int]" = MIN_RSYNC_VERSION) -> None:
    """Refuse to run an rsync older than ``minimum`` (the version that sanitizes sender-chosen file NAMES).
    Fail-closed: an UNPARSEABLE version line is a refusal, never assumed new enough — a relay that cannot
    prove its rsync sanitizes names does not transfer (the hostile-filename threat is real, so the floor is
    not optional)."""
    v = parse_rsync_version(version_line)
    if v is None:
        raise RelayRefused(f"could not parse rsync version from {version_line!r}", reason="rsync_version_unparsed")
    if v < minimum:
        raise RelayRefused(
            f"rsync {'.'.join(map(str, v))} is older than the minimum {'.'.join(map(str, minimum))} "
            f"(no client-side received-name sanitization)", reason="rsync_too_old")


@dataclass
class RelayPlan:
    """A validated, pinned relay plan the shell wrapper executes argument-for-argument."""

    rsync_bin: str
    direction: str                 # "pull" (reports -> landing) or "push" (grants -> per-tenant dir)
    source: str
    landing_dir: str
    flags: "list[str]" = field(default_factory=list)
    notes: "list[str]" = field(default_factory=list)


def plan_pull(rsync_bin: str, source: str, landing_dir: str,
              forbidden_roots: "tuple[str, ...]" = DEFAULT_FORBIDDEN_ROOTS) -> RelayPlan:
    """Build a validated PULL plan (reports -> landing dir). Pins ``--no-links``, refuses a vault source,
    and (lexically) refuses a landing dir that is itself a vault path. Raises :class:`RelayRefused` on any
    violation; the shell wrapper runs the returned plan verbatim."""
    assert_source_not_forbidden(source, forbidden_roots)
    assert_source_not_forbidden(landing_dir, forbidden_roots)
    flags = ["--no-links", "--recursive", "--times", "--prune-empty-dirs"]
    validate_rsync_flags(flags)
    return RelayPlan(rsync_bin=rsync_bin, direction="pull", source=source, landing_dir=landing_dir,
                     flags=flags, notes=["keyless pull; regular files only; fixed landing dir"])


# ==================================================================================================
# CLI — backs tools/z3r/z3r-relay.sh and the aegis-infra advisory job.
# ==================================================================================================
def _main(argv: "list[str]") -> int:
    import argparse  # noqa: PLC0415 (CLI-only; keep the import path light for the library users)

    p = argparse.ArgumentParser(prog="aegis_relay_guard", description="AS-26 Z3R relay guards")
    sub = p.add_subparsers(dest="cmd", required=True)

    pn = sub.add_parser("check-name", help="contain a transferred file name inside a landing dir")
    pn.add_argument("--landing-dir", required=True)
    pn.add_argument("--name", required=True)

    ps = sub.add_parser("check-source", help="refuse a vault/forbidden relay source")
    ps.add_argument("--source", required=True)

    pf = sub.add_parser("check-rsync-flags", help="validate a pinned rsync flag set")
    pf.add_argument("--flags", required=True, help="comma-joined rsync flags, e.g. '--no-links,--recursive'")

    pv = sub.add_parser("check-rsync-version", help="refuse an rsync below the minimum (name sanitization)")
    pv.add_argument("--line", required=True, help="the first line of `rsync --version`")

    pt = sub.add_parser("check-transport", help="refuse an unauthenticated transport")
    pt.add_argument("--spec", required=True)
    pt.add_argument("--strict-host-key-checking", action="store_true")
    pt.add_argument("--known-hosts", default="")
    pt.add_argument("--identity", default="")

    args = p.parse_args(argv)
    try:
        if args.cmd == "check-name":
            print(contain_in_landing(args.landing_dir, args.name))
        elif args.cmd == "check-source":
            assert_source_not_forbidden(args.source)
            print("source-ok")
        elif args.cmd == "check-rsync-flags":
            validate_rsync_flags([f for f in args.flags.split(",") if f])
            print("flags-ok")
        elif args.cmd == "check-rsync-version":
            require_min_rsync_version(args.line)
            print("rsync-version-ok")
        elif args.cmd == "check-transport":
            spec = parse_transport(args.spec)
            spec.strict_host_key_checking = args.strict_host_key_checking
            spec.known_hosts = args.known_hosts
            spec.identity = args.identity
            require_authenticated_transport(spec)
            print("transport-ok")
    except RelayRefused as exc:
        print(f"REFUSED[{exc.reason}]: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
