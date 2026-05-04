"""
common.ethics — the inviolable gates.

Per FORGE PROTOCOL § 8: charter requirement, scope enforcement,
authorization on intake, no exfil, no backdoors. These gates are
load-bearing for the moral integrity of the framework. They live in
one file so they can be audited in one read.

Every entry point that touches a target must call the appropriate
require_* function before proceeding. Functions raise typed
EthicsViolation subclasses; callers must not silently catch them.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from . import paths
from .errors import (
    AuthorizationMissing,
    CharterMissing,
    CharterNotSigned,
    OutOfScope,
)


# ---------------------------------------------------------------------------
# Charter signature check
# ---------------------------------------------------------------------------

# The signature line in framework/templates/charter.md is:
#   Signed: `<name>`     Date: `__________`
# When unsigned the angle-bracketed placeholder remains. Anything that
# is not the literal placeholder counts as signed.
_SIGNATURE_LINE = re.compile(r"^Signed:\s*`?([^`\n]+?)`?\s*(?:Date:.*)?$", re.MULTILINE)
_PLACEHOLDER = re.compile(r"<\s*name\s*>", re.IGNORECASE)


def is_charter_signed(slug: str) -> tuple[bool, str]:
    """
    Return (signed, reason). signed=True means a non-placeholder name
    is on the 'Signed:' line. reason gives the raw evidence either way.
    """
    cp = paths.charter_path(slug)
    if not cp.is_file():
        return False, f"charter file missing at {cp}"
    text = cp.read_text(encoding="utf-8")

    m = _SIGNATURE_LINE.search(text)
    if not m:
        return False, "no 'Signed:' line found in charter"
    sig = m.group(1).strip().strip("`").strip()
    if not sig:
        return False, "'Signed:' line has empty value"
    if _PLACEHOLDER.search(sig):
        return False, f"signature is the unfilled placeholder ({sig!r})"
    return True, f"signed by {sig!r}"


def require_charter_signed(slug: str) -> None:
    cp = paths.charter_path(slug)
    if not cp.is_file():
        raise CharterMissing(f"no charter at {cp}")
    signed, reason = is_charter_signed(slug)
    if not signed:
        raise CharterNotSigned(
            f"charter for target {slug!r} is not signed: {reason}. "
            f"Edit {cp} and replace the placeholder name on the 'Signed:' line."
        )


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

# Section 2 of the charter template lists in-scope hosts in a markdown
# table. Parse permissively; err on the side of refusing.
_SCOPE_HEADER = re.compile(
    r"^##\s*2\.\s*In[- ]scope systems\b", re.MULTILINE | re.IGNORECASE
)
_NEXT_H2 = re.compile(r"^##\s+\d", re.MULTILINE)


def parse_scope(slug: str) -> list[str]:
    """Return the literal host strings from the charter scope table."""
    cp = paths.charter_path(slug)
    if not cp.is_file():
        raise CharterMissing(f"no charter at {cp}")
    text = cp.read_text(encoding="utf-8")
    m = _SCOPE_HEADER.search(text)
    if not m:
        return []
    after = text[m.end():]
    nxt = _NEXT_H2.search(after)
    block = after if nxt is None else after[: nxt.start()]

    hosts: list[str] = []
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if not cols:
            continue
        first = cols[0].strip("`").strip()
        # skip header / separator rows
        if not first:
            continue
        if set(first) <= {"-", " ", ":"}:
            continue
        if first.lower().startswith("host"):
            continue
        # strip trailing "(if any)" or similar parenthetical
        first = re.sub(r"\s*\(.*?\)\s*$", "", first).strip()
        if first:
            hosts.append(first)
    return hosts


def host_matches_scope(host: str, scope_entries: list[str]) -> bool:
    """Match a hostname against scope entries.

    Supports:
      - literal match
      - wildcard prefix (`*.example.com` matches any subdomain of example.com,
        and the apex `example.com` itself).
    """
    h = host.lower().strip().rstrip(".")
    if not h:
        return False
    for raw in scope_entries:
        e = raw.lower().strip().strip("`").rstrip(".")
        if not e:
            continue
        # tolerate "N/A" sentinels operators write when a row doesn't apply
        if e in {"n/a", "n\\/a", "none"}:
            continue
        if e.startswith("*."):
            base = e[2:]  # "example.com"
            if h == base or h.endswith("." + base):
                return True
        elif h == e:
            return True
    return False


def require_in_scope(slug: str, target_url: str) -> None:
    parsed = urlparse(target_url if "://" in target_url else "https://" + target_url)
    host = parsed.hostname
    if not host:
        raise OutOfScope(f"could not parse hostname from {target_url!r}")
    scope = parse_scope(slug)
    if not scope:
        raise OutOfScope(
            f"charter for {slug!r} declares no in-scope hosts; "
            f"cannot test {host!r}"
        )
    if not host_matches_scope(host, scope):
        raise OutOfScope(
            f"host {host!r} is not in the charter scope for {slug!r}. "
            f"Charter scope: {scope}"
        )


# ---------------------------------------------------------------------------
# Intake authorization ledger
# ---------------------------------------------------------------------------

# UTI may not draft against a URL until the operator has appended an
# attestation line to the ledger. Format:
#   2026-05-04T12:34:56Z | <operator-name> | <hostname>
# Lines starting with '#' are comments. The ledger is gitignored.

_LEDGER_HEADER = """\
# Operator attestation ledger for UTI intake.
#
# Each line below records that the operator has explicit authority to
# perform passive fingerprinting against a hostname.  UTI refuses to
# operate on any hostname not present here.
#
# Format:
#     <ISO-8601 UTC timestamp> | <operator-name> | <hostname>
#
# Example:
#     2026-05-04T12:34:56Z | satoshi | mrbeanpanel.com
#
# Edit by hand. UTI never writes to this file.
"""


def authorization_ledger() -> Path:
    return paths.authorization_ledger()


def is_authorized_for_intake(target_url: str) -> bool:
    led = authorization_ledger()
    if not led.is_file():
        return False
    parsed = urlparse(target_url if "://" in target_url else "https://" + target_url)
    h = (parsed.hostname or "").lower().strip().rstrip(".")
    if not h:
        return False
    for line in led.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            entry_host = parts[2].lower().strip().rstrip(".")
            if entry_host == h:
                return True
            if entry_host.startswith("*.") and h.endswith(entry_host[1:]):
                return True
    return False


def require_authorized_intake(target_url: str) -> None:
    if not is_authorized_for_intake(target_url):
        raise AuthorizationMissing(
            f"no operator-attested authorization for {target_url!r}.\n"
            f"Append a line to {authorization_ledger()} of the form:\n"
            f"    <ISO-8601 timestamp> | <operator-name> | <hostname>"
        )


def init_authorization_ledger() -> None:
    """Create the ledger with a header comment if it does not exist."""
    led = authorization_ledger()
    led.parent.mkdir(parents=True, exist_ok=True)
    if not led.exists():
        led.write_text(_LEDGER_HEADER, encoding="utf-8")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
