"""
mcp.evidence_config — the OPERATOR-ONLY egress allowlist for the external-MCP EVIDENCE connector.

This is the CONSUME-side companion to :mod:`mcp.sensor`: it loads the operator-provisioned list of
EXTERNAL MCP servers that a :class:`MCPEvidenceSensor` may reach to pull evidence (a DB-schema server, a
logs/env server, …). It is a pure config-and-validation layer — it parses + validates a JSON file and
returns typed records. It reaches no host, runs no subprocess, resolves no secret, and mints nothing.

Why it is a SEPARATE provisioning surface (mirrors ``agents.egress_guard.provisioned_collector_hosts``):
  The evidence source is the OPERATOR'S OWN infrastructure — NOT an attack target. So the set of evidence
  servers is a SEPARATE AXIS from the engagement charter scope, and it is DISJOINT from it by doctrine: a
  recon/evidence source must be a third party disjoint from what we are attacking. This module does NOT
  read the charter — keeping the two axes decoupled is the point. The DROP-on-conflict (dropping any
  evidence host that overlaps the target scope) is applied by the INTEGRATOR at egress-allowlist-build
  time, exactly as ``build_engagement_allowlist`` drops ``collector_scope_conflicts`` — see
  ``agents.egress_guard.collector_scope_conflicts``. Feed ``evidence_egress_hosts(...)`` through that same
  conflict filter against the charter scope before trusting a host.

Doctrine, by construction (the CONSUME half is LEAD-not-FACT):
  * THIRD-PARTY SAY-SO. Whatever an external MCP evidence server returns is a third party's claim. It
    enters the world-model only as a provenance-labelled LEAD (an ``IntelSourceKind``, Admiralty C3),
    NEVER a FACT — a CRUCIBLE oracle must re-fire over a trusted-channel capture to promote it. This
    module does not touch that path at all; it only decides WHICH operator servers are reachable.
  * FAIL-CLOSED / DEFAULT-EMPTY. Absent file ⇒ ``[]`` (no evidence egress until the operator provisions
    it). A malformed file, an unsafe slug, or a bad entry never crashes and never widens reach — the bad
    entry is DROPPED (never half-registered), the rest load. ``load_evidence_servers`` NEVER raises.
  * NO WILDCARDS. An http server's URL host MUST be an exact IP LITERAL or a single hostname (no
    wildcard, no bare TLD, no public-suffix wildcard — mirrors ``_collector_host_too_broad``), so the
    never-liftable L3/L4 egress FLOOR's literal-only loopback/RFC1918 lift can apply to it.
  * SECRETS STAY REFERENCES. A bearer token is referenced ONLY by the env-var NAME that holds it
    (``auth_env``); an inline secret (``token``/``auth``/``password``/URL userinfo/…) is REFUSED. This
    module never resolves, stores, or logs a token value — only the env-var name.

Pure stdlib + ``framework.v2.common.paths`` only. No third-party deps, no ``sigil`` import, no intel/
oracle/finding construction.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..common import paths
from ..common.errors import CrucibleRootNotFound

__all__ = [
    "EvidenceServer",
    "EvidenceConfigIssue",
    "EVIDENCE_SERVERS_FILENAME",
    "load_evidence_servers",
    "load_evidence_servers_with_issues",
    "evidence_egress_hosts",
]

# The operator-only provisioning file, read from ``targets/<slug>/``. Gitignored by the operator in
# practice (it names internal infra); provisioned deliberately, never scaffolded by default.
EVIDENCE_SERVERS_FILENAME = "mcp-evidence-servers.json"

_TRANSPORTS: frozenset[str] = frozenset({"stdio", "http"})

# Server ids an operator-supplied evidence source may NOT claim. Two groups: (a) first-party / self
# identities — above all ``oracle`` (an evidence LEAD source must never masquerade as the sole FACT
# authority) — and (b) the reserved system MCP-server ids (mirrors
# ``tools.mcp_registry.SYSTEM_SERVER_IDS``). Compared case-insensitively.
_RESERVED_EVIDENCE_IDS: frozenset[str] = frozenset({
    "vigil", "crucible", "aegis", "sigil", "oracle", "self", "local", "localhost",
    "builtin", "built_in", "system", "internal", "core", "default", "none",
    "network_recon", "nmap", "nuclei", "metasploit", "playwright",
})

# An id is one conservative, portable token (mirrors ``tools.mcp_registry.MCPServer.id``).
_ID_RE = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_-]*")
# An env-var NAME (POSIX-ish): a letter/underscore start, then letters/digits/underscore. This is a NAME,
# never a value — the value is resolved out-of-band at request time by the transport, never here.
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# One DNS label: 1–63 chars, alnum ends, hyphens allowed inside.
_HOSTNAME_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")

# Inline-secret key names that are REFUSED on an entry (normalised: lowercased, separators stripped). The
# ONLY sanctioned way to carry a credential is ``auth_env`` (normalises to "authenv", which is NOT here),
# so these never collide with the allowed field. An entry bearing any of these is dropped.
_INLINE_SECRET_KEYS: frozenset[str] = frozenset({
    "auth", "token", "password", "passwd", "passphrase", "bearer", "secret", "apikey",
    "credential", "credentials", "accesstoken", "privatekey", "pat", "jwt", "cookie",
    "sessiontoken", "key", "authorization",
})

# Secret-bearing SUBSTRINGS: a key whose normalised form CONTAINS one of these is ALSO refused, so a common
# compound name the exact set misses — ``auth_token``/``authToken`` → "authtoken", ``api_token``,
# ``client_secret``, ``x_api_key`` — cannot slip past. Chosen so the ONE sanctioned reference, ``auth_env``
# (normalises to "authenv"), contains none of them: bare "auth"/"key" are deliberately NOT stems here (they
# stay EXACT-match in the set above) precisely because "authenv" contains "auth".
_SECRET_STEMS: frozenset[str] = frozenset({
    "token", "secret", "password", "passwd", "passphrase", "apikey", "credential", "bearer",
    "privatekey", "sessiontoken", "accesstoken", "jwt", "cookie",
})

# Bounds on the (operator-authored, but still defensively bounded) config.
_MAX_SERVERS = 64
_MAX_STR = 4096
_MAX_ARGS = 128
_MAX_TOOLS = 256
_MAX_ID = 64
_MAX_ENV_NAME = 128
_MAX_HOSTNAME = 253

# Common multi-label public suffixes — a VERBATIM mirror of ``agents.egress_guard._PUBLIC_2LABEL_SUFFIXES``
# (egress_guard.py:113). Kept in sync by ``tests/test_evidence_config.py::test_host_too_broad_mirrors_...``
# (best-effort drift guard). A wildcard whose base IS a public suffix opens an enormous egress range.
_PUBLIC_2LABEL_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
    "com.br", "co.in", "com.cn", "co.za", "com.mx", "com.sg", "co.kr",
})


@dataclass(frozen=True)
class EvidenceServer:
    """One validated external MCP evidence server (operator infrastructure).

    Fields:
      * ``id``          — unique, non-reserved identifier (``^[A-Za-z0-9_][A-Za-z0-9_-]*$``, ≤64).
      * ``transport``   — ``"stdio"`` (local subprocess) or ``"http"`` (remote server).
      * ``command``     — stdio: the executable to spawn (``None`` for http).
      * ``args``        — stdio: the argv tail (``()`` for http).
      * ``url``         — http: the full server URL — scheme ``http``/``https``, no userinfo
                          (``None`` for stdio).
      * ``host``        — http: the egress host parsed from ``url`` — an exact IP literal or a single
                          hostname, NEVER a wildcard (``None`` for stdio). This is the value the operator
                          egress allowlist is built from.
      * ``auth_env``    — the NAME of an env var holding a bearer token, or ``None``. Never the token
                          itself — the value is resolved out-of-band by the transport at request time.
      * ``allowed_tools`` — optional tuple of remote tool names this server may expose. ``()`` means no
                          extra per-tool restriction FROM THIS CONFIG (the downstream gate chain still
                          applies); a non-empty tuple restricts to exactly those names.
    """

    id: str
    transport: str
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    host: str | None = None
    auth_env: str | None = None
    allowed_tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceConfigIssue:
    """A structured, NON-SECRET reason an evidence-server entry (or the file) was rejected — for an
    operator UI / log. ``server_id`` is the offending entry's id (or a placeholder). ``message`` names
    the field/key at fault but NEVER echoes a secret, a URL, a command string, or an arg value."""

    server_id: str
    code: str
    message: str


# =============================================================================
# HOST / FIELD VALIDATORS (pure, stdlib-only)
# =============================================================================


def _host_too_broad(h: str) -> bool:
    """A VERBATIM mirror of ``agents.egress_guard._collector_host_too_broad`` (egress_guard.py:119): a
    bare ``*``, a single-label wildcard (``*.com``/``*.internal``), or a public-suffix wildcard
    (``*.co.uk``) opens a whole TLD / public suffix (an exfil footgun). A concrete apex, or a wildcard
    whose base has ≥2 PRIVATE labels, is not 'too broad' BY THIS RULE — but note the http path below is
    STRICTER still (it rejects EVERY wildcard, broad or not)."""
    h = h.strip().strip(".").lower()
    if not h or h in ("*", "*.*"):
        return True
    if not h.startswith("*."):
        return False
    base = h[2:]
    if not base or "." not in base:
        return True
    return base in _PUBLIC_2LABEL_SUFFIXES


def _is_ip_literal(host: str) -> bool:
    """True iff ``host`` is an exact IPv4/IPv6 literal (``urlsplit`` already de-brackets IPv6)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_single_hostname(host: str) -> bool:
    """True iff ``host`` is a syntactically valid single hostname (one or more DNS labels, no wildcard,
    ≤253 chars). A single label (e.g. ``evidence-db``) is permitted — 'a single hostname'."""
    if not host or len(host) > _MAX_HOSTNAME or "*" in host:
        return False
    labels = host.split(".")
    return all(_HOSTNAME_LABEL_RE.fullmatch(lbl) for lbl in labels)


def _normalise_key(key: Any) -> str:
    """Normalise a dict key for secret-name matching: lowercase, strip ``-``/``_``. Non-str → ''."""
    if not isinstance(key, str):
        return ""
    return key.lower().replace("-", "").replace("_", "")


def _clip_str(value: Any, limit: int = _MAX_STR) -> str | None:
    """Return a non-empty, control-char-free, length-bounded string, else ``None``. Rejects (does not
    truncate) an over-long value — an over-long operator field is a misconfiguration, not input to trim.
    Rejects embedded NUL / newline / carriage-return (shell / log-injection hygiene)."""
    if not isinstance(value, str):
        return None
    if not value or len(value) > limit:
        return None
    if any(c in value for c in ("\x00", "\n", "\r")):
        return None
    return value


# =============================================================================
# PER-ENTRY PARSE (fail-closed: a bad entry yields an issue + is dropped, never half-registered)
# =============================================================================


def _inline_secret_issue(sid: str, entry: dict) -> EvidenceConfigIssue | None:
    """Refuse an entry that inlines a credential. Only ``auth_env`` (an env-var NAME) may carry a secret
    reference; a literal ``token``/``auth``/``password``/… key is a config error. The message names the
    offending KEY, never its value."""
    for raw_key in entry:
        nk = _normalise_key(raw_key)
        if nk in _INLINE_SECRET_KEYS or any(stem in nk for stem in _SECRET_STEMS):
            return EvidenceConfigIssue(
                server_id=sid, code="inline_secret",
                message=(f"inline secret field {str(raw_key)!r} is not allowed; reference a credential "
                         f"only by env-var NAME via 'auth_env'"))
    return None


def _parse_auth_env(sid: str, entry: dict) -> tuple[str | None, EvidenceConfigIssue | None]:
    """Validate the optional ``auth_env`` — it must be a valid env-var NAME (never a token value)."""
    if "auth_env" not in entry or entry.get("auth_env") is None:
        return None, None
    raw = entry.get("auth_env")
    if not isinstance(raw, str) or not _ENV_NAME_RE.fullmatch(raw) or len(raw) > _MAX_ENV_NAME:
        return None, EvidenceConfigIssue(
            server_id=sid, code="bad_auth_env",
            message="'auth_env' must be an env-var NAME (^[A-Za-z_][A-Za-z0-9_]*$), not a token value")
    return raw, None


def _parse_allowed_tools(sid: str, entry: dict) -> tuple[tuple[str, ...], EvidenceConfigIssue | None]:
    """Validate the optional ``allowed_tools`` — a bounded list of non-empty tool-name strings. Malformed
    ⇒ reject the whole entry (it is a security-relevant allowlist; a silently-dropped item could widen)."""
    if "allowed_tools" not in entry or entry.get("allowed_tools") is None:
        return (), None
    raw = entry.get("allowed_tools")
    if not isinstance(raw, list) or len(raw) > _MAX_TOOLS:
        return (), EvidenceConfigIssue(server_id=sid, code="bad_allowed_tools",
                                       message="'allowed_tools' must be a list of <=256 tool-name strings")
    tools: list[str] = []
    for item in raw:
        clipped = _clip_str(item, _MAX_STR)
        if clipped is None:
            return (), EvidenceConfigIssue(
                server_id=sid, code="bad_allowed_tools",
                message="'allowed_tools' entries must be non-empty, length-bounded strings")
        tools.append(clipped)
    # de-dup, preserve order
    return tuple(dict.fromkeys(tools)), None


def _parse_http_host(sid: str, url: str) -> tuple[str | None, EvidenceConfigIssue | None]:
    """Parse + validate an http server URL, returning its egress host. The host MUST be an exact IP
    literal or a single hostname — NO wildcard (even a non-'too-broad' one), no bare TLD wildcard, no
    public-suffix wildcard — so the egress floor's literal-only loopback/RFC1918 lift can apply. The URL
    must be http/https and carry NO userinfo (inline credentials). On any failure the message avoids
    echoing the raw URL (it may carry a query token / userinfo)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None, EvidenceConfigIssue(server_id=sid, code="bad_url", message="'url' is unparseable")
    if parts.scheme not in ("http", "https"):
        return None, EvidenceConfigIssue(server_id=sid, code="bad_url_scheme",
                                         message="http server 'url' scheme must be http or https")
    if parts.username or parts.password or "@" in parts.netloc:
        return None, EvidenceConfigIssue(
            server_id=sid, code="inline_secret",
            message="http 'url' must not carry userinfo/credentials; reference a token via 'auth_env'")
    if parts.query or parts.fragment:
        # A query/fragment is an inline-secret vector (``?api_key=…``) that would ride in the stored URL
        # and leak via a repr/log/error; an MCP JSON-RPC endpoint needs NEITHER. Refuse it at the source,
        # mirroring the userinfo refusal — the message never echoes the raw URL (it may carry the token).
        return None, EvidenceConfigIssue(
            server_id=sid, code="inline_secret",
            message="http 'url' must not carry a query or fragment (an inline-secret vector; reference a "
                    "token via 'auth_env')")
    try:
        host = parts.hostname  # lowercased, IPv6 de-bracketed; may raise on a malformed netloc
        _ = parts.port         # validates the port is numeric / in range
    except ValueError:
        return None, EvidenceConfigIssue(server_id=sid, code="bad_url",
                                         message="http server 'url' has a malformed host/port")
    if not host:
        return None, EvidenceConfigIssue(server_id=sid, code="bad_url",
                                         message="http server 'url' has no host")
    if "*" in host:
        return None, EvidenceConfigIssue(
            server_id=sid, code="wildcard_host",
            message=(f"http host {host!r} is a wildcard; an evidence host must be an exact IP literal or "
                     f"a single hostname so the egress floor can pin it"))
    if _host_too_broad(host):
        return None, EvidenceConfigIssue(
            server_id=sid, code="over_broad_host",
            message=f"http host {host!r} is over-broad (a whole TLD / public-suffix range)")
    if not (_is_ip_literal(host) or _is_single_hostname(host)):
        return None, EvidenceConfigIssue(
            server_id=sid, code="bad_host",
            message=f"http host {host!r} is not an exact IP literal or a single valid hostname")
    return host, None


def _parse_entry(entry: Any, index: int) -> tuple[EvidenceServer | None, EvidenceConfigIssue | None]:
    """Validate ONE raw entry into an :class:`EvidenceServer`, or an :class:`EvidenceConfigIssue`.

    Returns ``(server, None)`` on success or ``(None, issue)`` on rejection. The id (``sid``) is kept
    for the caller's duplicate check. Does the id / reserved-id / transport / per-transport-field /
    inline-secret / auth_env / allowed_tools checks — all fail-closed."""
    placeholder = f"<index {index}>"
    if not isinstance(entry, dict):
        return None, EvidenceConfigIssue(server_id=placeholder, code="not_an_object",
                                         message="each evidence server must be a JSON object")

    raw_id = entry.get("id")
    sid = raw_id if isinstance(raw_id, str) and raw_id else placeholder
    if not isinstance(raw_id, str) or not _ID_RE.fullmatch(raw_id) or len(raw_id) > _MAX_ID:
        return None, EvidenceConfigIssue(
            server_id=sid, code="bad_id",
            message="'id' must match ^[A-Za-z0-9_][A-Za-z0-9_-]*$ (<=64 chars)")
    if raw_id.lower() in _RESERVED_EVIDENCE_IDS:
        return None, EvidenceConfigIssue(server_id=raw_id, code="reserved_id",
                                         message=f"id '{raw_id}' is reserved and may not be claimed")

    secret_issue = _inline_secret_issue(raw_id, entry)
    if secret_issue is not None:
        return None, secret_issue

    transport = entry.get("transport")
    if transport not in _TRANSPORTS:
        return None, EvidenceConfigIssue(server_id=raw_id, code="bad_transport",
                                         message="'transport' must be 'stdio' or 'http'")

    auth_env, auth_issue = _parse_auth_env(raw_id, entry)
    if auth_issue is not None:
        return None, auth_issue
    allowed_tools, tools_issue = _parse_allowed_tools(raw_id, entry)
    if tools_issue is not None:
        return None, tools_issue

    if transport == "stdio":
        command = _clip_str(entry.get("command"), _MAX_STR)
        if command is None:
            return None, EvidenceConfigIssue(
                server_id=raw_id, code="missing_command",
                message="stdio server requires a non-empty 'command' string")
        raw_args = entry.get("args", [])
        if raw_args is None:
            raw_args = []
        if not isinstance(raw_args, list) or len(raw_args) > _MAX_ARGS:
            return None, EvidenceConfigIssue(server_id=raw_id, code="bad_args",
                                             message="stdio 'args' must be a list of <=128 strings")
        args: list[str] = []
        for a in raw_args:
            clipped = _clip_str(a, _MAX_STR)
            if clipped is None:
                return None, EvidenceConfigIssue(
                    server_id=raw_id, code="bad_args",
                    message="stdio 'args' entries must be non-empty, length-bounded strings")
            args.append(clipped)
        # stdio runs a local subprocess: NO egress host, so url/host are None by construction (any stray
        # 'url' on a stdio entry is irrelevant — it is never dialled — so it is ignored, not an egress).
        return EvidenceServer(
            id=raw_id, transport="stdio", command=command, args=tuple(args),
            url=None, host=None, auth_env=auth_env, allowed_tools=allowed_tools), None

    # transport == "http"
    url = _clip_str(entry.get("url"), _MAX_STR)
    if url is None:
        return None, EvidenceConfigIssue(server_id=raw_id, code="missing_url",
                                         message="http server requires a non-empty 'url' string")
    host, host_issue = _parse_http_host(raw_id, url)
    if host_issue is not None:
        return None, host_issue
    return EvidenceServer(
        id=raw_id, transport="http", command=None, args=(),
        url=url, host=host, auth_env=auth_env, allowed_tools=allowed_tools), None


# =============================================================================
# FILE LOAD (fail-closed, default-empty, never raises)
# =============================================================================


def _slug_safe(slug: Any) -> bool:
    """A slug is a single path component (mirrors ``agents.egress_guard._slug_safe``): reject traversal /
    separators / absolute / leading-dot so a crafted slug can never read a file outside targets/<slug>/."""
    s = str(slug or "")
    return bool(s) and ".." not in s and "/" not in s and "\\" not in s and ":" not in s \
        and not s.startswith(".")


def _config_path(slug: str, root: "str | Path | None") -> Path:
    """Resolve ``targets/<slug>/mcp-evidence-servers.json``. ``root`` (a test / deployment override) is
    the crucible root; ``None`` falls back to ``paths.target_dir(slug)`` (the real repo layout)."""
    if root is None:
        return paths.target_dir(slug) / EVIDENCE_SERVERS_FILENAME
    return Path(root) / "targets" / slug / EVIDENCE_SERVERS_FILENAME


def load_evidence_servers_with_issues(
    slug: str, *, root: "str | Path | None" = None,
) -> tuple[list[EvidenceServer], list[EvidenceConfigIssue]]:
    """Load + validate the operator-only evidence-server allowlist for ``slug``, returning
    ``(servers, issues)``. NEVER raises: an unsafe slug, an unresolvable root, a missing file, malformed
    JSON, or a bad entry all degrade to an empty/partial list plus NON-SECRET issue records (fail-closed,
    default-empty, never a wildcard, never half-registered). Duplicate ids (case-insensitive) are
    rejected — the FIRST wins, every later collision is dropped with an issue."""
    issues: list[EvidenceConfigIssue] = []
    if not _slug_safe(slug):
        return [], [EvidenceConfigIssue(server_id=str(slug), code="unsafe_slug",
                                        message="slug is not a single safe path component")]

    try:
        path = _config_path(slug, root)
    except CrucibleRootNotFound:  # no root resolvable and none supplied ⇒ fail closed, no file loaded
        return [], [EvidenceConfigIssue(server_id=str(slug), code="root_unresolved",
                                        message="could not resolve the targets root (no file loaded)")]

    try:
        if not path.is_file():
            return [], []          # DEFAULT-EMPTY: no provisioning ⇒ no evidence egress (normal, no issue)
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [EvidenceConfigIssue(server_id=str(slug), code="unreadable_file",
                                        message=f"could not read {EVIDENCE_SERVERS_FILENAME}")]

    try:
        payload = json.loads(text)
    except ValueError:
        return [], [EvidenceConfigIssue(server_id=str(slug), code="malformed_file",
                                        message=f"{EVIDENCE_SERVERS_FILENAME} is not well-formed JSON")]
    if not isinstance(payload, list):
        return [], [EvidenceConfigIssue(
            server_id=str(slug), code="malformed_file",
            message=f"{EVIDENCE_SERVERS_FILENAME} must be a JSON list of server objects")]

    if len(payload) > _MAX_SERVERS:
        issues.append(EvidenceConfigIssue(
            server_id=str(slug), code="too_many_servers",
            message=f"only the first {_MAX_SERVERS} of {len(payload)} entries are loaded"))

    servers: list[EvidenceServer] = []
    seen_ids: set[str] = set()
    for i, entry in enumerate(payload[:_MAX_SERVERS]):
        server, issue = _parse_entry(entry, i)
        if issue is not None or server is None:
            if issue is not None:
                issues.append(issue)
            continue
        sid_l = server.id.lower()
        if sid_l in seen_ids:
            issues.append(EvidenceConfigIssue(
                server_id=server.id, code="duplicate_id",
                message=f"id '{server.id}' is already used by an earlier server (case-insensitive)"))
            continue
        seen_ids.add(sid_l)
        servers.append(server)
    return servers, issues


def load_evidence_servers(slug: str, *, root: "str | Path | None" = None) -> list[EvidenceServer]:
    """Load the operator-only external-MCP evidence-server allowlist for ``slug`` from
    ``targets/<slug>/mcp-evidence-servers.json`` and return the VALID servers (the primary interface the
    integrator calls).

    Default-EMPTY + fail-closed: an absent/malformed file, an unsafe slug, or a bad entry yields ``[]`` or
    the partial valid list — NEVER a crash, NEVER a wildcard host, NEVER a half-registered entry. Use
    :func:`load_evidence_servers_with_issues` to also surface WHY entries were rejected (operator UI)."""
    servers, _issues = load_evidence_servers_with_issues(slug, root=root)
    return servers


def evidence_egress_hosts(servers: "list[EvidenceServer] | tuple[EvidenceServer, ...]") -> tuple[str, ...]:
    """Project the http servers' hosts — the operator egress allowlist this axis contributes. Each is an
    exact IP literal or a single hostname (never a wildcard) by construction. The INTEGRATOR must still
    drop any that overlap the engagement target scope (``egress_guard.collector_scope_conflicts``) before
    trusting it — this axis is DISJOINT from the attack target scope by doctrine. De-duped, order-stable."""
    hosts = [s.host for s in servers if s.transport == "http" and s.host]
    return tuple(dict.fromkeys(h for h in hosts if h))
