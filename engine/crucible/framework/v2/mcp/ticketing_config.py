"""
mcp.ticketing_config — the OPERATOR-ONLY egress allowlist for the ticketing-OUT (notification) connector.

This is the PUSH-side sibling of :mod:`mcp.evidence_config`. Where ``evidence_config`` loads the external
MCP servers a sensor may PULL evidence FROM, this loads the external ticketing systems the operator has
authorized a finding to be pushed OUT TO (start: GitHub Issues as the one connector). It is a pure
config-and-validation layer — it parses + validates a JSON file and returns typed records. It reaches no
host, runs no subprocess, resolves no secret, and mints nothing.

Why it is a SEPARATE provisioning surface (mirrors ``evidence_config`` / ``egress_guard``):
  A ticketing system is the OPERATOR'S OWN infrastructure (their issue tracker) — NOT an attack target. So
  the set of ticketing targets is a SEPARATE AXIS from the engagement charter scope, and it is DISJOINT
  from it by doctrine (you do not file your findings INTO the system you are attacking). This module does
  NOT read the charter — keeping the two axes decoupled is the point. A DROP-on-conflict against the
  charter scope is applied by the PUSH adapter at egress-allowlist-build time, exactly as the evidence
  connector feeds its hosts through ``egress_guard.collector_scope_conflicts``.

Doctrine, by construction (the PUSH half is a ONE-WAY NOTIFICATION — NEVER a FACT):
  * OUTBOUND-ONLY, LEAD/RECORD NOT FACT. A finding pushed OUT is a one-way notification. The connector
    reads NOTHING back into the world-model: the ticketing system's response (an issue number / URL) is a
    notification RECEIPT (a record), never promoted to a FACT. This module only decides WHICH operator
    ticketing targets are reachable; it never ingests, never constructs a Finding/Observation/grounding.
  * FAIL-CLOSED / DEFAULT-EMPTY. Absent file ⇒ ``[]`` (no ticketing egress — the connector is OFF until the
    operator provisions it). A malformed file, an unsafe slug, an unsafe tenant id, or a bad entry never
    crashes and never widens reach — the bad entry is DROPPED (never half-registered), the rest load.
    ``load_ticketing_targets`` NEVER raises.
  * NO WILDCARDS. A ticketing host MUST be an exact IP LITERAL or a single hostname (no wildcard, no bare
    TLD, no public-suffix wildcard — mirrors ``evidence_config._parse_http_host`` / ``egress_guard.
    _collector_host_too_broad``), so the never-liftable L3/L4 egress FLOOR's literal-only loopback/RFC1918
    lift can apply to it.
  * SECRETS STAY REFERENCES. An API token is referenced ONLY by the env-var NAME that holds it
    (``auth_env``, REQUIRED here — a ticketing API needs auth and we never push unauthenticated); an inline
    secret (``token``/``auth``/``password``/userinfo/…) is REFUSED. This module never resolves, stores, or
    logs a token value — only the env-var name.
  * (tenant_id, slug) KEYING. org == tenant_id (the shared enterprise-wave contract). Every loaded record
    is stamped with the active tenant (``common.paths.active_tenant`` — ``None`` when unsharded/single-
    tenant, handled as the default/global scope) AND the engagement ``slug``, so YOUR config + any audit
    record are keyed by ``(tenant_id, slug)``. The config FILE still lives at ``targets/<slug>/`` via the
    per-tenant ``CRUCIBLE_ROOT`` (``target_dir``) — this module does NOT re-wrap that path; it only adds
    ``tenant_id`` to its OWN record keys.

Pure stdlib + ``framework.v2.common.paths`` only. No third-party deps, no ``sigil`` import, no intel/
oracle/finding construction, no ``httpx`` (the egress lives in :mod:`mcp.ticketing_push`).
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common import paths
from ..common.errors import CrucibleRootNotFound

__all__ = [
    "TicketingTarget",
    "TicketingConfigIssue",
    "TICKETING_TARGETS_FILENAME",
    "TICKETING_KINDS",
    "load_ticketing_targets",
    "load_ticketing_targets_with_issues",
    "ticketing_egress_hosts",
    "find_ticketing_target",
]

# The operator-only provisioning file, read from ``targets/<slug>/``. Gitignored by the operator in
# practice (it names internal infra + an org/repo); provisioned deliberately, never scaffolded by default.
TICKETING_TARGETS_FILENAME = "ticketing-targets.json"

# The connectors this slice supports. Start with GitHub Issues as the ONE connector; a closed set so an
# unknown/typo'd kind is REFUSED (fail-closed) rather than silently accepted and later mis-dispatched.
TICKETING_KINDS: frozenset[str] = frozenset({"github_issues"})

# Target ids an operator-supplied ticketing entry may NOT claim. Mirrors ``evidence_config``: (a) first-
# party / self identities — above all ``oracle`` (a one-way notification sink must never masquerade as the
# sole FACT authority) — and (b) reserved system ids. Compared case-insensitively.
_RESERVED_IDS: frozenset[str] = frozenset({
    "vigil", "crucible", "aegis", "sigil", "oracle", "self", "local", "localhost",
    "builtin", "built_in", "system", "internal", "core", "default", "none",
})

# An id is one conservative, portable token (mirrors ``evidence_config._ID_RE``).
_ID_RE = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_-]*")
# An env-var NAME (POSIX-ish): a letter/underscore start, then letters/digits/underscore. This is a NAME,
# never a value — the value is resolved out-of-band at request time by the push adapter, never here.
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# One DNS label: 1–63 chars, alnum ends, hyphens allowed inside.
_HOSTNAME_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
# A repo "owner" segment (GitHub login): alnum start, then alnum/hyphen (no leading hyphen), ≤39.
_REPO_OWNER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
# A repo "name" segment: a conservative repo charset, ≤100. A leading ``.`` is allowed (the common
# org-level ``.github`` repo); the actual traversal tokens ``.``/``..`` are refused explicitly below. The
# segment has no ``/`` (``repo`` is split on it first), so a substring ``..`` is not a path-traversal risk.
_REPO_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")

# Inline-secret key names that are REFUSED on an entry (normalised: lowercased, separators stripped). A
# VERBATIM mirror of ``evidence_config._INLINE_SECRET_KEYS``. The ONLY sanctioned way to carry a credential
# is ``auth_env`` (normalises to "authenv", which is NOT here).
_INLINE_SECRET_KEYS: frozenset[str] = frozenset({
    "auth", "token", "password", "passwd", "passphrase", "bearer", "secret", "apikey",
    "credential", "credentials", "accesstoken", "privatekey", "pat", "jwt", "cookie",
    "sessiontoken", "key", "authorization",
})
# Secret-bearing SUBSTRINGS: a key whose normalised form CONTAINS one of these is ALSO refused (base set
# mirrors ``evidence_config._SECRET_STEMS``). Chosen so ``auth_env`` → "authenv" contains none of them, and
# none collide with this entry's legit keys (id/kind/host/repo/auth_env). The last three are a deliberate,
# CONNECTOR-SPECIFIC hardening over evidence_config (no mirror-drift test pins these): ``pat`` catches a
# GitHub Personal Access Token inlined as ``gh_pat`` / ``github_pat`` (the native credential for this
# github_issues connector); ``accesskey`` catches ``access_key`` / ``accessKey``; ``cred`` catches
# ``creds``. An inlined credential's VALUE is never read/stored/egressed regardless (only ``auth_env`` is),
# so this is a best-effort operator lint — it just refuses to silently accept a secret-at-rest in the file.
_SECRET_STEMS: frozenset[str] = frozenset({
    "token", "secret", "password", "passwd", "passphrase", "apikey", "credential", "bearer",
    "privatekey", "sessiontoken", "accesstoken", "jwt", "cookie",
    "pat", "accesskey", "cred",
})

# Bounds on the (operator-authored, but still defensively bounded) config.
_MAX_TARGETS = 64
_MAX_STR = 4096
_MAX_ID = 64
_MAX_ENV_NAME = 128
_MAX_HOSTNAME = 253
_MAX_REPO_SEGMENT = 100

# Common multi-label public suffixes — a VERBATIM mirror of ``evidence_config._PUBLIC_2LABEL_SUFFIXES`` /
# ``egress_guard._PUBLIC_2LABEL_SUFFIXES``. Kept in sync by
# ``tests/test_ticketing_config.py::test_host_too_broad_mirrors_evidence_config`` (best-effort drift guard).
_PUBLIC_2LABEL_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
    "com.br", "co.in", "com.cn", "co.za", "com.mx", "com.sg", "co.kr",
})


@dataclass(frozen=True)
class TicketingTarget:
    """One validated external ticketing target (operator infrastructure) a finding may be pushed OUT to.

    Fields:
      * ``id``        — unique, non-reserved identifier (``^[A-Za-z0-9_][A-Za-z0-9_-]*$``, ≤64).
      * ``kind``      — the connector kind; one of :data:`TICKETING_KINDS` (this slice: ``"github_issues"``).
      * ``host``      — the egress host — an exact IP literal or a single hostname, NEVER a wildcard. This is
                        the value the operator egress allowlist is built from (e.g. ``api.github.com``).
      * ``repo``      — ``"owner/repo"`` — the target repository the issue is filed under (each segment
                        validated; no traversal / separators / spaces).
      * ``auth_env``  — the NAME of an env var holding the API token (REQUIRED). Never the token itself —
                        the value is resolved out-of-band by the push adapter at request time.
      * ``tenant_id`` — the active tenant (``org``) scope key, or ``None`` when unsharded/single-tenant.
      * ``slug``      — the engagement slug this config was loaded for. ``(tenant_id, slug)`` is the scope
                        key for this record and any audit it drives.
    """

    id: str
    kind: str
    host: str
    repo: str
    auth_env: str
    tenant_id: str | None = None
    slug: str = ""

    @property
    def scope_key(self) -> tuple[str | None, str]:
        """The ``(tenant_id, slug)`` key this record (and any audit record it drives) is scoped by."""
        return (self.tenant_id, self.slug)


@dataclass(frozen=True)
class TicketingConfigIssue:
    """A structured, NON-SECRET reason a ticketing entry (or the file) was rejected — for an operator UI /
    log. ``target_id`` is the offending entry's id (or a placeholder). ``message`` names the field/key at
    fault but NEVER echoes a secret, a token, or URL userinfo."""

    target_id: str
    code: str
    message: str


# =============================================================================
# HOST / FIELD VALIDATORS (pure, stdlib-only — mirror evidence_config)
# =============================================================================


def _host_too_broad(h: str) -> bool:
    """A VERBATIM mirror of ``evidence_config._host_too_broad`` / ``egress_guard._collector_host_too_broad``:
    a bare ``*``, a single-label wildcard (``*.com``), or a public-suffix wildcard (``*.co.uk``) opens a
    whole TLD / public suffix. The ticketing path below is STRICTER still (it rejects EVERY wildcard)."""
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
    """True iff ``host`` is an exact IPv4/IPv6 literal."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_single_hostname(host: str) -> bool:
    """True iff ``host`` is a syntactically valid single hostname (one or more DNS labels, no wildcard,
    ≤253 chars). A single label (e.g. ``gitea-internal``) is permitted."""
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
    """A non-empty, control-char-free, length-bounded string, else ``None``. Rejects (does not truncate) an
    over-long value. Rejects embedded NUL / newline / carriage-return (header / log-injection hygiene)."""
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


def _inline_secret_issue(sid: str, entry: dict) -> TicketingConfigIssue | None:
    """Refuse an entry that inlines a credential. Only ``auth_env`` (an env-var NAME) may carry a secret
    reference. The message names the offending KEY, never its value."""
    for raw_key in entry:
        nk = _normalise_key(raw_key)
        if nk in _INLINE_SECRET_KEYS or any(stem in nk for stem in _SECRET_STEMS):
            return TicketingConfigIssue(
                target_id=sid, code="inline_secret",
                message=(f"inline secret field {str(raw_key)!r} is not allowed; reference a credential "
                         f"only by env-var NAME via 'auth_env'"))
    return None


def _parse_host(sid: str, entry: dict) -> tuple[str | None, TicketingConfigIssue | None]:
    """Validate the ``host`` field — an exact IP literal or a single hostname, NO wildcard (even a non-too-
    broad one), no scheme, no port, no userinfo — so the egress floor can pin it. The message never echoes a
    raw value that could carry a secret."""
    host = _clip_str(entry.get("host"), _MAX_HOSTNAME)
    if host is None:
        return None, TicketingConfigIssue(target_id=sid, code="missing_host",
                                          message="a ticketing target requires a non-empty 'host' string")
    host = host.strip()
    # The raw host is NEVER echoed in a message: an operator may paste a credentialed value
    # (userinfo/token/query), and the message lands in the operator UI / log. The field name + code identify
    # the problem without disclosing the secret (mirrors evidence_config._parse_http_host).
    if "*" in host:
        return None, TicketingConfigIssue(
            target_id=sid, code="wildcard_host",
            message=("the 'host' is a wildcard; a ticketing host must be an exact IP literal or a single "
                     "hostname so the egress floor can pin it (raw value omitted — it may carry a secret)"))
    if _host_too_broad(host):
        return None, TicketingConfigIssue(
            target_id=sid, code="over_broad_host",
            message="the 'host' is over-broad (a whole TLD / public-suffix range); raw value omitted")
    if not (_is_ip_literal(host) or _is_single_hostname(host)):
        return None, TicketingConfigIssue(
            target_id=sid, code="bad_host",
            message=("the 'host' is not an exact IP literal or a single valid hostname "
                     "(no scheme/port/userinfo); raw value omitted"))
    return host, None


def _parse_repo(sid: str, entry: dict) -> tuple[str | None, TicketingConfigIssue | None]:
    """Validate ``repo`` as ``"owner/repo"`` — EXACTLY two non-empty, bounded segments drawn from a
    conservative charset, with ``.``/``..`` refused. The repo rides in the issue-API URL PATH, so a stray
    separator / traversal / space must never slip through (path-injection hygiene)."""
    repo = _clip_str(entry.get("repo"), _MAX_STR)
    if repo is None:
        return None, TicketingConfigIssue(target_id=sid, code="missing_repo",
                                          message="a ticketing target requires a non-empty 'repo' string")
    parts = repo.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None, TicketingConfigIssue(
            target_id=sid, code="bad_repo",
            message="'repo' must be exactly 'owner/repo' (two non-empty segments)")
    owner, name = parts
    if len(owner) > 39 or not _REPO_OWNER_RE.fullmatch(owner):
        return None, TicketingConfigIssue(
            target_id=sid, code="bad_repo",
            message="'repo' owner must match ^[A-Za-z0-9][A-Za-z0-9-]*$ (<=39 chars, no leading hyphen)")
    if (len(name) > _MAX_REPO_SEGMENT or name in (".", "..")
            or not _REPO_NAME_RE.fullmatch(name)):
        return None, TicketingConfigIssue(
            target_id=sid, code="bad_repo",
            message="'repo' name must match ^[A-Za-z0-9._-]+$ (<=100 chars, not '.'/'..')")
    return f"{owner}/{name}", None


def _parse_auth_env(sid: str, entry: dict) -> tuple[str | None, TicketingConfigIssue | None]:
    """Validate the REQUIRED ``auth_env`` — it must be a valid env-var NAME (never a token value). A
    ticketing API needs auth and we never push unauthenticated, so an absent/empty ``auth_env`` is refused
    (unlike the evidence connector, where a token is optional)."""
    if "auth_env" not in entry or entry.get("auth_env") is None:
        return None, TicketingConfigIssue(
            target_id=sid, code="missing_auth_env",
            message="a ticketing target requires 'auth_env' (the NAME of an env var holding the API token)")
    raw = entry.get("auth_env")
    if not isinstance(raw, str) or not _ENV_NAME_RE.fullmatch(raw) or len(raw) > _MAX_ENV_NAME:
        return None, TicketingConfigIssue(
            target_id=sid, code="bad_auth_env",
            message="'auth_env' must be an env-var NAME (^[A-Za-z_][A-Za-z0-9_]*$), not a token value")
    return raw, None


def _parse_entry(
    entry: Any, index: int, *, tenant_id: str | None, slug: str,
) -> tuple[TicketingTarget | None, TicketingConfigIssue | None]:
    """Validate ONE raw entry into a :class:`TicketingTarget`, or a :class:`TicketingConfigIssue`.

    Returns ``(target, None)`` on success or ``(None, issue)`` on rejection. Does the id / reserved-id /
    kind / inline-secret / host / repo / auth_env checks — all fail-closed. The record is stamped with the
    ``(tenant_id, slug)`` scope key."""
    placeholder = f"<index {index}>"
    if not isinstance(entry, dict):
        return None, TicketingConfigIssue(target_id=placeholder, code="not_an_object",
                                          message="each ticketing target must be a JSON object")

    raw_id = entry.get("id")
    sid = raw_id if isinstance(raw_id, str) and raw_id else placeholder
    if not isinstance(raw_id, str) or not _ID_RE.fullmatch(raw_id) or len(raw_id) > _MAX_ID:
        return None, TicketingConfigIssue(
            target_id=sid, code="bad_id",
            message="'id' must match ^[A-Za-z0-9_][A-Za-z0-9_-]*$ (<=64 chars)")
    if raw_id.lower() in _RESERVED_IDS:
        return None, TicketingConfigIssue(target_id=raw_id, code="reserved_id",
                                          message=f"id '{raw_id}' is reserved and may not be claimed")

    secret_issue = _inline_secret_issue(raw_id, entry)
    if secret_issue is not None:
        return None, secret_issue

    kind = entry.get("kind")
    if kind not in TICKETING_KINDS:
        return None, TicketingConfigIssue(
            target_id=raw_id, code="bad_kind",
            message=f"'kind' must be one of {sorted(TICKETING_KINDS)} (this slice supports GitHub Issues)")

    host, host_issue = _parse_host(raw_id, entry)
    if host_issue is not None:
        return None, host_issue
    repo, repo_issue = _parse_repo(raw_id, entry)
    if repo_issue is not None:
        return None, repo_issue
    auth_env, auth_issue = _parse_auth_env(raw_id, entry)
    if auth_issue is not None:
        return None, auth_issue

    assert host is not None and repo is not None and auth_env is not None  # narrowed by the checks above
    return TicketingTarget(
        id=raw_id, kind=str(kind), host=host, repo=repo, auth_env=auth_env,
        tenant_id=tenant_id, slug=slug), None


# =============================================================================
# FILE LOAD (fail-closed, default-empty, never raises)
# =============================================================================


def _slug_safe(slug: Any) -> bool:
    """A slug is a single path component (mirrors ``evidence_config._slug_safe`` / ``egress_guard
    ._slug_safe``): reject traversal / separators / absolute / leading-dot so a crafted slug can never read
    a file outside targets/<slug>/."""
    s = str(slug or "")
    return bool(s) and ".." not in s and "/" not in s and "\\" not in s and ":" not in s \
        and not s.startswith(".")


def _config_path(slug: str, root: "str | Path | None") -> Path:
    """Resolve ``targets/<slug>/ticketing-targets.json``. ``root`` (a test / deployment override) is the
    crucible root; ``None`` falls back to ``paths.target_dir(slug)`` (the real, per-tenant repo layout —
    NOT re-wrapped here per the enterprise-wave contract)."""
    if root is None:
        return paths.target_dir(slug) / TICKETING_TARGETS_FILENAME
    return Path(root) / "targets" / slug / TICKETING_TARGETS_FILENAME


def _resolve_tenant() -> tuple[str | None, TicketingConfigIssue | None]:
    """Read the active tenant (``org``) FAIL-CLOSED. ``active_tenant`` returns ``None`` when unsharded
    (the default/global scope) and RAISES ``CrucibleRootNotFound`` on a set-but-UNSAFE ``CRUCIBLE_TENANT``;
    we degrade that raise to an issue (never crash — the loader never raises)."""
    try:
        return paths.active_tenant(), None
    except CrucibleRootNotFound:
        return None, TicketingConfigIssue(
            target_id="<tenant>", code="unsafe_tenant",
            message="CRUCIBLE_TENANT is set but not a safe path component (no ticketing target loaded)")


def load_ticketing_targets_with_issues(
    slug: str, *, root: "str | Path | None" = None,
) -> tuple[list[TicketingTarget], list[TicketingConfigIssue]]:
    """Load + validate the operator-only ticketing-target allowlist for ``slug``, returning
    ``(targets, issues)``. NEVER raises: an unsafe slug, an unsafe tenant id, an unresolvable root, a
    missing file, malformed JSON, or a bad entry all degrade to an empty/partial list plus NON-SECRET issue
    records (fail-closed, default-empty, never a wildcard, never half-registered). Duplicate ids (case-
    insensitive) are rejected — the FIRST wins, every later collision is dropped with an issue. Every loaded
    record is stamped with the ``(tenant_id, slug)`` scope key."""
    issues: list[TicketingConfigIssue] = []
    if not _slug_safe(slug):
        return [], [TicketingConfigIssue(target_id=str(slug), code="unsafe_slug",
                                         message="slug is not a single safe path component")]

    tenant_id, tenant_issue = _resolve_tenant()
    if tenant_issue is not None:
        return [], [tenant_issue]

    try:
        path = _config_path(slug, root)
    except CrucibleRootNotFound:  # no root resolvable and none supplied ⇒ fail closed, no file loaded
        return [], [TicketingConfigIssue(target_id=str(slug), code="root_unresolved",
                                         message="could not resolve the targets root (no file loaded)")]

    try:
        if not path.is_file():
            return [], []          # DEFAULT-EMPTY: no provisioning ⇒ connector OFF (normal, no issue)
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [TicketingConfigIssue(target_id=str(slug), code="unreadable_file",
                                         message=f"could not read {TICKETING_TARGETS_FILENAME}")]

    try:
        payload = json.loads(text)
    except ValueError:
        return [], [TicketingConfigIssue(target_id=str(slug), code="malformed_file",
                                         message=f"{TICKETING_TARGETS_FILENAME} is not well-formed JSON")]
    if not isinstance(payload, list):
        return [], [TicketingConfigIssue(
            target_id=str(slug), code="malformed_file",
            message=f"{TICKETING_TARGETS_FILENAME} must be a JSON list of target objects")]

    if len(payload) > _MAX_TARGETS:
        issues.append(TicketingConfigIssue(
            target_id=str(slug), code="too_many_targets",
            message=f"only the first {_MAX_TARGETS} of {len(payload)} entries are loaded"))

    targets: list[TicketingTarget] = []
    seen_ids: set[str] = set()
    for i, entry in enumerate(payload[:_MAX_TARGETS]):
        target, issue = _parse_entry(entry, i, tenant_id=tenant_id, slug=slug)
        if issue is not None or target is None:
            if issue is not None:
                issues.append(issue)
            continue
        sid_l = target.id.lower()
        if sid_l in seen_ids:
            issues.append(TicketingConfigIssue(
                target_id=target.id, code="duplicate_id",
                message=f"id '{target.id}' is already used by an earlier target (case-insensitive)"))
            continue
        seen_ids.add(sid_l)
        targets.append(target)
    return targets, issues


def load_ticketing_targets(slug: str, *, root: "str | Path | None" = None) -> list[TicketingTarget]:
    """Load the operator-only ticketing-target allowlist for ``slug`` from
    ``targets/<slug>/ticketing-targets.json`` and return the VALID targets (the primary interface the push
    adapter calls).

    Default-EMPTY + fail-closed: an absent/malformed file, an unsafe slug/tenant, or a bad entry yields
    ``[]`` or the partial valid list — NEVER a crash, NEVER a wildcard host, NEVER a half-registered entry.
    The connector is OFF until the operator provisions a target. Use
    :func:`load_ticketing_targets_with_issues` to also surface WHY entries were rejected (operator UI)."""
    targets, _issues = load_ticketing_targets_with_issues(slug, root=root)
    return targets


def find_ticketing_target(
    slug: str, target_id: str, *, root: "str | Path | None" = None,
) -> TicketingTarget | None:
    """Return the provisioned target whose ``id`` equals ``target_id`` (case-insensitive), or ``None`` if
    none is provisioned (the connector stays OFF). Convenience for the push adapter — never raises."""
    want = str(target_id or "").lower()
    if not want:
        return None
    for t in load_ticketing_targets(slug, root=root):
        if t.id.lower() == want:
            return t
    return None


def ticketing_egress_hosts(
    targets: "list[TicketingTarget] | tuple[TicketingTarget, ...]",
) -> tuple[str, ...]:
    """Project the targets' hosts — the operator egress allowlist this axis contributes. Each is an exact IP
    literal or a single hostname (never a wildcard) by construction. The PUSH adapter must still drop any
    that overlap the engagement target scope (``egress_guard.collector_scope_conflicts``) before trusting
    it — this axis is DISJOINT from the attack target scope by doctrine. De-duped, order-stable."""
    hosts = [t.host for t in targets if t.host]
    return tuple(dict.fromkeys(h for h in hosts if h))
