"""
tools.mcp_registry — the pluggable MCP-server manifest layer (VIGIL-FUSION F3, slice 1).

A near-verbatim adaptation of redamon's ``agentic/mcp_registry.py`` (MIT; see NOTICE) — the pydantic
manifest models + trust-tiered cross-server validation + secret redaction + phase-view helpers, which
carry zero LangChain/LLM deps and port cleanly. This is the manifest half of the governed tool
boundary; ``tools.governance`` is the half that subordinates it to the sovereign core (WARDEN tier +
conjunctive gate). The live client that actually speaks to an MCP server (redamon binds LangChain's
``MultiServerMCPClient``; VIGIL will bind the Claude-Agent-SDK MCP client) is the one real seam and is
a later slice — this module only produces the validated manifest + the transport config a client
consumes.

**Sovereign inversions applied on port (deny-by-default, per the fusion invariant):**

  * ``default_phases`` defaults to the LEAST-privilege phase (``["informational"]``), NOT redamon's
    ``ALL_PHASES``. A server/tool that declares no phase is recon-only; exploitation / post-exploitation
    authority must be granted EXPLICITLY. (redamon fails open: an undeclared tool runs everywhere,
    including post-exploitation.)
  * ``default_phases_for`` returns ``[]`` (deny in every phase) for a tool declared by NO enabled
    manifest — an unregistered tool is refused, not allowed-everywhere. ``tools.governance`` reads this
    as fail-closed.
  * ``validate_servers`` keeps redamon's fail-closed drop (any error → the whole server is dropped, never
    half-registered) and the trust-tiered checks (reserved system ids, builtin-tool-name collision,
    duplicate id/tool).

Import-clean: pydantic + stdlib only. No ``framework.*`` / ``strix.*`` / LangChain.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)

PHASES: Tuple[str, ...] = ("informational", "exploitation", "post_exploitation")
ALL_PHASES: List[str] = list(PHASES)
LEAST_PRIVILEGE_PHASES: List[str] = ["informational"]   # VIGIL default (was redamon's ALL_PHASES)
TRANSPORTS: Tuple[str, ...] = ("sse", "streamable_http", "stdio")

# Server IDs reserved for system MCP servers — a user-supplied server may not claim one.
SYSTEM_SERVER_IDS: Set[str] = {
    "network_recon",
    "nmap",
    "nuclei",
    "metasploit",
    "playwright",
}

# Builtin tool names a user manifest may not shadow. Injected by the tool catalog (a later slice) via
# ``set_builtin_tool_names`` rather than imported, to avoid a cycle and keep this module catalog-free.
_builtin_lock = threading.RLock()
_builtin_tool_name_set: Set[str] = set()


def set_builtin_tool_names(names: Set[str]) -> None:
    """Register the builtin tool-catalog names so ``validate_servers`` can reject a user manifest that
    shadows one. Called once by the tool catalog on load (empty until then → no collision check)."""
    global _builtin_tool_name_set
    with _builtin_lock:
        _builtin_tool_name_set = set(names or set())


def _builtin_tool_names() -> Set[str]:
    with _builtin_lock:
        return set(_builtin_tool_name_set)


# =============================================================================
# SCHEMA
# =============================================================================


class ToolSpec(BaseModel):
    """One tool exposed by an MCP server. ``default_phases=None`` inherits the server's phases."""

    name: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    when_to_use: str = Field(min_length=1)
    args_format: str = Field(min_length=1)
    description: str = Field(min_length=1)
    default_phases: Optional[List[Literal["informational", "exploitation", "post_exploitation"]]] = None
    # The operator's AUTHORITATIVE blast-class declaration. None inherits the server default. This can
    # only RAISE destructiveness — the name-based floor in tools.governance also marks a known-dangerous
    # tool destructive even if the manifest under-declares it.
    destructive: Optional[bool] = None


class BearerAuth(BaseModel):
    """Bearer-token auth. Either ``token`` (literal) or ``token_env_var`` (resolved at request time)
    must be provided; the token is sent verbatim as ``Authorization: Bearer <token>``."""

    type: Literal["bearer"] = "bearer"
    token: Optional[str] = None
    token_env_var: Optional[str] = None

    @model_validator(mode="after")
    def _at_least_one(self) -> "BearerAuth":
        if not (self.token or self.token_env_var):
            raise ValueError("auth requires a non-empty 'token' (bearer token)")
        return self


class MCPServer(BaseModel):
    """One MCP server definition. Same schema for system + user-added servers. ``default_phases``
    defaults to least-privilege (informational only) — exploitation/post must be declared."""

    id: str = Field(min_length=1, pattern=r"^[a-zA-Z0-9_][a-zA-Z0-9_-]*$")
    name: str = Field(min_length=1)
    description: str = ""
    enabled: bool = True
    transport: Literal["sse", "streamable_http", "stdio"]
    default_phases: List[Literal["informational", "exploitation", "post_exploitation"]] = Field(
        default_factory=lambda: list(LEAST_PRIVILEGE_PHASES)
    )
    default_destructive: bool = False   # server-level blast-class default for tools that don't declare one
    tags: List[str] = Field(default_factory=list)

    # HTTP-only fields
    url: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    auth: Optional[BearerAuth] = None
    connect_timeout: int = 60
    read_timeout: int = 600

    # stdio-only fields
    command: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    env: Dict[str, str] = Field(default_factory=dict)
    cwd: Optional[str] = None
    encoding: str = "utf-8"

    tools: List[ToolSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_transport_fields(self) -> "MCPServer":
        if self.transport in ("sse", "streamable_http"):
            if not self.url:
                raise ValueError(f"server '{self.id}': url is required for transport '{self.transport}'")
        elif self.transport == "stdio":
            if not self.command:
                raise ValueError(f"server '{self.id}': command is required for transport 'stdio'")
        seen: Set[str] = set()
        for t in self.tools:
            if t.name in seen:
                raise ValueError(f"server '{self.id}': duplicate tool name '{t.name}'")
            seen.add(t.name)
        return self

    def effective_phases_for(self, tool_name: str) -> List[str]:
        """The phase list for a tool, falling back to the server default (least-privilege)."""
        for t in self.tools:
            if t.name == tool_name:
                return list(t.default_phases) if t.default_phases else list(self.default_phases)
        return list(self.default_phases)

    def effective_destructive_for(self, tool_name: str) -> bool:
        """The operator-declared blast class for a tool, falling back to the server default. The
        name-based floor in ``tools.governance`` can still mark a tool destructive on top of this."""
        for t in self.tools:
            if t.name == tool_name:
                return self.default_destructive if t.destructive is None else bool(t.destructive)
        return self.default_destructive


class ValidationError(BaseModel):
    """Structured validation problem for surfacing to an operator UI."""

    server_id: str
    code: str
    message: str


# =============================================================================
# VALIDATION (post-parse, cross-server) — fail-closed: any error drops the whole server
# =============================================================================


def validate_servers(
    servers: List[MCPServer],
    *,
    is_user_supplied: bool = False,
) -> Tuple[List[MCPServer], List[ValidationError]]:
    """Cross-server validation: id uniqueness, reserved system-id collision (user manifests only),
    builtin-tool-name collision, cross-server tool-name collision. A server with ANY error is dropped
    from the valid list (never half-registered)."""
    errors: List[ValidationError] = []
    valid: List[MCPServer] = []
    # All identity comparisons are CASE-INSENSITIVE (folded to lower): "NMAP" must not slip the reserved
    # check, and "nmap"/"Nmap" must collide, so no downstream case-insensitive consumer can be confused.
    seen_ids: Set[str] = set()
    seen_tool_names: Set[str] = set()
    reserved_ids = {s.lower() for s in SYSTEM_SERVER_IDS}
    builtin_names = {b.lower() for b in _builtin_tool_names()} if is_user_supplied else set()

    for srv in servers:
        srv_errors: List[ValidationError] = []
        sid_l = srv.id.lower()
        if sid_l in seen_ids:
            srv_errors.append(ValidationError(server_id=srv.id, code="duplicate_id",
                              message=f"Server id '{srv.id}' is used by another server (case-insensitive)."))
        if is_user_supplied and sid_l in reserved_ids:
            srv_errors.append(ValidationError(server_id=srv.id, code="system_id_collision",
                              message=f"Server id '{srv.id}' is reserved for a system MCP server."))
        for t in srv.tools:
            tn_l = t.name.lower()
            if tn_l in builtin_names:
                srv_errors.append(ValidationError(server_id=srv.id, code="builtin_name_collision",
                                  message=f"Tool name '{t.name}' collides with a built-in tool."))
            if tn_l in seen_tool_names:
                srv_errors.append(ValidationError(server_id=srv.id, code="duplicate_tool_name",
                                  message=f"Tool name '{t.name}' is already declared by another server."))
        if srv_errors:
            errors.extend(srv_errors)
            continue
        seen_ids.add(sid_l)
        for t in srv.tools:
            seen_tool_names.add(t.name.lower())
        valid.append(srv)

    return valid, errors


# =============================================================================
# CONVERSION TO CLIENT CONFIG (the transport config a live MCP client consumes)
# =============================================================================


def _resolve_auth_header(srv: MCPServer) -> Tuple[Dict[str, str], List[str]]:
    """Build auth + custom headers, resolving env vars. Returns (headers, missing_vars). A masked or
    non-ASCII token is dropped rather than crashing the HTTP client (defensive)."""
    headers: Dict[str, str] = {}
    missing: List[str] = []
    if srv.headers:
        headers.update(srv.headers)   # verbatim, no interpolation
    if srv.auth and srv.auth.type == "bearer":
        token: Optional[str] = None
        if srv.auth.token:
            token = srv.auth.token
        elif srv.auth.token_env_var:
            token = os.environ.get(srv.auth.token_env_var)
            if not token:
                missing.append(srv.auth.token_env_var)
        if token:
            try:
                token.encode("ascii")
                headers["Authorization"] = f"Bearer {token}"
            except UnicodeEncodeError:
                logger.warning("server '%s': bearer token is non-ASCII (likely a masked placeholder); "
                               "dropping Authorization header.", srv.id)
    return headers, missing


def to_client_config(
    servers: List[MCPServer],
) -> Tuple[Dict[str, Dict[str, Any]], List[ValidationError]]:
    """Convert the manifest into the transport-config dict a live MCP client consumes. Disabled servers
    are skipped. Headers / stdio env are passed through verbatim. (The client binding itself — LangChain
    in redamon, the Claude-Agent-SDK MCP client in VIGIL — is a later slice.)"""
    config: Dict[str, Dict[str, Any]] = {}
    warnings: List[ValidationError] = []
    for srv in servers:
        if not srv.enabled:
            continue
        if srv.transport in ("sse", "streamable_http"):
            headers, missing = _resolve_auth_header(srv)
            for var in missing:
                warnings.append(ValidationError(server_id=srv.id, code="env_var_unset",
                                message=f"Environment variable '{var}' is unset; sent without it."))
            entry: Dict[str, Any] = {"url": srv.url, "transport": srv.transport,
                                     "timeout": srv.connect_timeout, "sse_read_timeout": srv.read_timeout}
            if headers:
                entry["headers"] = headers
            config[srv.id] = entry
        elif srv.transport == "stdio":
            entry = {"command": srv.command, "args": list(srv.args), "transport": "stdio",
                     "encoding": srv.encoding}
            if srv.env:
                entry["env"] = dict(srv.env)
            if srv.cwd:
                entry["cwd"] = srv.cwd
            config[srv.id] = entry
    return config, warnings


# =============================================================================
# CURRENT-STATE HOLDER (single source of truth for the running agent)
# =============================================================================

_state_lock = threading.RLock()
_current_servers: List[MCPServer] = []
_current_errors: List[ValidationError] = []
_current_warnings: List[ValidationError] = []


def set_current(servers: List[MCPServer], errors: Optional[List[ValidationError]] = None,
                warnings: Optional[List[ValidationError]] = None) -> None:
    """Replace the registry's current state (called on manifest (re)load)."""
    global _current_servers, _current_errors, _current_warnings
    with _state_lock:
        _current_servers = list(servers)
        _current_errors = list(errors or [])
        _current_warnings = list(warnings or [])


def current() -> List[MCPServer]:
    with _state_lock:
        return list(_current_servers)


def current_errors() -> List[ValidationError]:
    with _state_lock:
        return list(_current_errors)


def current_warnings() -> List[ValidationError]:
    with _state_lock:
        return list(_current_warnings)


def default_phases_for(tool_name: str) -> List[str]:
    """Read-time phase lookup for the phase gate. **VIGIL inversion:** a tool declared by NO enabled
    server returns ``[]`` (denied in every phase), not redamon's all-phases fallback."""
    for srv in current():
        if not srv.enabled:
            continue
        for t in srv.tools:
            if t.name == tool_name:
                return list(t.default_phases) if t.default_phases else list(srv.default_phases)
    return []   # unknown tool → deny everywhere (fail-closed)


def manifest_tool_names() -> Set[str]:
    """All tool names currently declared by any enabled MCP server."""
    out: Set[str] = set()
    for srv in current():
        if not srv.enabled:
            continue
        for t in srv.tools:
            out.add(t.name)
    return out


def manifest_tool_phase_view() -> Dict[str, List[str]]:
    """Map of ``tool_name -> effective phases`` for every currently-declared, enabled tool."""
    out: Dict[str, List[str]] = {}
    for srv in current():
        if not srv.enabled:
            continue
        for t in srv.tools:
            out[t.name] = list(t.default_phases) if t.default_phases else list(srv.default_phases)
    return out


def manifest_tool_destructive_view() -> Dict[str, bool]:
    """Map of ``tool_name -> operator-declared destructiveness`` for every enabled tool. Consumed by
    ``tools.governance`` as the authoritative blast-class source (the name-based floor can only raise it)."""
    out: Dict[str, bool] = {}
    for srv in current():
        if not srv.enabled:
            continue
        for t in srv.tools:
            out[t.name] = srv.default_destructive if t.destructive is None else bool(t.destructive)
    return out


# =============================================================================
# PARSING ENTRYPOINT
# =============================================================================


def parse_user_servers(raw: Any) -> Tuple[List[MCPServer], List[ValidationError]]:
    """Parse + validate user-supplied ``mcpServers`` JSON (a list of dicts). Returns (valid, errors).
    Always ``is_user_supplied=True`` → the reserved-id and builtin-collision checks apply."""
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], [ValidationError(server_id="<root>", code="invalid_payload",
                                    message="mcpServers must be a list")]
    parsed: List[MCPServer] = []
    errors: List[ValidationError] = []
    for i, entry in enumerate(raw):
        try:
            parsed.append(MCPServer.model_validate(entry))
        except Exception as exc:  # noqa: BLE001 — a bad entry is reported, never registered
            sid = entry.get("id", f"<index {i}>") if isinstance(entry, dict) else f"<index {i}>"
            errors.append(ValidationError(server_id=str(sid), code="schema_invalid", message=str(exc)))
    valid, cross_errors = validate_servers(parsed, is_user_supplied=True)
    errors.extend(cross_errors)
    return valid, errors


# =============================================================================
# SECRET REDACTION (for any API/log surface; the LLM never sees raw secrets)
# =============================================================================


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "••••"
    return "••••••••" + value[-4:]


# Secret-key detection: a key is a secret if its separator-stripped lowercase form is an exact known
# secret key, contains a secret STEM, or has a secret TOKEN at a word boundary. The token rule catches
# crypto key-material (ssh_key/master_key/signing_key) and session_id via boundary splitting, WITHOUT
# over-matching "monkey"/"keyword"/"author"/"description" (those are single non-secret tokens). Stems
# are chosen NOT to over-match ("authorization" not "auth"; "apikey"/"privatekey" not bare "key").
_SECRET_KEY_STEMS = ("token", "secret", "password", "passwd", "passphrase", "apikey", "bearer",
                     "credential", "privatekey", "sessiontoken", "accesskey", "passcode",
                     # no-separator crypto key-material compounds (masterkey/sshkey → no word boundary
                     # to tokenize, and bare "key" is excluded to spare "monkey"/"whiskey")
                     "sshkey", "gpgkey", "masterkey", "signingkey", "encryptionkey", "sessionkey",
                     "privkey", "hostkey", "secretkey")
_SECRET_KEY_EXACT = frozenset({"key", "auth", "authorization", "cookie", "session", "pat", "pwd", "pw",
                               "pass", "otp", "totp", "cred", "creds", "jwt", "passcode"})
_SECRET_KEY_TOKENS = frozenset({"key", "secret", "token", "password", "passwd", "passphrase", "pwd",
                                "credential", "credentials", "cred", "creds", "auth", "bearer",
                                "cookie", "session", "jwt", "pat", "otp", "totp", "passcode"})
# Inline secrets embedded in a command/arg/URL/header/body string value. Forms handled:
#   * a ``param=value`` / ``param:value`` / JSON ``"param":"value"`` assignment where the PARAM NAME is
#     a secret — decided by ``_is_secret_key`` itself (NOT a second hardcoded vocabulary), so the inline
#     scrubber and the key scrubber can never disagree (the leak class that recurred across reviews);
#   * a ``Bearer <token>`` header value;
#   * a secret CLI flag (``--api-key``) followed by whitespace then the value.
# The value class stops at whitespace / query separators (& ;) / quotes, so ``a=x&secret=Y`` masks only Y.
# All quantifiers act on disjoint character classes → linear, no catastrophic backtracking.
# A ``secret-param = value`` assignment. Notes on the pieces:
#   * The fixed-width lookbehind + bounded param name ({0,63}) keep matching linear — an unbounded
#     greedy name backtracks O(n²) against a failing op on a long alpha run (a ReDoS).
#   * The op's leading ``["']?`` consumes a JSON key's CLOSING quote (``"password":``); the ``(?!//)``
#     rejects a scheme colon (``https://``) so it can't swallow the query params that follow.
#   * The VALUE is a double-quoted / single-quoted string (whose content may contain spaces — a spaced
#     secret is ALWAYS quoted/encoded in every real serialization) OR an unquoted token that stops at
#     whitespace / query separators (& ;) / a quote. ``/`` stays in the unquoted class so a base64 token
#     is not truncated. Quoted content is bounded ({0,8192}) for ReDoS safety.
_KV_SECRET_RE = re.compile(
    r"""(?<![A-Za-z0-9_.])([A-Za-z][A-Za-z0-9_.]{0,63})(["']?\s*[:=](?!//)\s*)"""
    r'''("(?P<dq>[^"]{0,8192})"|'(?P<sq>[^']{0,8192})'|(?P<uq>[^\s&;"']+))''')
_BEARER_RE = re.compile(r"(?i)((?:authorization\s*:\s*)?bearer\s+)(\S+)")
_FLAG_VALUE_RE = re.compile(r"(?i)(-{1,2}[a-z0-9][a-z0-9_-]{0,63})(\s+)(\S+)")
# Greedy to the LAST '@' before the path so an '@' inside the password is still masked; the username
# class is `*` so an empty-username `://:pw@host` is also covered.
_URL_USERINFO_RE = re.compile(r"(://[^/:@\s]*:)([^/\s]*?)(@)(?=[^@]*(?:[/?#]|$))")


def _is_secret_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    nk = key.lower().replace("-", "").replace("_", "")
    if nk in _SECRET_KEY_EXACT:
        return True
    if any(stem in nk for stem in _SECRET_KEY_STEMS):
        return True
    # tokenize on separators AND camelCase boundaries so ssh_key / masterKey / sessionId reveal their
    # secret token, WITHOUT over-matching single words (monkey/keyword/keyboard have no boundary).
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key)
    return any(tok in _SECRET_KEY_TOKENS for tok in re.split(r"[^a-z0-9]+", spaced.lower()))


def _redact_kv(s: str) -> str:
    """Mask the value of any ``param=value``/``param:value`` assignment whose PARAM NAME ``_is_secret_key``
    — the single secret vocabulary, so this can never recognize fewer names than the key scrubber. A
    quoted value is masked whole (its quotes kept, spaces inside included); an unquoted value is masked
    to the token boundary."""
    def repl(m: "re.Match[str]") -> str:
        name, op = m.group(1), m.group(2)
        if not _is_secret_key(name):
            return m.group(0)
        if m.group("dq") is not None:
            return f'{name}{op}"••••"'
        if m.group("sq") is not None:
            return f"{name}{op}'••••'"
        return f"{name}{op}••••"
    return _KV_SECRET_RE.sub(repl, s)


def _redact_flag_values(s: str) -> str:
    """Mask a secret CLI flag's space-separated value (``--api-key VALUE``). The next token is left
    alone if it is itself a flag (``--verbose --other``)."""
    def repl(m: "re.Match[str]") -> str:
        flag, sp, val = m.group(1), m.group(2), m.group(3)
        if val.startswith("-"):
            return m.group(0)
        return f"{flag}{sp}••••" if _is_secret_key(flag.lstrip("-")) else m.group(0)
    return _FLAG_VALUE_RE.sub(repl, s)


def _redact_str(s: str) -> str:
    """The single comprehensive free-string scrubber — BOTH the API surface (``redact_for_api``) and the
    immutable-spine surface (``redact_tool_args`` → ``_redact_value``) route every free string through
    this, so a scrubber can never again cover one path but not the other, and its inline arm shares ONE
    secret vocabulary (``_is_secret_key``) with the key scrubber. Masks: ``Bearer <tok>``; any
    ``secret-param=value`` / ``"secret-param":"value"`` assignment; ``--secret-flag <value>``; and a
    ``scheme://user:pass@host`` basic-auth password."""
    if not isinstance(s, str):
        return s
    s = _BEARER_RE.sub(lambda m: m.group(1) + "••••", s)
    s = _redact_kv(s)
    s = _redact_flag_values(s)
    return _redact_url_userinfo(s)


def _redact_url_userinfo(url: str) -> str:
    """Mask the password in a ``scheme://user:pass@host`` URL (the username is kept as a reference)."""
    if not isinstance(url, str):
        return url
    return _URL_USERINFO_RE.sub(r"\1••••\3", url)


def _redact_arg_list(args: List[Any]) -> List[Any]:
    """Mask secret CLI arg values: ``--api-key <v>`` (value is the next arg), ``--api-key=<v>`` (inline),
    and any inline secret inside an arg string."""
    out: List[Any] = []
    mask_next = False
    for a in args:
        if mask_next:
            out.append("••••" if isinstance(a, str) else a)
            mask_next = False
            continue
        if not isinstance(a, str):
            out.append(a)
            continue
        if a.startswith("-"):
            name, sep, _val = a.partition("=")
            if _is_secret_key(name.lstrip("-")):
                if sep:
                    out.append(name + "=••••")
                else:
                    out.append(a)
                    mask_next = True   # the secret value is the following arg
                continue
        out.append(_redact_str(a))
    return out


def redact_for_api(servers: List[MCPServer]) -> List[Dict[str, Any]]:
    """Render servers safer for an API/log surface. Masks the secret-bearing fields it recognizes: the
    literal auth token, all header values, all stdio env values, the password in a URL userinfo, secret
    CLI arg values (``--secret-flag value`` / ``--secret-flag=value``), and inline secrets in the command
    string. Non-secret keys/structure are kept as references. Best-effort on free-form CLI: an ambiguous
    single-char flag (``-p``) or a purely positional secret is not detected — declare secrets via
    ``auth``/``env`` rather than inline args when possible."""
    out: List[Dict[str, Any]] = []
    for srv in servers:
        d = srv.model_dump()
        auth = d.get("auth")
        if isinstance(auth, dict) and auth.get("token"):
            auth["token"] = _mask_secret(auth["token"])
        hdrs = d.get("headers")
        if isinstance(hdrs, dict) and hdrs:
            d["headers"] = {k: _mask_secret(str(v)) for k, v in hdrs.items()}
        env = d.get("env")
        if isinstance(env, dict) and env:
            d["env"] = {k: _mask_secret(str(v)) for k, v in env.items()}
        if isinstance(d.get("url"), str) and d["url"]:
            d["url"] = _redact_url_userinfo(d["url"])
        if isinstance(d.get("args"), list) and d["args"]:
            d["args"] = _redact_arg_list(d["args"])
        if isinstance(d.get("command"), str) and d["command"]:
            d["command"] = _redact_str(d["command"])
        out.append(d)
    return out
