"""SIGIL runtime configuration. All paths local-first, owner-only.

Layered resolution (highest precedence first):
  1. the process environment (os.environ)
  2. ~/.sigil/sigil.env (persisted KEY=VALUE, merged via setdefault → the real env still wins)
  3. built-in defaults — host-relative (Path.home() / package-relative), never an operator-
     specific absolute path, so the code deploys on any host.

`SIGIL_HOME` is resolved from env-or-default BEFORE the env file is read (it locates that file),
so it cannot be set from within its own sigil.env; everything else honours the full
env → file → default chain. `effective_config()` returns the resolved values (secrets redacted)
and `doctor()` self-checks the runtime.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


# --- data root (runtime, 0700) --------------------------------------------------------
def _resolve_home() -> Path:
    return Path(os.environ.get("SIGIL_HOME", str(Path.home() / ".sigil")))


SIGIL_HOME = _resolve_home()


# Every character str.splitlines() treats as a line boundary. The sigil.env tier is a line-based
# `KEY=value` format with NO escaping, so ANY of these inside a value would break it into an extra line —
# an envfile line-injection that can plant a var like VIGIL_DESTRUCTION_OWNER_KEY (the auto-patch signing
# key). An ord<0x20/==0x7f guard misses three: NEL (U+0085), LINE SEPARATOR (U+2028), PARAGRAPH SEPARATOR
# (U+2029). A literal "\n" is stopped ONLY by this input guard (the reader splits ON "\n", so parsing can
# never neutralize a real newline) — so EVERY writer of sigil.env must validate through it before writing.
_ENV_LINE_BREAK_CHARS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")


def assert_env_value_safe(value: str, what: str = "value", *, maxlen: int = 8192) -> None:
    """Fail-closed if `value` cannot be persisted as a single `KEY=value` line in sigil.env: reject a
    control character (ord < 0x20 or DEL), any Unicode line separator str.splitlines() honors, or an
    oversize value. The ONE guard EVERY sigil.env writer shares (settings._persist_env, secrets._env_upsert,
    voice.set_voice) so a line-injection cannot recur at a writer that forgot it."""
    if len(value) > maxlen:
        raise ValueError(f"invalid {what}: too long (> {maxlen})")
    if any(ord(c) < 0x20 or ord(c) == 0x7f or c in _ENV_LINE_BREAK_CHARS for c in value):
        raise ValueError(f"invalid {what}: control or line-break character")


def assert_env_key_safe(key: str) -> None:
    """Fail-closed if `key` cannot be the KEY half of a single `KEY=value` line in sigil.env: reject empty,
    any control/line-break char (a str.splitlines() boundary), or an '=' (which would split the assignment).
    Every writer emits f"{key}={value}", so the KEY needs the same class-guard as the value — a line-break in
    a caller-supplied key (e.g. a CredentialVault `service`) would otherwise plant a second KEY=value line
    just like a poisoned value. Legal keys (A-Z/_/-/./ and the `vault/<svc>/password` form) pass unchanged."""
    if not key:
        raise ValueError("invalid env key: empty")
    if "=" in key:
        raise ValueError("invalid env key: contains '='")
    if any(ord(c) < 0x20 or ord(c) == 0x7f or c in _ENV_LINE_BREAK_CHARS for c in key):
        raise ValueError("invalid env key: control or line-break character")


def _load_env_file(home: Path | None = None) -> None:
    """Load persisted `KEY=VALUE` settings from ~/.sigil/sigil.env so a value set once (e.g.
    SIGIL_QDRANT_URL for server mode) reaches BOTH the CLI and the MCP server that Claude spawns
    without an explicit env. The real environment always wins (setdefault). Read with
    `errors="replace"` so a stray non-UTF-8 byte in the file can NEVER crash `import sigil`."""
    f = (home or SIGIL_HOME) / "sigil.env"
    if not f.exists():
        return
    try:
        raw = f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    # Parse on "\n" ONLY (not str.splitlines()): a persisted value may contain a Unicode line separator
    # (U+0085/U+2028/U+2029) which str.splitlines() would treat as a line boundary, splitting one value
    # into a second `KEY=value` line — an envfile line-injection. On "\n" the separator stays inert
    # inside its value. (The settings-plane writers also reject those chars at the source.)
    for line in raw.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())


_load_env_file()

_spine = SIGIL_HOME / "spine"
SPINE_PATH = _spine / "spine.jsonl"
HEAD_PATH = _spine / "head.json"
KEYS_DIR = _spine / "keys"
# The per-spine DATA KEY (DEK) for field-level payload encryption (audit G1 slice-4), sealed at rest
# under the TPM KEK (the G1 vault). Absent until `sigil vault provision` + a first content-bearing append.
SPINE_DEK_PATH = KEYS_DIR / "spine.dek"
CACHE_DIR = SIGIL_HOME / "cache"
# Durable external anti-rollback floor (hard-prune C1). At the SIGIL_HOME root, deliberately OUTSIDE
# `spine/` so `SpineStore.reset()` / `sigil ingest --reset` (which rmtree the spine dir) can NEVER lower
# it — a routine reset cannot roll the durable floor back. See spine/floor.py.
FLOOR_PATH = SIGIL_HOME / "floor.json"

# The segment-rotation layout (manifest, lockfile, segments dir, …) is NOT named here: it is derived from
# the spine data-file path — and NAMESPACED BY THAT FILE'S STEM — by `spine.manifest.SpineLayout.for_path`,
# which is the single source of truth. Naming fixed constants here would drift from that namespacing and
# would wrongly assume the spine dir is private to one store (it is not, e.g. under tempfile.mktemp).

# Rotation thresholds: seal the active segment + start a new one once it reaches EITHER bound. Applies only
# to a MIGRATED store (a legacy single-file spine never auto-rotates — the owner runs `sigil spine migrate`
# first). 0 on either bound disables that bound; 0 on both disables rotation (byte-identical passthrough).
def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default


SPINE_SEG_MAX_BYTES = _int_env("SIGIL_SPINE_SEG_MAX_BYTES", 16 * 1024 * 1024)   # 16 MiB
SPINE_SEG_MAX_RECORDS = _int_env("SIGIL_SPINE_SEG_MAX_RECORDS", 12_000)

# --- ingestion sources ----------------------------------------------------------------
CLAUDE_PROJECTS = Path(os.environ.get("SIGIL_CLAUDE_PROJECTS", str(Path.home() / ".claude" / "projects")))
# Phase-0a thin slice: PENTEST-main only. Slugified cwd = dir name under ~/.claude/projects.
PROJECT_ALLOWLIST = os.environ.get(
    "SIGIL_PROJECT_ALLOWLIST", "-home-kali-Pictures-PENTEST-main"
).split(",")
# ephemeral CRUCIBLE-engine runs to filter out
EPHEMERAL_PREFIXES = ("-tmp-crucible-cc-", "-tmp-")

# --- vectors (Qdrant, local/embedded — no server, no Docker; in-process, file-backed) -
QDRANT_PATH = SIGIL_HOME / "qdrant"                       # embedded local-mode store
QDRANT_URL = os.environ.get("SIGIL_QDRANT_URL", "")       # set to switch to a server later
QDRANT_COLLECTION = os.environ.get("SIGIL_QDRANT_COLLECTION", "sigil_memory")
EMBED_MODEL = os.environ.get("SIGIL_EMBED_MODEL", "BAAI/bge-small-en-v1.5")
EMBED_DIM = 384

# --- graph (Kùzu, deterministic mirror of the spine) ----------------------------------
GRAPH_DIR = SIGIL_HOME / "graph"                          # base; holds current/ + staging/ (atomic swap)

# --- identity / scope -----------------------------------------------------------------
SCOPE = os.environ.get("SIGIL_SCOPE", "sigil")          # the owner's single scope
OWNER_KEY_ID = os.environ.get("SIGIL_OWNER_KEY_ID", "owner")


# --- OIDC Relying Party (Slice S5 — SHIPPED OFF BY DEFAULT) ----------------------------
# The OIDC RP is DISABLED unless SIGIL_OIDC_ENABLED is affirmative. This MIRRORS the
# VIGIL_EGRESS_GUARD precedent: opt-in by env, byte-identical (no new route, no egress, no surface)
# unless explicitly asked. When enabled it targets an OPERATOR-RUN IdP reachable over the private
# tunnel (loopback / RFC1918 / Tailscale-CGNAT / IPv6-ULA — the ranges `bridge.daemon.bind_ok` allows);
# a PUBLIC cloud IdP is NOT the default and breaks the air-gap posture (see docs/OIDC-RP.md).
# CRITICAL invariant: OIDC authenticates *who you are*; the *role* is NEVER taken from an OIDC claim —
# it comes only from an owner-signed `governor.account` grant (single-owner-key / nothing-self-
# authorizes doctrine). An OIDC identity with no matching owner-signed account is REFUSED.
_OIDC_AFFIRMATIVE = frozenset({"1", "true", "yes", "on", "enabled"})


def oidc_enabled() -> bool:
    """True iff the OIDC Relying Party is turned ON (SIGIL_OIDC_ENABLED ∈ {1,true,yes,on,enabled},
    case-insensitive). Absent / empty / anything else ⇒ OFF. When OFF the OIDC routes are NOT registered
    at all — the cockpit is byte-identical to a build without OIDC (no /api/oidc/* route, no egress)."""
    return (os.environ.get("SIGIL_OIDC_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def oidc_settings() -> dict:
    """The resolved SIGIL_OIDC_* configuration (env → sigil.env → default), read at call time so an
    override applied after import is honoured. Consulted ONLY when `oidc_enabled()`. The client secret is
    included here for the token exchange; callers that DISPLAY config must redact it (`effective_config`
    surfaces only a redacted view). `username_claim` selects which verified id_token claim maps to a
    `governor.account` username; `signing_algs` is the ASYMMETRIC-only allowlist (a symmetric/`none` alg is
    refused — algorithm-confusion defence)."""
    g = os.environ.get
    return {
        "issuer": (g("SIGIL_OIDC_ISSUER") or "").strip(),
        "client_id": (g("SIGIL_OIDC_CLIENT_ID") or "").strip(),
        "client_secret": (g("SIGIL_OIDC_CLIENT_SECRET") or ""),
        "redirect_uri": (g("SIGIL_OIDC_REDIRECT_URI") or "").strip(),
        "authorize_endpoint": (g("SIGIL_OIDC_AUTHORIZE_ENDPOINT") or "").strip(),
        "token_endpoint": (g("SIGIL_OIDC_TOKEN_ENDPOINT") or "").strip(),
        "jwks_uri": (g("SIGIL_OIDC_JWKS_URI") or "").strip(),
        "scopes": (g("SIGIL_OIDC_SCOPES") or "openid profile email").strip(),
        # which verified id_token claim carries the username that must match an owner-signed account.
        # DEFAULT is the IMMUTABLE `sub` (globally unique + IdP-stable): a mutable claim (preferred_username
        # /email) is opt-in only, because if a user can change theirs the mapping can drift or be steered.
        "username_claim": (g("SIGIL_OIDC_USERNAME_CLAIM") or "sub").strip(),
        # asymmetric-only signing-alg allowlist for the id_token (RS256 default; ES256 also supported)
        "signing_algs": [a.strip().upper() for a in (g("SIGIL_OIDC_SIGNING_ALGS") or "RS256").split(",")
                         if a.strip()],
        "clock_skew_seconds": _int_env("SIGIL_OIDC_CLOCK_SKEW_SECONDS", 60),
    }

# --- external binaries (resolved; never an operator-specific absolute path) -----------
_CLAUDE_FALLBACK = Path.home() / ".local" / "bin" / "claude"
_REPO_ROOT = Path(__file__).resolve().parents[1]         # <repo>/sigil/config.py → <repo>


def claude_bin() -> str:
    """Resolve the `claude` CLI: env SIGIL_CLAUDE_BIN → PATH (`which claude`) → a documented
    per-user fallback (~/.local/bin/claude). Never embeds an operator-specific absolute path."""
    return os.environ.get("SIGIL_CLAUDE_BIN") or shutil.which("claude") or str(_CLAUDE_FALLBACK)


def kernel_bin() -> str | None:
    """Resolve the Rust KERNEL binary: env SIGIL_KERNEL_BIN → package-relative build dirs → PATH.
    Returns None when it cannot be found, so a caller can FAIL LOUD rather than hand a bare name to
    subprocess (which would ENOENT with a confusing generic error)."""
    exe = "sigil-kernel.exe" if os.name == "nt" else "sigil-kernel"
    env = os.environ.get("SIGIL_KERNEL_BIN")
    if env and Path(env).exists():
        return env
    for rel in (f"kernel/target/release/{exe}", f"kernel/target/debug/{exe}"):
        cand = _REPO_ROOT / rel
        if cand.exists():
            return str(cand)
    # A `pip install` ships the kernel (setuptools-rust RustBin) into the environment's script dir,
    # alongside this interpreter and the `sigil` console script — resolve it there even when that dir
    # is not on PATH (e.g. the venv is invoked by absolute path, not "activated"). Trust sys.executable
    # ONLY when it is an ABSOLUTE path: an empty or bare-name sys.executable would make `.parent / exe`
    # resolve CWD-relatively (`./sigil-kernel`), which — for the WARDEN authorizer — would let a binary
    # planted in the process's CWD win. is_absolute() rejects both "" and "python3".
    exe_path = Path(sys.executable)
    if exe_path.is_absolute():
        venv_bin = exe_path.parent / exe
        if venv_bin.exists():
            return str(venv_bin)
    return shutil.which(exe)


# --- git ingestion sources (operator-specific data; overridable, host-relative default) -
def _resolve_ingest_repos() -> list[str]:
    """Colon-separated repo paths (env SIGIL_INGEST_REPOS) to backfill as `commit` spine events.
    Default = the operator's high-signal set (excludes the huge RECOR + vendored flutter repos),
    made host-relative so it is portable; override the env var to deploy on another host."""
    override = [p.strip() for p in os.environ.get("SIGIL_INGEST_REPOS", "").split(":") if p.strip()]
    return override or [str(Path.home() / "Pictures" / "PENTEST-main"), str(Path.home() / "sigil")]


INGEST_REPOS = _resolve_ingest_repos()


def ensure_dirs() -> None:
    for d in (SIGIL_HOME, SPINE_PATH.parent, KEYS_DIR, CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass


# --- W5-4 (#448): the ~/.sigil install manifest (product version + schema versions + install id) ---------
def install_manifest_schema_versions() -> "dict[str, int]":
    """The versioned artifacts THIS sovereign build writes into ``~/.sigil`` and the max schema of each it
    understands — the map that drives the fail-closed startup verify (W5-4). A future build that bumps any of
    these refuses-newer a ``~/.sigil`` written by an even newer build; and an older build refuses a home this
    one wrote with a bumped schema. Assembled from the per-artifact ``_MAX_*_SCHEMA`` constants so a schema
    bump is reflected here automatically. Imported lazily to avoid an import cycle (config -> spine)."""
    from .spine.checkpoint import _MAX_HEAD_SCHEMA
    from .spine.floor import _MAX_FLOOR_SCHEMA
    from .spine.manifest import _MAX_MANIFEST_SCHEMA
    from .spine.models import SCHEMA_VERSION
    from .spine.snapshot import _MAX_SNAPSHOT_SCHEMA
    return {
        "spine_record": int(SCHEMA_VERSION),
        "signed_head": int(_MAX_HEAD_SCHEMA),
        "anti_rollback_floor": int(_MAX_FLOOR_SCHEMA),
        "segment_manifest": int(_MAX_MANIFEST_SCHEMA),
        "snapshot_state": int(_MAX_SNAPSHOT_SCHEMA),
    }


def ensure_install_manifest():
    """Write-if-absent + verify-if-present the ``~/.sigil`` install manifest (W5-4, #448). Returns
    ``(manifest, created)``. Raises ``vigil_core.install_manifest.InstallManifestRefused`` (fail closed) if
    ``~/.sigil`` was written by a build this one does not understand (a newer manifest format, or a
    newer/foreign tracked schema) or whose self-integrity hash does not match. A fresh install writes the
    manifest with NO operator action. Called at sovereign CLI startup."""
    from vigil_core.install_manifest import ensure_operable

    from . import __version__
    return ensure_operable(SIGIL_HOME, product_version=__version__,
                           schema_versions=install_manifest_schema_versions())


# --- effective config + self-check ----------------------------------------------------
_SECRET_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")


def _strip_url_credentials(value):
    """Thin wrapper over the SHARED scrubber in ``vigil_core.doctor`` (imported lazily, like this module's
    other vigil_core uses). Sharing it with the offense doctor means the URL-credential redaction can never
    drift between the two trust planes — both surface DSNs to operator+ over /api/doctor."""
    from vigil_core.doctor import strip_url_credentials
    return strip_url_credentials(value)


def _redact(name: str, value):
    """Redact any value whose KEY NAME looks like a secret; then strip URL-embedded credentials from
    whatever survives (a value-level backstop for creds under a non-secret-named key)."""
    if value and any(h in name.upper() for h in _SECRET_HINTS):
        return "***redacted***"
    return _strip_url_credentials(value)


def effective_config() -> dict:
    """The fully-resolved runtime configuration (env → sigil.env → default), secrets REDACTED.
    Re-reads the environment at call time, so it reflects overrides applied after import — this is
    the honest "what will SIGIL actually use on this host" view the audit asked for."""
    home = _resolve_home()
    spine = home / "spine"
    api_key = os.environ.get("SIGIL_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or ""
    cfg = {
        "SIGIL_HOME": str(home),
        "SPINE_PATH": str(spine / "spine.jsonl"),
        "HEAD_PATH": str(spine / "head.json"),
        "KEYS_DIR": str(spine / "keys"),
        "CACHE_DIR": str(home / "cache"),
        "QDRANT_PATH": str(home / "qdrant"),
        "GRAPH_DIR": str(home / "graph"),
        "CLAUDE_PROJECTS": os.environ.get("SIGIL_CLAUDE_PROJECTS", str(Path.home() / ".claude" / "projects")),
        "PROJECT_ALLOWLIST": os.environ.get("SIGIL_PROJECT_ALLOWLIST", "-home-kali-Pictures-PENTEST-main").split(","),
        "QDRANT_URL": os.environ.get("SIGIL_QDRANT_URL", ""),
        "QDRANT_COLLECTION": os.environ.get("SIGIL_QDRANT_COLLECTION", "sigil_memory"),
        "EMBED_MODEL": os.environ.get("SIGIL_EMBED_MODEL", "BAAI/bge-small-en-v1.5"),
        "SCOPE": os.environ.get("SIGIL_SCOPE", "sigil"),
        "OWNER_KEY_ID": os.environ.get("SIGIL_OWNER_KEY_ID", "owner"),
        "CLAUDE_BIN": claude_bin(),
        "KERNEL_BIN": kernel_bin(),
        "INGEST_REPOS": _resolve_ingest_repos(),
        "LOG_LEVEL": os.environ.get("SIGIL_LOG_LEVEL", "INFO"),
        "ANTHROPIC_API_KEY": api_key,
        # OIDC RP: OFF by default (byte-identical / no egress). When ON, surface the issuer + endpoints so
        # the operator can confirm the IdP is a PRIVATE/tunnel address; the client secret is redacted by the
        # SECRET name-hint below (and is not placed here at all).
        "SIGIL_OIDC_ENABLED": oidc_enabled(),
        "SIGIL_OIDC_ISSUER": (os.environ.get("SIGIL_OIDC_ISSUER", "") if oidc_enabled() else ""),
        "SIGIL_OIDC_CLIENT_ID": (os.environ.get("SIGIL_OIDC_CLIENT_ID", "") if oidc_enabled() else ""),
    }
    return {k: _redact(k, v) for k, v in cfg.items()}


def _probe_writable(d: Path) -> tuple[bool, str]:
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / ".sigil-doctor-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True, f"{d} writable"
    except OSError as e:
        return False, f"{d} NOT writable: {e}"


def _check_kernel() -> tuple[str, bool, str]:
    kb = kernel_bin()
    return ("kernel_binary", kb is not None,
            kb or "not found — set SIGIL_KERNEL_BIN, add sigil-kernel to PATH, or build kernel/")


def _check_claude() -> tuple[str, bool, str]:
    cb = claude_bin()
    ok = Path(cb).exists() or shutil.which(cb) is not None
    return ("claude_cli", ok, cb if ok else f"{cb} — not found; set SIGIL_CLAUDE_BIN or install the claude CLI")


def _check_qdrant() -> tuple[str, bool, str]:
    url = os.environ.get("SIGIL_QDRANT_URL", "")
    if not url:
        return ("qdrant", True, f"embedded/local-mode at {_resolve_home() / 'qdrant'} (no server configured)")
    safe = _strip_url_credentials(url)   # the detail is surfaced to operator+ over /api/doctor — never inline creds
    try:
        import urllib.request
        with urllib.request.urlopen(url.rstrip("/") + "/readyz", timeout=2) as r:
            code = getattr(r, "status", None) or r.getcode()
        return ("qdrant", 200 <= int(code) < 300, f"{safe} → HTTP {code}")
    except Exception as e:  # noqa: BLE001 — any failure = not reachable
        # NEVER echo the raw exception text: a malformed-URL error can quote a credential FRAGMENT that is
        # neither the whole URL nor a parseable URL (so neither replace nor the URL scrubber would catch it).
        # A socket error's `.reason` is URL-free and useful; a parse error (no `.reason`) → just the type.
        reason = getattr(e, "reason", None)
        why = str(reason) if reason is not None else type(e).__name__
        return ("qdrant", False, f"{safe} unreachable: {_strip_url_credentials(why)}")


def _check_keyring() -> tuple[str, bool, str]:
    try:
        import keyring  # noqa: F401
        try:
            backend = keyring.get_keyring().__class__.__name__
        except Exception:  # noqa: BLE001
            backend = "unknown backend"
        return ("keyring", True, f"available ({backend})")
    except Exception:  # noqa: BLE001 — no keyring package/backend
        return ("keyring", False, "not installed — secrets fall back to ~/.sigil/sigil.env (0600)")


def doctor() -> list[tuple[str, bool, str]]:
    """Self-check the runtime. Each row is `(name, ok, detail)`; no check ever raises. Side-effect
    free apart from a writability probe under SIGIL_HOME that cleans up after itself."""
    checks: list[tuple[str, bool, str]] = []
    ok, detail = _probe_writable(_resolve_home())
    checks.append(("sigil_home_writable", ok, detail))
    checks.append(_check_kernel())
    checks.append(_check_claude())
    checks.append(_check_qdrant())
    checks.append(_check_keyring())
    return checks
