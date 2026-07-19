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
    for line in raw.splitlines():
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
CACHE_DIR = SIGIL_HOME / "cache"

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


# --- effective config + self-check ----------------------------------------------------
_SECRET_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")


def _redact(name: str, value):
    """Redact any value whose KEY NAME looks like a secret. Never inspect the value itself."""
    if value and any(h in name.upper() for h in _SECRET_HINTS):
        return "***redacted***"
    return value


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
    try:
        import urllib.request
        with urllib.request.urlopen(url.rstrip("/") + "/readyz", timeout=2) as r:
            code = getattr(r, "status", None) or r.getcode()
        return ("qdrant", 200 <= int(code) < 300, f"{url} → HTTP {code}")
    except Exception as e:  # noqa: BLE001 — any failure = not reachable
        return ("qdrant", False, f"{url} unreachable: {e}")


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
