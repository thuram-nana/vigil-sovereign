"""SIGIL runtime configuration. All paths local-first, owner-only."""
from __future__ import annotations

import os
from pathlib import Path

# --- data root (runtime, 0700) --------------------------------------------------------
SIGIL_HOME = Path(os.environ.get("SIGIL_HOME", str(Path.home() / ".sigil")))


def _load_env_file() -> None:
    """Load persisted `KEY=VALUE` settings from ~/.sigil/sigil.env so a value set once
    (e.g. SIGIL_QDRANT_URL for server mode) reaches BOTH the CLI and the MCP server that
    Claude spawns without an explicit env. The real environment always wins (setdefault)."""
    f = SIGIL_HOME / "sigil.env"
    if not f.exists():
        return
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())


_load_env_file()

SPINE_PATH = SIGIL_HOME / "spine" / "spine.jsonl"
HEAD_PATH = SIGIL_HOME / "spine" / "head.json"
KEYS_DIR = SIGIL_HOME / "spine" / "keys"
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


def ensure_dirs() -> None:
    for d in (SIGIL_HOME, SPINE_PATH.parent, KEYS_DIR, CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
