"""Live git ingestion via marker-delimited git hooks (SIGIL §6.2).

Mirrors graphify's hook model (non-destructive, marker-delimited, idempotent) but installs
`post-commit` AND `post-merge` (the spec calls for post-merge) that append new commits to
the spine. Respects `core.hooksPath`. Safe to re-run; `uninstall` removes only SIGIL's block.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

_BEGIN = "# >>> sigil-hook >>>"
_END = "# <<< sigil-hook <<<"
_PY = "/home/kali/.sigil/venv/bin/python"
_BODY = f'{_PY} -m sigil.cli ingest --git-only >/dev/null 2>&1 || true'
_HOOKS = ("post-commit", "post-merge")


def _hooks_dir(repo: Path) -> Path:
    try:
        hp = subprocess.run(["git", "-C", str(repo), "config", "--get", "core.hooksPath"],
                            capture_output=True, text=True, timeout=10).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        hp = ""
    return (repo / hp) if hp else (repo / ".git" / "hooks")


def _block() -> str:
    return f"{_BEGIN}\n{_BODY}\n{_END}\n"


def install(repo: str | Path) -> list[str]:
    repo = Path(repo)
    hd = _hooks_dir(repo)
    hd.mkdir(parents=True, exist_ok=True)
    done = []
    for name in _HOOKS:
        hook = hd / name
        text = hook.read_text(encoding="utf-8") if hook.exists() else "#!/bin/sh\n"
        if _BEGIN in text:
            continue  # idempotent
        if not text.startswith("#!"):
            text = "#!/bin/sh\n" + text
        hook.write_text(text.rstrip("\n") + "\n" + _block(), encoding="utf-8")
        hook.chmod(0o755)
        done.append(name)
    return done


def uninstall(repo: str | Path) -> list[str]:
    repo = Path(repo)
    hd = _hooks_dir(repo)
    done = []
    import re
    pat = re.compile(re.escape(_BEGIN) + r".*?" + re.escape(_END) + r"\n?", re.S)
    for name in _HOOKS:
        hook = hd / name
        if hook.exists() and _BEGIN in (t := hook.read_text(encoding="utf-8")):
            hook.write_text(pat.sub("", t), encoding="utf-8")
            done.append(name)
    return done
