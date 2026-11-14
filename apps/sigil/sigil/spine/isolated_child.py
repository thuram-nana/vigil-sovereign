"""Run a sovereign step in a CHILD process scoped to ONE home — the helpers the upgrade drill and the home-unit
verifier share.

Every head / floor / key / archive path the spine code reads is derived from the PROCESS's ``SIGIL_HOME`` at import
time. A step that must read ANOTHER home (a drill copy, a staged restore, an operator-named home) therefore runs in
a child whose ``SIGIL_HOME`` is that home and whose ``TMPDIR`` is inside a private work dir. The parent proves it
launched the child with a ONE-SHOT nonce: a file it writes into the work dir plus the same value in the child's
environment; the child consumes the file whether or not it matches, so the hidden entry point never authorizes a
second run and a hand-run against a real home refuses. The child prints one JSON line as its verdict.

Sovereign plane; stdlib only.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


def run_isolated(module: str, argv: "list[str]", *, home: Path, work_dir: Path, nonce_file: str, nonce_env: str,
                 timeout: float, extra_env: "Optional[dict[str, str]]" = None) -> "subprocess.CompletedProcess[str]":
    """Run ``python -m <module> <argv…>`` with ``SIGIL_HOME=home`` and ``TMPDIR=<work_dir>/tmp`` (plus
    ``extra_env``), handing it a one-shot nonce through ``<work_dir>/<nonce_file>`` and ``$<nonce_env>``. The nonce
    file is removed again whatever the child did. Returns the completed process (stdout/stderr captured as text)."""
    import sigil
    pkg_root = str(Path(sigil.__file__).resolve().parent.parent)
    tmp = work_dir / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["SIGIL_HOME"] = str(home)
    env["TMPDIR"] = str(tmp)
    env["PYTHONPATH"] = os.pathsep.join([pkg_root] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    for k, v in (extra_env or {}).items():
        env[k] = v
    nonce, nonce_path = secrets.token_hex(16), work_dir / nonce_file
    nonce_path.unlink(missing_ok=True)
    fd = os.open(str(nonce_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, nonce.encode("ascii"))
    finally:
        os.close(fd)
    env[nonce_env] = nonce
    try:
        return subprocess.run([sys.executable, "-m", module, *argv], cwd=str(work_dir), env=env,
                              capture_output=True, text=True, timeout=timeout)
    finally:
        nonce_path.unlink(missing_ok=True)


def last_json_line(stdout: "Optional[str]") -> "Optional[dict]":
    """The child's verdict: its LAST stdout line parsed as a JSON object, or None."""
    try:
        res = json.loads((stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None
    return res if isinstance(res, dict) else None


def consume_nonce(work_dir: Path, nonce_file: str, nonce_env: str) -> bool:
    """CHILD side: True iff the parent's nonce file in ``work_dir`` matches ``$<nonce_env>``. The file is consumed
    (removed) either way, so it never authorizes a second run."""
    path = Path(work_dir) / nonce_file
    try:
        made = path.read_text(encoding="ascii").strip()
        path.unlink()
    except (OSError, UnicodeDecodeError):
        made = ""
    sent = os.environ.get(nonce_env, "").encode("utf-8", "surrogateescape")
    return bool(made and hmac.compare_digest(made.encode(), sent))


def tempdir_outside(work_dir: Path) -> "Optional[Path]":
    """CHILD side: this process's temp dir when it is NOT inside ``work_dir`` (resolved), else None."""
    tmp = Path(tempfile.gettempdir()).resolve()
    return None if tmp.is_relative_to(Path(work_dir).resolve()) else tmp
