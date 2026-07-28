"""
vigil_integration.knowledge_sync — the operator-gated ``knowledge/`` → GitHub sync (K6).

`sync` regenerates the committed knowledge artifacts (the S1 system-map manifest), runs a DEFENSE-IN-DEPTH
secret scan over the folder (refuses the commit on a hit — but it is a net, NOT a guarantee: the operator
still redacts before committing, per knowledge/CONTRIBUTING.md), then ``git add knowledge/`` and
``git commit``. `push` is a SEPARATE, explicit act (the only outward-facing one). These are OPERATOR CLI
verbs — an agent never invokes them, and committing a file makes nothing a FACT (the graph counterparts
stay intel/ungrounded). Pure-stdlib + subprocess; imports no offense/sovereign engine (boundary-clean).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

# A defense-in-depth secret scan (NOT a guarantee — see knowledge/CONTRIBUTING.md; the operator still
# redacts before committing). High-confidence patterns: PEM private keys, provider tokens (the GitHub token
# a GitHub-sync feature is most likely to leak, plus Slack/Stripe/GCP/JWT), and credential ASSIGNMENTS where
# the key name CONTAINS a sensitive word (so `GITHUB_TOKEN=`, `MY_API_KEY=`, `DB_PASSWORD=` are caught — the
# `\b…\b` word boundary treated `_` as a word char and missed exactly those). Deliberately NOT bare
# hex/base64 — the committed system-map manifest carries a legitimate `source_sha` hash that must not fire.
_SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----")),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github-fine-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}")),
    ("gitlab-pat", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("stripe-key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("gcp-service-account", re.compile(
        r'"private_key_id"\s*:\s*"[a-f0-9]{16,}"|"type"\s*:\s*"service_account"')),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    # keyword (possibly a suffix of a longer identifier — re.search finds it anywhere, so `GITHUB_TOKEN=`
    # matches at `TOKEN`), a bounded identifier tail, then `= value`. NO leading greedy prefix (that caused
    # catastrophic backtracking on a long run of identifier chars).
    ("credential-assignment", re.compile(
        r"(?i)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|access[_-]?key)"
        r"[A-Za-z0-9_.\-]{0,40}[ \t]*[:=][ \t]*['\"]?[A-Za-z0-9/+=_\-]{16,}")),
]
# The committed KB is PLAINTEXT knowledge. A binary/compressed/oversized file can't be reliably text-scanned
# for secrets (a secret could hide in a .gz transcript or a renamed .png), so it is REFUSED — never silently
# skipped. Compressed/archive magic bytes; a NUL byte flags a binary; oversized files are only partially
# scannable → also refused.
_COMPRESSED_MAGIC = (b"\x1f\x8b", b"PK\x03\x04", b"%PDF", b"BZh", b"\xfd7zXZ")
_MAX_SCAN_BYTES = 2_000_000


def repo_root(start: Path | None = None) -> Path:
    """Nearest ancestor holding both ``.git`` and ``knowledge/`` — the repo we sync."""
    p = (start or Path(__file__)).resolve()
    for d in [p, *p.parents]:
        if (d / ".git").exists() and (d / "knowledge").is_dir():
            return d
    raise FileNotFoundError("repo root (with .git and knowledge/) not found")


def scan_secrets(root: Path) -> list[tuple[str, str]]:
    """Scan EVERY file under ``knowledge/`` (recursively) — no suffix is exempt, so a secret renamed to a
    benign extension is still caught. Returns ``[(relpath, reason), …]`` where ``reason`` is a secret
    pattern name, ``"binary-unscannable"`` (a compressed/binary file that can't be secret-scanned — commit
    plaintext only), or ``"oversized"`` (larger than the scan cap → not fully clearable). A non-empty result
    REFUSES the commit; the operator removes/redacts, then re-runs. This is a defense-in-depth net, not a
    guarantee — see knowledge/CONTRIBUTING.md."""
    kdir = Path(root) / "knowledge"
    hits: list[tuple[str, str]] = []
    if not kdir.is_dir():
        return hits
    for f in sorted(kdir.rglob("*")):
        if not f.is_file():
            continue
        rel = str(f.relative_to(root))
        try:
            data = f.read_bytes()
        except OSError:
            continue
        head = data[:8192]
        if head.startswith(_COMPRESSED_MAGIC) or b"\x00" in head:
            hits.append((rel, "binary-unscannable"))        # can't text-scan → refuse (plaintext KB only)
            continue
        text = data[:_MAX_SCAN_BYTES].decode("utf-8", "ignore")
        found = next((name for name, pat in _SECRET_PATTERNS if pat.search(text)), None)
        if found:
            hits.append((rel, found))
        elif len(data) > _MAX_SCAN_BYTES:
            hits.append((rel, "oversized"))                 # only partially scannable → refuse (verify it)
    return hits


def _git(root: Path, *args: str, dry_run: bool = False, check: bool = True) -> dict:
    cmd = ["git", "-C", str(root), *args]
    if dry_run:
        return {"dry_run": True, "cmd": cmd}
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return {"cmd": cmd, "code": proc.returncode, "out": proc.stdout.strip(), "err": proc.stderr.strip()}


def regenerate(root: Path) -> str:
    """Re-run the deterministic ``knowledge/sync.sh`` (regenerates the system-map manifest). Returns its
    stdout. No network, no API cost."""
    sh = Path(root) / "knowledge" / "sync.sh"
    proc = subprocess.run(["bash", str(sh)], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"knowledge/sync.sh failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def sync(root: Path | None = None, *, message: str = "", dry_run: bool = False) -> dict:
    """Regenerate → scan (refuse if secrets) → ``git add knowledge/`` → ``git commit``. Commit runs ONLY
    here, and only when ``knowledge/`` actually changed (never an empty commit). Operator-invoked."""
    root = Path(root) if root else repo_root()
    regen = regenerate(root)
    secrets = scan_secrets(root)
    if secrets:
        return {"ok": False, "regenerated": regen, "secrets": secrets,
                "refused": "secret(s) found in knowledge/ — remove or redact before committing"}
    add = _git(root, "add", "knowledge/", dry_run=dry_run)
    msg = (message or "").strip() or "knowledge: sync living KB + regenerate system-map"
    committed = None
    note = None
    if dry_run:
        committed = {"dry_run": True, "cmd": ["git", "-C", str(root), "commit", "-m", msg, "--", "knowledge/"]}
    else:
        staged = _git(root, "diff", "--cached", "--quiet", "--", "knowledge/", check=False)
        if staged.get("code") == 1:                   # 1 == there ARE staged changes under knowledge/
            committed = _git(root, "commit", "-m", msg, "--", "knowledge/")
        else:
            note = "nothing to commit (knowledge/ unchanged)"
    return {"ok": True, "regenerated": regen, "secrets": [], "added": add, "committed": committed, "note": note}


def push(root: Path | None = None, *, dry_run: bool = False) -> dict:
    """The single outward-facing act: ``git push``. Explicit + operator-invoked (never automatic)."""
    root = Path(root) if root else repo_root()
    return {"ok": True, "pushed": _git(root, "push", dry_run=dry_run)}


def status(root: Path | None = None) -> dict:
    """Porcelain git status of ``knowledge/`` — what a sync would commit."""
    root = Path(root) if root else repo_root()
    return {"status": _git(root, "status", "--porcelain", "--", "knowledge/", check=False).get("out", "")}
