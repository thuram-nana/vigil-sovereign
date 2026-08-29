"""Wave 10 (parity) — surface the sovereign KEY-MATERIAL CEREMONY *status* in the browser, read-only.
Shells THIS venv's `sigil <verb> [status]` (fixed argv, no request input, shell=False) and returns its
text. OPERATOR+ reads (the same `config_nonsecret` tier as `/api/doctor`, enforced at the route) — every
status here prints only PUBLIC key material + at-rest sealing METADATA (owner pubkey, succession epochs,
KEK/DEK/warden sealed-state, kernel pin, config drift) — never a private key or secret, and none of these
reads unseal the private key; but `key status` also surfaces absolute sealed-key file PATHS + the
SEALED/PLAINTEXT posture + per-account TOTP labels, the same operational/FS-layout class doctor gates to
operator+. This module is the pure reader. The owner-key MUTATIONS (vault provision,
kernel pin, key rotate, mesh authorize, warden-anchor-set, delegate-offense, floor reset) are wired
owner-only in a later slice; this is the status half only. FATAL-2: pure sovereign — spawns
`python -m sigil`, imports no framework/strix.
"""
from __future__ import annotations

import subprocess
import sys


def _run(argv_tail: list, timeout: int = 30) -> dict:
    # FIXED argv — every element is a literal here (never request-controlled); shell=False.
    verb = argv_tail[0]
    try:
        proc = subprocess.run([sys.executable, "-m", "sigil", *argv_tail],   # noqa: S603 — fixed argv, shell=False
                              capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": proc.returncode == 0, "verb": verb, "exit_code": proc.returncode,
            "text": (proc.stdout or "")[:8000], "stderr": (proc.stderr or "")[:1000]}


def vault_status() -> dict:
    """`sigil vault status` — at-rest sealing of the trust root under the TPM-sealed KEK (provisioned?)."""
    return _run(["vault", "status"])


def kernel_status() -> dict:
    """`sigil kernel status` — the WARDEN kernel integrity pin + config drift (owner-signed manifest state)."""
    return _run(["kernel", "status"])


def key_status() -> dict:
    """`sigil key status` — the owner-key succession chain (pinned genesis -> epochs -> validated tip) + the
    per-key at-rest sealing state. PUBLIC keys + metadata only; fail-closed on a forked/tampered chain."""
    return _run(["key", "status"])


def owner_pubkey_show() -> dict:
    """`sigil owner-pubkey` — the base64 owner PUBLIC key (the private half never leaves the sovereign store)."""
    return _run(["owner-pubkey"])
