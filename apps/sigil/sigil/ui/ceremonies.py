"""Wave 10 (parity) — surface the sovereign KEY-MATERIAL CEREMONY *status* + run the safe owner ceremonies
in the browser. Shells THIS venv's `sigil <verb> [subcmd]` (FIXED argv, no request input, shell=False) and
returns its text.

READS (OPERATOR+, the same `config_nonsecret` tier as `/api/doctor`, enforced at the route) — every status
here prints only PUBLIC key material + at-rest sealing METADATA (owner pubkey, succession epochs, KEK/DEK/
warden sealed-state, kernel pin, config drift) — never a private key or secret, and none unseal the private
key; but `key status` also surfaces absolute sealed-key file PATHS + the SEALED/PLAINTEXT posture + per-
account TOTP labels, the same operational/FS-layout class doctor gates to operator+.

MUTATIONS (OWNER-ONLY `secrets`, enforced at the route) — `vault_provision` (TPM-seal a fresh KEK) and
`kernel_pin` (owner-sign the kernel binary hash into the manifest). Both are ZERO-arg, idempotent-ish, and
reuse the AUDITED CLI ceremony so no signing/sealing is re-implemented here; the owner key is sealed on the
host and never crosses — only the CLI's secret-free stdout returns. The remaining owner-key mutations
(key rotate/re-genesis, mesh authorize, warden-anchor-set, delegate-offense, floor reset) are wired in
later slices. FATAL-2: pure sovereign — spawns `python -m sigil`, imports no framework/strix.
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


# --- OWNER-ONLY mutations (route gates `secrets`) — ZERO-arg, reuse the audited CLI ceremony ----------

def vault_provision() -> dict:
    """`sigil vault provision` — TPM-seal a FRESH KEK to this machine so the trust root + secrets seal at
    rest (owner ceremony; zero-arg, idempotent — a no-op if a KEK is already present). Fixed argv; the CLI
    does the sealing on the host, the browser sees only the secret-free status text."""
    return _run(["vault", "provision"], timeout=60)


def kernel_pin() -> dict:
    """`sigil kernel pin` — owner-sign the resolved WARDEN kernel binary's content hash into the security
    manifest (owner ceremony; zero-arg). Fails CLOSED if the vault is locked (it will NOT mint a new owner
    identity over the old one). Fixed argv; output is secret-free (path + sha256 + scope)."""
    return _run(["kernel", "pin"], timeout=60)
