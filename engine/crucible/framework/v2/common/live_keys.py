"""live_keys — hot-reload the Anthropic API key for the RUNNING offense engine.

A key re-sealed through the UI (sigil settings.set_secret -> ~/.sigil/sigil.env) must reach the running
engine WITHOUT a Stop->Start. These two helpers re-read the CURRENT persisted key at CALL time so every
in-process consumer (the live think step, the console chat, the kernel Anthropic backend) and the Anthropic
SDK itself (which reads ANTHROPIC_API_KEY from the environment) pick up a re-seal on their next call.

Gated by ``VIGIL_LIVE_KEY_RELOAD`` (uiproxy sets it for its managed children) so a test or a bare-shell
``vigil engage`` keeps the plain-env behaviour and never reads a stray ``~/.sigil`` key. This is a pure data
read of a 0600 file (the plaintext ``sigil.env`` backend) + an in-place ``os.environ`` update; it imports no
sovereign code (FATAL-2-clean), never logs the key value, and never raises. A keyring / TPM-vault secret is
NOT re-read here (the offense process cannot unseal the sovereign vault), so those backends still need a
Start-offense — a named, honest residual.
"""

from __future__ import annotations

import os
import pathlib

# Mirrors sigil.config.effective_config's precedence: the SIGIL_-prefixed override wins over the bare name.
_KEY_NAMES = ("SIGIL_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")


def read_persisted_anthropic_key() -> "str | None":
    """Re-read the CURRENT Anthropic key from ``$SIGIL_HOME/sigil.env`` (default ``~/.sigil/sigil.env``) at
    call time. Mirrors ``sigil.config._load_env_file``'s parse (split on "\\n", ``partition("=")``, strip) and
    its ``SIGIL_ANTHROPIC_API_KEY`` > ``ANTHROPIC_API_KEY`` precedence, but ONLY extracts the key and NEVER
    mutates ``os.environ``. UNGATED — the caller applies the ``VIGIL_LIVE_KEY_RELOAD`` gate. Returns the value
    or ``None`` (a missing / unreadable / sealed-backend store -> None). Never raises, never logs the value."""
    try:
        home = os.environ.get("SIGIL_HOME") or str(pathlib.Path.home() / ".sigil")
        f = pathlib.Path(home) / "sigil.env"
        if not f.exists():
            return None
        raw = f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    found: dict = {}
    for line in raw.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        if k in _KEY_NAMES:
            v = v.strip()
            if v:
                found[k] = v
    return found.get("SIGIL_ANTHROPIC_API_KEY") or found.get("ANTHROPIC_API_KEY")


def refresh_live_anthropic_key() -> bool:
    """In the MANAGED offense engine (``VIGIL_LIVE_KEY_RELOAD=1``) ONLY, update
    ``os.environ['ANTHROPIC_API_KEY']`` in place from the CURRENT persisted key, so every in-process consumer
    and the Anthropic SDK (which reads the env) pick up a UI re-seal without a restart. Returns ``True`` iff
    the value CHANGED (so a caller that caches an SDK client can rebuild it on change). A no-op returning
    ``False`` when the flag is unset or nothing is persisted (a shell-only operator is unaffected). Never
    raises, never logs the value."""
    if os.environ.get("VIGIL_LIVE_KEY_RELOAD") != "1":
        return False
    fresh = read_persisted_anthropic_key()
    if not (isinstance(fresh, str) and fresh.strip()):
        return False
    if os.environ.get("ANTHROPIC_API_KEY") == fresh:
        return False
    os.environ["ANTHROPIC_API_KEY"] = fresh
    return True
