"""Settings — the owner-signed secrets + model plane behind the UI's Settings screen (VIGIL COMMAND P4).

The browser never holds or receives key material. It sends an authenticated REQUEST ("seal this key",
"use this model"); the SERVER seals via the hardened `SecretStore` (keyring → TPM-sealed → 0600 env
file) and records only a **fingerprint** on the spine — the secret value NEVER enters the append-only
spine, a log, or any HTTP response. Reads return a REDACTED status only.

Two closed allowlists keep this a real, bounded control (never an arbitrary env-poisoning surface):
  • SECRET_NAMES — the exact secret names the plane may seal (the LLM API key both planes read).
  • MODEL_CHOICES — the exact model IDs the picker may select (served to the UI, so the UI hard-codes
    no model list). Choosing one persists the canonical model env vars BOTH planes honor:
    `CRUCIBLE_ANTHROPIC_MODEL` (the offense reasoning backend reads it) and `SIGIL_LLM_MODEL` (the
    sovereign research/reasoning default). The mechanical fast-extraction helpers keep their own fast
    model by design and are out of scope — the UI says so plainly, so the control is honest.
"""
from __future__ import annotations

import hashlib
import os
from typing import Optional

from ..config import SIGIL_HOME
from ..platform.secrets import SecretStore

# The one secret the settings plane may seal today: the Anthropic/Claude API key. Stored under the name
# BOTH planes resolve (`sigil.config` reads SIGIL_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY; the offense
# AnthropicBackend reads ANTHROPIC_API_KEY) so a single seal feeds the whole system. A closed set — an
# unknown name is refused, so the UI can never seal an arbitrary env var. GITHUB_TOKEN is what the
# auto-patch engine uses to push a fix branch + open a gated PR (LAP-3); it is sealed + delivered exactly
# like the LLM key and never returned to the browser.
SECRET_NAMES = ("ANTHROPIC_API_KEY", "GITHUB_TOKEN")
# Friendly labels + one-line purposes the UI shows per managed secret (the UI hard-codes no secret list).
SECRET_META = {
    "ANTHROPIC_API_KEY": {"label": "Claude / Anthropic API key",
                          "purpose": "Lets the AI reason over your target (engagements, scans, fix proposals)."},
    "GITHUB_TOKEN": {"label": "GitHub token",
                     "purpose": "Lets the auto-patch engine push a fix branch and open a gated pull request. "
                                "Needs 'repo' + 'pull-request' scope. Optional until you use live auto-patch."},
}
_MAX_SECRET_LEN = 8192

# The canonical env vars each plane reads (persisted, non-secret) + delivered to the keyless offense
# engine by `vigil up`. Three DISTINCT knobs — conflating them was the P4 red-pen bug (a backend NAME
# stuffed into a model-id var):
#   * CRUCIBLE_LLM_BACKEND  — SELECTS the offense backend by name (e.g. "claude-code" → the local
#     Claude-Code session, keyless). Read by kernel/llm.py get_backend() as the override.
#   * CRUCIBLE_ANTHROPIC_MODEL — the MODEL ID the anthropic-SDK backend calls. Read by AnthropicBackend.
#   * SIGIL_LLM_MODEL — the sovereign research MODEL passed to `claude -p --model`. Read by scholar.
# set_model sets only the right subset per choice and CLEARS the others, so no stale/invalid value leaks.
_BACKEND_ENV = "CRUCIBLE_LLM_BACKEND"
_ANTHROPIC_MODEL_ENV = "CRUCIBLE_ANTHROPIC_MODEL"
_SIGIL_MODEL_ENV = "SIGIL_LLM_MODEL"
MODEL_ENV_VARS = (_BACKEND_ENV, _ANTHROPIC_MODEL_ENV, _SIGIL_MODEL_ENV)
_CHOICE_ENV = "VIGIL_MODEL_CHOICE"               # the selected choice id — the status view's source of truth
_DEFAULT_OFFENSE_MODEL = "claude-sonnet-4-6"     # AnthropicBackend's built-in default, for the status view

# The closed set of selectable models (served to the UI — the UI hard-codes NO model list). `keyless`
# marks the choice that routes the offense engine to the local Claude Code session (a BACKEND, no API
# key). The other ids are the Claude model identifiers this project targets across the codebase.
MODEL_CHOICES = (
    {"id": "claude-opus-5", "label": "Claude Opus 5",
     "note": "Most capable — deepest reasoning over your target. Needs an API key.", "keyless": False},
    {"id": "claude-sonnet-5", "label": "Claude Sonnet 5",
     "note": "Balanced speed and capability for most engagements. Needs an API key.", "keyless": False},
    {"id": "claude-haiku-4-5-20251001", "label": "Claude Haiku 4.5",
     "note": "Fastest and cheapest for lighter runs. Needs an API key.", "keyless": False},
    {"id": "claude-code", "label": "Claude Code (local session)",
     "note": "Uses your logged-in Claude Code session on this machine — no API key required.",
     "keyless": True},
)
_MODEL_IDS = frozenset(c["id"] for c in MODEL_CHOICES)
_KEYLESS_IDS = frozenset(c["id"] for c in MODEL_CHOICES if c["keyless"])


def _env_plan(model: str) -> dict:
    """The exact env a choice applies (empty string = CLEAR the var). A keyless choice (claude-code)
    ROUTES the offense backend by name and clears the model-id vars — feeding a backend name to the
    anthropic SDK / `claude --model` was the red-pen bug. An API-model choice sets the model ids and
    clears any forced backend so offense availability selects the anthropic SDK when a key is present."""
    if model in _KEYLESS_IDS:
        return {_BACKEND_ENV: model, _ANTHROPIC_MODEL_ENV: "", _SIGIL_MODEL_ENV: ""}
    return {_BACKEND_ENV: "", _ANTHROPIC_MODEL_ENV: model, _SIGIL_MODEL_ENV: model}


def _fingerprint(value: str) -> str:
    """A short, non-reversible fingerprint of a secret — safe to display and to record on the spine.
    Salted with a fixed domain label so it can't be matched against a bare sha256 of a guessed key."""
    digest = hashlib.sha256(b"sigil/secret-fingerprint\x00" + value.encode("utf-8")).hexdigest()
    return "sha256:" + digest[:12]


def _persist_env(key: str, value: str) -> None:
    """Upsert (or, when ``value`` is "", REMOVE) a NON-secret var in `~/.sigil/sigil.env` (0600, no
    world-readable window) and mirror the change into this process's env. Clearing leaves no stale line
    and pops the var, so a prior choice's var never lingers to be re-delivered to the offense engine."""
    f = SIGIL_HOME / "sigil.env"
    SIGIL_HOME.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    try:
        for ln in f.read_text(encoding="utf-8").splitlines():
            if ln.split("=", 1)[0].strip() != key:
                lines.append(ln)                 # drop any existing line for this key
    except OSError:
        pass
    if value != "":
        lines.append(f"{key}={value}")
    fd = os.open(str(f), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    if value == "":
        os.environ.pop(key, None)
    else:
        os.environ[key] = value


def _record_signed_event(store, owner_key, core: dict, reason: str) -> Optional[int]:
    """Append one owner-signed governance event to the spine (same pattern as KillSwitch/PromotionPolicy).
    `core` carries ONLY non-secret fields (a fingerprint, a name, a model id) — never a secret value."""
    from ..governor.authn import signed_payload
    payload = {**signed_payload(core, owner_key), "by": "owner", "reason": str(reason or "")[:200],
               "tier": "A0", "decision": "auto"}
    return store.append(kind="event", source="governor", actor="SETTINGS", payload=payload)


def set_secret(name: str, value: str, *, store, owner_key, reason: str = "") -> dict:
    """Seal a secret. Returns {ok, name, fingerprint, backend, recorded_seq} — NEVER the value.
    Refuses an unknown name or an empty/oversized value (fail-closed)."""
    if name not in SECRET_NAMES:
        raise ValueError(f"unknown secret {name!r}: only {', '.join(SECRET_NAMES)} may be set here")
    if not isinstance(value, str):
        raise ValueError("secret value must be a string")
    value = value.strip()
    if not value:
        raise ValueError("secret value is empty")
    if len(value) > _MAX_SECRET_LEN:
        raise ValueError(f"secret value too large (>{_MAX_SECRET_LEN} bytes)")
    # Reject control characters. A newline would let a value inject an extra line into the envfile tier
    # (`KEY=value\nEVIL=...`); an API key is printable text anyway. Defense-in-depth even for an owner.
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in value):
        raise ValueError("secret value contains control characters")
    fp = _fingerprint(value)
    backend = SecretStore().set(name, value)          # keyring → sealed → 0600 env file; never the spine
    seq = _record_signed_event(
        store, owner_key,
        {"signal": "governor.secret_set", "name": name, "fp": fp, "backend": backend}, reason)
    return {"ok": True, "action": "set_secret", "name": name, "fingerprint": fp,
            "backend": backend, "recorded_seq": seq}


def set_model(model: str, *, store, owner_key, reason: str = "") -> dict:
    """Select the primary reasoning model (a closed allowlist). Applies the choice's exact env plan for
    BOTH planes (routing the backend for a keyless choice, setting the model id otherwise, clearing the
    rest) and records the (non-secret) choice on the spine. Returns {ok, model, backend, recorded_seq}."""
    model = str(model or "").strip()
    if model not in _MODEL_IDS:
        raise ValueError(f"unknown model {model!r}: choose one of {', '.join(sorted(_MODEL_IDS))}")
    plan = _env_plan(model)
    for var, val in plan.items():
        _persist_env(var, val)
    _persist_env(_CHOICE_ENV, model)                 # the display source of truth
    backend = plan.get(_BACKEND_ENV) or "anthropic"
    seq = _record_signed_event(
        store, owner_key, {"signal": "governor.model_set", "model": model, "backend": backend}, reason)
    return {"ok": True, "action": "set_model", "model": model, "backend": backend, "recorded_seq": seq}


def export_runtime_env(include_secrets: bool = False) -> dict:
    """The runtime LLM env the keyless offense engine needs — the model vars (from the process env, where
    sigil.env has been loaded) always, and (only when `include_secrets`) the resolved API key from the
    keyring/TPM-sealed/env store. `vigil up` calls this in the SOVEREIGN venv and injects the result into
    the offense children, so the key/model set in the UI reaches the offense plane without it importing
    sigil. Only non-empty string values are emitted."""
    env: dict = {}
    for var in MODEL_ENV_VARS:
        val = os.environ.get(var, "").strip()
        if val:
            env[var] = val
    if include_secrets:
        ss = SecretStore()
        for name in SECRET_NAMES:
            val = ss.get(name)
            if val:
                env[name] = val
    return env


def settings_status() -> dict:
    """The REDACTED settings view for the UI — never a secret value. For each managed secret: whether it
    is set, its fingerprint, and the backend holding it. Plus the current models and the model catalog
    (so the UI hard-codes nothing) and whether the system will run keyless."""
    ss = SecretStore()
    secrets = []
    key_set = False
    for name in SECRET_NAMES:
        val = ss.get(name)
        present = bool(val)
        if name == "ANTHROPIC_API_KEY" and present:
            key_set = True
        meta = SECRET_META.get(name, {})
        secrets.append({
            "name": name,
            "set": present,
            "fingerprint": _fingerprint(val) if present else None,
            "backend": ss.backend,
            "label": meta.get("label", name),
            "purpose": meta.get("purpose", ""),
        })
    # the SELECTED choice is tracked explicitly (a keyless choice sets no model id), so the picker
    # reflects it even for claude-code. offense_model is the HONEST effective routing: a forced backend
    # (claude-code) shows the local session, otherwise the anthropic-SDK model id (or its default).
    selected = os.environ.get(_CHOICE_ENV, "").strip()
    forced_backend = os.environ.get(_BACKEND_ENV, "").strip()
    anthropic_model = os.environ.get(_ANTHROPIC_MODEL_ENV, "").strip()
    sovereign_model = os.environ.get(_SIGIL_MODEL_ENV, "").strip()
    if forced_backend == "claude-code":
        offense_model = "claude-code (local session)"
    else:
        offense_model = anthropic_model or _DEFAULT_OFFENSE_MODEL
    return {
        "secrets": secrets,
        "secret_backend": ss.backend,
        "models": list(MODEL_CHOICES),
        "selected_model": selected if selected in _MODEL_IDS else None,
        "offense_backend": forced_backend or "anthropic",
        "offense_model": offense_model,
        "sovereign_model": sovereign_model or None,
        "keyless": not key_set,
        "keyless_note": ("No API key is set — engagements run keyless (deterministic oracles only; "
                         "no LLM reasoning) unless you pick the local Claude Code model or add a key."),
    }
