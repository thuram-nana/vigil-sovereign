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

from ..config import SIGIL_HOME, assert_env_key_safe, assert_env_value_safe
from ..platform.secrets import SecretStore

# The one secret the settings plane may seal today: the Anthropic/Claude API key. Stored under the name
# BOTH planes resolve (`sigil.config` reads SIGIL_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY; the offense
# AnthropicBackend reads ANTHROPIC_API_KEY) so a single seal feeds the whole system. A closed set — an
# unknown name is refused, so the UI can never seal an arbitrary env var. GITHUB_TOKEN is what the
# auto-patch engine uses to push a fix branch + open a gated PR (LAP-3); it is sealed + delivered exactly
# like the LLM key and never returned to the browser.
# The full inventory of secrets the system uses, grouped by category (the UI hard-codes no secret list — it
# renders whatever settings_status serves). A closed allowlist: an unknown name is refused by set_secret, so
# the UI can never seal an arbitrary env var. `category` groups the API-keys screen; `probe` flags whether a
# LIVE health check exists (see platform/secret_probes.py) so a bad/expired key shows as FAILING, not green.
SECRET_META = {
    # --- LLM providers (the AI that reasons over your target; bring-your-own-model) ---
    "ANTHROPIC_API_KEY": {"category": "llm", "probe": True, "label": "Claude / Anthropic API key",
                          "purpose": "Lets the AI reason over your target (engagements, scans, fix proposals)."},
    "MISTRAL_API_KEY": {"category": "llm", "probe": True, "label": "Mistral API key",
                        "purpose": "Bring-your-own-model: route the reasoning engine through Mistral."},
    "OPENAI_API_KEY": {"category": "llm", "probe": True, "label": "OpenAI API key",
                       "purpose": "Bring-your-own-model for the Strix agent body (OpenAI / Azure OpenAI models)."},
    "PERPLEXITY_API_KEY": {"category": "llm", "probe": True, "label": "Perplexity API key",
                           "purpose": "Lets the agent do live web research during a codebase engagement (Strix)."},
    "AZURE_OPENAI_API_KEY": {"category": "llm", "probe": True, "label": "Azure OpenAI API key",
                             "purpose": "Bring-your-own-model via Azure OpenAI. Also set the endpoint in Models."},
    # --- Cloud credentials (read-only; used by cloud/Bedrock + Phase-C cloud pentesting) ---
    "AWS_ACCESS_KEY_ID": {"category": "cloud", "probe": True, "label": "AWS access key id",
                          "purpose": "Read-only AWS creds for Bedrock models and cloud posture testing. "
                                     "Pair with the secret access key below."},
    "AWS_SECRET_ACCESS_KEY": {"category": "cloud", "probe": False, "label": "AWS secret access key",
                              "purpose": "The secret half of the AWS credential pair (validated via the access "
                                         "key id)."},
    # --- Integrations ---
    "GITHUB_TOKEN": {"category": "integration", "probe": True, "label": "GitHub token",
                     "purpose": "Lets the auto-patch engine push a fix branch and open a gated pull request. "
                                "Needs 'repo' + 'pull-request' scope. Optional until you use live auto-patch."},
    "ELEVENLABS_API_KEY": {"category": "integration", "probe": True, "label": "ElevenLabs API key",
                           "purpose": "Voice output (JARVIS TTS). Optional."},
    "CRUCIBLE_API_KEY": {"category": "integration", "probe": False, "label": "Gated-API shared secret",
                         "purpose": "Protects the offense gated API when you host the cockpit behind a domain. "
                                    "An internal secret you choose — no external service to check."},
    "CRUCIBLE_OOB_RELAY_SECRET": {"category": "integration", "probe": False, "label": "OOB relay secret",
                                  "purpose": "Authenticates out-of-band (OAST) callbacks. Internal secret."},
    # --- Auto-patch signing (the m-of-n destruction quorum) ---
    "VIGIL_DESTRUCTION_OWNER_KEY": {
        "category": "destruction", "probe": False, "label": "Auto-patch signing key (owner)",
        "purpose": "The owner key that AUTHORIZES an auto-patch pull request (the m-of-n destruction quorum). "
                   "Generate it with `vigil provision-destruction` and seal it here. Deliberately NOT broadcast "
                   "to the offense engine: the `vigil authorize-destruction` step reads it from the "
                   "VIGIL_DESTRUCTION_OWNER_KEY env, so run that one command in a shell where it is exported. "
                   "Optional until you open PRs. Solo setups: whoever holds this key can authorize — for "
                   "separation of duties, provision with more signers and keep their keys off this machine."},
}
# Ordered allowlist (grouping order preserved for the UI). Only these names may be sealed here.
SECRET_NAMES = tuple(SECRET_META.keys())
_SECRET_CATEGORY_ORDER = ("llm", "cloud", "integration", "destruction")
_SECRET_CATEGORY_LABEL = {"llm": "AI model providers", "cloud": "Cloud credentials",
                          "integration": "Integrations", "destruction": "Auto-patch signing"}
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
_DEFAULT_OFFENSE_MODEL = "claude-opus-5"          # AnthropicBackend's built-in default, for the status view

# Reasoning-effort control (persisted, non-secret, delivered to offense). Current-gen models read it as
# output_config.effort; older ones ignore it. "" = the model's own default. Kept OUT of PROVIDER_ENV_VARS
# so switching provider never clears the operator's effort choice; delivered via _EXTRA_DELIVERED_ENV.
_EFFORT_ENV = "CRUCIBLE_EFFORT"
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
_EXTRA_DELIVERED_ENV = (_EFFORT_ENV,)             # non-provider model-plane vars also bridged to offense

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
    """The exact env a built-in Claude choice applies (empty string = CLEAR the var). A keyless choice
    (claude-code) ROUTES the offense backend by name and clears the model-id vars; an API-model choice sets
    the model ids and clears any forced backend. Retained for back-compat; set_model now routes through
    set_provider (the general BYO path) so there is one env-writer."""
    if model in _KEYLESS_IDS:
        return {_BACKEND_ENV: model, _ANTHROPIC_MODEL_ENV: "", _SIGIL_MODEL_ENV: ""}
    return {_BACKEND_ENV: "", _ANTHROPIC_MODEL_ENV: model, _SIGIL_MODEL_ENV: model}


# --- Bring-your-own-model providers (Phase A2b) ----------------------------------------------------
# The closed provider registry. Selecting a provider ROUTES CRUCIBLE_LLM_BACKEND + the provider's model var
# + its (non-secret) config vars, CLEARS every other provider's vars, and maps the same choice onto Strix
# (STRIX_LLM/LLM_API_BASE) so the codebase agent uses the same model. Keys live in the API-keys plane
# (SECRET_META, category llm/cloud); config (regions/endpoints/project ids) lives here. `backend` is the
# CRUCIBLE_LLM_BACKEND value ("" = the default anthropic SDK); `model_var` is where the model/deployment id
# goes; `sovereign_model` marks providers whose model also drives SIGIL research (`claude -p`).
_PROVIDER_ORDER = ("anthropic", "anthropic-zdr", "bedrock", "vertex", "mistral", "azure_openai",
                   "self-hosted", "ollama", "claude-code")
PROVIDERS = {
    "anthropic": {"label": "Claude (Anthropic API)", "backend": "", "model_var": _ANTHROPIC_MODEL_ENV,
                  "models": ["claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5-20251001"],
                  "keyless": False, "keys": ["ANTHROPIC_API_KEY"], "config": (),
                  "strix": "anthropic/{model}", "sovereign_model": True},
    "anthropic-zdr": {"label": "Claude (zero-data-retention API)", "backend": "anthropic-zdr",
                      "model_var": _ANTHROPIC_MODEL_ENV, "models": ["claude-opus-5", "claude-sonnet-5"],
                      "keyless": False, "keys": ["ANTHROPIC_API_KEY"], "config": (),
                      "strix": "anthropic/{model}", "sovereign_model": True},
    "bedrock": {"label": "Claude on AWS Bedrock", "backend": "bedrock", "model_var": "CRUCIBLE_BEDROCK_MODEL",
                "models": ["anthropic.claude-opus-5", "anthropic.claude-sonnet-5"], "keyless": False,
                "keys": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], "strix": "bedrock/{model}",
                "config": ({"env": "CRUCIBLE_BEDROCK_REGION", "label": "AWS region",
                            "placeholder": "eu-west-1", "required": True},)},
    "vertex": {"label": "Claude on Google Vertex", "backend": "vertex", "model_var": "CRUCIBLE_VERTEX_MODEL",
               "models": ["claude-opus-5", "claude-sonnet-5"], "keyless": False, "keys": [],
               "strix": "vertex_ai/{model}",
               "note": "Also set GOOGLE_APPLICATION_CREDENTIALS (service-account JSON path) below.",
               "config": ({"env": "CRUCIBLE_VERTEX_PROJECT", "label": "GCP project id",
                           "placeholder": "my-project", "required": True},
                          {"env": "CRUCIBLE_VERTEX_REGION", "label": "Vertex region",
                           "placeholder": "europe-west4", "required": True},
                          {"env": "GOOGLE_APPLICATION_CREDENTIALS", "label": "Service-account JSON path",
                           "placeholder": "/path/to/sa.json", "required": True})},
    "mistral": {"label": "Mistral (EU)", "backend": "mistral", "model_var": "CRUCIBLE_MISTRAL_MODEL",
                "models": ["mistral-large-latest"], "keyless": False, "keys": ["MISTRAL_API_KEY"],
                "config": (), "strix": "mistral/{model}"},
    "azure_openai": {"label": "Azure OpenAI", "backend": "azure_openai",
                     "model_var": "CRUCIBLE_AZURE_OPENAI_DEPLOYMENT", "models": [], "keyless": False,
                     "keys": ["AZURE_OPENAI_API_KEY"], "strix": "azure/{model}",
                     "config": ({"env": "AZURE_OPENAI_ENDPOINT", "label": "Azure endpoint",
                                 "placeholder": "https://<resource>.openai.azure.com", "required": True},
                                {"env": "CRUCIBLE_AZURE_OPENAI_API_VERSION", "label": "API version",
                                 "placeholder": "2024-06-01", "required": False})},
    "self-hosted": {"label": "Self-hosted (OpenAI-compatible)", "backend": "self-hosted",
                    "model_var": "CRUCIBLE_SELFHOSTED_MODEL", "models": [], "keyless": True, "keys": [],
                    "strix": "openai/{model}", "strix_base": "CRUCIBLE_SELFHOSTED_ENDPOINT",
                    "config": ({"env": "CRUCIBLE_SELFHOSTED_ENDPOINT", "label": "OpenAI-compatible base URL",
                                "placeholder": "http://localhost:8000/v1", "required": True},)},
    "ollama": {"label": "Ollama (local)", "backend": "ollama", "model_var": "CRUCIBLE_OLLAMA_MODEL",
               "models": ["qwen2.5-coder:32b"], "keyless": True, "keys": [], "strix": "ollama/{model}",
               "strix_base": "CRUCIBLE_OLLAMA_HOST",
               "config": ({"env": "CRUCIBLE_OLLAMA_HOST", "label": "Ollama host",
                           "placeholder": "http://localhost:11434", "required": False},)},
    "claude-code": {"label": "Claude Code (local session)", "backend": "claude-code", "model_var": "",
                    "models": [], "keyless": True, "keys": [], "config": (), "strix": ""},
}
_PROVIDER_IDS = frozenset(PROVIDERS)
_STRIX_VARS = ("STRIX_LLM", "LLM_API_BASE")
# Every var any provider touches — set_provider CLEARS all of these, then sets the chosen provider's subset,
# so a prior provider's model/region/endpoint never lingers to mislead the engine. Also the exact set
# export_runtime_env delivers to the offense plane.
_ALL_MODEL_VARS = tuple(sorted({p["model_var"] for p in PROVIDERS.values() if p.get("model_var")}))
_ALL_CONFIG_VARS = tuple(sorted({c["env"] for p in PROVIDERS.values() for c in p.get("config", ())}))
PROVIDER_ENV_VARS = tuple(dict.fromkeys(
    (_BACKEND_ENV, _ANTHROPIC_MODEL_ENV, _SIGIL_MODEL_ENV, _CHOICE_ENV, *_ALL_MODEL_VARS,
     *_ALL_CONFIG_VARS, *_STRIX_VARS)))
# The sealed secrets that MAY reach the keyless offense engine (least-privilege): every managed secret EXCEPT
# the auto-patch signing key and the voice key. VIGIL_DESTRUCTION_OWNER_KEY must never reach an offense process
# (it must not be able to self-authorize a destructive PR; A2a red-pen); ELEVENLABS_API_KEY is a sovereign
# voice-TTS concern the offense engine never reads. The GitHub token + LLM/cloud/OAST/gated-API keys ARE
# legitimately needed by the offense engine (PR push, model calls, OAST relay, gated API).
_OFFENSE_EXCLUDED_SECRETS = frozenset({"VIGIL_DESTRUCTION_OWNER_KEY", "ELEVENLABS_API_KEY"})
_OFFENSE_DELIVERED_SECRETS = tuple(n for n in SECRET_NAMES if n not in _OFFENSE_EXCLUDED_SECRETS)

def _validate_config_value(env: str, value: str) -> str:
    """A non-secret provider-config value (region/endpoint/project/path). Reject control/line-break chars
    (envfile line-injection) + oversize; light endpoint sanity (the BACKEND does the authoritative host
    validation at construct time). Returns the cleaned value ("" clears the var)."""
    value = str(value or "").strip()
    if not value:
        return ""
    assert_env_value_safe(value, f"value for {env}", maxlen=1024)
    if env == "AZURE_OPENAI_ENDPOINT" and not value.startswith("https://"):
        raise ValueError("AZURE_OPENAI_ENDPOINT must start with https://")
    if env == "CRUCIBLE_SELFHOSTED_ENDPOINT" and not (value.startswith("http://") or value.startswith("https://")):
        raise ValueError("CRUCIBLE_SELFHOSTED_ENDPOINT must be an http(s) URL")
    return value


def set_provider(provider: str, model: str = "", config: Optional[dict] = None, *,
                 store, owner_key, reason: str = "") -> dict:
    """Route the whole system to a provider: set CRUCIBLE_LLM_BACKEND + the model var + the provider's config
    vars + the Strix mapping, and CLEAR every other provider's vars. Fail-closed on an unknown provider, a
    missing required config field, or an invalid value. Records the (non-secret) choice on the spine. This is
    the single env-writer both the built-in model picker and the BYO picker go through."""
    provider = str(provider or "").strip()
    if provider not in _PROVIDER_IDS:
        raise ValueError(f"unknown provider {provider!r}: choose one of {', '.join(sorted(_PROVIDER_IDS))}")
    spec = PROVIDERS[provider]
    model = str(model or "").strip()
    # model is written into env vars (+ persisted to sigil.env), so it gets the SAME line-injection guard
    # as config/secrets — a newline OR a Unicode line separator (U+0085/U+2028/U+2029, which an ord-only
    # guard misses) could inject an extra `KEY=value` line into the envfile tier. "" is fine (keyless).
    assert_env_value_safe(model, "model id", maxlen=512)
    config = {str(k): str(v) for k, v in (config or {}).items()}

    plan = {v: "" for v in PROVIDER_ENV_VARS}          # start by clearing EVERYTHING, then set the chosen subset
    plan[_BACKEND_ENV] = spec["backend"]               # "" for the default anthropic SDK
    if spec.get("model_var") and model:
        plan[spec["model_var"]] = model
    if spec.get("sovereign_model") and model:
        plan[_SIGIL_MODEL_ENV] = model                 # the same model drives SIGIL research (claude -p)
    # provider config: only the provider's DECLARED config envs are honored; required ones must be present
    declared = {c["env"]: c for c in spec.get("config", ())}
    for env, field in declared.items():
        val = _validate_config_value(env, config.get(env, ""))
        if field.get("required") and not val:
            raise ValueError(f"{spec['label']} needs {field['label']} ({env})")
        plan[env] = val
    # Strix mapping (LiteLLM): same model on the codebase agent. self-hosted/ollama also pass a base URL.
    if spec.get("strix") and model:
        plan["STRIX_LLM"] = spec["strix"].format(model=model)
        base_env = spec.get("strix_base")
        if base_env:
            plan["LLM_API_BASE"] = plan.get(base_env, "")
    plan[_CHOICE_ENV] = provider

    for var, val in plan.items():
        _persist_env(var, val)
    seq = _record_signed_event(
        store, owner_key,
        {"signal": "governor.provider_set", "provider": provider, "backend": spec["backend"] or "anthropic",
         "model": model}, reason)
    return {"ok": True, "action": "set_provider", "provider": provider,
            "backend": spec["backend"] or "anthropic", "model": model, "recorded_seq": seq}


def _fingerprint(value: str) -> str:
    """A short, non-reversible fingerprint of a secret — safe to display and to record on the spine.
    Salted with a fixed domain label so it can't be matched against a bare sha256 of a guessed key."""
    digest = hashlib.sha256(b"sigil/secret-fingerprint\x00" + value.encode("utf-8")).hexdigest()
    return "sha256:" + digest[:12]


def _persist_env(key: str, value: str) -> None:
    """Upsert (or, when ``value`` is "", REMOVE) a NON-secret var in `~/.sigil/sigil.env` (0600, no
    world-readable window) and mirror the change into this process's env. Clearing leaves no stale line
    and pops the var, so a prior choice's var never lingers to be re-delivered to the offense engine."""
    assert_env_key_safe(key)                                    # guard BOTH axes at the write primitive
    if value != "":
        assert_env_value_safe(value, f"env value for {key}")   # airtight backstop
    f = SIGIL_HOME / "sigil.env"
    SIGIL_HOME.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    try:
        # Parse on "\n" ONLY (not str.splitlines()) so a value that contains a Unicode line separator
        # (U+0085/U+2028/U+2029) is never re-split into a new line and re-materialized as a real newline
        # on rewrite — the envfile line-injection re-check caught exactly that. Blank lines are dropped.
        for ln in f.read_text(encoding="utf-8").split("\n"):
            if not ln.strip():
                continue
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
    # Reject oversize + any char that could break the envfile tier into an extra `KEY=value` line — a
    # newline OR a Unicode line separator (U+0085/U+2028/U+2029). An API key is printable text anyway.
    # Defense-in-depth even for an owner: a value must never be able to plant VIGIL_DESTRUCTION_OWNER_KEY.
    assert_env_value_safe(value, "secret value", maxlen=_MAX_SECRET_LEN)
    fp = _fingerprint(value)
    backend = SecretStore().set(name, value)          # keyring → sealed → 0600 env file; never the spine
    seq = _record_signed_event(
        store, owner_key,
        {"signal": "governor.secret_set", "name": name, "fp": fp, "backend": backend}, reason)
    return {"ok": True, "action": "set_secret", "name": name, "fingerprint": fp,
            "backend": backend, "recorded_seq": seq}


def check_secret(name: str, *, store, owner_key, reason: str = "") -> dict:
    """Run a LIVE health probe for one secret (does it actually work?) and record the (non-secret) verdict on
    the spine. Returns {ok, name, status, reason, checked_at} — never the value. Fail-closed: an unknown name
    is refused; any probe error is a FAIL, never a false ok."""
    if name not in SECRET_NAMES:
        raise ValueError(f"unknown secret {name!r}: only {', '.join(SECRET_NAMES)} may be checked here")
    from ..platform.secret_probes import check_secret_health
    verdict = check_secret_health(name)          # {name,status,reason,checked_at}; value never touched
    seq = _record_signed_event(
        store, owner_key,
        {"signal": "governor.secret_checked", "name": name, "status": verdict["status"]}, reason)
    return {"ok": True, "action": "check_secret", "recorded_seq": seq, **verdict}


def check_secrets(*, store, owner_key, reason: str = "") -> dict:
    """Run live health probes for every SET, probeable secret; record one summary event. Never a value."""
    from ..platform.secret_probes import check_all
    results = check_all([n for n in SECRET_NAMES if SECRET_META.get(n, {}).get("probe")])
    failing = sorted(r["name"] for r in results if r.get("status") == "fail")
    seq = _record_signed_event(
        store, owner_key,
        {"signal": "governor.secrets_checked", "checked": len(results), "failing": len(failing)}, reason)
    return {"ok": True, "action": "check_secrets", "results": results, "failing": failing, "recorded_seq": seq}


def set_model(model: str, *, store, owner_key, reason: str = "") -> dict:
    """Select a built-in Claude model (a closed allowlist) — the quick picker. Routes through set_provider (the
    single env-writer): a keyless id → the claude-code provider, else the anthropic provider. Returns the
    set_model-shaped result for back-compat."""
    model = str(model or "").strip()
    if model not in _MODEL_IDS:
        raise ValueError(f"unknown model {model!r}: choose one of {', '.join(sorted(_MODEL_IDS))}")
    if model in _KEYLESS_IDS:
        r = set_provider("claude-code", "", store=store, owner_key=owner_key, reason=reason)
    else:
        r = set_provider("anthropic", model, store=store, owner_key=owner_key, reason=reason)
    return {"ok": True, "action": "set_model", "model": model, "backend": r["backend"],
            "recorded_seq": r["recorded_seq"]}


def set_effort(effort: str, *, store, owner_key, reason: str = "") -> dict:
    """Set the reasoning-effort level applied to current-gen models (output_config.effort) on BOTH planes.
    A closed allowlist; "" clears it (the model's own default). Persists CRUCIBLE_EFFORT (delivered to the
    offense engine by `vigil up`) and records the (non-secret) choice on the spine."""
    effort = str(effort or "").strip().lower()
    if effort and effort not in EFFORT_LEVELS:
        raise ValueError(f"unknown effort {effort!r}: choose one of {', '.join(EFFORT_LEVELS)} (or empty)")
    _persist_env(_EFFORT_ENV, effort)             # "" clears the var → model default
    seq = _record_signed_event(
        store, owner_key, {"signal": "governor.effort_set", "effort": effort or "default"}, reason)
    return {"ok": True, "action": "set_effort", "effort": effort, "recorded_seq": seq}


def export_runtime_env(include_secrets: bool = False) -> dict:
    """The runtime LLM env the keyless offense engine needs — the provider model/config/Strix vars + the
    reasoning-effort var (CRUCIBLE_EFFORT, via _EXTRA_DELIVERED_ENV) from the process env (where sigil.env has
    been loaded) always, and (only when `include_secrets`) the resolved LLM +
    cloud provider keys from the keyring/TPM-sealed/env store. `vigil up` calls this in the SOVEREIGN venv and
    injects the result into the offense children, so the provider/model/key set in the UI reaches the offense
    plane without it importing sigil. Only non-empty string values are emitted. Delivers every managed secret
    via _OFFENSE_DELIVERED_SECRETS EXCEPT the auto-patch signing key + the voice key (_OFFENSE_EXCLUDED_SECRETS)
    — the signing key must NEVER reach an offense process (A2a red-pen). The GitHub token IS delivered (LAP PR
    push). The uiproxy consumer re-allowlists the same set (defense-in-depth)."""
    env: dict = {}
    for var in (*PROVIDER_ENV_VARS, *_EXTRA_DELIVERED_ENV):
        val = os.environ.get(var, "").strip()
        if val:
            env[var] = val
    if include_secrets:
        ss = SecretStore()
        for name in _OFFENSE_DELIVERED_SECRETS:
            val = ss.get(name)
            if val:
                env[name] = val
    return env


def settings_status() -> dict:
    """The REDACTED settings view for the UI — never a secret value. For each managed secret: whether it
    is set, its fingerprint, and the backend holding it. Plus the current models and the model catalog
    (so the UI hard-codes nothing) and whether the system will run keyless."""
    from ..platform.secret_probes import cached_health
    ss = SecretStore()
    secrets = []
    key_set = False
    keys_failing = 0
    for name in SECRET_NAMES:
        val = ss.get(name)
        present = bool(val)
        if name == "ANTHROPIC_API_KEY" and present:
            key_set = True
        meta = SECRET_META.get(name, {})
        # health = the last cached LIVE verdict ({status: ok|fail|unknown, reason, checked_at}); "unchecked"
        # if never probed. A SET-but-not-yet-checked probeable secret reads as unchecked (not a false ok).
        health = cached_health(name) if present else None
        if present and health and health.get("status") == "fail":
            keys_failing += 1
        secrets.append({
            "name": name,
            "set": present,
            "fingerprint": _fingerprint(val) if present else None,
            "backend": ss.backend,
            "label": meta.get("label", name),
            "purpose": meta.get("purpose", ""),
            "category": meta.get("category", "integration"),
            "probeable": bool(meta.get("probe")),
            "health": (health or {"status": "unchecked", "reason": "", "checked_at": 0}) if present else None,
        })
    # the SELECTED choice is tracked explicitly (a keyless choice sets no model id), so the picker
    # reflects it even for claude-code. offense_model is the HONEST effective routing: a forced backend
    # (claude-code) shows the local session, otherwise the anthropic-SDK model id (or its default).
    selected_provider = os.environ.get(_CHOICE_ENV, "").strip()
    forced_backend = os.environ.get(_BACKEND_ENV, "").strip()
    anthropic_model = os.environ.get(_ANTHROPIC_MODEL_ENV, "").strip()
    sovereign_model = os.environ.get(_SIGIL_MODEL_ENV, "").strip()
    # _CHOICE_ENV now tracks the PROVIDER; derive the built-in picker's "current" model from the actual model
    # var so the quick-pick highlight still works (anthropic-family → the anthropic model id; claude-code).
    if selected_provider == "claude-code":
        selected_model = "claude-code"
        offense_model = "claude-code (local session)"
    elif selected_provider in ("anthropic", "anthropic-zdr"):
        selected_model = anthropic_model
        offense_model = anthropic_model or _DEFAULT_OFFENSE_MODEL
    else:
        spec = PROVIDERS.get(selected_provider, {})
        cur = os.environ.get(spec.get("model_var", ""), "").strip() if spec else ""
        selected_model = None
        offense_model = (f"{cur} ({selected_provider})" if cur else (forced_backend or "anthropic"))
    # a serializable provider registry for the UI (config schema + which keys each needs) + current config
    providers = []
    for pid in _PROVIDER_ORDER:
        p = PROVIDERS[pid]
        providers.append({
            "id": pid, "label": p["label"], "backend": p["backend"] or "anthropic",
            "keyless": p["keyless"], "keys": list(p.get("keys", [])),
            "models": list(p.get("models", [])), "model_var": p.get("model_var", ""),
            "note": p.get("note", ""),
            "config": [{"env": c["env"], "label": c["label"], "placeholder": c.get("placeholder", ""),
                        "required": bool(c.get("required"))} for c in p.get("config", ())],
        })
    provider_config = {v: os.environ.get(v, "").strip()          # non-secret config values (safe to show)
                       for v in _ALL_CONFIG_VARS if os.environ.get(v, "").strip()}
    return {
        "secrets": secrets,
        "secret_backend": ss.backend,
        "keys_failing": keys_failing,          # drives the top-bar "N keys failing" badge
        "secret_categories": [{"id": c, "label": _SECRET_CATEGORY_LABEL[c]}
                              for c in _SECRET_CATEGORY_ORDER],
        "models": list(MODEL_CHOICES),
        "providers": providers,
        "selected_provider": selected_provider if selected_provider in _PROVIDER_IDS else None,
        "provider_config": provider_config,
        "selected_model": selected_model if selected_model in _MODEL_IDS else None,
        "offense_backend": forced_backend or "anthropic",
        "offense_model": offense_model,
        "sovereign_model": sovereign_model or None,
        "effort_levels": list(EFFORT_LEVELS),
        "selected_effort": (os.environ.get(_EFFORT_ENV, "").strip().lower() or None),   # None = model default
        "keyless": not key_set,
        "keyless_note": ("No API key is set — engagements run keyless (deterministic oracles only; "
                         "no LLM reasoning) unless you pick the local Claude Code model or add a key."),
    }
