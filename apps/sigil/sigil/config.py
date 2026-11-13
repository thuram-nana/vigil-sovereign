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


# Every character str.splitlines() treats as a line boundary. The sigil.env tier is a line-based
# `KEY=value` format with NO escaping, so ANY of these inside a value would break it into an extra line —
# an envfile line-injection that can plant a var like VIGIL_DESTRUCTION_OWNER_KEY (the auto-patch signing
# key). An ord<0x20/==0x7f guard misses three: NEL (U+0085), LINE SEPARATOR (U+2028), PARAGRAPH SEPARATOR
# (U+2029). A literal "\n" is stopped ONLY by this input guard (the reader splits ON "\n", so parsing can
# never neutralize a real newline) — so EVERY writer of sigil.env must validate through it before writing.
_ENV_LINE_BREAK_CHARS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")


def assert_env_value_safe(value: str, what: str = "value", *, maxlen: int = 8192) -> None:
    """Fail-closed if `value` cannot be persisted as a single `KEY=value` line in sigil.env: reject a
    control character (ord < 0x20 or DEL), any Unicode line separator str.splitlines() honors, or an
    oversize value. The ONE guard EVERY sigil.env writer shares (settings._persist_env, secrets._env_upsert,
    voice.set_voice) so a line-injection cannot recur at a writer that forgot it."""
    if len(value) > maxlen:
        raise ValueError(f"invalid {what}: too long (> {maxlen})")
    if any(ord(c) < 0x20 or ord(c) == 0x7f or c in _ENV_LINE_BREAK_CHARS for c in value):
        raise ValueError(f"invalid {what}: control or line-break character")


def assert_env_key_safe(key: str) -> None:
    """Fail-closed if `key` cannot be the KEY half of a single `KEY=value` line in sigil.env: reject empty,
    any control/line-break char (a str.splitlines() boundary), or an '=' (which would split the assignment).
    Every writer emits f"{key}={value}", so the KEY needs the same class-guard as the value — a line-break in
    a caller-supplied key (e.g. a CredentialVault `service`) would otherwise plant a second KEY=value line
    just like a poisoned value. Legal keys (A-Z/_/-/./ and the `vault/<svc>/password` form) pass unchanged."""
    if not key:
        raise ValueError("invalid env key: empty")
    if "=" in key:
        raise ValueError("invalid env key: contains '='")
    if any(ord(c) < 0x20 or ord(c) == 0x7f or c in _ENV_LINE_BREAK_CHARS for c in key):
        raise ValueError("invalid env key: control or line-break character")


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
    # Parse on "\n" ONLY (not str.splitlines()): a persisted value may contain a Unicode line separator
    # (U+0085/U+2028/U+2029) which str.splitlines() would treat as a line boundary, splitting one value
    # into a second `KEY=value` line — an envfile line-injection. On "\n" the separator stays inert
    # inside its value. (The settings-plane writers also reject those chars at the source.)
    for line in raw.split("\n"):
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
# The per-spine DATA KEY (DEK) for field-level payload encryption (audit G1 slice-4), sealed at rest
# under the TPM KEK (the G1 vault). Absent until `sigil vault provision` + a first content-bearing append.
SPINE_DEK_PATH = KEYS_DIR / "spine.dek"
CACHE_DIR = SIGIL_HOME / "cache"
# Durable external anti-rollback floor (hard-prune C1). At the SIGIL_HOME root, deliberately OUTSIDE
# `spine/` so `SpineStore.reset()` / `sigil ingest --reset` (which rmtree the spine dir) can NEVER lower
# it — a routine reset cannot roll the durable floor back. See spine/floor.py.
FLOOR_PATH = SIGIL_HOME / "floor.json"
# PRICING M1c: the model gateway's per-launch meters (hash-chained JSONL, one per (engagement, nonce)). MONEY data:
# a run's charge is computed from its meter at settle, so the directory is in every backup.
MODEL_METER_DIR = SIGIL_HOME / "model_meter"

# The segment-rotation layout (manifest, lockfile, segments dir, …) is NOT named here: it is derived from
# the spine data-file path — and NAMESPACED BY THAT FILE'S STEM — by `spine.manifest.SpineLayout.for_path`,
# which is the single source of truth. Naming fixed constants here would drift from that namespacing and
# would wrongly assume the spine dir is private to one store (it is not, e.g. under tempfile.mktemp).

# Rotation thresholds: seal the active segment + start a new one once it reaches EITHER bound. Applies only
# to a MIGRATED store (a legacy single-file spine never auto-rotates — the owner runs `sigil spine migrate`
# first). 0 on either bound disables that bound; 0 on both disables rotation (byte-identical passthrough).
def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default


SPINE_SEG_MAX_BYTES = _int_env("SIGIL_SPINE_SEG_MAX_BYTES", 16 * 1024 * 1024)   # 16 MiB
SPINE_SEG_MAX_RECORDS = _int_env("SIGIL_SPINE_SEG_MAX_RECORDS", 12_000)

# SCALE-C1b: commit-coalescing group commit (the 1M-scale concurrent-append throughput lift). When ON
# (>= 1), INDEPENDENT concurrent SpineStore.append() calls (different threads — e.g. the ThreadingHTTPServer
# bridge + event-capture appenders) are gathered into one group whose actual write is delegated to the
# EXISTING append_many() on a single LEADER thread — ONE fsync per group instead of one per caller (today's
# N-serialized-fsyncs wall). DEFAULT-OFF (0): the coalescing queue is never touched and append() is
# byte-identical to today. A re-entrant spine_lock holder (e.g. envelope.consume's TOCTOU replay gate) and a
# dedup append ALWAYS take the direct path regardless of this flag, so correctness never depends on it.
SPINE_GROUP_COMMIT_COALESCE = _int_env("SIGIL_SPINE_GROUP_COMMIT", 0)

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

# ---- SaaS customer plane (Slice E1) -------------------------------------------------------------
# The keyless customer edge + the owner-signed provisioner live behind these. All default OFF/empty, so a
# sovereign install is byte-identical until the customer plane is turned on (`vigil up` mints the hop key).
CUSTOMER_UI_PORT = _int_env("VIGIL_CUSTOMER_PORT", 8734)
COCKPIT_UI_PORT = _int_env("SIGIL_UI_PORT", 8733)       # the sovereign cockpit port (the edge's hop target)
PUBLIC_UI_PORT = _int_env("VIGIL_PUBLIC_PORT", 8735)    # the keyless/cookieless public marketing+tools site
CVE_CATALOG_PATH = SIGIL_HOME / "cve" / "catalog.db"    # the public CVE catalog (populated by `sigil cve ingest`)
_customer = SIGIL_HOME / "customer"


def sovereign_provision_base() -> str:
    """The loopback base URL the keyless customer edge calls to reach the sovereign provisioner routes
    (`/api/provision/*`) over the hop key. Loopback by construction — the edge and the cockpit run on the
    same host; the edge holds NO owner key, only `VIGIL_PROVISION_HOP_KEY`. Overridable via
    `VIGIL_PROVISION_BASE` (e.g. a private-tunnel address) for a split deployment."""
    return os.environ.get("VIGIL_PROVISION_BASE", f"http://127.0.0.1:{COCKPIT_UI_PORT}")
CUSTOMER_SESSIONS_DIR = _customer / "sessions"          # the customer cookie-session ledger (disjoint from operator)
EMAIL_TOKENS_DIR = _customer / "email_tokens"           # single-use, purpose-bound verify/recover tokens
LOGIN_RATELIMIT_DIR = _customer / "login_ratelimit"     # per-account / per-ip lockout markers
TRIAL_CREDITS = _int_env("VIGIL_TRIAL_CREDITS", 100)    # server-constant trial grant (never on-the-wire)
# Anti-farming ceilings on the provisioner's owner-signed mints. The signup cap is a GLOBAL per-rolling-day
# ceiling on self-serve signups (each mints a real trial credit — a Sybil ceiling on real money); the member
# limiter is a per-org ceiling on grant/revoke churn. Both are SEPARATE LoginRateLimiter instances rooted
# here under disjoint marker dirs, so they never interfere with the per-account/per-ip login limiter.
SIGNUP_CAP_DIR = _customer / "signup_cap"               # the global signup-cap limiter's markers
MEMBER_RATELIMIT_DIR = _customer / "member_ratelimit"   # the per-org member-management limiter's markers
SIGNUP_EMAIL_RATELIMIT_DIR = _customer / "signup_mailbox_ratelimit"   # per-canonical-mailbox sign-up limiter
TRIAL_LAUNCH_CAP_DIR = _customer / "trial_launch_cap"   # the global daily trial-launch cap's markers
TRIAL_IP_LIMIT_DIR = _customer / "trial_ip_limit"       # the opt-in per-IP trial-grant limiter's markers
# Slice E3b — customer MFA (TOTP / passkey). The AEAD context that binds a sealed CUSTOMER TOTP secret to its
# purpose — DOMAIN-SEPARATED from the operator `sigil/account.totp` so a customer seal can never be opened as
# an operator TOTP secret (or vice-versa) or swapped for the owner key. The provisioner (the owner-key holder)
# seals at enroll + unseals at verify; only the sealed blob ever reaches the spine (the plaintext is shown to
# the customer ONCE at enrollment, never persisted).
CUSTOMER_TOTP_SEAL_CONTEXT = b"sigil/customer.totp"
CUSTOMER_MFA_REPLAY_DIR = _customer / "mfa_totp_replay"  # the per-customer TOTP (username, step) replay ledger
# Slice E3b-2 — customer passkey (WebAuthn). The single-use registration/assertion challenge ledger (edge) +
# the NON-SIGNED per-credential sign-count clone-floor ledger (provisioner; a monotonic high-water, NOT an
# owner-signed record — a passkey login is a pure signature check with no owner re-sign). OFF by default:
# with customer_passkey_enabled() false the edge's passkey routes are absent and nothing is minted.
CUSTOMER_PASSKEY_CHALLENGE_DIR = _customer / "passkey_challenges"   # single-use WebAuthn challenges (edge)
CUSTOMER_PASSKEY_SIGNCOUNT_DIR = _customer / "passkey_signcount"    # per-credential_id monotonic sign-count floor
# Slice E3c — step-up MFA. How recently a customer must have proven a fresh factor (TOTP code / passkey
# assertion) for a sensitive op (launch / target-verify / member grant+revoke) to proceed when enforcement
# is ON. The session's `mfa_at` is stamped by the edge on a fresh factor proof; the provisioner refuses a
# sensitive op whose session mfa_at is older than this window (or absent).
CUSTOMER_STEPUP_WINDOW_SECONDS = _int_env("VIGIL_CUSTOMER_STEPUP_WINDOW_SECONDS", 300)   # 5 minutes


def customer_stepup_required() -> bool:
    """True iff step-up MFA enforcement is ON (`VIGIL_CUSTOMER_STEPUP_REQUIRED` affirmative). OFF by default
    (the codebase's posture-flag pattern): when OFF the sensitive customer ops are BYTE-IDENTICAL to pre-E3c
    (no mfa_at check); when ON, a customer must have stepped up with a FRESH factor (within
    `CUSTOMER_STEPUP_WINDOW_SECONDS`) before a launch / target-verify / member grant+revoke — so a paid or
    offense op always rides a recent second-factor proof."""
    return (os.environ.get("VIGIL_CUSTOMER_STEPUP_REQUIRED") or "").strip().lower() in _OIDC_AFFIRMATIVE
SIGNUP_DAILY_CAP = _int_env("VIGIL_SIGNUP_DAILY_CAP", 500)      # <= this many committed signups per 24h window
MEMBER_OPS_PER_MIN = _int_env("VIGIL_MEMBER_OPS_PER_MIN", 30)   # max grant/revoke ops per org per minute
# sign-up requests per canonical mailbox per hour, counted only after the per-ip guard passed. 0 (the default)
# leaves the per-mailbox limiter unwired; the trial-preview readiness check requires a positive owner-set value.
SIGNUP_EMAIL_PER_HOUR = _int_env("VIGIL_SIGNUP_EMAIL_PER_HOUR", 0)
# trial launches per rolling 24h, all trial orgs together (bounds daily trial spend at cap x trial reservation).
# Owner-set; 0 (the default) means trial launches are off.
TRIAL_LAUNCH_DAILY_CAP = _int_env("VIGIL_TRIAL_LAUNCH_DAILY_CAP", 0)
# preview trial GRANTS per client IP per rolling 24h, when VIGIL_TRIAL_IP_LIMIT_ENABLED is on.
TRIAL_GRANTS_PER_IP = _int_env("VIGIL_TRIAL_GRANTS_PER_IP", 3)
# Slice G — the SERVER-DECIDED credit reservation cap for one offense launch (money doctrine: the amount is
# decided here, never by the customer's request). A flat per-launch hold; a scope-dependent catalog cost is a
# later refinement. The unused remainder is refunded on settle, so net spend tracks metered consumption.
LAUNCH_UNITS = _int_env("VIGIL_LAUNCH_UNITS", 10)
# AEGIS-SaaS AE-1 — the SERVER-DECIDED window of one monitoring grant (a customer may only ask for SHORTER; the
# registry further clamps it to the ownership proof's expiry).
MONITORING_WINDOW_SECONDS = _int_env("VIGIL_MONITORING_WINDOW_SECONDS", 30 * 24 * 3600)

# AEGIS-SaaS — server-side renewal GRACE after a monitoring period ends with no down event: the sweep keeps the
# (already inert, clamped-to-period_end) grants this long so a late renewal can re-mint them; then it retires.
MONITORING_RENEWAL_GRACE_SECONDS = _int_env("VIGIL_MONITORING_RENEWAL_GRACE_SECONDS", 72 * 3600)


def customer_monitoring_enabled() -> bool:
    """True iff the customer monitoring-authority routes are ON (`VIGIL_CUSTOMER_MONITORING_ENABLED`
    affirmative). OFF by default: the edge routes and provisioner actions are absent (404) exactly as an
    unknown route, and nothing is minted or published."""
    return (os.environ.get("VIGIL_CUSTOMER_MONITORING_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_pause_resume_enabled() -> bool:
    """True iff the customer pause/resume launch routes are ON (`VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED`
    affirmative). OFF by default (pause/resume PR-4b): the edge routes and provisioner actions are absent (404)
    exactly as an unknown route, and NOTHING records or clears a lease pause — so the whole PR-1..PR-4a pause
    substrate stays INERT until the owner turns this on. Pausing moves NO money (it is money-doctrine-neutral);
    this flag gates only the CUSTOMER-facing ability to record/clear a reversible pause on their own lease."""
    return (os.environ.get("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def trial_preview_enabled() -> bool:
    """True iff the free-trial PREVIEW is ON (`VIGIL_TRIAL_PREVIEW_ENABLED` affirmative). OFF by default: sign-up
    grants the legacy trial exactly as before. ON: a sign-up grants the trial under the `trial-preview:<org>` entry
    only when the org, its canonical mailbox and its trial entries are all unclaimed (one trial per org and per
    mailbox), and later slices show that org partial results until it buys credits."""
    return (os.environ.get("VIGIL_TRIAL_PREVIEW_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def trial_ip_limit_enabled() -> bool:
    """True iff the opt-in per-IP soft limit on preview trial grants is ON (`VIGIL_TRIAL_IP_LIMIT_ENABLED`
    affirmative; default OFF)."""
    return (os.environ.get("VIGIL_TRIAL_IP_LIMIT_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def trial_product_id() -> str:
    """The launch product a trial-preview org may run (`VIGIL_TRIAL_PRODUCT_ID`, an offered catalog launch
    product). Owner-set; no default — while it is unset a locked trial org cannot launch at all."""
    return (os.environ.get("VIGIL_TRIAL_PRODUCT_ID") or "").strip()


def customer_checkout_enabled() -> bool:
    """True iff the CUSTOMER hosted-checkout action is ON (`VIGIL_CUSTOMER_CHECKOUT_ENABLED` affirmative). OFF by
    default (Front B CHK-1): the edge route and the provisioner action are absent (404) exactly as an unknown route,
    and nothing ever posts to the payment processor. Even when ON, checkout still refuses unless the owner has
    provisioned the processor named by VIGIL_BILLING_PROVIDER (unset = Flutterwave: VIGIL_BILLING_WEBHOOK_SECRET +
    VIGIL_FLW_SECRET_KEY; stripe: the Stripe adapter opt-in, VIGIL_STRIPE_WEBHOOK_SECRET, VIGIL_STRIPE_SECRET_KEY and
    VIGIL_STRIPE_API_VERSION; any other value: not configured) — the amount is always the OWNER CATALOG's, and
    credit is granted ONLY by the verified inbound webhook drain, never here."""
    return (os.environ.get("VIGIL_CUSTOMER_CHECKOUT_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_plan_checkout_enabled() -> bool:
    """True iff customers may also check out SUBSCRIPTION plans (`VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED`
    affirmative). Effective only together with the base checkout flag (the edge route is absent without it).
    OFF by default (CHK-1b). A plan checkout subscribes the payer
    to the processor's recurring plan (the catalog price_id IS the payment_plan id); every RENEWAL must then map back
    to the tenant via the tx_ref / meta we set — a sandbox-confirm item. ENABLE ONLY after a sandbox renewal shows
    it attributes. While ON, the billing drain QUARANTINES (alarms on) a verified successful plan charge it cannot
    attribute or price, instead of a silent no-op."""
    return (os.environ.get("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def billing_plan_alarm_enabled() -> bool:
    """Whether the billing drain QUARANTINES (alarms on) an unaccountable paid PLAN charge. ON whenever plan
    checkout is ON, and independently via `VIGIL_BILLING_PLAN_ALARM` — keep it ON for as long as any plan sold
    while checkout was enabled may still RENEW: turning plan SALES off must never silence the alarm on renewals
    that are still being billed (CHK-1b red-pen)."""
    return customer_plan_checkout_enabled() or (
        (os.environ.get("VIGIL_BILLING_PLAN_ALARM") or "").strip().lower() in _OIDC_AFFIRMATIVE)


def customer_billing_return_url() -> "str | None":
    """The optional post-payment return URL handed to the processor (`VIGIL_CUSTOMER_BILLING_RETURN_URL`, e.g.
    ``https://app.example.com/#/billing/return``). Unset ⇒ None (the processor's own completion page). A set value
    must be an absolute ``https://`` URL with a host — anything else raises ``ValueError`` (checkout fails closed
    rather than redirecting a paying customer somewhere unintended)."""
    from urllib.parse import urlparse
    raw = (os.environ.get("VIGIL_CUSTOMER_BILLING_RETURN_URL") or "").strip()
    if not raw:
        return None
    p = urlparse(raw)
    if p.scheme != "https" or not p.hostname or any(c.isspace() for c in raw) or "@" in (p.netloc or ""):
        raise ValueError("VIGIL_CUSTOMER_BILLING_RETURN_URL must be an absolute https:// URL")
    return raw


def kek_backend() -> str:
    """Which custody backend wraps the at-rest KEK (the key that seals the owner key + secrets):

      * ``"tpm"`` (DEFAULT) — TPM-sealed to this machine (byte-identical to the pre-cloud behaviour).
      * ``"kms"`` — AWS-KMS envelope-encrypted (cloud): `sigil vault provision` wraps a fresh KEK with the
        instance role's ``kms:Encrypt`` under `VIGIL_KMS_KEY_ID`; boot unwraps it with ``kms:Decrypt``.

    Any unknown value falls back to ``"tpm"`` — a typo can never silently disable sealing or pick a
    surprise backend. The owner Ed25519 key still signs in-process; KMS only guards the KEK at rest."""
    v = (os.environ.get("VIGIL_KEK_BACKEND") or "tpm").strip().lower()
    return v if v in ("tpm", "kms") else "tpm"


def kms_key_id() -> str:
    """The AWS KMS CMK id/arn/alias that wraps the KEK when `kek_backend()` is ``"kms"`` (VIGIL_KMS_KEY_ID).
    Empty unless the cloud backend is configured; the KMS backend fails CLOSED if it is empty."""
    return (os.environ.get("VIGIL_KMS_KEY_ID") or "").strip()


def aws_region() -> str:
    """The AWS region for the KMS CMK (VIGIL_AWS_REGION, falling back to the standard AWS_REGION /
    AWS_DEFAULT_REGION the `aws` CLI already reads). Empty unless configured; the KMS backend fails
    closed if it is empty."""
    return (os.environ.get("VIGIL_AWS_REGION") or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION") or "").strip()


def margin_dashboard_enabled() -> bool:
    """True iff the EC-6 operator MARGIN dashboard route is ON (`VIGIL_MARGIN_DASHBOARD_ENABLED` affirmative).
    OFF by default (mirrors `customer_monitoring_enabled`): with it off the owner-tier `/api/billing/margin`
    read is absent (404 exactly as an unknown route) — the SERVER surface is byte-identical to a build without
    EC-6. (The cockpit static assets ship unconditionally; the panel stays hidden and the client probes the
    route once on load, then latches OFF on the 404/403 so it never re-polls — the panel reveals only for an
    owner with the flag on.) The read is still owner-gated AND fail-closed on an unset cost rate even when on —
    this flag only decides whether the route exists at all (a pure READ projection; nothing is ever minted)."""
    return (os.environ.get("VIGIL_MARGIN_DASHBOARD_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def tiered_products_enabled() -> bool:
    """True iff the EC-7 tiered Quick/Deep LAUNCH PRODUCTS are offered (`VIGIL_TIERED_PRODUCTS` affirmative).
    OFF by default: `catalog.launch_products()` returns `()` and the existing pricing surface (plans() /
    expected_amounts() / entitlements()) is byte-identical to pre-EC-7 — a launch product is a NEW offering,
    not a change to any existing one. A launch's run tier is DERIVED from its signed units_reserved either way
    (no new signed field); this flag decides whether the Quick/Deep products are LISTED/OFFERED (the run tier
    is applied by the engage worker when on). Wiring a customer's product choice into the credit reservation
    is a follow-on — until then a launch reserves the default units (the base 'quick' tier)."""
    return (os.environ.get("VIGIL_TIERED_PRODUCTS") or "").strip().lower() in _OIDC_AFFIRMATIVE


def monitoring_publish_dir() -> Path:
    """Where owner-signed monitoring authorities are published for the KEYLESS AEGIS gateway (AE-2 reads,
    verify-only). `VIGIL_MONITORING_PUBLISH_DIR` overrides; default under the live data dir
    (`VIGIL_BASE_DIR`, else `.vigil-live`). Only signed public artifacts land here — never private material."""
    override = (os.environ.get("VIGIL_MONITORING_PUBLISH_DIR") or "").strip()
    if override:
        return Path(override)
    return Path(os.environ.get("VIGIL_BASE_DIR") or ".vigil-live") / "aegis" / "monitoring_authority"


def monitoring_secrets_dir() -> Path:
    """Where the sovereign keeps the per-(org, host) AEGIS-SaaS monitoring REPORT secrets (AE-6). These are
    shared HMAC secrets (one copy goes to that tenant's managed gateway as a 0600 file); never published.
    `VIGIL_MONITORING_SECRETS_DIR` overrides; default under the live data dir."""
    override = (os.environ.get("VIGIL_MONITORING_SECRETS_DIR") or "").strip()
    if override:
        return Path(override)
    return Path(os.environ.get("VIGIL_BASE_DIR") or ".vigil-live") / "aegis" / "report_secrets"


def _bool_env(name: str, default: bool = False) -> bool:
    """A strict, fail-closed boolean env read: only the affirmative tokens below (case-insensitive) are True;
    anything else — including a typo — is the default. Used for opt-in DEV escape hatches that must never
    turn on by accident."""
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _float_env(name: str, default: float) -> float:
    """A fail-safe float env read: a missing / empty / non-numeric value falls back to `default` (never
    raises). Used for the owner-set EC-5 pool band fractions, which must deploy with safe defaults."""
    try:
        return float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


# --- EC-5 global cost POOL + graduated kill-switch (SHIPPED OFF BY DEFAULT) ------------
# A GLOBAL (cross-tenant) cost-pool METER over the EC-4 cost ledger + a graduated kill-switch. The pool
# BUDGET is an OWNER capacity number in TOKENS (never a $ amount, never on the wire); unset/0 ⇒ UNBOUNDED ⇒
# the meter short-circuits to NORMAL without folding the ledger, so a sovereign install is BYTE-IDENTICAL.
# The per-token $ rate and the credit→token envelope E stay single-sourced in vigil_core
# (ENVELOPE_TOKENS_PER_CREDIT), referenced not re-defined here. Mirrors the customer_monitoring_enabled /
# catalog placeholder doctrine: a reviewed-code default-off operator number, owner-ratified before go-live.
def global_pool_tokens():
    """The GLOBAL cross-tenant cost-pool capacity in TOKENS (`VIGIL_GLOBAL_POOL_TOKENS`). Unset / 0 /
    non-numeric ⇒ None = UNBOUNDED (default-off): the pool meter short-circuits to NORMAL and admits the full
    request WITHOUT folding the cost ledger, so reserve_launch is byte-identical to pre-EC-5. An OWNER capacity
    number — the owner arms the pool by setting it to >= 1 (plus optional band-fraction overrides)."""
    raw = (os.environ.get("VIGIL_GLOBAL_POOL_TOKENS") or "").strip()
    if not raw:
        return None
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return None
    return n if n >= 1 else None


def global_pool_bands() -> dict:
    """The owner-set band fractions (fraction used/budget at which each posture engages) + the DEGRADE shrink
    factor for the graduated pool kill-switch. SAFE PLACEHOLDER defaults (NOT real money numbers), each
    env-overridable; the owner ratifies before go-live. Monotone by construction
    (0 < throttle ≤ degrade ≤ refuse ≤ hard_stop ≤ 1, 0 < degrade_factor ≤ 1); a non-monotone / out-of-range
    override reverts to the safe defaults wholesale (FAIL-SAFE — a bad band must never INVERT the graduation,
    e.g. a refuse threshold below throttle, which could admit MORE draw at a HIGHER fraction; and a threshold
    ABOVE 1.0 — a percent-vs-fraction typo like refuse=150 — must never be accepted, or the armed kill-switch
    is silently DISARMED because the used-fraction can never reach it. Since the thresholds are monotone,
    bounding hard_stop ≤ 1.0 bounds them all)."""
    bands = {
        "throttle_at": _float_env("VIGIL_GLOBAL_POOL_THROTTLE_AT", 0.75),
        "degrade_at": _float_env("VIGIL_GLOBAL_POOL_DEGRADE_AT", 0.85),
        "refuse_at": _float_env("VIGIL_GLOBAL_POOL_REFUSE_AT", 0.95),
        "hard_stop_at": _float_env("VIGIL_GLOBAL_POOL_HARD_STOP_AT", 1.0),
        "degrade_factor": _float_env("VIGIL_GLOBAL_POOL_DEGRADE_FACTOR", 0.5),
    }
    t, d, r, h, f = (bands["throttle_at"], bands["degrade_at"], bands["refuse_at"],
                     bands["hard_stop_at"], bands["degrade_factor"])
    # upper bound h <= 1.0 (fail-safe against a percent-vs-fraction typo silently disarming the kill-switch).
    if not (0.0 < t <= d <= r <= h <= 1.0 and 0.0 < f <= 1.0):
        return {"throttle_at": 0.75, "degrade_at": 0.85, "refuse_at": 0.95, "hard_stop_at": 1.0,
                "degrade_factor": 0.5}
    return bands


def cost_ledger_write_enabled() -> bool:
    """True iff the launch gate writes the EC-4 cost reserve/settle pair (the EC-5 live-path wiring). OFF by
    default (`VIGIL_COST_LEDGER_WRITE` unset / non-affirmative) UNLESS the global cost pool is ARMED — an armed
    pool MUST meter its own draw, so arming it implies the writes. When OFF the gate appends NO cost record and
    reserve_launch / settle_launch are byte-identical to pre-EC-5. Single-sourced here (the shared seam EC-6
    reuses rather than re-adding the reserve_launch cost write)."""
    if (os.environ.get("VIGIL_COST_LEDGER_WRITE") or "").strip().lower() in _OIDC_AFFIRMATIVE:
        return True
    return global_pool_tokens() is not None


def settle_spine_record_enabled() -> bool:
    """True iff every FRESH launch settle appends an owner-signed ``governor.launch_settled`` v2 DECISION record
    (``governor/launch_settlement.py``: mode, reserved, consumed and the exact plan / wallet / postpaid refund
    split, keyed on the lease ``(slug, nonce)``) before it moves any money — so a settle that moved no money (a
    completed run, refund 0) is on the spine and not only in the seam settlement marker, and a later settle can
    finish a decision a crash interrupted at the RECORDED amounts. OFF by default (``VIGIL_SETTLE_SPINE_RECORD``
    unset / non-affirmative): no record is appended and every settle path writes the same spine records as
    before. Resolved at call time.

    It gates ONLY: the decision-record append; the sweep's finish path for a marker-present lease
    (``ops_sweeps``); the spine check of an earlier launch in ``_earlier_launch_in_flight``; and the spine check in
    ``pause_launch``. Settle evidence already on the spine (a refund grant, a postpaid settle) is honoured either
    way. OWNER DECISION OD-4: set it IDENTICALLY for every process that settles — the cockpit, the customer
    server, the settle-drain and ``ops-sweep`` — or a process with it off settles without a record its crash
    could be finished from."""
    return (os.environ.get("VIGIL_SETTLE_SPINE_RECORD") or "").strip().lower() in _OIDC_AFFIRMATIVE


#: The default and the bounds of :func:`settle_lock_wait_s` (OWNER DECISION OD-7).
SETTLE_LOCK_WAIT_DEFAULT_S = 10.0
_SETTLE_LOCK_WAIT_BOUNDS = (0.1, 120.0)


def settle_lock_wait_s() -> float:
    """How long a settle / publish / pause waits for the cross-process settle lock before it answers "busy; retry"
    (``VIGIL_SETTLE_LOCK_WAIT_S`` seconds, default 10, clamped to [0.1, 120]; an unparsable or non-finite value
    reads as the default). Resolved at call time. A settle that times out moves nothing and is retryable: the
    drain defers the completion, the sweep reports ``deferred``, a customer cancel / start is refused with a
    retry hint."""
    raw = (os.environ.get("VIGIL_SETTLE_LOCK_WAIT_S") or "").strip()
    if not raw:
        return SETTLE_LOCK_WAIT_DEFAULT_S
    try:
        v = float(raw)
    except ValueError:
        return SETTLE_LOCK_WAIT_DEFAULT_S
    if v != v or v in (float("inf"), float("-inf")):
        return SETTLE_LOCK_WAIT_DEFAULT_S
    lo, hi = _SETTLE_LOCK_WAIT_BOUNDS
    return min(hi, max(lo, v))


def one_launch_per_host_enabled() -> bool:
    """True iff a customer may hold only ONE outstanding launch per ``(org, host)`` (E7): ``reserve_launch``
    refuses a new reservation while an earlier one for the same target is unsettled, and ``publish_lease``
    (launch_start) refuses to put a lease on the seam over another launch's unsettled lease (the seam holds one
    lease per slug, so the second would overwrite the first and strand its reservation). Both checks run under
    the cross-process settle lock (`governor/launch_settlement.settle_lock`). OFF by default
    (`VIGIL_ONE_LAUNCH_PER_HOST` unset / non-affirmative): reserve and start behave exactly as before."""
    return (os.environ.get("VIGIL_ONE_LAUNCH_PER_HOST") or "").strip().lower() in _OIDC_AFFIRMATIVE


def paused_expiry_settle_enabled() -> bool:
    """E8 — True iff the settle-drain also settles every PAUSED customer launch whose lease window closed more than
    the settle grace ago and that nothing settled (`sigil/paused_expiry_settle.py`, due predicate
    `vigil_integration/live/credit_lease_expiry.py`), by the owner's paused-launch rule: a metered launch is charged
    for what it used, a flat one refunded — exactly what `ops-sweep reservations --apply` does for it. OFF by default
    (`VIGIL_PAUSED_EXPIRY_SETTLE` unset / non-affirmative): the drain is unchanged and such a launch waits for the
    sweep; `vigil doctor` reports it as a hard issue either way. Set it for the settle-drain unit."""
    return (os.environ.get("VIGIL_PAUSED_EXPIRY_SETTLE") or "").strip().lower() in _OIDC_AFFIRMATIVE


def provision_hop_key() -> str:
    """The edge→provisioner shared HMAC hop secret (`VIGIL_PROVISION_HOP_KEY`), minted per `vigil up` and
    handed to the edge + the sovereign cockpit, NEVER to the browser. Empty ⇒ the provisioner routes fail
    CLOSED (no customer provisioning until the key is provisioned)."""
    return os.environ.get("VIGIL_PROVISION_HOP_KEY", "")


def provision_expose_dev_tokens() -> bool:
    """DEV-ONLY: whether the provision HTTP surface may echo the email verify/recover token in its response
    (so a dev install can complete signup/recovery without an SMTP relay).

    FAIL-CLOSED by default (the red-pen's CO13): echoing the token to the browser lets anyone self-verify
    WITHOUT mailbox control — i.e. a trial without email verification = Sybil farming, which breaks the
    NON-NEGOTIABLE anti-Sybil invariant. So this is OFF unless EXPLICITLY opted in with
    `VIGIL_PROVISION_DEV_TOKENS`, and is suppressed outright under BOTH the production AND the (explicitly
    hardened) governed posture, and whenever a real SMTP sender is configured (the token is emailed, never
    surfaced). It must NEVER default open merely because no posture/SMTP is set."""
    from vigil_core.posture import is_governed_posture, is_production_posture
    if is_production_posture() or is_governed_posture():
        return False
    if email_enabled():
        return False
    return _bool_env("VIGIL_PROVISION_DEV_TOKENS", False)


def email_enabled() -> bool:
    """True iff an SMTP sender is configured (`SIGIL_EMAIL_HOST` set) — mirrors the OIDC opt-in. OFF by
    default: a dev/sovereign install uses NullEmailSender and surfaces a verify/recover token only on an
    explicit dev flag, NEVER in production."""
    return bool(os.environ.get("SIGIL_EMAIL_HOST", "").strip())


def email_sender():
    """The configured EmailSender: a stdlib SmtpEmailSender behind `SIGIL_EMAIL_*`, else the OFF-by-default
    NullEmailSender. Lazily imports the (stdlib-only) channel so `config` stays import-light."""
    from .ui.email_channel import NullEmailSender, SmtpEmailSender
    if not email_enabled():
        return NullEmailSender()
    return SmtpEmailSender(os.environ["SIGIL_EMAIL_HOST"], _int_env("SIGIL_EMAIL_PORT", 587),
                           from_addr=os.environ.get("SIGIL_EMAIL_FROM", "noreply@vigil.local"),
                           username=os.environ.get("SIGIL_EMAIL_USER") or None,
                           password=os.environ.get("SIGIL_EMAIL_PASSWORD") or None)
def ownership_verify_enabled() -> bool:
    """True iff the operator enabled self-serve asset-ownership verification (`VIGIL_OWNERSHIP_VERIFY`). OFF
    by default — the sovereign plane makes NO outbound fetch to a customer-named host unless the operator
    explicitly opts into this egress (mirrors the email / OIDC opt-ins). While off, target_verify fail-closed."""
    return _bool_env("VIGIL_OWNERSHIP_VERIFY", False)


def ownership_fetcher():
    """The configured ownership-proof fetcher (SSRF-hardened; serves both the well-known HTTP file and the
    dns-txt-over-DoH methods) when enabled, else None (fail-closed — the provisioner's target_verify
    refuses). Lazily imports the stdlib-only fetcher so `config` stays import-light."""
    if not ownership_verify_enabled():
        return None
    from .ui.ownership_fetch import WellKnownFetcher
    return WellKnownFetcher()


OWNER_KEY_ID = os.environ.get("SIGIL_OWNER_KEY_ID", "owner")


# --- OIDC Relying Party (Slice S5 — SHIPPED OFF BY DEFAULT) ----------------------------
# The OIDC RP is DISABLED unless SIGIL_OIDC_ENABLED is affirmative. This MIRRORS the
# VIGIL_EGRESS_GUARD precedent: opt-in by env, byte-identical (no new route, no egress, no surface)
# unless explicitly asked. When enabled it targets an OPERATOR-RUN IdP reachable over the private
# tunnel (loopback / RFC1918 / Tailscale-CGNAT / IPv6-ULA — the ranges `bridge.daemon.bind_ok` allows);
# a PUBLIC cloud IdP is NOT the default and breaks the air-gap posture (see docs/OIDC-RP.md).
# CRITICAL invariant: OIDC authenticates *who you are*; the *role* is NEVER taken from an OIDC claim —
# it comes only from an owner-signed `governor.account` grant (single-owner-key / nothing-self-
# authorizes doctrine). An OIDC identity with no matching owner-signed account is REFUSED.
_OIDC_AFFIRMATIVE = frozenset({"1", "true", "yes", "on", "enabled"})


def oidc_enabled() -> bool:
    """True iff the OIDC Relying Party is turned ON (SIGIL_OIDC_ENABLED ∈ {1,true,yes,on,enabled},
    case-insensitive). Absent / empty / anything else ⇒ OFF. When OFF the OIDC routes are NOT registered
    at all — the cockpit is byte-identical to a build without OIDC (no /api/oidc/* route, no egress)."""
    return (os.environ.get("SIGIL_OIDC_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def fold_cache_enabled() -> bool:
    """True iff the verified incremental FOLD CACHE is ON (`VIGIL_FOLD_CACHE_ENABLED` affirmative). OFF by default
    (Front C S0a): every registry read runs its full signature-verifying fold, byte-identical to a build without
    the cache. When ON, a registry that supports it (S0a: `CustomerRegistry`) extends an in-memory fold over only
    the records appended since its last read, anchored to the chain (`spine/fold_cache.py`); on any doubt it
    rebuilds from the spine. Read at call time, so an operator can turn it off without a restart."""
    return (os.environ.get("VIGIL_FOLD_CACHE_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


# Front C S0d: the cockpit's background fold-cache AUDIT report (`governor/fold_warm.py`), read by `vigil doctor`
# (stdlib mirror: `$SIGIL_HOME/fold_cache_audit.json`) and printed by `sigil verify`.
FOLD_AUDIT_PATH = SIGIL_HOME / "fold_cache_audit.json"


def fold_cache_audit_interval() -> float:
    """Seconds between the cockpit's background rebuild-and-compare audits of the fold caches
    (`VIGIL_FOLD_CACHE_AUDIT_S`, default 21600 = 6 h). 0 (or negative / unparseable-as-positive) disables the
    PERIODIC audit; the start-up warm-up still runs. Only consulted when `fold_cache_enabled()`. A rebuild costs
    what a cold start costs (O(spine) per fold), hence the long default."""
    raw = (os.environ.get("VIGIL_FOLD_CACHE_AUDIT_S") or "").strip()
    if not raw:
        return 21600.0
    try:
        v = float(raw)
    except ValueError:
        return 21600.0
    return v if v > 0 and v == v and v != float("inf") else 0.0


def metered_billing_enabled() -> bool:
    """True iff customer runs are billed METERED (PRICING M1c; design §4): a run's charge is its model gateway
    meter's cost x K, clamped to [floor, reservation], instead of the flat full reservation. OFF by default
    (`VIGIL_METERED_BILLING` unset): the launch mints no model grant and settle is byte-identical (flat). Turning it
    on REQUIRES the model gateway (`model_gateway_enabled`), which `vigil doctor` checks. Read at call time."""
    return (os.environ.get("VIGIL_METERED_BILLING") or "").strip().lower() in _OIDC_AFFIRMATIVE


def model_gateway_enabled() -> bool:
    """True iff the cockpit starts the sovereign model gateway (`sigil.model_gateway`) at boot
    (`VIGIL_MODEL_GATEWAY_ENABLED` affirmative). OFF by default: nothing listens."""
    return (os.environ.get("VIGIL_MODEL_GATEWAY_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


_MODEL_GATEWAY_DEFAULT_PORT = 8742


def model_gateway_port() -> int:
    """The loopback port the model gateway listens on (`VIGIL_MODEL_GATEWAY_PORT`, default 8742). A junk or
    out-of-range value falls back to the default (the gateway is loopback-only either way)."""
    raw = (os.environ.get("VIGIL_MODEL_GATEWAY_PORT") or "").strip()
    try:
        port = int(raw) if raw else _MODEL_GATEWAY_DEFAULT_PORT
    except ValueError:
        return _MODEL_GATEWAY_DEFAULT_PORT
    return port if 1 <= port <= 65535 else _MODEL_GATEWAY_DEFAULT_PORT


def model_gateway_url() -> str:
    """The base URL a customer run's engine uses for every model request (published with each grant)."""
    return f"http://127.0.0.1:{model_gateway_port()}"


def run_model() -> str:
    """The one model every customer run uses (`VIGIL_RUN_MODEL`, default `claude-opus-4-8`, the owner's
    decision). The model gateway refuses any other model for a run's grant."""
    from vigil_core import model_metering as _mm
    return _mm.run_model()


def oidc_settings() -> dict:
    """The resolved SIGIL_OIDC_* configuration (env → sigil.env → default), read at call time so an
    override applied after import is honoured. Consulted ONLY when `oidc_enabled()`. The client secret is
    included here for the token exchange; callers that DISPLAY config must redact it (`effective_config`
    surfaces only a redacted view). `username_claim` selects which verified id_token claim maps to a
    `governor.account` username; `signing_algs` is the ASYMMETRIC-only allowlist (a symmetric/`none` alg is
    refused — algorithm-confusion defence)."""
    g = os.environ.get
    return {
        "issuer": (g("SIGIL_OIDC_ISSUER") or "").strip(),
        "client_id": (g("SIGIL_OIDC_CLIENT_ID") or "").strip(),
        "client_secret": (g("SIGIL_OIDC_CLIENT_SECRET") or ""),
        "redirect_uri": (g("SIGIL_OIDC_REDIRECT_URI") or "").strip(),
        "authorize_endpoint": (g("SIGIL_OIDC_AUTHORIZE_ENDPOINT") or "").strip(),
        "token_endpoint": (g("SIGIL_OIDC_TOKEN_ENDPOINT") or "").strip(),
        "jwks_uri": (g("SIGIL_OIDC_JWKS_URI") or "").strip(),
        "scopes": (g("SIGIL_OIDC_SCOPES") or "openid profile email").strip(),
        # which verified id_token claim carries the username that must match an owner-signed account.
        # DEFAULT is the IMMUTABLE `sub` (globally unique + IdP-stable): a mutable claim (preferred_username
        # /email) is opt-in only, because if a user can change theirs the mapping can drift or be steered.
        "username_claim": (g("SIGIL_OIDC_USERNAME_CLAIM") or "sub").strip(),
        # asymmetric-only signing-alg allowlist for the id_token (RS256 default; ES256 also supported)
        "signing_algs": [a.strip().upper() for a in (g("SIGIL_OIDC_SIGNING_ALGS") or "RS256").split(",")
                         if a.strip()],
        "clock_skew_seconds": _int_env("SIGIL_OIDC_CLOCK_SKEW_SECONDS", 60),
    }


# --- CUSTOMER Google OIDC login (Slice E2b — SHIPPED OFF BY DEFAULT, a DISJOINT toggle) ----
# The self-serve CUSTOMER plane's federated login ("Sign in with Google"), entirely separate from the
# operator OIDC above (different env toggle, different routes, different terminal mint — a customer session,
# NEVER an operator bearer). OFF by default: with `customer_oidc_enabled()` false the custui edge's
# /api/customer/oidc/* routes are NOT served and the provisioner makes NO outbound call (byte-identical to a
# build without it). The config is SPLIT so the owner secret never reaches the keyless edge: the edge reads
# only `customer_oidc_public_settings()` (endpoints + client_id + redirect + scopes, client_secret forced
# blank) to build the authorize redirect; the `client_secret` + the token/JWKS EGRESS live ONLY in the
# provisioner (`customer_oidc_settings()`), bounded by the host allowlist below. Google endpoints are pinned
# as defaults (overridable for a private test IdP), but the allowlist is what actually bounds the egress.
_GOOGLE_OIDC_ISSUER = "https://accounts.google.com"
_GOOGLE_OIDC_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_OIDC_TOKEN = "https://oauth2.googleapis.com/token"
_GOOGLE_OIDC_JWKS = "https://www.googleapis.com/oauth2/v3/certs"
# The outbound host allowlist for the provisioner's customer-OIDC token + JWKS calls (enforced by the
# injected poster/fetcher — the keyless edge never makes an OIDC egress). A token_endpoint/jwks_uri steered
# off these hosts is REFUSED, so a misconfiguration (or a hostile override) cannot turn the provisioner into
# an SSRF proxy against an internal address. Pinned to Google's auth/token/JWKS hosts.
CUSTOMER_OIDC_EGRESS_ALLOWLIST = frozenset({
    "accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"})


# --- Flutterwave OUTBOUND billing egress (Slice A1 — SHIPPED OFF BY DEFAULT) ------------
# The outbound host allowlist for the provider's /v3/payments (hosted-checkout create) and
# /v3/transactions/{id}/verify (server-side re-verify) calls, enforced by the stdlib poster/verifier in
# `governor.flutterwave_egress` BEFORE any socket opens (mirrors CUSTOMER_OIDC_EGRESS_ALLOWLIST above). The
# egress is itself gated DEFAULT-OFF on the provider secret key (`VIGIL_FLW_SECRET_KEY`): unset ⇒ neither
# outbound callable is wired, so `create_checkout` refuses and `billing-drain` refuses (no egress, no new
# surface). An API base/endpoint steered off this host is REFUSED, so a misconfiguration (or a hostile
# override) cannot turn the key-holding egress into an SSRF proxy. Pinned to Flutterwave's v3 API host.
FLUTTERWAVE_EGRESS_ALLOWLIST = frozenset({"api.flutterwave.com"})


# --- Stripe OUTBOUND billing egress (SHIPPED OFF BY DEFAULT) ----------------------------
# The outbound host allowlist for the Stripe API calls in `governor.stripe_egress` (object re-fetch for an inbound
# event, hosted-checkout create), enforced BEFORE any socket opens. Gated DEFAULT-OFF on `VIGIL_STRIPE_SECRET_KEY`:
# unset ⇒ nothing is wired and no Stripe egress exists. There is no API-base override, so the key-holding egress
# can only ever reach this host.
STRIPE_EGRESS_ALLOWLIST = frozenset({"api.stripe.com"})
# The ONLY host a Stripe hosted-checkout link may point at (`billing._https_link_on`, exact match). A link pin, never
# fetched — it is deliberately NOT in the egress allowlist above.
STRIPE_CHECKOUT_LINK_HOSTS = frozenset({"checkout.stripe.com"})


def customer_oidc_enabled() -> bool:
    """True iff customer Google-OIDC login is ON (`VIGIL_CUSTOMER_OIDC_ENABLED` ∈ {1,true,yes,on,enabled}).
    OFF by default and INDEPENDENT of the operator `SIGIL_OIDC_ENABLED`. When OFF the edge's
    /api/customer/oidc/* routes are not served and the provisioner builds no OIDC provider (no egress)."""
    return (os.environ.get("VIGIL_CUSTOMER_OIDC_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def _customer_oidc_base() -> dict:
    """The NON-SECRET customer-OIDC settings (Google-pinned by default, overridable via `VIGIL_CUSTOMER_OIDC_*`).
    NEVER reads the client secret. `username_claim` is fixed to the immutable `sub` — the customer binding is
    the stable `(iss, sub)` pair (never a mutable claim)."""
    g = os.environ.get
    return {
        "issuer": (g("VIGIL_CUSTOMER_OIDC_ISSUER") or _GOOGLE_OIDC_ISSUER).strip(),
        "client_id": (g("VIGIL_CUSTOMER_OIDC_CLIENT_ID") or "").strip(),
        "redirect_uri": (g("VIGIL_CUSTOMER_OIDC_REDIRECT_URI") or "").strip(),
        "authorize_endpoint": (g("VIGIL_CUSTOMER_OIDC_AUTHORIZE_ENDPOINT") or _GOOGLE_OIDC_AUTHORIZE).strip(),
        "token_endpoint": (g("VIGIL_CUSTOMER_OIDC_TOKEN_ENDPOINT") or _GOOGLE_OIDC_TOKEN).strip(),
        "jwks_uri": (g("VIGIL_CUSTOMER_OIDC_JWKS_URI") or _GOOGLE_OIDC_JWKS).strip(),
        # `openid email` — we need the verified `email` + `email_verified` claims for auto-provision/anti-takeover.
        "scopes": (g("VIGIL_CUSTOMER_OIDC_SCOPES") or "openid email").strip(),
        "username_claim": "sub",                                   # binding is (iss, sub); never a mutable claim
        "signing_algs": [a.strip().upper() for a in (g("VIGIL_CUSTOMER_OIDC_SIGNING_ALGS") or "RS256,ES256").split(",")
                         if a.strip()],
        "clock_skew_seconds": _int_env("VIGIL_CUSTOMER_OIDC_CLOCK_SKEW_SECONDS", 60),
    }


def customer_oidc_public_settings() -> dict:
    """What the KEYLESS EDGE reads — the non-secret settings with `client_secret` EXPLICITLY blank. The edge
    builds an `OidcConfig(client_secret="")` from this to form the authorize 302; it never reads the secret
    env var at all (the secret lives ONLY in the provisioner's `customer_oidc_settings()`)."""
    base = _customer_oidc_base()
    base["client_secret"] = ""
    return base


def customer_oidc_settings() -> dict:
    """What the PROVISIONER reads — the non-secret settings PLUS the client secret, for the token exchange.
    Consulted ONLY when `customer_oidc_enabled()` and ONLY on the provisioner side; the secret never reaches
    the keyless edge."""
    base = _customer_oidc_base()
    base["client_secret"] = (os.environ.get("VIGIL_CUSTOMER_OIDC_CLIENT_SECRET") or "")
    return base


# --- customer passkey (WebAuthn, Slice E3b-2 — SHIPPED OFF BY DEFAULT) ----------------
def customer_passkey_enabled() -> bool:
    """True iff customer passkey (WebAuthn) login is ON (`VIGIL_CUSTOMER_PASSKEY_ENABLED` affirmative). OFF by
    default: the edge's /api/customer/passkey/* routes are not served and nothing is minted."""
    return (os.environ.get("VIGIL_CUSTOMER_PASSKEY_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_passkey_rp_id() -> str:
    """The WebAuthn Relying-Party id (the registrable customer domain, e.g. `app.vigil.example`) the
    authenticator binds its assertion to (authenticatorData.rpIdHash == sha256(rp_id)). Empty ⇒ passkey
    verification fail-closed (the provisioner refuses)."""
    return (os.environ.get("VIGIL_CUSTOMER_PASSKEY_RP_ID") or "").strip()


def customer_passkey_origins() -> tuple:
    """The exact browser origins a customer passkey assertion/registration may carry in clientDataJSON.origin
    (comma-separated `VIGIL_CUSTOMER_PASSKEY_ORIGINS`, e.g. `https://app.vigil.example`). The WebAuthn core
    binds the origin cryptographically, so this is the phishing-resistance allowlist; empty ⇒ fail-closed."""
    raw = os.environ.get("VIGIL_CUSTOMER_PASSKEY_ORIGINS") or ""
    return tuple(o.strip().rstrip("/") for o in raw.split(",") if o.strip())


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


# --- W5-4 (#448): the ~/.sigil install manifest (product version + schema versions + install id) ---------
def install_manifest_schema_versions() -> "dict[str, int]":
    """The versioned artifacts THIS sovereign build writes into ``~/.sigil`` and the max schema of each it
    understands — the map that drives the fail-closed startup verify (W5-4). A future build that bumps any of
    these refuses-newer a ``~/.sigil`` written by an even newer build; and an older build refuses a home this
    one wrote with a bumped schema. Assembled from the per-artifact ``_MAX_*_SCHEMA`` constants so a schema
    bump is reflected here automatically. Imported lazily to avoid an import cycle (config -> spine)."""
    from .spine.checkpoint import _MAX_HEAD_SCHEMA
    from .spine.floor import _MAX_FLOOR_SCHEMA
    from .spine.manifest import _MAX_MANIFEST_SCHEMA
    from .spine.models import SCHEMA_VERSION
    from .spine.snapshot import _MAX_SNAPSHOT_SCHEMA
    return {
        "spine_record": int(SCHEMA_VERSION),
        "signed_head": int(_MAX_HEAD_SCHEMA),
        "anti_rollback_floor": int(_MAX_FLOOR_SCHEMA),
        "segment_manifest": int(_MAX_MANIFEST_SCHEMA),
        "snapshot_state": int(_MAX_SNAPSHOT_SCHEMA),
    }


def ensure_install_manifest():
    """Write-if-absent + verify-if-present the ``~/.sigil`` install manifest (W5-4, #448). Returns
    ``(manifest, created)``. Raises ``vigil_core.install_manifest.InstallManifestRefused`` (fail closed) if
    ``~/.sigil`` was written by a build this one does not understand (a newer manifest format, or a
    newer/foreign tracked schema) or whose self-integrity hash does not match. A fresh install writes the
    manifest with NO operator action. Called at sovereign CLI startup."""
    from vigil_core.install_manifest import ensure_operable

    from . import __version__
    return ensure_operable(SIGIL_HOME, product_version=__version__,
                           schema_versions=install_manifest_schema_versions())


# --- effective config + self-check ----------------------------------------------------
_SECRET_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")


def _strip_url_credentials(value):
    """Thin wrapper over the SHARED scrubber in ``vigil_core.doctor`` (imported lazily, like this module's
    other vigil_core uses). Sharing it with the offense doctor means the URL-credential redaction can never
    drift between the two trust planes — both surface DSNs to operator+ over /api/doctor."""
    from vigil_core.doctor import strip_url_credentials
    return strip_url_credentials(value)


def _redact(name: str, value):
    """Redact any value whose KEY NAME looks like a secret; then strip URL-embedded credentials from
    whatever survives (a value-level backstop for creds under a non-secret-named key)."""
    if value and any(h in name.upper() for h in _SECRET_HINTS):
        return "***redacted***"
    return _strip_url_credentials(value)


def effective_config() -> dict:
    """The fully-resolved runtime configuration (env → sigil.env → default), secrets REDACTED.
    Re-reads the environment at call time, so it reflects overrides applied after import — this is
    the honest "what will SIGIL actually use on this host" view the audit asked for."""
    home = _resolve_home()
    spine = home / "spine"
    # Only the key's PRESENCE is surfaced — the raw value never enters this dict. `_redact` would mask it by
    # key NAME anyway, but a name-based sanitizer is invisible to taint analysis (CodeQL
    # py/clear-text-logging-sensitive-data traced the raw key into `sigil doctor --json`), so keep the secret
    # out of the data entirely. Output is byte-identical: set -> "***redacted***", unset/empty -> "".
    api_key_set = bool(os.environ.get("SIGIL_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))
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
        "ANTHROPIC_API_KEY": "***redacted***" if api_key_set else "",
        # OIDC RP: OFF by default (byte-identical / no egress). When ON, surface the issuer + endpoints so
        # the operator can confirm the IdP is a PRIVATE/tunnel address; the client secret is redacted by the
        # SECRET name-hint below (and is not placed here at all).
        "SIGIL_OIDC_ENABLED": oidc_enabled(),
        "SIGIL_OIDC_ISSUER": (os.environ.get("SIGIL_OIDC_ISSUER", "") if oidc_enabled() else ""),
        "SIGIL_OIDC_CLIENT_ID": (os.environ.get("SIGIL_OIDC_CLIENT_ID", "") if oidc_enabled() else ""),
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
    safe = _strip_url_credentials(url)   # the detail is surfaced to operator+ over /api/doctor — never inline creds
    try:
        import urllib.request
        with urllib.request.urlopen(url.rstrip("/") + "/readyz", timeout=2) as r:
            code = getattr(r, "status", None) or r.getcode()
        return ("qdrant", 200 <= int(code) < 300, f"{safe} → HTTP {code}")
    except Exception as e:  # noqa: BLE001 — any failure = not reachable
        # NEVER echo the raw exception text: a malformed-URL error can quote a credential FRAGMENT that is
        # neither the whole URL nor a parseable URL (so neither replace nor the URL scrubber would catch it).
        # A socket error's `.reason` is URL-free and useful; a parse error (no `.reason`) → just the type.
        reason = getattr(e, "reason", None)
        why = str(reason) if reason is not None else type(e).__name__
        return ("qdrant", False, f"{safe} unreachable: {_strip_url_credentials(why)}")


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
