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
import re
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
# The roll-forward journal of a restore into this home that swaps a hard-pruned unit in, or replaces an interrupted
# restore (`sigil restore`). It exists only while such a restore is between its first and its last swap: while it
# does, signed-head verification and signing fail closed and the CLI refuses everything but `sigil restore --resume /
# --abort` and `sigil doctor`.
RESTORE_JOURNAL_PATH = SIGIL_HOME / "restore-journal.json"
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
EMAIL_CODES_DIR = _customer / "email_codes"             # the 6-digit codes sent beside them (when enabled)
EMAIL_CODE_RATELIMIT_DIR = _customer / "email_code_ratelimit"   # wrong codes per email+purpose, across re-sends
LOGIN_RATELIMIT_DIR = _customer / "login_ratelimit"     # per-account / per-ip lockout markers
TRIAL_CREDITS = _int_env("VIGIL_TRIAL_CREDITS", 100)    # server-constant trial grant (never on-the-wire)
# Anti-farming ceilings on the provisioner's owner-signed mints. The signup cap is a GLOBAL per-rolling-day
# ceiling on self-serve signups (each mints a real trial credit — a Sybil ceiling on real money); the member
# limiter is a per-org ceiling on grant/revoke churn. Both are SEPARATE LoginRateLimiter instances rooted
# here under disjoint marker dirs, so they never interfere with the per-account/per-ip login limiter.
SIGNUP_CAP_DIR = _customer / "signup_cap"               # the global signup-cap limiter's markers
MEMBER_RATELIMIT_DIR = _customer / "member_ratelimit"   # the per-org member-management limiter's markers
# The PENDING team invitations an org_admin raises for a person who has no VIGIL account yet (ui/member_invites_store.py):
# one 0600 marker per invite, named by sha256(the single-use token). An invite GRANTS NOTHING until it is redeemed at
# sign-up / sign-in; the raw token is never stored (only its hash names the marker) so a directory read cannot recover a
# live token. Ephemeral operational state under customer/ (the backup EXCLUDES it, like the email-token markers): a
# restore drops any un-redeemed invite (it is simply re-sent; the authoritative membership a redeemed invite produced is
# owner-signed on the spine). The invite TTL (7 days) and the per-org pending ceiling bound abuse.
CUSTOMER_MEMBER_INVITES_DIR = _customer / "member_invites"
CUSTOMER_INVITE_TTL_SECONDS = _int_env("VIGIL_CUSTOMER_INVITE_TTL_SECONDS", 7 * 24 * 3600)   # a pending invite lives 7 days
CUSTOMER_MAX_PENDING_INVITES = _int_env("VIGIL_CUSTOMER_MAX_PENDING_INVITES", 100)           # per-org pending-invite ceiling
SIGNUP_EMAIL_RATELIMIT_DIR = _customer / "signup_mailbox_ratelimit"   # per-canonical-mailbox sign-up limiter
TRIAL_LAUNCH_CAP_DIR = _customer / "trial_launch_cap"   # the global daily trial-launch cap's markers
TRIAL_IP_LIMIT_DIR = _customer / "trial_ip_limit"       # the opt-in per-IP trial-grant limiter's markers
CHECKOUT_RATELIMIT_DIR = _customer / "checkout_ratelimit"   # the per-org/per-requester checkout limiter's markers
PENDING_PLAN_CHECKOUT_DIR = _customer / "pending_plan_checkout"   # owner-signed pending plan-checkout records
# Slice E3b — customer MFA (TOTP / passkey). The AEAD context that binds a sealed CUSTOMER TOTP secret to its
# purpose — DOMAIN-SEPARATED from the operator `sigil/account.totp` so a customer seal can never be opened as
# an operator TOTP secret (or vice-versa) or swapped for the owner key. The provisioner (the owner-key holder)
# seals at enroll + unseals at verify; only the sealed blob ever reaches the spine (the plaintext is shown to
# the customer ONCE at enrollment, never persisted).
CUSTOMER_TOTP_SEAL_CONTEXT = b"sigil/customer.totp"
CUSTOMER_MFA_REPLAY_DIR = _customer / "mfa_totp_replay"  # the per-customer TOTP (username, step) replay ledger
# Enrolment hardening (VIGIL_CUSTOMER_MFA_ENROLL_STEPUP). Confirm-before-activate stores a freshly generated
# TOTP secret as PENDING here (the owner-vault-SEALED blob, never plaintext) until a fresh code confirms it, so
# a hijacked session cannot silently SWAP the active factor; one marker per account, named by a domain-separated
# sha256 of the username; expires after CUSTOMER_MFA_PENDING_TTL_SECONDS. The per-account MFA brute-force /
# enrolment-churn limiter's markers live in their own dir. Both are inert while the flag is off (nothing writes).
CUSTOMER_MFA_PENDING_TOTP_DIR = _customer / "mfa_totp_pending"
CUSTOMER_MFA_ENROLL_RATELIMIT_DIR = _customer / "mfa_enroll_ratelimit"
CUSTOMER_MFA_PENDING_TTL_SECONDS = _int_env("VIGIL_CUSTOMER_MFA_PENDING_TTL_SECONDS", 900)   # 15 minutes
# Slice E3b-2 — customer passkey (WebAuthn). The single-use registration/assertion challenge ledger (edge) +
# the NON-SIGNED per-credential sign-count clone-floor ledger (provisioner; a monotonic high-water, NOT an
# owner-signed record — a passkey login is a pure signature check with no owner re-sign). OFF by default:
# with customer_passkey_enabled() false the edge's passkey routes are absent and nothing is minted.
CUSTOMER_PASSKEY_CHALLENGE_DIR = _customer / "passkey_challenges"   # single-use WebAuthn challenges (edge)
CUSTOMER_PASSKEY_SIGNCOUNT_DIR = _customer / "passkey_signcount"    # per-credential_id monotonic sign-count floor
# Whether each customer account has finished or skipped the onboarding tour (ui/onboarding_store.py): a UI preference,
# never money or authority — one hashed-name JSON file per account. Losing it only shows the tour once more.
CUSTOMER_ONBOARDING_DIR = _customer / "onboarding"
# The settings shell's General-tab preferences (ui/preferences_store.py): the legal-entity / contact profile a
# workspace records (entity name, registered address, contractual + emergency contact). A UI preference, never money
# or authority and never on the signed spine — one hashed-name JSON file per account; written only while
# VIGIL_CUSTOMER_SETTINGS is on. The customer typed it and nothing regenerates it, so it is NOT under customer/ (the
# operational markers a backup excludes): it is its own top-level directory, which the backup captures
# (backup._STATE_DIRS) and a restore brings back.
CUSTOMER_PREFERENCES_DIR = SIGIL_HOME / "customer_preferences"
# Legal/governance S12 — the owner-review requests a customer drops from the read-only Authorizations surface
# (ui/authorization_requests_store.py): "please authorize an assessment of host X". It is NOT an authority and NOT
# money — it mints nothing and is never owner-signed; the owner still signs the real EngagementAuthority in the cockpit
# (ui/target_authorization.py). An UNSIGNED, off-spine per-org queue (one hashed-name JSON file per org), written only
# while VIGIL_CUSTOMER_AUTHORIZATIONS is on. It is an operational owner-review queue: a restore drops any pending
# request (the customer re-requests; the authoritative authorities live owner-signed on the authority seam), so the
# backup EXCLUDES it with a documented reason (backup._EXCLUSION_REASONS).
CUSTOMER_AUTHORIZATION_REQUESTS_DIR = SIGIL_HOME / "customer_authorization_requests"
# Legal/governance S3 — the customer data-rights request ledger (ui/data_rights_store.py): one owner-signed,
# append-only record per deletion / close-account request a customer records from the Data-rights screen. It is a
# DURABLE record of what the owner must act on, not money and not authority — it unlocks nothing by itself and never
# touches the hot signed spine. Its own top-level directory (the customer recorded it and nothing regenerates it), so
# the backup captures it (backup._STATE_DIRS) and a restore brings it back; written only while
# VIGIL_CUSTOMER_DATA_RIGHTS is on.
CUSTOMER_DATA_RIGHTS_DIR = SIGIL_HOME / "customer_data_rights"
# Legal/governance S3 — the OWNER DECISION wired into the Data-rights screen: VIGIL responds to a data-rights request
# (access / correction / deletion / export) within this many days (GDPR-standard), and the published data-subject
# contact is this mailbox (as stated in the Privacy notice and Terms of Service). Single-sourced here so the screen,
# the recorded request and the owner notification all state the same figures.
CUSTOMER_DATA_RIGHTS_SLA_DAYS = 30
CUSTOMER_DATA_RIGHTS_CONTACT = "info@sigilsovereign.com"
# Per-tenant customer KNOWLEDGE corpus (customer_knowledge_enabled). A customer uploads their own organization
# documents so the assistant knows their org. Each org's corpus lives in its OWN sub-directory under here, named by a
# one-way hash of org_id (tenant_knowledge.store), and inside it a per-org signed spine, a per-org vector index and a
# per-org graph dir. It is DISJOINT by construction from the owner's global single-tenant stores (SPINE_PATH /
# QDRANT_PATH / GRAPH_DIR) and from every other org's corpus, so a customer can NEVER read the owner's private notes /
# transcripts / commits and NEVER another tenant's documents. Durable customer content (the customer uploaded it and
# nothing regenerates it): its own top-level directory the backup captures and a restore brings back. Written only
# while VIGIL_CUSTOMER_KNOWLEDGE is on.
CUSTOMER_KNOWLEDGE_DIR = SIGIL_HOME / "customer_knowledge"
# C1a — the launches a customer reserved from the app and has not started or cancelled yet (ui/customer_launches.py):
# a cache of the owner-signed leases the customer was already handed, so the app can start or cancel one after a
# reload. Never money or authority; written only while VIGIL_CUSTOMER_LAUNCH_UI is on.
CUSTOMER_LAUNCHES_DIR = _customer / "launches"
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


def customer_mfa_enroll_stepup_enabled() -> bool:
    """True iff AUTHENTICATOR-ENROLMENT hardening is ON (`VIGIL_CUSTOMER_MFA_ENROLL_STEPUP` affirmative). OFF by
    default (the codebase's posture-flag pattern): when OFF the enrol/verify paths are BYTE-IDENTICAL to today
    (a TOTP enrol activates the new secret at once, enrolling a factor needs only a session, and verify has no
    per-account limiter). When ON, this one flag turns on all three enrolment guards together:

      * CONFIRM-BEFORE-ACTIVATE (TOTP): `enroll_totp` stores the sealed secret as PENDING instead of activating
        it; a separate `confirm_totp` (a fresh code) activates it — so a hijacked session cannot silently SWAP
        the victim's authenticator (a passkey enrol is confirm-by-construction: its WebAuthn registration
        ceremony is itself the proof, so it has no pending/confirm split);
      * STEP-UP ON ENROLMENT (TOTP + passkey): adding/replacing a factor when the account ALREADY has one needs
        a FRESH second-factor proof (the session's `mfa_at` within `CUSTOMER_STEPUP_WINDOW_SECONDS`), checked at
        enrolment and again when a pending TOTP is confirmed; the FIRST factor (bootstrap, no existing factor) is
        allowed without step-up;
      * RATE-LIMIT: a per-account limiter bounds TOTP code-guessing (verify + confirm) and enrolment churn.

    Distinct from `customer_stepup_required()` (E3c), which gates step-up on the SPEND/offense ops
    (launch / target-verify / member change); this flag gates step-up on the ACCOUNT-SECURITY ops. Both the edge
    (the confirm route, relaying the session's `mfa_at`) and the cockpit (the guards) read it on each request —
    set the SAME value in customer.env and cockpit.env (a value on one side only fails closed or stays inert)."""
    return (os.environ.get("VIGIL_CUSTOMER_MFA_ENROLL_STEPUP") or "").strip().lower() in _OIDC_AFFIRMATIVE
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

# PL01 CHK-1b — how long PAST period_end the "org already holds a live plan" double-bill guard keeps refusing a
# SECOND plan of that kind, so one is never sold in the window where the FIRST can still produce a charge (which
# would double-bill). SPLIT by subscription status, because the two gaps differ by orders of magnitude:
#   * ACTIVE: a successful auto-renewal webhook lands within minutes, so a SHORT grace covers the stale-period_end
#     window between the paid month ending and the renewal landing.
#   * PAST_DUE: Stripe keeps RETRYING (Smart Retries) for its whole dunning window (~2-3 weeks) and a late
#     success RE-ACTIVATES the subscription with a pushed-forward period_end — so a second plan sold anywhere in
#     that window double-bills. Keep the guard on for the full dunning deadline; after it the plan is presumed
#     dead (no terminal-cancel webhook is wired yet) and a fresh purchase is allowed. Tune to the configured
#     Stripe retry horizon if it differs.
PLAN_RENEWAL_GRACE_SECONDS = _int_env("VIGIL_PLAN_RENEWAL_GRACE_SECONDS", 72 * 3600)           # active renewal gap
PLAN_PAST_DUE_GRACE_SECONDS = _int_env("VIGIL_PLAN_PAST_DUE_GRACE_SECONDS", 30 * 24 * 3600)     # past_due dunning window


def customer_monitoring_enabled() -> bool:
    """True iff the customer monitoring-authority routes are ON (`VIGIL_CUSTOMER_MONITORING_ENABLED`
    affirmative). OFF by default: the edge routes and provisioner actions are absent (404) exactly as an
    unknown route, and nothing is minted or published."""
    return (os.environ.get("VIGIL_CUSTOMER_MONITORING_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


# AEGIS AS-6d — the customer-app AEGIS ONBOARDING flow (#/monitoring/onboarding + its read). STRICT, default-OFF.
# A SECOND, independent gate on top of `customer_monitoring_enabled` (like AS-2f's v2 surface): the onboarding
# read `monitor_onboarding` and its screen are ABSENT (404 exactly as an unknown route) unless BOTH the
# monitoring master flag AND this flag are affirmative. The flow mints/arms/releases NOTHING — it only guides
# and READS the already-signed grants the Monitoring screens already surface — so with it off the build is
# byte-identical and no existing read gains a key. It deep-links to the already-built surfaces (Monitoring,
# the AS-4b preview, the AS-27b defense control), which require the monitoring flag, hence the double gate.
def customer_aegis_onboarding_enabled() -> bool:
    """True iff the customer AEGIS onboarding flow is ON (`VIGIL_CUSTOMER_AEGIS_ONBOARDING` affirmative). Read
    at call time; fail-safe default OFF. The route serves only when this AND `customer_monitoring_enabled` are
    on; off, the onboarding route is an unknown route (404) and the Monitoring settings link to it is absent."""
    return (os.environ.get("VIGIL_CUSTOMER_AEGIS_ONBOARDING") or "").strip().lower() in _OIDC_AFFIRMATIVE


# AEGIS AS-2f — the SOVEREIGN v2 authority surface (grant/revoke/renew over the AS-2a authority-v2 contracts).
# STRICT, default-OFF. A SECOND, independent gate on top of `customer_monitoring_enabled`: the v2 provisioner
# actions (`monitor_authorize_v2` / `monitor_revoke_v2` / `monitor_renew`) are ABSENT (404 exactly as an unknown
# route) unless BOTH flags are affirmative, and nothing v2 is minted or published. With it off the build is
# byte-identical to before (the v1 AE-1 path is untouched). Tenant origins stay OUT (deferred to AS-2g).
def aegis_sovereign_v2_enabled() -> bool:
    """True iff the AEGIS sovereign-v2 authority surface is ON (`VIGIL_AEGIS_SOVEREIGN_V2` affirmative). Read at
    call time; fail-safe default OFF."""
    return (os.environ.get("VIGIL_AEGIS_SOVEREIGN_V2") or "").strip().lower() in _OIDC_AFFIRMATIVE


# The short-lived v2 LEASE window (§4.7 proposed 1 h): the TIGHT end-to-end liveness bound inside the grant's
# outer window. A lapsed lease degrades the data plane to uninspected pass-through (R16), so a grant is renewed
# (`monitor_renew`) well before it lapses. Clamped to never exceed the grant window.
MONITORING_LEASE_SECONDS = _int_env("VIGIL_MONITORING_LEASE_SECONDS", 3600)


def monitoring_v2_publish_dir() -> Path:
    """Where owner-signed v2 monitoring authorities + epoch statements are published for the KEYLESS AEGIS
    gateway (AS-2c reads, verify-only). `VIGIL_MONITORING_V2_PUBLISH_DIR` overrides; default a dedicated `v2`
    subtree under the v1 publish dir so v1 and v2 artifacts never share a file (distinct, content-addressed
    names). Only signed public artifacts land here — never private material."""
    override = (os.environ.get("VIGIL_MONITORING_V2_PUBLISH_DIR") or "").strip()
    if override:
        return Path(override)
    return monitoring_publish_dir() / "v2"


def redpen_enabled() -> bool:
    """True iff the Red-Pen (code-review) surfaces are ON (`VIGIL_REDPEN_ENABLED` affirmative). OFF by default
    (mirrors `customer_monitoring_enabled`): with it off EVERY Red-Pen route / action / worker / check-run / schedule
    is absent (404 exactly as an unknown route), the GitHub App egress refuses, `reserve_redpen_review` refuses, no
    connected-repo record is minted and no installation token is ever requested — so the server is byte-identical to a
    build without Red-Pen. The master flag over the whole Red-Pen pipeline (the GitHub App auth, the connected-repo
    registry, per-repo settings + review metering, the PR-review worker and the Code screen). Read at call time.
    Even when ON, each leg still fails closed unless its own credential is provisioned (the App id + private key, the
    webhook secret) — the owner registers the real GitHub App (with `checks:write`) as the last step before go-live."""
    return (os.environ.get("VIGIL_REDPEN_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_fix_it_enabled() -> bool:
    """True iff the customer one-click "Fix it for me" DISPATCH (consumer Area 10 / PR-K) is ON
    (`VIGIL_CUSTOMER_FIX_IT` affirmative). OFF by default and NESTED under `VIGIL_REDPEN_ENABLED` (which gates the
    whole Code screen): with it off the Code screen's Fix this action keeps returning the honest inert "coming"
    answer — byte-identical to a build without the dispatch — and the overview advertises `fix` as unavailable;
    nothing is reserved, metered or published to the `redpen-actions` seam.

    With it ON (and `VIGIL_REDPEN_ENABLED` also on), an explicit customer "Fix this" on ONE reproduced finding
    DISPATCHES to the already-built offense Fix worker (`vigil_integration.jobs.redpen_fix`) by publishing a
    validated action marker to the dedicated `redpen-actions` seam — but ONLY after the full sovereign guard
    chain that was already present: the `manage_code` admit (decision O-4), the E3c step-up (a fix opens a PR —
    sensitive), and a `reserve_redpen_review` that re-verifies the active owner-signed connected-repo record +
    the wallet floor + the per-repo monthly limit and METERS the model spend with no estimate. The dispatch
    GRANTS NO BYPASS: the marker is an untrusted trigger and the offense plane re-checks every authority where it
    WRITES (the owner-signed repo-exact `"pr"` grant + the signed-spine FACT), re-reviews the patch, and opens
    only a gated, m-of-n-quorum PR from a fix branch — VIGIL never merges. It mints NO fact and implies NO
    clearance: a clearance is the signed NEGATIVE remediation cert the independent verification path earns, never
    a button's claim. Read at call time; a pure env read (FATAL-2 clean — this sovereign accessor loads no
    offense module, and the offense plane reads the same master `VIGIL_REDPEN_ENABLED` through its own helper)."""
    return (os.environ.get("VIGIL_CUSTOMER_FIX_IT") or "").strip().lower() in _OIDC_AFFIRMATIVE


def presentation_enabled() -> bool:
    """True iff the APEX PR-A presentation spine is ON (`VIGIL_APEX_PRESENTATION` affirmative). OFF by default
    (mirrors `redpen_enabled`): with it off the customer Posture read (``/api/customer/assessments/posture`` →
    the ``assessment_posture`` cockpit action → ``finding_presentation.assessment_posture``) is absent (404 exactly
    as an unknown route), the findings projection NEVER carries the ``presentation`` cert field, and the page's
    ``__VIGIL_PRESENTATION__`` switch is "0" — so the server is byte-identical to a build without the feature.

    This is the SOVEREIGN-side master flag over the consumer surface (the Posture screen + the per-finding
    plain-language/standards/remediation projection). The ENGINE reads the SAME env var at FACT-mint
    (``evidence.certify``) to decide whether to embed the additive SIGNED ``presentation`` block into a
    certificate; both planes read ``VIGIL_APEX_PRESENTATION`` independently (no cross-env import — the engine
    reads ``os.environ`` directly, the sovereign plane reads it here), so one value turns the whole feature on.
    The ``presentation`` block is ADDITIVE SIGNED DATA that never changes a FACT/oracle verdict, and posture +
    triage are derived SOVEREIGN-side ONLY from the org's own proven findings. Read at call time."""
    return (os.environ.get("VIGIL_APEX_PRESENTATION") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_attack_path_enabled() -> bool:
    """True iff the customer Attack-path storytelling screen is ON (`VIGIL_CUSTOMER_ATTACK_PATH` affirmative). OFF
    by default (Area 11 UI): with it off the ``#/attack-path`` SPA route is the home screen (exactly as an unknown
    route), no nav link is shown, the page's ``__VIGIL_ATTACK_PATH__`` switch is "0", and the sovereign findings
    projection NEVER surfaces the inert ``attack_path`` cert field — so the server is byte-identical to a build
    without the feature.

    PURE PRESENTATION: ``attack_path`` is additive, purely-descriptive signed DATA that rides the EXISTING
    tenant-scoped finding projection (``assessments._finding_json``); it restates oracles that already fired for
    the org's OWN proven findings, is NEVER read for any verdict, and can promote nothing. The screen only draws
    a chain the signed data already established — it invents no finding and asserts no impact the cert did not.
    Read at call time."""
    return (os.environ.get("VIGIL_CUSTOMER_ATTACK_PATH") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_blind_vuln_enabled() -> bool:
    """True iff the customer blind-vulnerability (out-of-band) confirmation badge is ON (`VIGIL_CUSTOMER_BLIND_VULN`
    affirmative). OFF by default (Area 11 UI): with it off the finding card renders byte-identically (no badge),
    the page's ``__VIGIL_BLIND_VULN__`` switch is "0", and the sovereign findings projection NEVER surfaces the
    inert ``oob_attestation`` cert field — so the server is byte-identical to a build without the feature.

    PURE PRESENTATION: ``oob_attestation`` is the EXISTING signed, independent out-of-band callback receipt
    (pinned-collector-key attested) carried on the finding cert as inert DATA. The badge only SURFACES that a
    proven finding was confirmed out of band (a vuln with no visible response); it re-verifies nothing, promotes
    nothing, and is shown ONLY when the signed attestation is present — absence is never rendered as "clean".
    Read at call time."""
    return (os.environ.get("VIGIL_CUSTOMER_BLIND_VULN") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_assistant_enabled() -> bool:
    """True iff the customer security ASSISTANT (PR-J) is ON. DEFAULT-ON for the hosted deployment: UNSET reads
    ENABLED, and an explicit ``VIGIL_CUSTOMER_ASSISTANT=0`` (or any non-affirmative token) forces it OFF
    byte-identically to the pre-default-on build - off, the `assistant_ask` edge route and the provisioner action are
    ABSENT (404 exactly as an unknown route/action), NO model grant is minted for the assistant and NO model request
    is made, so the server is byte-identical to a build without the assistant. The assistant is a metered NL chat
    grounded ONLY in the tenant's own oracle-confirmed findings: it summarises / explains / prioritises existing
    findings as ADVICE, never asserts a new vulnerability and never mints a FACT (the oracle is the sole minter), and
    every model request goes through the sovereign model gateway (it holds no provider key). Read at call time. Even
    ON, a turn still fails closed unless the model gateway is reachable and an owner key is present to mint the turn's
    grant."""
    return _default_on_flag("VIGIL_CUSTOMER_ASSISTANT")


def customer_assistant_wallet_enabled() -> bool:
    """True iff every customer security-assistant turn is ACCOUNTED to the asking org (PR-J2,
    `VIGIL_CUSTOMER_ASSISTANT_WALLET` affirmative). OFF by default (mirrors `redpen_enabled`): with it off the assistant
    is exactly PR-J's — refused while metered billing is on, otherwise metered against its grant's cap — the model
    gateway's allowance source never answers for an assistant grant, the customer statement carries no assistant line
    and the reservation sweep has no assistant leg: byte-identical to a build without it. ON (with
    `VIGIL_CUSTOMER_ASSISTANT`), in EVERY billing mode a turn is admitted only within the org's rate limit and daily
    turn budget (`assistant_turns_per_hour` / `assistant_turns_per_day`; over either ⇒ rate limited) and only after an
    owner-signed audit record of it (who asked, for which org, under which grant — `governor.assistant_turns`) is on the
    spine. With `VIGIL_METERED_BILLING` on it is also BILLED to the org's own credits: before its one model request the
    turn HOLDS that request's worst case (an owner-signed reserve keyed by the turn's grant nonce — refused, with nothing
    held, when the exact balance or the credit line cannot cover it), the gateway admits the request only within that
    hold, and the turn then settles EXACTLY (its confirmed metered charge kept to the milli-credit, the rest returned)
    with a "Security assistant" line on the statement (`ui.assistant_wallet`). With metered billing off nothing is
    drawn (flat billing: VIGIL bears the model cost, bounded per org per day by the turn budget times the grant's cap).
    Read at call time."""
    return (os.environ.get("VIGIL_CUSTOMER_ASSISTANT_WALLET") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_knowledge_enabled() -> bool:
    """True iff the per-tenant customer KNOWLEDGE corpus is ON (`VIGIL_CUSTOMER_KNOWLEDGE`). DEFAULT ON: with the var
    UNSET (or any value that is not an explicit off, `_FLAG_EXPLICIT_OFF`) the feature is enabled, so a fresh consumer
    deploy ships with it on; ONLY an explicit off value (`0`/`false`/`no`/`off`/`disabled`) turns it off. This is the
    ONE consumer flag that defaults on (an owner launch decision - every other `customer_*` predicate defaults off);
    the production deploy templates also set it to `1` explicitly. A working flag-OFF path is retained so it can be
    toggled and a flag-off golden stays valid: with it off the three `customer_knowledge_*` provisioner actions and
    their edge routes are ABSENT (404 as an unknown action), NO per-org corpus directory is created, and the security
    assistant grounds ONLY in oracle-confirmed findings exactly as before (no document block) - byte-identical to a
    build without the feature. ON, a customer may upload their own organization documents into a SEPARATE per-org
    corpus (its own spine + vector index + graph dir, scoped by a one-way hash of org_id - `CUSTOMER_KNOWLEDGE_DIR`)
    that NEVER touches the owner's global single-tenant stores, and the assistant MAY additionally summarise / cite
    that org's OWN documents as context - it still never asserts or mints a finding from a document (the oracle alone
    mints a FACT). Read at call time. The per-tenant isolation, the owner-global-store unreachability, the upload caps
    and the assistant finding-minting firewall hold regardless of this flag's default."""
    return (os.environ.get("VIGIL_CUSTOMER_KNOWLEDGE") or "").strip().lower() not in _FLAG_EXPLICIT_OFF


def assistant_turns_per_hour() -> int:
    """PR-J2 — the most security-assistant turns ONE org may have answered in any rolling hour
    (`VIGIL_ASSISTANT_TURNS_PER_HOUR`, default 20), counted from the owner-signed turn ledger
    (`governor.assistant_turns`); a turn past it is refused as rate limited. Consulted only while
    `customer_assistant_wallet_enabled()`. A junk/out-of-range value falls back to the default (never "unlimited")."""
    raw = (os.environ.get("VIGIL_ASSISTANT_TURNS_PER_HOUR") or "").strip()
    try:
        n = int(raw) if raw else 20
    except ValueError:
        return 20
    return n if 1 <= n <= 10_000 else 20


def assistant_turns_per_day() -> int:
    """PR-J2 — the daily turn BUDGET of ONE org's security assistant: the most turns it may have answered in any
    rolling day (`VIGIL_ASSISTANT_TURNS_PER_DAY`, default 100), from the same ledger as `assistant_turns_per_hour`. With
    each turn's model spend capped by its grant (`assistant_cap_nano_usd`), a flat-billed org can cost VIGIL at most
    this many times that cap a day. Consulted only while `customer_assistant_wallet_enabled()`. A junk/out-of-range
    value falls back to the default (never "unlimited")."""
    raw = (os.environ.get("VIGIL_ASSISTANT_TURNS_PER_DAY") or "").strip()
    try:
        n = int(raw) if raw else 100
    except ValueError:
        return 100
    return n if 1 <= n <= 100_000 else 100


def customer_notify_enabled() -> bool:
    """True iff the customer Notifications & integrations surfaces are ON (`VIGIL_CUSTOMER_NOTIFY` affirmative).
    OFF by default (mirrors `redpen_enabled`): with it off EVERY notify route / channel registration / outbound
    delivery / issue-tracker sync / notify-drain is absent (404 exactly as an unknown route), no channel config is
    written, no outbound socket opens and no tracker issue is opened or closed — so the server is byte-identical to a
    build without the notify consumer. The master flag over the whole PR-D pipeline (the per-tenant channel registry,
    the SSRF-guarded delivery egress, the notify-drain and the Jira/Linear/GitHub issue sync). Read at call time.
    Even when ON, each leg still fails closed unless its own delivery credential is provisioned (an SMTP relay, a
    tracker API token) AND the target host is on the owner-reviewed outbound allowlist — a notification is a DELIVERY
    of an oracle-minted FACT, never a FACT source (the oracle alone mints a finding)."""
    return (os.environ.get("VIGIL_CUSTOMER_NOTIFY") or "").strip().lower() in _OIDC_AFFIRMATIVE


def apex_autonomous_enabled() -> bool:
    """True iff the APEX autonomous DRIVER is ON (`VIGIL_APEX_AUTONOMOUS` affirmative). OFF by default
    (mirrors `redpen_enabled`): with it OFF an engagement runs the exact current fixed pipeline — crawl →
    audit → confirm → chain → ground — and the autonomous OODA loop stays a post-scan advisory appendix
    behind `--autonomous`; nothing in the primary path changes and `make gate` is byte-identical. With it
    ON, `framework.v2.engage.run_engagement` keeps the one gated scan executor OPEN past the scan and drives
    the select→act→observe→reorient loop IN-ENGAGEMENT over it (one shared request budget), so a recon-
    discovered surface is promoted → crawled → probed → oracle-confirmed WITHOUT a human pointing at it —
    the loop proposes, the gate authorizes, the oracle confirms (no new mint site). Read at call time.
    FATAL-2 safe: a pure env read; this sovereign accessor loads no offense module, and the offense engine
    reads the SAME env var directly (it never imports sigil). Even ON, every probe is still re-gated fail-
    closed (kill-switch → scope → budget → egress) and a finding is minted only when the oracle fires."""
    return (os.environ.get("VIGIL_APEX_AUTONOMOUS") or "").strip().lower() in _OIDC_AFFIRMATIVE
def customer_sso_enabled() -> bool:
    """True iff the consumer SSO / SCIM surfaces are ON (`VIGIL_CUSTOMER_SSO` affirmative). OFF by default
    (mirrors `redpen_enabled`): with it off EVERY SSO/SCIM route / action is absent (404 exactly as an unknown
    route), the edge serves no SAML ACS / enterprise-OIDC callback / SCIM endpoint, the provisioner's `sso_*` /
    `scim_*` dispatch returns None, no SSO config is read and no membership is ever provisioned from an IdP — so
    the server is byte-identical to a build without SSO. The master flag over the whole PR-H pipeline
    (`governor.sso_config`, `governor.scim`, `ui.saml`, `ui.scim`). Read at call time.

    Even when ON, every leg still fails closed unless the OWNER has signed a per-org SSO config
    (`governor.sso_config`): SSO proves identity, the owner-signed config supplies the (ceiling-capped) role, and
    SCIM/SAML/OIDC can provision ONLY `viewer`/`analyst`/`org_admin` — never `operator`/`founder`/`owner` or any
    money/offense authority, which stay owner-signed. SAML signature verification additionally requires a vetted
    XML-DSig backend (`ui.saml.signxml_sig_verifier`); absent it, SAML login fails closed (enterprise-OIDC does
    not need it). Set the SAME value in customer.env and cockpit.env: the edge serves the routes, the cockpit
    dispatches the actions (a value on one side only fails closed)."""
    return (os.environ.get("VIGIL_CUSTOMER_SSO") or "").strip().lower() in _OIDC_AFFIRMATIVE


# Consumer PR-H — the provisioner-side SSO/SCIM ledgers (written only while VIGIL_CUSTOMER_SSO is on): the durable
# single-use SAML assertion-ID ledger (replay guard), the per-(org, client IP) failed-SCIM-authentication limiter
# and the per-org SCIM write budget (VIGIL_SCIM_OPS_PER_MIN spine records per org per minute: a write is admitted
# while the org is within budget and then charged one unit per record it appended — bounds how fast even a valid
# token can grow the spine; see ui.sso_provision for the per-request bounds). The default, 1800 records a minute, keeps a
# first user sync at about 600 users a minute (a user create writes 3 records: user, audit, grant). The per-org SCIM
# READ budget (VIGIL_SCIM_READS_PER_MIN reads per org per minute, guard-and-count) bounds how much spine folding one
# org's token can ask for; its default matches a first sync's "does this user exist?" lookup before each create.
CUSTOMER_SAML_REPLAY_DIR = _customer / "sso_saml_replay"
SCIM_AUTH_RATELIMIT_DIR = _customer / "scim_auth_ratelimit"
SCIM_WRITE_RATELIMIT_DIR = _customer / "scim_write_ratelimit"
SCIM_READ_RATELIMIT_DIR = _customer / "scim_read_ratelimit"
SCIM_OPS_PER_MIN = _int_env("VIGIL_SCIM_OPS_PER_MIN", 1800)
SCIM_READS_PER_MIN = _int_env("VIGIL_SCIM_READS_PER_MIN", 1800)
# The per-org DEPROVISIONING cap (VIGIL_SCIM_DEPROVISIONS_PER_MIN units per org per minute; a deprovisioning request
# costs the records it appended, at least one): a request that can only take privilege away skips the write budget,
# and this is its own, much higher, count bound. Never refuses while the org is under it, and even an org over it
# gets one deprovisioning admitted per minute, so an offboarding always makes progress.
SCIM_DEPROV_RATELIMIT_DIR = _customer / "scim_deprov_ratelimit"
SCIM_DEPROVISIONS_PER_MIN = _int_env("VIGIL_SCIM_DEPROVISIONS_PER_MIN", 6000)
# The per-org enterprise sign-in budget (VIGIL_SSO_SIGNINS_PER_MIN VERIFIED sign-ins per org per minute, beside the
# per-client-IP limiter): an org's own IdP can mint valid assertions without limit and from any address, and each
# resolved sign-in folds the spine.
SSO_SIGNIN_RATELIMIT_DIR = _customer / "sso_signin_ratelimit"
SSO_SIGNINS_PER_MIN = _int_env("VIGIL_SSO_SIGNINS_PER_MIN", 600)
# Every UNAUTHENTICATED SSO leg (sign-in start, SAML ACS, OIDC callback) is guard-and-counted per client IP,
# successes included (VIGIL_SSO_REQUESTS_PER_IP_PER_MIN, default 300 a minute: a sign-in is two legs, and a company
# behind one NAT address signs many people in), and at most VIGIL_SSO_CONCURRENCY of them do CPU work at once in the
# provisioner (default 4; over it, a short wait, then 503 + Retry-After). The per-IP count is kept in the provisioner
# process's memory (`ui.sso_provision._LegCounter`).
SSO_REQUESTS_PER_IP_PER_MIN = _int_env("VIGIL_SSO_REQUESTS_PER_IP_PER_MIN", 300)
SSO_CONCURRENCY = _int_env("VIGIL_SSO_CONCURRENCY", 4)
# ... of which ONE org may hold at most VIGIL_SSO_ORG_CONCURRENCY at once (default 1: its further legs wait in its own
# queue, never in another org's share).
SSO_ORG_CONCURRENCY = _int_env("VIGIL_SSO_ORG_CONCURRENCY", 1)


def apex_impact_enabled() -> bool:
    """True iff the APEX Impact & Closure surfaces are ON (``VIGIL_APEX_IMPACT`` affirmative). OFF by default
    (mirrors ``redpen_enabled``): with it off EVERY APEX impact/closure capability is inert and the server is
    byte-identical to a build without it — the engagement's chaining phase pursues NO impact (it stays pure
    reasoning over the report), the autonomous proof-carrying-remediation close-the-loop is a no-op (status
    ``disabled``, nothing proposed, no PR, no certificate minted), and the continuous retest scheduler runs no
    cadence tick. The master flag over PR-3's three capabilities: chaining-to-demonstrated-impact, autonomous
    PCR (confirmed FACT → gated fix PR → signed NEGATIVE remediation certificate), and continuous prove-clean
    retesting. Read at call time. Even when ON, each leg still fails closed unless its own inputs are provisioned
    (an oracle-confirmed FACT to drive PCR, governance signers to sign the negative cert, a verified authority +
    the m-of-n destruction quorum for the gated PR), so flipping this flag alone grants no new reach — it only
    un-gates machinery that still obeys every FACT-gate, offense-gate and signature check beneath it. Keyless:
    an env flag, never a secret — FATAL-2 clean; the offense plane reads the SAME env var through its own
    ``apex_impact_enabled`` helpers (``framework.v2.apex_impact`` / ``vigil_integration.apex_flags``)."""
    return (os.environ.get("VIGIL_APEX_IMPACT") or "").strip().lower() in _OIDC_AFFIRMATIVE


# A GitHub App slug is the App's URL name (lower alnum + single hyphens): the ONLY form the public install URL
# (`https://github.com/apps/<slug>/installations/new`) accepts — the numeric App id cannot build it. The owner sets
# it when they register the real App (go-live, HANDOFF §6); unset ⇒ the Code screen's Connect GitHub refuses with a
# clean "not set up yet" rather than a dead link. A presence/format accessor only — never a secret (the App PRIVATE
# key lives in `governor.github_app`, env/SSM, call-time read).
_GITHUB_APP_SLUG_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38})")


def github_app_slug() -> str:
    """The customer-facing GitHub App slug (`VIGIL_GITHUB_APP_SLUG`), lower-cased and format-checked, or ""
    when unset/malformed (⇒ Connect GitHub is unavailable and says so). Read at call time."""
    raw = (os.environ.get("VIGIL_GITHUB_APP_SLUG") or "").strip().lower()
    return raw if _GITHUB_APP_SLUG_RE.fullmatch(raw) else ""


def customer_pause_resume_enabled() -> bool:
    """True iff the customer pause/resume launch routes are ON (pause/resume PR-4b). DEFAULT-ON for the hosted
    deployment: UNSET reads ENABLED, and an explicit ``VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED=0`` (or any
    non-affirmative token) forces it OFF byte-identically to the pre-default-on build - off, the edge routes and
    provisioner actions are absent (404) exactly as an unknown route, and NOTHING records or clears a lease pause,
    so the whole PR-1..PR-4a pause substrate stays INERT. Pausing moves NO money (it is money-doctrine-neutral);
    this flag gates only the CUSTOMER-facing ability to record/clear a reversible pause on their own lease."""
    return _default_on_flag("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED")


def customer_live_control_enabled() -> bool:
    """True iff the customer Live Control routes are ON. DEFAULT-ON for the hosted deployment: UNSET reads
    ENABLED, and an explicit ``VIGIL_CUSTOMER_LIVE_CONTROL=0`` (or any non-affirmative token) forces it OFF
    byte-identically to the pre-default-on build - off, the edge route /api/customer/launch/instruct + its
    provisioner action `launch_instruct`, the activity read and the #/live SPA screen are all absent (404 / tab
    hidden) exactly as an unknown route, so the whole mission-steering surface stays INERT. A customer instruction
    is ADVISORY ONLY - it is folded into the running engine's untrusted think context (it fires no tool, relaxes no
    scope, mints no fact); this flag gates only the CUSTOMER-facing ability to enqueue such guidance for THEIR own
    engagement."""
    return _default_on_flag("VIGIL_CUSTOMER_LIVE_CONTROL")


def trial_preview_enabled() -> bool:
    """True iff the free-trial PREVIEW is ON (`VIGIL_TRIAL_PREVIEW_ENABLED` affirmative). OFF by default: sign-up
    grants the legacy trial exactly as before. ON: a sign-up grants the trial under the `trial-preview:<org>` entry
    only when the org, its canonical mailbox and its trial entries are all unclaimed (one trial per org and per
    mailbox), and later slices show that org partial results until it buys credits."""
    return (os.environ.get("VIGIL_TRIAL_PREVIEW_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def signup_founder_tester_enabled() -> bool:
    """True iff the founder role is switched on (`VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED` affirmative). OFF by
    default: both sign-up paths grant `org_admin` exactly as before (billing and members, no testing). ON, together
    with `trial_preview_enabled()`: they grant `founder` (org_admin plus run_engagement and view_assessments), so
    the founder can prove a host it controls and scan it; every launch gate still applies. ON with the preview OFF:
    sign-ups still grant `org_admin` (the founder role needs the rule-bound preview trial). Also the kill switch:
    while it is OFF, an existing founder membership is admitted as `org_admin` (no testing, billing kept), with no
    spine write. Read on each request by the provisioner process (the cockpit) from its own environment, which
    systemd loads from cockpit.env when the service starts: a change applies once the cockpit restarts."""
    return (os.environ.get("VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def trial_ip_limit_enabled() -> bool:
    """True iff the opt-in per-IP soft limit on preview trial grants is ON (`VIGIL_TRIAL_IP_LIMIT_ENABLED`
    affirmative; default OFF)."""
    return (os.environ.get("VIGIL_TRIAL_IP_LIMIT_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def trial_product_id() -> str:
    """The launch product a trial-preview org may run (`VIGIL_TRIAL_PRODUCT_ID`, an offered catalog launch
    product). Owner-set; no default — while it is unset a locked trial org cannot launch at all."""
    return (os.environ.get("VIGIL_TRIAL_PRODUCT_ID") or "").strip()


#: The payment processors VIGIL takes money through, and the DEFAULT one (owner decision 2026-11-16: Stripe;
#: Flutterwave is retained, its development paused).
BILLING_PROVIDERS = ("stripe", "flutterwave")
DEFAULT_BILLING_PROVIDER = "stripe"


def billing_provider() -> "str | None":
    """The ONE answer to "which payment processor" (`VIGIL_BILLING_PROVIDER`, case and surrounding whitespace
    ignored): unset or blank is the DEFAULT, ``"stripe"``; ``"stripe"`` / ``"flutterwave"`` name themselves; anything
    else is None — not configured, and every caller REFUSES (checkout opens nothing; a bare ``billing-drain`` or
    ``ops-sweep tx-refs`` exits 2), never a fall-back to either processor.
    Checkout (``provision._checkout_provider``) and the bare money-IN drain and tx-refs sweep (``cli._billing_lane``)
    all resolve here, so the processor checkout takes payments on and the spool a bare drain credits from agree by
    construction. An explicit ``--provider`` on the drain or the sweep still names its own lane: each drain unit
    pins its own processor's spool (a renewal of a plan sold through Flutterwave must be credited after a switch)."""
    choice = (os.environ.get("VIGIL_BILLING_PROVIDER") or "").strip().lower()
    if not choice:
        return DEFAULT_BILLING_PROVIDER
    return choice if choice in BILLING_PROVIDERS else None


def customer_checkout_enabled() -> bool:
    """True iff the CUSTOMER hosted-checkout action is ON (`VIGIL_CUSTOMER_CHECKOUT_ENABLED` affirmative). OFF by
    default (Front B CHK-1): the edge route and the provisioner action are absent (404) exactly as an unknown route,
    and nothing ever posts to the payment processor. Even when ON, checkout still refuses unless the owner has
    provisioned the processor ``billing_provider()`` resolves (VIGIL_BILLING_PROVIDER unset = Stripe, the default:
    the Stripe adapter opt-in VIGIL_BILLING_ENABLE_STRIPE, VIGIL_STRIPE_WEBHOOK_SECRET, VIGIL_STRIPE_SECRET_KEY and
    VIGIL_STRIPE_API_VERSION; flutterwave: VIGIL_BILLING_WEBHOOK_SECRET + VIGIL_FLW_SECRET_KEY; any other value:
    not configured) — the amount is always the OWNER CATALOG's, and
    credit is granted ONLY by the verified inbound webhook drain, never here."""
    return (os.environ.get("VIGIL_CUSTOMER_CHECKOUT_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_onboarding_enabled() -> bool:
    """True iff the customer app shows the onboarding guide (`VIGIL_CUSTOMER_ONBOARDING` affirmative): a skippable
    click-through tour after a person's first sign-in — on any device, until they finish or skip it (the answer is
    kept server-side, ``ui/onboarding_store.py``, and the edge's ``api/customer/onboarding`` route exists only while
    this is on) — a Guide screen in the top bar (the whole app, end to end) and the VIGIL wordmark brightening and
    dimming while a screen loads.
    OFF by default: the guide walks through flows that must be live first (launching from the app, Red-Pen, the
    monitoring screen). Read when the customer edge starts (it is written into the page), so a change takes effect at
    the edge's next start."""
    return (os.environ.get("VIGIL_CUSTOMER_ONBOARDING") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_security_ui_enabled() -> bool:
    """True iff the customer app shows its account-security screens (`VIGIL_CUSTOMER_SECURITY_UI` affirmative): the
    Account security screen (set up an authenticator app, add a passkey), "Sign in with a passkey" on the sign-in screen
    (also needs `customer_passkey_enabled()`), and the inline "Verify with your authenticator" prompt a sensitive action
    shows when the server asks for a fresh second factor. The screen's status read (the edge's
    ``api/customer/security`` route and the cockpit's ``security_status`` action) exists only while this is on.
    OFF by default: the app is exactly as before. The edge reads it at startup (it is written into the page) and on each
    status request; the cockpit reads it on each request — set the SAME value in customer.env and cockpit.env."""
    return (os.environ.get("VIGIL_CUSTOMER_SECURITY_UI") or "").strip().lower() in _OIDC_AFFIRMATIVE
def customer_launch_ui_enabled() -> bool:
    """True iff customers launch and control assessments from the app (`VIGIL_CUSTOMER_LAUNCH_UI` affirmative; C1a):
    the Assessments screen offers Launch on each verified host (one of the depths the server offers, then
    ``launch/reserve`` and ``launch/start``) and lists the org's launches with the controls the server would accept
    (Start and Cancel before a launch starts; Pause and Resume while it runs, when VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED
    is on too), read from the edge's ``api/customer/launches`` route; the provisioner keeps each lease reserved while
    it is on (``ui/customer_launches.py``) so the app can start or cancel it after a reload.
    DEFAULT-ON for the hosted deployment: UNSET reads ENABLED, and an explicit ``VIGIL_CUSTOMER_LAUNCH_UI=0`` (or any
    non-affirmative token) forces it OFF byte-identically to the pre-default-on build - off, that route and its
    provisioner read are absent (404), nothing is kept, and the Assessments screen is exactly as before. Read by the
    customer edge when it starts (it is written into the page) and by the cockpit on each request."""
    return _default_on_flag("VIGIL_CUSTOMER_LAUNCH_UI")


def customer_retest_ui_enabled() -> bool:
    """True iff customers may RETEST a finding from the app (`VIGIL_CUSTOMER_RETEST_UI` affirmative; C1b): the
    Assessments screen shows a Retest button on each finding, which re-runs THAT finding's proof against the
    customer's verified host (``retest`` → the launch-gate authorization + a confirm-by-re-execution of the
    finding's retained proof); a finding is marked fixed ONLY when its proof stops working, else Still-Vulnerable.
    OFF by default: the edge ``retest`` action and the cockpit ``retest`` dispatch are absent (404, exactly as an
    unknown action), nothing is re-fired and no retest record is written — so the app is byte-identical to a build
    without it. Read by the customer edge when it starts (it is written into the page) and by the cockpit on each
    request, the same way ``customer_launch_ui_enabled`` is."""
    return (os.environ.get("VIGIL_CUSTOMER_RETEST_UI") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_retest_reproof_enabled() -> bool:
    """True iff a customer retest runs the REAL cross-plane LIVE re-proof (`VIGIL_CUSTOMER_RETEST_REPROOF`
    affirmative; C1b completion). Requires `customer_retest_ui_enabled` too (the UI flag gates the action; this
    flag gates whether its re-verifier sends live traffic). When ON, ``provision.retest`` reserves an owner-signed
    credit-launch lease for the one finding, publishes an owner-signed re-proof ticket to the ``retest-reproof``
    seam, bounded-waits the keyless offense worker's inert outcome, and settles the lease (a model-free re-fire
    refunds in full). When OFF (default), the re-verifier is the fail-closed stub (``_retest_reverify`` ->
    ``"unavailable"``): the retest action still exists but honestly refuses as "not available", sending NO traffic
    and reserving NO credit — byte-identical to the merged C1b UI/authz slice. Default-OFF so turning the retest
    UI on never silently starts sending live offense traffic; the live re-proof is a separate, explicit opt-in."""
    return (os.environ.get("VIGIL_CUSTOMER_RETEST_REPROOF") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_connect_enabled() -> bool:
    """True iff the unified customer CONNECT surface is ON (consumer PR-C). DEFAULT-ON for the hosted deployment:
    UNSET reads ENABLED, and an explicit ``VIGIL_CUSTOMER_CONNECT=0`` (or any non-affirmative token) forces it OFF
    byte-identically to the pre-default-on build - off, EVERY connect action is absent (404 exactly as an unknown
    route): the one-screen connect overview, the single-asset ownership poll, and the read-only cloud-grant connect /
    verify / disconnect all refuse, nothing is minted and no cloud grant is recorded, so the server is byte-identical
    to a build without PR-C.

    This flag gates only the one-screen connect site/repo/cloud SURFACE; it never changes how an asset is TESTED.
    CONNECTING RECORDS AN OWNER-VERIFIED ASSET; IT NEVER BY ITSELF AUTHORIZES LIVE OFFENSE: a live customer run
    still rides the UNCHANGED `vigil_core.posture.customer_prod_execution_enabled()` (VIGIL_CUSTOMER_PROD_EXECUTION)
    owner gate PLUS a current host-ownership proof PLUS the owner-signed EngagementAuthority, and a cloud grant is
    READ-ONLY (running cloud posture against it is a separate, separately-gated engagement — not unlocked here).

    The cloud leg has its OWN flag on top of this one (`customer_cloud_connect_enabled`), which stays DEFAULT-OFF:
    the cloud leg never turns on without being explicitly set, even though its master now defaults on. Read at call
    time."""
    return _default_on_flag("VIGIL_CUSTOMER_CONNECT")


def customer_cloud_connect_enabled() -> bool:
    """True iff the connect surface's CLOUD leg is ON: `VIGIL_CUSTOMER_CLOUD_CONNECT` affirmative AND the master
    `customer_connect_enabled()` (the cloud leg is part of the connect surface and can never be on without it).
    OFF by default: the cloud routes are absent (404 exactly as an unknown route), the connect overview carries no
    cloud leg, and no cloud challenge / grant can be recorded.

    Even when ON, connecting an account still fails CLOSED until the owner provisions VIGIL's own read-only AWS
    connector identity (`cloud_connect_fetcher` / `cloud_connect_aws_principal_arn` below) — the identity the
    customer's role trusts. A grant is READ-ONLY and authorizes no offense. Read at call time."""
    if not customer_connect_enabled():
        return False
    return (os.environ.get("VIGIL_CUSTOMER_CLOUD_CONNECT") or "").strip().lower() in _OIDC_AFFIRMATIVE


# Consumer PR-C — the connect surface's durable limiters (their own marker dirs under SIGIL_HOME, never shared with
# the login limiter). CONNECT_CHECK = the per-(org, host) automatic ownership re-check CADENCE; CONNECT_ORG = the
# per-org ceiling on ownership fetches across all hosts; CLOUD_CONNECT = the per-org ceiling on cloud verifications
# (each one is three STS calls under VIGIL's connector identity).
CONNECT_CHECK_RATELIMIT_DIR = _customer / "connect_check_ratelimit"
CONNECT_ORG_RATELIMIT_DIR = _customer / "connect_org_ratelimit"
CLOUD_CONNECT_RATELIMIT_DIR = _customer / "cloud_connect_ratelimit"

# --- AWS STS OUTBOUND egress for the cloud-connect proof (PR-C — SHIPPED OFF BY DEFAULT) -----------------------
# The ONLY host the cloud-connect fetcher (`ui.cloud_fetch`) may reach, enforced BEFORE any socket opens (mirrors
# GITHUB_APP_EGRESS_ALLOWLIST). No endpoint override: the credential-holding egress can only ever reach AWS STS
# (the global endpoint, SigV4 region us-east-1). A customer supplies only a role ARN — a PARAMETER of the signed
# request, never a URL — so the customer can never steer this egress anywhere.
AWS_STS_EGRESS_ALLOWLIST = frozenset({"sts.amazonaws.com"})

# The ONLY host the CLOUDFLARE cloud-connect fetcher (`ui.cloudflare_fetch`) may reach, enforced BEFORE any socket
# opens (mirrors AWS_STS_EGRESS_ALLOWLIST). No endpoint override: the token-bearing egress can only ever reach the
# Cloudflare API. A customer supplies only a bearer token (an Authorization HEADER, never a URL) and the account id;
# the token id placed in a URL path is format-checked (32 hex) first, so the customer can never steer this egress.
CLOUDFLARE_API_EGRESS_ALLOWLIST = frozenset({"api.cloudflare.com"})

# VIGIL's connector principal (an IAM role or user in the aws partition) — the exact `Principal` a customer's
# read-only role trusts. Validated so a malformed value can never be printed into a customer's trust policy.
_AWS_PRINCIPAL_ARN_RE = re.compile(r"arn:aws:iam::[0-9]{12}:(?:role|user)/[A-Za-z0-9+=,.@_/-]{1,512}")


def cloud_connect_aws_principal_arn() -> str:
    """VIGIL's AWS connector principal ARN (`VIGIL_CLOUD_CONNECT_AWS_PRINCIPAL_ARN`), format-checked, or "" when
    unset/malformed (the cloud leg then offers nothing — fail closed, never a trust policy naming a bad principal)."""
    raw = (os.environ.get("VIGIL_CLOUD_CONNECT_AWS_PRINCIPAL_ARN") or "").strip()
    return raw if _AWS_PRINCIPAL_ARN_RE.fullmatch(raw) else ""


def cloud_connect_fetcher():
    """The live AWS cloud-connect fetcher (``ui.cloud_fetch.AwsStsConnectFetcher``: assume the customer's role with
    the issued external id, read the caller identity, and run the same-shape negative control) when the cloud leg is
    ON and the owner has provisioned VIGIL's connector credentials + principal, else None (fail closed: the
    provisioner then offers and verifies nothing). Credentials: `VIGIL_CLOUD_CONNECT_AWS_ACCESS_KEY_ID` +
    `VIGIL_CLOUD_CONNECT_AWS_SECRET_ACCESS_KEY` (+ optional `VIGIL_CLOUD_CONNECT_AWS_SESSION_TOKEN`) — an identity
    whose only permission is `sts:AssumeRole`. Lazily imports the stdlib-only fetcher so `config` stays import-light."""
    if not customer_cloud_connect_enabled() or not cloud_connect_aws_principal_arn():
        return None
    key_id = (os.environ.get("VIGIL_CLOUD_CONNECT_AWS_ACCESS_KEY_ID") or "").strip()
    secret = (os.environ.get("VIGIL_CLOUD_CONNECT_AWS_SECRET_ACCESS_KEY") or "").strip()
    token = (os.environ.get("VIGIL_CLOUD_CONNECT_AWS_SESSION_TOKEN") or "").strip()
    if not key_id or not secret:
        return None
    from .ui.cloud_fetch import AwsStsConnectFetcher
    return AwsStsConnectFetcher(access_key_id=key_id, secret_access_key=secret, session_token=token)


# --- GCP OUTBOUND egress for the cloud-connect proof (PR-C — SHIPPED OFF BY DEFAULT) ---------------------------
# The ONLY hosts the GCP cloud-connect fetcher (`ui.cloud_fetch.GcpImpersonationConnectFetcher`) may reach, enforced
# per-endpoint BEFORE any socket opens (mirrors AWS_STS_EGRESS_ALLOWLIST): the OAuth2 token endpoint (the connector
# SA assertion exchange) and IAM Credentials (generateAccessToken on the challenge-named SA). No endpoint override:
# the credential-holding egress can only ever reach these two Google hosts. The target SA email is VIGIL-COMPUTED
# from the project id + the issued external id (never customer-supplied as a URL), so the customer can never steer
# this egress anywhere.
GCP_EGRESS_ALLOWLIST = frozenset({"oauth2.googleapis.com", "iamcredentials.googleapis.com"})

# VIGIL's connector SERVICE-ACCOUNT email — the member a customer grants roles/iam.serviceAccountTokenCreator on
# their target SA (analog to the AWS connector principal). Validated so a malformed value is never shown to a customer.
_GCP_CONNECTOR_SA_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com")


def cloud_connect_gcp_connector_sa() -> str:
    """VIGIL's GCP connector SA email (`VIGIL_CLOUD_CONNECT_GCP_CONNECTOR_SA`), format-checked, or "" when
    unset/malformed (the GCP leg then offers nothing — fail closed, never placement naming a bad connector SA)."""
    raw = (os.environ.get("VIGIL_CLOUD_CONNECT_GCP_CONNECTOR_SA") or "").strip()
    return raw if _GCP_CONNECTOR_SA_RE.fullmatch(raw) else ""


def cloud_connect_gcp_fetcher():
    """The live GCP cloud-connect fetcher (``ui.cloud_fetch.GcpImpersonationConnectFetcher``: sign the connector SA
    assertion, impersonate the customer's target SA, bind its description to the external id, and run the same-shape
    negative control) when the cloud leg is ON and the owner has provisioned VIGIL's connector SA email + its RSA
    private key, else None (fail closed: the provisioner then offers and verifies nothing for GCP). The private key
    PEM comes from `VIGIL_CLOUD_CONNECT_GCP_PRIVATE_KEY` (the owner-provisioned secret, analog to the AWS secret key).
    Lazily imports the fetcher so `config` stays import-light."""
    if not customer_cloud_connect_enabled() or not cloud_connect_gcp_connector_sa():
        return None
    pem = (os.environ.get("VIGIL_CLOUD_CONNECT_GCP_PRIVATE_KEY") or "").strip()
    if not pem:
        return None
    from .ui.cloud_fetch import GcpImpersonationConnectFetcher
    return GcpImpersonationConnectFetcher(connector_email=cloud_connect_gcp_connector_sa(), private_key_pem=pem)


# --- AZURE OUTBOUND egress for the cloud-connect proof (PR-C — SHIPPED OFF BY DEFAULT) -------------------------
# The ONLY hosts the Azure cloud-connect fetcher (`ui.cloud_fetch.AzureConsentConnectFetcher`) may reach, enforced
# BEFORE any socket opens (mirrors AWS_STS_EGRESS_ALLOWLIST): Microsoft Entra ID (the client-credentials token
# endpoint) and Microsoft Graph (the admin-set external-id binding read). No endpoint override — the credential-
# holding egress can only ever reach these two. A customer supplies only a tenant id + the enterprise-app Object ID
# (PATH segments of host-pinned requests, never a host), so the customer can never steer this egress anywhere.
AZURE_CLOUD_CONNECT_EGRESS_ALLOWLIST = frozenset({"login.microsoftonline.com", "graph.microsoft.com"})

# VIGIL's multi-tenant Azure AD app-registration client id (a GUID) — the tenant-agnostic application a customer's
# Global Admin admin-consents into their tenant (the Azure analog of the AWS connector principal). Validated so a
# malformed value can never be printed into a customer's admin-consent URL.
_AZURE_CLIENT_ID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def cloud_connect_azure_client_id() -> str:
    """VIGIL's Azure connector app (client) id (`VIGIL_CLOUD_CONNECT_AZURE_CLIENT_ID`), format-checked, or "" when
    unset/malformed (the Azure cloud leg then offers nothing — fail closed, never an admin-consent URL naming a bad
    client id)."""
    raw = (os.environ.get("VIGIL_CLOUD_CONNECT_AZURE_CLIENT_ID") or "").strip()
    return raw if _AZURE_CLIENT_ID_RE.fullmatch(raw) else ""


def azure_connect_fetcher():
    """The live Azure cloud-connect fetcher (``ui.cloud_fetch.AzureConsentConnectFetcher``: a client-credentials
    token against the customer's tenant proves admin consent, a Microsoft Graph read confirms the admin-set
    external-id binding, and the same-shape negative control proves the result is tenant-specific) when the cloud leg
    is ON and the owner has provisioned VIGIL's Azure app (client id + a client secret OR a client assertion/cert),
    else None (fail closed: the provisioner then offers and verifies no Azure flow). Credentials:
    `VIGIL_CLOUD_CONNECT_AZURE_CLIENT_SECRET` OR `VIGIL_CLOUD_CONNECT_AZURE_CLIENT_ASSERTION` — an app whose only
    consented permission is a read-only Graph read. Lazily imports the stdlib-only fetcher so `config` stays
    import-light."""
    if not customer_cloud_connect_enabled() or not cloud_connect_azure_client_id():
        return None
    secret = (os.environ.get("VIGIL_CLOUD_CONNECT_AZURE_CLIENT_SECRET") or "").strip()
    assertion = (os.environ.get("VIGIL_CLOUD_CONNECT_AZURE_CLIENT_ASSERTION") or "").strip()
    if not secret and not assertion:
        return None
    from .ui.cloud_fetch import AzureConsentConnectFetcher
    return AzureConsentConnectFetcher(client_id=cloud_connect_azure_client_id(), client_secret=secret,
                                      client_assertion=assertion)


def cloud_connect_cloudflare_fetcher():
    """The live Cloudflare cloud-connect fetcher (``ui.cloudflare_fetch.CloudflareTokenConnectFetcher``: verify the
    customer's read-only API token, read its own definition to bind the challenge and confirm read-only +
    single-account) when the cloud leg is ON, else None (fail closed: the provisioner then offers and verifies
    nothing for Cloudflare). Unlike AWS, VIGIL holds NO Cloudflare credential of its own — the customer's token is
    the only secret and it travels per-verify, read once and never stored — so this fetcher needs no owner-provisioned
    connector identity, only the cloud leg's flag. Lazily imports the stdlib-only fetcher so `config` stays
    import-light."""
    if not customer_cloud_connect_enabled():
        return None
    from .ui.cloudflare_fetch import CloudflareTokenConnectFetcher
    return CloudflareTokenConnectFetcher()


def customer_posture_enabled() -> bool:
    """True iff the customer app's Fix-first screen is on (`VIGIL_CUSTOMER_POSTURE` affirmative; APEX consumer PR-B,
    Area 1's UI half): the 0-100 security posture, its trend over the last twelve weeks, and the worst-first list of
    what to fix first — each open finding's plain-language impact, its standards chips and its exact remediation — read
    from the edge's ``api/customer/posture`` (the cockpit's ``customer_posture`` action) and
    ``api/customer/posture/trend`` (``posture_trend``, which also feeds the Overview's Posture card).

    Effective ONLY together with `presentation_enabled()` (VIGIL_APEX_PRESENTATION): that is the master switch over
    the consumer posture surface and the signed presentation block this screen renders, so this flag on with it off
    is OFF. OFF by default (mirrors `redpen_enabled`): both routes and both cockpit actions are absent (404, exactly
    as an unknown route), the page's ``data-posture`` switch is "0", there is no Fix first tab, ``#/fix-first`` is
    the home screen exactly as an unknown route, and the Overview has no Posture card and makes no posture read — so
    the app is byte-identical to a build without it. Everything shown is a read-only projection of the org's OWN
    oracle-confirmed findings (``ui/customer_posture.py``): it mints nothing, decides no verdict and makes no model
    call. Read by the customer edge when it starts (it is written into the page) and by the edge and the cockpit on
    every request for the routes — set the SAME value in customer.env and cockpit.env."""
    return ((os.environ.get("VIGIL_CUSTOMER_POSTURE") or "").strip().lower() in _OIDC_AFFIRMATIVE
            and presentation_enabled())


def customer_seats_enabled() -> bool:
    """True iff per-workspace member SEAT limits are enforced (``VIGIL_CUSTOMER_SEATS`` affirmative). OFF by
    default: no limit is applied and ``add_member`` / ``grant_member`` behave byte-identically. When ON, a NEW
    member is refused once the workspace already holds ``customer_default_seats()`` members; a role change for
    an existing member consumes no seat and is never limited. A later slice resolves the allowance per plan
    from the owner catalog (mirroring ``monitor_hosts``)."""
    return (os.environ.get("VIGIL_CUSTOMER_SEATS") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_default_seats() -> int:
    """The flat per-workspace member seat allowance enforced while ``customer_seats_enabled()``
    (``VIGIL_CUSTOMER_DEFAULT_SEATS``, default 5). Read live so the owner can tune it at deploy; a later slice
    resolves the allowance per plan from the owner catalog."""
    return _int_env("VIGIL_CUSTOMER_DEFAULT_SEATS", 5)


def customer_team_ui_enabled() -> bool:
    """True iff the customer app's Team screen is on (`VIGIL_CUSTOMER_TEAM_UI` affirmative): the member list (the edge's
    ``GET api/customer/members`` → provision ``members_list``), Add member by the email of an existing VIGIL account
    (``POST api/customer/member/add`` → ``member_add``), and the change-role / remove buttons over the existing
    member/grant and member/revoke routes. OFF by default: both routes and both cockpit actions are absent (404, exactly
    an unknown route) and the Team tab shows the "being wired" card it always showed. Read when the customer edge starts
    for the page (it is written into the page, so a change takes effect at the edge's next start) and on every request
    by the edge and the cockpit for the routes."""
    return (os.environ.get("VIGIL_CUSTOMER_TEAM_UI") or "").strip().lower() in _OIDC_AFFIRMATIVE


# The small set of explicit OFF values for a DEFAULT-ON flag (case-insensitive). Unlike the default-OFF posture flags
# above (enabled only on an affirmative value), a default-ON flag is enabled unless it is explicitly turned off, so an
# unset / empty / unrecognised value leaves it ON.
_CUSTOMER_FLAG_NEGATIVE = frozenset({"0", "false", "no", "off", "disabled"})


def customer_team_invite_enabled() -> bool:
    """True iff the team EMAIL-INVITE flow is on (`VIGIL_CUSTOMER_TEAM_INVITE`). DEFAULT ON (launch posture): the flow
    ships enabled, so an unset / empty / unrecognised value leaves it ON, and ONLY an explicit off value
    (`0`/`false`/`no`/`off`/`disabled`, case-insensitive) turns it off. This is the gate for the invite backend an
    org_admin uses to invite a person who has NO VIGIL account yet: the edge's `POST api/customer/member/invite` ->
    provision `member_invite`, `GET api/customer/member/invites` -> `member_invites_list`,
    `POST api/customer/member/invite/revoke` -> `member_invite_revoke`, and the accept-token path wired into sign-up /
    sign-in (`member_invite_accept`). With it OFF every one of those is absent (404, exactly an unknown route/action)
    and sign-up / sign-in ignore any presented invite token, so the flow is byte-identical to its not existing.

    Distinct from `customer_team_ui_enabled()` (the Team SCREEN -- member list, add an existing account, change role,
    remove -- default OFF, its own PR): turning the Team screen off does not touch the invite backend, and vice versa.
    NON-NEGOTIABLE regardless of this flag: an invite is role-capped to the customer-grantable set, its token is
    single-use and expiring, it is tenant-scoped to the inviting workspace, it is rate-limited per org, and it GRANTS
    NOTHING until it is accepted. Read by the edge and the cockpit on every request, so set the SAME value on both
    sides (a value on one side only still fails closed)."""
    return (os.environ.get("VIGIL_CUSTOMER_TEAM_INVITE") or "").strip().lower() not in _CUSTOMER_FLAG_NEGATIVE


def customer_settings_enabled() -> bool:
    """True iff the customer app shows its settings shell (`VIGIL_CUSTOMER_SETTINGS` affirmative; legal/governance S1):
    the #/settings hub (a General tab that captures the legal-entity / contact profile through
    ``GET/POST api/customer/preferences`` for the SESSION's account only — ``ui/preferences_store.py``, a UI preference
    never on the signed spine) and in-hub links to the existing Account-security, Team (authorized administrators) and
    Billing screens. It adds no new authority or money control. The edge's ``api/customer/preferences`` route and the
    cockpit's ``preferences_get`` / ``preferences_set`` actions exist only while this is on.
    OFF by default: the app is exactly as before (no Settings tab, #/settings is the home screen exactly as any unknown
    route, and no preferences call is made). The edge reads it at startup (it is written into the page) and on each
    request; the cockpit reads it on each request — set the SAME value in customer.env and cockpit.env."""
    return (os.environ.get("VIGIL_CUSTOMER_SETTINGS") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_authorizations_enabled() -> bool:
    """True iff the customer app shows its read-only Authorizations surface (`VIGIL_CUSTOMER_AUTHORIZATIONS`
    affirmative; legal/governance S12): the #/settings/authorizations screen that DISCLOSES to a workspace, read-only,
    the owner-signed EngagementAuthorities on record for its OWN proven-owned hosts — scope, validity window,
    environment and the GET-only / non-destructive flags — plus a "request authorization" action that drops an UNSIGNED
    owner-review request only (it mints NO authority; the owner still signs in the cockpit via ui/target_authorization.py).
    It is a DISCLOSURE of the enforced gate (scope/exclusions R1, expiry R2, out-of-scope/new-host refusal R3), never a
    second enforcement path and never a widening one: the launch gate (`ui/launch_gate._has_verified_authority`) and the
    conjunctive gate chain stay the sole authority and are byte-identical when this is off. The edge's
    ``api/customer/authorizations`` read + ``authorizations/request`` action and the cockpit's
    ``customer_authorizations_list`` / ``customer_authorization_request`` actions exist only while this is on.
    OFF by default: the app is exactly as before (no Authorizations screen, its routes 404, and nothing is read or
    dropped). The edge reads it at startup (it is written into the page) and on each request; the cockpit reads it on
    each request — set the SAME value in customer.env and cockpit.env."""
    return (os.environ.get("VIGIL_CUSTOMER_AUTHORIZATIONS") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_privacy_center_enabled() -> bool:
    """True iff the customer app shows its Privacy centre (`VIGIL_CUSTOMER_PRIVACY_CENTER` affirmative; legal/governance
    S2): a #/privacy screen that SURFACES, for the signed-in customer, the privacy information this deployment has already
    PUBLISHED — the strictly-necessary cookie inventory (``public_site/cookies``), the subprocessor list
    (``public_site/privacy``) and a link to the full privacy policy. It renders the EXISTING canonical text (read from
    the packaged public pages at request time — one source of truth, never a reworded copy) and links out to those
    pages; it adds NO new authority or money control and makes NO mutation (a pure read of published, org-independent
    facts — the same for every workspace). The edge route ``GET api/customer/privacy`` and the cockpit's
    ``privacy_center`` read exist only while this is on. OFF by default: the app is exactly as before (no Privacy tab,
    #/privacy is the home screen exactly as any unknown route, and no privacy read is made). The edge reads it at
    startup (it is written into the page) and on each request; the cockpit reads it on each request — set the SAME value
    in customer.env and cockpit.env."""
    return (os.environ.get("VIGIL_CUSTOMER_PRIVACY_CENTER") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_data_rights_enabled() -> bool:
    """True iff the customer app shows its Data-rights screen (`VIGIL_CUSTOMER_DATA_RIGHTS` affirmative; legal/governance
    S3): a settings sub-screen that states the customer's data rights (access / correction / deletion / export) in the
    EXISTING published words of the Privacy notice and Terms of Service, names the 30-day response SLA
    (``CUSTOMER_DATA_RIGHTS_SLA_DAYS``) and the data-subject contact (``CUSTOMER_DATA_RIGHTS_CONTACT``), lets a customer
    EXPORT their own org's non-secret records (the same tenant-scoped, redacted invoices / usage / findings reads the
    other screens use — no new authority, no mutation), and RECORD a close-account / deletion request (one owner-signed
    append-only row in ``ui/data_rights_store.py``, idempotent per request_id; it does NOT auto-wipe the immutable spine
    — that is the owner-gated hard-prune / VAULT-PRUNE path — and unlocks nothing by itself).
    The edge's ``GET api/customer/data-rights`` + ``GET api/customer/data-rights/export`` + ``POST
    api/customer/data-rights/request`` routes, and the cockpit's ``data_rights_overview`` / ``data_rights_export`` /
    ``data_rights_request`` actions, exist only while this is on. OFF by default: the app is exactly as before (no
    Data-rights link, #/data-rights is the home screen exactly as any unknown route, and no data-rights call is made).
    The edge reads it at startup (it is written into the page) and on each request; the cockpit reads it on each
    request — set the SAME value in customer.env and cockpit.env."""
    return (os.environ.get("VIGIL_CUSTOMER_DATA_RIGHTS") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_ai_governance_enabled() -> bool:
    """True iff the customer app shows its AI / human-in-the-loop GOVERNANCE disclosure (`VIGIL_CUSTOMER_AI_GOVERNANCE`
    affirmative; legal/governance S5): a settings sub-screen (#/ai-governance, linked from the #/settings hub) that
    STATES how VIGIL uses AI and the human oversight around it. It is a pure READ — the statements are SYNTHESISED from
    the published Terms (§11 AI-assisted features, §12 data), the README's governing invariant (the AI only proposes;
    four separate authorities run the system and none is the AI) and the Safety & Authorization briefing (the AI-free
    danger-tier classifier; "AI proposes, the oracle disposes"), each cited on the screen. It adds NO new authority or
    money control, mints nothing and mutates nothing.
    OFF by default: the app is exactly as before (no #/ai-governance link, the route is the home screen exactly as any
    unknown route, and no disclosure call is made). The edge's ``api/customer/ai-governance`` route and the cockpit's
    ``ai_governance_disclosure`` action exist only while this is on. The edge reads it at startup (it is written into the
    page) and on each request; the cockpit reads it on each request — set the SAME value in customer.env and cockpit.env."""
    return (os.environ.get("VIGIL_CUSTOMER_AI_GOVERNANCE") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_seller_identity_enabled() -> bool:
    """True iff the customer app shows its Seller identity screen (`VIGIL_CUSTOMER_SELLER_IDENTITY` affirmative;
    legal/governance S7): the #/seller-identity screen, a READ-ONLY display of the legally-required seller identity of
    the hosted VIGIL service — SIGIL SARL's published legal name, legal form, registered city/country, registration
    number, contact email, website and governing law. The block is a GLOBAL owner-reviewed CODE constant
    (``ui/seller_identity.py``), the SAME trust root as the catalog, served through ``GET api/customer/seller-identity``
    (``seller_identity_get``) — never a per-tenant wire field and never an invented value. It adds no new authority or
    money control: a pure display read, nothing minted, nothing mutated, off the signed spine.
    OFF by default: the app is exactly as before (no Seller identity tab, #/seller-identity is the home screen exactly
    as any unknown route, and no seller-identity call is made). The edge reads it at startup (it is written into the
    page) and on each request; the cockpit reads it on each request — set the SAME value in customer.env and
    cockpit.env."""
    return (os.environ.get("VIGIL_CUSTOMER_SELLER_IDENTITY") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_overview_enabled() -> bool:
    """True iff the customer app's home screen is the fuller Overview (`VIGIL_CUSTOMER_OVERVIEW` affirmative; C7):
    compact summary cards that pull from the SAME session-org-scoped reads the full screens use — credits available
    (billing), verified, expired and awaiting hosts (assets), authorized assessments and their findings (assessments),
    monitoring (monitoring, only while that screen is on) and unread notifications (the bell's read) — each card
    opening its full screen. Every read is the server's own tenant-scoped one (the UI never sends an org id); a card whose read a role
    may not make degrades to an honest line, never an error, and no card ever shows an estimate, a predicted cost or an
    engine name. OFF by default: the home screen is the Account-only dashboard exactly as before (byte-identical). Read
    when the customer edge starts (it is written into the page), so a change takes effect at the edge's next start."""
    return (os.environ.get("VIGIL_CUSTOMER_OVERVIEW") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_billing_dashboard_enabled() -> bool:
    """True iff the customer app shows the fuller Billing dashboard (`VIGIL_CUSTOMER_BILLING_DASHBOARD` affirmative;
    W6 / C5): available credits, credits on hold for running assessments, live consumption per running scan, the
    statement with each charge's rate and balance-after, the published Rates view, the low-balance notice and the
    Auto top-up settings — all over the reads W1/W2c-2 already serve (`billing`, `billing/usage`, `billing/rates`).
    OFF by default: the Billing screen is exactly as before — the Credits / Wallet / Subscription cards and Buy —
    and no extra read is made. Read when the customer edge starts (it is written into the page and counts in the
    build id), so a change takes effect at the edge's next start."""
    return (os.environ.get("VIGIL_CUSTOMER_BILLING_DASHBOARD") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_ios_install_banner_enabled() -> bool:
    """True iff the customer app shows iPhone and iPad visitors a dismissible "Share → Add to Home Screen" banner and
    carries the iOS home-screen tags (`VIGIL_CUSTOMER_IOS_INSTALL_BANNER` affirmative). OFF by default, and it stays
    off until the owner has signed in with Google inside the installed app on a real iPhone: the sign-in binding
    cookie is SameSite=Lax, path-scoped and lasts 600 s, and an app installed from Safari may keep a cookie jar of
    its own. Read when the customer edge starts (it is written into the page), so a change takes effect at the
    edge's next start."""
    return (os.environ.get("VIGIL_CUSTOMER_IOS_INSTALL_BANNER") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_plan_checkout_enabled() -> bool:
    """True iff customers may also check out SUBSCRIPTION plans (`VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED`
    affirmative). Effective only together with the base checkout flag (the edge route is absent without it).
    OFF by default (CHK-1b). A plan checkout subscribes the payer
    to the processor's recurring plan (the catalog price_id IS the payment_plan id); every RENEWAL must then map back
    to the tenant via the tx_ref / meta we set — a sandbox-confirm item. ENABLE ONLY after a sandbox renewal shows
    it attributes. While ON, the billing drain QUARANTINES (alarms on) a verified successful plan charge it cannot
    attribute or price, instead of a silent no-op."""
    return (os.environ.get("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def multi_shard_enabled() -> bool:
    """True iff Front C multi-shard routing + live migration is on (`VIGIL_MULTI_SHARD` affirmative; S2/S3).

    OFF by default — the historical SINGLETON deployment, byte-identical: the routing resolver returns the single
    shared ``CRUCIBLE_ROOT`` for EVERY tenant regardless of any shard-assignment record on the spine (nothing is
    routed, no assignment is consulted), and the live-migration orchestrator refuses to run. ON, the resolver
    directs each tenant to its OWN shard via its owner-signed ``ShardAssignment`` and FAILS CLOSED for an
    unassigned tenant (never defaulted onto a shard), and the migration orchestrator is enabled.

    The actual cross-HOST dispatch + copy and the keyless routing-edge wiring are owner deploy work (this flag
    gates only the in-repo resolution + orchestration code); the production flip stays the OWNER's, after S4 is
    green (HANDOFF §13.1)."""
    return (os.environ.get("VIGIL_MULTI_SHARD") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_fair_queue_enabled() -> bool:
    """True iff consumer PR-F is on (`VIGIL_CUSTOMER_FAIR_QUEUE` affirmative). OFF by default (mirrors
    `redpen_enabled` / `customer_monitoring_enabled`): the job queue claims in arrival order, the launches read shows
    no queue position, a sign-up mints no shard assignment — every surface byte-identical to a build without PR-F.
    Read at call time. The consumer plan named this flag VIGIL_FAIR_QUEUE; it ships under the VIGIL_CUSTOMER_* name
    every consumer-wave flag uses.

    ON, three things change, each wired on its production path:
      * FAIR CLAIM — the engine job queue (`framework.v2.engagement_scheduler.EngagementScheduler.claim_next`, which
        reads this same env var offense-side) claims the oldest job of the tenant with the fewest jobs running, then
        the least recent service (`vigil_core.fair_share`), so one tenant's backlog never starves another's launch.
      * QUEUED — the customer launches read (`ui.customer_launches`) marks a started launch still waiting in that
        queue with how many jobs are claimed before it (a count; never whose).
      * SHARD ON SIGN-UP — with `multi_shard_enabled()` AND an owner `shard_ids()` topology also set, every sign-up
        path owner-signs the new org's shard placement (`Provisioner._place_on_signup`; a tenant NEVER chooses its
        shard). Coupled to THIS flag on purpose: `VIGIL_MULTI_SHARD` alone is Front C's ROUTING switch, whose owner
        places tenants explicitly; an owner who runs that keeps exactly that until they also opt in to automatic
        placement, which writes an owner-signed record per sign-up (see LIMIT-consumer-shard-on-signup-ops).

    Fairness orders work and nothing else: one target is never parallelized (a job whose slug is running waits; the
    slug lease + run gate are untouched), and a queue position mints NO FACT. The elastic we-host fleet the shard ids
    name is owner deploy work, deploy-gated and outside this flag (LIMIT-frontc-shard-cross-host-deploy)."""
    return (os.environ.get("VIGIL_CUSTOMER_FAIR_QUEUE") or "").strip().lower() in _OIDC_AFFIRMATIVE


# A SAFE single shard-id path component — mirrors ``vigil_core.shard_assignment_record._TENANT_RE`` (replicated
# here as a config-time pre-filter, so a malformed owner entry is DROPPED rather than reaching the signer):
# alnum start then [A-Za-z0-9._-], max 64, no separators / ``.``/``..`` traversal / absolute path / NUL.
_SHARD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def shard_ids() -> "tuple[str, ...]":
    """The owner-set shard topology for placement-on-signup (`VIGIL_SHARD_IDS`, a comma-separated list of safe
    shard-id components, e.g. ``shard01,shard02``), de-duplicated with order preserved. EMPTY by default: with no
    topology the provisioner places NOTHING on sign-up (fail-safe — a tenant is never guessed onto a shard, and
    routing then fails closed for it), so even with the flags on, shard-on-signup stays inert until the owner
    names the shards. A malformed entry (not a safe single path component) is DROPPED, so a bad owner value can
    never traverse a path. Standing up the matching cross-HOST fleet is owner deploy work, deploy-gated and outside
    this reader (LIMIT-frontc-shard-cross-host-deploy). Read at call time."""
    raw = (os.environ.get("VIGIL_SHARD_IDS") or "").strip()
    if not raw:
        return ()
    out: "list[str]" = []
    seen: "set[str]" = set()
    for part in raw.split(","):
        c = part.strip()
        if not c or c in seen or not _SHARD_ID_RE.fullmatch(c):
            continue
        seen.add(c)
        out.append(c)
    return tuple(out)


def billing_plan_alarm_enabled() -> bool:
    """Whether the billing drain QUARANTINES (alarms on) an unaccountable paid PLAN charge. ON whenever plan
    checkout is ON, and independently via `VIGIL_BILLING_PLAN_ALARM` — keep it ON for as long as any plan sold
    while checkout was enabled may still RENEW: turning plan SALES off must never silence the alarm on renewals
    that are still being billed (CHK-1b red-pen)."""
    return customer_plan_checkout_enabled() or (
        (os.environ.get("VIGIL_BILLING_PLAN_ALARM") or "").strip().lower() in _OIDC_AFFIRMATIVE)


def billing_topup_alarm_enabled() -> bool:
    """Whether the Flutterwave billing drain QUARANTINES (alarms on) a verified paid TOP-UP it cannot credit at the
    catalog price — a price not in the catalog, no verified currency, or less than / another currency than the
    catalog price — instead of archiving it as a no-op (``VIGIL_BILLING_TOPUP_ALARM`` affirmative; default OFF:
    unchanged). The Stripe drain always alarms. Read by the billing drain process."""
    return (os.environ.get("VIGIL_BILLING_TOPUP_ALARM") or "").strip().lower() in _OIDC_AFFIRMATIVE


def stripe_terms_consent_enabled() -> bool:
    """True iff every Stripe checkout makes the customer ACCEPT the Terms of Service before paying
    (`VIGIL_STRIPE_TERMS_CONSENT` affirmative; default OFF). ON, the session asks Stripe for a required terms checkbox
    (`consent_collection.terms_of_service = required`) whose text is VIGIL's (`custom_text.terms_of_service_acceptance`
    REPLACES Stripe's default agreement text): a link to the Terms and the consumer's request for immediate supply and
    the end of the right of withdrawal once a purchase's credits are used (Terms §8). A session Stripe does not confirm
    with that requirement is refused (fail-closed). Stripe shows the box only when the account's
    Terms of Service URL is set in its public details: set it before turning this on. OFF: the checkout payload is
    byte-identical to before. Read at call time."""
    return (os.environ.get("VIGIL_STRIPE_TERMS_CONSENT") or "").strip().lower() in _OIDC_AFFIRMATIVE


def billing_reversals_enabled() -> bool:
    """W5 — chargebacks, refunds and the billing hold (``VIGIL_BILLING_REVERSALS`` affirmative; default OFF). ON: the
    Stripe drain acts on dispute and refund events (each re-fetched from Stripe) through the owner-signed reversal
    ledger (``governor.billing_reversal``): disputed or refunded credits leave the wallet, a part already spent is
    owed, an org that owes credits is on a billing HOLD (no new launch, no allowance extension) until a top-up repays
    it, and the owner is alerted (``vigil doctor``, ``vigil alerts``). OFF: those events are ignored exactly as before,
    no reversal record is written or read and no launch consults a hold. Read at call time by each process."""
    return (os.environ.get("VIGIL_BILLING_REVERSALS") or "").strip().lower() in _OIDC_AFFIRMATIVE


def low_balance_alert_enabled() -> bool:
    """W5 — the LOW-BALANCE alert (``VIGIL_BILLING_LOW_BALANCE_ALERT`` affirmative; default OFF). ON: an org whose
    available credits fall below max(100, 20% of its last top-up) gets one notification-centre item and one email
    per crossing (re-armed by the next top-up); the cockpit runs the email sweep in the background. It states the
    balance threshold in credits and never an estimate. OFF: no item, no sweep, no email."""
    return (os.environ.get("VIGIL_BILLING_LOW_BALANCE_ALERT") or "").strip().lower() in _OIDC_AFFIRMATIVE


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


def owner_money_view_enabled() -> bool:
    """True iff the O1 OWNER MONEY VIEW is ON (`VIGIL_OWNER_MONEY_VIEW` affirmative). OFF by default (mirrors
    `margin_dashboard_enabled`): with it off the owner-tier `/api/billing/owner-money` read is absent (404
    exactly as an unknown route) and the `sigil owner-money` verb (`vigil sigil owner-money`) is not registered (an
    unknown verb, its handler refusing too), so the surface is byte-identical to a build without O1. The verb is
    registered when the CLI starts, the route is decided per request. This is the OWNER's own money reconciliation —
    rate-card revenue (credits charged) vs the gateway meter's confirmed provider cost, the gross margin between
    them and the at-risk (unconfirmed) spend, folded from the signed spine + the meters. It is an operator surface,
    never a customer one, so it may show
    currency and the owner's target line; it is owner-gated AND fail-closed even when on (an unset target line is
    omitted, never fabricated). This flag only decides whether the surface exists at all (a pure READ projection;
    nothing is ever minted). Read at call time."""
    return (os.environ.get("VIGIL_OWNER_MONEY_VIEW") or "").strip().lower() in _OIDC_AFFIRMATIVE


def tiered_products_enabled() -> bool:
    """True iff the EC-7 tiered Quick/Deep LAUNCH PRODUCTS are offered (`VIGIL_TIERED_PRODUCTS` affirmative).
    OFF by default: `catalog.launch_products()` returns `()` and the existing pricing surface (plans() /
    expected_amounts() / entitlements()) is byte-identical to pre-EC-7 — a launch product is a NEW offering,
    not a change to any existing one. A launch's run tier is DERIVED from its signed units_reserved either way
    (no new signed field); this flag decides whether the Quick/Deep products are LISTED/OFFERED (the run tier
    is applied by the engage worker when on). Wiring a customer's product choice into the credit reservation
    is a follow-on — until then a launch reserves the default units (the base 'quick' tier)."""
    return (os.environ.get("VIGIL_TIERED_PRODUCTS") or "").strip().lower() in _OIDC_AFFIRMATIVE


def max_depth_enabled() -> bool:
    """L1 — True iff the **Max** assessment DEPTH is OFFERED as a launch product (``VIGIL_MAX_DEPTH`` affirmative).
    OFF by default: ``catalog.launch_products()`` offers only Quick/Deep (byte-identical to EC-7), so a customer
    cannot SELECT Max until the owner enables it, and ``provision.launch_reserve`` denies the Max product id. Max
    on a LIVE system runs under the L1 controls — one rate limit per engagement and governed tools only (pricing
    design §6) — which the ENGINE enforces for ANY ``max``-depth run (keyed on the owner-signed lease depth, not
    this flag); this flag only gates whether Max can be CHOSEN. Mirrors ``tiered_products_enabled`` (Max is only
    offered when the tiered-products launch surface is also on)."""
    return (os.environ.get("VIGIL_MAX_DEPTH") or "").strip().lower() in _OIDC_AFFIRMATIVE


def _seam_base() -> str:
    from vigil_core.seam_base import resolve_seam_base
    return resolve_seam_base()


def seam_migration_guard_enabled() -> bool:
    """``VIGIL_SEAM_MIGRATION_GUARD`` — refuse to serve, settle, sweep with ``--apply``, arm an eval grant or provision
    a monitoring secret while a former seam directory of this host holds launch-seam records the seam lacks (until
    ``sigil seam migrate --apply`` commits them). DEFAULT OFF in code; the shipped ``sigil-cockpit.service`` and
    ``vigil-settle-drain.service`` set it to 1, so the seam move and the guard always arrive together. When this
    environment does not set it, a guarded verb follows the configured seam units' value (``cli._seam_guard_on``)."""
    return (os.environ.get("VIGIL_SEAM_MIGRATION_GUARD") or "").strip().lower() in _OIDC_AFFIRMATIVE


def monitoring_publish_dir() -> Path:
    """Where owner-signed monitoring authorities are published for the KEYLESS AEGIS gateway (AE-2 reads,
    verify-only). `VIGIL_MONITORING_PUBLISH_DIR` overrides; default under the live data dir
    (`VIGIL_BASE_DIR`, else `.vigil-live`). Only signed public artifacts land here — never private material."""
    from vigil_core.aegis_seam import (
        AEGIS_SEAM_SUBDIR,
        MONITORING_AUTHORITY_SUBDIR,
        MONITORING_PUBLISH_DIR_ENV,
    )
    override = (os.environ.get(MONITORING_PUBLISH_DIR_ENV) or "").strip()
    if override:
        return Path(override)
    return Path(_seam_base()) / AEGIS_SEAM_SUBDIR / MONITORING_AUTHORITY_SUBDIR


def monitoring_secrets_dir() -> Path:
    """Where the sovereign keeps the per-(org, host) AEGIS-SaaS monitoring REPORT secrets (AE-6). These are
    shared HMAC secrets (one copy goes to that tenant's managed gateway as a 0600 file); never published.
    `VIGIL_MONITORING_SECRETS_DIR` overrides; default under the live data dir."""
    from vigil_core.aegis_seam import (
        AEGIS_SEAM_SUBDIR,
        MONITORING_SECRETS_DIR_ENV,
        REPORT_SECRETS_SUBDIR,
    )
    override = (os.environ.get(MONITORING_SECRETS_DIR_ENV) or "").strip()
    if override:
        return Path(override)
    return Path(_seam_base()) / AEGIS_SEAM_SUBDIR / REPORT_SECRETS_SUBDIR


def _bool_env(name: str, default: bool = False) -> bool:
    """A strict, fail-closed boolean env read: only the affirmative tokens below (case-insensitive) are True;
    anything else — including a typo — is the default. Used for opt-in DEV escape hatches that must never
    turn on by accident."""
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _default_on_flag(name: str) -> bool:
    """A DEFAULT-ON feature-flag read for the consumer surfaces that ship ENABLED for the hosted deployment
    while KEEPING an explicit operator override to force OFF. An UNSET env var reads ENABLED; a SET value is
    parsed EXACTLY as the opt-in readers parse it (``_OIDC_AFFIRMATIVE`` ⇒ on, any other token ⇒ off). So
    forcing the feature OFF (``VIGIL_...=0`` / ``false`` / ``no`` / ``off`` / ``""`` / any non-affirmative token)
    returns ``False`` BYTE-IDENTICALLY to the pre-default-on reader - the only behaviour that changes is the
    UNSET case flipping from off to on. The explicit-OFF path is unchanged, so every flag-off golden stays green
    once it forces the override instead of relying on the old unset-is-off default."""
    raw = os.environ.get(name)
    if raw is None:
        return True
    return raw.strip().lower() in _OIDC_AFFIRMATIVE


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

    It gates ONLY: the decision-record append; the sweeps' finish paths for a recorded settle (``ops_sweeps``); the
    settle drain's pass that finishes every recorded settle of a lease still on the seam
    (``ops_sweeps.finish_interrupted_settles`` — it only rolls forward a recorded decision); the spine check of an
    earlier launch in ``_earlier_launch_in_flight``; and the spine check in ``pause_launch``. Settle evidence already on the spine (a refund grant, a postpaid settle) is honoured either
    way. OWNER DECISION OD-4: set it IDENTICALLY for every process that settles — the cockpit, the customer
    server, the settle-drain and ``ops-sweep`` — or a process with it off settles without a record its crash
    could be finished from.

    W2c-1: it does NOT gate an EXACT (v3) decision record. A metered charge (``settle_launch(consumed_mc=...)``)
    records its decision whatever this says — the record is the only place the org's sub-credit remainder moves — so
    with it off a metered charge still appends exactly one record; flat, cancel and refund settles are unchanged.
    The finish paths above stay gated, so `vigil doctor` reports metered billing with this off as a hard issue."""
    return (os.environ.get("VIGIL_SETTLE_SPINE_RECORD") or "").strip().lower() in _OIDC_AFFIRMATIVE


def lease_plan_split_enabled() -> bool:
    """True iff a prepaid launch lease records, under the owner signature, the plan/wallet split its reserve
    debited (``plan_reserved`` and ``plan_period_end``), so its settle restores each bucket from the lease itself,
    whatever the live spine window still holds of the reserve records. OFF by default (``VIGIL_LEASE_PLAN_SPLIT``
    unset / non-affirmative): leases are minted exactly as before, byte-identical. Read by the process that reserves
    (the cockpit's provisioner). Turn it on only once the offense plane runs a build that accepts these optional
    lease fields: an older verifier refuses a lease that carries them (the launch does not run, and its reservation
    is refunded like any launch that never started). Resolved at call time."""
    return (os.environ.get("VIGIL_LEASE_PLAN_SPLIT") or "").strip().lower() in _OIDC_AFFIRMATIVE


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
    lease per slug, so the second would replace the first, whose reservation only `ops-sweep reservations` then
    settles). Both checks run under
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


def pruned_restore_enabled() -> bool:
    """True iff a backup / restore handles a HARD-PRUNED spine as one verified unit (``SIGIL_PRUNED_RESTORE``
    affirmative): the backup captures the spine, its head, the floor and the archive as one consistent set and
    verifies it before writing (manifest schema 4, ``prune_unit``); a restore stages that set, verifies it in a child
    process scoped to the staged home and only then swaps it in. OFF by default (unset / non-affirmative): a backup
    is written exactly as before, and a restore of a backup holding a hard-pruned spine is refused before anything
    is written. Read at call time."""
    return (os.environ.get("SIGIL_PRUNED_RESTORE") or "").strip().lower() in _OIDC_AFFIRMATIVE


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


def customer_email_code_enabled() -> bool:
    """True iff the sign-up and password-reset emails also carry a 6-digit code (`VIGIL_CUSTOMER_EMAIL_CODE`
    affirmative), so a person in the installed app can type it instead of following the email into a browser. OFF by
    default: the emails carry only the token, exactly as before, and a code confirmation is refused. Read by the
    customer provisioner (the cockpit process). A code is bound to the email and the purpose, used once, lives 10
    minutes, and is gone after 5 wrong codes; wrong codes are also limited per email across re-sent codes and per
    client IP. The token in the same email keeps working."""
    return (os.environ.get("VIGIL_CUSTOMER_EMAIL_CODE") or "").strip().lower() in _OIDC_AFFIRMATIVE


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
    """True iff self-serve asset-ownership verification is enabled. DEFAULT-ON for the hosted deployment: UNSET
    reads ENABLED (the SSRF-hardened ownership fetcher is armed so customers can prove a domain), and an explicit
    ``VIGIL_OWNERSHIP_VERIFY=0`` (or any non-affirmative token) forces it OFF byte-identically to the pre-default-on
    build - off, the sovereign plane makes NO outbound fetch to a customer-named host and target_verify fail-closed."""
    return _default_on_flag("VIGIL_OWNERSHIP_VERIFY")


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
# The explicit-OFF values for a DEFAULT-ON flag (`customer_knowledge_enabled`): unset, blank or anything that is not one
# of these keeps a default-on feature ON, and only an explicit off turns it off. The inverse-polarity complement of the
# default-off `_OIDC_AFFIRMATIVE` predicates, for the lone consumer flag the owner ships on by default.
_FLAG_EXPLICIT_OFF = frozenset({"0", "false", "no", "off", "disabled"})


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
    rebuilds from the spine. Read at call time (tests toggle it), but a running process keeps the caches it built and
    the environment it started with: to turn the cache off in production, change the setting AND restart the process."""
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


def billing_auto_topup_enabled() -> bool:
    """True iff AUTO TOP-UP is wired (`VIGIL_BILLING_AUTO_TOPUP` affirmative; A1). OFF by default — with it unset
    the Stripe adapter does not handle `payment_intent.succeeded` (byte-identical webhook behaviour), a checkout
    never asks Stripe to save the card (the checkout payload is byte-identical), the saved-method capture hook is
    never wired, and the `auto-topup-run` sweep refuses. Even ON, a charge fires only for an org whose owner-signed
    auto-top-up settings are `enabled`, only up to the org's monthly cap, and CREDIT is minted solely by the
    verified webhook drain — never by the off-session charge call. Read at call time."""
    return (os.environ.get("VIGIL_BILLING_AUTO_TOPUP") or "").strip().lower() in _OIDC_AFFIRMATIVE


def model_gateway_enabled() -> bool:
    """True iff the cockpit starts the sovereign model gateway (`sigil.model_gateway`) at boot
    (`VIGIL_MODEL_GATEWAY_ENABLED` affirmative). OFF by default: nothing listens."""
    return (os.environ.get("VIGIL_MODEL_GATEWAY_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def gateway_g1_enabled() -> bool:
    """True iff the model gateway runs at SCALE (PRICING G1; design §5.2): capacity sized from the provider's live
    rate-limit response headers, a per-tenant fair share, a pool of provider accounts with health checks and
    failover, and the loss alarm (`sigil.gateway_capacity`, `sigil.gateway_loss`). OFF by default
    (`VIGIL_GATEWAY_G1` unset): the gateway reads no rate-limit headers, builds no pool, runs no health thread and no
    loss ledger, and the account protections are the stand-in semaphores (`VIGIL_GATEWAY_TENANT_CONCURRENCY` /
    `VIGIL_GATEWAY_GLOBAL_CONCURRENCY`) exactly as before — byte-identical. Read when the gateway is built; a change
    takes effect when the cockpit restarts."""
    return (os.environ.get("VIGIL_GATEWAY_G1") or "").strip().lower() in _OIDC_AFFIRMATIVE


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


def assistant_model() -> str:
    """The model the customer security assistant (PR-J) answers with (`VIGIL_ASSISTANT_MODEL`, default = `run_model`).
    Server-side only — the model identifier is NEVER shown to a customer (design: a customer sees advice, not a
    provider/model name). The assistant's grant names this model and the gateway refuses any other for that grant; it
    must be a model the price table can price, so an unset/blank value falls back to the priced `run_model`."""
    raw = (os.environ.get("VIGIL_ASSISTANT_MODEL") or "").strip()
    return raw or run_model()


def assistant_max_tokens() -> int:
    """The max output tokens one assistant turn may generate (`VIGIL_ASSISTANT_MAX_TOKENS`, default 1024). A bound on
    the turn's cost and length; a junk/out-of-range value falls back to the default. The gateway lowers it further to
    fit the grant's cap, so this is a ceiling, never a spend promise."""
    raw = (os.environ.get("VIGIL_ASSISTANT_MAX_TOKENS") or "").strip()
    try:
        n = int(raw) if raw else 1024
    except ValueError:
        return 1024
    return n if 1 <= n <= 8192 else 1024


def assistant_cap_nano_usd() -> int:
    """The technical ceiling on what ONE assistant turn's model requests may cost VIGIL (`VIGIL_ASSISTANT_CAP_NANO_USD`,
    default 500_000_000 = $0.50). The grant's cap (a leaked token can never spend past it); the gateway reserves every
    request against it before forwarding. A junk/out-of-range value falls back to the default."""
    raw = (os.environ.get("VIGIL_ASSISTANT_CAP_NANO_USD") or "").strip()
    try:
        n = int(raw) if raw else 500_000_000
    except ValueError:
        return 500_000_000
    return n if 0 < n <= 10 ** 12 else 500_000_000


def assistant_finding_limit() -> int:
    """The most oracle-confirmed findings one assistant turn grounds on (`VIGIL_ASSISTANT_FINDING_LIMIT`, default 50).
    Newest-first (the assessments projection's order); a bound on the prompt's input size. Junk/out-of-range → default."""
    raw = (os.environ.get("VIGIL_ASSISTANT_FINDING_LIMIT") or "").strip()
    try:
        n = int(raw) if raw else 50
    except ValueError:
        return 50
    return n if 1 <= n <= 200 else 50


def customer_knowledge_max_doc_bytes() -> int:
    """The largest single document a customer may upload into their knowledge corpus
    (`VIGIL_CUSTOMER_KNOWLEDGE_MAX_DOC_BYTES`, default 1 MiB). A hard cap enforced server-side before any chunk /
    embed / spine write, so one upload can never exhaust the corpus. Junk/out-of-range falls back to the default."""
    raw = (os.environ.get("VIGIL_CUSTOMER_KNOWLEDGE_MAX_DOC_BYTES") or "").strip()
    try:
        n = int(raw) if raw else 1024 * 1024
    except ValueError:
        return 1024 * 1024
    return n if 1 <= n <= 32 * 1024 * 1024 else 1024 * 1024


def customer_knowledge_max_docs_per_org() -> int:
    """The most distinct documents one org's knowledge corpus may hold (`VIGIL_CUSTOMER_KNOWLEDGE_MAX_DOCS`, default
    200). A per-org ceiling checked before each ingest (fail-closed: at the cap a new filename is refused), so a tenant
    can never grow an unbounded corpus. Junk/out-of-range falls back to the default."""
    raw = (os.environ.get("VIGIL_CUSTOMER_KNOWLEDGE_MAX_DOCS") or "").strip()
    try:
        n = int(raw) if raw else 200
    except ValueError:
        return 200
    return n if 1 <= n <= 10_000 else 200


def customer_knowledge_query_limit() -> int:
    """The most document chunks one assistant turn (or one `customer_knowledge_query`) grounds on
    (`VIGIL_CUSTOMER_KNOWLEDGE_QUERY_LIMIT`, default 6). A bound on the document context size the grounded prompt
    carries, additive to `assistant_finding_limit` (which bounds findings). Junk/out-of-range falls back to default."""
    raw = (os.environ.get("VIGIL_CUSTOMER_KNOWLEDGE_QUERY_LIMIT") or "").strip()
    try:
        n = int(raw) if raw else 6
    except ValueError:
        return 6
    return n if 1 <= n <= 50 else 6


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


# --- GitHub App OUTBOUND egress (Red-Pen R2 — SHIPPED OFF BY DEFAULT) --------------------
# The outbound host allowlist for the customer-facing GitHub App API calls in `governor.github_app_egress`
# (App-JWT -> installation-token exchange, repository list, check-run write), enforced BEFORE any socket opens
# (mirrors STRIPE_EGRESS_ALLOWLIST above). Gated DEFAULT-OFF on the master flag `redpen_enabled()` AND on the App
# credentials (`VIGIL_GITHUB_APP_ID` + `VIGIL_GITHUB_APP_PRIVATE_KEY`/SSM): unset ⇒ nothing is wired and no GitHub
# egress exists. There is no API-base override, so the credential-holding egress can only ever reach this host.
GITHUB_APP_EGRESS_ALLOWLIST = frozenset({"api.github.com"})


# --- Customer Notifications & integrations OUTBOUND egress (PR-D — SHIPPED OFF BY DEFAULT) --------------
# The OWNER-REVIEWED outbound host allowlist for delivering an oracle-minted FACT finding to a tenant's out-of-band
# channels — Slack / Discord / a generic customer webhook — enforced by `governor.notify_channels.guard_outbound_url`
# BEFORE any socket opens (mirrors GITHUB_APP_EGRESS_ALLOWLIST above). A tenant SUPPLIES a webhook URL, but it can
# only ever reach a host the OWNER has reviewed here (exact host, or an allowed suffix) AND that resolves ENTIRELY to
# PUBLIC addresses — so a tenant can never steer the delivery egress at an internal / loopback / cloud-metadata
# (169.254.169.254) host (the SSRF class). Gated DEFAULT-OFF on `customer_notify_enabled()`: unset ⇒ nothing is
# wired and no notify egress exists. A generic customer webhook host the owner has reviewed is added here (exact).
NOTIFY_WEBHOOK_HOST_ALLOWLIST = frozenset({"hooks.slack.com"})
# Suffixes the owner has reviewed for providers that mint many sender hosts; a host is allowed iff it EQUALS a
# member above OR ends with ("." + a member here) — ".discord.com" admits discord.com's own webhook host without
# admitting a look-alike like `discord.com.evil.test` (that ends with `.evil.test`, never `.discord.com`).
NOTIFY_WEBHOOK_HOST_ALLOWLIST_SUFFIXES = frozenset({"discord.com", "discordapp.com"})
# The issue-tracker API hosts the sync may reach (exact host). A customer's self-hosted Jira host is NOT here by
# default — the owner adds the specific host after review; this is the OWNER's allowlist, never a tenant free-form.
NOTIFY_ISSUE_API_ALLOWLIST = frozenset({
    "api.github.com",            # GitHub issues REST
    "api.atlassian.com",         # Jira Cloud REST (api.atlassian.com/ex/jira/{cloudid})
    "api.linear.app",            # Linear GraphQL
})


def customer_oidc_enabled() -> bool:
    """True iff customer Google-OIDC login is ON (`VIGIL_CUSTOMER_OIDC_ENABLED` ∈ {1,true,yes,on,enabled}).
    OFF by default and INDEPENDENT of the operator `SIGIL_OIDC_ENABLED`. When OFF the edge's
    /api/customer/oidc/* routes are not served and the provisioner builds no OIDC provider (no egress)."""
    return (os.environ.get("VIGIL_CUSTOMER_OIDC_ENABLED") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_oidc_handoff_enabled() -> bool:
    """True iff Google sign-in may complete inside an INSTALLED customer app through the app hand-off
    (`VIGIL_CUSTOMER_OIDC_HANDOFF` affirmative; ui/oidc_handoff.py). OFF by default. Read by the customer edge only,
    and only together with `customer_oidc_enabled()`: with it on, an app running standalone (added to a Home Screen)
    starts Google sign-in with a hand-off challenge, the edge shows a pairing code where the Google sign-in
    finished, and the app redeems verifier + code for its session. With it off, the edge refuses a hand-off login
    and the installed app uses the browser flow (which on an iPhone lands the session outside the app). Read when
    the edge starts (it is written into the page) and on each hand-off request."""
    return (os.environ.get("VIGIL_CUSTOMER_OIDC_HANDOFF") or "").strip().lower() in _OIDC_AFFIRMATIVE


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


def _provider_key_source() -> str:
    from .provider_key import key_source
    return key_source()


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
        # Where the model gateway's provider key comes from ("ssm" | "env" | ""), and the SSM parameter NAME when
        # it is SSM (sigil.provider_key: SSM is then the only source). Never the key itself.
        "MODEL_PROVIDER_SOURCE": _provider_key_source(),
        "MODEL_PROVIDER_SSM_PARAMETER": (os.environ.get("VIGIL_ANTHROPIC_KEY_SSM_PARAMETER") or "").strip(),
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


def apex_oob_enabled() -> bool:
    """True iff APEX PR-2 OOB-First confirmation is ON (`VIGIL_APEX_OOB` affirmative). OFF by default
    (mirrors `redpen_enabled`): with it off the one genuinely-new OOB class — blind SSTI — is absent from the
    effective out-of-band re-drive set, so the autonomous router/feeder/arm never route a `blind_ssti`
    candidate to the out-of-band confirmation seam and such a claim stays a LEAD, byte-identical to a build
    without APEX OOB. The already-merged out-of-band classes (ssrf / xxe / blind_xxe / rce / command_injection
    / deserialization / oob_sqli) are UNAFFECTED by this flag — they ship on the standing VF-2b collector path.
    Read at call time. The offense/integration plane reads the SAME `VIGIL_APEX_OOB` env var directly
    (``runtime_redrive.apex_oob_enabled`) — it may not import this sovereign module (FATAL-2); this function is
    the sovereign-side convenience + the canonical place the flag is documented. Even ON, a blind-SSTI OOB
    FACT still requires the full collector provisioning (an owner-pinned collector pubkey + the deployment
    collector private key + a verified owner-signed authority), exactly like every other out-of-band class."""
    return (os.environ.get("VIGIL_APEX_OOB") or "").strip().lower() in _OIDC_AFFIRMATIVE


# ---- consumer PR-G (Area 6): the Plans screen + plan change, the report export, the compliance view ----------
# Each capability is default-OFF and read at CALL time (mirrors `redpen_enabled`): with a flag off its edge routes and
# cockpit actions are absent (404 exactly as an unknown route), the page writes "0" for it, and nothing else changes.
PLAN_CHANGE_DIR = _customer / "plan_change"             # owner-signed scheduled plan-change records (display only)
REPORT_RATELIMIT_DIR = _customer / "report_ratelimit"   # the per-org/per-requester report-export limiter's markers


def customer_plans_enabled() -> bool:
    """True iff the customer Plans screen is ON (`VIGIL_CUSTOMER_PLANS` affirmative). OFF by default: the
    ``api/customer/billing/plans`` read and its ``billing_plans`` cockpit action are absent (404 exactly as an unknown
    route) and the page writes data-plans="0" (no tab). ON, the screen compares the OWNER CATALOG's credit plans (price,
    credits per period, period) with the trial and pay-as-you-go, marks the workspace's current plan and offers the
    one-click upgrade through the EXISTING hosted checkout (which still needs VIGIL_CUSTOMER_CHECKOUT_ENABLED +
    VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED). A pure read: it mints nothing and never decides money."""
    return (os.environ.get("VIGIL_CUSTOMER_PLANS") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_plan_change_enabled() -> bool:
    """True iff a customer may CHANGE or CANCEL their credit plan self-serve (`VIGIL_CUSTOMER_PLAN_CHANGE`
    affirmative). OFF by default: the ``api/customer/billing/plan-change`` route and its ``billing_plan_change`` action
    are absent (404). Effective only together with the Plans screen and the base + plan checkout flags. ON, a change is
    scheduled on the processor's subscription to take effect AT THE NEXT RENEWAL (no mid-period charge or refund — the
    renewal invoice is then exactly the new catalog price, which the EXISTING verified webhook drain credits through the
    EXISTING owner catalog); a cancel ends the plan at the end of the period it already paid for. Stripe only."""
    return (os.environ.get("VIGIL_CUSTOMER_PLAN_CHANGE") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_report_export_enabled() -> bool:
    """True iff the shareable assessment REPORT export is ON (`VIGIL_CUSTOMER_PDF_REPORT` affirmative). OFF by default:
    the ``api/customer/report`` / ``api/customer/report/pdf`` reads and their cockpit actions are absent (404) and the
    page writes data-report-export="0". ON, a member who may read assessments downloads a deterministic, self-contained
    HTML report of the workspace's PROVEN findings (no script, no external reference, every value escaped); the PDF of
    the same report additionally needs the owner's renderer (`report_pdf_renderer`), and fails closed without it."""
    return (os.environ.get("VIGIL_CUSTOMER_PDF_REPORT") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_compliance_map_enabled() -> bool:
    """True iff the customer COMPLIANCE view is ON (`VIGIL_CUSTOMER_COMPLIANCE_MAP` affirmative). OFF by default: the
    ``api/customer/compliance`` read and its ``compliance_view`` action are absent (404) and the page writes
    data-compliance="0". ON, the OWASP Top 10 / PCI DSS / SOC 2 controls the workspace's PROVEN findings implicate are
    rolled up per framework — it never states that a control is met, covered or compliant."""
    return (os.environ.get("VIGIL_CUSTOMER_COMPLIANCE_MAP") or "").strip().lower() in _OIDC_AFFIRMATIVE


def report_pdf_renderer() -> str:
    """The owner/ops-provisioned HTML→PDF renderer (`VIGIL_REPORT_PDF_RENDERER`): the ABSOLUTE path of an executable
    that reads the report's HTML on stdin and writes a PDF to stdout. It must live OUTSIDE the customer venv (a headless
    renderer is an ops-layer dependency, never a sovereign one). Unset (the default) = no PDF: the PDF export refuses
    and the HTML report stays available. Read at call time."""
    return (os.environ.get("VIGIL_REPORT_PDF_RENDERER") or "").strip()


def customer_proof_badge_enabled() -> bool:
    """True iff the customer PROOF BADGE + per-finding PCF export (consumer PR-I, Area 8) are ON
    (`VIGIL_CUSTOMER_PROOF_BADGE` affirmative). OFF by default (mirrors `redpen_enabled`): with it off the edge
    download route (``/api/customer/assessments/proof``) and the ``proof_export`` cockpit action are absent (404
    exactly as an unknown route), the findings read carries NO ``proof`` overlay, the page's
    ``__VIGIL_PROOF_BADGE__`` switch is "0" and the public site's ``/verify`` explainer is absent — so the server is
    byte-identical to a build without the feature. A PURE sovereign projection of already-signed data: it mints no
    FACT, touches no target and makes no model call. Read at call time."""
    return (os.environ.get("VIGIL_CUSTOMER_PROOF_BADGE") or "").strip().lower() in _OIDC_AFFIRMATIVE


def customer_proof_delegation_paths() -> "tuple[Path, ...]":
    """The owner-signed OFFENSE-GOVERNANCE delegation certs (`VIGIL_CUSTOMER_PROOF_DELEGATIONS`: ABSOLUTE paths
    separated by ``os.pathsep``) the proof badge derives its governance trust root(s) from — normally the same file
    the finding drain admits findings under (``VIGIL_FINDING_GOV_DELEGATION``), plus the previous one(s) during a
    governance-key rotation. A relative / unexpanded (``%``) entry is dropped (fail-closed: it can never resolve to
    a different file than the operator meant). Each listed cert is still verified at use against the CURRENT owner
    key, its role, the finding's engagement scope and the CURRENT clock (an expired delegation vouches for
    nothing), so this list can only ever narrow what verifies, never widen it. Empty → no finding is badged and no
    proof bundle is produced. Read at call time."""
    raw = os.environ.get("VIGIL_CUSTOMER_PROOF_DELEGATIONS") or ""
    out: "list[Path]" = []
    for part in raw.split(os.pathsep):
        v = part.strip()
        if not v or "%" in v or not Path(v).is_absolute():
            continue
        out.append(Path(v))
    return tuple(out)


def proof_published_fingerprints() -> "tuple[str, ...]":
    """The governance trust-root fingerprints VIGIL PUBLISHES for auditors (`VIGIL_PROOF_PUBLISHED_FINGERPRINTS`:
    ``sha256:<64 lowercase hex>`` values separated by commas and/or whitespace). The public ``/verify`` explainer
    prints them (the out-of-band channel an auditor pins from), and, when the list is non-empty, the proof export
    refuses a bundle whose trust root is not on it — so a customer is never handed a badge an auditor could not
    re-check against the published pin. A malformed entry is dropped (never "fixed up"). Read at call time."""
    import re as _re
    raw = os.environ.get("VIGIL_PROOF_PUBLISHED_FINGERPRINTS") or ""
    seen: "list[str]" = []
    for tok in _re.split(r"[\s,]+", raw.strip()):
        if _re.fullmatch(r"sha256:[0-9a-f]{64}", tok) and tok not in seen:
            seen.append(tok)
    return tuple(seen)
