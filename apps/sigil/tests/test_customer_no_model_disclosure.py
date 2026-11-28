"""STRICT PRODUCT RULE — a CONSUMER never chooses, and never sees, an AI model.

In the consumer SaaS app the AI model is a HIDDEN engine detail. A customer must NEVER
choose a model and must NEVER see an AI-model name or an AI-provider / model-host name
ANYWHERE — not in the single-page app bundle it downloads, not in an assistant reply, not
in a report / export it downloads, not in a notification it receives. The vendored agentic
engine is shown to customers as "NYX" (ui.js DISPLAY_RENAMES); its real identifiers and the
underlying model/provider stay server-side.

This is the PERMANENT regression guard for that rule. It fails if anyone later lets a model
or provider name reach a consumer-visible surface. Three layers:

  1. The STATIC customer_app bundle carries no AI-model / AI-provider NAME, and no model-TYPE
     label a customer could read ("AI model", "language model", ...).
  2. The operator console's shared-kit model-picker CSS classes are never INSTANTIATED in
     consumer JavaScript / HTML (a customer must never be shown a model picker).
  3. Representative consumer-visible BACKEND outputs — an assistant reply dict, a customer
     report/export, a customer notification render — carry no model/provider identifier,
     because each is projected through a field allowlist. This reuses the notify_channels
     shared checker (``_assert_no_model_identifier`` / ``_MODEL_ID_TOKENS``).

WHY NAMES, NOT THE BARE WORD "model":
  The consumer bundle legitimately carries guardrail COMMENTS that say "no model name is
  shown" / "model-free command interpreter", and the shared UI kit (packages/vigil-ui,
  pinned byte-identical to customer_app/components.css by test_customer_kit_copies.py)
  carries an INERT "model picker" / "model/effort strip" CSS comment whose classes
  (.chat-sysctl / .chat-toolrow / .chat-model-note) are LIVE only in the OPERATOR console
  (packages/vigil-ui/app.js) — where the sovereign operator configures their OWN engine, an
  audience that is OUT OF SCOPE for this rule. None of those comments discloses a model or a
  provider. So this guard scans for actual model/provider NAMES + model-TYPE labels (layer 1)
  and for the picker classes being USED in consumer code (layer 2) — never the bare word
  "model".

ALLOWLIST (kept as narrow as possible — see _ALLOWLIST_NOTES):
  * Cloud-infrastructure providers (AWS / GCP / Azure / Cloudflare) are legitimate,
    customer-facing cloud vendors (cloud-connect) and are NOT in the token set. "Azure
    OpenAI" is still caught, via the "openai" token.
  * The Trust-Center / Privacy-centre "Subprocessors" disclosure names Anthropic (Claude API)
    as a data subprocessor. That is a compliance/GDPR disclosure the user owns; it lives in
    public_site/privacy (served separately and fetched at runtime by the Privacy centre),
    NOT in the static customer_app bundle. This test scans the static bundle only, which is
    free of it — so no allowlist entry is needed, and baking that text into the static bundle
    would (correctly) trip layer 1 for the user to review.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from sigil.governor import notify_channels as nc
from sigil.ui import assistant
from sigil.ui import report_export as rx

_CUSTOMER_APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"

# ---- the forbidden token set ------------------------------------------------------------------------------------
# AI-model family names, AI-provider / model-host names, versiony model ids, and model-TYPE labels a customer could
# SEE. Case-insensitive; word-boundaried to avoid benign collisions. A match anywhere a customer reaches is a leak.
_NAME_PATTERNS = (
    # provider / model-host names
    r"\banthropic\b",
    r"\bopenai\b",                 # also catches "Azure OpenAI"
    r"\bchatgpt\b",
    r"\bcohere\b",
    r"\bmistral\b",                # Mistral AI
    r"\bollama\b",
    r"\bbedrock\b",                # AWS Bedrock — a MODEL host (distinct from AWS the cloud, which is allowed)
    r"\bvertex\s+ai\b",            # Google Vertex AI — a MODEL host (distinct from bare geometry "vertex")
    # model family names
    r"\bclaude\b",
    r"\bgemini\b",
    r"\bllama\b",
    r"\bopus\b",
    r"\bsonnet\b",
    r"\bhaiku\b",
    r"\bgpt\b",
    r"gpt-?\d",                    # gpt-4 / gpt4 / gpt-4o
    # versiony model ids, e.g. claude-opus-4-8, gemini-1.5, llama-3
    r"\b(?:claude|gemini|llama|mistral|gpt)[-\s]?\d",
    # model-TYPE labels a customer could read
    r"\b(?:ai|language|large\s+language|foundation|engine)\s+model\b",
    r"\bmodel[_-]id\b",
)
_NAME_RE = tuple(re.compile(p, re.I) for p in _NAME_PATTERNS)

# The operator console's shared-kit model-picker classes. The CSS is DEFINED in the byte-identical kit copy
# (components.css) and LIVE only in the operator console; it must never be INSTANTIATED in consumer code.
_PICKER_CLASSES = ("chat-sysctl", "chat-toolrow", "chat-model-note")

# Text files a customer actually downloads with the app (skip binary png/ico/wav).
_TEXT_SUFFIXES = {".js", ".css", ".html", ".svg", ".webmanifest"}
# Consumer code that can INSTANTIATE UI (where a picker would be wired up). CSS can only DEFINE inert styles.
_CODE_SUFFIXES = {".js", ".html"}

_ALLOWLIST_NOTES = """cloud providers (aws/gcp/azure/cloudflare) are intentionally not tokens; the Anthropic/Claude \
API subprocessor disclosure lives in public_site/privacy, not the static bundle, and is the user's compliance \
decision."""


def _hits(text: str) -> list[str]:
    """Every forbidden model/provider pattern that matches ``text`` (the patterns, for a readable failure)."""
    return [p.pattern for p in _NAME_RE if p.search(text)]


def _bundle_files() -> list[Path]:
    files = sorted(p for p in _CUSTOMER_APP.rglob("*") if p.is_file() and p.suffix.lower() in _TEXT_SUFFIXES)
    assert files, f"no customer_app bundle files found under {_CUSTOMER_APP}"
    return files


# ---- layer 1: the static bundle names no model / provider -------------------------------------------------------
def test_customer_app_bundle_names_no_model_or_provider():
    """Scan every text file a customer downloads with the app for any AI-model / AI-provider NAME or model-TYPE
    label. A hit means a model name leaked into the consumer surface — fail with the exact file:line and token."""
    leaks: list[str] = []
    for path in _bundle_files():
        rel = path.relative_to(_CUSTOMER_APP)
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for pat in _hits(line):
                leaks.append(f"{rel}:{n}: token /{pat}/  ->  {line.strip()[:160]}")
    assert not leaks, (
        "AI model/provider name on a CONSUMER-visible surface (the model is a hidden engine detail). "
        f"Allowlist notes: {_ALLOWLIST_NOTES}\n" + "\n".join(leaks)
    )


# ---- layer 2: no model PICKER is wired into consumer code -------------------------------------------------------
def test_consumer_code_never_instantiates_a_model_picker():
    """The operator console's model-picker classes (styled by the shared kit CSS) must never be USED in consumer
    JS/HTML — a customer must never be shown a picker that chooses the engine/model. The CSS *definition* in
    components.css is fine (inert; byte-identical to the operator kit); this asserts it is never instantiated."""
    used: list[str] = []
    for path in sorted(p for p in _CUSTOMER_APP.rglob("*") if p.is_file() and p.suffix.lower() in _CODE_SUFFIXES):
        rel = path.relative_to(_CUSTOMER_APP)
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for cls in _PICKER_CLASSES:
                if cls in line:
                    used.append(f"{rel}:{n}: uses .{cls}  ->  {line.strip()[:160]}")
    assert not used, (
        "consumer code instantiates an operator model-picker class — the consumer app must not let a customer "
        "choose a model:\n" + "\n".join(used)
    )


# ---- layer 3: consumer-visible BACKEND outputs carry no model identifier -----------------------------------------
def test_customer_notification_render_carries_no_model_identifier():
    """A customer notification is projected through notify_channels' inert-field allowlist, so a model id carried
    on a finding record can never reach a channel. Inject model tokens into NON-allowlisted fields and prove the
    rendered notice drops them; also run the shared checker to prove it stays clean."""
    row = {
        "finding_ref": "f1", "bug_class": "sqli", "surface": "https://x/f1", "severity": "high",
        "title": "SQL injection on login", "summary": "a demo finding", "engagement_slug": "acme",
        # model identifiers smuggled onto the record (none of these is an allowlisted notice field):
        "model_id": "claude-opus-4-8", "ai_provider": "Anthropic", "engine": "bedrock/claude-sonnet-5",
    }
    notice = nc.render_finding_notice(row)
    rendered = notice.subject + "\n" + notice.body + "\n" + json.dumps(notice.fields)
    assert not _hits(rendered), f"a customer notification leaked a model identifier: {_hits(rendered)}"
    # reuse the shared, allowlist-aware checker (it would raise on a leak):
    nc._assert_no_model_identifier(notice.subject, notice.body, *notice.fields.values())


def test_assistant_reply_dict_carries_no_model_and_keeps_the_model_server_side():
    """The assistant reply the route returns (AssistantReply.as_dict) is ADVICE: it carries the answer text and
    honest provenance only — never the model id, never a provider, never a 'model' key. The model id lives ONLY in
    the request body sent to the loopback gateway (request framing), never in what the customer gets back."""
    reply = assistant.AssistantReply(
        answer="Patch the SQL injection on the login form and add a prepared-statement test.",
        grounded_in=["f1"], finding_count=1,
    ).as_dict()
    assert "model" not in reply and "provider" not in reply, f"reply dict exposes model/provider: {sorted(reply)}"
    # the non-free-text structure of the reply carries no model/provider token:
    structural = {k: v for k, v in reply.items() if k != "answer"}
    assert not _hits(json.dumps(structural)), f"reply structure leaks a model identifier: {reply}"

    # the boundary: the request framing DOES carry the model id (internal, to the gateway) ...
    body = assistant.build_request([{"finding_ref": "f1", "title": "SQL injection"}], "How do I fix f1?",
                                   org_id="acme", model="claude-opus-4-8", max_tokens=256)
    assert "model" in body and body["model"] == "claude-opus-4-8"
    # ... but it NEVER appears in what the customer receives:
    assert "model" not in reply


def test_customer_report_export_redacts_any_model_identifier():
    """A customer-downloadable report is projected through the REPORT_FIELDS allowlist, so a model id carried on a
    finding can never reach the exported HTML. Prove it at the pure-redaction seam and end-to-end through
    build_report."""
    # pure seam: _redact drops any non-allowlisted field (where a model id would ride):
    redacted = rx._redact({
        "finding_ref": "f1", "title": "SQL injection on login", "severity": "high", "bug_class": "sqli",
        "summary": "a demo finding",
        "model_id": "claude-opus-4-8", "provider": "anthropic", "engine_model": "gpt-4o",
    })
    assert not _hits(json.dumps(redacted)), f"the report redaction leaked a model identifier: {redacted}"

    # end-to-end: a finding whose record smuggles model fields still exports a model-free report.
    from sigil.governor.identity import ensure_owner_keypair
    from test_compliance_rollup import _finding, _member, _prov, _prove, _store  # shared Area-6 fixtures

    store = _store()
    p = _prov(store, ensure_owner_keypair(), now=1000.0)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    _finding(store, slug, "f1", bug_class="sqli", severity="critical", title="SQL injection on login",
             model_id="claude-opus-4-8", ai_provider="Anthropic", engine="bedrock/claude-sonnet-5")
    report = rx.build_report(store, "acme", now=1000.0, org_name="Acme")
    assert report["findings_total"] == 1          # the finding IS in the report ...
    assert not _hits(report["html"]), f"the exported report leaked a model identifier: {_hits(report['html'])}"


# ---- the guard stays consistent with the notify_channels shared checker ------------------------------------------
def test_scanner_is_a_superset_of_the_notify_channels_token_list():
    """This guard and notify_channels._MODEL_ID_TOKENS must not drift: every notify model-id token is something
    this scanner would also flag, so a string that notify refuses is a string this guard refuses too."""
    missed = [tok for tok in nc._MODEL_ID_TOKENS if not _hits(f"left {tok} right")]
    assert not missed, f"notify_channels tokens this guard would miss (keep them in sync): {missed}"
