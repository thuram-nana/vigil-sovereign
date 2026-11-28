"""Customer outbound DevSecOps INTEGRATIONS — the Slack / Jira / Linear delivery layer, richer than a bare webhook.

READ-ONLY CONSUMER of the oracle-minted finding spine (the OUTBOUND twin of ``issue_sync``, one tier up). When a
finding is CONFIRMED (an oracle-minted ``kind="finding"`` FACT) or an engagement reaches a milestone, this layer
DELIVERS it to a tenant's configured DevSecOps destinations: a Slack message (incoming-webhook or chat.postMessage),
a Jira issue (REST v3 create), or a Linear issue (GraphQL ``issueCreate``). GitLab / Bitbucket are a documented seam
(:data:`PROVIDER_GITLAB` / :data:`PROVIDER_BITBUCKET`): add an adapter behind the same :class:`IntegrationSink`
contract and an owner-reviewed host to ``config.CUSTOMER_INTEGRATION_API_ALLOWLIST``.

WHAT MAKES THIS RICHER THAN A HOSTED-PLATFORM PUSH — every delivery carries VIGIL's advantage, the SIGNED,
INDEPENDENTLY-REPLAYABLE EVIDENCE CERTIFICATE reference (:class:`EvidenceReference`): the recipient gets the finding's
``cert_digest`` (the canonical digest of the m-of-n-signed certificate — the handle ``ui.proof_export.export_for_org``
hands out the downloadable proof bundle by), its ``engagement_slug`` and ``oracle_context_digest``, and a line that
tells them they can VERIFY the finding offline, not merely read a claim. Deliveries are IDEMPOTENT (keyed by the
finding identity + binding — a retry never opens a duplicate issue) and recorded in an owner-signed, append-only
DELIVERY LEDGER (auditable: who was told what, when, with which proof).

LOAD-BEARING INVARIANTS (a false-green here is a real breach):

  * DEFAULT-OFF, strict, fail-closed. The whole layer is gated on ``config.customer_integrations_enabled()``
    (``VIGIL_CUSTOMER_INTEGRATIONS``). OFF ⇒ INERT: no binding is read or written, no sealed secret is opened, no
    socket opens, no issue is created, no ledger record is appended.
  * NEVER A FACT SOURCE. This module only READS inert finding records and SENDS bytes to a provider; it appends ONLY
    its own ``governor.customer_integration`` (bindings) and ``governor.customer_integration_delivery`` (ledger)
    governance records — NEVER a ``kind="finding"`` / FACT record. A notice can never become a finding.
  * CREDENTIAL CUSTODY. A provider token / webhook URL rides SEALED (owner-vault ``seal_secret``, base64) INSIDE the
    owner-signed binding record — NEVER plaintext on the spine, NEVER in a delivery BODY, NEVER logged. At delivery it
    is opened only to stamp the provider's AUTH HEADER. A delivery whose secret cannot be opened (vault locked) does
    NOT go (fail-closed).
  * EGRESS GATE. The sole egress is :mod:`integration_egress`, which routes every URL through the ONE sovereign
    outbound gate (``notify_channels.guard_outbound_url``: https-only + no userinfo + default port + owner-reviewed
    host allowlist + every resolved address PUBLIC) with redirects BLOCKED. A tenant can never steer a delivery at an
    internal / metadata host, nor relay the credential through a 3xx.
  * MONEY-SAFE. An adapter only ever CREATES (posts a message / opens an issue). It never charges, launches,
    remediates, deletes or transitions anything — the create-only surface is the whole surface.
  * NO MODEL IDENTIFIER. Content reuses ``notify_channels.render_finding_notice`` (the inert-field allowlist + the
    no-model-identifier backstop); the backstop is re-run over the appended evidence lines.
  * TENANT ISOLATION. Bindings and ledger records are keyed per ``org_id`` and folded per-org, so one tenant can
    neither read, trigger nor overwrite another's integrations or deliveries.

FATAL-2: SOVEREIGN-only (``assert_no_offense`` at import); stdlib + ``vigil_core`` (the canonical digest only) +
sovereign siblings (``config``, ``notify_channels``, ``integration_egress``, ``authn``, ``identity``,
``key_history``, ``asset_ownership`` id validator, ``platform.vault``). Never imports engine/crucible or ``strix``.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core.canonical import digest_payload  # noqa: E402  (cert_digest == the proof-bundle handle)

from .. import config  # noqa: E402
from . import integration_egress as _egress  # noqa: E402
from . import key_history as _kh  # noqa: E402
from . import notify_channels as _nc  # noqa: E402  (render + the no-model-id backstop + the OutboundRefused type)
from .asset_ownership import _check_org_id  # noqa: E402  (ONE tenant-id validator, shared)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

# ---- providers -----------------------------------------------------------------------------------------------
PROVIDER_SLACK = "slack"
PROVIDER_JIRA = "jira"
PROVIDER_LINEAR = "linear"
# Documented SEAM — not yet delivered. Add an adapter behind IntegrationSink + an owner-reviewed host to
# config.CUSTOMER_INTEGRATION_API_ALLOWLIST, then move the constant into _DELIVERABLE below.
PROVIDER_GITLAB = "gitlab"
PROVIDER_BITBUCKET = "bitbucket"
_DELIVERABLE = frozenset({PROVIDER_SLACK, PROVIDER_JIRA, PROVIDER_LINEAR})
_SEAM = frozenset({PROVIDER_GITLAB, PROVIDER_BITBUCKET})
_PROVIDERS = _DELIVERABLE | _SEAM

# Slack delivery modes.
SLACK_WEBHOOK = "webhook"          # the sealed secret IS the hooks.slack.com incoming-webhook URL
SLACK_POSTMESSAGE = "postmessage"  # the sealed secret is a bot token; slack_channel is the (non-secret) destination
_SLACK_MODES = frozenset({SLACK_WEBHOOK, SLACK_POSTMESSAGE})

# Severity routing ladder (which confirmed findings reach a binding). A finding delivers to a binding iff
# rank(finding.severity) >= rank(binding.min_severity). Unknown finding severity ranks at the bottom (info);
# unknown binding min_severity defaults to "high" (conservative — a mis-set binding is quieter, never louder).
_SEVERITY_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}
_DEFAULT_MIN_SEVERITY = "high"

# Outcome kinds (the orchestrator's return + the ledger).
OUTCOME_DELIVERED = "delivered"
OUTCOME_SKIPPED_DUPLICATE = "skipped_duplicate"   # idempotency: already delivered to this binding
OUTCOME_REFUSED = "refused"                        # fail-closed (locked vault, egress refusal, provider error)

# Owner-vault AEAD context — binds a sealed integration secret to its purpose so it can never be opened as, or
# swapped for, another sealed secret.
_SECRET_CONTEXT = b"sigil/customer-integration-secret"

_BINDING_SIGNAL = "governor.customer_integration"
_LEDGER_SIGNAL = "governor.customer_integration_delivery"

# The owner-signed binding core (FIXED order; absent destination fields canonicalize as ""). The sealed secret is
# INSIDE it, so a tenant can neither lift a routing threshold, re-aim a destination, nor swap the sealed credential
# without a FRESH owner signature.
_BINDING_CORE = ("signal", "org_id", "binding_id", "provider", "state", "min_severity", "mode",
                 "slack_channel", "jira_cloud_id", "jira_project_key", "jira_user_email", "linear_team_id",
                 "sealed_secret", "issued_at")
# The owner-signed ledger core (append-only; one record per delivered/refused attempt).
_LEDGER_CORE = ("signal", "org_id", "binding_id", "provider", "engagement_slug", "finding_ref",
                "oracle_context_digest", "cert_digest", "outcome", "issue_ref", "issued_at")

_BINDING_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SLACK_CHANNEL_RE = re.compile(r"^[A-Za-z0-9#_-]{1,80}$")
_JIRA_CLOUD_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_JIRA_PROJECT_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,30}$")
_JIRA_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}$")
_LINEAR_TEAM_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


class IntegrationRefused(RuntimeError):
    """A fail-closed integration refusal (flag off, a non-FACT input, a bad binding, a locked vault, an egress
    refusal). Its message NEVER contains a credential."""


# ==============================================================================================================
# 1. The evidence-certificate reference — VIGIL's advantage, on every delivery
# ==============================================================================================================
@dataclass(frozen=True)
class EvidenceReference:
    """The signed, independently-replayable evidence-certificate reference carried by every finding delivery. These
    are the exact handles a recipient needs to VERIFY the finding without a VIGIL account: ``engagement_slug`` +
    ``cert_digest`` name the proof bundle ``ui.proof_export.export_for_org`` hands out; ``oracle_context_digest`` is
    the digest of the evidence the oracle judged; ``finding_ref`` is the finding's reference. All are inert digests /
    slugs / refs — never a model identifier, a secret or raw evidence."""

    finding_ref: str
    engagement_slug: str
    oracle_context_digest: str
    cert_digest: str

    @property
    def present(self) -> bool:
        """True iff a verifiable certificate digest is attached (a confirmed finding), vs a bare engagement event."""
        return bool(self.cert_digest)

    def lines(self) -> "list[str]":
        """The human-readable evidence block appended to every finding delivery — the 'verify, don't trust' note."""
        if not self.present:
            return []
        return [
            "— Signed evidence certificate (verify this finding yourself, no VIGIL account needed) —",
            f"Certificate digest: {self.cert_digest}",
            f"Engagement: {self.engagement_slug}",
            f"Oracle evidence digest: {self.oracle_context_digest}",
            ("Download the proof bundle for this finding from your VIGIL workspace (Findings → this finding → "
             "\"Download proof\") and run the shipped verifier offline; pin VIGIL's governance fingerprint from its "
             "public /verify page."),
        ]

    def as_json(self) -> "dict[str, str]":
        return {"finding_ref": self.finding_ref, "engagement_slug": self.engagement_slug,
                "oracle_context_digest": self.oracle_context_digest, "cert_digest": self.cert_digest}


def _cert_digest(certificate: Any) -> str:
    """The canonical digest of a signed finding certificate (the proof-bundle handle), or "" if none was supplied.
    Byte-identical to ``ui.proof_export.build_bundle``'s ``cert_digest`` and the standalone verifier's."""
    if not isinstance(certificate, dict) or not certificate:
        return ""
    try:
        return str(digest_payload(certificate))
    except Exception:  # noqa: BLE001 — a malformed cert contributes no digest, never a crash
        return ""


def evidence_reference(finding_row: "dict[str, Any]", certificate: Any = None) -> EvidenceReference:
    """Build the :class:`EvidenceReference` for a confirmed finding row. ``cert_digest`` is computed from the SIGNED
    ``certificate`` when the caller supplies it (the drain reads it beside the inert row); absent a certificate it
    falls back to a ``cert_digest`` field already on the row, else "" (a milestone / legacy row carries no proof)."""
    row = finding_row if isinstance(finding_row, dict) else {}
    digest = _cert_digest(certificate) or str(row.get("cert_digest") or "")
    return EvidenceReference(
        finding_ref=str(row.get("finding_ref") or ""),
        engagement_slug=str(row.get("engagement_slug") or ""),
        oracle_context_digest=str(row.get("oracle_context_digest") or ""),
        cert_digest=digest)


# ==============================================================================================================
# 2. The provider-agnostic delivery (what a sink formats + sends) and the FACT gate
# ==============================================================================================================
def finding_identity(row: "dict[str, Any]") -> "tuple[str, str, str]":
    """``(engagement_slug, finding_ref, oracle_context_digest)`` — the identity a delivery is keyed by for
    idempotency. Mirrors ``ui.assessments.finding_identity`` / ``issue_sync.finding_identity`` (defined locally to
    keep governor below ui)."""
    return (str(row.get("engagement_slug") or ""), str(row.get("finding_ref") or ""),
            str(row.get("oracle_context_digest") or ""))


class NotAConfirmedFinding(IntegrationRefused):
    """Raised when something that is NOT an oracle-minted CONFIRMED (FACT) finding is handed to the delivery path (a
    notice, a LEAD, a malformed row). A notification can never become an integration delivery."""


def _require_confirmed_finding(row: Any) -> "tuple[str, str, str]":
    """Return a FACT finding's identity, or raise :class:`NotAConfirmedFinding`. A confirmed finding is the inert
    projection of a ``kind="finding"`` record: a dict with a non-empty ``engagement_slug`` AND ``finding_ref`` (the
    signed marks of an oracle mint). Fail-closed before any egress."""
    if not isinstance(row, dict):
        raise NotAConfirmedFinding("integration delivery requires a finding record, not " + type(row).__name__)
    slug, ref, digest = finding_identity(row)
    if not slug or not ref:
        raise NotAConfirmedFinding(
            "refusing a non-FACT input to integration delivery (no signed engagement_slug + finding_ref) — a "
            "notice/LEAD can never become a Slack/Jira/Linear delivery; only an oracle-minted finding may")
    return (slug, ref, digest)


@dataclass(frozen=True)
class Delivery:
    """The provider-agnostic content of ONE delivery, built once and formatted by each sink. ``title`` + ``body``
    come from the inert-field + no-model-id notice renderer; ``evidence`` is the verifiable certificate reference;
    ``labels`` are stable tags. ``is_milestone`` marks an engagement event (no certificate, Slack-only)."""

    title: str
    body: str
    evidence: EvidenceReference
    labels: "tuple[str, ...]" = ()
    is_milestone: bool = False

    def text_body(self) -> str:
        """The plain-text body + the appended evidence block — the shape Slack-webhook / Jira / Linear all render."""
        lines = [self.body]
        ev = self.evidence.lines()
        if ev:
            lines.append("")
            lines.extend(ev)
        return "\n".join(lines)


def build_finding_delivery(finding_row: "dict[str, Any]", evidence: EvidenceReference) -> Delivery:
    """The :class:`Delivery` for ONE confirmed finding — title/body/labels via ``notify_channels`` (the inert-field
    allowlist + the no-model-identifier backstop), plus the evidence reference. The backstop is re-run over the
    appended evidence lines (digests/slugs only, but author-controlled hint text is covered). PURE."""
    _require_confirmed_finding(finding_row)
    notice = _nc.render_finding_notice(finding_row)
    sev = notice.fields.get("severity", "")
    labels = ["vigil-finding"]
    if sev:
        labels.append(f"severity:{sev}")
    bug = notice.fields.get("bug_class")
    if bug:
        labels.append(f"class:{bug}")
    delivery = Delivery(title=notice.subject, body=notice.body, evidence=evidence, labels=tuple(labels))
    _nc._assert_no_model_identifier(delivery.title, delivery.text_body())   # backstop over the FULL rendered text
    return delivery


def build_milestone_delivery(*, title: str, body: str, engagement_slug: str = "") -> Delivery:
    """The :class:`Delivery` for an engagement MILESTONE (e.g. "assessment complete"). Carries NO certificate (a
    milestone is not a single FACT), so it is NOTIFICATION-ONLY: the orchestrator delivers it to Slack bindings
    only and never opens a Jira/Linear issue (money-safe; a milestone must never mint an issue claiming a proof it
    does not carry). The no-model-identifier backstop still runs."""
    ev = EvidenceReference(finding_ref="", engagement_slug=str(engagement_slug or ""),
                           oracle_context_digest="", cert_digest="")
    delivery = Delivery(title=str(title or "VIGIL engagement update"), body=str(body or ""), evidence=ev,
                        labels=("vigil-engagement",), is_milestone=True)
    _nc._assert_no_model_identifier(delivery.title, delivery.text_body())
    return delivery


# ==============================================================================================================
# 3. The sink contract + the three adapters (+ the GitLab/Bitbucket seam)
# ==============================================================================================================
@dataclass(frozen=True)
class DeliveredRef:
    """What a sink returns on a successful create: the provider's own reference (a Slack ``ts``, a Jira issue key, a
    Linear identifier) and, where the provider gives one, a URL. Never a credential."""

    issue_ref: str
    url: str = ""


class IntegrationSink:
    """The provider-agnostic outbound sink contract. One adapter per provider, each ``deliver``-ing a
    :class:`Delivery` for a confirmed finding (or, for Slack, an engagement milestone) to a tenant's
    :class:`IntegrationBinding`, authenticated by the binding's OPENED sealed secret, through the shared egress gate.

    An adapter MUST: (a) build a create-only payload that REFERENCES the evidence certificate; (b) put the credential
    in the AUTH HEADER only (never the body/url/log), except a Slack incoming-webhook whose URL *is* the secret;
    (c) go through :mod:`integration_egress` (so the SSRF/allowlist gate + redirect block run). It MUST NOT delete,
    transition, pay or remediate."""

    provider: str = ""

    def deliver(self, delivery: Delivery, binding: "IntegrationBinding", *, secret: str,
                resolver=None, transport=None) -> DeliveredRef:   # pragma: no cover - interface
        raise NotImplementedError


def _slack_blocks(delivery: Delivery) -> "list[dict[str, Any]]":
    """Slack Block Kit sections for a delivery — a header + the body + the evidence block as mrkdwn."""
    blocks: "list[dict[str, Any]]" = [
        {"type": "header", "text": {"type": "plain_text", "text": delivery.title[:150], "emoji": False}},
        {"type": "section", "text": {"type": "mrkdwn", "text": delivery.body[:2900]}},
    ]
    ev = delivery.evidence.lines()
    if ev:
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(ev)[:2900]}})
    return blocks


class SlackSink(IntegrationSink):
    """Slack delivery — incoming-webhook (``SLACK_WEBHOOK``: the sealed secret is the ``hooks.slack.com`` URL, no
    header) or ``chat.postMessage`` (``SLACK_POSTMESSAGE``: the sealed secret is a bot token sent as
    ``Authorization: Bearer``, posting to the binding's non-secret ``slack_channel``). Both carry the evidence block.
    Create-only (post a message)."""

    provider = PROVIDER_SLACK
    _API_POSTMESSAGE = "https://slack.com/api/chat.postMessage"

    def deliver(self, delivery: Delivery, binding: "IntegrationBinding", *, secret: str,
                resolver=None, transport=None) -> DeliveredRef:
        blocks = _slack_blocks(delivery)
        text = delivery.title                      # fallback/summary line for notifications
        if binding.mode == SLACK_WEBHOOK:
            # The webhook URL IS the secret; guard it against hooks.slack.com and POST the message (no auth header).
            res = _egress.post_json(secret, body={"text": text, "blocks": blocks}, auth=None,
                                    allow_hosts=frozenset({"hooks.slack.com"}), resolver=resolver,
                                    transport=transport)
            if not res.ok:
                raise IntegrationRefused(f"Slack webhook delivery returned HTTP {res.status}")
            return DeliveredRef(issue_ref="webhook")
        # chat.postMessage: bot token in Authorization: Bearer; channel is the non-secret destination.
        body = {"channel": binding.slack_channel, "text": text, "blocks": blocks}
        res = _egress.post_json(self._API_POSTMESSAGE, body=body, auth=("Authorization", f"Bearer {secret}"),
                                allow_hosts=frozenset({"slack.com"}), resolver=resolver, transport=transport)
        payload = res.json if isinstance(res.json, dict) else {}
        if not res.ok or not payload.get("ok"):
            # Slack returns 200 with {"ok": false, "error": "..."} — the error is provider metadata, not a secret.
            err = str(payload.get("error") or res.status)
            raise IntegrationRefused(f"Slack chat.postMessage was not accepted ({err})")
        return DeliveredRef(issue_ref=str(payload.get("ts") or ""))


def _jira_adf(delivery: Delivery) -> "dict[str, Any]":
    """A minimal Atlassian Document Format description — one paragraph per body line (body + evidence block)."""
    paras = [{"type": "paragraph", "content": [{"type": "text", "text": line}]} if line
             else {"type": "paragraph", "content": []}
             for line in delivery.text_body().split("\n")]
    return {"type": "doc", "version": 1, "content": paras}


class JiraSink(IntegrationSink):
    """Jira Cloud issue create (REST v3) — ``POST https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue`` with
    HTTP Basic ``email:api_token`` (the api_token is the sealed secret; the email is the binding's non-secret
    identity). The description is ADF carrying the evidence block. Create-only (open an issue; never transition it)."""

    provider = PROVIDER_JIRA

    def deliver(self, delivery: Delivery, binding: "IntegrationBinding", *, secret: str,
                resolver=None, transport=None) -> DeliveredRef:
        url = f"https://api.atlassian.com/ex/jira/{binding.jira_cloud_id}/rest/api/3/issue"
        fields: "dict[str, Any]" = {
            "project": {"key": binding.jira_project_key},
            "summary": delivery.title[:250],
            "description": _jira_adf(delivery),
            "issuetype": {"name": "Task"},
        }
        if delivery.labels:
            fields["labels"] = [lbl.replace(" ", "-") for lbl in delivery.labels][:16]
        basic = base64.b64encode(f"{binding.jira_user_email}:{secret}".encode("utf-8")).decode("ascii")
        res = _egress.post_json(url, body={"fields": fields}, auth=("Authorization", f"Basic {basic}"),
                                allow_hosts=frozenset({"api.atlassian.com"}), resolver=resolver, transport=transport)
        payload = res.json if isinstance(res.json, dict) else {}
        key = payload.get("key")
        if not res.ok or not isinstance(key, str) or not key:
            raise IntegrationRefused(f"Jira issue create was not accepted (HTTP {res.status})")
        return DeliveredRef(issue_ref=key)


_LINEAR_MUTATION = ("mutation VigilIssueCreate($input: IssueCreateInput!) {"
                    " issueCreate(input: $input) { success issue { id identifier url } } }")


class LinearSink(IntegrationSink):
    """Linear issue create (GraphQL) — ``POST https://api.linear.app/graphql`` with the personal API key in the
    ``Authorization`` header (Linear personal keys are sent as the raw value, no ``Bearer`` prefix). The description
    is markdown carrying the evidence block. Create-only (``issueCreate``; never archive/transition)."""

    provider = PROVIDER_LINEAR
    _API = "https://api.linear.app/graphql"

    def deliver(self, delivery: Delivery, binding: "IntegrationBinding", *, secret: str,
                resolver=None, transport=None) -> DeliveredRef:
        variables = {"input": {"teamId": binding.linear_team_id, "title": delivery.title[:250],
                               "description": delivery.text_body()[:9000]}}
        res = _egress.post_json(self._API, body={"query": _LINEAR_MUTATION, "variables": variables},
                                auth=("Authorization", secret), allow_hosts=frozenset({"api.linear.app"}),
                                resolver=resolver, transport=transport)
        payload = res.json if isinstance(res.json, dict) else {}
        data = payload.get("data")
        data = data if isinstance(data, dict) else {}
        created = data.get("issueCreate")
        created = created if isinstance(created, dict) else {}
        issue = created.get("issue")
        issue = issue if isinstance(issue, dict) else {}
        if not res.ok or not created.get("success") or not issue:
            raise IntegrationRefused(f"Linear issueCreate was not accepted (HTTP {res.status})")
        return DeliveredRef(issue_ref=str(issue.get("identifier") or issue.get("id") or ""),
                            url=str(issue.get("url") or ""))


_SINKS: "dict[str, IntegrationSink]" = {
    PROVIDER_SLACK: SlackSink(),
    PROVIDER_JIRA: JiraSink(),
    PROVIDER_LINEAR: LinearSink(),
}


# ==============================================================================================================
# 4. Credential custody — owner-vault seal/open (the vault seam is injectable for tests)
# ==============================================================================================================
Sealer = Callable[[bytes], bytes]
Opener = Callable[[bytes], bytes]


def _default_seal(plaintext: bytes) -> bytes:
    from ..platform.vault import owner_vault
    return owner_vault().seal_secret(plaintext, context=_SECRET_CONTEXT)


def _default_open(blob: bytes) -> bytes:
    from ..platform.vault import owner_vault
    return owner_vault().unseal_secret(blob, context=_SECRET_CONTEXT)


def seal_token(plaintext: str, *, sealer: "Optional[Sealer]" = None) -> str:
    """Seal a provider token / webhook URL for storage in an owner-signed binding: base64 of the owner-vault AEAD
    seal. Requires the vault provisioned (``seal_secret`` raises ``VaultLocked`` otherwise — fail-closed; a secret
    that must be sealed never lands in the clear). ``sealer`` is the test seam (default: the owner vault)."""
    if not isinstance(plaintext, str) or not plaintext:
        raise IntegrationRefused("refusing to seal an empty integration secret")
    blob = (sealer or _default_seal)(plaintext.encode("utf-8"))
    return base64.b64encode(blob).decode("ascii")


def open_token(sealed_b64: str, *, opener: "Optional[Opener]" = None) -> str:
    """Open a sealed token for stamping onto a delivery's auth header. Fail-closed: a malformed blob, a locked vault
    or a wrong-context seal raises (``ValueError``/``VaultLocked``) and the delivery does NOT go. ``opener`` is the
    test seam (default: the owner vault)."""
    if not isinstance(sealed_b64, str) or not sealed_b64:
        raise IntegrationRefused("refusing to open an empty sealed secret")
    blob = base64.b64decode(sealed_b64, validate=True)
    return (opener or _default_open)(blob).decode("utf-8")


# ==============================================================================================================
# 5. The owner-signed per-(org, binding) binding registry (credential custody + routing)
# ==============================================================================================================
@dataclass(frozen=True)
class IntegrationBinding:
    """One active owner-signed integration binding for a tenant: provider + routing (min_severity) + non-secret
    destination + the SEALED secret. Keyed per (org_id, binding_id)."""

    org_id: str
    binding_id: str
    provider: str
    min_severity: str
    sealed_secret: str
    mode: str = ""                 # slack only
    slack_channel: str = ""        # slack postmessage
    jira_cloud_id: str = ""
    jira_project_key: str = ""
    jira_user_email: str = ""
    linear_team_id: str = ""
    issued_at: float = 0.0

    def deliverable(self) -> bool:
        return self.provider in _DELIVERABLE


def _check_binding_id(binding_id: str) -> str:
    bid = str(binding_id or "").strip()
    if not _BINDING_ID_RE.match(bid):
        raise ValueError("binding_id must be 1-64 chars of [a-z0-9_-] starting alphanumeric")
    return bid


def _norm_severity(value: Any) -> str:
    s = str(value or "").strip().lower()
    return s if s in _SEVERITY_RANK else _DEFAULT_MIN_SEVERITY


def _validate_destination(provider: str, *, mode: str, slack_channel: str, jira_cloud_id: str,
                          jira_project_key: str, jira_user_email: str, linear_team_id: str) -> None:
    """Fail-closed shape check of the NON-SECRET destination for ``provider`` (so a malformed binding can never be
    signed/stored, and the delivery URL/body are built from validated components only)."""
    if provider == PROVIDER_SLACK:
        if mode not in _SLACK_MODES:
            raise ValueError(f"slack binding mode must be one of {sorted(_SLACK_MODES)}")
        if mode == SLACK_POSTMESSAGE and not _SLACK_CHANNEL_RE.match(slack_channel):
            raise ValueError("slack postmessage binding requires a well-formed slack_channel")
    elif provider == PROVIDER_JIRA:
        if not _JIRA_CLOUD_ID_RE.match(jira_cloud_id):
            raise ValueError("jira binding requires a well-formed jira_cloud_id")
        if not _JIRA_PROJECT_RE.match(jira_project_key):
            raise ValueError("jira binding requires an uppercase jira_project_key (e.g. SEC)")
        if not _JIRA_EMAIL_RE.match(jira_user_email):
            raise ValueError("jira binding requires the account email for Basic auth")
    elif provider == PROVIDER_LINEAR:
        if not _LINEAR_TEAM_RE.match(linear_team_id):
            raise ValueError("linear binding requires a well-formed linear_team_id")
    else:
        raise ValueError(f"provider {provider!r} is not a deliverable integration (seam: {sorted(_SEAM)})")


class IntegrationBindingRegistry:
    """Owner-signed per-(org, binding_id) integration bindings on the spine, under ``governor.customer_integration``.
    Trust construction mirrors ``customer_credentials`` / ``connected_repos`` EXACTLY:

      * configure = the DANGEROUS direction → honored only if OWNER-SIGNED (``verify_signed`` under the owner pubkey
        valid at the record's seq) AND FRESH (``issued_at`` strictly above the per-(org, binding) high-water). The
        routing threshold, the destination AND the sealed secret are inside the signed bytes, so a tenant cannot lift
        a threshold, re-aim a destination or swap the credential without a fresh owner signature;
      * remove = the SAFE direction → ``state="revoked"`` honored even UNSIGNED (a replay merely re-removes);
      * per-(org, binding) LWW high-water closes replay-resurrection; owner-key-succession-aware verify.

    Tenant-isolated: ``active_for_org`` returns only that org's bindings; a binding for another org is structurally
    unreachable. FLAG-GATED writes (``customer_integrations_enabled``)."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations -----------------------------------------------------------------------------
    def configure(self, org_id: str, binding_id: str, *, provider: str, sealed_secret: str, issued_at: float,
                  min_severity: str = _DEFAULT_MIN_SEVERITY, mode: str = "", slack_channel: str = "",
                  jira_cloud_id: str = "", jira_project_key: str = "", jira_user_email: str = "",
                  linear_team_id: str = "") -> int:
        """Owner-sign a binding (create or replace) — the DANGEROUS direction (owner-signed + FRESH). ``sealed_secret``
        is an ALREADY-sealed token (see :func:`seal_token`), NEVER a plaintext credential. Fail-closed ``ValueError``
        on a bad org / binding id / provider / destination / severity or a missing signing key; ``IntegrationRefused``
        when the layer is OFF."""
        if not config.customer_integrations_enabled():
            raise IntegrationRefused("refusing to configure a binding: integrations are off (VIGIL_CUSTOMER_INTEGRATIONS)")
        if self.owner_key is None:
            raise ValueError("configuring an integration binding requires the owner signing key")
        oid = _check_org_id(org_id)
        bid = _check_binding_id(binding_id)
        if provider not in _DELIVERABLE:
            raise ValueError(f"provider must be one of {sorted(_DELIVERABLE)} (seam providers: {sorted(_SEAM)})")
        if not isinstance(sealed_secret, str) or not sealed_secret:
            raise ValueError("a binding requires a sealed_secret (owner-vault seal, not plaintext)")
        sev = _norm_severity(min_severity)
        _validate_destination(provider, mode=mode, slack_channel=slack_channel, jira_cloud_id=jira_cloud_id,
                              jira_project_key=jira_project_key, jira_user_email=jira_user_email,
                              linear_team_id=linear_team_id)
        core = {"signal": _BINDING_SIGNAL, "org_id": oid, "binding_id": bid, "provider": provider,
                "state": "active", "min_severity": sev, "mode": mode, "slack_channel": slack_channel,
                "jira_cloud_id": jira_cloud_id, "jira_project_key": jira_project_key,
                "jira_user_email": jira_user_email, "linear_team_id": linear_team_id,
                "sealed_secret": sealed_secret, "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"integration binding {oid}/{bid} ({provider}) configured (owner-signed)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def remove(self, org_id: str, binding_id: str) -> int:
        """Remove a binding — the SAFE direction (honored even unsigned, fixed ``issued_at`` 0.0). Idempotent; a
        replayed remove merely re-removes. Deliveries then stop for this binding (no active record)."""
        oid = _check_org_id(org_id)
        bid = _check_binding_id(binding_id)
        payload = {"signal": _BINDING_SIGNAL, "org_id": oid, "binding_id": bid, "state": "revoked", "by": "owner",
                   "requested_by": "owner", "tier": "A0", "decision": "auto",
                   "reason": f"integration binding {oid}/{bid} REMOVED"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware genesis fold; tenant-isolated) -----------------------------
    def _fold(self) -> "dict[tuple, IntegrationBinding]":
        """{(org_id, binding_id): IntegrationBinding} for bindings whose latest state is ACTIVE. A signature-verifying
        genesis scan of the live window: an owner-signed active record is honored only under the owner pubkey valid at
        its seq and only when FRESH (LWW high-water); a remove (even unsigned) supersedes."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: "dict[tuple, str]" = {}
        issued: "dict[tuple, float]" = {}
        rows: "dict[tuple, IntegrationBinding]" = {}
        for r in self.store.iter_records():
            self._apply(r, resolver, state, issued, rows)
        return {k: b for k, b in rows.items() if state.get(k) == "active"}

    def _apply(self, r, resolver, state: dict, issued: dict, rows: dict) -> None:
        p = getattr(r, "payload", None)
        if not isinstance(p, dict) or p.get("signal") != _BINDING_SIGNAL:
            return
        oid, bid = p.get("org_id"), p.get("binding_id")
        if not isinstance(oid, str) or not oid or not isinstance(bid, str) or not bid:
            return
        key = (oid, bid)
        st = p.get("state")
        if st == "revoked":
            state[key] = "revoked"                 # safe direction: honor ANY remove (even unsigned)
            return
        if st == "active":
            if not verify_signed(p, _BINDING_CORE, resolver.at(r.seq)):
                return                             # fail-closed: unsigned/forged/wrong-epoch binding
            at = as_issued_at(p.get("issued_at"))
            if at <= issued.get(key, NO_HIGHWATER):
                return                             # REPLAY / stale re-append of an already-honored binding
            issued[key] = at
            state[key] = "active"
            rows[key] = IntegrationBinding(
                org_id=oid, binding_id=bid, provider=str(p.get("provider") or ""),
                min_severity=_norm_severity(p.get("min_severity")), sealed_secret=str(p.get("sealed_secret") or ""),
                mode=str(p.get("mode") or ""), slack_channel=str(p.get("slack_channel") or ""),
                jira_cloud_id=str(p.get("jira_cloud_id") or ""), jira_project_key=str(p.get("jira_project_key") or ""),
                jira_user_email=str(p.get("jira_user_email") or ""), linear_team_id=str(p.get("linear_team_id") or ""),
                issued_at=at)

    def active_for_org(self, org_id: str) -> "list[IntegrationBinding]":
        """Every active binding for ``org_id``, in binding_id order — tenant-isolated (only this org's rows). This is
        the set a confirmed finding is routed across."""
        if not isinstance(org_id, str) or not org_id:
            return []
        try:
            oid = _check_org_id(org_id)
        except ValueError:
            return []
        return [b for (o, _b), b in sorted(self._fold().items()) if o == oid]

    def get(self, org_id: str, binding_id: str) -> "Optional[IntegrationBinding]":
        """One active binding (org_id, binding_id), or None (fail-closed: no record, removed, or a different org)."""
        if not isinstance(org_id, str) or not org_id or not isinstance(binding_id, str) or not binding_id:
            return None
        try:
            key = (_check_org_id(org_id), _check_binding_id(binding_id))
        except ValueError:
            return None
        return self._fold().get(key)


# ==============================================================================================================
# 6. The owner-signed, append-only delivery LEDGER (audit + idempotency)
# ==============================================================================================================
@dataclass(frozen=True)
class DeliveryOutcome:
    """The result of ONE binding's delivery (the orchestrator's return item). ``outcome`` ∈ {delivered,
    skipped_duplicate, refused}. ``issue_ref`` is the provider reference on a delivered create; ``detail`` is a
    short, CREDENTIAL-FREE note."""

    binding_id: str
    provider: str
    outcome: str
    issue_ref: str = ""
    detail: str = ""

    @property
    def delivered(self) -> bool:
        return self.outcome == OUTCOME_DELIVERED


class IntegrationDeliveryLedger:
    """Owner-signed, APPEND-ONLY per-org delivery ledger on the spine, under
    ``governor.customer_integration_delivery``. Every delivered/refused attempt is an owner-signed record carrying the
    finding identity + the evidence ``cert_digest`` + the outcome + the provider reference — so deliveries are
    auditable (who was told what, when, with which proof) and tamper-evident. ``delivered_keys_of`` folds the org's
    own records into the IDEMPOTENCY set, so a retry never opens a duplicate issue. Tenant-isolated per ``org_id``."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    def record(self, org_id: str, binding: IntegrationBinding, identity: "tuple[str, str, str]",
               evidence: EvidenceReference, *, outcome: str, issue_ref: str, issued_at: float) -> int:
        """Append ONE owner-signed ledger record for a delivery attempt. Only ``delivered``/``refused`` are recorded
        (a routed-away or deduped binding writes nothing). The record carries NO credential and no raw finding
        content beyond the inert identity + digests."""
        if self.owner_key is None:
            raise IntegrationRefused("recording a delivery requires the owner signing key")
        slug, ref, ocd = identity
        core = {"signal": _LEDGER_SIGNAL, "org_id": _check_org_id(org_id), "binding_id": binding.binding_id,
                "provider": binding.provider, "engagement_slug": slug, "finding_ref": ref,
                "oracle_context_digest": ocd, "cert_digest": evidence.cert_digest, "outcome": str(outcome),
                "issue_ref": str(issue_ref or ""), "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "WARDEN", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"integration delivery {outcome} {binding.provider} for {slug}/{ref}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _fold_for_org(self, org_id: str) -> "list[dict]":
        """Every VERIFIED owner-signed ledger record for ``org_id`` (fail-closed: a forged/unsigned record is inert),
        in spine order. Tenant-isolated — a record for another org is never returned."""
        try:
            oid = _check_org_id(org_id)
        except ValueError:
            return []
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        out: "list[dict]" = []
        for r in self.store.iter_records():
            p = getattr(r, "payload", None)
            if not isinstance(p, dict) or p.get("signal") != _LEDGER_SIGNAL or p.get("org_id") != oid:
                continue
            if not verify_signed(p, _LEDGER_CORE, resolver.at(r.seq)):
                continue                           # fail-closed: only owner-signed records count (tamper-evident)
            out.append(p)
        return out

    def delivered_keys_of(self, org_id: str) -> "set[tuple[str, tuple[str, str, str]]]":
        """The IDEMPOTENCY set for ``org_id``: every (binding_id, finding_identity) that already has a ``delivered``
        record. A binding+finding in here is NOT delivered again (a retry is a no-op). Only this org's records."""
        keys: "set[tuple[str, tuple[str, str, str]]]" = set()
        for p in self._fold_for_org(org_id):
            if p.get("outcome") != OUTCOME_DELIVERED:
                continue
            bid = str(p.get("binding_id") or "")
            ident = (str(p.get("engagement_slug") or ""), str(p.get("finding_ref") or ""),
                     str(p.get("oracle_context_digest") or ""))
            keys.add((bid, ident))
        return keys

    def records_of(self, org_id: str) -> "list[dict]":
        """This org's ledger records (verified), newest-last — the auditable delivery history for an owner/admin
        view. Credential-free by construction."""
        return [{"binding_id": p.get("binding_id"), "provider": p.get("provider"),
                 "engagement_slug": p.get("engagement_slug"), "finding_ref": p.get("finding_ref"),
                 "cert_digest": p.get("cert_digest"), "outcome": p.get("outcome"),
                 "issue_ref": p.get("issue_ref"), "issued_at": p.get("issued_at")}
                for p in self._fold_for_org(org_id)]


# ==============================================================================================================
# 7. The orchestrator — flag-gated, tenant-isolated, idempotent, ledgered
# ==============================================================================================================
def _routes(binding: IntegrationBinding, finding_row: "dict[str, Any]") -> bool:
    """True iff ``binding`` wants this finding's severity (rank(finding) >= rank(binding.min_severity))."""
    f_rank = _SEVERITY_RANK.get(str(finding_row.get("severity") or "").strip().lower(), 0)
    b_rank = _SEVERITY_RANK.get(binding.min_severity, _SEVERITY_RANK[_DEFAULT_MIN_SEVERITY])
    return f_rank >= b_rank


def deliver_confirmed_finding(store, org_id: str, finding_row: "dict[str, Any]", *, now: float,
                              certificate: Any = None, bindings: "Optional[IntegrationBindingRegistry]" = None,
                              ledger: "Optional[IntegrationDeliveryLedger]" = None, owner_key=None,
                              trusted_pubkey: Optional[str] = None, resolver=None,
                              transports: "Optional[dict[str, Any]]" = None,
                              opener: "Optional[Opener]" = None) -> "list[DeliveryOutcome]":
    """Deliver ONE confirmed finding to every routed binding of ``org_id``. The top-level entry the edge/drain calls
    (org from the session, gated reads/writes through the provisioner hop). Returns one :class:`DeliveryOutcome` per
    ROUTED binding.

    Fail-closed / money-safe pipeline, per binding:
      flag OFF ⇒ INERT (returns ``[]``, no read, no socket). Else: require a CONFIRMED (FACT) finding (raises on a
      notice/LEAD); for each active binding of the org whose routing admits the severity → IDEMPOTENCY check against
      the owner-signed ledger (a prior ``delivered`` ⇒ ``skipped_duplicate``, no second issue); build the delivery
      (carrying the evidence-certificate reference); OPEN the sealed secret (fail-closed — a locked vault ⇒ ``refused``,
      no POST); deliver create-only through the egress gate; append an owner-signed ledger record of the outcome.

    ``transports`` maps a provider to an injected egress transport (offline tests); ``opener`` is the vault seam."""
    if not config.customer_integrations_enabled():
        return []                                  # INERT: no read, no secret, no socket, no ledger
    identity = _require_confirmed_finding(finding_row)      # RAISES on a non-FACT (a notice can never deliver)
    bindings = bindings or IntegrationBindingRegistry(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
    ledger = ledger or IntegrationDeliveryLedger(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
    evidence = evidence_reference(finding_row, certificate)
    delivery = build_finding_delivery(finding_row, evidence)
    delivered_keys = ledger.delivered_keys_of(org_id)
    transports = transports or {}
    outcomes: "list[DeliveryOutcome]" = []
    for binding in bindings.active_for_org(org_id):
        if not binding.deliverable() or not _routes(binding, finding_row):
            continue                               # routed away — no delivery, no ledger noise
        if (binding.binding_id, identity) in delivered_keys:
            outcomes.append(DeliveryOutcome(binding.binding_id, binding.provider, OUTCOME_SKIPPED_DUPLICATE,
                                            detail="already delivered (idempotent)"))
            continue
        outcomes.append(_deliver_one(ledger, org_id, binding, delivery, identity, evidence, now=now,
                                     transport=transports.get(binding.provider), resolver=resolver, opener=opener))
    return outcomes


def deliver_engagement_event(store, org_id: str, delivery: Delivery, *, now: float,
                             bindings: "Optional[IntegrationBindingRegistry]" = None,
                             ledger: "Optional[IntegrationDeliveryLedger]" = None, owner_key=None,
                             trusted_pubkey: Optional[str] = None, resolver=None,
                             transports: "Optional[dict[str, Any]]" = None,
                             opener: "Optional[Opener]" = None) -> "list[DeliveryOutcome]":
    """Deliver an engagement MILESTONE (:func:`build_milestone_delivery`) to the org's SLACK bindings only —
    notification-only (a milestone carries no certificate, so it never opens a Jira/Linear issue; money-safe). Same
    flag gate, custody, egress gate and ledger as a finding delivery. Not idempotent-keyed by a finding (a milestone
    has none); an operator fires it deliberately."""
    if not config.customer_integrations_enabled():
        return []
    if not isinstance(delivery, Delivery) or not delivery.is_milestone:
        raise IntegrationRefused("deliver_engagement_event requires a milestone Delivery (build_milestone_delivery)")
    bindings = bindings or IntegrationBindingRegistry(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
    ledger = ledger or IntegrationDeliveryLedger(store, owner_key=owner_key, trusted_pubkey=trusted_pubkey)
    identity = (delivery.evidence.engagement_slug, "milestone", "")
    transports = transports or {}
    outcomes: "list[DeliveryOutcome]" = []
    for binding in bindings.active_for_org(org_id):
        if binding.provider != PROVIDER_SLACK:
            continue                               # milestones are Slack-only (no issue mint without a proof)
        outcomes.append(_deliver_one(ledger, org_id, binding, delivery, identity, delivery.evidence, now=now,
                                     transport=transports.get(binding.provider), resolver=resolver, opener=opener))
    return outcomes


def _deliver_one(ledger: IntegrationDeliveryLedger, org_id: str, binding: IntegrationBinding, delivery: Delivery,
                 identity: "tuple[str, str, str]", evidence: EvidenceReference, *, now: float, transport,
                 resolver, opener: "Optional[Opener]") -> DeliveryOutcome:
    """Open the sealed secret, deliver create-only through the egress gate, and record the owner-signed ledger
    outcome. ALL faults (locked vault, egress refusal, provider rejection) are caught and recorded as ``refused`` —
    nothing raises out of a single binding's delivery (one bad binding never sinks the others), and a ``refused``
    never blocks a later retry. The secret is opened ONLY here, stamped onto the auth header by the sink, and never
    returned, logged or placed in the body."""
    sink = _SINKS.get(binding.provider)
    if sink is None:                               # a seam provider slipped through — refuse, never deliver
        outcome = DeliveryOutcome(binding.binding_id, binding.provider, OUTCOME_REFUSED,
                                  detail="provider is a documented seam, not deliverable")
        _safe_record(ledger, org_id, binding, identity, evidence, outcome, now=now)
        return outcome
    try:
        secret = open_token(binding.sealed_secret, opener=opener)     # fail-closed: locked vault ⇒ no POST
        ref = sink.deliver(delivery, binding, secret=secret, resolver=resolver, transport=transport)
        outcome = DeliveryOutcome(binding.binding_id, binding.provider, OUTCOME_DELIVERED,
                                  issue_ref=ref.issue_ref, detail="created")
    except Exception as exc:  # noqa: BLE001 — a credential-free refusal; one binding's fault never sinks the rest
        outcome = DeliveryOutcome(binding.binding_id, binding.provider, OUTCOME_REFUSED,
                                  detail=_safe_detail(exc))
    _safe_record(ledger, org_id, binding, identity, evidence, outcome, now=now)
    return outcome


def _safe_detail(exc: Exception) -> str:
    """A short, CREDENTIAL-FREE detail for a refusal. The egress/refusal types already build credential-free
    messages; this caps length and never includes a traceback."""
    msg = str(exc) or type(exc).__name__
    return msg[:200]


def _safe_record(ledger: IntegrationDeliveryLedger, org_id: str, binding: IntegrationBinding,
                 identity: "tuple[str, str, str]", evidence: EvidenceReference, outcome: DeliveryOutcome, *,
                 now: float) -> None:
    """Append the owner-signed ledger record, never raising out of delivery (a ledger write fault must not re-raise
    into the data plane; the delivery already happened or was refused)."""
    try:
        ledger.record(org_id, binding, identity, evidence, outcome=outcome.outcome, issue_ref=outcome.issue_ref,
                      issued_at=now)
    except Exception:  # noqa: BLE001 — a ledger append fault is swallowed (the outcome is still returned to the caller)
        pass


__all__ = [
    "PROVIDER_SLACK", "PROVIDER_JIRA", "PROVIDER_LINEAR", "PROVIDER_GITLAB", "PROVIDER_BITBUCKET",
    "SLACK_WEBHOOK", "SLACK_POSTMESSAGE",
    "OUTCOME_DELIVERED", "OUTCOME_SKIPPED_DUPLICATE", "OUTCOME_REFUSED",
    "IntegrationRefused", "NotAConfirmedFinding",
    "EvidenceReference", "evidence_reference", "finding_identity",
    "Delivery", "build_finding_delivery", "build_milestone_delivery",
    "IntegrationSink", "SlackSink", "JiraSink", "LinearSink", "DeliveredRef",
    "seal_token", "open_token",
    "IntegrationBinding", "IntegrationBindingRegistry",
    "DeliveryOutcome", "IntegrationDeliveryLedger",
    "deliver_confirmed_finding", "deliver_engagement_event",
]
