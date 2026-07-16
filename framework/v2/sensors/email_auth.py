"""sensors.email_auth — ingest an operator-supplied DNS email-auth policy export into posture LEADS.

FORGE **Domain 10** (the first FORGE-built stream), stage 1. The capture feed that makes the
email-auth-posture oracle (``verify.email_auth``) reachable from an operator's exported DNS records — a
confirmed finding emits a real signed **PCF v0.1** certificate (``evidence/pcf.py``) by construction.

Mirrors ``sensors.cicd.WorkflowScanSensor`` method-for-method: Tier-1, reads a LOCAL operator-supplied JSON
export (**no DNS is queried, no mail is sent**), kill-switch-gated via ``sensors.pipeline.run_sensor``, and
mints one ``NodeKind.CONTROL`` LEAD per candidate policy control, keyed ``email:<domain>:<rule>``. The leads
STOP here; the oracle re-verifies a lead to a FACT only when the PUBLISHED policy provably permits spoofing
(no DMARC / ``p=none`` / SPF ``+all``). A hardened domain stays a LEAD.

Export shape (JSON) — the records EXACTLY as published::

    {"domains": [
      {"domain": "gov.example",                     # an ORGANIZATIONAL (registrable) domain
       "dmarc": "v=DMARC1; p=none; rua=mailto:r@gov.example",   # omit if none published
       "spf":   "v=spf1 include:_spf.example.com -all",         # omit if none published
       "dmarc_observed": true,                      # the DMARC lookup WAS performed
       "is_org_domain": true},                      # no parent policy exists to inherit
      {"domain": "mail.gov.example",                # a SUBDOMAIN
       "spf": "v=spf1 -all", "dmarc_observed": true,
       "org_domain": "gov.example",                 # RFC 7489 §6.6.3 fallback target …
       "org_dmarc": "v=DMARC1; p=reject",           # … and its retained policy (§6.3 sp= else p=)
       "org_dmarc_observed": true}]}

The attestations are load-bearing and are read STRICTLY (only a literal ``true`` counts — a truthy
``"false"`` must never launder into a signed certificate):
  * ``dmarc_observed`` — the oracle REFUSES to call a record "missing" without it (absence must be
    OBSERVED, never assumed).
  * ``is_org_domain`` / ``org_dmarc*`` — an absent record at a SUBDOMAIN proves NOTHING on its own: RFC 7489
    §6.6.3 makes receivers fall back to the organizational domain, whose ``sp=`` (else ``p=``) protects the
    subdomain. Without either the org-domain attestation or its retained policy, the oracle REFUSES.

Pure + total: a malformed export is a non-ingestion, never a crash. Defensive-only — a posture read of the
operator's own domains.
"""

from __future__ import annotations

import json
import os

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef
from ..verify.email_auth import ingest_dns_policy
from ..worldmodel.models import NodeKind

# An operator-supplied DNS export: Admiralty B2 (usually reliable / probably true), like SBOM/MobSF.
_EMAIL_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)
_MAX_DOMAINS = 2000


def parse_email_auth_export(text: str) -> list[dict]:
    """Parse a DNS email-auth export into per-domain candidate controls, each tagged with a stable
    ``check_id`` (``<domain>:<rule>``) so the lead and its later oracle-promoted FACT land on the SAME
    CONTROL node. PURE + total — invalid JSON / an unknown shape yields ``[]``, never an exception."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    rows = doc.get("domains") if isinstance(doc, dict) else (doc if isinstance(doc, list) else None)
    if not isinstance(rows, list):
        return []
    controls: list[dict] = []
    seen_nodes: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        domain = str(row.get("domain") or "").strip()
        if not domain:
            continue
        # STRICT attestations: only a literal `true` in the export counts. NEVER bool()-coerce — a truthy
        # "false"/"no" would launder a fabricated attestation into a signed, forever-re-firing certificate.
        for c in ingest_dns_policy(domain,
                                   dmarc_record=row.get("dmarc"), spf_record=row.get("spf"),
                                   dmarc_observed=row.get("dmarc_observed") is True,
                                   is_org_domain=row.get("is_org_domain") is True,
                                   org_domain=row.get("org_domain"),
                                   org_dmarc_record=row.get("org_dmarc"),
                                   org_dmarc_observed=row.get("org_dmarc_observed") is True):
            c["check_id"] = f"{domain}:{c['rule']}"
            # Dedup FIRST-WINS by the CONTROL node a lead/FACT lands on (case-insensitive: DNS names are
            # case-insensitive, RFC 4343, and the node key is `email:<check_id>`.lower()). A registrable
            # domain has ONE policy per rule, so two rows that collide on one node are a contradictory/
            # duplicate operator export — keep the first and drop the rest. Load-bearing for PCF round-trip
            # integrity: without it a LATER row's oracle-confirmed FACT could ground onto the node carrying
            # an EARLIER row's (possibly hardened) record, so an offline re-verify from that node's own
            # retained evidence would reproduce nothing. Deduping here (the sole producer) keeps the lead
            # path and the fusion-promotion path judging the SAME control per node, by construction.
            node_key = c["check_id"].lower()
            if node_key in seen_nodes:
                continue
            seen_nodes.add(node_key)
            controls.append(c)
            if len(controls) >= _MAX_DOMAINS:
                return controls
    return controls


def email_auth_observations(controls: list[dict], *, seq: int, source: str = "email_auth") -> list[Observation]:
    """Mint one ``NodeKind.CONTROL`` LEAD per candidate policy control, keyed ``email:<check_id>``. The
    retained record text (the exact evidence the oracle re-derives over) rides in ``attrs``. GROUNDING_INTEL,
    claim-keyed obs_ids (idempotent), pure."""
    out: list[Observation] = []
    seen: set[str] = set()
    for c in controls:
        cid = str(c.get("check_id") or "").strip()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        ref = EntityRef(kind=NodeKind.CONTROL, key=f"email:{cid}".lower())
        attrs = {"lead": True, "unverified": True, "check_id": cid, "rule": c.get("rule"),
                 "domain": c.get("domain"), "dmarc_record": c.get("dmarc_record"),
                 "spf_record": c.get("spf_record")}
        out.append(Observation(
            obs_id=f"{source}:{seq}:{ref.node_id}||", source=source,
            source_kind=IntelSourceKind.OPERATOR_INGEST, collector=source, subject=ref,
            relation=None, object=None, attrs={k: v for k, v in attrs.items() if v not in (None, "")},
            source_reliability=_EMAIL_RELIABILITY, confidence=0.7, seq=seq))
    return out


class EmailAuthSensor:
    """Ingest an operator-provided DNS email-auth export and mint posture LEADS. args:
    ``{"export": "/path/to/dns-email-auth.json"}``. Passive (Tier-1): reads a local file, NO DNS query, NO
    mail, no entitlement — kill-switch-gated via ``sensors.pipeline.run_sensor``. The leads STOP here; the
    email-auth-posture oracle re-verifies a lead to a FACT. Mirrors ``WorkflowScanSensor``."""

    name = "email_auth"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path = args.get("export") if isinstance(args, dict) else None
        if not path or not isinstance(path, str):
            return ToolResult(ok=False, note="email_auth requires args['export'] (a DNS policy JSON path)")
        if not os.path.isfile(path):
            return ToolResult(ok=False, note=f"email_auth: export not found: {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            return ToolResult(ok=False, note=f"email_auth: could not read export: {e}")
        controls = parse_email_auth_export(text)
        return ToolResult(ok=True, summary=f"email_auth: {len(controls)} policy control(s)",
                          output={"controls": controls})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        controls = out.get("controls")
        if not isinstance(controls, list):
            return []
        return email_auth_observations(controls, seq=seq, source="email_auth")

    def controls(self, result: ToolResult) -> list[dict]:
        """The retained policy controls for the email-auth-posture oracle (``confirm_email_auth_posture``)."""
        out = result.output or {}
        c = out.get("controls")
        return c if isinstance(c, list) else []
