"""sensors.identity — ingest an operator-supplied identity-provider export into posture LEADS.

FORGE **Domain 7** (slice 1), stage 1. The capture feed that makes the identity-posture oracle
(``verify.identity_posture``) reachable from an operator's exported IdP inventory — a confirmed finding emits
a real signed **PCF v0.1** certificate (``evidence/pcf.py``) by construction.

Mirrors ``sensors.email_auth.EmailAuthSensor``: Tier-1, reads a LOCAL operator-supplied JSON export (**no IdP
is queried, no authentication is attempted**), kill-switch-gated via ``sensors.pipeline.run_sensor``, and
mints one ``NodeKind.CONTROL`` LEAD per candidate posture control (keyed ``identity:<subject>:<rule>``)
carrying the STRICT-TYPED evidence the oracle judges on the node, so a grounded FACT re-derives from its own
node — parity with every sibling posture sensor. The leads STOP here; the oracle re-verifies a lead to a FACT only when the
export's STRICT-TYPED fields provably carry a weakness (a privileged identity with MFA off, or a credential
past its rotation policy). A compliant identity stays a LEAD-that-never-fires (in fact it mints no candidate).

Export shape (JSON) — the identity records EXACTLY as the operator exported them::

    {"identities": [
      {"subject": "admin@corp.example",             # the identity / credential id
       "privileged": true,                          # a PRODUCER ATTESTATION (never inferred by the oracle)
       "mfa_enrolled": false},                       # STRICT bool; absent -> the oracle REFUSES
      {"subject": "svc-deploy-key",
       "age_days": 400, "max_age_days": 90}]}        # the operator's rotation policy for this credential

The attestations are read STRICTLY (only a literal ``true``/``false`` counts — a truthy ``"false"`` must
never launder into a signed certificate). Pure + total: a malformed export is a non-ingestion, never a crash.
Defensive-only — a posture read of the operator's OWN identities.
"""

from __future__ import annotations

import json
import os

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef
from ..verify.identity_posture import ingest_identity_export
from ..worldmodel.models import NodeKind

# An operator-supplied IdP export: Admiralty B2 (usually reliable / probably true), like SBOM/MobSF/email.
_IDENTITY_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)
_MAX_CONTROLS = 5000


def parse_identity_export(text: str) -> list[dict]:
    """Parse an identity-provider export into per-identity candidate controls, each tagged with a stable
    ``check_id`` (``<subject>:<rule>``) so the lead and its later oracle-promoted FACT land on the SAME
    CONTROL node. PURE + total — invalid JSON / an unknown shape yields ``[]``, never an exception. Dedup is
    already applied by ``ingest_identity_export`` (first-wins per ``subject:rule`` node key), so the lead
    path and the fusion-promotion path judge the same control per node (the Domain-10 provenance lesson)."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    controls = ingest_identity_export(doc)
    out: list[dict] = []
    for c in controls:
        subject = str(c.get("subject") or "").strip()
        c["check_id"] = f"{subject}:{c['rule']}"
        out.append(c)
        if len(out) >= _MAX_CONTROLS:
            break
    return out


# The STRICT-TYPED fields the oracle judges — persisted on the CONTROL node so a grounded FACT re-derives
# from its OWN node (prove-by-re-execution at the graph layer), exactly as every sibling posture sensor
# persists its load-bearing record (email_auth: dmarc_record/spf_record; mesh: mtls_mode/action;
# cicd: uses/run/trigger; k8s: actual_value). Booleans and ints only, so nothing sensitive beyond the
# `subject` already on the node, and nothing free-text.
_JUDGED_FIELDS = ("privileged", "mfa_enrolled", "never_rotated", "age_days", "max_age_days",
                  "admin_all", "grant", "days_since_login", "dormancy_threshold_days")


def identity_observations(controls: list[dict], *, seq: int, source: str = "identity") -> list[Observation]:
    """Mint one ``NodeKind.CONTROL`` LEAD per candidate posture control, keyed ``identity:<check_id>``
    (lowercased). The RETAINED control fields the oracle judges (``_JUDGED_FIELDS``) ride in ``attrs`` so a
    later oracle-grounded FACT on this node RE-DERIVES from the node's own evidence — the graph-layer twin of
    the PCF certificate's re-verifiability, and parity with every sibling posture sensor. GROUNDING_INTEL,
    claim-keyed obs_ids (idempotent), pure."""
    out: list[Observation] = []
    seen: set[str] = set()
    for c in controls:
        cid = str(c.get("check_id") or "").strip()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        ref = EntityRef(kind=NodeKind.CONTROL, key=f"identity:{cid}".lower())
        base = {"lead": True, "unverified": True, "check_id": cid, "rule": c.get("rule"),
                "subject": c.get("subject")}
        attrs: dict = {k: v for k, v in base.items() if v not in (None, "")}
        # then persist the load-bearing evidence VERBATIM (added AFTER the empties filter, so a load-bearing
        # `mfa_enrolled: False` or `age_days: 0` is kept, never dropped as falsy).
        for k in _JUDGED_FIELDS:
            if k in c and c.get(k) is not None:
                attrs[k] = c.get(k)
        out.append(Observation(
            obs_id=f"{source}:{seq}:{ref.node_id}||", source=source,
            source_kind=IntelSourceKind.OPERATOR_INGEST, collector=source, subject=ref,
            relation=None, object=None, attrs=attrs,
            source_reliability=_IDENTITY_RELIABILITY, confidence=0.7, seq=seq))
    return out


class IdentitySensor:
    """Ingest an operator-provided identity-provider export and mint posture LEADS. args:
    ``{"export": "/path/to/identity-export.json"}``. Passive (Tier-1): reads a local file, NO IdP query, NO
    authentication attempt, no entitlement — kill-switch-gated via ``sensors.pipeline.run_sensor``. The
    leads STOP here; the identity-posture oracle re-verifies a lead to a FACT. Mirrors ``EmailAuthSensor``."""

    name = "identity"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path = args.get("export") if isinstance(args, dict) else None
        if not path or not isinstance(path, str):
            return ToolResult(ok=False, note="identity requires args['export'] (an IdP export JSON path)")
        if not os.path.isfile(path):
            return ToolResult(ok=False, note=f"identity: export not found: {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            return ToolResult(ok=False, note=f"identity: could not read export: {e}")
        controls = parse_identity_export(text)
        return ToolResult(ok=True, summary=f"identity: {len(controls)} posture control(s)",
                          output={"controls": controls})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        controls = out.get("controls")
        if not isinstance(controls, list):
            return []
        return identity_observations(controls, seq=seq, source="identity")

    def controls(self, result: ToolResult) -> list[dict]:
        """The retained posture controls for the identity-posture oracle (``confirm_identity_posture``)."""
        out = result.output or {}
        c = out.get("controls")
        return c if isinstance(c, list) else []
