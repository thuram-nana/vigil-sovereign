"""
intel.models — the Observation, the atomic intel fact (the ONLY collector output).

Every intel datum carries provenance (source + collector + raw_ref), a source
reliability (Admiralty A–F × 1–6), a per-datum confidence, a polarity (affirms /
refutes — a REFUTES observation drives the world-model belief DOWN), and a monotonic
seq (the world-model time doctrine — never wallclock). Nothing enters the graph
without this. A node-only claim sets just `subject`; an edge claim sets
`subject → relation → object`, mirroring the world-model edge shape exactly.
"""

from __future__ import annotations

import enum
import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..worldmodel.models import EdgeKind
from .refs import EntityRef


class Reliability(str, enum.Enum):
    """Admiralty source-reliability axis (A best … E worst, F cannot be judged)."""
    A = "A"; B = "B"; C = "C"; D = "D"; E = "E"; F = "F"


class Credibility(str, enum.Enum):
    """Admiralty information-credibility axis (1 confirmed … 5 improbable, 6 cannot judge)."""
    C1 = "1"; C2 = "2"; C3 = "3"; C4 = "4"; C5 = "5"; C6 = "6"


class Polarity(str, enum.Enum):
    AFFIRMS = "affirms"   # the claim is true
    REFUTES = "refutes"   # the claim is false — folds to (1 - confidence) truth


class IntelSourceKind(str, enum.Enum):
    DNS = "dns"
    CERT_TRANSPARENCY = "cert_transparency"
    RDAP_WHOIS = "rdap_whois"
    ASN_BGP = "asn_bgp"
    WEB_ARCHIVE = "web_archive"
    PUBLIC_REPO = "public_repo"
    VULN_DB = "vuln_db"
    FINGERPRINT = "fingerprint"       # the intake fingerprinter feeding the engine
    OPERATOR_INGEST = "operator_ingest"  # operator-provided data (offline path)
    SCAN = "scan"                     # a confirmed scan/engage finding
    INFERENCE = "inference"           # a fact DERIVED from other observations (intel.infer)
    PACKET_CAPTURE = "packet_capture"  # observed in captured traffic (a pcap read by a packet engine)
    WEB_SCANNER = "web_scanner"       # a third-party web scanner's heuristic match (Nuclei/ZAP/Burp) —
    #                                   a LEAD, never a fact, until a CRUCIBLE oracle re-verifies it
    CLOUD_POSTURE = "cloud_posture"   # a cloud/IAM posture export (ScoutSuite/Prowler/provider) — the
    #                                   IAM topology + mis-config LEADS; a privilege PATH is a fact only
    #                                   when the policy-path oracle re-derives it over the retained graph
    MISP = "misp"                     # a MISP threat-intel event feed (IOCs) — a LEAD/corroboration, never a fact
    STIX = "stix"                     # a STIX 2.x bundle (IOC indicators + vulnerability objects) — a LEAD
    #                                   NOTE: CVE / advisory observations use VULN_DB above, whatever the feed format.
    MCP_TOOL = "mcp_tool"             # an external MCP tool consumed as a gated sensor (mcp.sensor) —
    #                                   a third-party say-so; a LEAD, never a fact, until an oracle re-verifies it
    # AEGIS (the DEFENSIVE dual) — inbound, in-request-path telemetry the operator's OWN app emits
    # about actors hitting it. A LEAD tier, exactly like the scanner/MISP sources above: an actor's
    # request/LLM telemetry enters as GROUNDING_INTEL and becomes a FACT only when an AEGIS oracle
    # (system_prompt_disclosure / prompt_injection / automated_access) re-fires over retained evidence.
    REQUEST_TELEMETRY = "request_telemetry"  # in-request-path metadata (method/path/honeypot hit) — a LEAD
    LLM_INTERACTION = "llm_interaction"      # the app's own LLM I/O (prompt/output/canary/behavior) — a LEAD
    AUTH_TELEMETRY = "auth_telemetry"        # auth-outcome events (account/source/success) — a LEAD; credential
    #                                          stuffing is a FACT only when the credential_stuffing oracle re-fires


_REL_W = {Reliability.A: 1.0, Reliability.B: 0.85, Reliability.C: 0.65,
          Reliability.D: 0.45, Reliability.E: 0.25, Reliability.F: 0.0}
_CRED_W = {Credibility.C1: 1.0, Credibility.C2: 0.85, Credibility.C3: 0.65,
           Credibility.C4: 0.45, Credibility.C5: 0.25, Credibility.C6: 0.0}


class SourceReliability(BaseModel):
    """A NATO STANAG-2511 rating (or a calibrated override). `weight()` collapses the
    two axes to a [0, 1] factor; 'cannot be judged' (F or 6) → 0.0, so a worthless
    source contributes nothing and 'unknown stays unknown'."""

    model_config = ConfigDict(extra="forbid")

    reliability: Reliability = Reliability.C
    credibility: Credibility = Credibility.C3
    calibrated_prior: float | None = Field(default=None, ge=0.0, le=1.0)

    def weight(self) -> float:
        if self.calibrated_prior is not None:
            return self.calibrated_prior
        r, c = _REL_W[self.reliability], _CRED_W[self.credibility]
        if r <= 0.0 or c <= 0.0:
            return 0.0
        return math.sqrt(r * c)  # geometric mean of the two axes


class Observation(BaseModel):
    """One atomic intel fact. A collector's ONLY output; the single thing that enters
    the world-model (via intel.project). Immutable once minted."""

    model_config = ConfigDict(extra="forbid")

    obs_id: str = Field(min_length=1, description="Stable id → world-model provenance + evidence join key.")
    source: str
    source_kind: IntelSourceKind
    collector: str = ""
    subject: EntityRef
    relation: EdgeKind | None = None            # None → a node claim; set → an edge claim
    object: EntityRef | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)
    source_reliability: SourceReliability = Field(default_factory=SourceReliability)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    polarity: Polarity = Polarity.AFFIRMS
    seq: int = Field(ge=0)                       # monotonic (never wallclock)
    observed_at: str = ""
    valid_from: str | None = None
    valid_to: str | None = None
    raw_ref: str = ""
    evidence: str = ""

    def reliability(self) -> float:
        """The source's [0,1] trust factor for this datum."""
        return self.source_reliability.weight()

    def truth_confidence(self) -> float:
        """Confidence that the CLAIM IS TRUE, with polarity folded in — a high-confidence
        REFUTES becomes a low truth-confidence, which drives the Beta belief down."""
        return self.confidence if self.polarity is Polarity.AFFIRMS else 1.0 - self.confidence

    @property
    def claim_key(self) -> tuple[str, str, str]:
        """The (subject, relation, object) identity this observation asserts — the key
        fusion groups on and projection upserts onto."""
        return (self.subject.node_id, self.relation.value if self.relation else "",
                self.object.node_id if self.object else "")
