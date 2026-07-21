"""
detection.telemetry — the honest LEAD-only stubs for the telemetry/egress planes (SENSOR-WRIGHT gap).

The edge plane (recon + injection + credential) works over telemetry the loopback substrate actually
produces. The telemetry and egress planes do NOT: no NetFlow/proxy/DNS, no Domain-Controller/LDAP/
Kerberos, no CloudTrail/k8s-audit, no session/IdP events are ingested here. The doctrine (§7) is
explicit — "No log source, no proof." So these domains are represented by STUBS that:

  * NEVER mint a FACT (``fact_possible`` is False by construction — there is no oracle to fire and no
    telemetry to fire it over);
  * return a single LEAD carrying an honest coverage-gap note naming the ABSENT telemetry;
  * fake nothing — they do not synthesize beacons, tickets, or API calls.

This is the sovereign-honest posture: a quiet plane is reported as UNMONITORED, never as SAFE. When the
telemetry is later ingested (SENSOR-WRIGHT), the named oracles become real fired detections.

Import-clean: stdlib + the F2 ``Finding`` + the detection base.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..agent.state import Finding
from .base import Detection, Grade


@dataclass(frozen=True)
class TelemetryStub:
    """One unmonitored detection domain. ``oracles`` are the detections it WOULD provide once
    ``required_telemetry`` is ingested; until then every assessment is a LEAD with the honest note."""

    domain: str
    required_telemetry: str
    oracles: tuple
    note: str
    severity: str = "info"

    #: A stub can never reach FACT — there is no ingested telemetry and no fired oracle.
    fact_possible: bool = False

    def available(self) -> bool:
        """Whether the required telemetry is ingested. Always False for a stub (deny-by-default)."""
        return False

    def coverage_note(self) -> str:
        return (f"{self.domain}: needs {self.required_telemetry} (absent) — {self.note} "
                f"Would provide: {', '.join(self.oracles)}.")

    def assess(self, suspicion: str = "", *, seq: int = 0) -> Detection:
        """Return the honest LEAD for this plane. It NEVER carries a certificate or an evidence ref (a
        FACT would require ingested telemetry + a fired oracle, both absent). ``suspicion`` is an
        analyst's optional context, folded into the summary as non-authoritative text."""
        summary = self.coverage_note()
        if isinstance(suspicion, str) and suspicion.strip():
            summary = f"{summary} Analyst note (unproven): {suspicion.strip()}"
        lead = Finding(
            ref=f"detection:telemetry:{self.domain}:{seq}",
            bug_class=f"telemetry.{self.domain}",
            title=f"{self.domain} plane unmonitored — LEAD only",
            severity=self.severity, status="lead", evidence_ref="",
            source=f"detection/telemetry/{self.domain}",
        )
        return Detection(
            oracle=f"telemetry.{self.domain}", grade=Grade.LEAD, signature_kind="telemetry-absent",
            bug_class=f"telemetry.{self.domain}", severity=self.severity, summary=summary,
            source="", evidence=(), finding=lead, certificate=None, note=self.coverage_note(),
        )


# The four telemetry/egress planes the mirror covers but this substrate does not feed.
C2_STUB = TelemetryStub(
    domain="c2",
    required_telemetry="NetFlow / proxy logs + DNS logs (optionally EDR)",
    oracles=("beacon_periodicity", "c2_tls_fingerprint", "dns_tunnel", "exfil_volume"),
    note=("no egress/network telemetry is ingested, so beaconing, DNS tunnelling and exfil stay "
          "LEAD-only; modern C2 also defeats naive timing analysis with jitter/domain-fronting "
          "(an arms race), so even with telemetry high-fidelity is not guaranteed"),
)

IDENTITY_GRAPH_STUB = TelemetryStub(
    domain="identity_graph",
    required_telemetry="Domain Controller / LDAP / Kerberos event logs (+ EDR for LSASS)",
    oracles=("ldap_recon", "kerberoast", "asrep_roast", "dcsync", "ticket_anomaly",
             "lsass_access", "adcs_abuse"),
    note="no directory/Kerberos telemetry is ingested (lsass_access additionally requires EDR)",
)

CLOUD_STUB = TelemetryStub(
    domain="cloud",
    required_telemetry="CloudTrail / cloud-audit / k8s-audit logs",
    oracles=("cloud_enumeration", "iam_privesc", "k8s_attack", "container_escape"),
    note="no cloud/k8s audit telemetry is ingested; detections additionally require actor/context",
)

SESSION_STUB = TelemetryStub(
    domain="session",
    required_telemetry="session logs + identity-provider (IdP) events",
    oracles=("session_origin_anomaly", "token_replay", "oauth_grant_anomaly"),
    note=("no session/IdP telemetry is ingested; this is the hardest domain — the benign overlap is "
          "large (VPNs, new devices), so even with telemetry SINGLE signals stay LEAD and only strong "
          "composite evidence (replay AND impossible-travel) would reach FACT"),
)

TELEMETRY_STUBS: dict = {
    s.domain: s for s in (C2_STUB, IDENTITY_GRAPH_STUB, CLOUD_STUB, SESSION_STUB)
}


def telemetry_stub(domain: object) -> Optional[TelemetryStub]:
    """Resolve a telemetry-plane stub by domain name; ``None`` for an unknown domain. Total."""
    return TELEMETRY_STUBS.get(str(domain or "").strip().lower())
