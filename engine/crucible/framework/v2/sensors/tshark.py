"""
sensors.tshark — the packet/flow sensor (Wave 3.2): a mature packet engine (Wireshark's ``tshark``)
driven as a gated sensor over an operator-provided PCAP.

CRUCIBLE does not reimplement packet dissection — it drives tshark and reasons over what it reports.
The sensor reads a capture the operator supplies (their own authorized traffic — passive, offline, no
network, like the SBOM / cloud file-ingest paths) and mints three high-signal, unambiguous observation
families into the ONE world-model:

  * OPEN SERVICES — a TCP SYN-ACK proves the responding endpoint accepted a connection, so its
    (ip, port) is an open SERVICE (reuses the shared ``service_observations`` minter).
  * DNS RESOLUTIONS — a query name is a DOMAIN; each answer address is a ``DOMAIN --RESOLVES_TO--> HOST``.
  * TLS SNI — a client's requested server name is a DOMAIN.

Doctrine, by construction:
  * PASSIVE / OFFLINE. It reads a local pcap FILE (``tshark -r``); it sends no packets and reaches no
    host, so it is Tier-1, no egress, no entitlement — gated only by the kill-switch via ``invoke_tool``.
    The pcap is operator-provided authorized capture; its observations are provenance-labelled
    GROUNDING_INTEL (``PACKET_CAPTURE``), never a fact until a scope-gated oracle (reachability / TLS)
    re-verifies them live.
  * DEGRADES CLEANLY. No ``tshark`` binary, or a missing/unreadable pcap -> a failed ToolResult with a
    reason (never a crash); the framework does not install it.
  * DETERMINISM. tshark's OUTPUT reflects the capture, but ``parse -> observations`` is a PURE,
    replayable function of that output (caller ``seq``, no wallclock, no rng); a malformed line is
    skipped, never raised.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef, canonicalize
from ..worldmodel.models import EdgeKind, NodeKind
from .base import service_observations

# Captured traffic: a reliable first-party observation (we hold the pcap), content probably-true — a
# SYN-ACK / DNS answer / SNI is real, but historical and re-verified live before it becomes a fact.
_PCAP_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)

_DEFAULT_TIMEOUT_S = 120
_SEP = "\t"

# The fixed ``-e`` field order tshark emits (tab-separated, one row per packet). Parsing is by column,
# so this list and _parse_row must stay in lockstep.
_FIELDS: tuple[str, ...] = (
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.srcport",
    "dns.qry.name", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name",
)


def parse_tshark_fields(text: str) -> dict:
    """Parse ``tshark -T fields`` output (our fixed ``_FIELDS`` order, tab-separated) into typed,
    de-duplicated records: ``{"services": [(host, port)], "dns": [(qname, (answers...))],
    "sni": [name]}``. PURE and total — a short/blank/garbled line is skipped, never raised. Records
    are returned in deterministic (sorted) order so obs minting is order-independent."""
    services: set[tuple[str, str]] = set()
    dns: dict[tuple[str, tuple[str, ...]], bool] = {}
    sni: set[str] = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        cols = line.split(_SEP)
        if len(cols) < len(_FIELDS):
            cols = cols + [""] * (len(_FIELDS) - len(cols))
        (ip_src, ip_dst, ip6_src, ip6_dst, syn, ack, tcp_sport,
         qname, dns_a, dns_aaaa, srv_name) = cols[:len(_FIELDS)]
        src = (ip_src or ip6_src).strip()
        # an OPEN service: a SYN-ACK (syn & ack set) means the SOURCE accepted the connection.
        if _flag_set(syn) and _flag_set(ack) and src and tcp_sport.strip():
            port = tcp_sport.split(",")[0].strip()
            if port.isdigit():
                services.add((src, port))
        # a DNS resolution: the query name is a domain; each answer address resolves it. tshark comma-
        # joins multiple questions into one field, so split (as for SNI/answers) and validate each name.
        if qname.strip():
            names = [n for n in (_clean_name(q) for q in qname.split(",")) if n]
            answers = tuple(sorted(
                a.strip() for a in (dns_a.split(",") + dns_aaaa.split(","))
                if _is_ip(a.strip())))
            if len(names) == 1:
                dns[(names[0], answers)] = True     # single question: pair the answers to it
            else:
                for name in names:                  # multi-question: ambiguous pairing, mint names only
                    dns.setdefault((name, ()), True)
        # a TLS SNI: the client's requested server name is a domain.
        if srv_name.strip():
            for n in srv_name.split(","):
                cn = _clean_name(n)
                if cn:
                    sni.add(cn)
    return {"services": sorted(services), "dns": sorted(dns), "sni": sorted(sni)}


def _flag_set(value: str) -> bool:
    """A tshark ``-T fields`` boolean flag is set. tshark renders boolean fields as ``True``/``False``
    (verified empirically on a real SYN-ACK) — older builds used ``1``/``0`` — so accept both, case-
    insensitively. Anything else (``False`` / ``0`` / empty) is unset."""
    return value.strip().lower() in ("1", "true")


# A DNS name: dot-separated LDH labels (underscore allowed for SRV/DNS-SD/mDNS names like
# ``_airplay._tcp.local``), total <= 253 chars, each label <= 63 and alphanumeric-bounded.
_DNS_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_DNS_NAME_RE = re.compile(rf"\A{_DNS_LABEL}(?:\.{_DNS_LABEL})*\Z")   # \Z (not $) — no trailing-newline match


def _clean_name(name: str) -> str:
    """Normalise a captured query/SNI name to a valid DNS domain, or "" to skip it. Rejects reverse-DNS
    (``.arpa``), an IP literal (that is a HOST, not a DOMAIN — wrong tier), and anything that is not a
    structurally valid DNS name (a comma-joined multi-value, a backslash-escaped control byte, a slash,
    whitespace) so the sensor never mints a garbage DOMAIN node."""
    n = (name or "").strip().rstrip(".").lower()
    if not n or n.endswith(".arpa") or _is_ip(n):
        return ""
    return n if _DNS_NAME_RE.match(n) else ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _mint(subject: EntityRef, *, seq: int, rel: EdgeKind | None = None,
          obj: EntityRef | None = None, conf: float) -> Observation:
    r = rel.value if rel else ""
    o = obj.node_id if obj else ""
    return Observation(
        obs_id=f"tshark:{seq}:{subject.node_id}|{r}|{o}",
        source="tshark", source_kind=IntelSourceKind.PACKET_CAPTURE, collector="tshark",
        subject=subject, relation=rel, object=obj,
        source_reliability=_PCAP_RELIABILITY, confidence=conf, seq=seq)


def _observations_from_records(parsed: dict, *, seq: int) -> list[Observation]:
    """Mint observations from parsed records — the pure normalize core (no I/O), so tests exercise it
    directly. Claim-keyed obs_ids (like the shared minter) make re-ingest idempotent."""
    out: list[Observation] = []
    by_host: dict[str, list[dict]] = {}
    for host, port in parsed.get("services", []):
        by_host.setdefault(host, []).append({"port": port, "protocol": "tcp"})
    for host in sorted(by_host):
        out.extend(service_observations(
            host, by_host[host], seq=seq, source="tshark",
            source_kind=IntelSourceKind.PACKET_CAPTURE, reliability=_PCAP_RELIABILITY))
    for name, answers in parsed.get("dns", []):
        dom = canonicalize(NodeKind.DOMAIN, name)
        out.append(_mint(dom, seq=seq, conf=0.9))                       # the domain was observed
        for addr in answers:
            out.append(_mint(dom, seq=seq, rel=EdgeKind.RESOLVES_TO,
                             obj=canonicalize(NodeKind.HOST, addr), conf=0.9))
    for name in parsed.get("sni", []):
        out.append(_mint(canonicalize(NodeKind.DOMAIN, name), seq=seq, conf=0.85))
    return out


class TsharkFlowSensor:
    """Read an operator-provided pcap with ``tshark`` and mint open-service / DNS / TLS-SNI
    observations. args: ``{"pcap": "/path/to/capture.pcap", "display_filter": "..."?}``. Passive
    (Tier-1): no network, no egress, no entitlement — reads a local file the operator supplied."""

    name = "tshark_flow"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def __init__(self, timeout_s: int = _DEFAULT_TIMEOUT_S) -> None:
        self._timeout_s = timeout_s

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        pcap = args.get("pcap") if isinstance(args, dict) else None
        if not pcap or not isinstance(pcap, str):
            return ToolResult(ok=False, note="tshark_flow requires args['pcap'] (a path to a capture file)")
        if not os.path.isfile(pcap):
            return ToolResult(ok=False, note=f"tshark_flow: pcap not found: {pcap}")
        binary = shutil.which("tshark")
        if binary is None:
            return ToolResult(ok=False, note="tshark not on PATH (install wireshark to enable packet analysis)")
        argv = [binary, "-r", pcap, "-T", "fields", "-E", f"separator={_SEP}"]
        for f in _FIELDS:
            argv += ["-e", f]
        display_filter = args.get("display_filter") if isinstance(args, dict) else None
        if isinstance(display_filter, str) and display_filter.strip():
            argv += ["-Y", display_filter.strip()]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell; pcap is -r's value, not a flag
                argv, capture_output=True, text=True, timeout=self._timeout_s, check=False)
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, note=f"tshark timed out after {self._timeout_s}s")
        except OSError as e:
            return ToolResult(ok=False, note=f"tshark failed to launch: {e}")
        if proc.returncode != 0 and not (proc.stdout or "").strip():
            return ToolResult(ok=False, note=f"tshark exited {proc.returncode}: {proc.stderr.strip()[:200]}")
        return ToolResult(ok=True, summary=f"tshark read {os.path.basename(pcap)}",
                          output={"fields": proc.stdout, "pcap": pcap})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        text = out.get("fields")
        if not isinstance(text, str) or not text.strip():
            return []
        return _observations_from_records(parse_tshark_fields(text), seq=seq)
