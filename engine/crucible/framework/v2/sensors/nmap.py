"""
sensors.nmap — the Nmap network-service sensor (Wave 2.2): the FIRST integration of a mature
external engine as a gated CRUCIBLE sensor, and the reference for every CLI adapter to come.

CRUCIBLE does not reimplement Nmap — it drives it as a SENSOR and reasons over what it reports. The
seam is the W2.1 framework end to end:

    invoke_tool (kill-switch / entitlement / scope / destructive / egress)  ->  NmapServiceSensor.run
    (bounded subprocess, fixed argv, no shell)  ->  normalize (parse -oX XML)  ->  service_observations
    (the SHARED HOST/SERVICE/HOSTS minter)  ->  IntelIngest  ->  the ONE world-model

Doctrine, by construction:
  * ACTIVE, so GATED harder than the declared reference sensor. Nmap SENDS probe packets at the
    target, so it is Tier-2 active-validation: it declares ``capability = ACTIVE_RECON`` (the
    entitlement gate refuses it without that grant) and the invoker scope-gates its ``args['target']``
    against the charter (so it can only ever scan an in-scope host). Correlatable, never evasive.
  * PROVE-DON'T-GUESS. An Nmap "open 443" is a provenance-labelled OBSERVATION (``IntelSourceKind
    .SCAN``, ``GROUNDING_INTEL``), NOT a fact — the W2.3 service-reachability oracle re-verifies "open"
    to a FACT only when a real handshake reproduces. A Sensor never writes a Finding.
  * DEGRADES CLEANLY. No ``nmap`` binary -> a failed ToolResult with a reason (never a crash, never a
    guess); the framework does not install it — a deployment that wants active discovery provisions it.
  * DETERMINISM. The scan OUTPUT reflects the live network, but ``parse -> service_observations ->
    project`` is a PURE, replayable function of that XML (caller ``seq``, no wallclock, no rng); a
    malformed scan yields zero observations, not an exception.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from xml.etree import ElementTree

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.models import Credibility, IntelSourceKind, Reliability, SourceReliability
from .base import service_observations

# An active first-party scan: a reliable source (we probed the host directly), content probably-true
# (a reported port state can still be filtered/misread — which is exactly why W2.3's oracle re-verifies
# "open" before it becomes a fact). Admiralty A2.
_NMAP_RELIABILITY = SourceReliability(reliability=Reliability.A, credibility=Credibility.C2)

_DEFAULT_TIMEOUT_S = 120

# One DNS label: 1-63 chars, alphanumeric-bounded (no leading/trailing hyphen).
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*\.?$")
# A valid nmap port spec: numbers, ranges, comma lists — always the VALUE of -p (one argv token), so
# it cannot inject a flag, but a malformed value should fail cleanly rather than reach nmap.
_PORTS_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")


def _ipv6_literal(target: str) -> str | None:
    """The bare IPv6 literal ``target`` denotes (accepting a bracketed ``[fe80::1]``
    or bare ``fe80::1`` single host), else None. nmap wants the bare form + ``-6``."""
    t = target.strip()
    inner = t[1:-1] if (t.startswith("[") and t.endswith("]")) else t
    try:
        return inner if ipaddress.ip_address(inner).version == 6 else None
    except ValueError:
        return None


def _is_single_host_target(target: str) -> bool:
    """True iff ``target`` is EXACTLY one host — a single IPv4/IPv6 literal or a single DNS hostname —
    and nothing nmap would expand or reinterpret. This is the AUTHORIZATION-CRITICAL guard: the
    invoker's charter-scope gate validates the hostname, but nmap honours a richer target syntax the
    URL parser silently drops — a CIDR/netmask ('10.0.0.5/24' → gate sees the base IP, nmap probes 256
    hosts), an octet range ('10.0.0.1-50'), a wildcard ('10.0.0.*'), a comma list, or a leading '-'
    (parsed as an nmap OPTION, e.g. --script/--datadir). Rejecting anything but a single host here
    guarantees the string handed to nmap is the SAME host the gate authorized. A single IPv6 literal
    (bare ``fe80::1`` or bracketed ``[fe80::1]``) is accepted now that the scope gate brackets a bare
    IPv6 before parsing (so it validates the SAME address nmap scans, run with ``-6``); an IPv6
    CIDR/range/list still contains ``/`` , ``,`` , ``*`` or a space and is refused above."""
    t = target.strip()
    if not t or t.startswith("-") or any(c in t for c in "/,*") or any(c.isspace() for c in t):
        return False
    if _ipv6_literal(t) is not None:
        return True   # a single IPv6 literal (bare or bracketed)
    try:
        return ipaddress.ip_address(t).version == 4   # a single IPv4 literal (not a range/CIDR/list)
    except ValueError:
        pass
    # a DNS hostname must contain a letter — else it is a numeric IP range/list nmap would expand.
    return any(c.isalpha() for c in t) and bool(_HOSTNAME_RE.match(t))


def parse_nmap_xml(xml: str) -> list[tuple[str, list[dict]]]:
    """Parse ``nmap -oX`` output into ``(host, services)`` structures the shared minter understands.

    Each host yields its address (an IP if present, else its first hostname) and a list of
    ``{"port", "protocol", "state", "service"?, "product"?, "version"?}`` dicts — the exact shape
    ``service_observations`` consumes (it keeps only OPEN services). PURE and total: any parse error
    (malformed / truncated / non-XML) returns ``[]`` so a bad scan degrades to no observations, never
    a crash."""
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, TypeError, ValueError):
        return []
    out: list[tuple[str, list[dict]]] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") not in (None, "", "up"):
            continue   # a host reported down mints nothing
        addr = None
        for a in host_el.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and a.get("addr"):
                addr = a.get("addr")
                break
        if not addr:
            hn = host_el.find("hostnames/hostname")
            addr = hn.get("name") if hn is not None else None
        if not addr:
            continue
        services: list[dict] = []
        for p in host_el.findall("ports/port"):
            portid = p.get("portid")
            if not portid:
                continue
            try:
                port = int(portid)
            except (TypeError, ValueError):
                continue
            st = p.find("state")
            item: dict = {
                "port": port,
                "protocol": (p.get("protocol") or "tcp"),
                "state": (st.get("state") if st is not None else "open") or "open",
            }
            svc = p.find("service")
            if svc is not None:
                for xml_key, out_key in (("name", "service"), ("product", "product"),
                                         ("version", "version")):
                    v = svc.get(xml_key)
                    if v:
                        item[out_key] = v
            services.append(item)
        out.append((str(addr), services))
    return out


class NmapServiceSensor:
    """Drive ``nmap`` (gated) against a single in-scope target and mint its open services into the
    world-model. args: ``{"target": "10.0.0.5", "ports": "1-1024"?}``. Active (Tier-2): requires the
    ``ACTIVE_RECON`` entitlement and is charter-scope-gated on ``args['target']`` by the invoker, and
    ``run`` additionally enforces that ``target`` is a SINGLE host (no CIDR/range/list/flag), so the
    host nmap probes is exactly the host the scope gate authorized — never a wider sweep."""

    name = "nmap"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False
    egress_hosts: tuple = ()   # the concrete target is scope-gated via args['target'] (not a fixed host)

    def __init__(self, timeout_s: int = _DEFAULT_TIMEOUT_S) -> None:
        self._timeout_s = timeout_s

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        target = args.get("target") if isinstance(args, dict) else None
        if not target or not isinstance(target, str):
            return ToolResult(ok=False, note="nmap requires args['target'] (a single in-scope host/IP)")
        # AUTHORIZATION-CRITICAL: only ever scan a SINGLE host — the exact host the invoker's scope gate
        # validated. A CIDR / range / list / flag-shaped target would let nmap probe hosts the gate
        # never authorized (see _is_single_host_target). Reject before touching the network.
        if not _is_single_host_target(target):
            return ToolResult(ok=False, note=(
                "nmap target must be a single host or IPv4 address — a CIDR, address range, list, "
                "wildcard, or option-like value is refused (it would scan beyond the scoped host)"))
        binary = shutil.which("nmap")
        if binary is None:
            return ToolResult(ok=False, note="nmap not on PATH (install to enable active service discovery)")
        argv = [binary, "-oX", "-", "-Pn", "-sV"]
        ports = args.get("ports") if isinstance(args, dict) else None
        if isinstance(ports, str) and ports.strip():
            if not _PORTS_RE.match(ports.strip()):
                return ToolResult(ok=False, note="nmap args['ports'] must be a port spec (e.g. '1-1024', '22,80,443')")
            argv += ["-p", ports.strip()]
        argv += ["--", target]   # end-of-options guard: the target can never be read as a flag
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv, capture_output=True, text=True, timeout=self._timeout_s, check=False)
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, note=f"nmap timed out after {self._timeout_s}s")
        except OSError as e:
            return ToolResult(ok=False, note=f"nmap failed to launch: {e}")
        if not (proc.stdout or "").strip():
            return ToolResult(ok=False,
                              note=f"nmap produced no XML (exit {proc.returncode}): {proc.stderr.strip()[:200]}")
        return ToolResult(ok=True, summary=f"nmap scanned {target}",
                          output={"xml": proc.stdout, "target": target})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        xml = out.get("xml")
        if not isinstance(xml, str) or not xml.strip():
            return []
        observations = []
        for host, services in parse_nmap_xml(xml):
            observations.extend(service_observations(
                host, services, seq=seq, source="nmap",
                source_kind=IntelSourceKind.SCAN, reliability=_NMAP_RELIABILITY))
        return observations
