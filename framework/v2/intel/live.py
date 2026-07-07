"""
intel.live — gated live recon against real third-party sources.

Everything upstream of this module is offline: collectors parse a CANONICAL payload
shape served by a `Transport`. This module is the only place that knows about the
actual public APIs — their URLs and their (messy, per-vendor) JSON — and it maps each
real response back onto that canonical shape. That keeps the collectors stable and
testable while making live collection real.

The sources are public, third-party, passive recon endpoints — a DNS-over-HTTPS
resolver, a Certificate Transparency log, an RDAP server, a BGP/ASN stat service.
They are queried ABOUT the target; they are never the target. Live collection stays a
deliberate, gated opt-in:

  * `build_live_transport` returns a `GuardedHttpTransport` whose allowlist is exactly
    these source hosts, disjoint from target scope (the transport refuses construction
    on overlap and refuses any off-allowlist host before bytes leave).
  * responses can be mirrored to a capture dir, so one authorized live run seeds the
    offline fixture corpus for deterministic replay thereafter.

Every normalizer is TOTAL: malformed / unexpected JSON yields an empty canonical
payload, never an exception — a flaky source degrades to "found nothing", exactly as
a missing fixture does.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .models import IntelSourceKind

# Public passive-recon endpoints. `{query}` is substituted with the (already-canonical)
# subject key. These hosts form the default collector allowlist — disjoint from target
# scope by construction (they are third-party sources, never the engagement target).
LIVE_ENDPOINTS: dict[IntelSourceKind, str] = {
    IntelSourceKind.DNS: "https://dns.google/resolve?name={query}&type=ANY",
    IntelSourceKind.CERT_TRANSPARENCY: "https://crt.sh/?q={query}&output=json",
    IntelSourceKind.RDAP_WHOIS: "https://rdap.org/domain/{query}",
    IntelSourceKind.ASN_BGP: "https://stat.ripe.net/data/network-info/data.json?resource={query}",
}

DEFAULT_COLLECTOR_HOSTS: tuple[str, ...] = (
    "dns.google", "crt.sh", "rdap.org", "stat.ripe.net",
)


# ---------------------------------------------------------------------------
# response normalizers: real API JSON → the collectors' canonical payload
# ---------------------------------------------------------------------------

# DoH RR type numbers we care about.
_DOH_A, _DOH_AAAA, _DOH_CNAME = 1, 28, 5


def _normalize_dns(payload: Any) -> dict:
    """Google/Cloudflare DoH JSON → {"A": [...], "AAAA": [...], "CNAME": [...]}."""
    out: dict[str, list[str]] = {"A": [], "AAAA": [], "CNAME": []}
    if not isinstance(payload, dict):
        return out
    for ans in payload.get("Answer", []) or []:
        if not isinstance(ans, dict):
            continue
        t, data = ans.get("type"), str(ans.get("data", "")).strip().rstrip(".")
        if not data:
            continue
        if t == _DOH_A:
            out["A"].append(data)
        elif t == _DOH_AAAA:
            out["AAAA"].append(data)
        elif t == _DOH_CNAME:
            out["CNAME"].append(data)
    return out


def _normalize_ct(payload: Any) -> list:
    """crt.sh JSON (list of log entries) → [{"fingerprint", "names", "not_after"}].

    crt.sh has no SHA-256 in its default output; ``name_value`` is a newline-separated
    SAN list. A stable per-cert key is synthesized from serial+issuer (or the entry id),
    so two domains on the SAME logged cert still collapse to one certificate node."""
    out: list[dict] = []
    if not isinstance(payload, list):
        return out
    for e in payload:
        if not isinstance(e, dict):
            continue
        names = [n.strip().lstrip("*.") for n in str(e.get("name_value", "")).split("\n") if n.strip()]
        cn = str(e.get("common_name", "")).strip().lstrip("*.")
        if cn:
            names.append(cn)
        if not names:
            continue
        raw_key = str(e.get("serial_number") or "") + "|" + str(e.get("issuer_ca_id") or "")
        fp = (hashlib.sha256(raw_key.encode()).hexdigest() if raw_key.strip("|")
              else str(e.get("id") or e.get("min_cert_id") or ""))
        out.append({"fingerprint": fp, "names": sorted(set(names)),
                    "not_after": str(e.get("not_after", ""))})
    return out


def _normalize_rdap(payload: Any) -> dict:
    """RDAP domain/ip JSON → {"org", "netblock", "asn", "registrar", "handle"}.

    RDAP nests the registrant under ``entities[].vcardArray``; org is the vCard ``fn``.
    IP objects carry ``cidr0_cidrs`` / start-end addresses for the netblock."""
    out: dict[str, str] = {}
    if not isinstance(payload, dict):
        return out
    out["handle"] = str(payload.get("handle", ""))
    # organisation + registrant email from the first entity carrying an fn.
    for ent in payload.get("entities", []) or []:
        if not isinstance(ent, dict):
            continue
        fn = _vcard_fn(ent.get("vcardArray"))
        if fn:
            out["org"] = fn
            roles = ent.get("roles") or []
            if "registrar" in roles:
                out.setdefault("registrar", fn)
            email = _vcard_field(ent.get("vcardArray"), "email")
            if email:
                out["registrant_email"] = email
            break
    # nameservers (weak infra signal, carried for context).
    ns = [str(n.get("ldhName", "")).strip().lower()
          for n in (payload.get("nameservers") or []) if isinstance(n, dict) and n.get("ldhName")]
    if ns:
        out["nameservers"] = ",".join(sorted(set(n for n in ns if n)))
    # netblock (IP objects): cidr0_cidrs preferred, else start/end.
    cidrs = payload.get("cidr0_cidrs") or []
    if isinstance(cidrs, list) and cidrs and isinstance(cidrs[0], dict):
        c = cidrs[0]
        pfx = c.get("v4prefix") or c.get("v6prefix")
        length = c.get("length")
        if pfx and length is not None:
            out["netblock"] = f"{pfx}/{length}"
    return out


def _vcard_field(vcard_array: Any, field: str) -> str:
    """Pull a named property (``fn``, ``email``, …) out of a jCard ``vcardArray``."""
    try:
        for p in vcard_array[1]:
            if isinstance(p, list) and p and p[0] == field:
                return str(p[3]).strip()
    except (TypeError, IndexError, KeyError):
        pass
    return ""


def _vcard_fn(vcard_array: Any) -> str:
    return _vcard_field(vcard_array, "fn")


def _normalize_asn(payload: Any) -> dict:
    """RIPEstat network-info JSON → {"asn", "netblock", "holder"}."""
    out: dict[str, str] = {}
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return out
    asns = data.get("asns") or []
    if isinstance(asns, list) and asns:
        out["asn"] = f"AS{str(asns[0]).lstrip('AS')}"
    pfx = data.get("prefix")
    if pfx:
        out["netblock"] = str(pfx)
    return out


_NORMALIZERS = {
    IntelSourceKind.DNS: _normalize_dns,
    IntelSourceKind.CERT_TRANSPARENCY: _normalize_ct,
    IntelSourceKind.RDAP_WHOIS: _normalize_rdap,
    IntelSourceKind.ASN_BGP: _normalize_asn,
}


def normalize_response(source_kind: IntelSourceKind, payload: Any) -> dict | list:
    """Map a live source's raw JSON onto the collectors' canonical payload shape.
    Total: any unexpected shape yields an empty payload, never raises."""
    fn = _NORMALIZERS.get(source_kind)
    if fn is None:
        return {} if not isinstance(payload, list) else []
    try:
        return fn(payload)
    except Exception:
        return [] if source_kind is IntelSourceKind.CERT_TRANSPARENCY else {}


def build_live_transport(
    *,
    collector_hosts: tuple[str, ...] = DEFAULT_COLLECTOR_HOSTS,
    target_hosts: tuple[str, ...] = (),
    capture_dir: "object | None" = None,
    client: object | None = None,
):
    """Construct a gated, allowlisted `GuardedHttpTransport` for the live sources, with
    per-source response normalization wired in. ``target_hosts`` (when given) makes the
    transport REFUSE construction if any source host overlaps target scope. Live runs
    can mirror to ``capture_dir`` to seed the offline corpus."""
    from .transport import GuardedHttpTransport

    return GuardedHttpTransport(
        collector_hosts=collector_hosts,
        endpoints=LIVE_ENDPOINTS,
        target_hosts=target_hosts,
        capture_dir=capture_dir,  # type: ignore[arg-type]
        client=client,
        response_normalizer=normalize_response,
    )
