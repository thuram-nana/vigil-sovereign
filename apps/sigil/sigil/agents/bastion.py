"""BASTION (SIGIL §4.8) — defensive security posture over the owner's OWN infrastructure ONLY.
Ceiling A1 (writes findings; remediation/patching is A3 and never taken here). Checks: TLS cert
expiry, dependency CVE exposure, and uptime — all OBSERVATIONAL. There is NO exploit, no port
sweep, no third-party target: BASTION iterates an allowlisted asset INVENTORY, and any target not
in that allowlist is REFUSED and logged (`refusal` record). This makes "own systems only" a
structural property, not a promise (SIGIL §4.8 doctrine; enforced, not documented).

GROUNDING (serve-the-quote, reused from SCHOLAR/consolidation): every finding carries the verbatim
observed fact it stands on — the real cert `notAfter`, the exact manifest line, the probe status —
never a model's guess. A dependency is flagged ONLY when its parsed version PROVABLY falls in an
advisory's affected range; an unparseable version is a non-assessment, never a fabricated CVE."""
from __future__ import annotations

import re
import ssl
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Protocol, Tuple, runtime_checkable

from .base import Agent, AgentResult, Proposal, Tier

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([0-9][0-9A-Za-z.\-]*)")


@dataclass(frozen=True)
class Asset:
    """One allowlisted own-infra asset. `kind` ∈ {tls, deps, uptime}; `ref` is host:port / manifest
    path / url. Membership in the inventory IS the authorization to observe it."""
    name: str
    kind: str
    ref: str
    meta: Optional[dict] = None


# --- version reasoning (strict, fail-closed to NON-assessment — never a fabricated vuln) ----------
def _ver_tuple(v: Optional[str]) -> Optional[tuple]:
    """A purely numeric dotted version → tuple; anything else (rc/beta/git/empty) → None (can't
    assess). Being strict here is what keeps CVE matching near-zero-false-positive."""
    if not v:
        return None
    parts = str(v).strip().lstrip("vV").split(".")
    out = []
    for p in parts:
        # ASCII decimals ONLY — str.isdigit() also accepts superscripts/other-script digits that
        # int() rejects or reinterprets, so guard on isascii() too (truly fail-closed, never a crash).
        if not (p.isascii() and p.isdigit()):
            return None
        out.append(int(p))
    return tuple(out) if out else None


def _cmp(a: tuple, b: tuple) -> int:
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _affected(version: str, introduced: Optional[str], fixed: Optional[str]) -> Optional[bool]:
    """True iff introduced <= version < fixed. None if it cannot be proven either way (unparseable
    version/bound) — the caller treats None as 'no finding' (honest non-assessment)."""
    vt = _ver_tuple(version)
    if vt is None:
        return None
    it = _ver_tuple(introduced) if introduced else (0,)
    if it is None:
        return None
    if fixed:
        ft = _ver_tuple(fixed)
        if ft is None:
            return None
        if _cmp(vt, ft) >= 0:
            return False
    return _cmp(vt, it) >= 0


# --- capture seams (real by default, injectable doubles for offline tests) ------------------------
@runtime_checkable
class CertSource(Protocol):
    def pem(self, ref: str) -> Optional[str]: ...    # ref="host:port" → leaf cert PEM, or None


@runtime_checkable
class UptimeSource(Protocol):
    def probe(self, ref: str) -> Tuple[bool, int]: ...   # (up, status_code)


class SocketCertSource:
    """Fetch the leaf TLS cert from an OWN host. Only ever called for allowlisted refs (BASTION
    guards before calling). Returns None on any error (no reachable cert = no finding)."""
    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    def pem(self, ref: str) -> Optional[str]:
        host, _, port = ref.partition(":")
        try:
            return ssl.get_server_certificate((host, int(port or 443)), timeout=self.timeout)
        except (OSError, ssl.SSLError, ValueError):
            return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow 3xx. A redirect target is chosen by the (possibly compromised) allowlisted
    server and is NOT itself allowlisted — following it would let BASTION's probe reach a host outside
    the own-infra scope, silently and un-audited (red-pen RP-BASTION-01). The 3xx is the status."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibUptimeSource:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)   # never auto-follows a redirect

    def probe(self, ref: str) -> Tuple[bool, int]:
        try:
            req = urllib.request.Request(ref, method="HEAD",
                                         headers={"User-Agent": "SIGIL-BASTION/1.0 (own-infra uptime)"})
            with self._opener.open(req, timeout=self.timeout) as r:
                return (200 <= r.status < 500, r.status)
        except urllib.error.HTTPError as e:       # a 5xx is 'down'; a 3xx (not followed) is 'up' + its code
            return (e.code < 500, e.code)
        except (OSError, ValueError):
            return (False, 0)


class Bastion(Agent):
    name = "BASTION"
    mandate = "defensive posture over OWN infrastructure only; observe, never remediate"
    ceiling = Tier.A1

    def __init__(self, store=None, *, inventory: Optional[List[Asset]] = None,
                 cve_feed: Optional[List[dict]] = None,
                 cert_source: Optional[CertSource] = None,
                 uptime_source: Optional[UptimeSource] = None):
        super().__init__(store)
        self.inventory = list(inventory or [])
        self._allow = {a.ref for a in self.inventory}          # THE own-infra allowlist
        self.cve_feed = list(cve_feed or [])
        self.cert_source = cert_source or SocketCertSource()
        self.uptime_source = uptime_source or UrllibUptimeSource()

    # --- scope doctrine (structural own-infra-only) -----------------------------------------------
    def _refuse(self, ref: str, reason: str) -> int:
        return self.store.append(
            kind="refusal", source="agent", actor=self.name,
            payload={"agent": self.name, "tier": "A0", "decision": "refused", "requested": ref,
                     "reason": reason,
                     "doctrine": "BASTION observes only the allowlisted own-infra inventory (SIGIL §4.8); "
                                 "no third-party scanning, no exploit tooling."})

    def probe_target(self, ref: str, kind: str, *, now_iso: Optional[str] = None) -> AgentResult:
        """Guarded ad-hoc entry. A ref outside the own-infra allowlist is REFUSED and logged — it is
        never scanned. This is the doctrine's structural teeth."""
        if ref not in self._allow:
            self._refuse(ref, "ad-hoc target is not in the own-infra allowlist")
            res = AgentResult(agent=self.name)
            res.notes.append(f"REFUSED {ref}: outside own-infra scope (logged, not scanned)")
            return res
        return self._dispatch(self._assess(Asset(name=ref, kind=kind, ref=ref), now_iso=now_iso))

    def _assess(self, asset: Asset, *, now_iso: Optional[str] = None) -> List[Proposal]:
        if asset.ref not in self._allow:            # defense in depth — never scan an unlisted ref
            self._refuse(asset.ref, "asset not in the own-infra allowlist")
            return []
        if asset.kind == "tls":
            return self._cert(asset, now_iso)
        if asset.kind == "deps":
            return self._deps(asset)
        if asset.kind == "uptime":
            return self._uptime(asset)
        return []

    # --- scanners (observational; each finding carries its verbatim ground truth) -----------------
    def _cert(self, asset: Asset, now_iso: Optional[str]) -> List[Proposal]:
        pem = self.cert_source.pem(asset.ref)
        if not pem:
            return []
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(pem.encode())
            not_after = getattr(cert, "not_valid_after_utc", None) or \
                cert.not_valid_after.replace(tzinfo=timezone.utc)
        except Exception:  # noqa: BLE001 — an unparseable cert is no finding, not a crash
            return []
        now = datetime.fromisoformat(now_iso) if now_iso else datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        days = (not_after - now).days
        threshold = (asset.meta or {}).get("expiry_days", 30)
        if days > threshold:
            return []
        sev = "critical" if days <= 0 else ("high" if days <= 7 else "medium")
        state = "EXPIRED" if days < 0 else f"expires in {days}d"
        return [Proposal("finding", {
            "check": "tls-cert-expiry", "asset": asset.name, "ref": asset.ref, "severity": sev,
            "days_to_expiry": days,
            "quote": f"notAfter={not_after.isoformat()}",         # verbatim observed ground truth
            "summary": f"TLS cert for {asset.name} {state} ({not_after.date()})",
            "assessed_at": now.isoformat()}, Tier.A1)]

    def _deps(self, asset: Asset) -> List[Proposal]:
        try:
            lines = Path(asset.ref).read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []
        props: List[Proposal] = []
        for raw in lines:
            m = _PIN.match(raw.strip())
            if not m:
                continue
            pkg, ver = m.group(1).lower(), m.group(2)
            for adv in self.cve_feed:
                if str(adv.get("package", "")).lower() != pkg:
                    continue
                if _affected(ver, adv.get("introduced"), adv.get("fixed")) is not True:
                    continue                         # only a PROVEN match fires (None/False → skip)
                props.append(Proposal("finding", {
                    "check": "dependency-cve", "asset": asset.name, "ref": asset.ref,
                    "severity": str(adv.get("severity", "medium")), "cve": adv.get("id"),
                    "package": pkg, "version": ver,
                    "quote": raw.strip(),            # verbatim manifest line — the ground truth
                    "advisory": f"{adv.get('id')}: affected {adv.get('introduced') or '0'} "
                                f"..< {adv.get('fixed') or '∞'}",
                    "summary": f"{pkg} {ver} is affected by {adv.get('id')} "
                               f"({str(adv.get('summary', ''))[:60]})",
                    "fixed_in": adv.get("fixed")}, Tier.A1))
        return props

    def _uptime(self, asset: Asset) -> List[Proposal]:
        up, status = self.uptime_source.probe(asset.ref)
        if up:
            return []
        return [Proposal("finding", {
            "check": "uptime", "asset": asset.name, "ref": asset.ref, "severity": "high",
            "quote": f"HEAD {asset.ref} → status={status}",
            "summary": f"{asset.name} appears DOWN (probe status {status})"}, Tier.A1)]

    @staticmethod
    def _key(payload: dict) -> tuple:
        """A finding's IDENTITY: (asset, check, cve). The `cve` discriminator keeps N concurrent CVEs
        on one manifest distinct (RP-2) and lets a re-run resolve exactly the right prior finding."""
        return (payload.get("asset"), payload.get("check"), payload.get("cve"))

    def _resolutions(self, fired_keys: set) -> List[Proposal]:
        """For any (asset,check,cve) we flagged before that this run did NOT re-flag — and whose asset
        we actually re-assessed — emit a `resolved` supersession, so the brief stops presenting a fixed
        problem as current (RP-1/RP-5). A resolution supersedes the stale finding (latest wins)."""
        assessed = {a.name for a in self.inventory}
        latest: dict = {}
        for r in self.store.iter_records():
            if r.kind == "finding" and r.actor == self.name:
                latest[self._key(r.payload)] = r        # iter is seq-ascending → last seen = newest
        props: List[Proposal] = []
        for key, r in latest.items():
            if r.payload.get("resolved"):
                continue                                # already resolved — don't churn
            asset_name, check, cve = key
            if asset_name in assessed and key not in fired_keys:
                props.append(Proposal("finding", {
                    "check": check, "asset": asset_name, "cve": cve, "resolved": True,
                    "severity": "info", "resolves_seq": r.seq,
                    "summary": f"{asset_name} {check}{(' ' + str(cve)) if cve else ''} resolved — re-assessed clean",
                    "quote": "resolved: prior finding no longer reproduces"},
                    Tier.A1, supersedes_id=r.seq))
        return props

    def run(self, *, now_iso: Optional[str] = None) -> AgentResult:
        proposals: List[Proposal] = []
        for asset in self.inventory:
            proposals.extend(self._assess(asset, now_iso=now_iso))
        fired = {self._key(p.payload) for p in proposals}
        resolutions = self._resolutions(fired)
        res = self._dispatch(proposals + resolutions)
        res.notes.append(f"assessed {len(self.inventory)} own-infra asset(s) → {len(proposals)} finding(s)"
                         + (f", {len(resolutions)} resolved" if resolutions else ""))
        return res
