"""
detection.recon — the perimeter-reconnaissance oracles (RECON-SENTINEL).

Fires at the earliest kill-chain stage — "they mapped us" — over edge/flow telemetry:

  * ``port_scan``           — one source sweeping many distinct destination ports (Nmap/masscan) over a
    connection/flow log. FACT.
  * ``forced_browsing``     — one source generating many DISTINCT 404 paths in a window (ffuf/gobuster/
    dirsearch dictionary walking). FACT.
  * ``scanner_fingerprint`` — a self-identifying scanner User-Agent (Nuclei/Nikto/sqlmap/…) → FACT; a
    burst of distinct infra/secret-discovery paths (``/.git``,``/.env``,``/server-status``,admin) → LEAD
    (a path pattern is suggestive, a tool that names itself is proof).
  * ``cms_enumeration``     — a burst of distinct CMS paths / plugin walking (WPScan). FACT.
  * ``waf_probe``           — a wafw00f UA, or one source throwing MANY distinct attack classes to elicit
    a WAF (the "fingerprint the WAF" composite). LEAD only, per the doctrine (§4).

Benign twins that must stay silent: an uptime monitor (one port / one path, no spread), a robots-
respecting crawler (fetches real 200 pages, few 404s), a legitimate WordPress visitor (2-3 CMS paths,
not plugin walking), a normal client (no attack classes). Pure/deterministic/total; windows come from
the records' ts/seq, never a clock.

Import-clean: stdlib ``re`` + the detection base + the injection detectors (composite WAF probe).
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .base import DetectionOracle, Grade, OracleHit, group_by, windowed
from .injection import ATTACK_DETECTORS

# ---------------------------------------------------------------------------------------------------
# port_scan — over a connection/flow log (conntrack/NetFlow evidence)
# ---------------------------------------------------------------------------------------------------


class PortScanOracle(DetectionOracle):
    """One source contacting >= ``PORT_SPREAD`` distinct destination ports within a window. A legitimate
    uptime monitor hits one (or a handful of) fixed service port(s) → port-spread stays tiny → silent."""

    name = "port_scan"
    bug_class = "recon.port_scan"
    severity = "medium"
    evidence_kind = "conn_log"
    default_grade = Grade.FACT
    window_seconds = 120
    window_events = 400
    PORT_SPREAD = 15

    def _params(self) -> dict:
        return {**super()._params(), "port_spread": self.PORT_SPREAD}

    def evaluate(self, records: Any) -> Optional[OracleHit]:
        for src, evs in group_by(records, "src").items():
            def _spread(window: list) -> bool:
                return len({e.dport for e in window if getattr(e, "dport", 0)}) >= self.PORT_SPREAD
            window = windowed(evs, window_seconds=self.window_seconds,
                              window_events=self.window_events, predicate=_spread)
            if window:
                ports = sorted({e.dport for e in window if getattr(e, "dport", 0)})
                return OracleHit(
                    signature_kind="port-sweep",
                    summary=f"port scan: {src} swept {len(ports)} distinct ports "
                            f"(>= {self.PORT_SPREAD}) in a window",
                    evidence_records=tuple(window), source=src,
                    params={"distinct_ports": len(ports)},
                )
        return None


# ---------------------------------------------------------------------------------------------------
# forced_browsing — 404-walk density over access logs
# ---------------------------------------------------------------------------------------------------


class ForcedBrowsingOracle(DetectionOracle):
    """One source producing >= ``DISTINCT_404`` DISTINCT 404 paths in a window — dictionary/content
    discovery. A crawler fetches real pages (200s, few 404s); a monitor repeats one path → silent."""

    name = "forced_browsing"
    bug_class = "recon.forced_browsing"
    severity = "medium"
    evidence_kind = "access_log"
    default_grade = Grade.FACT
    window_seconds = 60
    window_events = 400
    DISTINCT_404 = 12

    def _params(self) -> dict:
        return {**super()._params(), "distinct_404": self.DISTINCT_404}

    def evaluate(self, records: Any) -> Optional[OracleHit]:
        for src, evs in group_by(records, "src").items():
            def _walk(window: list) -> bool:
                return len({e.route for e in window
                            if getattr(e, "status", 0) == 404 and getattr(e, "route", "")}) >= self.DISTINCT_404
            window = windowed(evs, window_seconds=self.window_seconds,
                              window_events=self.window_events, predicate=_walk)
            if window:
                distinct = len({e.route for e in window if getattr(e, "status", 0) == 404})
                return OracleHit(
                    signature_kind="dir-walk-404",
                    summary=f"forced browsing: {src} hit {distinct} distinct 404 paths "
                            f"(>= {self.DISTINCT_404}) in a window",
                    evidence_records=tuple(window), source=src,
                    params={"distinct_404_routes": distinct},
                )
        return None


# ---------------------------------------------------------------------------------------------------
# scanner_fingerprint — self-identifying UA (FACT) or a discovery-path burst (LEAD)
# ---------------------------------------------------------------------------------------------------

# Scanners that name themselves in the UA. curl / python-requests / Googlebot are DELIBERATELY absent —
# they are used by legitimate clients and monitors, so a UA match would be a false positive.
_SCANNER_UA_RE = re.compile(
    r"\b(nuclei|nikto|sqlmap|masscan|zgrab|wpscan|gobuster|feroxbuster|dirbuster|dirsearch|ffuf|"
    r"nmap\s+scripting\s+engine|nessus|openvas|acunetix|nuclei|wafw00f|arachni|w3af|whatweb|"
    r"httpx|katana|zaproxy|owasp\s+zap|burp\s?suite\s+professional)\b", re.I)

# Infra / secret / admin discovery paths a scanner hunts (distinct from CMS enumeration).
_SCANNER_PATH_MARKERS = (
    "/.git", "/.svn", "/.hg", "/.env", "/.aws", "/.ssh", "/.htaccess", "/.htpasswd", "/.ds_store",
    "/server-status", "/server-info", "/actuator", "/phpinfo", "/phpmyadmin", "/adminer",
    "/config.php", "/wp-config", "/.well-known/security", "/manager/html", "/solr", "/jenkins",
    "/console", "/.git/config", "/.env.local", "/backup", "/.aws/credentials")


def _scanner_ua(rec: Any) -> Optional[str]:
    ua = getattr(rec, "user_agent", "") or ""
    m = _SCANNER_UA_RE.search(ua)
    return m.group(1).lower() if m else None


def _is_scanner_path(route: str) -> bool:
    r = (route or "").lower()
    return any(marker in r for marker in _SCANNER_PATH_MARKERS)


class ScannerFingerprintOracle(DetectionOracle):
    """A self-identifying scanner UA → FACT; else a burst of >= ``PATH_BURST`` distinct discovery paths
    from one source → LEAD (a path pattern alone is not proof)."""

    name = "scanner_fingerprint"
    bug_class = "recon.scanner"
    severity = "medium"
    evidence_kind = "access_log"
    default_grade = Grade.FACT
    window_seconds = 120
    window_events = 400
    PATH_BURST = 3

    def _params(self) -> dict:
        return {**super()._params(), "path_burst": self.PATH_BURST}

    def evaluate(self, records: Any) -> Optional[OracleHit]:
        if not isinstance(records, (list, tuple)):
            return None
        # 1) a scanner that names itself → FACT
        for rec in records:
            name = _scanner_ua(rec)
            if name:
                return OracleHit(
                    signature_kind=f"scanner-ua:{name}",
                    summary=f"scanner fingerprint: self-identifying User-Agent {name!r}",
                    evidence_records=(rec,), grade=Grade.FACT,
                    source=getattr(rec, "src", "") or "",
                )
        # 2) a discovery-path burst → LEAD
        for src, evs in group_by(records, "src").items():
            def _burst(window: list) -> bool:
                return len({e.route for e in window if _is_scanner_path(getattr(e, "route", ""))}) >= self.PATH_BURST
            window = windowed(evs, window_seconds=self.window_seconds,
                              window_events=self.window_events, predicate=_burst)
            if window:
                hits = sorted({e.route for e in window if _is_scanner_path(getattr(e, "route", ""))})
                return OracleHit(
                    signature_kind="scanner-path-burst",
                    summary=f"scanner fingerprint (lead): {src} probed {len(hits)} discovery paths "
                            f"(>= {self.PATH_BURST}) — {hits[:5]}",
                    evidence_records=tuple(window), grade=Grade.LEAD, source=src,
                    params={"distinct_scanner_paths": len(hits)},
                )
        return None


# ---------------------------------------------------------------------------------------------------
# cms_enumeration — CMS/plugin path walking (WPScan)
# ---------------------------------------------------------------------------------------------------

_CMS_PATH_MARKERS = (
    "/wp-login.php", "/wp-admin", "/wp-json", "/wp-content/plugins/", "/wp-content/themes/",
    "/wp-includes/", "/xmlrpc.php", "/wp-cron.php", "/?author=", "/administrator/", "/user/login",
    "/changelog.txt", "/readme.txt", "/wp-config", "/droopescan", "/sites/default/")


def _is_cms_path(route: str, query: str = "") -> bool:
    r = (route or "").lower()
    q = (query or "").lower()
    if any(marker in r for marker in _CMS_PATH_MARKERS):
        return True
    return "author=" in q and r in ("/", "")


class CmsEnumerationOracle(DetectionOracle):
    """A burst of >= ``DISTINCT_CMS`` distinct CMS paths (plugin/theme/user walking) from one source. A
    normal CMS visitor touches a couple of CMS paths for one theme → below threshold → silent."""

    name = "cms_enumeration"
    bug_class = "recon.cms"
    severity = "medium"
    evidence_kind = "access_log"
    default_grade = Grade.FACT
    window_seconds = 120
    window_events = 400
    DISTINCT_CMS = 5

    def _params(self) -> dict:
        return {**super()._params(), "distinct_cms": self.DISTINCT_CMS}

    def evaluate(self, records: Any) -> Optional[OracleHit]:
        for src, evs in group_by(records, "src").items():
            def _enum(window: list) -> bool:
                return len({e.route for e in window
                            if _is_cms_path(getattr(e, "route", ""), getattr(e, "query", ""))}) >= self.DISTINCT_CMS
            window = windowed(evs, window_seconds=self.window_seconds,
                              window_events=self.window_events, predicate=_enum)
            if window:
                distinct = len({e.route for e in window
                                if _is_cms_path(getattr(e, "route", ""), getattr(e, "query", ""))})
                return OracleHit(
                    signature_kind="cms-path-walk",
                    summary=f"CMS enumeration: {src} walked {distinct} distinct CMS paths "
                            f"(>= {self.DISTINCT_CMS}) in a window",
                    evidence_records=tuple(window), source=src,
                    params={"distinct_cms_routes": distinct},
                )
        return None


# ---------------------------------------------------------------------------------------------------
# waf_probe — LEAD only (doctrine §4): wafw00f UA, or a multi-class attack burst
# ---------------------------------------------------------------------------------------------------


class WafProbeOracle(DetectionOracle):
    """LEAD-only WAF-fingerprint detection: a wafw00f UA, OR one source presenting >= ``CLASS_SPREAD``
    DISTINCT attack classes (the "throw everything to see what the WAF blocks" pattern). Graded LEAD
    because the same pattern is consistent with a genuine multi-vector attacker (the per-class injection
    oracles independently mint the FACTs)."""

    name = "waf_probe"
    bug_class = "recon.waf_probe"
    severity = "low"
    evidence_kind = "access_log"
    default_grade = Grade.LEAD
    window_seconds = 120
    window_events = 400
    CLASS_SPREAD = 3

    def _params(self) -> dict:
        return {**super()._params(), "class_spread": self.CLASS_SPREAD}

    @staticmethod
    def _classes(rec: Any) -> set:
        text = getattr(rec, "decoded_target", "") or getattr(rec, "target", "")
        raw = getattr(rec, "target", "")
        found = set()
        for cls, fn in ATTACK_DETECTORS.items():
            if fn(text) or fn(raw):
                found.add(cls)
        return found

    def evaluate(self, records: Any) -> Optional[OracleHit]:
        if not isinstance(records, (list, tuple)):
            return None
        for rec in records:
            ua = (getattr(rec, "user_agent", "") or "").lower()
            if "wafw00f" in ua:
                return OracleHit(
                    signature_kind="waf-probe-ua",
                    summary="WAF probe (lead): wafw00f User-Agent",
                    evidence_records=(rec,), grade=Grade.LEAD,
                    source=getattr(rec, "src", "") or "",
                )
        for src, evs in group_by(records, "src").items():
            def _spread(window: list) -> bool:
                seen = set()
                for e in window:
                    seen |= self._classes(e)
                    if len(seen) >= self.CLASS_SPREAD:
                        return True
                return False
            window = windowed(evs, window_seconds=self.window_seconds,
                              window_events=self.window_events, predicate=_spread)
            if window:
                seen = set()
                for e in window:
                    seen |= self._classes(e)
                return OracleHit(
                    signature_kind="waf-probe-multiclass",
                    summary=f"WAF probe (lead): {src} presented {len(seen)} attack classes "
                            f"{sorted(seen)} (>= {self.CLASS_SPREAD})",
                    evidence_records=tuple(window), grade=Grade.LEAD, source=src,
                    params={"attack_classes": sorted(seen)},
                )
        return None
