"""Business-impact translation — turn confirmed findings into what they mean for the agency.

VIGIL's graph-theoretic `attack-paths` verb reasons over a MULTI-HOST spine; MERIDIAN is a single web host,
so the meaningful "attack path" here is how the confirmed web findings translate to citizen/agency impact.
This module maps each confirmed finding class to a plain-language business impact an official understands,
and surfaces multi-finding chains when their prerequisites are all confirmed. It is honest: a chain only
appears when every class it needs has actually been confirmed as a FACT.
"""

from __future__ import annotations

from dataclasses import dataclass

from .compliance import normalize

# per-family impact (fires when that class is confirmed)
_PER_CLASS: dict[str, tuple[str, str, str]] = {
    # family: (title, impact, severity)
    "sqli": ("SQL injection → public register dump",
             "An attacker reads the entire permit register directly from the database — every holder name, "
             "permit number and status — with a single crafted search.", "critical"),
    "idor": ("Broken object access → citizen-register exfiltration",
             "Any request can read any citizen's full identity record (name, national ID, phone, email) — "
             "mass exfiltration of the applicant register, a reportable personal-data breach.", "critical"),
    "broken_access_control": ("Back-office takeover / privilege escalation",
                              "An unauthenticated caller reaches staff and admin functions and can elevate "
                              "itself to administrator — full control of the licensing back office.", "critical"),
    "business_logic": ("Fee-payment bypass → revenue loss",
                       "Any permit fee can be marked PAID for $0 (or a negative amount) — systemic fee "
                       "evasion and direct loss of licensing revenue.", "high"),
    "ssrf": ("SSRF → internal reach",
             "The server fetches attacker-chosen URLs, letting an outsider reach internal services or a "
             "cloud metadata endpoint from inside the trust boundary.", "high"),
    "xss": ("Cross-site scripting → session hijack",
            "Injected script runs in a reviewer's browser, hijacking a staff session in the back office.", "high"),
    "exposure": ("Secret exposure",
                 "Application configuration (database credentials, signing secrets) is served to anyone — "
                 "the keys to move laterally.", "high"),
    "open_redirect": ("Open redirect → phishing",
                      "The portal will bounce a citizen to an attacker's site under the government domain — "
                      "a credible phishing lure against the public.", "medium"),
    "ssrf_xxe": ("XXE → out-of-band reach", "An imported XML document reaches attacker infrastructure.", "high"),
}


@dataclass(frozen=True)
class Chain:
    title: str
    impact: str
    chain: str
    severity: str
    needs: tuple[str, ...]


# multi-finding chains (appear only when EVERY needed class is confirmed)
_CHAINS: list[Chain] = [
    Chain("Full citizen-register breach",
          "Object-level access plus injection lets an attacker enumerate and exfiltrate the identity records "
          "of every applicant — a national-scale personal-data breach with mandatory notification.",
          "SQLi (register dump) + IDOR (per-citizen PII) → bulk export of the applicant register", "critical",
          ("sqli", "idor")),
    Chain("Fraudulent-permit issuance",
          "An attacker escalates to administrator and approves/issues permits at will while paying nothing — "
          "the licensing authority loses both control and revenue.",
          "privilege-escalation (admin) + business-logic (fee bypass) → self-issued, unpaid permits", "critical",
          ("broken_access_control", "business_logic")),
]


def chains_for(confirmed_findings: list[dict]) -> list[dict]:
    families = {normalize(f.get("bug_class", "")) for f in confirmed_findings}
    out: list[dict] = []
    # named multi-finding chains first (highest narrative value)
    for ch in _CHAINS:
        if all(n in families for n in ch.needs):
            out.append({"title": ch.title, "impact": ch.impact, "chain": ch.chain, "severity": ch.severity})
    # then the per-finding business impact of each confirmed class
    for fam in sorted(families):
        info = _PER_CLASS.get(fam)
        if info:
            title, impact, sev = info
            out.append({"title": title, "impact": impact, "chain": f"{fam} (confirmed)", "severity": sev})
    return out
