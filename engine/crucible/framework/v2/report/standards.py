"""
report.standards — deterministic compliance + ATT&CK mapping (flagship C3).

A PURE, data-driven mapper from a finding's ``bug_class`` (the oracle vocabulary in
``verify.verifier.BUG_CLASS_ORACLES``) to the standards controls it implicates:

  * OWASP Top 10:2021          — the single best-fit category (or ``None``)
  * CWE                        — the Common Weakness Enumeration id(s)
  * PCI DSS v4.0               — the implicated requirement(s)
  * SOC 2 (AICPA TSC 2017)     — the Trust Services Criteria
  * ISO/IEC 27001:2022 Annex A — the Annex A control(s)
  * MITRE ATT&CK v15           — the technique id(s) (AI/LLM classes use MITRE ATLAS, ``AML.*``)

The whole point of this module is the HONESTY rule, and it is enforced structurally:

  A mapping is *data* — the controls a weakness of that class WOULD implicate. It becomes
  an ASSERTION OF COVERAGE only for a finding the deterministic oracle actually PROVED.

  ``map_finding`` grades every finding through the SAME authority the rest of the report
  package uses — ``report.grounding.grade_finding``, which RE-EXECUTES the finding's
  retained ``oracle_context`` NOW. Only a re-firing proof (grade == ``fact``) yields
  ``coverage_asserted: True`` with the controls under the ``controls`` key. A LEAD or a
  DEMOTED finding (a stored ``verified_by_oracle`` flag that no longer reproduces) is
  capped at an advisory NOTE: its ``controls`` key is ``None`` and the mapping is echoed
  only under ``advisory`` — so a LEAD can never claim control coverage. A raw dict that
  merely *claims* ``verified_by_oracle=True`` is not trusted; the oracle must re-fire.

``coverage_matrix`` grades a set of findings into a control matrix that distinguishes
tested-and-PROVEN from tested-with-no-finding (clear) from NOT-TESTED — it never implies
coverage of a surface that was not tested (a control is ``tested_clear`` only when its
class is explicitly in ``tested_bug_classes``).

``compliance_attestation`` is a deterministic, signable summary (a plain structured dict
with a canonical ``content_digest`` the caller can sign later — no crypto is invented here).

Purity + determinism: frozen tables, sorted outputs, and NO wallclock / RNG on any path.
A timestamp, if wanted, is passed in explicitly. The module is engine-side (framework/v2)
so it imports ``framework`` freely, but it performs no I/O and sends no traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..verify.verifier import canonical_bug_class
from .grounding import GRADE_LEAD, GradedFinding, grade_finding

# ---------------------------------------------------------------------------
# Source-standard versions. Every mapping cites these — the control ids below are
# meaningless without the document version they are drawn from.
# ---------------------------------------------------------------------------

STANDARD_VERSIONS: dict[str, str] = {
    "owasp": "OWASP Top 10:2021",
    "cwe": "CWE (MITRE Common Weakness Enumeration) 4.x",
    "pci_dss": "PCI DSS v4.0",
    "soc2": "AICPA Trust Services Criteria (TSC) 2017 (rev. 2022)",
    "iso27001": "ISO/IEC 27001:2022 Annex A",
    "attack": "MITRE ATT&CK v15 (Enterprise); MITRE ATLAS for AI/LLM techniques (AML.*)",
}

# Human labels for the OWASP Top 10:2021 categories used below (display only).
OWASP_2021_NAMES: dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}


@dataclass(frozen=True)
class ControlMapping:
    """The frozen set of standards controls one bug_class implicates. Immutable so the
    table cannot be mutated at runtime; lists are tuples for the same reason.

    This is DATA (what a weakness of this class implicates), never an assertion that the
    control is covered — only :func:`map_finding` over a PROVEN fact asserts coverage."""

    owasp: str | None
    cwe: tuple[str, ...]
    pci_dss: tuple[str, ...]
    soc2: tuple[str, ...]
    iso27001: tuple[str, ...]
    attack: tuple[str, ...]


# ---------------------------------------------------------------------------
# Reusable control clusters (DRY). Each cluster names the requirement/criteria/
# control family a class-family implicates, under the STANDARD_VERSIONS above.
# ---------------------------------------------------------------------------

# Secure-development / injection-class controls.
_SDLC_PCI = ("6.2.4",)
_SDLC_SOC2 = ("CC7.1", "CC8.1")
_SDLC_ISO = ("A.8.28", "A.8.29")

# Access-control / authorization controls.
_AC_PCI = ("7.2.1", "7.2.2")
_AC_SOC2 = ("CC6.1", "CC6.3")
_AC_ISO = ("A.5.15", "A.8.3")

# Authentication / identity controls.
_AUTH_PCI = ("8.3.1", "8.4.1")
_AUTH_SOC2 = ("CC6.1", "CC6.2")
_AUTH_ISO = ("A.8.5", "A.5.17")

# Cryptography / transport-protection controls.
_CRYPTO_PCI = ("4.2.1",)
_CRYPTO_SOC2 = ("CC6.7",)
_CRYPTO_ISO = ("A.8.24", "A.5.14")

# Confidentiality / data-exposure controls.
_CONF_PCI = ("3.2.1", "3.5.1")
_CONF_SOC2 = ("CC6.1", "C1.1")
_CONF_ISO = ("A.5.12", "A.8.12")

# Security-misconfiguration controls.
_MISCFG_PCI = ("2.2.1",)
_MISCFG_SOC2 = ("CC6.1", "CC8.1")
_MISCFG_ISO = ("A.8.9",)

# Vulnerable-component / patch-management controls.
_VULN_PCI = ("6.3.1", "6.3.3")
_VULN_SOC2 = ("CC7.1",)
_VULN_ISO = ("A.8.8",)

# Availability / resource-exhaustion (DoS) controls.
_DOS_PCI = ("6.2.4",)
_DOS_SOC2 = ("A1.1", "A1.2")
_DOS_ISO = ("A.8.6",)

# Network-security-control (exposed-surface) controls.
_NET_PCI = ("1.2.1", "1.3.1")
_NET_SOC2 = ("CC6.6",)
_NET_ISO = ("A.8.20", "A.8.21")

# Cloud / container / mesh posture controls.
_CLOUD_PCI = ("2.2.1", "1.2.1")
_CLOUD_SOC2 = ("CC6.1", "CC6.6")
_CLOUD_ISO = ("A.8.9", "A.5.23")

# Software-supply-chain / CI-CD integrity controls.
_SUPPLY_PCI = ("6.3.2", "6.5.1")
_SUPPLY_SOC2 = ("CC8.1", "CC7.1")
_SUPPLY_ISO = ("A.8.25", "A.8.31")

# Logging / monitoring controls.
_LOG_PCI = ("10.2.1", "10.4.1")
_LOG_SOC2 = ("CC7.2", "CC7.3")
_LOG_ISO = ("A.8.15", "A.8.16")


def _m(owasp: str | None, cwe: tuple[str, ...], *, pci: tuple[str, ...], soc2: tuple[str, ...],
       iso: tuple[str, ...], attack: tuple[str, ...]) -> ControlMapping:
    return ControlMapping(owasp=owasp, cwe=cwe, pci_dss=pci, soc2=soc2, iso27001=iso, attack=attack)


# ---------------------------------------------------------------------------
# The frozen mapping table. One entry per canonical bug_class in BUG_CLASS_ORACLES
# (a completeness test enforces this). ATT&CK ids: T#### are Enterprise; AML.* are
# MITRE ATLAS (the AI/LLM matrix). An empty ``attack`` tuple is an honest "no clean
# technique in the cited matrix" — never a fabricated id.
# ---------------------------------------------------------------------------

_STANDARDS: dict[str, ControlMapping] = {
    # ---- SQL / query injection (A03) ----
    "boolean_sqli": _m("A03:2021", ("CWE-89",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    "time_based_sqli": _m("A03:2021", ("CWE-89",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    "error_based_sqli": _m("A03:2021", ("CWE-89",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    "sqli": _m("A03:2021", ("CWE-89",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    "sqli_attempt": _m("A03:2021", ("CWE-89",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    "nosqli": _m("A03:2021", ("CWE-943", "CWE-89"), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    "nosql_injection_attempt": _m("A03:2021", ("CWE-943",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                                  attack=("T1190",)),
    "ldap_injection": _m("A03:2021", ("CWE-90",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    "xpath_injection": _m("A03:2021", ("CWE-643",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    # ---- OS command / code execution (A03) ----
    "time_based_command_injection": _m("A03:2021", ("CWE-78",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                                       attack=("T1059", "T1190")),
    "command_injection": _m("A03:2021", ("CWE-78",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                            attack=("T1059", "T1190")),
    "command_injection_attempt": _m("A03:2021", ("CWE-78",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                                    attack=("T1059", "T1190")),
    "rce": _m("A03:2021", ("CWE-94", "CWE-78"), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
              attack=("T1059", "T1190")),
    "ssti": _m("A03:2021", ("CWE-1336", "CWE-94"), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
               attack=("T1059", "T1190")),
    "el_injection": _m("A03:2021", ("CWE-917",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                       attack=("T1059", "T1190")),
    # ---- Generic time-based blind injection oracle (no sub-class committed) ----
    "time_based": _m("A03:2021", ("CWE-89", "CWE-78"), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                     attack=("T1190",)),
    # ---- Insecure deserialization (A08 integrity) ----
    "deserialization": _m("A08:2021", ("CWE-502",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                          attack=("T1059", "T1190")),
    # ---- Cross-site scripting / client-side script execution (A03) ----
    "xss": _m("A03:2021", ("CWE-79",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1059.007",)),
    "dom_xss": _m("A03:2021", ("CWE-79",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1059.007",)),
    "websocket_injection": _m("A03:2021", ("CWE-79", "CWE-20"), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                              attack=("T1190",)),
    # ---- Broken access control (A01) ----
    "idor": _m("A01:2021", ("CWE-639", "CWE-284"), pci=_AC_PCI, soc2=_AC_SOC2, iso=_AC_ISO, attack=("T1190",)),
    "bola": _m("A01:2021", ("CWE-639",), pci=_AC_PCI, soc2=_AC_SOC2, iso=_AC_ISO, attack=("T1190",)),
    "bfla": _m("A01:2021", ("CWE-285", "CWE-862"), pci=_AC_PCI, soc2=_AC_SOC2, iso=_AC_ISO, attack=("T1190",)),
    "broken_access_control": _m("A01:2021", ("CWE-284", "CWE-862"), pci=_AC_PCI, soc2=_AC_SOC2, iso=_AC_ISO,
                                attack=("T1190",)),
    "authorization": _m("A01:2021", ("CWE-285", "CWE-862"), pci=_AC_PCI, soc2=_AC_SOC2, iso=_AC_ISO,
                        attack=("T1190",)),
    "mass_assignment": _m("A01:2021", ("CWE-915",), pci=_AC_PCI, soc2=_AC_SOC2, iso=_AC_ISO, attack=("T1190",)),
    "cors": _m("A01:2021", ("CWE-942", "CWE-346"), pci=_AC_PCI, soc2=_AC_SOC2, iso=_AC_ISO, attack=("T1190",)),
    "cross_site_websocket_hijacking": _m("A01:2021", ("CWE-1385", "CWE-346"), pci=_AC_PCI, soc2=_AC_SOC2,
                                         iso=_AC_ISO, attack=("T1185",)),
    "request_race": _m("A01:2021", ("CWE-362", "CWE-367"), pci=_AC_PCI, soc2=_AC_SOC2, iso=_AC_ISO,
                       attack=("T1190",)),
    # ---- Privilege escalation (A01) ----
    "privilege_escalation": _m("A01:2021", ("CWE-269",), pci=_AC_PCI, soc2=_AC_SOC2, iso=("A.8.2", "A.5.15"),
                               attack=("T1068", "T1548")),
    "privilege_path": _m("A01:2021", ("CWE-269", "CWE-266"), pci=_AC_PCI, soc2=_AC_SOC2, iso=("A.8.2", "A.5.15"),
                         attack=("T1548", "T1098")),
    "iam_privilege_escalation": _m("A01:2021", ("CWE-269", "CWE-266"), pci=_AC_PCI, soc2=_AC_SOC2,
                                   iso=("A.8.2", "A.5.15"), attack=("T1548", "T1098")),
    "excessive_privilege": _m("A01:2021", ("CWE-250", "CWE-269"), pci=_AC_PCI, soc2=_AC_SOC2,
                              iso=("A.8.2", "A.5.15"), attack=("T1078.004",)),
    # ---- Authentication / identity failures (A07) ----
    "auth_bypass": _m("A07:2021", ("CWE-287", "CWE-288"), pci=_AUTH_PCI, soc2=_AUTH_SOC2, iso=_AUTH_ISO,
                      attack=("T1190", "T1078")),
    "jwt": _m("A07:2021", ("CWE-347",), pci=_AUTH_PCI, soc2=_AUTH_SOC2, iso=_AUTH_ISO, attack=("T1550.001",)),
    "jwt_forgeable": _m("A07:2021", ("CWE-347", "CWE-327"), pci=_AUTH_PCI, soc2=_AUTH_SOC2, iso=_AUTH_ISO,
                        attack=("T1606",)),
    "credential_stuffing": _m("A07:2021", ("CWE-307", "CWE-799"), pci=_AUTH_PCI, soc2=_AUTH_SOC2, iso=_AUTH_ISO,
                             attack=("T1110.004",)),
    "identity_misconfiguration": _m("A07:2021", ("CWE-308", "CWE-1392"), pci=_AUTH_PCI, soc2=_AUTH_SOC2,
                                    iso=_AUTH_ISO, attack=("T1078",)),
    "saml_signature_wrapping": _m("A07:2021", ("CWE-347", "CWE-290"), pci=_AUTH_PCI, soc2=_AUTH_SOC2, iso=_AUTH_ISO,
                                  attack=("T1606.002",)),
    "saml_assertion_tampering": _m("A07:2021", ("CWE-347", "CWE-345"), pci=_AUTH_PCI, soc2=_AUTH_SOC2, iso=_AUTH_ISO,
                                   attack=("T1606.002",)),
    "saml_structural_forgery": _m("A07:2021", ("CWE-347", "CWE-290"), pci=_AUTH_PCI, soc2=_AUTH_SOC2, iso=_AUTH_ISO,
                                  attack=("T1606.002",)),
    "oidc_redirect_uri": _m("A07:2021", ("CWE-601", "CWE-20"), pci=_AUTH_PCI, soc2=_AUTH_SOC2, iso=_AUTH_ISO,
                            attack=("T1528",)),
    "oidc_idtoken_forgery": _m("A07:2021", ("CWE-347", "CWE-290"), pci=_AUTH_PCI, soc2=_AUTH_SOC2, iso=_AUTH_ISO,
                              attack=("T1606",)),
    # ---- Cryptographic failures (A02) ----
    "weak_tls": _m("A02:2021", ("CWE-326", "CWE-327"), pci=_CRYPTO_PCI, soc2=_CRYPTO_SOC2, iso=_CRYPTO_ISO,
                   attack=("T1557",)),
    "weak_crypto_artifact": _m("A02:2021", ("CWE-327",), pci=("4.2.1", "3.6.1"), soc2=_CRYPTO_SOC2, iso=_CRYPTO_ISO,
                              attack=("T1553",)),
    # ---- Sensitive-data / information exposure ----
    "exposure": _m("A01:2021", ("CWE-200",), pci=_CONF_PCI, soc2=_CONF_SOC2, iso=_CONF_ISO, attack=("T1213",)),
    "sensitive_exposure": _m("A02:2021", ("CWE-200", "CWE-359"), pci=_CONF_PCI, soc2=_CONF_SOC2, iso=_CONF_ISO,
                             attack=("T1213", "T1552")),
    "graphql_introspection": _m("A05:2021", ("CWE-200",), pci=_CONF_PCI, soc2=_CONF_SOC2, iso=_CONF_ISO,
                                attack=("T1213",)),
    "graphql_suggestions": _m("A05:2021", ("CWE-200",), pci=_CONF_PCI, soc2=_CONF_SOC2, iso=_CONF_ISO,
                              attack=("T1213",)),
    # ---- Security misconfiguration (A05) ----
    "security_misconfiguration": _m("A05:2021", ("CWE-16",), pci=_MISCFG_PCI, soc2=_MISCFG_SOC2, iso=_MISCFG_ISO,
                                    attack=("T1190",)),
    "host_header_injection": _m("A05:2021", ("CWE-644", "CWE-20"), pci=_MISCFG_PCI, soc2=_MISCFG_SOC2, iso=_MISCFG_ISO,
                               attack=("T1190",)),
    "open_redirect": _m("A01:2021", ("CWE-601",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                        attack=("T1566.002",)),
    "request_smuggling": _m("A05:2021", ("CWE-444",), pci=_MISCFG_PCI, soc2=_MISCFG_SOC2, iso=_MISCFG_ISO,
                            attack=("T1190",)),
    # ---- Insecure design / business logic (A04) ----
    "business_logic": _m("A04:2021", ("CWE-840", "CWE-841"), pci=_SDLC_PCI, soc2=("CC5.1", "CC8.1"),
                         iso=("A.8.26", "A.8.28"), attack=("T1190",)),
    # ---- Resource exhaustion / GraphQL DoS (A04 / availability) ----
    "graphql_depth_limit": _m("A04:2021", ("CWE-770", "CWE-400"), pci=_DOS_PCI, soc2=_DOS_SOC2, iso=_DOS_ISO,
                              attack=("T1499",)),
    "graphql_alias_overloading": _m("A04:2021", ("CWE-770", "CWE-400"), pci=_DOS_PCI, soc2=_DOS_SOC2, iso=_DOS_ISO,
                                    attack=("T1499",)),
    "graphql_batching": _m("A04:2021", ("CWE-770", "CWE-400"), pci=_DOS_PCI, soc2=_DOS_SOC2, iso=_DOS_ISO,
                           attack=("T1499",)),
    "graphql_cost": _m("A04:2021", ("CWE-770", "CWE-400"), pci=_DOS_PCI, soc2=_DOS_SOC2, iso=_DOS_ISO,
                       attack=("T1499",)),
    # ---- SSRF (A10) ----
    "ssrf": _m("A10:2021", ("CWE-918",), pci=("1.3.1", "1.4.1"), soc2=("CC6.6",), iso=("A.8.23", "A.8.20"),
               attack=("T1090",)),
    # ---- XXE (A05, external entities) ----
    "xxe": _m("A05:2021", ("CWE-611",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    "blind_xxe": _m("A05:2021", ("CWE-611",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1190",)),
    # ---- File access (path traversal / LFI) ----
    "path_traversal": _m("A01:2021", ("CWE-22",), pci=_SDLC_PCI, soc2=_AC_SOC2, iso=("A.8.3", "A.8.28"),
                         attack=("T1083", "T1005")),
    "lfi": _m("A01:2021", ("CWE-98", "CWE-22"), pci=_SDLC_PCI, soc2=_AC_SOC2, iso=("A.8.3", "A.8.28"),
              attack=("T1083", "T1005")),
    # ---- Memory-safety (sanitizer-proven) ----
    "memory_corruption": _m("A03:2021", ("CWE-787", "CWE-119"), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                            attack=("T1203",)),
    "buffer_overflow": _m("A03:2021", ("CWE-120", "CWE-787"), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO,
                          attack=("T1203",)),
    "use_after_free": _m("A03:2021", ("CWE-416",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=_SDLC_ISO, attack=("T1203",)),
    "crash": _m("A03:2021", ("CWE-248", "CWE-119"), pci=_SDLC_PCI, soc2=_DOS_SOC2, iso=_SDLC_ISO, attack=("T1499",)),
    # ---- Network exposure ----
    "service_reachable": _m("A05:2021", ("CWE-668",), pci=_NET_PCI, soc2=_NET_SOC2, iso=_NET_ISO, attack=("T1046",)),
    "anonymous_reachable": _m("A01:2021", ("CWE-306", "CWE-284"), pci=_NET_PCI, soc2=("CC6.1", "CC6.6"),
                             iso=("A.5.15", "A.5.23"), attack=("T1530",)),
    # ---- Vulnerable / outdated components (A06) ----
    "vulnerable_dependency": _m("A06:2021", ("CWE-1104", "CWE-937"), pci=_VULN_PCI, soc2=_VULN_SOC2, iso=_VULN_ISO,
                               attack=("T1190", "T1195.001")),
    # ---- Cloud / container / mesh / CI-CD / mobile / email posture ----
    "cloud_misconfiguration": _m("A05:2021", ("CWE-16", "CWE-284"), pci=_CLOUD_PCI, soc2=_CLOUD_SOC2, iso=_CLOUD_ISO,
                                attack=("T1530", "T1078.004")),
    "k8s_misconfiguration": _m("A05:2021", ("CWE-1188", "CWE-16"), pci=_CLOUD_PCI, soc2=_CLOUD_SOC2, iso=_CLOUD_ISO,
                              attack=("T1610", "T1611")),
    "mesh_misconfiguration": _m("A05:2021", ("CWE-306", "CWE-16"), pci=_CLOUD_PCI, soc2=_CLOUD_SOC2, iso=_CLOUD_ISO,
                               attack=("T1557",)),
    "cicd_misconfiguration": _m("A08:2021", ("CWE-829", "CWE-16"), pci=_SUPPLY_PCI, soc2=_SUPPLY_SOC2, iso=_SUPPLY_ISO,
                               attack=("T1195.002",)),
    "mobile_misconfiguration": _m("A02:2021", ("CWE-798", "CWE-312"), pci=("3.5.1", "8.3.1"), soc2=_CRYPTO_SOC2,
                                  iso=("A.8.24", "A.8.28"), attack=("T1552.001",)),
    "email_auth_misconfiguration": _m("A05:2021", ("CWE-16", "CWE-290"), pci=_MISCFG_PCI, soc2=("CC6.1", "CC7.2"),
                                     iso=("A.8.9", "A.5.14"), attack=("T1566",)),
    # ---- LLM / AI application classes (OWASP LLM Top 10; ATT&CK has no clean web technique, ATLAS does) ----
    "prompt_injection": _m(None, ("CWE-1427",), pci=_SDLC_PCI, soc2=_SDLC_SOC2, iso=("A.8.28", "A.8.26"),
                           attack=("AML.T0051",)),
    "system_prompt_disclosure": _m(None, ("CWE-200",), pci=_CONF_PCI, soc2=_CONF_SOC2, iso=("A.8.12", "A.5.12"),
                                   attack=()),
    # ---- Automated-access / bot detection (defensive telemetry; anti-automation controls) ----
    "automated_access": _m("A04:2021", ("CWE-799",), pci=_LOG_PCI, soc2=_LOG_SOC2, iso=_LOG_ISO, attack=("T1595",)),
}


# Status vocabulary for a graded finding's coverage assertion.
STATUS_PROVEN = "proven"        # graded FACT + a mapped class → coverage IS asserted
STATUS_ADVISORY = "advisory"    # graded LEAD/DEMOTED + a mapped class → a NOTE, no coverage
STATUS_UNMAPPED = "unmapped"    # bug_class not in the oracle/mapping vocabulary

# Matrix cell states, strongest → weakest.
CELL_PROVEN = "proven"          # a PROVEN fact implicates this control
CELL_ADVISORY = "advisory"      # only an unproven lead implicates this control
CELL_TESTED_CLEAR = "tested_clear"   # a class implicating it was tested → no fact/lead (clear)
CELL_NOT_TESTED = "not_tested"  # nothing tested implicates this control

_FRAMEWORKS = ("owasp", "cwe", "pci_dss", "soc2", "iso27001", "attack")


# ---------------------------------------------------------------------------
# Pure table lookups (DATA — never a coverage assertion).
# ---------------------------------------------------------------------------

def known_mapped_classes() -> frozenset[str]:
    """The canonical bug classes the table maps (== the oracle vocabulary)."""
    return frozenset(_STANDARDS)


def _controls_dict(mapping: ControlMapping) -> dict[str, Any]:
    """Serialize a ControlMapping to sorted JSON-friendly lists (deterministic)."""
    return {
        "owasp": mapping.owasp,
        "cwe": sorted(mapping.cwe),
        "pci_dss": sorted(mapping.pci_dss),
        "soc2": sorted(mapping.soc2),
        "iso27001": sorted(mapping.iso27001),
        "attack": sorted(mapping.attack),
    }


def controls_for(bug_class: str) -> dict[str, Any] | None:
    """The standards controls a ``bug_class`` implicates, as DATA — canonicalised via
    ``normalize_bug_class`` and looked up in the frozen table. ``None`` for a class the
    oracle vocabulary does not know (degrades safely, no crash).

    IMPORTANT: this is what a weakness of the class *would* implicate; it is NOT an
    assertion that the control is covered. Only :func:`map_finding` over a PROVEN fact
    asserts coverage."""
    canonical = canonical_bug_class(bug_class)
    if canonical is None:
        return None
    mapping = _STANDARDS.get(canonical)
    return _controls_dict(mapping) if mapping is not None else None


# ---------------------------------------------------------------------------
# Grading (reuse the report authority — RE-EXECUTE the oracle, never trust a flag).
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Record:
    """One graded + mapped finding — the internal unit the public functions share."""

    finding_ref: str
    input_bug_class: str
    canonical: str | None
    grade: str
    is_fact: bool
    mapping: ControlMapping | None
    certificate_digest: str | None
    oracle_kind: str | None
    severity: str | None
    confidence: float | None


def _graded_finding(finding: Any) -> GradedFinding | None:
    """Grade a finding through the shared report authority. Returns the ``GradedFinding``
    or ``None`` when the input cannot even be validated (then the caller treats it as an
    unproven lead — the conservative, honest default)."""
    if isinstance(finding, GradedFinding):
        return finding
    try:
        return grade_finding(finding)
    except Exception:
        return None


def _record(finding: Any) -> _Record:
    g = _graded_finding(finding)
    if g is not None:
        payload = g.finding
        raw_bc = payload.bug_class or ""
        ref = payload.finding_slug or "?"
        return _Record(
            finding_ref=ref,
            input_bug_class=raw_bc,
            canonical=canonical_bug_class(raw_bc),
            grade=g.grade,
            is_fact=g.is_fact,
            mapping=_STANDARDS.get(canonical_bug_class(raw_bc) or ""),
            certificate_digest=g.certificate_digest,
            oracle_kind=g.oracle_kind,
            severity=payload.severity,
            confidence=g.confidence,
        )
    # Could not validate/grade — recover the class from a raw mapping, treat as a LEAD
    # (unproven): a finding we cannot even validate can NEVER be asserted as coverage.
    raw = finding if isinstance(finding, dict) else {}
    raw_bc = str(raw.get("bug_class", ""))
    return _Record(
        finding_ref=str(raw.get("finding_slug", "?")),
        input_bug_class=raw_bc,
        canonical=canonical_bug_class(raw_bc),
        grade=GRADE_LEAD,
        is_fact=False,
        mapping=_STANDARDS.get(canonical_bug_class(raw_bc) or ""),
        certificate_digest=None,
        oracle_kind=None,
        severity=None,
        confidence=None,
    )


# ---------------------------------------------------------------------------
# Public: per-finding mapping (the honesty gate lives here).
# ---------------------------------------------------------------------------

def map_finding(finding: Any) -> dict[str, Any]:
    """Map ONE finding to the standards controls it implicates, gated by proof.

    The finding is graded by RE-EXECUTING its retained ``oracle_context`` (the same
    authority ``report.grounding`` / ``reporter_agent`` use). The return shape encodes
    the honesty rule structurally:

      * graded ``fact`` + a mapped class  → ``status="proven"``, ``coverage_asserted=True``,
        the controls under ``controls`` (an ASSERTION that this proven weakness implicates
        these controls), ``advisory=None``.
      * graded ``lead`` / ``demoted``      → ``status="advisory"``, ``coverage_asserted=False``,
        ``controls=None``; the mapping is echoed only under ``advisory`` (a NOTE). A LEAD
        can never claim control coverage.
      * bug_class out of vocabulary        → ``status="unmapped"``, both ``controls`` and
        ``advisory`` ``None`` — an honest "unmapped", no crash.

    Pure + deterministic (the grader re-runs pure oracles; no wallclock/RNG)."""
    r = _record(finding)
    controls = _controls_dict(r.mapping) if r.mapping is not None else None

    if r.mapping is None:
        status = STATUS_UNMAPPED
        note = (
            f"bug_class {r.input_bug_class!r} is not in the oracle/compliance vocabulary — "
            "no control mapping asserted (honest 'unmapped')."
        )
        controls_out: dict[str, Any] | None = None
        advisory_out: dict[str, Any] | None = None
    elif r.is_fact:
        status = STATUS_PROVEN
        note = "oracle-PROVEN fact — its retained proof re-fired; the controls below are implicated."
        controls_out = controls
        advisory_out = None
    else:
        status = STATUS_ADVISORY
        note = (
            f"unproven {r.grade} — advisory NOTE only. The oracle did not (re-)fire, so this "
            "does NOT assert control coverage; the mapping is informational until proven."
        )
        controls_out = None
        advisory_out = controls

    out: dict[str, Any] = {
        "finding_ref": r.finding_ref,
        "input_bug_class": r.input_bug_class,
        "bug_class": r.canonical,
        "graded": r.grade,
        "is_fact": r.is_fact,
        "status": status,
        "coverage_asserted": status == STATUS_PROVEN,
        "controls": controls_out,
        "advisory": advisory_out,
        "note": note,
        "sources": dict(STANDARD_VERSIONS),
    }
    if r.is_fact:
        out["proof"] = {
            "oracle_kind": r.oracle_kind,
            "confidence": r.confidence,
            "certificate": f"sha256:{r.certificate_digest}" if r.certificate_digest else None,
        }
    return out


# ---------------------------------------------------------------------------
# Public: coverage matrix (proven vs tested-clear vs not-tested).
# ---------------------------------------------------------------------------

def _control_universe() -> dict[str, list[str]]:
    """Every control the table references, per framework, sorted. This is the mapper's
    KNOWN universe — the coverage map is honest within it and never implies coverage of a
    surface/control outside it."""
    universe: dict[str, set[str]] = {fw: set() for fw in _FRAMEWORKS}
    for mapping in _STANDARDS.values():
        if mapping.owasp is not None:
            universe["owasp"].add(mapping.owasp)
        universe["cwe"].update(mapping.cwe)
        universe["pci_dss"].update(mapping.pci_dss)
        universe["soc2"].update(mapping.soc2)
        universe["iso27001"].update(mapping.iso27001)
        universe["attack"].update(mapping.attack)
    return {fw: sorted(vals) for fw, vals in universe.items()}


def _controls_by_framework(mapping: ControlMapping) -> dict[str, tuple[str, ...]]:
    fw: dict[str, tuple[str, ...]] = {
        "owasp": (mapping.owasp,) if mapping.owasp is not None else (),
        "cwe": mapping.cwe,
        "pci_dss": mapping.pci_dss,
        "soc2": mapping.soc2,
        "iso27001": mapping.iso27001,
        "attack": mapping.attack,
    }
    return fw


def coverage_matrix(findings: Iterable[Any], *, tested_bug_classes: Iterable[str] | None = None) -> dict[str, Any]:
    """Build a deterministic coverage matrix over a set of findings.

    Each control (per framework) is graded into one of four states, strongest wins:

      * ``proven``       — a graded FACT implicates it (a proven weakness exists).
      * ``advisory``     — only an unproven LEAD/DEMOTED implicates it (under review).
      * ``tested_clear`` — a class implicating it was in ``tested_bug_classes`` but produced
                           no fact/lead → tested, no finding (clear).
      * ``not_tested``   — nothing tested implicates it.

    ``tested_bug_classes`` is REQUIRED to distinguish "tested, no finding" from "not tested":
    without it, a control with no finding stays ``not_tested`` — the mapper never *implies*
    a surface was tested clean. Pure + deterministic (grades via re-execution; sorted)."""
    return _coverage_from_records([_record(f) for f in findings], tested_bug_classes)


def _coverage_from_records(records: list[_Record], tested_bug_classes: Iterable[str] | None) -> dict[str, Any]:
    """The coverage-matrix body over already-graded records — shared by ``coverage_matrix``
    (which grades first) and ``compliance_attestation`` (which reuses its records), so a
    finding is graded exactly once per call and never re-graded by mistake."""
    tested = {c for c in (canonical_bug_class(t) for t in (tested_bug_classes or ())) if c is not None}
    # A class that produced ANY finding was, trivially, tested.
    tested |= {r.canonical for r in records if r.canonical is not None}

    # control (framework, id) → contributing findings / bug_classes, at each evidence level.
    proven: dict[tuple[str, str], dict[str, set[str]]] = {}
    advisory: dict[tuple[str, str], dict[str, set[str]]] = {}

    def _touch(bucket: dict[tuple[str, str], dict[str, set[str]]], key: tuple[str, str],
               ref: str, bc: str) -> None:
        cell = bucket.setdefault(key, {"findings": set(), "bug_classes": set()})
        cell["findings"].add(ref)
        cell["bug_classes"].add(bc)

    for r in records:
        if r.mapping is None or r.canonical is None:
            continue
        by_fw = _controls_by_framework(r.mapping)
        bucket = proven if r.is_fact else advisory
        for fw, ids in by_fw.items():
            for cid in ids:
                _touch(bucket, (fw, cid), r.finding_ref, r.canonical)

    # tested_clear reach: controls implicated by a tested class (regardless of finding).
    tested_controls: dict[tuple[str, str], set[str]] = {}
    for bc in sorted(tested):
        mapping = _STANDARDS.get(bc)
        if mapping is None:
            continue
        for fw, ids in _controls_by_framework(mapping).items():
            for cid in ids:
                tested_controls.setdefault((fw, cid), set()).add(bc)

    universe = _control_universe()
    frameworks: dict[str, dict[str, Any]] = {}
    summary: dict[str, dict[str, int]] = {}
    for fw in _FRAMEWORKS:
        fw_cells: dict[str, Any] = {}
        counts = {CELL_PROVEN: 0, CELL_ADVISORY: 0, CELL_TESTED_CLEAR: 0, CELL_NOT_TESTED: 0}
        for cid in universe[fw]:
            key = (fw, cid)
            if key in proven:
                state = CELL_PROVEN
                cell = proven[key]
            elif key in advisory:
                state = CELL_ADVISORY
                cell = advisory[key]
            elif key in tested_controls:
                state = CELL_TESTED_CLEAR
                cell = {"findings": set(), "bug_classes": tested_controls[key]}
            else:
                state = CELL_NOT_TESTED
                cell = {"findings": set(), "bug_classes": set()}
            counts[state] += 1
            fw_cells[cid] = {
                "status": state,
                "findings": sorted(cell["findings"]),
                "bug_classes": sorted(cell["bug_classes"]),
            }
        frameworks[fw] = fw_cells
        summary[fw] = counts

    total = {CELL_PROVEN: 0, CELL_ADVISORY: 0, CELL_TESTED_CLEAR: 0, CELL_NOT_TESTED: 0}
    for fw in _FRAMEWORKS:
        for state, n in summary[fw].items():
            total[state] += n

    return {
        "schema": "crucible.coverage-matrix/v1",
        "sources": dict(STANDARD_VERSIONS),
        "legend": {
            CELL_PROVEN: "a deterministic oracle PROVED a weakness implicating this control",
            CELL_ADVISORY: "only an unproven lead implicates this control (not asserted)",
            CELL_TESTED_CLEAR: "a class implicating this control was tested — no finding (clear)",
            CELL_NOT_TESTED: "no tested class implicates this control (no coverage implied)",
        },
        "frameworks": frameworks,
        "summary": {**summary, "total": total},
    }


# ---------------------------------------------------------------------------
# Public: compliance attestation (deterministic, signable — no crypto invented).
# ---------------------------------------------------------------------------

def _content_digest(payload: dict[str, Any]) -> str | None:
    """A canonical sha256 over the attestation content the caller can sign later. Reuses
    the platform's canonical-bytes discipline (``evidence.digest_payload``). ``None`` if the
    canonicaliser is unavailable — we never fabricate a digest."""
    try:
        from ..evidence import digest_payload

        return digest_payload(payload)
    except Exception:
        return None


def compliance_attestation(
    findings: Iterable[Any],
    *,
    generated_at: str | None = None,
    target: str | None = None,
    tested_bug_classes: Iterable[str] | None = None,
    standard: str | None = None,
) -> dict[str, Any]:
    """A deterministic, signable compliance summary over a set of graded findings.

    Structured data only — no crypto is invented. The document carries a canonical
    ``content_digest`` (sha256 over its content, minus the digest field) that the caller
    signs later with the platform's evidence signer. ``generated_at`` is the ONLY
    non-deterministic input and is passed in explicitly (default ``None`` → reproducible).

    Honesty is preserved end to end: ``proven_findings`` lists ONLY graded FACTs (each with
    its controls + re-runnable certificate digest); unproven leads live in
    ``advisory_findings`` as NOTES and never appear as proven coverage; the embedded
    ``coverage_matrix`` distinguishes proven / tested-clear / not-tested."""
    records = [_record(f) for f in findings]  # graded ONCE; the matrix reuses these records

    proven_findings: list[dict[str, Any]] = []
    advisory_findings: list[dict[str, Any]] = []
    unmapped: list[dict[str, Any]] = []
    for r in records:
        if r.mapping is None:
            unmapped.append({"finding_ref": r.finding_ref, "input_bug_class": r.input_bug_class, "graded": r.grade})
            continue
        controls = _controls_dict(r.mapping)
        if r.is_fact:
            proven_findings.append({
                "finding_ref": r.finding_ref,
                "bug_class": r.canonical,
                "severity": r.severity,
                "controls": controls,
                "proof": {
                    "oracle_kind": r.oracle_kind,
                    "confidence": r.confidence,
                    "certificate": f"sha256:{r.certificate_digest}" if r.certificate_digest else None,
                },
            })
        else:
            advisory_findings.append({
                "finding_ref": r.finding_ref,
                "bug_class": r.canonical,
                "graded": r.grade,
                "advisory": controls,
                "note": "unproven lead — advisory only; not asserted as control coverage",
            })

    proven_findings.sort(key=lambda d: d["finding_ref"])
    advisory_findings.sort(key=lambda d: d["finding_ref"])
    unmapped.sort(key=lambda d: d["finding_ref"])

    content: dict[str, Any] = {
        "schema": "crucible.compliance-attestation/v1",
        "sources": dict(STANDARD_VERSIONS),
        "target": target,
        "standard": standard,
        "generated_at": generated_at,
        "summary": {
            "findings_total": len(records),
            "proven": len(proven_findings),
            "advisory": len(advisory_findings),
            "unmapped": len(unmapped),
        },
        "proven_findings": proven_findings,
        "advisory_findings": advisory_findings,
        "unmapped_findings": unmapped,
        "coverage_matrix": _coverage_from_records(records, tested_bug_classes),
        "attestation": (
            "This attestation asserts control coverage ONLY for findings a deterministic oracle "
            "PROVED (see proven_findings, each with a re-runnable certificate). Advisory leads are "
            "not asserted coverage. Controls with no proven or tested class are 'not_tested' — no "
            "coverage is implied for any surface that was not tested."
        ),
    }
    digest = _content_digest(content)
    content["content_digest"] = f"sha256:{digest}" if digest else None
    return content
