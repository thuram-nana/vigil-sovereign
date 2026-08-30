"""Standards / compliance mapping — each confirmed finding class → the controls a government procures against.

The engine confirms a `bug_class`; this module maps it to OWASP ASVS · NIST SP 800-53 · ISO/IEC 27001 ·
CIS Controls v8 · MITRE ATT&CK. The references are curated and conservative (a defensible primary control
per framework, not an exhaustive list). Aliases (error_based_sqli/boolean_sqli → sqli, bola → idor, …) are
normalized so the map keys on the class family.
"""

from __future__ import annotations

from dataclasses import dataclass

FRAMEWORKS = ["OWASP ASVS", "NIST 800-53", "ISO 27001", "CIS v8", "MITRE ATT&CK"]


@dataclass(frozen=True)
class ControlSet:
    asvs: str
    nist: str
    iso: str
    cis: str
    attack: str


# family → controls
_MAP: dict[str, ControlSet] = {
    "sqli": ControlSet("V5.3.4", "SI-10", "A.8.28", "16.11", "T1190"),
    "xss": ControlSet("V5.3.3", "SI-10", "A.8.28", "16.11", "T1059.007"),
    "idor": ControlSet("V4.1.1", "AC-3", "A.8.3", "3.3", "T1213"),
    "broken_access_control": ControlSet("V4.1.3", "AC-6", "A.8.3", "6.8", "T1068"),
    "ssrf": ControlSet("V12.6.1", "SC-7", "A.8.22", "12.2", "T1090"),
    "path_traversal": ControlSet("V12.3.1", "AC-6", "A.8.3", "3.3", "T1083"),
    "open_redirect": ControlSet("V5.1.5", "SI-10", "A.8.28", "16.11", "T1204"),
    "exposure": ControlSet("V14.3.2", "IA-5", "A.8.24", "3.11", "T1552.001"),
    "cors": ControlSet("V14.5.3", "AC-4", "A.8.22", "12.2", "T1190"),
    "host_header_injection": ControlSet("V5.1.1", "SI-10", "A.8.28", "16.11", "T1190"),
    "business_logic": ControlSet("V11.1.1", "SI-10", "A.8.26", "16.10", "T1499"),
    "authentication": ControlSet("V2.2.1", "IA-2", "A.8.5", "6.3", "T1110"),
    "xxe": ControlSet("V5.5.2", "SI-10", "A.8.28", "16.11", "T1059"),
    "llm_injection": ControlSet("OWASP LLM01", "SI-10", "A.8.28", "16.11", "AML.T0051"),
}

# engine/registry class → family
_ALIASES = {
    "error_based_sqli": "sqli", "boolean_sqli": "sqli", "time_based_sqli": "sqli", "error_signature": "sqli",
    "reflection_context": "xss", "dom_xss": "xss", "reflected_xss": "xss", "stored_xss": "xss",
    "bola": "idor", "bfla": "broken_access_control", "privilege_escalation": "broken_access_control",
    "mass_assignment": "broken_access_control", "authorization": "broken_access_control",
    "blind_xxe": "xxe", "lfi": "path_traversal", "cmd_injection": "sqli",
}


def normalize(bug_class: str) -> str:
    bc = (bug_class or "").strip().lower()
    return _ALIASES.get(bc, bc)


def controls_for(bug_class: str) -> ControlSet | None:
    return _MAP.get(normalize(bug_class))


def mapped_row(bug_class: str) -> dict[str, str]:
    """A flat {framework: control} row for a bug_class, '—' where unmapped."""
    cs = controls_for(bug_class)
    if cs is None:
        return dict.fromkeys(FRAMEWORKS, "—")
    return {"OWASP ASVS": cs.asvs, "NIST 800-53": cs.nist, "ISO 27001": cs.iso,
            "CIS v8": cs.cis, "MITRE ATT&CK": cs.attack}
