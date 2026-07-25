"""
detection.registry — the oracle catalogue, the offline resolver, and the operating surface.

Registers every deterministic detection oracle, resolves an oracle by name for OFFLINE certificate
re-verification (``base.reverify_certificate`` re-runs the named oracle over the certificate's embedded
evidence), and offers the plane-level ``run_*`` helpers that parse a log source and run its oracle set.

Every helper is total (a non-str log → ``[]``), deterministic (distinct injected ``seq`` per oracle),
and offense-free (reads telemetry, wields nothing, performs NO egress). Wiring an injected ``signer`` +
``verify_key`` is what lets a FACT-grade fire mint a signed, re-verifiable certificate; without them (or
if a certificate fails to re-verify) the fire degrades to a LEAD, never a silent block.

Import-clean: stdlib + the detection oracle modules.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .base import Detection, DetectionOracle
from .credential import BruteForceOracle, PasswordSprayOracle
from .injection import (
    CmdInjectionOracle,
    CrlfInjectionOracle,
    PathTraversalOracle,
    SqliStructureOracle,
    XssStructureOracle,
)
from .logs import parse_access_log, parse_auth_log, parse_conn_log
from .recon import (
    CmsEnumerationOracle,
    ForcedBrowsingOracle,
    PortScanOracle,
    ScannerFingerprintOracle,
    WafProbeOracle,
)

CertSigner = Callable[[bytes], str]

# Every oracle class, keyed by its stable ``name`` (the certificate's ``oracle`` field).
ORACLE_CLASSES: dict = {
    cls.name: cls for cls in (
        # recon (edge / flow)
        PortScanOracle, ForcedBrowsingOracle, ScannerFingerprintOracle, CmsEnumerationOracle,
        WafProbeOracle,
        # injection (edge, in-path)
        SqliStructureOracle, XssStructureOracle, PathTraversalOracle, CrlfInjectionOracle,
        CmdInjectionOracle,
        # credential (auth telemetry)
        BruteForceOracle, PasswordSprayOracle,
    )
}

# Which oracles run over which log source.
ACCESS_ORACLE_NAMES = (
    "forced_browsing", "scanner_fingerprint", "cms_enumeration", "waf_probe",
    "sqli_structure", "xss_structure", "path_traversal", "crlf_injection", "cmd_injection",
)
CONN_ORACLE_NAMES = ("port_scan",)
AUTH_ORACLE_NAMES = ("brute_force", "password_spray")


def resolve_oracle(name: object) -> Optional[DetectionOracle]:
    """Instantiate a fresh, stateless oracle by name (for offline re-verification). Thresholds are class
    constants, so a fresh instance re-runs identically to the one that minted the certificate. ``None``
    for an unknown name (fail-closed — an unknown oracle can never re-verify)."""
    cls = ORACLE_CLASSES.get(str(name or ""))
    if cls is None:
        return None
    try:
        return cls()
    except Exception:  # noqa: BLE001
        return None


def _run(names, records: Any, *, signer, verify_key, key_id, seq_start) -> list:
    out: list = []
    for i, nm in enumerate(names):
        oracle = resolve_oracle(nm)
        if oracle is None:
            continue
        det = oracle.detect(records, signer=signer, verify_key=verify_key,
                            key_id=key_id, seq=seq_start + i)
        if det is not None:
            out.append(det)
    return out


def run_access_detections(
    access_log: object, *, signer: Optional[CertSigner] = None, verify_key: str = "",
    key_id: str = "", seq_start: int = 0,
) -> list:
    """Parse a CLF access log and run every edge oracle over it. Total: a non-str → ``[]``."""
    records = parse_access_log(access_log)
    return _run(ACCESS_ORACLE_NAMES, records, signer=signer, verify_key=verify_key,
                key_id=key_id, seq_start=seq_start)


def run_conn_detections(
    conn_log: object, *, signer: Optional[CertSigner] = None, verify_key: str = "",
    key_id: str = "", seq_start: int = 100,
) -> list:
    """Parse a connection/flow log and run the flow oracles (``port_scan``). Total."""
    records = parse_conn_log(conn_log)
    return _run(CONN_ORACLE_NAMES, records, signer=signer, verify_key=verify_key,
                key_id=key_id, seq_start=seq_start)


def run_auth_detections(
    auth_log: object, *, signer: Optional[CertSigner] = None, verify_key: str = "",
    key_id: str = "", seq_start: int = 200,
) -> list:
    """Parse an auth log and run the credential oracles (``brute_force``/``password_spray``). Total."""
    records = parse_auth_log(auth_log)
    return _run(AUTH_ORACLE_NAMES, records, signer=signer, verify_key=verify_key,
                key_id=key_id, seq_start=seq_start)


def run_all_detections(
    *, access_log: object = "", conn_log: object = "", auth_log: object = "",
    signer: Optional[CertSigner] = None, verify_key: str = "", key_id: str = "",
) -> list:
    """Run every plane over its (optional) log source and return all detections (FACTs + LEADs), each
    oracle on a disjoint ``seq`` band so certificate ids never collide. Total on any input."""
    out: list = []
    out += run_access_detections(access_log, signer=signer, verify_key=verify_key,
                                 key_id=key_id, seq_start=0)
    out += run_conn_detections(conn_log, signer=signer, verify_key=verify_key,
                               key_id=key_id, seq_start=100)
    out += run_auth_detections(auth_log, signer=signer, verify_key=verify_key,
                               key_id=key_id, seq_start=200)
    return out


def facts(detections: Any) -> list:
    """The oracle-proven, certificate-backed detections."""
    return [d for d in (detections or []) if isinstance(d, Detection) and d.is_fact]


def leads(detections: Any) -> list:
    """The honest, non-authoritative suspicions (never a silent block)."""
    return [d for d in (detections or []) if isinstance(d, Detection) and not d.is_fact]


# The detection mirror's DECLARED bug-class vocabulary (unification S3) — the ONE place that names every
# class a detection oracle can emit, with a self-check (``verify_registration``) so a hallucinated/typo'd
# class can never ship on a detection finding (the defensive analogue of aegis/registry.py). DEFENSIVE
# detection classes (an attack OBSERVED in telemetry) are a SEPARATE taxonomy from CRUCIBLE's OFFENSIVE
# confirmation classes and are DELIBERATELY NOT added to CRUCIBLE's ``OracleKind``: a detection oracle is
# confirmed by its own log re-run (``reverify_certificate``), not by a ``verify/oracles.py`` body, so a
# detection ``OracleKind`` member would be a BODYLESS kind the verifier could never fire (an unsound
# "unification"). NAMING: SOME detection classes reuse CRUCIBLE's exact class name where the taxonomy
# genuinely coincides — ``sqli``, ``xss``, ``path_traversal`` ARE CRUCIBLE bug classes too (one shared name
# across offense + defense). The rest are detection-SPECIFIC: ``crlf_injection`` and ``cmd_injection`` have
# NO CRUCIBLE counterpart (CRUCIBLE's is ``command_injection``, deliberately NOT aliased here), and
# ``recon.*``/``cred.*`` are detection-namespaced. (The deferred cert-fold must therefore alias/rename
# crlf/cmd, not assume a name match.) A cross-vocabulary test (test_detection_vocabulary.py) asserts this
# exact shared/specific split AND that importing detection adds NO bodyless ``OracleKind``. This module
# stays framework-free — the CRUCIBLE cross-reference lives only in the test.
DETECTION_BUG_CLASSES: frozenset = frozenset({
    "recon.port_scan", "recon.forced_browsing", "recon.scanner", "recon.cms", "recon.waf_probe",
    "sqli", "xss", "path_traversal", "crlf_injection", "cmd_injection",
    "cred.brute_force", "cred.password_spray",
})


def detection_bug_classes() -> frozenset:
    """The detection mirror's declared, self-checked confirmed-class vocabulary."""
    return DETECTION_BUG_CLASSES


def verify_registration() -> None:
    """Fail loudly if any registered detection oracle carries an UNDECLARED bug_class, does not resolve by
    name, or if a declared class has no backing oracle — the self-check the gate test runs, so the detection
    vocabulary is closed and every detection finding's class is a known, non-hallucinated one."""
    for name, cls in ORACLE_CLASSES.items():
        inst = resolve_oracle(name)
        assert inst is not None, f"detection oracle {name!r} does not resolve"
        # check BOTH the class attr AND the resolved-instance value — `detect()` emits `self.bug_class`, so a
        # (future) instance-level override to a hallucinated class must not slip past a class-only check.
        for bc in (getattr(cls, "bug_class", ""), getattr(inst, "bug_class", "")):
            assert bc in DETECTION_BUG_CLASSES, f"detection oracle {name!r} has undeclared bug_class {bc!r}"
    covered = {getattr(cls, "bug_class", "") for cls in ORACLE_CLASSES.values()}
    orphans = DETECTION_BUG_CLASSES - covered
    assert not orphans, f"declared detection classes with no backing oracle: {sorted(orphans)}"
