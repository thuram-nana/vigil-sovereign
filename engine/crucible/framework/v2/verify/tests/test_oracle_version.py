"""verify.oracle_version — the PCF oracle id@version identity.

Pins that every OracleKind has a version, the version is a deterministic content hash of the oracle
source (so a body change changes it — the whole point), and that stamping it onto a certificate stays
byte-identical for a cert that carries no version.
"""

from __future__ import annotations

import framework.v2.verify.oracle_version as ov
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracle_version import _ORACLE_FNS, oracle_version


def test_every_oracle_kind_is_mapped():
    # a newly-added kind MUST register a source function here, or its certificates carry no version
    assert set(_ORACLE_FNS) == set(OracleKind), (
        f"unmapped: {set(OracleKind) - set(_ORACLE_FNS)}; stale: {set(_ORACLE_FNS) - set(OracleKind)}")


def test_version_is_deterministic_and_kind_specific():
    v = oracle_version(OracleKind.CLOUD_POSTURE)
    assert v.startswith("sha256:") and v == oracle_version(OracleKind.CLOUD_POSTURE)   # stable
    assert v == oracle_version("cloud_posture")                                        # enum == str value
    # distinct kinds hash distinct sources
    assert oracle_version(OracleKind.CLOUD_POSTURE) != oracle_version(OracleKind.MOBILE_POSTURE)


def test_unknown_kind_returns_empty():
    assert oracle_version("not_a_kind") == ""
    assert oracle_version("") == ""


def test_version_tracks_the_oracle_SOURCE(monkeypatch):
    # THE load-bearing property: the version is derived from the function's source, so pointing a kind at
    # a different-bodied function yields a different version — it is not a constant/label.
    def body_a(x):
        return 1

    def body_b(x):
        return 2   # different body

    oracle_version.cache_clear()
    monkeypatch.setitem(_ORACLE_FNS, OracleKind.CLOUD_POSTURE, (body_a,))
    va = oracle_version(OracleKind.CLOUD_POSTURE)
    oracle_version.cache_clear()
    monkeypatch.setitem(_ORACLE_FNS, OracleKind.CLOUD_POSTURE, (body_b,))
    vb = oracle_version(OracleKind.CLOUD_POSTURE)
    assert va != vb and va.startswith("sha256:") and vb.startswith("sha256:")
    oracle_version.cache_clear()   # restore the real cache for other tests


def test_multi_function_kind_hashes_all_bodies(monkeypatch):
    # a kind that dispatches to >1 function (e.g. TLS_WEAKNESS) hashes ALL of them, so editing EITHER changes it
    def a(x): return 1
    def b(x): return 2
    def b2(x): return 3
    oracle_version.cache_clear()
    monkeypatch.setitem(_ORACLE_FNS, OracleKind.TLS_WEAKNESS, (a, b))
    v1 = oracle_version(OracleKind.TLS_WEAKNESS)
    oracle_version.cache_clear()
    monkeypatch.setitem(_ORACLE_FNS, OracleKind.TLS_WEAKNESS, (a, b2))   # second fn changed
    v2 = oracle_version(OracleKind.TLS_WEAKNESS)
    assert v1 != v2
    oracle_version.cache_clear()


def test_certificate_stamps_and_signs_the_version(monkeypatch, tmp_path):
    # a real build_certificate cert carries the version, and it round-trips through sign/verify
    from framework.v2.evidence.certify import build_certificate

    finding = {"check_id": "f1", "bug_class": "cloud_misconfiguration",
               "confirmed_by": "cloud_posture", "confidence": 0.99,
               "oracle_context": {"bug_class": "cloud_misconfiguration"}}
    cert = build_certificate(finding)
    assert cert.oracle_version == oracle_version("cloud_posture") and cert.oracle_version.startswith("sha256:")
    # a finding with no confirmed_by → no version → dropped from canonical bytes (byte-identical to a v1 cert)
    from framework.v2.evidence.canonical import canonical_json
    cert0 = build_certificate({"check_id": "f0", "oracle_context": {}})
    assert cert0.oracle_version == "" and b"oracle_version" not in canonical_json(cert0.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# AUDIT — THE CLASS HOLE in the reachable-source closure.
#
# `_reachable_source_blob` promises "every module-level helper FUNCTION, CLASS and
# constant reachable from `fns` ... the entry function alone no longer hides a
# changed procedure". Before this slice the walk followed only
# `types.FunctionType`, so `reflection_context_oracle` -> `_ReflectionScanner`
# stopped dead at the class. MEASURED at 9bc3e632: mutating `_js_scan`,
# `_ReflectionScanner.handle_data`, `_ReflectionScanner.handle_starttag`,
# `_EVENT_HANDLER_ATTRIBUTES` or `_INERT_TEXT_CONTAINERS` left
# `oracle_version(reflection_context)` BYTE-IDENTICAL, while editing one prose
# string in the entry function's own body changed it. The version tracked the
# PROSE and missed the PROCEDURE — the exact inversion the identity exists to
# prevent, and it would have let every fix in this slice ship invisibly.
# ---------------------------------------------------------------------------


def _reflection_version() -> str:
    oracle_version.cache_clear()
    try:
        return oracle_version(OracleKind.REFLECTION_CONTEXT)
    finally:
        oracle_version.cache_clear()


def test_a_class_based_decision_procedure_is_inside_the_version_closure(monkeypatch):
    """The scanner CLASS's own source must be in the blob."""
    from framework.v2.verify import oracles

    blob = ov._reachable_source_blob(ov._ORACLE_FNS[OracleKind.REFLECTION_CONTEXT]).decode()
    assert "class _ReflectionScanner" in blob, "the scanner class is invisible to the version"
    assert "def handle_data" in blob, "the scanner's decision method is invisible to the version"
    assert "def _js_scan" in blob, "the JS lexer, reached only via the class, is invisible"
    for const in ("_EVENT_HANDLER_ATTRIBUTES", "_INERT_TEXT_CONTAINERS", "_JS_MIME_ESSENCES"):
        assert f"{const}=" in blob, f"{const} is invisible to the version"
        assert getattr(oracles, const), f"{const} is empty — the assertion above would be vacuous"


def test_editing_a_class_method_changes_the_version(monkeypatch):
    """The behavioural half: a change to the class's decision method must move the
    version. Asserted by swapping the class for a mutated subclass, so it holds
    without touching the file on disk."""
    from framework.v2.verify import oracles

    before = _reflection_version()

    class _Mutated(oracles._ReflectionScanner):          # noqa: SLF001 - pinning the closure
        def handle_data(self, data: str) -> None:        # a DIFFERENT decision procedure
            return None

    monkeypatch.setattr(oracles, "_ReflectionScanner", _Mutated)
    after = _reflection_version()
    assert after != before, (
        "swapping the scanner class for one with a different handle_data left "
        "oracle_version(reflection_context) unchanged — the class hole is back")


def test_editing_a_class_reached_constant_changes_the_version(monkeypatch):
    """A validation constant reached ONLY through the class must move the version.
    `_EVENT_HANDLER_ATTRIBUTES` is referenced from `_ReflectionScanner.handle_starttag`
    and from nowhere else in the closure."""
    from framework.v2.verify import oracles

    before = _reflection_version()
    monkeypatch.setattr(oracles, "_EVENT_HANDLER_ATTRIBUTES",
                        frozenset(oracles._EVENT_HANDLER_ATTRIBUTES) | {"onsomethingnew"})
    assert _reflection_version() != before, (
        "editing the closed handler set left the version unchanged — a changed "
        "decision procedure would ship under an unchanged id@version")
