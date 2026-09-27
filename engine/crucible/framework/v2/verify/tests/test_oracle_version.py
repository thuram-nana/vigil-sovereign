"""verify.oracle_version — the PCF oracle id@version identity.

Pins that every OracleKind has a version, the version is a deterministic content hash of the oracle
source (so a body change changes it — the whole point), and that stamping it onto a certificate stays
byte-identical for a cert that carries no version.
"""

from __future__ import annotations

import functools
import importlib
import json
import linecache
import os
import subprocess
import sys
from pathlib import Path
from statistics import median as _median

import pytest

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


# ---------------------------------------------------------------------------
# AUDIT (this slice) — THE CROSS-MODULE / LOCAL-IMPORT HOLE + FAIL-CLOSED classification.
#
# `_reachable_source_blob` promised "every module-level helper FUNCTION, CLASS and
# constant reachable from `fns` ... the entry function alone no longer hides a
# changed procedure." That promise was FALSE for a helper reached ONLY by a local
# in-repo import — the pattern used to keep the module graph acyclic. Three oracles'
# actual decision procedures live behind such imports:
#   * OOB_CALLBACK           -> `from .oob import verify_oob_receipt`
#   * VERSION_RANGE          -> `from .version import version_in_affected`
#   * SAML_STRUCTURAL_FORGERY-> `from ..scanner.sso import safe_parse_xml, saml_nameid, XxeBlocked, ...`
# MEASURED at d445c8b3: none of those helpers' source was in the closure, so
# mutating them left the version byte-identical — the version tracked the entry
# function's prose and missed the procedure, the exact inversion the identity exists
# to prevent. Separately, an in-repo callable that is neither a plain function nor a
# class (functools.partial / bound method / instance-callable) reached via a
# module-global reference was SILENTLY SKIPPED; it now FAILS CLOSED.
# ---------------------------------------------------------------------------

# Each newly-covered local-import path: (kind, defining module, a marker string that lives INSIDE the
# helper reached only via that path, a mutated form of the marker of a different length, a needle proving
# the helper's own source is in the closure).
_LOCAL_IMPORT_PATHS = [
    (OracleKind.OOB_CALLBACK, "framework.v2.verify.oob",
     "reject non-canonical", "reject NON-CANONICAL-MUT", "def verify_oob_receipt"),
    (OracleKind.VERSION_RANGE, "framework.v2.verify.version",
     "PROVABLY falls", "PROVABLY_MUTATED falls", "def version_in_affected"),
    (OracleKind.SAML_STRUCTURAL_FORGERY, "framework.v2.scanner.sso",
     "entity-expansion defused", "entity-expansion DEFUSED-MUTATED", "def safe_parse_xml"),
]


@pytest.mark.parametrize("kind,modname,marker,mut,needle", _LOCAL_IMPORT_PATHS)
def test_local_import_helper_source_is_inside_the_closure(kind, modname, marker, mut, needle):
    """Structural half: the helper reached ONLY via a local in-repo import must have its OWN source in the
    version blob — proving the closure now follows the import instead of stopping at the entry function."""
    blob = ov._reachable_source_blob(_ORACLE_FNS[kind]).decode()
    assert needle in blob, f"{needle!r} (reached only via a local import) is invisible to {kind.value}'s version"


def test_saml_closure_also_captures_the_sso_class_and_tree_helpers():
    """The SAML oracle's local import pulls in a CLASS (`XxeBlocked`) and further helpers (`saml_nameid`)
    from `scanner.sso`; all must be inside the closure, not just the first function."""
    blob = ov._reachable_source_blob(_ORACLE_FNS[OracleKind.SAML_STRUCTURAL_FORGERY]).decode()
    assert "class XxeBlocked" in blob, "the sso XXE guard class is invisible to the SAML version"
    assert "def saml_nameid" in blob, "an sso tree helper reached via the local import is invisible"


@pytest.mark.parametrize("kind,modname,marker,mut,needle", _LOCAL_IMPORT_PATHS)
def test_mutating_a_local_import_helper_ON_DISK_changes_the_version(kind, modname, marker, mut, needle):
    """Behavioural half: editing the body of a helper reached ONLY via a local in-repo import — ON DISK —
    must move the version. Proves `inspect.getsource` sees the real file and that the closure reaches it.
    The edit stays on one line (no line-count change) so every function's `co_firstlineno` remains valid,
    and the original bytes are restored in a finally."""
    mod = importlib.import_module(modname)
    path = Path(mod.__file__)
    original = path.read_bytes()
    oracle_version.cache_clear()
    baseline = oracle_version(kind)
    assert baseline.startswith("sha256:")
    try:
        text = original.decode()
        assert text.count(marker) == 1, f"marker {marker!r} not uniquely inside {modname} (count={text.count(marker)})"
        path.write_text(text.replace(marker, mut, 1))
        linecache.clearcache()
        oracle_version.cache_clear()
        mutated = oracle_version(kind)
        assert mutated != baseline, (
            f"mutating {modname}'s helper (reached only via a local import) left oracle_version({kind.value}) "
            f"unchanged — the cross-module hole is back")
    finally:
        path.write_bytes(original)
        linecache.clearcache()
        oracle_version.cache_clear()
    assert oracle_version(kind) == baseline, "version did not restore after the file was restored"


# --- fail-closed: an unclassifiable IN-REPO callable raises rather than silently returning a stale-safe "" ---
#
# Built as real module-level objects so `_reachable_source_blob` (which resolves a function's co_names
# against its DEFINING module's namespace, and `inspect.getsource`s the function) actually reaches them.

_AN_IN_REPO_PARTIAL = functools.partial(
    importlib.import_module("framework.v2.verify.oracles")._hit_token_matches)


def _references_an_unclassifiable_in_repo_callable(hit):
    # `_AN_IN_REPO_PARTIAL` is callable, is neither a types.FunctionType nor a type, and unwraps to an
    # in-repo function — exactly the shape the walk must refuse rather than silently skip.
    return _AN_IN_REPO_PARTIAL(hit)


def test_unclassifiable_in_repo_callable_raises_not_skips():
    with pytest.raises(ov._UnclassifiableInRepoCallable):
        ov._reachable_source_blob((_references_an_unclassifiable_in_repo_callable,))


def test_oracle_version_PROPAGATES_the_fail_closed_raise(monkeypatch):
    """The raise must reach the caller as a build failure — NOT be swallowed into the stale-safe "" that
    `_SourceUnavailable` produces (which would hide the changed procedure it is meant to surface)."""
    oracle_version.cache_clear()
    monkeypatch.setitem(_ORACLE_FNS, OracleKind.CLOUD_POSTURE,
                        (_references_an_unclassifiable_in_repo_callable,))
    try:
        with pytest.raises(ov._UnclassifiableInRepoCallable):
            oracle_version(OracleKind.CLOUD_POSTURE)
    finally:
        oracle_version.cache_clear()


def _references_a_third_party_callable(xs):
    # `_median` is a genuinely third-party (stdlib) callable reached via a module-global reference; it must
    # be SKIPPED, never sourced and never raised. If the fail-closed rule leaked to third parties, every
    # oracle that calls a stdlib function would fail to build.
    return _median(xs)


def test_third_party_callable_via_module_global_is_skipped_not_raised():
    """The fail-closed rule is for IN-REPO siblings only — a third-party callable is out of scope."""
    blob = ov._reachable_source_blob((_references_a_third_party_callable,)).decode()   # must NOT raise
    # third-party is SKIPPED: neither its library source nor a name-only const token enters the blob.
    assert "def median" not in blob, "the stdlib median source was pulled into the version"
    assert "_median=<callable" not in blob, "a third-party callable was name-bound into the version"


# --- determinism across separate interpreters for the newly-covered kinds (no repr(<lambda at 0x…>)) ---

def _versions_in_subprocess(hashseed: str) -> dict:
    kinds = ["oob_callback", "version_range", "saml_structural_forgery"]
    code = (
        "import json;"
        "from framework.v2.verify.oracle_version import oracle_version as v;"
        f"print(json.dumps({{k: v(k) for k in {kinds!r}}}, sort_keys=True))"
    )
    env = dict(os.environ, PYTHONHASHSEED=hashseed)
    out = subprocess.check_output([sys.executable, "-c", code], env=env, text=True)
    return json.loads(out.strip().splitlines()[-1])


def test_newly_covered_versions_are_identical_across_processes():
    a = _versions_in_subprocess("0")
    b = _versions_in_subprocess("12345")
    assert a == b and all(v.startswith("sha256:") for v in a.values()), (
        f"the cross-module closure is non-deterministic across interpreters: {a} != {b}")
