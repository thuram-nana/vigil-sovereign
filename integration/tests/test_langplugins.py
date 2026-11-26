"""MULTILANG-P1 — the LanguagePlugin architectural spine: registry, the Python reference plugin, and the
HYBRID default-OFF flag wiring (``VIGIL_MULTILANG_CODESCAN``).

This proves the phase-1 invariants:

  * (I4) byte-identical when OFF — the flag unset keeps the Python FACT path byte-identical and imports NO
    ``langplugins`` / ``tree_sitter`` module (asserted in a clean subprocess via ``sys.modules``).
  * Python-through-plugin byte-identical (flag ON) — the existing Python broken-crypto + insecure-flag FACT
    fixtures mint IDENTICAL oracle signals + certs through the plugin as through the direct ``ast`` path, and
    re-verify offline.
  * fail-closed — flag ON, a non-Python ``static_rule`` ctx with no registered plugin REFUSES → LEAD exactly
    like today.
  * (I3) FATAL-2 — ``langplugins`` imports neither ``framework`` nor ``tree_sitter`` at module scope.
  * (I8) LEAD boundary — ``insecure-randomness-sink`` / ``direct-taint`` stay LEAD-only through the plugin path.
  * registry totality on hostile input + ``all_extensions() ⊆ DEFAULT_EXTENSIONS``.
  * tamper-no-refire still holds for Python through the plugin.

The offense leg imports ``framework`` (DAA / the verify oracle), so this importorskips it.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

pytest.importorskip("framework")   # the verify oracle + DAA — offense leg only

from vigil_integration import codescan                               # noqa: E402
from vigil_integration.langplugins import registry                   # noqa: E402

# the existing Python FACT fixtures (mirrors analysis/tests/test_static_facts.py).
_A_PLANTED = "import hashlib\ndef sign(x):\n    return hashlib.md5(x).hexdigest()\n"
_A_SAFE = "import hashlib\ndef sign(x):\n    return hashlib.sha256(x).hexdigest()\n"
_C_PLANTED = "import requests\ndef fetch(u):\n    return requests.get(u, verify=False)\n"

_PY_FIXTURES = [
    ("broken-crypto-invocation", "static_broken_crypto", _A_PLANTED),
    ("insecure-flag-literal", "static_insecure_flag", _C_PLANTED),
]


def _obs(src, language="python", rule_id="broken-crypto-invocation", path="a.py", line=1):
    return {"rule_id": rule_id, "source": src, "language": language, "path": path, "line": line}


def _sig_tuple(s):
    """A stable, comparable projection of an OracleSignal — the fields that become the signed FACT."""
    return (s.kind, s.fired, s.confidence, s.evidence, tuple(sorted((s.observed or {}).items())))


@pytest.fixture(autouse=True)
def _default_off(monkeypatch):
    """Default every test to the flag-OFF world; a test flips it ON with ``monkeypatch.setenv``."""
    monkeypatch.delenv("VIGIL_MULTILANG_CODESCAN", raising=False)
    yield


# ---------------------------------------------------------------------------------------------------
# registry — the one new dispatch point (pure / total / deterministic)
# ---------------------------------------------------------------------------------------------------

def test_registry_for_language_and_for_path_resolve_python():
    assert registry.for_language("python").id == "python"
    assert registry.for_language("py").id == "python"          # the oracle's ("python","py") alias
    assert registry.for_language("PYTHON").id == "python"       # case-insensitive
    assert registry.for_path("pkg/sub/app.py").id == "python"
    assert registry.for_path("APP.PY").id == "python"


def test_registry_unregistered_language_and_path_are_none_fail_closed():
    # an UNREGISTERED language / non-.py path resolves to None — the fail-closed answer the FACT path treats
    # as today's non-Python refuse (a LEAD). Phase-1 registers ONLY Python.
    assert registry.for_language("javascript") is None
    assert registry.for_language("go") is None
    assert registry.for_path("app.js") is None
    assert registry.for_path("main.go") is None
    assert registry.for_path("README.md") is None


def test_registry_all_extensions_is_a_subset_of_default_extensions():
    # CRITICAL REGRESSION GUARD: phase-1 registers only Python, so the registry's extension union is a strict
    # SUBSET of DEFAULT_EXTENSIONS. DEFAULT_EXTENSIONS stays authoritative for the language-agnostic DAA walk —
    # deriving it from the registry now would SHRINK the multi-lang walk set (see the plan's DEFAULT_EXTENSIONS
    # note). This test is what makes "do not shrink it" enforceable.
    from framework.v2.analysis.models import DEFAULT_EXTENSIONS
    exts = registry.all_extensions()
    assert exts == frozenset({".py"})
    assert exts <= set(DEFAULT_EXTENSIONS)
    # the effective DAA tree-walk set is UNCHANGED (the hard-coded multi-language tuple, not the registry union).
    assert ".js" in DEFAULT_EXTENSIONS and ".go" in DEFAULT_EXTENSIONS and ".py" in DEFAULT_EXTENSIONS


def test_registry_is_total_on_hostile_input():
    # mirrors buildsys hostile-repo totality — no input raises.
    for bad in (None, "", 123, 0, b"x", "\x00", "/../../etc/passwd", "noext", ".", ".py", "x" * 5000):
        assert registry.for_path(bad) is None or registry.for_path(bad).id == "python"
        assert registry.for_language(bad) is None or registry.for_language(bad).id == "python"


def test_register_is_idempotent_and_ignores_a_blank_id():
    class _Blank:
        id = ""
        extensions = frozenset()
    assert registry.for_language("python").id == "python"   # python resolves before
    registry.register(_Blank())                             # a blank id must be ignored, not corrupt the maps
    assert registry.for_language("python").id == "python"   # ... and still resolves after
    assert registry.for_language("") is None


# ---------------------------------------------------------------------------------------------------
# the Python plugin — FACT-path methods REUSE the existing logic (byte-identical)
# ---------------------------------------------------------------------------------------------------

def test_python_plugin_reuses_the_oracle_fact_capable_set():
    from framework.v2.verify import oracles
    plugin = registry.for_language("python")
    # IS the oracle's own set — not a re-listing (so it can never drift).
    assert plugin.fact_capable_rule_ids is oracles._FACT_RULE_IDS
    assert plugin.fact_capable_rule_ids == {"broken-crypto-invocation", "insecure-flag-literal"}


def test_python_plugin_parse_symbols_matches_the_index_walk():
    from framework.v2.analysis.index import symbols_from_source
    plugin = registry.for_language("python")
    src = "import os\nclass K:\n    def m(self):\n        return os.getcwd()\n"
    got = plugin.parse_symbols(src, "m.py")
    expect, _err = symbols_from_source(src, "m.py")
    assert [(s.kind, s.name, s.line) for s in got] == [(s.kind, s.name, s.line) for s in expect]


def test_python_plugin_retain_region_matches_the_codescan_helper():
    plugin = registry.for_language("python")
    src = "import hashlib\n\ndef sign(x):\n    return hashlib.md5(x).hexdigest()\n"
    assert plugin.retain_region(src, 4) == codescan._retain_region_from_text(src, 4)


def test_python_plugin_static_tier_predicate_calls_the_existing_dispatch():
    import ast
    from framework.v2.verify import oracles
    plugin = registry.for_language("python")
    tree = ast.parse(_A_PLANTED)
    assert plugin.static_tier_predicate("broken-crypto-invocation", tree) == \
        oracles._static_tier_hit("broken-crypto-invocation", tree)


# ---------------------------------------------------------------------------------------------------
# HYBRID flag wiring at the oracle — byte-identical OFF, Python-through-plugin byte-identical ON
# ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id,src", [
    ("broken-crypto-invocation", _A_PLANTED),
    ("insecure-flag-literal", _C_PLANTED),
    ("broken-crypto-invocation", _A_SAFE),            # a safe twin (refuses) must also be identical
])
def test_oracle_signal_is_byte_identical_off_vs_on_for_python(rule_id, src, monkeypatch):
    from framework.v2.verify import oracles
    monkeypatch.delenv("VIGIL_MULTILANG_CODESCAN", raising=False)
    off = oracles.static_rule_oracle(_obs(src, rule_id=rule_id))
    monkeypatch.setenv("VIGIL_MULTILANG_CODESCAN", "1")
    on = oracles.static_rule_oracle(_obs(src, rule_id=rule_id))
    assert _sig_tuple(off) == _sig_tuple(on), f"{rule_id}: flag ON (plugin) must be byte-identical to OFF (ast)"


def test_non_python_refuse_is_identical_off_vs_on_fail_closed(monkeypatch):
    from framework.v2.verify import oracles
    obs = _obs("const h = md5(x);", language="javascript", path="a.js")
    monkeypatch.delenv("VIGIL_MULTILANG_CODESCAN", raising=False)
    off = oracles.static_rule_oracle(obs)
    monkeypatch.setenv("VIGIL_MULTILANG_CODESCAN", "1")
    on = oracles.static_rule_oracle(obs)
    assert off.fired is False and on.fired is False
    # an UNREGISTERED language with the flag ON takes the IDENTICAL refuse shape as today's non-Python refuse.
    assert _sig_tuple(off) == _sig_tuple(on)
    assert (on.observed or {}).get("reason") == "unsupported_language"


@pytest.mark.parametrize("rule_id", ["insecure-randomness-sink", "direct-taint"])
def test_lead_only_classes_stay_lead_through_the_plugin_path(rule_id, monkeypatch):
    # (I8) the LEAD-only boundary is preserved with the flag ON — these never mint a FACT, in any language.
    from framework.v2.verify import oracles
    monkeypatch.setenv("VIGIL_MULTILANG_CODESCAN", "1")
    firing_shaped = _obs("import random\ndef mk(m):\n    return derive_key(m, salt=random.random())\n",
                         rule_id=rule_id)
    sig = oracles.static_rule_oracle(firing_shaped)
    assert sig.fired is False and sig.confidence == 0.0


# ---------------------------------------------------------------------------------------------------
# full mint + offline re-verify — identical certs through the plugin (flag ON)
# ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id,bug_class,src", _PY_FIXTURES)
def test_python_fixture_mints_identical_cert_off_vs_on_and_reverifies(rule_id, bug_class, src, monkeypatch):
    from framework.v2.analysis.static_facts import confirm_code_region, static_fact_finding
    from framework.v2.evidence.certify import build_certificate
    from framework.v2.verify.reverify import reverify_finding

    def mint(flag):
        if flag:
            monkeypatch.setenv("VIGIL_MULTILANG_CODESCAN", "1")
        else:
            monkeypatch.delenv("VIGIL_MULTILANG_CODESCAN", raising=False)
        fact = confirm_code_region("app/mod.py", 3, src, rule_id)
        finding = static_fact_finding(fact)
        cert = build_certificate(finding, engagement_slug="mlp1")
        return fact, finding, cert

    off_fact, off_finding, off_cert = mint(False)
    on_fact, on_finding, on_cert = mint(True)

    assert off_fact.confirmed and on_fact.confirmed
    assert off_fact.bug_class == on_fact.bug_class == bug_class
    assert off_fact.confirmed_by == on_fact.confirmed_by == "static_rule"
    assert off_fact.confidence == on_fact.confidence
    assert off_fact.evidence == on_fact.evidence
    # the RETAINED bytes the cert binds are identical (this is what re-verifies offline).
    assert off_fact.oracle_context == on_fact.oracle_context
    assert off_finding == on_finding
    # the signed cert binds the same oracle_version + class + retained context through the plugin.
    assert off_cert.oracle_version == on_cert.oracle_version
    assert off_cert.bug_class == on_cert.bug_class
    assert off_cert.confirmed_by == on_cert.confirmed_by
    # both re-verify OFFLINE by re-running the pure oracle over the retained bytes.
    for finding in (off_finding, on_finding):
        r = reverify_finding(finding)
        assert r.ok and r.reproduced


def test_tamper_no_refire_through_the_plugin(monkeypatch):
    # mutating the retained region to remove the property flips the verdict to silent, with the flag ON.
    from framework.v2.analysis.static_facts import confirm_code_region, static_fact_finding
    from framework.v2.verify.reverify import reverify_finding
    monkeypatch.setenv("VIGIL_MULTILANG_CODESCAN", "1")
    fact = confirm_code_region("app/mod.py", 3, _A_PLANTED, "broken-crypto-invocation")
    finding = static_fact_finding(fact)
    finding["oracle_context"]["static_rule"]["source"] = _A_SAFE       # tamper: md5 -> sha256
    r = reverify_finding(finding)
    assert not r.reproduced, "a tampered retained region must NOT re-confirm, even through the plugin"


# ---------------------------------------------------------------------------------------------------
# codescan end-to-end — byte-identical static_facts OFF vs ON
# ---------------------------------------------------------------------------------------------------

def _run_codescan(tmp_path, flag, monkeypatch):
    if flag:
        monkeypatch.setenv("VIGIL_MULTILANG_CODESCAN", "1")
    else:
        monkeypatch.delenv("VIGIL_MULTILANG_CODESCAN", raising=False)
    src = tmp_path / ("on" if flag else "off")
    src.mkdir()
    (src / "sign.py").write_text(
        "import hashlib\ndef sign(data):\n    return hashlib.md5(data).hexdigest()\n", encoding="utf-8")
    base = tmp_path / ("base_on" if flag else "base_off")
    return codescan.run_codescan(root=str(src), slug="wc", base_dir=str(base), max_files=20)


def test_codescan_static_facts_are_byte_identical_off_vs_on(tmp_path, monkeypatch):
    off = _run_codescan(tmp_path, False, monkeypatch)
    on = _run_codescan(tmp_path, True, monkeypatch)

    def projection(res):
        return [(f["bug_class"], f["confirmed_by"], f["oracle_context"]["static_rule"]["rule_id"],
                 f["oracle_context"]["static_rule"]["source"]) for f in res["static_facts"]]

    assert len(off["static_facts"]) == 1
    assert projection(off) == projection(on)


def test_static_rule_for_is_byte_identical_off_vs_on(monkeypatch):
    class _AF:
        def __init__(self, path, rule_id):
            self.path = path
            self.rule_id = rule_id
    cases = [
        ("app.py", "DAA-WEAK-HASH", "broken-crypto-invocation"),
        ("app.py", "DAA-TLS-VERIFY-OFF", "insecure-flag-literal"),
        ("app.py", "DAA-EVAL", ""),               # not a FACT-capable DAA class
        ("app.js", "DAA-WEAK-HASH", ""),          # non-Python → fail-closed ""
        ("x.go", "DAA-WEAK-HASH", ""),
    ]
    for path, rule_id, expect in cases:
        monkeypatch.delenv("VIGIL_MULTILANG_CODESCAN", raising=False)
        off = codescan._static_rule_for(_AF(path, rule_id))
        monkeypatch.setenv("VIGIL_MULTILANG_CODESCAN", "1")
        on = codescan._static_rule_for(_AF(path, rule_id))
        assert off == on == expect, f"{path}/{rule_id}: expected {expect!r}, off={off!r} on={on!r}"


# ---------------------------------------------------------------------------------------------------
# (I3) FATAL-2 + (I4) no plugin import when OFF — proven in a clean subprocess via sys.modules
# ---------------------------------------------------------------------------------------------------

def _subprocess(code: str, *, flag_on: bool) -> dict:
    import json
    env = {k: v for k, v in os.environ.items()}
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    if flag_on:
        env["VIGIL_MULTILANG_CODESCAN"] = "1"
    else:
        env.pop("VIGIL_MULTILANG_CODESCAN", None)
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120)
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


_ORACLE_PROBE = r"""
import json, sys
from framework.v2.verify import oracles
obs = {"rule_id": "broken-crypto-invocation",
       "source": "import hashlib\ndef s(x):\n    return hashlib.md5(x).hexdigest()\n",
       "language": "python", "path": "a.py", "line": 1}
sig = oracles.static_rule_oracle(obs)
leaked = sorted(m for m in sys.modules if "langplugins" in m or "tree_sitter" in m or m == "tree_sitter")
print(json.dumps({"fired": bool(sig.fired), "leaked": leaked}))
"""


def test_flag_off_fires_python_and_imports_no_langplugins_or_tree_sitter():
    # (I4): with the flag unset, the Python FACT still fires AND no langplugins/tree_sitter module is imported.
    out = _subprocess(_ORACLE_PROBE, flag_on=False)
    assert out["fired"] is True
    assert out["leaked"] == [], f"OFF path imported a plugin/tree-sitter module: {out['leaked']}"


def test_flag_on_fires_python_through_the_plugin_and_imports_no_tree_sitter():
    # flag ON: the registry IS imported (the plugin route), but tree-sitter is NEVER imported (phase-1 adds no dep).
    out = _subprocess(_ORACLE_PROBE, flag_on=True)
    assert out["fired"] is True
    assert any("langplugins" in m for m in out["leaked"]), "ON path must import the plugin registry"
    assert not any("tree_sitter" in m for m in out["leaked"]), "phase-1 must import NO tree-sitter"


_IMPORT_PROBE = r"""
import json, sys
import vigil_integration.langplugins
import vigil_integration.langplugins.base
import vigil_integration.langplugins.registry
import vigil_integration.langplugins.python_plugin
import vigil_integration.multilang_flag
leaked = sorted(m for m in sys.modules if m == "framework" or m.startswith("framework.") or m == "tree_sitter")
print(json.dumps({"leaked": leaked}))
"""


def test_langplugins_package_imports_no_framework_or_tree_sitter_at_module_scope():
    # (I3) FATAL-2: importing the whole plugin package (incl. python_plugin) pulls neither framework nor
    # tree-sitter at module scope — every framework import is function-local, run only when a method is called.
    out = _subprocess(_IMPORT_PROBE, flag_on=False)
    assert out["leaked"] == [], f"langplugins imported framework/tree_sitter at module scope: {out['leaked']}"
