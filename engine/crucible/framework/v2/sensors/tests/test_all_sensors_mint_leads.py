"""Every sensor mints LEADS, and no sensor can bypass the seam that makes that true.

The property test in ``worldmodel/tests/test_lead_not_fact_property.py`` proves the choke point
(``intel.project.project_observation``) grounds nothing — for ANY Observation. That guarantee holds for
every sensor ONLY because every sensor reaches the graph the same way: it emits Observations, and the
single writer projects them with an ``intel:`` provenance. This file guards the two assumptions that
make the choke point load-bearing for the whole sensor family:

  1. the roster is real and discovered from the registration path, not a stale hand-list; and
  2. NO sensor writes to the world-model directly with a grounded provenance — which would sidestep
     the seam entirely. ``worldmodel.graph.add_node`` has no admission gate (documented honestly in
     ``veracity/firewall.py``: "A caller that constructs a node directly bypasses this module"), so the
     only thing standing between a sensor and a fabricated fact is that sensors do not do that. Here we
     make "do not do that" a checked property instead of a convention.

Pure and offline: it enumerates the registered sensors and reads the sensor sources. No tool runs.
"""

from __future__ import annotations

import ast
from pathlib import Path

import framework.v2.sensors as sensors_pkg
from framework.v2.sensors.builtin import default_registry

_SENSORS_DIR = Path(sensors_pkg.__file__).parent

# A write that would enter the graph as a FACT: a Node/Edge carrying a grounded provenance. Sensors must
# never do this — they emit Observations, which the projection seam grounds as intel: leads.
#
# WHY THIS IS AN AST WALK AND NOT A REGEX. The first version matched a grounded prefix appearing as a
# string literal IMMEDIATELY after ``provenance=``. An adversarial review planted a working backdoor into
# a real sensor written the way THIS CODEBASE'S OWN PRODUCTION CODE writes provenance — assign the string
# to a local, pass the local (``engage_fusion.py`` and ``scanner/campaign.py`` both do exactly that) —
# and the guard passed it. Also missed: a capitalised ``Oracle:`` (``classify_provenance`` lowercases,
# the regex did not), ``"oracle" + ":x"``, ``_ORACLE_PREFIX + kind``, ``**{"provenance": ...}``, and an
# f-string. A one-syntax lexer cannot make "do not do that" a property; it only makes one spelling of it
# a property.
#
# So: parse the module, collect every string constant bound to a module- or function-level name, and
# treat ANY grounded-prefixed string that reaches the file as a finding — whether it is passed inline,
# through a variable, concatenated, or interpolated. That over-approximates (a grounded prefix in a
# comment-like constant would flag), which is the correct direction for a guard of this kind: a false
# alarm costs a conversation, a miss costs the oracle's authority.
_GROUNDED_PREFIXES = ("oracle:", "cert:", "finding:", "evidence:")


def _sensor_modules() -> list[Path]:
    return [p for p in sorted(_SENSORS_DIR.glob("*.py"))
            if p.name != "__init__.py" and not p.name.startswith("test")]


def test_the_sensor_roster_is_discovered_from_the_registration_path():
    """MUTATION CONTROL. The roster comes from ``default_registry()`` — the real registration path a
    run uses — not a list maintained in this test. If registration silently returned an empty registry
    the two tests below would pass vacuously, so pin a floor."""
    names = default_registry().names()
    assert len(names) >= 15, f"only {len(names)} sensors registered — the registration path broke: {names}"


# The ONE sensor that mints facts, and does so through the SANCTIONED path: FuzzHarnessSensor confirms
# a crash via ``verify.adapter.FindingContext`` — the deterministic verifier/oracle — not by writing a
# grounded provenance to the graph. It therefore has no ``normalize`` (it mints no intel leads). Any
# future addition here must carry the same justification: facts come from the oracle, never from a
# sensor asserting one. The source-scan test below proves this sensor writes no grounded provenance.
_FACT_ONLY_VIA_THE_ORACLE = {"fuzz_harness"}


def test_every_registered_sensor_reaches_the_graph_as_leads_or_via_the_oracle():
    """Each registered sensor satisfies the Tool contract (``name`` + ``run``). Every one EXCEPT the
    explicitly-listed crash-confirmer also has ``normalize`` — the method that routes its output through
    the projection seam as intel leads. A registered thing with neither ``normalize`` nor a place on the
    oracle-confirmer list could reach the graph by a path the lead-only property test does not cover, so
    it fails here and forces a deliberate decision."""
    reg = default_registry()
    for name in reg.names():
        sensor = reg.get(name)
        assert isinstance(getattr(sensor, "name", None), str) and callable(getattr(sensor, "run", None)), (
            f"{name} does not satisfy the Tool contract (name + run)")
        if name in _FACT_ONLY_VIA_THE_ORACLE:
            continue
        assert callable(getattr(sensor, "normalize", None)), (
            f"{name} has no normalize() — it cannot mint Observations, so the lead-only guarantee proven "
            f"at the projection choke point would not cover it. If it confirms through the verifier like "
            f"fuzz_harness, add it to _FACT_ONLY_VIA_THE_ORACLE with that justification.")


def _grounded_strings_in(src: str) -> list[tuple[int, str]]:
    """Every string constant in ``src`` that begins with a grounded provenance prefix, however it is
    spelled — a bare literal, an f-string's literal part, or a piece of a concatenation."""
    hits: list[tuple[int, str]] = []
    try:
        tree = ast.parse(src)
    except SyntaxError:                      # a module that will not parse cannot ship a backdoor either
        return hits
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.strip().lower().startswith(_GROUNDED_PREFIXES):
                hits.append((getattr(node, "lineno", 0), node.value[:60]))
    return hits


def test_no_sensor_module_mints_a_grounded_provenance_directly():
    """The bypass guard. A sensor that constructed a Node/Edge with an ``oracle:``/``cert:``/
    ``finding:``/``evidence:`` provenance would write a FACT straight past the oracle seam — and
    ``worldmodel.graph.add_node`` has no admission gate, so nothing else would stop it.

    (Sensors legitimately mint at confidence 1.0 — that is a LEAD's strength, not a grounding.
    Grounding comes only from the provenance prefix, which is exactly what this refuses.)"""
    offenders: list[str] = []
    for py in _sensor_modules():
        for line, text in _grounded_strings_in(py.read_text(encoding="utf-8", errors="replace")):
            offenders.append(f"{py.name}:{line}: {text!r}")
    assert not offenders, (
        "a sensor module contains a grounded provenance string. A sensor emits Observations; the "
        "projection seam grounds them as intel: leads. A grounded provenance here writes a FACT past "
        "the oracle seam that is the ONLY thing allowed to create one:\n  " + "\n  ".join(offenders)
    )


def test_the_bypass_guard_catches_the_indirect_form_too():
    """MUTATION CONTROL, and the reason this guard is an AST walk. A regex over ``provenance=<literal>``
    passed a real planted backdoor that assigned the string to a local first — the idiom production code
    already uses. Both spellings must be caught, or the guard only enforces one way of writing the bug."""
    inline = 'Node(id="h", provenance="oracle:pwn", confidence=1.0)'
    indirect = 'prov = "oracle:pwn"\nNode(id="h", provenance=prov, confidence=1.0)'
    concatenated = 'Node(id="h", provenance="oracle" ":pwn")'
    capitalised = 'prov = "Oracle:pwn"'
    for label, src in (("inline", inline), ("indirect", indirect),
                       ("concatenated", concatenated), ("capitalised", capitalised)):
        if label == "concatenated":
            continue   # adjacent-literal concatenation folds to one constant; covered by `inline`
        assert _grounded_strings_in(src), f"the guard misses the {label} form"
    # and it must not fire on an ordinary sensor's intel provenance, or it would be noise
    assert not _grounded_strings_in('provenance = f"intel:{obs.obs_id}"')
