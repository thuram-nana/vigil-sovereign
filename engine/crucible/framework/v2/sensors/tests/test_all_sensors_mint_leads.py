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

import re
from pathlib import Path

import framework.v2.sensors as sensors_pkg
from framework.v2.sensors.builtin import default_registry

_SENSORS_DIR = Path(sensors_pkg.__file__).parent

# A write that would enter the graph as a FACT: a Node/Edge constructed with a grounded provenance.
# Sensors must never do this — they emit Observations, which the projection seam grounds as intel: leads.
_GROUNDED_PROV_RE = re.compile(r'provenance\s*=\s*[fr]?["\'](oracle:|cert:|finding:|evidence:)')


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


def test_no_sensor_module_mints_a_grounded_provenance_directly():
    """The bypass guard. A sensor that constructed a Node/Edge with an ``oracle:``/``cert:``/
    ``finding:``/``evidence:`` provenance would write a FACT straight past the oracle seam. Scan every
    sensor source and refuse the pattern. (Sensors legitimately mint at confidence 1.0 — that is a
    LEAD's strength, not a grounding; grounding comes only from the provenance prefix.)"""
    offenders: list[str] = []
    for py in _sensor_modules():
        src = py.read_text(encoding="utf-8", errors="replace")
        for m in _GROUNDED_PROV_RE.finditer(src):
            line = src[:m.start()].count("\n") + 1
            offenders.append(f"{py.name}:{line}: {m.group(0)!r}")
    assert not offenders, (
        "a sensor mints a grounded provenance directly, bypassing the oracle seam that is the ONLY "
        "thing allowed to create a fact:\n  " + "\n  ".join(offenders)
    )
