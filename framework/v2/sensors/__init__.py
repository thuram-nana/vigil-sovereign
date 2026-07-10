"""
sensors — the Universal Sensor/Producer framework (Wave 2).

CRUCIBLE is the reasoning OS; every tool is a SENSOR. A ``Sensor`` is a gated W1.4 ``Tool`` that also
knows how to NORMALIZE its output into the ONE evidence model: ``run_sensor`` gates it (kill-switch /
entitlement / scope / destructive / egress), then its ``normalize`` turns the raw output into
``intel.Observation``s that project into the shared world-model as provenance-labelled facts
(``GROUNDING_INTEL``) — never oracle-proof until a deterministic oracle re-verifies them.

Wave 2.1 ships the framework + a safe reference producer (``DeclaredServiceSensor``, the first
HOST/SERVICE/HOSTS minter). Wave 2.2 adds the ``NmapServiceSensor`` (the first mature external engine
driven as a gated sensor); Wave 2.3 the service-reachability oracle.
"""

from __future__ import annotations

from .base import Sensor, SensorResult, service_observations
from .builtin import DeclaredServiceSensor, default_registry, register_builtin_sensors
from .nmap import NmapServiceSensor, parse_nmap_xml
from .pipeline import run_sensor
from .tshark import TsharkFlowSensor, parse_tshark_fields

__all__ = [
    "Sensor", "SensorResult", "service_observations",
    "run_sensor",
    "DeclaredServiceSensor", "default_registry", "register_builtin_sensors",
    "NmapServiceSensor", "parse_nmap_xml",
    "TsharkFlowSensor", "parse_tshark_fields",
]
