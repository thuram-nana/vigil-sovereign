"""
sensors.pipeline — run a Sensor through the gated producer pipeline (Wave 2.1).

    invoke_tool (W1.4 fail-closed gate chain)  ->  sensor.normalize  ->  IntelIngest.ingest

One call: gate the sensor (kill-switch / entitlement / scope / destructive / egress), and only if it
ran, normalize its output into Observations and project them into the SHARED world-model. A refused
or failed sensor mints nothing — prove-don't-guess and fail-closed hold end to end. Deterministic:
the caller supplies ``seq`` (the monotonic clock), and normalize→project is pure.
"""

from __future__ import annotations

from typing import Any

from ..agents.tools import ToolContext, ToolRegistry, invoke_tool
from ..intel.ingest import IntelIngest
from .base import SensorResult


def run_sensor(
    registry: ToolRegistry,
    name: str,
    args: dict,
    ctx: ToolContext,
    *,
    ingest: IntelIngest,
    seq: int,
    sink: Any = None,
) -> SensorResult:
    """Gate + run the registered sensor ``name``, then normalize its output into Observations and
    ingest them into ``ingest``'s world-model. A refused/failed invocation returns a SensorResult
    with no observations (nothing is minted). Best-effort normalization/ingest: a normalizer that
    raises yields zero observations rather than sinking the run. ``seq`` stamps the whole batch on
    the monotonic clock."""
    result = invoke_tool(registry, name, args, ctx, sink=sink)
    if not result.ok or result.refused:
        return SensorResult(result=result)

    sensor = registry.get(name)
    normalize = getattr(sensor, "normalize", None)
    if not callable(normalize):
        return SensorResult(result=result)   # a plain tool with no normalizer mints nothing
    try:
        observations = normalize(result, ctx, seq=seq)
    except Exception:
        observations = []
    if not observations:
        return SensorResult(result=result)

    try:
        ingested = ingest.ingest(observations, seq=seq)
        applied, dropped = ingested.applied, ingested.dropped
    except Exception:
        applied = dropped = 0
    return SensorResult(result=result, observations=observations, applied=applied, dropped=dropped)
