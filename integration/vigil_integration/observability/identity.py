"""
observability.identity — DETERMINISTIC span/trace/observation id derivation (VIGIL-FUSION F11, C11).

pentagi threads one cross-cutting ``Observation{ID, TraceID, Time}`` object through BOTH its
knowledge-graph writes AND its telemetry stack, so a graph mutation and the distributed trace that
produced it share one identity. VIGIL adopts that pattern but binds the identity to the SIGNED SPINE:
a span/observation id is derived deterministically from the injected spine record hash / sequence, so
a trace and the spine record it describes share an id and the whole trace is offline-verifiable AND
debuggable.

The sovereign rule this module upholds: **no wallclock, no RNG.** An OTel span id is normally random
and a trace is stamped with ``Date.now``; both would make the trace non-reproducible and break the
"re-execution, not string trust" veracity rule. Here every id is a pure ``sha256`` of injected spine
identity — re-deriving from the same spine hash/seq yields a byte-identical id forever. Timestamps are
NOT read from the clock; the caller passes an injected monotone integer (the spine sequence).

Total: every function coerces its input and never raises (a malformed identity degrades to a stable
derived id, never a crash). Stdlib only.
"""

from __future__ import annotations

import hashlib
from typing import Any

# OTel wire widths: trace id = 128 bits (32 hex), span id = 64 bits (16 hex). We keep those widths so
# a span is shape-compatible with an OTel collector, while deriving the bytes deterministically from
# spine identity (never randomly). The observation id is a Langfuse-style id (32 hex here).
_TRACE_HEX = 32
_SPAN_HEX = 16
_OBS_HEX = 32


def _norm(v: Any) -> str:
    """Coerce any input to a stable string for hashing. Total — never raises."""
    if isinstance(v, str):
        return v
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:  # noqa: BLE001 — a __str__ that raises must not crash id derivation
        return ""


def _seq_token(seq: Any) -> str:
    """The sequence component of an id basis. A real spine sequence is an int; anything else (incl.
    ``bool``, which is an ``int`` subclass but not a sequence) contributes an empty token so the id
    stays a pure function of the *valid* injected identity."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        return ""
    return str(seq)


def _digest(basis: str, width: int) -> str:
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:width]


def derive_trace_id(root: Any) -> str:
    """A deterministic 128-bit (32-hex) trace id for an engagement, derived from its ROOT spine hash
    (or any stable root key). Same root → same trace id, forever; no clock, no RNG."""
    return _digest("vigil.trace/" + _norm(root), _TRACE_HEX)


def derive_span_id(spine_hash: Any, seq: Any = None, *, salt: str = "") -> str:
    """A deterministic 64-bit (16-hex) span id, keyed on the injected SPINE RECORD HASH (preferred) and
    the spine sequence. ``salt`` disambiguates two spans that legitimately share a spine record (e.g. a
    parent/child pair projected off one event). Total; a non-str hash / non-int seq still yield a stable
    id from whatever identity is present."""
    basis = f"vigil.span/{_norm(spine_hash)}/{_seq_token(seq)}/{_norm(salt)}"
    return _digest(basis, _SPAN_HEX)


def derive_observation_id(spine_hash: Any, seq: Any = None, *, kind: str = "", name: str = "",
                          salt: str = "") -> str:
    """A deterministic 32-hex observation id keyed on spine identity plus the observation kind/name, so
    two distinct observations projected off the same spine record (e.g. a Guardrail and an Evaluator on
    one event) get distinct, reproducible ids. No clock, no RNG."""
    basis = (f"vigil.obs/{_norm(spine_hash)}/{_seq_token(seq)}/"
             f"{_norm(kind)}/{_norm(name)}/{_norm(salt)}")
    return _digest(basis, _OBS_HEX)


def span_id_matches(span_id: Any, spine_hash: Any, seq: Any = None, *, salt: str = "") -> bool:
    """Offline verification helper: re-derive a span id from the claimed spine identity and check it
    matches. Because derivation is pure, anyone can confirm a span truly belongs to the spine record it
    names. Total — returns False on any malformed input rather than raising."""
    if not isinstance(span_id, str) or not span_id:
        return False
    return derive_span_id(spine_hash, seq, salt=salt) == span_id
