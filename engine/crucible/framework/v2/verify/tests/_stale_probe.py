"""Test-support fixture for the AUDIT-B in-repo-helper-inside-a-source-bound-lambda staleness proof.

It builds a GENUINE instance of the hole ``oracle_version`` closes this slice: an in-repo helper FUNCTION
reached ONLY inside a source-bound lambda (nested in a module-level constant container) and NOT captured by
the reachable-source closure walk on its own. ``test_oracle_version`` mutates ``_probe_helper``'s BODY on disk
in a subprocess and asserts ``_reachable_source_blob((probe_entry,))`` changes — proving the helper's SOURCE is
now inside the version, so a changed helper body can no longer ship under an unchanged id@version.

Nothing here is wired to any ``OracleKind`` or to any decision procedure; it exists only for the staleness
proof, and only ``test_oracle_version`` imports it. Its module name lives under ``framework.`` so the version
machinery classifies ``_probe_helper`` as an in-repo sibling (``_in_repo_modname``).
"""

from __future__ import annotations

from typing import Any


def _probe_helper(value: Any) -> int:
    # BODY-UNDER-TEST — the mutation test rewrites the integer literal on the RETURN line below (a one-line
    # edit, so every function's ``co_firstlineno`` stays valid). It must stay a single, uniquely-matchable
    # statement so the test can find and restore it deterministically.
    return len(str(value)) + 1


# A source-bound lambda nested in a module-level constant CONTAINER (the shape of ``_SECRET_RECOGNIZERS``).
# ``_canon`` recurses this tuple, source-binds the lambda's TEXT, and — with the fix — binds the in-repo
# helper it CALLS, which is reached ONLY here and is visited by the closure walk on NO other path.
_PROBE_RECOGNIZERS: "tuple[Any, ...]" = (
    lambda v: _probe_helper(v),
)


def probe_entry(observed: Any) -> int:
    """The synthetic 'oracle' entry point. It references the CONTAINER (so ``_reachable_source_blob`` reaches
    the lambda via ``_canon``) but NEVER ``_probe_helper`` directly — so the only path to the helper is inside
    the source-bound lambda. Editing ``_probe_helper``'s body must therefore move the version."""
    return sum(f(observed) for f in _PROBE_RECOGNIZERS)
