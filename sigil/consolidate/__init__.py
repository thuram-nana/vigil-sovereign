"""SIGIL consolidation — the ARCHIVIST nightly pass (SIGIL §6.3).

Agent-driven extraction of durable facts (decisions/commitments/entities) from the spine,
behind a DEMOTE-ONLY veracity gate that re-executes every citation, promoting only
spine-traceable facts as new provenance-linked records. Offense-free by construction: imports
zero framework.* modules (assert_no_offense enforced at import)."""
from ..reuse import assert_no_offense

assert_no_offense()  # doctrine §12: no engine module may be loaded in a SIGIL process

from .extract import (  # noqa: E402
    AgentProvider,
    ApiProvider,
    HeuristicProvider,
    LocalProvider,
    ReplayProvider,
)
from .pipeline import ConsolidationReport, run_consolidation  # noqa: E402
from .queries import due_commitments, open_threads, pending_contradictions  # noqa: E402

# provider registry — the owner-facing choice (SIGIL D5): claude (Max) / api (key) / local (Ollama).
PROVIDERS = {
    "claude": AgentProvider,       # headless `claude -p` on the Max plan (owner preference)
    "api": ApiProvider,            # metered Anthropic API key
    "local": LocalProvider,        # local Ollama
    "heuristic": HeuristicProvider,  # offline, no LLM (default; zero cost)
    "replay": ReplayProvider,      # captured fixture (tests)
}

__all__ = [
    "run_consolidation", "ConsolidationReport", "PROVIDERS",
    "AgentProvider", "ApiProvider", "LocalProvider", "HeuristicProvider", "ReplayProvider",
    "open_threads", "due_commitments", "pending_contradictions",
]
