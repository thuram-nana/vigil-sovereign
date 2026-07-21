"""
vigil_integration.live — the LIVE bindings that replace the F1–F12 injected thunks with real backends
(VIGIL-LIVE, §12). Each module here is a drop-in for one injected seam: the Kali tool executor, the
Neo4j graph writer, the garak/PyRIT subprocess gauntlet, the OTLP span exporter, the Claude think-step,
and the vigil_core signed-spine checkpoint. Going live changes NOTHING about the sovereign contract —
the LLM/tools only propose, only the oracle mints a signed FACT, only the conjunctive gate authorizes,
and only the egress gate (pinned to loopback for validation) lets traffic out.

Exports are wired by the unified engine (§12 WS-2) after each binder lands; importing a specific binder
directly (``from vigil_integration.live.executor import ...``) always works.
"""
