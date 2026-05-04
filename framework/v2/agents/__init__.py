"""
agents — MAO, the Multi-Agent Orchestration layer.

Decomposes OBSIDIAN into specialised sub-agents communicating via a
shared blackboard. The blackboard is the single source of truth for
engagement state; every agent reads from it, writes to it, and is
gated by the typed event-kind contracts in `models.py`.

Public surface:

    from framework.v2.agents import open_blackboard
    from framework.v2.agents.blackboard import Blackboard
    from framework.v2.agents.coordinator import Coordinator
    from framework.v2.agents.recon_agent import ReconAgent
    from framework.v2.agents.hypothesis_agent import HypothesisAgent
    from framework.v2.agents.exploit_agent import ExploitAgent
    from framework.v2.agents.critique_agent import CritiqueAgent
    from framework.v2.agents.reporter_agent import ReporterAgent
    from framework.v2.agents.memory_agent import MemoryAgent
"""

from __future__ import annotations

from .blackboard import Blackboard, open_blackboard

__all__ = ["Blackboard", "open_blackboard"]
