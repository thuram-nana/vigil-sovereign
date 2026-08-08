"""vigil_integration.brains — pluggable reasoning cores ("brains") for the VIGIL agent body.

A brain is PROPOSE-ONLY: given a target profile it emits a proposed tool list + parameters + an ordered
attack chain, as LEADs. It computes no facts, self-authorizes nothing, touches no network. Every proposal
crosses VIGIL's conjunctive gate + egress gate and is executed only through the gated external-tool
runner; a finding becomes a FACT solely when a deterministic VIGIL oracle fires. The brain never reaches
that path.

``hexstrike_brain`` is a clean-room, drift-free reimplementation of hexstrike-ai's deterministic decision
model (design (c) 2026 Muhammad Osama / 0x4m4, MIT — see ``vendor/hexstrike-ai/``).
"""

from .hexstrike_brain import (  # noqa: F401
    AttackChain,
    AttackStep,
    HexstrikeBrain,
    TargetProfile,
    TargetType,
    TechnologyStack,
    ToolDanger,
)

__all__ = [
    "HexstrikeBrain",
    "TargetProfile",
    "TargetType",
    "TechnologyStack",
    "AttackStep",
    "AttackChain",
    "ToolDanger",
]
