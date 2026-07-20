"""
kernel — URK, the Universal Reasoning Kernel.

URK turns the v1 cognitive prose (framework/cognitive/*.md) into
typed, callable functions backed by an LLM. Every binding loads the
relevant section of the cognitive doc, prompts the LLM, and parses
the response into a Pydantic schema.

Public surface:

    from framework.v2.kernel import (
        hypothesize,        # → HypothesisSet
        critique,           # → CritiqueResult
        pivot,              # → PivotProposal
        decide,             # → SeverityDecision
        opsec,              # → OpsecGuidance
        threat_model,       # → ThreatModel
    )

The default LLM backend is DryRun, which writes the prompt to disk
and returns a deterministic stub. Set ANTHROPIC_API_KEY (and install
`anthropic`) or run a local Ollama server to upgrade. See backends/.
"""

from __future__ import annotations

from .consistency import (
    ConsistencyResult, consistency_evidence, run_consistent, sample_workers,
)
from .critique import critique
from .decide import decide, decide_consistent
from .hypothesize import hypothesize, hypothesize_consistent
from .opsec import opsec
from .pivot import pivot, pivot_consistent
from .threat_model import threat_model, threat_model_consistent

__all__ = [
    "critique",
    "decide",
    "decide_consistent",
    "hypothesize",
    "hypothesize_consistent",
    "run_consistent",
    "sample_workers",
    "ConsistencyResult",
    "consistency_evidence",
    "opsec",
    "pivot",
    "pivot_consistent",
    "threat_model",
    "threat_model_consistent",
]
