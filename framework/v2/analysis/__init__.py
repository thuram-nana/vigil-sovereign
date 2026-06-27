"""
analysis — DAA, the Deep Analysis Arsenal (Milestone M5).

The deep-sensing layer. The framework reasons well; DAA gives it
something rich to reason over. It orchestrates static analysis, presents
every analyzer's output in one normalized shape, and builds a queryable
symbol index — the raw material a reasoning kernel turns into
hypotheses. Reasoning over deep analysis is the difference between a
clever scanner and a Big-Sleep-class system.

Two classes of analyzer:

  - **Built-in, offline, always available.** A pattern analyzer with a
    curated dangerous-pattern ruleset that runs with no external
    dependency. Real, deterministic SAST you can run today.
  - **External adapters.** Wrappers over Semgrep (and, by the same
    contract, CodeQL / Joern) that shell out when the tool is installed
    and degrade gracefully — reported as skipped with a reason — when it
    is not. No silent capability loss.

Plus a Python symbol index (`index.py`) over AST: functions, classes,
imports, call sites — queryable by the kernel.

Whole-tree analysis is gated on Capability.DEEP_STATIC_ANALYSIS.

Public surface:

    from framework.v2.analysis import (
        AnalysisTarget, AnalysisFinding, AnalysisReport, Analyzer,
        PatternAnalyzer, SemgrepAnalyzer, run_analysis,
        SymbolIndex, build_symbol_index,
    )
"""

from __future__ import annotations

from .analyzers.builtin import PatternAnalyzer
from .analyzers.external import SemgrepAnalyzer
from .analyzers.joern import JoernAnalyzer
from .index import SymbolIndex, build_symbol_index
from .models import (
    AnalysisFinding,
    AnalysisReport,
    AnalysisTarget,
    Analyzer,
    SkippedAnalyzer,
)
from .orchestrator import run_analysis

__all__ = [
    "AnalysisTarget",
    "AnalysisFinding",
    "AnalysisReport",
    "Analyzer",
    "SkippedAnalyzer",
    "PatternAnalyzer",
    "SemgrepAnalyzer",
    "JoernAnalyzer",
    "run_analysis",
    "SymbolIndex",
    "build_symbol_index",
]
