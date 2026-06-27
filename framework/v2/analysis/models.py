"""
analysis.models — normalized schemas for DAA.

Every analyzer, built-in or external, produces `AnalysisFinding`s in one
shape so the reasoning kernel sees a single contract regardless of the
underlying tool. An `AnalysisReport` records what ran, what was skipped
(and why), and the merged findings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

# Default source extensions DAA walks. Operators can override per target.
DEFAULT_EXTENSIONS: tuple[str, ...] = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php",
    ".java", ".rs", ".yaml", ".yml", ".tf", ".sh", ".sql",
)


class AnalysisTarget(BaseModel):
    """What to analyze. `root` is a directory or a single file."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(min_length=1)
    extensions: tuple[str, ...] = Field(default=DEFAULT_EXTENSIONS)
    max_files: int = Field(default=5000, ge=1, description="Safety cap on tree walk.")
    max_file_bytes: int = Field(default=2_000_000, ge=1)

    def iter_files(self) -> list[Path]:
        """Source files under root matching the extension filter, sorted
        for determinism and capped at max_files."""
        root = Path(self.root).expanduser()
        if root.is_file():
            return [root]
        out: list[Path] = []
        for p in sorted(root.rglob("*")):
            if len(out) >= self.max_files:
                break
            if p.is_file() and p.suffix in self.extensions:
                out.append(p)
        return out


class AnalysisFinding(BaseModel):
    """One normalized static-analysis result."""

    model_config = ConfigDict(extra="forbid")

    analyzer: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    severity: str = Field(default="medium", pattern=r"^(info|low|medium|high|critical)$")
    path: str
    line: int = Field(ge=0)
    message: str
    snippet: str = ""
    cwe: str = ""

    def dedup_key(self) -> str:
        return f"{self.path}:{self.line}:{self.rule_id}"


class SkippedAnalyzer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    reason: str


class AnalysisReport(BaseModel):
    """The merged result of an analysis run."""

    model_config = ConfigDict(extra="forbid")

    root: str
    files_scanned: int = Field(ge=0)
    analyzers_run: list[str] = Field(default_factory=list)
    analyzers_skipped: list[SkippedAnalyzer] = Field(default_factory=list)
    findings: list[AnalysisFinding] = Field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


@runtime_checkable
class Analyzer(Protocol):
    """The contract every analyzer satisfies — built-in or external."""

    name: str

    def is_available(self) -> tuple[bool, str]:
        """(available, reason). Reason explains a False so the report can
        record why an analyzer was skipped."""
        ...

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        ...
