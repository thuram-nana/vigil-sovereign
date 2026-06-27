"""
analysis.analyzers.external — adapters over external SAST tools.

The Semgrep adapter is the reference implementation of the external
contract: probe for the binary, shell out with JSON output, normalize to
`AnalysisFinding`. CodeQL and Joern adapters follow the same shape
(probe → run → normalize). When the tool is absent, `is_available`
returns False with a reason and the orchestrator records the analyzer as
skipped — capability degrades visibly, never silently.

Subprocess use is bounded: a timeout, JSON-only output, and no shell.
The framework does not install these tools; a deployment that wants deep
external analysis provisions them on the analysis host.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ...common.errors import BackendError, BackendUnavailable
from ..models import AnalysisFinding, AnalysisTarget

# Map Semgrep severities to the normalized scale.
_SEMGREP_SEVERITY: dict[str, str] = {
    "INFO": "info",
    "WARNING": "medium",
    "ERROR": "high",
}


class SemgrepAnalyzer:
    """Adapter over the `semgrep` CLI. Skipped gracefully when absent."""

    name = "semgrep"

    def __init__(self, config: str = "auto", timeout_s: int = 300) -> None:
        self._config = config
        self._timeout_s = timeout_s

    def is_available(self) -> tuple[bool, str]:
        path = shutil.which("semgrep")
        if path is None:
            return False, "semgrep not on PATH (install to enable deep static analysis)"
        return True, f"semgrep at {path}"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        available, reason = self.is_available()
        if not available:
            raise BackendUnavailable(reason)

        root = Path(target.root).expanduser()
        cmd = [
            "semgrep", "--json", "--quiet", "--disable-version-check",
            "--config", self._config, str(root),
        ]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendError(f"semgrep timed out after {self._timeout_s}s") from e
        except OSError as e:
            raise BackendError(f"semgrep failed to launch: {e}") from e

        if not proc.stdout.strip():
            # Semgrep returns non-zero on findings; only treat empty stdout
            # with a non-zero code as a real failure.
            if proc.returncode != 0:
                raise BackendError(
                    f"semgrep exited {proc.returncode}: {proc.stderr.strip()[:300]}"
                )
            return []

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise BackendError(f"semgrep output was not valid JSON: {e}") from e

        return self._normalize(data, root)

    def _normalize(self, data: object, root: Path) -> list[AnalysisFinding]:
        if not isinstance(data, dict):
            return []
        results = data.get("results", [])
        if not isinstance(results, list):
            return []
        out: list[AnalysisFinding] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            extra = r.get("extra", {}) if isinstance(r.get("extra"), dict) else {}
            start = r.get("start", {}) if isinstance(r.get("start"), dict) else {}
            sev = _SEMGREP_SEVERITY.get(str(extra.get("severity", "WARNING")).upper(), "medium")
            raw_path = str(r.get("path", ""))
            try:
                rel = str(Path(raw_path).relative_to(root)) if root.is_dir() else raw_path
            except ValueError:
                rel = raw_path
            out.append(
                AnalysisFinding(
                    analyzer=self.name,
                    rule_id=str(r.get("check_id", "semgrep-rule")),
                    severity=sev,
                    path=rel,
                    line=int(start.get("line", 0) or 0),
                    message=str(extra.get("message", "")).strip()[:500] or "semgrep finding",
                    snippet=str(extra.get("lines", "")).strip()[:200],
                    cwe=_first_cwe(extra),
                )
            )
        out.sort(key=lambda f: (f.path, f.line, f.rule_id))
        return out


def _first_cwe(extra: dict[str, object]) -> str:
    meta = extra.get("metadata", {})
    if isinstance(meta, dict):
        cwe = meta.get("cwe")
        if isinstance(cwe, list) and cwe:
            return str(cwe[0])
        if isinstance(cwe, str):
            return cwe
    return ""
