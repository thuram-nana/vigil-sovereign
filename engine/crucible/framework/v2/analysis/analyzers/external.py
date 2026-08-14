"""
analysis.analyzers.external — adapters over external SAST tools.

The Semgrep adapter is the reference implementation of the external
contract: probe for the binary, shell out with JSON output, normalize to
`AnalysisFinding`. CodeQL and Joern adapters follow the same shape
(probe → run → normalize). When the tool is absent, `is_available`
returns False with a reason and the orchestrator records the analyzer as
skipped — capability degrades visibly, never silently.

Also here, on that same contract: `bandit` (Python-idiom SAST) and the
two secret scanners `gitleaks` / `trufflehog`. All five are source
analyzers — they take a DIRECTORY, not a host — which is why they live
behind the Analyzer protocol and not behind the live executor's typed
argv builders (those fail closed without a network target).

Everything any of these adapters emits is a LEAD. A pattern or entropy
match is not proof a sink is reachable or a credential is live, and
nothing below marks a finding confirmed or grounded.

NO EGRESS is a charter rule on this host, not a preference: no tool, no
DNS, no callback. It constrains the argv of two adapters below —
trufflehog is run with `--no-verification` (without it, it calls the
third-party API of every provider it recognises, carrying the operator's
real secrets out of scope), and gitleaks is given nothing that fetches or
updates a ruleset. Each site carries that reasoning inline.

Secret scanners hand back the credential itself. It is masked before it
reaches a finding (see `_SECRET_MASK`): a finding names the rule, the
file and the line, never the value.

Subprocess use is bounded: a timeout, JSON-only output, and no shell.
The framework does not install these tools; a deployment that wants deep
external analysis provisions them on the analysis host.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path

from ...common.errors import BackendError, BackendUnavailable
from ..models import AnalysisFinding, AnalysisTarget

# Map Semgrep severities to the normalized scale.
_SEMGREP_SEVERITY: dict[str, str] = {
    "INFO": "info",
    "WARNING": "medium",
    "ERROR": "high",
}

# bandit's own three-level scale.
_BANDIT_SEVERITY: dict[str, str] = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
}

# The stand-in for a credential a tool handed back. Same device — and the same glyphs —
# as ``imports/parsers.py:_HYDRA_MASK``, which masks hydra's proven password in the
# evidence string persisted to the intel store and rendered into reports. A finding is
# not weakened by this: it still names the rule, the file and the line that leaked. The
# raw value stays where the operator already has it — in their own source tree.
_SECRET_MASK = "•••• (masked)"

# bandit's B105/B106/B107 (hardcoded_password_string / _funcarg / _default) interpolate the
# MATCHED VALUE into their issue text — ``Possible hardcoded password: '<value>'`` — so
# passing that text through verbatim would persist a real credential into the report, which
# is exactly the leak the secret scanners are masked for. Mask the quoted value instead.
_BANDIT_CREDENTIAL_TESTS = frozenset({"B105", "B106", "B107"})
_SINGLE_QUOTED = re.compile(r"'[^']*'")


def _scrub(text: str, secrets: Iterable[str]) -> str:
    """Strip every raw credential a tool handed us out of a string bound for a finding.

    Applied to ALL tool-controlled text a secret scanner emits, not just the obvious
    ``Secret``/``Raw`` fields: rule descriptions and detector names come from tool config,
    and a custom rule that interpolates its hit would otherwise walk the credential into
    the report. Unconditional on length — mangling a short match is cosmetic, leaking it
    is a charter breach."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, _SECRET_MASK)
    return text


def _line_of(value: object) -> int:
    """A tool's line number, coerced totally and clamped at zero.

    ``AnalysisFinding.line`` is ``ge=0``, so a garbled or negative line raises a pydantic
    ValidationError — which is NOT a ``CrucibleError``, so the orchestrator's per-analyzer
    catch would miss it and one malformed record would abort the WHOLE report instead of
    degrading that analyzer."""
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _relative_path(raw_path: str, root: Path) -> str:
    """A tool's absolute path reported relative to the analyzed root — findings travel
    into reports, where an analysis-host absolute path is noise. Total: a path outside the
    root (or a non-directory root, e.g. a single-file target) is passed through as-is."""
    try:
        return str(Path(raw_path).relative_to(root)) if root.is_dir() else raw_path
    except ValueError:
        return raw_path


def shipped_rules_dir() -> Path:
    """The framework's curated taint ruleset, so semgrep does real
    dataflow analysis offline without the semgrep.dev registry."""
    return Path(__file__).resolve().parent.parent / "rules"


class SemgrepAnalyzer:
    """Adapter over the `semgrep` CLI, run in TAINT mode against the
    framework's shipped dataflow ruleset by default. Each finding means
    untrusted input provably reaches a sink — not a regex match. Skipped
    gracefully when the binary is absent.

    Pass `config="auto"` for the semgrep.dev registry (needs network) or a
    path to a custom ruleset."""

    name = "semgrep"

    def __init__(self, config: str | None = None, timeout_s: int = 300) -> None:
        self._config = config if config is not None else str(shipped_rules_dir())
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
            rel = _relative_path(str(r.get("path", "")), root)
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


class BanditAnalyzer:
    """Adapter over the `bandit` CLI — Python-specific AST checks (shell=True,
    yaml.load, weak crypto, `assert` in production, hardcoded credentials).

    It complements semgrep rather than repeating it: bandit's value is the
    breadth of Python-idiom checks, not dataflow — it does not prove a sink is
    reachable, so every result is a LEAD. Skipped gracefully when the binary is
    absent."""

    name = "bandit"

    def __init__(self, timeout_s: int = 300) -> None:
        self._timeout_s = timeout_s

    def is_available(self) -> tuple[bool, str]:
        path = shutil.which("bandit")
        if path is None:
            return False, "bandit not on PATH (install to enable Python-specific SAST)"
        return True, f"bandit at {path}"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        available, reason = self.is_available()
        if not available:
            raise BackendUnavailable(reason)

        root = Path(target.root).expanduser()
        # `-q` keeps the human progress banner out of the document we parse; with it,
        # bandit prints NOTHING at all on a clean tree, which is why the empty-stdout
        # branch below has to distinguish "clean" from "failed" by the exit code.
        # NO EGRESS: bandit has no network behaviour and no flag is added that would
        # give it one — the charter forbids all outbound traffic from this host.
        cmd = ["bandit", "-f", "json", "-q", "-r", str(root)]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendError(f"bandit timed out after {self._timeout_s}s") from e
        except OSError as e:
            raise BackendError(f"bandit failed to launch: {e}") from e

        if not proc.stdout.strip():
            # bandit exits 1 whenever it finds an issue, so a non-zero code alone is not a
            # failure — only a non-zero code with nothing on stdout is (same reading the
            # semgrep adapter above applies to its own exit codes).
            if proc.returncode != 0:
                raise BackendError(
                    f"bandit exited {proc.returncode}: {proc.stderr.strip()[:300]}"
                )
            return []

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise BackendError(f"bandit output was not valid JSON: {e}") from e

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
            rule_id = str(r.get("test_id", "") or "").strip() or "bandit-issue"
            sev = _BANDIT_SEVERITY.get(str(r.get("issue_severity", "MEDIUM")).upper(), "medium")
            out.append(
                AnalysisFinding(
                    analyzer=self.name,
                    rule_id=rule_id,
                    severity=sev,
                    path=_relative_path(str(r.get("filename", "")), root),
                    line=_line_of(r.get("line_number")),
                    message=_bandit_message(rule_id, str(r.get("issue_text", ""))),
                    # bandit's `code` field is the raw source line, and on the
                    # hardcoded-credential checks that line IS the credential. No snippet
                    # is carried at all rather than one that is safe only per-check.
                    snippet="",
                    cwe=_bandit_cwe(r.get("issue_cwe")),
                )
            )
        out.sort(key=lambda f: (f.path, f.line, f.rule_id))
        return out


def _bandit_message(rule_id: str, issue_text: str) -> str:
    text = issue_text.strip()[:500] or "bandit finding"
    if rule_id in _BANDIT_CREDENTIAL_TESTS:
        return _SINGLE_QUOTED.sub(_SECRET_MASK, text)
    return text


def _bandit_cwe(raw: object) -> str:
    """bandit >= 1.7.5 nests the CWE as `{"id": 78, "link": ...}`; older builds emit
    nothing there. Total either way — a missing or mistyped id yields no CWE, never a
    fabricated one."""
    if isinstance(raw, dict):
        cid = raw.get("id")
        if isinstance(cid, (int, str)) and not isinstance(cid, bool) and str(cid).strip():
            return f"CWE-{cid}"
    return ""


class GitleaksAnalyzer:
    """Adapter over the `gitleaks` CLI — rule + entropy secret scanning over the
    working tree.

    Reports WHERE a credential-shaped string is, never WHAT it is: the value is
    masked out of every field a finding carries (see `_SECRET_MASK`). A hit is a
    LEAD — gitleaks matches shape and entropy, it never establishes that the
    credential is live, and this adapter has no way to check that (nor may it:
    checking means egress). Skipped gracefully when the binary is absent."""

    name = "gitleaks"

    def __init__(self, timeout_s: int = 300) -> None:
        self._timeout_s = timeout_s

    def is_available(self) -> tuple[bool, str]:
        path = shutil.which("gitleaks")
        if path is None:
            return False, "gitleaks not on PATH (install to enable secret scanning)"
        return True, f"gitleaks at {path}"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        available, reason = self.is_available()
        if not available:
            raise BackendUnavailable(reason)

        root = Path(target.root).expanduser()
        # gitleaks writes findings to a FILE — stdout carries only the human summary — so
        # the report goes to a temp dir that is removed with it, exactly as the joern
        # adapter handles its own output file. Nothing lands in the engagement CWD.
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "gitleaks-report.json"
            cmd = [
                "gitleaks", "detect", "--source", str(root),
                # `--no-banner`: the ASCII banner goes to stderr, and a clean stderr is
                # what the BackendError below quotes back when the tool fails.
                "--no-banner",
                # `--no-git`: scan the tree as FILES. A DAA target is a directory that is
                # frequently not a git checkout at all, and in git mode gitleaks scans
                # HISTORY rather than the source actually under review.
                "--no-git",
                "--report-format", "json", "--report-path", str(report),
                # NO EGRESS: every flag above is local. gitleaks runs on its embedded
                # rules (or a `--config` an operator provisions out of band); nothing here
                # fetches or updates a ruleset, because the charter forbids all outbound
                # traffic from this host — a networked flag would make the adapter
                # unusable, not merely slower.
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
                raise BackendError(f"gitleaks timed out after {self._timeout_s}s") from e
            except OSError as e:
                raise BackendError(f"gitleaks failed to launch: {e}") from e

            if not report.is_file():
                # Exit 1 means "leaks found" and the report is still written, so the exit
                # code cannot decide failure here — a MISSING report is the unambiguous one.
                raise BackendError(
                    f"gitleaks produced no report (exit {proc.returncode}): "
                    f"{proc.stderr.strip()[:300]}"
                )
            try:
                raw = report.read_text(encoding="utf-8")
            except OSError as e:
                raise BackendError(f"gitleaks report could not be read: {e}") from e
            try:
                data = json.loads(raw or "[]")
            except json.JSONDecodeError as e:
                raise BackendError(f"gitleaks report was not valid JSON: {e}") from e

        return self._normalize(data, root)

    def _normalize(self, data: object, root: Path) -> list[AnalysisFinding]:
        # gitleaks' report is a top-level LIST (semgrep's is an object); a clean scan
        # writes `[]`.
        if not isinstance(data, list):
            return []
        out: list[AnalysisFinding] = []
        for r in data:
            if not isinstance(r, dict):
                continue
            # Both carry the credential: `Secret` is the captured value, `Match` the
            # surrounding source fragment that contains it.
            secrets = (str(r.get("Secret", "") or ""), str(r.get("Match", "") or ""))
            rule_id = _scrub(str(r.get("RuleID", "")).strip(), secrets) or "gitleaks-rule"
            desc = _scrub(str(r.get("Description", "")).strip(), secrets)
            detail = f": {desc}" if desc else ""
            out.append(
                AnalysisFinding(
                    analyzer=self.name,
                    rule_id=rule_id,
                    severity="high",
                    path=_relative_path(str(r.get("File", "")), root),
                    line=_line_of(r.get("StartLine")),
                    message=(
                        f"hard-coded secret matched rule {rule_id}{detail} "
                        f"— value {_SECRET_MASK}"
                    )[:500],
                    # `snippet` is where a line of source would go, and for a secret
                    # scanner that line IS the credential. Deliberately never populated.
                    snippet="",
                    cwe="CWE-798",
                )
            )
        out.sort(key=lambda f: (f.path, f.line, f.rule_id))
        return out


class TruffleHogAnalyzer:
    """Adapter over the `trufflehog` CLI — detector-based secret scanning over a
    filesystem tree.

    Same discipline as the gitleaks adapter: the value is masked out of every
    field, and a hit is a LEAD, never a confirmed credential. Skipped gracefully
    when the binary is absent."""

    name = "trufflehog"

    def __init__(self, timeout_s: int = 300) -> None:
        self._timeout_s = timeout_s

    def is_available(self) -> tuple[bool, str]:
        path = shutil.which("trufflehog")
        if path is None:
            return False, "trufflehog not on PATH (install to enable secret scanning)"
        return True, f"trufflehog at {path}"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        available, reason = self.is_available()
        if not available:
            raise BackendUnavailable(reason)

        root = Path(target.root).expanduser()
        cmd = [
            "trufflehog", "filesystem", str(root), "--json",
            # NO EGRESS — the one flag in this module that is load-bearing for scope, not
            # for output. WITHOUT `--no-verification` trufflehog takes every candidate it
            # finds and CALLS THE PROVIDER'S API to check whether the credential is live —
            # AWS, GitHub, Slack, hundreds more. That is outbound traffic to third parties
            # who are out of scope by default, carrying the operator's real secrets off the
            # box. The charter forbids all egress from this host (no tool, no DNS, no
            # callback), so this flag is an authorization requirement: removing it does not
            # make the scan slower, it exfiltrates.
            "--no-verification",
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
            raise BackendError(f"trufflehog timed out after {self._timeout_s}s") from e
        except OSError as e:
            raise BackendError(f"trufflehog failed to launch: {e}") from e

        if not proc.stdout.strip():
            if proc.returncode != 0:
                raise BackendError(
                    f"trufflehog exited {proc.returncode}: {proc.stderr.strip()[:300]}"
                )
            return []

        return self._normalize(proc.stdout, root)

    def _normalize(self, stdout: str, root: Path) -> list[AnalysisFinding]:
        # trufflehog emits JSON LINES — one object per detection, NOT a JSON array — so
        # this cannot be a single `json.loads` the way the semgrep/bandit adapters are.
        out: list[AnalysisFinding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # Some builds interleave their own human log lines on stdout. A line that
                # will not parse is dropped, never raised — one noisy line must not cost
                # the whole scan (the joern adapter takes the same posture on its JSONL).
                continue
            if not isinstance(rec, dict):
                continue
            # `Raw` is the credential; `RawV2` is the wider form some detectors add.
            secrets = (str(rec.get("Raw", "") or ""), str(rec.get("RawV2", "") or ""))
            detector = _scrub(str(rec.get("DetectorName", "")).strip(), secrets) \
                or "trufflehog-detector"
            meta = _trufflehog_filesystem_meta(rec)
            # `Verified` is deliberately NOT read. `--no-verification` is mandatory above,
            # so trufflehog cannot have checked this credential against its provider; a
            # severity that branched on that field would be dressing an unverifiable flag
            # as evidence. Every hit here is an unverified lead and is graded as one.
            out.append(
                AnalysisFinding(
                    analyzer=self.name,
                    rule_id=detector,
                    severity="high",
                    path=_relative_path(str(meta.get("file", "")), root),
                    line=_line_of(meta.get("line")),
                    message=_scrub(
                        f"credential-shaped string detected by the {detector} detector "
                        f"(unverified — value {_SECRET_MASK})",
                        secrets,
                    )[:500],
                    # As with gitleaks: the source line here is the credential.
                    snippet="",
                    cwe="CWE-798",
                )
            )
        out.sort(key=lambda f: (f.path, f.line, f.rule_id))
        return out


def _trufflehog_filesystem_meta(rec: dict[str, object]) -> dict[str, object]:
    """`SourceMetadata.Data.Filesystem` — trufflehog nests the location three levels down
    and keys the innermost object by SOURCE TYPE (`Filesystem`, `Git`, `Github`, …), so a
    record from another source shape has no filesystem block at all. Total: any level
    missing or mistyped yields `{}`, and the finding still records the detector."""
    meta = rec.get("SourceMetadata")
    data = meta.get("Data") if isinstance(meta, dict) else None
    fs = data.get("Filesystem") if isinstance(data, dict) else None
    return fs if isinstance(fs, dict) else {}
