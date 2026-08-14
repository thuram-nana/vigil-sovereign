"""
Wave 2 — the three new external analyzers: bandit, gitleaks, trufflehog.

Every test here plays the tool with a MOCKED ``subprocess.run`` over RECORDED output.
No real binary is ever spawned, so nothing in this file is evidence that a live bandit /
gitleaks / trufflehog behaves as recorded — it is evidence about this repo's parse,
normalize, mask and failure handling, which is what the adapters own.

Three properties get a control strong enough to fail on a real regression:

  * **No secret is ever recorded.** The fixtures plant credential-shaped strings in the
    fields that carry a real credential (gitleaks ``Secret``/``Match``, trufflehog
    ``Raw``/``RawV2``, bandit's B105 issue text) and each absence assertion is paired with
    a CONTROL asserting the fixture really does contain that string — an absence assertion
    over a fixture that lost its secret would otherwise pass vacuously forever.
  * **The no-egress flags are in the argv.** Asserted at CONSTRUCTION level only: these
    tests capture the argv the adapter builds and pin ``--no-verification`` (trufflehog)
    and the absence of any rule-fetching flag (gitleaks). That pins what this repo asks
    the tool to do. It is NOT a measurement of the tool's syscalls, and no test here
    observes the network — a build of trufflehog that ignored the flag would not be caught
    by anything in this file.
  * **Failure degrades, it does not crash.** A timeout and an OSError each become a
    ``BackendError`` (a ``CrucibleError``, which is what the orchestrator catches to record
    the analyzer as skipped), and an absent binary becomes ``BackendUnavailable``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from framework.v2.analysis.analyzers import external as external_mod
from framework.v2.analysis.analyzers.external import (
    _SECRET_MASK,
    BanditAnalyzer,
    GitleaksAnalyzer,
    TruffleHogAnalyzer,
)
from framework.v2.analysis.models import AnalysisFinding, AnalysisTarget
from framework.v2.analysis.orchestrator import default_analyzers, run_analysis
from framework.v2.common.errors import BackendError, BackendUnavailable

# The planted credentials. Distinctive enough that a substring match cannot be an accident.
_GITLEAKS_SECRET = "AKIAQYLPMN5OGWAVEXAMPLE"          # noqa: S105 - fixture, not a real key
_GITLEAKS_MATCH = f'aws_access_key_id = "{_GITLEAKS_SECRET}"'
_TRUFFLEHOG_RAW = "ghp_wave2FIXTUREtokenDEADBEEF0123456789"   # noqa: S105 - fixture
_TRUFFLEHOG_RAW_V2 = f"github_pat:{_TRUFFLEHOG_RAW}"          # noqa: S105 - fixture
_BANDIT_PASSWORD = "hunter2-wave2-fixture"                    # noqa: S105 - fixture


class _FakeProc:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _capture(monkeypatch: pytest.MonkeyPatch, binary: str, handler) -> list[list[str]]:
    """Put ``binary`` on the fake PATH and hand every spawn to ``handler(argv) -> _FakeProc``,
    recording the argv the adapter actually built."""
    seen: list[list[str]] = []
    monkeypatch.setattr(external_mod.shutil, "which", lambda b: f"/usr/bin/{b}")

    def _run(argv, **_kw):
        seen.append(list(argv))
        return handler(argv)

    monkeypatch.setattr(external_mod.subprocess, "run", _run)
    return seen


def _no_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(external_mod.shutil, "which", lambda _b: None)


def _raises(exc: BaseException):
    def _run(_argv, **_kw):
        raise exc
    return _run


def _dumped(findings: list[AnalysisFinding]) -> str:
    """Every field of every finding as one blob — what an absence assertion must search,
    since a leak into `snippet` or `rule_id` is just as bad as one into `message`.

    Serialized JSON AND the raw field values, because JSON ESCAPES: a credential-bearing
    string containing a quote does not appear literally in `model_dump_json()` output even
    when it is recorded verbatim in the field, so searching the JSON text alone could miss
    a real leak. (The gitleaks `Match` fixture is exactly that shape — this is not
    hypothetical, it is what the first run of these tests caught.)"""
    blob: list[str] = []
    for f in findings:
        blob.append(f.model_dump_json())
        blob.extend(str(v) for v in f.model_dump().values())
    return "\n".join(blob)


# ---------------------------------------------------------------------------
# recorded fixtures
# ---------------------------------------------------------------------------


def _bandit_json(root: Path) -> str:
    """A recorded ``bandit -f json -q -r`` document: a HIGH shell-injection issue, a MEDIUM
    yaml.load, and a LOW B105 whose issue text INTERPOLATES the matched password (which is
    what the mask exists for)."""
    return json.dumps({
        "errors": [],
        "generated_at": "2026-08-13T00:00:00Z",
        "metrics": {"_totals": {"loc": 42}},
        "results": [
            {
                "code": "12 subprocess.run(cmd, shell=True)\n",
                "filename": str(root / "app.py"),
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
                "issue_severity": "HIGH",
                "issue_text": "subprocess call with shell=True identified, security issue.",
                "line_number": 12,
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
            },
            {
                "code": "7 yaml.load(fh)\n",
                "filename": str(root / "conf.py"),
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 20, "link": "https://cwe.mitre.org/data/definitions/20.html"},
                "issue_severity": "MEDIUM",
                "issue_text": "Use of unsafe yaml load.",
                "line_number": 7,
                "test_id": "B506",
                "test_name": "yaml_load",
            },
            {
                "code": f"3 PASSWORD = '{_BANDIT_PASSWORD}'\n",
                "filename": str(root / "settings.py"),
                "issue_confidence": "MEDIUM",
                "issue_cwe": {"id": 259, "link": "https://cwe.mitre.org/data/definitions/259.html"},
                "issue_severity": "LOW",
                "issue_text": f"Possible hardcoded password: '{_BANDIT_PASSWORD}'",
                "line_number": 3,
                "test_id": "B105",
                "test_name": "hardcoded_password_string",
            },
        ],
    })


def _gitleaks_report(root: Path) -> str:
    """A recorded ``gitleaks detect --report-format json`` report: a top-level LIST (not an
    object), carrying the raw credential in both ``Secret`` and ``Match``."""
    return json.dumps([
        {
            "RuleID": "aws-access-token",
            "Description": "Identified a pattern that may indicate AWS credentials",
            "StartLine": 4,
            "EndLine": 4,
            "File": str(root / "deploy" / "settings.py"),
            "Secret": _GITLEAKS_SECRET,
            "Match": _GITLEAKS_MATCH,
            "Entropy": 3.9,
            "Fingerprint": "deploy/settings.py:aws-access-token:4",
        },
        {
            "RuleID": "generic-api-key",
            # A hostile / sloppy custom rule that interpolates its own hit into the
            # description — the reason `_scrub` runs over description text too, not only
            # over the fields documented to hold the value.
            "Description": f"generic key found: {_GITLEAKS_SECRET}",
            "StartLine": 11,
            "File": str(root / "app.py"),
            "Secret": _GITLEAKS_SECRET,
            "Match": _GITLEAKS_MATCH,
        },
    ])


def _trufflehog_jsonl(root: Path) -> str:
    """Recorded ``trufflehog filesystem --json`` output: JSON LINES, not an array. Includes
    a blank line and a human log line, both of which the adapter must skip."""
    return "\n".join([
        json.dumps({
            "DetectorName": "Github",
            "DecoderName": "PLAIN",
            "Verified": False,
            "Raw": _TRUFFLEHOG_RAW,
            "RawV2": _TRUFFLEHOG_RAW_V2,
            "SourceMetadata": {"Data": {"Filesystem": {
                "file": str(root / "ci" / "publish.sh"), "line": 22}}},
        }),
        "",
        "2026-08-13T00:00:00Z  info-0  trufflehog  scanning filesystem",
        json.dumps({
            "DetectorName": "AWS",
            "Verified": False,
            "Raw": _TRUFFLEHOG_RAW,
            "SourceMetadata": {"Data": {"Filesystem": {
                "file": str(root / "app.py"), "line": 3}}},
        }),
    ])


# ---------------------------------------------------------------------------
# bandit
# ---------------------------------------------------------------------------


def test_bandit_unavailable_when_binary_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_binary(monkeypatch)
    ok, reason = BanditAnalyzer().is_available()
    assert ok is False and "bandit" in reason and "PATH" in reason


def test_bandit_analyze_without_binary_raises_unavailable(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _no_binary(monkeypatch)
    with pytest.raises(BackendUnavailable):
        BanditAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_bandit_normalizes_recorded_output(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    argvs = _capture(monkeypatch, "bandit",
                     lambda _a: _FakeProc(stdout=_bandit_json(tmp_path), returncode=1))
    findings = BanditAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))

    assert argvs == [["bandit", "-f", "json", "-q", "-r", str(tmp_path)]]
    by_path = {f.path: f for f in findings}
    assert set(by_path) == {"app.py", "conf.py", "settings.py"}
    assert by_path["app.py"].severity == "high"       # HIGH -> high
    assert by_path["app.py"].line == 12 and by_path["app.py"].rule_id == "B602"
    assert by_path["app.py"].cwe == "CWE-78"
    assert by_path["conf.py"].severity == "medium"    # MEDIUM -> medium
    assert by_path["settings.py"].severity == "low"   # LOW -> low
    assert all(f.analyzer == "bandit" for f in findings)
    # deterministic sort by (path, line, rule_id)
    assert [f.path for f in findings] == sorted(f.path for f in findings)


def test_bandit_never_records_the_hardcoded_password(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """B105's issue text is literally ``Possible hardcoded password: '<value>'`` and its
    ``code`` field is the source line, so an unmasked passthrough would persist a real
    credential into the report."""
    recorded = _bandit_json(tmp_path)
    assert _BANDIT_PASSWORD in recorded, "CONTROL: the fixture must contain the password"

    _capture(monkeypatch, "bandit", lambda _a: _FakeProc(stdout=recorded, returncode=1))
    findings = BanditAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))

    assert findings, "no findings would make the absence assertion vacuous"
    assert _BANDIT_PASSWORD not in _dumped(findings)
    b105 = next(f for f in findings if f.rule_id == "B105")
    assert _SECRET_MASK in b105.message and b105.snippet == ""
    # …and the masking did not silently swallow the finding's meaning.
    assert "hardcoded password" in b105.message and b105.cwe == "CWE-259"


def test_bandit_empty_stdout_zero_exit_is_a_clean_tree(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # `-q` makes bandit print nothing at all when it finds nothing, so this is the clean case.
    _capture(monkeypatch, "bandit", lambda _a: _FakeProc(stdout="", returncode=0))
    assert BanditAnalyzer().analyze(AnalysisTarget(root=str(tmp_path))) == []


def test_bandit_empty_stdout_nonzero_exit_is_a_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _capture(monkeypatch, "bandit", lambda _a: _FakeProc(stdout="", stderr="boom", returncode=2))
    with pytest.raises(BackendError):
        BanditAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_bandit_nonzero_exit_with_results_is_not_an_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The control on the branch above: bandit exits 1 WHENEVER it finds an issue, so a
    non-zero code must not be read as failure on its own."""
    _capture(monkeypatch, "bandit", lambda _a: _FakeProc(stdout=_bandit_json(tmp_path),
                                                         returncode=1))
    assert len(BanditAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))) == 3


def test_bandit_invalid_json_is_a_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _capture(monkeypatch, "bandit", lambda _a: _FakeProc(stdout="not json", returncode=1))
    with pytest.raises(BackendError):
        BanditAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_bandit_normalize_is_total_on_garbage() -> None:
    n = BanditAnalyzer()._normalize
    assert n({"results": "not-a-list"}, Path("/x")) == []
    assert n(["not", "a", "dict"], Path("/x")) == []
    # a record with nothing usable still yields a valid finding rather than an exception
    f = n({"results": [42, "junk", {"filename": "z.py", "line_number": -9}]}, Path("/x"))[0]
    assert f.path == "z.py" and f.line == 0 and f.rule_id == "bandit-issue" and f.cwe == ""


def test_bandit_timeout_and_oserror_degrade_to_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for exc in (subprocess.TimeoutExpired(cmd="bandit", timeout=1), OSError("no exec")):
        _capture(monkeypatch, "bandit", _raises(exc))
        with pytest.raises(BackendError):
            BanditAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


# ---------------------------------------------------------------------------
# gitleaks
# ---------------------------------------------------------------------------


def _gitleaks_writes(report_text: str, returncode: int = 1):
    """Play gitleaks: write the report to the `--report-path` the adapter chose."""
    def _run(argv):
        Path(argv[argv.index("--report-path") + 1]).write_text(report_text, encoding="utf-8")
        return _FakeProc(returncode=returncode)
    return _run


def test_gitleaks_unavailable_when_binary_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_binary(monkeypatch)
    ok, reason = GitleaksAnalyzer().is_available()
    assert ok is False and "gitleaks" in reason and "PATH" in reason


def test_gitleaks_analyze_without_binary_raises_unavailable(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _no_binary(monkeypatch)
    with pytest.raises(BackendUnavailable):
        GitleaksAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_gitleaks_normalizes_recorded_report(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    argvs = _capture(monkeypatch, "gitleaks", _gitleaks_writes(_gitleaks_report(tmp_path)))
    findings = GitleaksAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))

    argv = argvs[0]
    assert argv[:4] == ["gitleaks", "detect", "--source", str(tmp_path)]
    assert "--no-banner" in argv and "--no-git" in argv
    assert argv[argv.index("--report-format") + 1] == "json"

    by_path = {f.path: f for f in findings}
    assert set(by_path) == {"app.py", str(Path("deploy") / "settings.py")}
    aws = by_path[str(Path("deploy") / "settings.py")]
    assert aws.rule_id == "aws-access-token" and aws.line == 4
    assert aws.severity == "high" and aws.cwe == "CWE-798"
    assert all(f.analyzer == "gitleaks" for f in findings)
    assert [f.path for f in findings] == sorted(f.path for f in findings)


def test_gitleaks_report_is_deleted_after_the_run(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The report holds raw credentials, so it must not survive the call."""
    argvs = _capture(monkeypatch, "gitleaks", _gitleaks_writes(_gitleaks_report(tmp_path)))
    GitleaksAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))
    report = Path(argvs[0][argvs[0].index("--report-path") + 1])
    assert not report.exists() and not report.parent.exists()


def test_gitleaks_never_records_the_secret(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    recorded = _gitleaks_report(tmp_path)
    # CONTROL over the report AS THE ADAPTER PARSES IT (not the serialized text — JSON
    # escapes the quotes in `Match`), so the absence assertions below cannot pass vacuously
    # against a fixture that quietly lost its planted credential.
    parsed = json.loads(recorded)
    assert any(r["Secret"] == _GITLEAKS_SECRET for r in parsed), "CONTROL: fixture lost the secret"
    assert any(r["Match"] == _GITLEAKS_MATCH for r in parsed), "CONTROL: fixture lost the match"
    assert any(_GITLEAKS_SECRET in r["Description"] for r in parsed), "CONTROL: desc lost the secret"

    _capture(monkeypatch, "gitleaks", _gitleaks_writes(recorded))
    findings = GitleaksAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))

    assert findings, "no findings would make the absence assertion vacuous"
    blob = _dumped(findings)
    assert _GITLEAKS_SECRET not in blob
    assert _GITLEAKS_MATCH not in blob
    assert all(f.snippet == "" for f in findings)
    # the second fixture record hides the secret inside the DESCRIPTION — proof the scrub
    # covers tool free-text, not only the two fields documented to hold the value
    generic = next(f for f in findings if f.rule_id == "generic-api-key")
    assert _SECRET_MASK in generic.message
    # …and the finding still locates the leak
    assert generic.path == "app.py" and generic.line == 11


def test_gitleaks_argv_carries_no_rule_fetching_flag(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """CONSTRUCTION-LEVEL no-egress pin: gitleaks must run on its embedded rules. Nothing
    here observes the network — it pins what this repo asks the tool to do."""
    argvs = _capture(monkeypatch, "gitleaks", _gitleaks_writes("[]", returncode=0))
    GitleaksAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))
    argv = argvs[0]
    for banned in ("--enable-rule-fetch", "--config-url", "--baseline-url", "--remote"):
        assert banned not in argv
    assert not any(a.startswith(("http://", "https://")) for a in argv)


def test_gitleaks_missing_report_is_a_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _capture(monkeypatch, "gitleaks", lambda _a: _FakeProc(stderr="boom", returncode=2))
    with pytest.raises(BackendError):
        GitleaksAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_gitleaks_invalid_json_report_is_a_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _capture(monkeypatch, "gitleaks", _gitleaks_writes("{ not json"))
    with pytest.raises(BackendError):
        GitleaksAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_gitleaks_empty_report_is_no_findings(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # gitleaks writes an EMPTY file (not `[]`) on some clean runs; both must read as clean.
    for body in ("", "[]"):
        _capture(monkeypatch, "gitleaks", _gitleaks_writes(body, returncode=0))
        assert GitleaksAnalyzer().analyze(AnalysisTarget(root=str(tmp_path))) == []


def test_gitleaks_normalize_is_total_on_garbage() -> None:
    n = GitleaksAnalyzer()._normalize
    assert n({"not": "a list"}, Path("/x")) == []
    f = n([42, "junk", {"File": "z.py", "StartLine": "not-a-number"}], Path("/x"))[0]
    assert f.path == "z.py" and f.line == 0 and f.rule_id == "gitleaks-rule"


def test_gitleaks_timeout_and_oserror_degrade_to_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for exc in (subprocess.TimeoutExpired(cmd="gitleaks", timeout=1), OSError("no exec")):
        _capture(monkeypatch, "gitleaks", _raises(exc))
        with pytest.raises(BackendError):
            GitleaksAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


# ---------------------------------------------------------------------------
# trufflehog
# ---------------------------------------------------------------------------


def test_trufflehog_unavailable_when_binary_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_binary(monkeypatch)
    ok, reason = TruffleHogAnalyzer().is_available()
    assert ok is False and "trufflehog" in reason and "PATH" in reason


def test_trufflehog_analyze_without_binary_raises_unavailable(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _no_binary(monkeypatch)
    with pytest.raises(BackendUnavailable):
        TruffleHogAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_trufflehog_argv_pins_no_verification(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """THE no-egress pin, at CONSTRUCTION level. Without ``--no-verification`` trufflehog
    calls every recognised provider's API with the operator's real secrets — outbound
    traffic to out-of-scope third parties from a host whose charter forbids all egress.

    This asserts the flag is in the argv this repo builds. It does not, and cannot,
    observe syscalls: a trufflehog build that ignored the flag would pass this test."""
    argvs = _capture(monkeypatch, "trufflehog",
                     lambda _a: _FakeProc(stdout=_trufflehog_jsonl(tmp_path)))
    TruffleHogAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))

    assert argvs == [["trufflehog", "filesystem", str(tmp_path), "--json", "--no-verification"]]
    argv = argvs[0]
    assert "--no-verification" in argv
    # the mutation control: the flags that would RE-ENABLE verification must not be present
    for banned in ("--verify", "--verification", "--only-verified", "--results=verified"):
        assert banned not in argv


def test_trufflehog_normalizes_recorded_jsonl(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _capture(monkeypatch, "trufflehog",
             lambda _a: _FakeProc(stdout=_trufflehog_jsonl(tmp_path)))
    findings = TruffleHogAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))

    # the blank line and the human log line were skipped, never raised
    assert len(findings) == 2
    by_path = {f.path: f for f in findings}
    assert set(by_path) == {"app.py", str(Path("ci") / "publish.sh")}
    gh = by_path[str(Path("ci") / "publish.sh")]
    assert gh.rule_id == "Github" and gh.line == 22
    assert gh.severity == "high" and gh.cwe == "CWE-798"
    assert by_path["app.py"].rule_id == "AWS" and by_path["app.py"].line == 3
    assert all(f.analyzer == "trufflehog" for f in findings)
    assert [f.path for f in findings] == sorted(f.path for f in findings)


def test_trufflehog_never_records_the_secret(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    recorded = _trufflehog_jsonl(tmp_path)
    assert _TRUFFLEHOG_RAW in recorded, "CONTROL: the fixture must contain the raw secret"
    assert _TRUFFLEHOG_RAW_V2 in recorded, "CONTROL: the fixture must contain RawV2"

    _capture(monkeypatch, "trufflehog", lambda _a: _FakeProc(stdout=recorded))
    findings = TruffleHogAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))

    assert findings, "no findings would make the absence assertion vacuous"
    blob = _dumped(findings)
    assert _TRUFFLEHOG_RAW not in blob
    assert _TRUFFLEHOG_RAW_V2 not in blob
    assert all(f.snippet == "" for f in findings)
    assert all(_SECRET_MASK in f.message for f in findings)
    # the grade stays honest: nothing is claimed verified, because nothing could be
    assert all("unverified" in f.message for f in findings)


def test_trufflehog_detector_name_carrying_the_secret_is_scrubbed(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The rule_id comes from tool-controlled text too, so it gets the same scrub — a leak
    into `rule_id` would be just as recorded as one into `message`."""
    line = json.dumps({"DetectorName": f"custom-{_TRUFFLEHOG_RAW}", "Raw": _TRUFFLEHOG_RAW,
                       "SourceMetadata": {"Data": {"Filesystem": {"file": "a.py", "line": 1}}}})
    _capture(monkeypatch, "trufflehog", lambda _a: _FakeProc(stdout=line))
    findings = TruffleHogAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))
    assert findings and _TRUFFLEHOG_RAW not in _dumped(findings)
    assert findings[0].rule_id == f"custom-{_SECRET_MASK}"


def test_trufflehog_empty_stdout_zero_exit_is_no_findings(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _capture(monkeypatch, "trufflehog", lambda _a: _FakeProc(stdout="", returncode=0))
    assert TruffleHogAnalyzer().analyze(AnalysisTarget(root=str(tmp_path))) == []


def test_trufflehog_empty_stdout_nonzero_exit_is_a_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _capture(monkeypatch, "trufflehog",
             lambda _a: _FakeProc(stdout="", stderr="boom", returncode=2))
    with pytest.raises(BackendError):
        TruffleHogAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


def test_trufflehog_normalize_is_total_on_garbage() -> None:
    n = TruffleHogAnalyzer()._normalize
    assert n("", Path("/x")) == []
    assert n("{ not json\n\n[1,2,3]\n\"a string\"", Path("/x")) == []   # unparseable + non-dicts
    f = n(json.dumps({"SourceMetadata": "wrong-shape"}), Path("/x"))[0]
    assert f.rule_id == "trufflehog-detector" and f.path == "" and f.line == 0


def test_trufflehog_timeout_and_oserror_degrade_to_backend_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for exc in (subprocess.TimeoutExpired(cmd="trufflehog", timeout=1), OSError("no exec")):
        _capture(monkeypatch, "trufflehog", _raises(exc))
        with pytest.raises(BackendError):
            TruffleHogAnalyzer().analyze(AnalysisTarget(root=str(tmp_path)))


# ---------------------------------------------------------------------------
# registration + the orchestrator's degrade-visibly contract
# ---------------------------------------------------------------------------


def test_the_three_are_registered_as_default_analyzers() -> None:
    assert {a.name for a in default_analyzers()} == {
        "pattern", "semgrep", "joern", "bandit", "gitleaks", "trufflehog"}


def test_absent_binaries_are_skipped_with_a_reason_not_failed(
        monkeypatch: pytest.MonkeyPatch, planted_tree: Path) -> None:
    """The whole point of the Analyzer contract: on a host with none of the three
    provisioned, the report still runs and NAMES what it could not do."""
    _no_binary(monkeypatch)
    report = run_analysis(
        AnalysisTarget(root=str(planted_tree)),
        analyzers=[BanditAnalyzer(), GitleaksAnalyzer(), TruffleHogAnalyzer()],
    )
    skipped = {s.name: s.reason for s in report.analyzers_skipped}
    assert set(skipped) == {"bandit", "gitleaks", "trufflehog"}
    assert report.analyzers_run == [] and report.findings == []
    # skipped, with a reason a human can act on — never a silent capability loss
    assert all("PATH" in reason for reason in skipped.values())


def test_findings_merge_into_the_report_and_carry_no_secret(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End-to-end through the orchestrator: the mask survives the merge/dedup/sort path
    that actually produces the report an operator reads."""
    monkeypatch.setattr(external_mod.shutil, "which", lambda b: f"/usr/bin/{b}")

    def _run(argv, **_kw):
        if argv[0] == "gitleaks":
            Path(argv[argv.index("--report-path") + 1]).write_text(
                _gitleaks_report(tmp_path), encoding="utf-8")
            return _FakeProc(returncode=1)
        return _FakeProc(stdout=_trufflehog_jsonl(tmp_path))

    monkeypatch.setattr(external_mod.subprocess, "run", _run)
    report = run_analysis(
        AnalysisTarget(root=str(tmp_path)),
        analyzers=[GitleaksAnalyzer(), TruffleHogAnalyzer()],
    )
    assert set(report.analyzers_run) == {"gitleaks", "trufflehog"}
    assert len(report.findings) == 4
    blob = _dumped(report.findings)
    for secret in (_GITLEAKS_SECRET, _GITLEAKS_MATCH, _TRUFFLEHOG_RAW, _TRUFFLEHOG_RAW_V2):
        assert secret not in blob
