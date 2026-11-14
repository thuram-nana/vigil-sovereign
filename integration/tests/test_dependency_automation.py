"""Dependency-update automation + the daily supply-chain scan are present and true of the code.

WHY THIS TEST EXISTS (slice W3-1 / #424). The repository had NO update automation and NO scheduled
supply-chain scan: the A14 gate fires only on push/PR to `main`, so a CVE disclosed against an
already-merged dependency stayed invisible until someone happened to open a PR. This slice added
`.github/dependabot.yml` and `.github/workflows/scheduled-supply-chain-scan.yml`. This test is the
pin that keeps both true of the code, OFFLINE, in the REQUIRED `integration two-env boundary (P5)`
job (which collects the whole `integration/tests` tree and has PyYAML installed).

WHAT IT PROVES:
  1. Dependabot config parses and covers all four ecosystems the repo contains: pip, cargo,
     github-actions, docker — every update entry carries a schedule, and a runtime package.json never
     lands without an npm entry watching its directory.
  2. The scheduled scan workflow parses, has a `schedule:` (daily cron) trigger, declares
     `issues: write`, and actually opens an issue on findings (`gh issue create`) via the pinned
     decision script.
  3. The decision script (.github/scripts/supply_chain_scan.py) FIRES on a known-CRITICAL report and
     STAYS SILENT on a clean one and on a sub-threshold (HIGH-only) one — the property that makes the
     scan neither a no-op nor a gate that always cries wolf.

FAILS WITHOUT THE CHANGE. On a tree without this slice, `.github/dependabot.yml` and the workflow do
not exist, so the discovery helpers raise and every test errors — the failure is observed, not
assumed.

NEGATIVE CONTROLS. The pure checker helpers take their data as ARGUMENTS so a deliberately-wrong
config can be fed to them in-process and asserted to be REJECTED (`test_negative_control_*`): a
dependabot config missing an ecosystem, and a workflow with no schedule trigger, must both be caught;
and the decision script must return no issue on a clean/sub-threshold report.

Pure stdlib + PyYAML — it imports no product module, sends no packet, runs no scanner.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
DEPENDABOT = REPO / ".github" / "dependabot.yml"
WORKFLOW = REPO / ".github" / "workflows" / "scheduled-supply-chain-scan.yml"
SCAN_SCRIPT = REPO / ".github" / "scripts" / "supply_chain_scan.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

REQUIRED_ECOSYSTEMS = {"pip", "cargo", "github-actions", "docker"}


# ------------------------------------------------------------------------------------------------
# Loading helpers. `on:` is the classic Actions gotcha — PyYAML (YAML 1.1) parses the unquoted word
# as the boolean True, so the trigger block lands under the key `True`, not `"on"`.
# ------------------------------------------------------------------------------------------------
def _load_yaml(path: Path) -> dict:
    assert path.is_file(), f"missing file: {path.relative_to(REPO)}"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path.relative_to(REPO)} did not parse to a mapping"
    return data


def _on_block(workflow: dict):
    """The `on:` trigger block, under either the string key or PyYAML's boolean-True key."""
    if "on" in workflow:
        return workflow["on"]
    return workflow.get(True)


def _load_scan_module():
    spec = importlib.util.spec_from_file_location("ssc_scan", SCAN_SCRIPT)
    assert spec and spec.loader, f"cannot load {SCAN_SCRIPT}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------------------------------------
# Pure checkers (data in, verdict out) so the negative controls can perturb them in-process.
# ------------------------------------------------------------------------------------------------
def dependabot_ecosystems(config: dict) -> set[str]:
    return {u.get("package-ecosystem") for u in (config.get("updates") or [])}


def missing_ecosystems(config: dict, required: set[str]) -> set[str]:
    return required - dependabot_ecosystems(config)


def updates_without_schedule(config: dict) -> list[int]:
    """Indices of update entries that declare no schedule.interval."""
    bad = []
    for i, u in enumerate(config.get("updates") or []):
        if not (isinstance(u.get("schedule"), dict) and u["schedule"].get("interval")):
            bad.append(i)
    return bad


def has_schedule_trigger(on_block) -> bool:
    """True iff the workflow declares at least one cron under `on.schedule`."""
    if not isinstance(on_block, dict):
        return False
    sched = on_block.get("schedule")
    if not isinstance(sched, list):
        return False
    return any(isinstance(e, dict) and e.get("cron") for e in sched)


# ------------------------------------------------------------------------------------------------
# 1. Dependabot
# ------------------------------------------------------------------------------------------------
def test_dependabot_parses_and_is_v2():
    cfg = _load_yaml(DEPENDABOT)
    assert cfg.get("version") == 2, "dependabot.yml must declare version: 2"
    assert isinstance(cfg.get("updates"), list) and cfg["updates"], "no updates declared"


def test_dependabot_covers_all_four_ecosystems():
    cfg = _load_yaml(DEPENDABOT)
    missing = missing_ecosystems(cfg, REQUIRED_ECOSYSTEMS)
    assert not missing, f"dependabot.yml does not cover: {sorted(missing)}"


def test_every_dependabot_update_has_a_schedule():
    cfg = _load_yaml(DEPENDABOT)
    bad = updates_without_schedule(cfg)
    assert not bad, f"update entries without a schedule.interval: indices {bad}"


def _dependabot_directories(config: dict) -> list[str]:
    """Every watched directory across all update entries (both `directory` and `directories`)."""
    dirs: list[str] = []
    for u in config.get("updates") or []:
        if isinstance(u.get("directory"), str):
            dirs.append(u["directory"])
        for d in u.get("directories") or []:
            dirs.append(str(d))
    return dirs


# A package.json that is NOT a runtime npm project: the deliberately-vulnerable eval corpus, quarantined
# vendor source, and installed node_modules trees. Anything else is a runtime project Dependabot must watch.
_NON_RUNTIME_NPM = ("engine/crucible/framework/v2/eval/corpus_apps/", "vendor/")


def runtime_package_jsons(tracked: list[str]) -> list[str]:
    """Tracked package.json paths that belong to a runtime npm project."""
    return sorted(p for p in tracked
                  if p.rsplit("/", 1)[-1] == "package.json"
                  and "node_modules/" not in p
                  and not p.startswith(_NON_RUNTIME_NPM))


def npm_dirs_without_entry(config: dict, package_jsons: list[str]) -> list[str]:
    """Directories (Dependabot form, leading '/') of runtime package.json files no npm entry watches."""
    watched: set[str] = set()
    for u in config.get("updates") or []:
        if u.get("package-ecosystem") != "npm":
            continue
        for d in ([u["directory"]] if isinstance(u.get("directory"), str) else []) + list(u.get("directories") or []):
            watched.add("/" + str(d).strip("/"))
    need = {"/" + (p.rsplit("/", 1)[0] if "/" in p else "").strip("/") for p in package_jsons}
    return sorted(d for d in need if d not in watched)


def test_a_runtime_package_json_is_watched_by_an_npm_entry():
    """No npm entry is declared while the repository ships no runtime npm project (an entry with no
    package.json fails every Dependabot run). The moment one lands, its directory must be watched."""
    tracked = subprocess.run(["git", "ls-files", "*package.json"], cwd=REPO, capture_output=True,
                             text=True, check=True).stdout.split()
    missing = npm_dirs_without_entry(_load_yaml(DEPENDABOT), runtime_package_jsons(tracked))
    assert not missing, f"runtime package.json without a Dependabot npm entry for: {missing}"


def test_negative_control_an_unwatched_runtime_package_json_is_caught():
    cfg = {"updates": [{"package-ecosystem": "pip", "directory": "/"}]}
    jsons = runtime_package_jsons(["web/package.json", "vendor/x/package.json",
                                   "engine/crucible/framework/v2/eval/corpus_apps/_cve/a/package.json",
                                   "web/node_modules/y/package.json"])
    assert jsons == ["web/package.json"]
    assert npm_dirs_without_entry(cfg, jsons) == ["/web"]
    cfg["updates"].append({"package-ecosystem": "npm", "directory": "/web"})
    assert npm_dirs_without_entry(cfg, jsons) == []


def test_dependabot_does_not_watch_the_vulnerable_eval_corpus():
    """The deliberately-vulnerable CVE fixtures must not get 'fix' PRs that would break the corpus."""
    for d in _dependabot_directories(_load_yaml(DEPENDABOT)):
        assert "corpus_apps" not in d and "vendor" not in d, \
            f"dependabot must not target quarantined/deliberately-vulnerable path: {d}"


# Dependabot's docker parser reads only LITERAL `FROM <image>[:tag][@sha256:…]` lines and never substitutes
# an ARG, so a base pinned only through `ARG X=<image>` + `FROM ${X}` is invisible to it: the directory is
# "watched" yet that pin never gets a refresh PR. (gateway/Dockerfile was in exactly that state.)
IMAGE_PINS = REPO / "infra" / "supply-chain" / "image_pins.py"
# Dependabot's own selection (dependabot-core docker/lib/dependabot/docker/file_fetcher.rb, DOCKER_REGEXP):
# any file in a listed directory whose NAME contains "dockerfile" or "containerfile", case-insensitively.
_DEPENDABOT_DOCKERFILE = re.compile(r"dockerfile|containerfile", re.IGNORECASE)


def _load_image_pins():
    import sys

    spec = importlib.util.spec_from_file_location("vigil_image_pins_for_dependabot", IMAGE_PINS)
    assert spec and spec.loader, f"cannot load {IMAGE_PINS}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod          # @dataclass resolves its module through sys.modules
    spec.loader.exec_module(mod)
    return mod


def dependabot_docker_files(config: dict, root: Path = REPO) -> list[Path]:
    """Every Dockerfile a docker update entry watches (Dependabot scans each listed directory, not below),
    selected by the same name rule Dependabot uses."""
    out: list[Path] = []
    for u in config.get("updates") or []:
        if u.get("package-ecosystem") != "docker":
            continue
        dirs = list(u.get("directories") or []) + ([u["directory"]] if u.get("directory") else [])
        for d in dirs:
            base = root / d.strip("/")
            out += sorted(p for p in base.iterdir() if p.is_file() and _DEPENDABOT_DOCKERFILE.search(p.name))
    return out


def dependabot_invisible_pins(dockerfile: Path, root: Path) -> list[str]:
    """The registry base images in `dockerfile` reached only through ARG substitution — the ones Dependabot
    cannot see. image_pins is the single parser of FROM lines (ARG- and build-stage-aware); a ref whose
    context is anything but a literal "FROM" came through an ARG."""
    return [f"{r.source}:{r.line} {r.ref} ({r.context})"
            for r in _load_image_pins().dockerfile_refs(dockerfile, root) if r.context != "FROM"]


def test_dependabot_can_see_every_docker_base_it_watches():
    """Every base image in every Dependabot-watched Dockerfile is on a literal FROM line, so the docker
    entry really refreshes it. FAILS on the pre-fix tree (gateway pinned only via `ARG PYTHON_BASE`)."""
    files = dependabot_docker_files(_load_yaml(DEPENDABOT))
    rels = {str(p.relative_to(REPO)) for p in files}
    assert {"gateway/Dockerfile", "engine/crucible/framework/v2/aegis/Dockerfile"} <= rels, rels
    invisible = [x for p in files for x in dependabot_invisible_pins(p, REPO)]
    assert not invisible, (
        "these pinned base images are reached only through an ARG, which Dependabot's docker parser never "
        "substitutes, so they get no refresh PRs. Pin the image on a literal `FROM … AS <stage>` and point "
        f"the ARG's default at that stage (see gateway/Dockerfile): {invisible}"
    )


def test_negative_control_arg_only_pin_is_invisible_to_dependabot(tmp_path):
    digest = "sha256:" + "a" * 64
    df = tmp_path / "Dockerfile"
    df.write_text(f"ARG BASE=python:3.13-slim@{digest}\nFROM ${{BASE}}\n", encoding="utf-8")
    assert dependabot_invisible_pins(df, tmp_path), "an ARG-only base pin was not flagged"
    df.write_text(f"ARG BASE=pinned\nFROM python:3.13-slim@{digest} AS pinned\nFROM ${{BASE}}\n", encoding="utf-8")
    assert dependabot_invisible_pins(df, tmp_path) == [], "the literal-stage form was wrongly flagged"


def test_negative_control_guard_discovers_every_file_dependabot_scans(tmp_path):
    """Discovery must match Dependabot's name rule, not a narrower list: an ARG-only pin in `Dockerfile-dev` or
    a lowercase `dockerfile` in a watched directory is scanned by Dependabot, so the guard must see it too."""
    watched = tmp_path / "svc"
    watched.mkdir()
    arg_only = "ARG BASE=python:3.13-slim@sha256:" + "a" * 64 + "\nFROM ${BASE}\n"
    for name in ("Dockerfile-dev", "dockerfile", "build.containerfile"):
        (watched / name).write_text(arg_only, encoding="utf-8")
    (watched / "README.md").write_text("FROM ${BASE}\n", encoding="utf-8")
    config = {"updates": [{"package-ecosystem": "docker", "directories": ["/svc"], "schedule": {"interval": "weekly"}}]}
    found = dependabot_docker_files(config, root=tmp_path)
    assert {p.name for p in found} == {"Dockerfile-dev", "dockerfile", "build.containerfile"}, found
    assert all(dependabot_invisible_pins(p, tmp_path) for p in found)


# ------------------------------------------------------------------------------------------------
# 2. The scheduled scan workflow
# ------------------------------------------------------------------------------------------------
def test_workflow_parses():
    _load_yaml(WORKFLOW)  # asserts it is a mapping / valid YAML


def test_workflow_has_daily_schedule_trigger():
    wf = _load_yaml(WORKFLOW)
    on = _on_block(wf)
    assert has_schedule_trigger(on), "the scheduled scan has no `on.schedule` cron trigger"


def test_workflow_declares_issues_write():
    wf = _load_yaml(WORKFLOW)
    perms = wf.get("permissions") or {}
    assert perms.get("issues") == "write", "workflow must declare `issues: write` to open an issue"


def test_workflow_opens_an_issue_on_findings():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "gh issue create" in text, "workflow has no issue-creation step"
    assert "supply_chain_scan.py" in text, "workflow does not invoke the decision script"
    # The open step must be gated to the schedule event so PR runs never create issues.
    assert "github.event_name == 'schedule'" in text, "issue-open step is not gated to the schedule event"


def test_workflow_has_asserted_negative_control():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "--expect-findings" in text, "workflow has no asserted negative control"
    assert "--dry-run" in text, "the negative control must run in dry-run so it opens no issue"


def test_workflow_actions_are_sha_pinned():
    """Every `uses:` in this workflow pins a 40-hex commit SHA, not a mutable tag."""
    import re

    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW.read_text(encoding="utf-8"))
    assert uses, "no actions found to check"
    for ref in uses:
        _, _, pin = ref.partition("@")
        assert re.fullmatch(r"[0-9a-f]{40}", pin), f"action not SHA-pinned: {ref}"


# ------------------------------------------------------------------------------------------------
# 3. The decision script — fires on CRITICAL, silent on clean and on sub-threshold
# ------------------------------------------------------------------------------------------------
def _report(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_script_opens_issue_on_critical():
    m = _load_scan_module()
    findings = m.collect_findings(_report("trivy_report_critical.json"), "CRITICAL")
    assert len(findings) == 1 and findings[0]["id"] == "CVE-2020-14343"
    issue = m.build_issue(findings, min_severity="CRITICAL")
    assert issue is not None
    title, body = issue
    assert "CVE-2020-14343" in body and "PyYAML" in body
    assert "CRITICAL" in title


def test_script_silent_on_clean_report():
    """NEGATIVE CONTROL: a clean report opens nothing — the scan is not a gate that always fires."""
    m = _load_scan_module()
    findings = m.collect_findings(_report("trivy_report_clean.json"), "CRITICAL")
    assert findings == []
    assert m.build_issue(findings, min_severity="CRITICAL") is None


def test_script_respects_threshold():
    """NEGATIVE CONTROL: a HIGH-only report opens nothing at a CRITICAL threshold."""
    m = _load_scan_module()
    report = _report("trivy_report_high_only.json")
    assert m.build_issue(m.collect_findings(report, "CRITICAL"), min_severity="CRITICAL") is None
    # ...but the SAME report does produce an issue once the threshold is HIGH (proves the knob works).
    assert m.build_issue(m.collect_findings(report, "HIGH"), min_severity="HIGH") is not None


def test_script_expect_findings_cli_fails_on_empty(tmp_path):
    """The `--expect-findings` negative-control flag exits non-zero on a clean report."""
    m = _load_scan_module()
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"Results": []}), encoding="utf-8")
    rc = m.main(["--report", str(clean), "--min-severity", "CRITICAL", "--dry-run", "--expect-findings"])
    assert rc == 2, "expected exit 2 when --expect-findings sees no finding"
    # And it exits 0 when the fixture genuinely has a CRITICAL.
    rc_ok = m.main([
        "--report", str(FIXTURES / "trivy_report_critical.json"),
        "--min-severity", "CRITICAL", "--dry-run", "--expect-findings",
    ])
    assert rc_ok == 0


# ------------------------------------------------------------------------------------------------
# Negative controls for the pure config checkers — they must REJECT bad input, not wave it through.
# ------------------------------------------------------------------------------------------------
def test_negative_control_missing_ecosystem_is_caught():
    broken = {"version": 2, "updates": [
        {"package-ecosystem": "pip", "directory": "/", "schedule": {"interval": "weekly"}},
    ]}
    assert missing_ecosystems(broken, REQUIRED_ECOSYSTEMS), "checker missed a config lacking four ecosystems"
    # sanity: the same checker passes the real, complete config.
    assert not missing_ecosystems(_load_yaml(DEPENDABOT), REQUIRED_ECOSYSTEMS)


def test_negative_control_update_without_schedule_is_caught():
    broken = {"version": 2, "updates": [{"package-ecosystem": "pip", "directory": "/"}]}
    assert updates_without_schedule(broken) == [0]


def test_negative_control_workflow_without_schedule_is_caught():
    assert not has_schedule_trigger({"pull_request": {"branches": ["main"]}})
    assert not has_schedule_trigger({"schedule": []})
    assert has_schedule_trigger({"schedule": [{"cron": "0 6 * * *"}]})
