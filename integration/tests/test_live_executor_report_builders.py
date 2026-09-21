"""
Typed argv builders for the three REPORT-FILE scanners: nikto, wapiti, zaproxy.

Before this, VIGIL could only PARSE these tools' reports (``framework.v2.imports.parsers``) — nothing in
the repository could drive them, so ``tools/profile.py`` honestly refused them for having no control
surface. These tests pin the capability that was built to close that gap, and they attack exactly the
properties that make a typed builder stronger than a prose playbook:

  * **Exact argv.** Each builder emits ONE well-understood, bounded invocation — asserted token for
    token, so a future edit that widens a scan, drops a bound, or changes the report format has to
    change a test that says why.
  * **The caller supplies data, never flags.** Every option is chosen by the builder. A caller value
    that looks like an option (``--proxy=…``, ``-o /etc/cron.d/x``) is either refused or lands as a
    flag VALUE — it can never introduce an option, and it can never name the report artifact.
  * **Refuse rather than guess.** An out-of-range bound, an off-host wapiti scope, or a module list
    that is not a plain token CSV returns a refusal, not a best effort.
  * **An invalid target never spawns anything.** The refusal happens in the executor's egress pin,
    before authorization and before the builder is reached.
  * **The output is what VIGIL can actually read.** The report the builder asks for is round-tripped
    through ``_absorb_report`` and then through the REAL import adapters — the same
    ``parse_export``/``detect_format`` the operator's import path uses.
  * **A stale artifact is never reported as this run's output** (the fabrication risk a deterministic
    report path creates).

Nothing here spawns a tool: the runner is injected and either records the argv or writes a canned
report where the builder asked for one.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import tempfile

import pytest
from types import SimpleNamespace

from vigil_integration.agent.state import Phase
from vigil_integration.live import executor as ex
from vigil_integration.live.executor import RunOutcome, execute

REPORT_TOOLS = ("nikto", "wapiti", "zaproxy")


# --- isolation: every test gets its own private report root ---------------------------------------


@pytest.fixture(autouse=True)
def _isolated_report_root(tmp_path, monkeypatch):
    """``_report_root`` hangs off ``tempfile.gettempdir()``; point that at a per-test directory so the
    deterministic artifact paths are reproducible AND no test can see another's artifacts."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    yield


#: Where the tools whose registry entry declares ALTERNATE binary names resolve to, for this file.
#: ``zaproxy`` (and ``httpx``, which the whole-roster tests below build) resolve through the registry's
#: declared names, so their argv[0] is an absolute path rather than a bare name — see
#: ``test_builder_binary_resolution.py``, which is where that behaviour is pinned. Without this pin
#: these tests would silently read the BOX: they passed here only because this machine happens to carry
#: /usr/bin/zaproxy and /usr/bin/httpx-toolkit, and would have failed on a checkout without them. A unit
#: test of an argv must not depend on which security tools are installed.
RESOLVED = {"zaproxy": "/usr/bin/zaproxy", "httpx": "/usr/bin/httpx-toolkit"}


@pytest.fixture(autouse=True)
def _pinned_binary_resolution(monkeypatch):
    by_name = {"zaproxy": RESOLVED["zaproxy"], "httpx-toolkit": RESOLVED["httpx"]}
    monkeypatch.setattr(ex, "_which", lambda name: by_name.get(name))
    monkeypatch.setattr(ex, "_version_banner", lambda path, args: "")
    yield


def root() -> str:
    return os.path.join(tempfile.gettempdir(), ex._REPORT_DIR_NAME)


def expected_report(tool: str, url: str) -> str:
    """Recompute the builder's deterministic artifact path independently (never by calling the
    allocator), so the test would catch a change in how the path is derived."""
    digest = hashlib.sha256(f"{tool}|{url}".encode("utf-8")).hexdigest()[:16]
    return os.path.join(root(), f"{tool}-{digest}.json")


# --- ZAP's automation plan: the file that now decides the SHAPE of the scan -----------------------
#
# ZAP is the one builder whose behaviour is not fully in its argv: `-autorun` points at a plan this
# module writes. That file is therefore part of the command surface, and these helpers exist so every
# property the other builders assert about their argv is asserted about ZAP's argv AND its plan — never
# about the argv alone, which after this change would be the weaker check.


def zap_plan_path(build) -> str:
    return build.argv[build.argv.index("-autorun") + 1]


def zap_plan_text(build) -> str:
    return open(zap_plan_path(build), encoding="utf-8").read()


def zap_jobs(plan: str) -> list:
    """``[(job type, {parameter: value})]`` in plan order, by indentation — no YAML library, so this
    test cannot be skipped on a checkout without one. A regression test that quietly does not run is
    the silent negative control this whole file exists to refuse."""
    jobs: list = []
    in_jobs = False
    for line in plan.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs or not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.strip()
        if stripped.startswith("- type:"):
            jobs.append((stripped.split(":", 1)[1].strip().strip("'\""), {}))
        elif ":" in stripped and jobs and not stripped.endswith(":"):
            key, _, value = stripped.partition(":")
            jobs[-1][1][key.strip()] = value.strip().strip("'\"")
    return jobs


def command_surface(build) -> str:
    """Everything this call hands the tool: the argv, plus — for ZAP — the plan the argv points at."""
    text = "\n".join(str(a) for a in build.argv)
    return text + "\n" + zap_plan_text(build) if "-autorun" in build.argv else text


# --- injected primitives (deterministic: no wallclock, no RNG, no spawn) --------------------------


PINNED = ex._Pinned(host="127.0.0.1", port=8080, scheme="http", path="/app", query="",
                    raw_host="127.0.0.1")
URL = "http://127.0.0.1:8080/app"


def det_signer(data: bytes) -> str:
    return "sig-" + hashlib.sha256(data).hexdigest()[:24]


class FakeRun:
    """Records the argv; never spawns. ``report`` (when given) is written to the path the builder put in
    the argv — i.e. the fake tool only ever writes where VIGIL told it to."""

    def __init__(self, stdout: str = "", report: str | None = None, report_suffix: str = "",
                 exit_code: int = 0):
        self.calls: list[list[str]] = []
        self.stdout, self.report, self.report_suffix, self.exit_code = (
            stdout, report, report_suffix, exit_code)

    def __call__(self, argv, *, timeout, output_cap):
        self.calls.append(list(argv))
        if self.report is not None:
            path = report_path_in(argv)
            assert path is not None, "the builder handed the runner no report path"
            with open(path + self.report_suffix, "w", encoding="utf-8") as fh:
                fh.write(self.report)
        return RunOutcome(exit_code=self.exit_code, stdout=self.stdout, stderr="")


def report_path_in(argv: list) -> str | None:
    """Where the tool has been told to write its report. For ZAP that is not in the argv at all: the
    argv points at an automation plan, and the plan's report job names the artifact — so the fake tool
    reads the plan exactly as ZAP does. A fake that guessed the path instead would keep passing even if
    the plan named a different file, which is precisely the break this seam exists to catch."""
    if "-autorun" in argv:
        report = dict(zap_jobs(open(argv[argv.index("-autorun") + 1], encoding="utf-8").read())).get("report", {})
        directory, name = report.get("reportDir"), report.get("reportFile")
        return os.path.join(directory, name) if directory and name else None
    for token in argv:
        if isinstance(token, str) and token.startswith(root()) and token.endswith(".json"):
            return token
    return None


def gate(allowed: bool = True):
    def _g(tool_name, target, destructive):
        return SimpleNamespace(outcome="allow" if allowed else "deny", allowed=allowed, reason="ok")
    return _g


def view():
    phases = [p.value for p in Phase]
    return {t: list(phases) for t in (*REPORT_TOOLS, "ffuf")}


def run_exec(tool, args, *, run, phase=Phase.INFORMATIONAL, g=None):
    return execute(tool, args, phase, gate=g or gate(), view=view(),
                   destructive_view={t: False for t in (*REPORT_TOOLS, "ffuf")}, run=run,
                   signer=det_signer, seq=next(_SEQ), now=7)


_SEQ = itertools.count(1)


# ==================================================================================================
# 1. the exact argv — one bounded, machine-readable invocation per tool
# ==================================================================================================


def test_nikto_argv_is_exactly_the_bounded_json_report_invocation():
    build = ex._BUILDERS["nikto"]({}, PINNED)
    report = expected_report("nikto", URL)
    assert build.argv == [
        "nikto", "-h", URL,
        "-Format", "json", "-output", report,     # the report parse_nikto_export reads
        "-nointeractive", "-ask", "no",           # never blocks on a prompt, never submits
        "-nocheck", "-nolookup",                  # no update fetch, no DNS — no request off the pin
        "-maxtime", "90s", "-timeout", "10",      # in-tool scan + per-request bounds
        "-Tuning", "x6",                          # every category EXCEPT denial of service
    ]
    assert build.report_path == report
    assert build.target == URL


def test_wapiti_argv_is_exactly_the_bounded_json_report_invocation():
    build = ex._BUILDERS["wapiti"]({}, PINNED)
    report = expected_report("wapiti", URL)
    state = os.path.join(root(), "wapiti-state")
    assert build.argv == [
        "wapiti", "-u", URL,
        "-f", "json", "-o", report,               # the report parse_wapiti_export reads
        "--scope", "folder",                      # same-host scope only (never domain/subdomain/punk)
        "-d", "2",
        "--max-scan-time", "90", "--max-attack-time", "60",
        "--max-links-per-page", "50", "--max-files-per-dir", "50",
        "--store-session", state, "--store-config", state,   # state stays out of the operator's $HOME
        "--no-bugreport",                         # no crash-report upload to a third party
        # The module set is DECLARED, never inherited. Wapiti's own defaults include `ssrf`, which
        # asks an external endpoint of the tool author's choosing for out-of-band results — observed
        # live contacting wapiti3.ovh on 443. That breaks the charter's no-egress limit, and neither
        # the scope pin (which constrains the TARGET) nor --no-bugreport (a different path) prevents
        # it. Every module below attacks the pinned target directly and needs no collaborator.
        "-m", ex._WAPITI_SAFE_MODULES,
        "--flush-session",                        # a fresh scan, never a resumed one
    ]
    assert build.report_path == report
    # A future edit that reintroduces an out-of-band module fails HERE as well as in the dedicated
    # egress test, because this is the argv a reader checks when asking "what does a default run do?"
    assert not ({m.strip() for m in ex._WAPITI_SAFE_MODULES.split(",")} & ex._WAPITI_EGRESSING_MODULES)


def test_zaproxy_argv_is_exactly_the_bounded_json_report_invocation():
    build = ex._BUILDERS["zaproxy"]({}, PINNED)
    report = expected_report("zaproxy", URL)
    assert build.argv == [
        # The RESOLVED ABSOLUTE PATH, not the bare name. ZAP installs as `zaproxy` (Debian package),
        # `zap.sh` (upstream) or `zap-cli`; the registry declares all three and the tools screen resolves
        # them, so a builder that hardcoded `zaproxy` reported ZAP controllable on a host carrying only
        # `zap.sh` and then failed to spawn. Recording what actually ran is the other half: the signed
        # record then says WHICH ZAP produced the report. Pinned by the fixture above, not read off this
        # box. See test_builder_binary_resolution.py.
        RESOLVED["zaproxy"],
        "-cmd", "-silent", "-notel",              # headless; no unsolicited request, no telemetry
        "-dir", os.path.join(root(), "zaproxy-home"),
        # The proxy-port pin is load-bearing, not cosmetic, and this test was written before it
        # existed. ZAP starts its MAIN PROXY LISTENER even for a one-shot headless scan, defaulting
        # to 8080 — a port very often already in use on an operator's own machine. When it is, ZAP
        # exits 1 after ~10 seconds with "Failed to start the main proxy: Address already in use" and
        # writes NO report, while the executor sees a process that ran to completion and returns an
        # empty result. That silent no-op scan is worse than a refusal: nothing fires and nothing
        # explains why. Measured on a real host — without the flag: exit 1, zero bytes. With it:
        # exit 0, a ~12KB report, 14 findings parsed by the import adapter.
        "-config", f"network.localServers.mainProxy.port={ex._ZAP_PROXY_PORT}",
        # `-autorun <plan>`, NOT `-quickurl <url>`. ZAP's quick scan active-scans ONLY the node it is
        # seeded with — measured, `Scanning 1 node(s)` — so a bare host produced a scan that sent zero
        # parameter requests and a report byte-identical to the hardened control's. See the plan tests
        # below and the builder's own block for the measurement.
        "-autorun", zap_plan_path(build),
        "-config", "spider.maxDuration=1",
        "-config", "scanner.maxScanDurationInMins=1",
        "-config", "scanner.maxRuleDurationInMins=1",
        # ZAP MUST NOT DRIVE A BROWSER. ZAP ships the DOM XSS active scan rule, which drives a real
        # Firefox through the selenium add-on, and Firefox resolves
        # `firefox.settings.services.mozilla.com` on startup for its Remote Settings sync — DNS
        # leaving the host for a name that is not the target, which the charter forbids in as many
        # words. Measured inside a network namespace whose only off-loopback route is a blackhole,
        # with every packet captured: 16 such queries in one 41-second scan WITHOUT these two lines,
        # ZERO with them, `Automation plan succeeded!` either way, and a report that still carries
        # the Cross Site Scripting alert. `-silent` and `-notel` do not cover it — they are the
        # callhome and telemetry add-ons, and a browser phoning its vendor is neither.
        "-config", "selenium.firefoxBinary=/nonexistent/vigil-no-browser",
        "-config", "selenium.chromeBinary=/nonexistent/vigil-no-browser",
    ]
    assert build.report_path == report
    assert "-quickurl" not in build.argv, "the quick scan cannot active-scan what the spider found"
    assert report.endswith(".json"), "ZAP reads the report FORMAT off the extension"
    # Pinning to ZAP's own default would reinstate the very collision the pin exists to avoid, so a
    # future "tidy-up" that sets this back to 8080 fails here rather than silently going quiet again.
    assert ex._ZAP_PROXY_PORT != 8080, "pinning to ZAP's default port reinstates the bind collision"
    # And the browser pin has to be a path that CANNOT exist, on EVERY browser ZAP can drive: a real
    # path here is a browser, and a browser is egress.
    for opt in ex._ZAP_NO_BROWSER:
        if opt == "-config":
            continue
        key, _, path = opt.partition("=")
        assert key.startswith("selenium.") and key.endswith("Binary"), key
        assert path.startswith("/nonexistent/") and not os.path.exists(path), path
    assert {o.split("=")[0] for o in ex._ZAP_NO_BROWSER if o != "-config"} == {
        "selenium.firefoxBinary", "selenium.chromeBinary"}


def test_nuclei_argv_is_exactly_the_bounded_no_egress_invocation():
    # nuclei is a stdout-JSONL builder, not a report-file one, so it lives beside the three above rather
    # than among them — but it has the SAME pair of invisible default egresses, and pinning its exact
    # argv is what makes a future drop of either suppression fail loudly here. `-disable-update-check`
    # covers the startup phone-home to ProjectDiscovery's update host; `-no-interactsh` covers the
    # OAST/interactsh registration to a public interaction server (oast.pro) that the update check does
    # NOT cover — the one the nightly full-table egress guard logs as BLOCKED. Both are the tool's own
    # defaults, invisible until pinned. The target is rebuilt from the pin, never from caller text.
    build = ex._BUILDERS["nuclei"]({}, PINNED)
    assert build.argv == [
        "nuclei", "-target", URL, "-jsonl", "-no-color",
        "-disable-update-check",                  # no startup version fetch off the pin
        "-no-interactsh",                         # no OAST/interactsh registration to oast.pro
    ]
    assert build.target == URL


# ==================================================================================================
# 1b. ZAP's plan — the tests that fail if the scan goes back to attacking one node
# ==================================================================================================
#
# THE DEFECT THIS SECTION GUARDS, measured against the loopback range: driven by `-quickurl` and seeded
# with a bare host, ZAP's active scanner scanned exactly the node it was seeded with (its own log:
# `Scanning 1 node(s)`), so every parameter-level rule sent ZERO requests
# (`CrossSiteScriptingScanRule … 0 message(s) sent`) even though the spider had already fetched the
# injectable `/search?q=`. The report came back weakness-free and byte-identical to the hardened
# control's, and raising the budget fivefold produced a byte-identical report — the limit was structural,
# not temporal. A clean report that means "I did not look" is the worst output this executor can
# produce, so these tests pin the three structural properties that stop it recurring, each of which
# ALONE restores the defect if it is lost: the crawl runs, the active scan takes the CONTEXT rather than
# one URL, and it runs after the crawl rather than before it.


def test_zaproxy_actively_scans_the_whole_crawl_not_just_the_node_it_was_seeded_with():
    jobs = zap_jobs(zap_plan_text(ex._BUILDERS["zaproxy"]({}, PINNED)))
    order = [kind for kind, _ in jobs]
    assert order == ["spider", "passiveScan-wait", "activeScan", "report"], (
        "the crawl must run BEFORE the active scan (an active scan with nothing in the sites tree has "
        "only its seed to attack, which is the quick-scan defect rebuilt inside the plan), and the "
        "passive scanner must drain BEFORE the report or its alerts are missing from it")
    params = dict(jobs)
    assert params["activeScan"].get("context"), "the active scan must be aimed at the CONTEXT"
    assert "url" not in params["activeScan"], (
        "an activeScan `url` narrows the scan to that subtree — the whole defect was a scan aimed at "
        "one node while the parameters the crawl found went untouched")
    assert params["spider"]["url"] == URL, (
        "the crawl must START at the caller's pinned URL, so a parameterised URL that nothing links to "
        "is still reached, still in the tree, and still attacked")
    assert params["activeScan"]["context"] == params["spider"]["context"], (
        "the scan must attack the context the crawl filled, not a different one")


def test_the_zap_context_is_the_pinned_origin_and_nothing_wider():
    plan = zap_plan_text(ex._BUILDERS["zaproxy"]({}, PINNED))
    origin = "http://127.0.0.1:8080/"
    assert f"- '{origin}'" in plan                      # the context's one top-level url
    assert f"- '\\Q{origin}\\E.*'" in plan, (
        "the include path must be an ANCHORED LITERAL (\\Q…\\E), so no character of a URL is ever read "
        "as a regex metacharacter")
    assert "excludePaths" not in plan                   # nothing quietly carved out of what was asked for


def test_a_zap_scan_that_could_not_reach_the_target_fails_instead_of_reporting_clean():
    """Measured against a closed port: `failOnError: true` + `continueOnFailure: false` gives exit 1,
    NO report file, and `Job spider failed to access URL … Connection refused` on the console the
    executor keeps as stderr. Without them the plan runs on to the report job and writes an empty but
    perfectly well-formed clean report — which is indistinguishable from a target that was scanned and
    found sound. That distinction is the only thing that makes the empty report evidence."""
    plan = zap_plan_text(ex._BUILDERS["zaproxy"]({}, PINNED))
    assert "failOnError: true" in plan
    assert "continueOnFailure: false" in plan
    assert "progressToStdout: true" in plan, (
        "the per-job coverage ZAP prints (`Job spider found N URLs`) is what a clean report has to be "
        "read against; without it the record holds a report and no account of what produced it")


def test_the_zap_plan_names_the_report_artifact_vigil_allocated():
    build = ex._BUILDERS["zaproxy"]({}, PINNED)
    jobs = dict(zap_jobs(zap_plan_text(build)))
    assert jobs["report"]["template"] == "traditional-json", "the shape parse_zap_export reads"
    assert jobs["report"]["reportDir"] == os.path.dirname(build.report_path)
    assert jobs["report"]["reportFile"] == os.path.basename(build.report_path)
    assert os.path.dirname(build.report_path) == root()


def test_the_zap_plan_file_is_named_for_its_own_bytes():
    """The plan decides the shape of the scan, so the signed record's argv has to commit to it: the
    filename is the sha256 of the plan's contents. A plan named for anything else would let two
    different scans share one record."""
    build = ex._BUILDERS["zaproxy"]({}, PINNED)
    path, text = zap_plan_path(build), zap_plan_text(build)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    assert os.path.basename(path) == f"zaproxy-plan-{digest}.yaml"
    assert os.path.dirname(path) == root()
    assert os.stat(path).st_mode & 0o077 == 0, "the plan names the report artifact; keep it private"
    # a different budget is a different scan, and must not reuse the same plan file
    assert zap_plan_path(ex._BUILDERS["zaproxy"]({"max_minutes": 7}, PINNED)) != path


@pytest.mark.parametrize("path,query", [("/a'b", ""), ("/a", "q='"), ("/a\\b", ""), ("/a\"b", ""),
                                        ("/a\x01b", ""), ("/é", "")])
def test_a_target_that_cannot_be_written_into_the_plan_is_refused_with_a_reason(path, query):
    """The plan is a file, so it is a quoting surface the argv never was. A target whose path or query
    carries a quote, a backslash or a non-printable character is REFUSED with a reason the operator
    sees — never emitted into YAML and left to a reader's escaping rules."""
    from dataclasses import replace
    refusal = ex._BUILDERS["zaproxy"]({}, replace(PINNED, path=path, query=query))
    assert isinstance(refusal, str) and "automation plan" in refusal


def test_the_zap_plan_is_valid_yaml_of_the_shape_asserted_above():
    """The hand-emitted plan is really YAML, and really parses to the structure the string assertions
    above check. Skippable ONLY because pyyaml is not a dependency of this package; the properties that
    matter are pinned by the unskippable tests above, and by ZAP having run this plan for real."""
    yaml = pytest.importorskip("yaml")
    build = ex._BUILDERS["zaproxy"]({}, PINNED)
    plan = yaml.safe_load(zap_plan_text(build))
    context = plan["env"]["contexts"][0]
    assert context["urls"] == ["http://127.0.0.1:8080/"]
    assert plan["env"]["parameters"]["failOnError"] is True
    jobs = {job["type"]: job.get("parameters", {}) for job in plan["jobs"]}
    assert jobs["activeScan"]["context"] == context["name"]
    assert "url" not in jobs["activeScan"]
    assert jobs["spider"]["url"] == URL
    assert jobs["report"]["reportFile"] == os.path.basename(build.report_path)


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_the_target_is_rebuilt_from_the_pin_not_from_caller_text(tool):
    """The URL the tool is given comes from the VALIDATED pin. A caller string that smuggles a second
    host reaches NOTHING the tool reads — not the argv, and not ZAP's plan, which is where ZAP's target
    now lives. Asserted over the whole command surface rather than the argv alone: moving the URL into
    a file the argv points at must not move it out of this test's reach."""
    build = ex._BUILDERS[tool]({"url": "http://127.0.0.1@evil.example/x", "target": "evil.example"},
                               PINNED)
    surface = command_surface(build)
    assert URL in surface
    assert "evil.example" not in surface
    assert not any("evil.example" in str(a) for a in build.argv)


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_every_run_is_bounded(tool):
    """No builder emits an unbounded scan: each argv carries at least one in-tool time cap, and the
    executor's own wall-clock timeout bounds the subprocess regardless of what the tool honours."""
    argv = ex._BUILDERS[tool]({}, PINNED).argv
    caps = {"nikto": ("-maxtime", "-timeout"),
            "wapiti": ("--max-scan-time", "--max-attack-time"),
            "zaproxy": ("spider.maxDuration=", "scanner.maxScanDurationInMins=")}[tool]
    for cap in caps:
        assert any(cap in str(a) for a in argv), f"{tool} lost its {cap} bound"
    assert ex.DEFAULT_TIMEOUT > 0


def test_the_default_in_tool_budgets_fit_inside_the_executors_wall_clock():
    """A tool killed by the executor's timeout before it writes its report produces NOTHING, so the
    DEFAULT budgets must fit inside ``DEFAULT_TIMEOUT``. (ZAP's floor is one minute — its caps have
    minute granularity — and a real ZAP scan genuinely needs a raised ``execute(timeout=…)``: its
    budget now covers a crawl AND an active scan, with the passive drain between them, so the worst
    case is roughly twice ``_ZAP_MAX_MINUTES`` plus the wait plus JVM start. That is stated in the
    builder rather than papered over.)"""
    assert ex._NIKTO_MAX_TIME <= ex.DEFAULT_TIMEOUT
    assert ex._WAPITI_MAX_SCAN_TIME <= ex.DEFAULT_TIMEOUT
    assert ex._WAPITI_MAX_ATTACK_TIME <= ex._WAPITI_MAX_SCAN_TIME
    assert ex._ZAP_MAX_MINUTES == 1
    assert ex._ZAP_PASSIVE_WAIT_MINUTES >= 1, "an unbounded passive wait is an unbounded run"


# ==================================================================================================
# 2. the caller supplies data, never flags
# ==================================================================================================


# every key each builder reads, with a value that would be an OPTION if it were concatenated onto a
# command line rather than validated and placed as one argv element.
FLAGGY = ("--proxy=http://evil.example:8080", "-o", "-o /etc/cron.d/pwn", "--config=/etc/passwd",
          "-output", "--tor", "-p 1080", "-", "--", "-Tuning=x", "; nikto -h evil.example",
          "$(id)", "`id`", "\n--proxy http://evil.example")

READ_KEYS = {
    "nikto": ("max_time", "maxtime", "request_timeout", "timeout", "tuning"),
    "wapiti": ("max_scan_time", "max_time", "depth", "modules", "module", "scope"),
    "zaproxy": ("max_minutes", "max_scan_minutes"),
}


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_a_caller_value_that_looks_like_a_flag_can_never_become_one(tool):
    """For every key a builder reads, a flag-shaped value must either be REFUSED or survive only as a
    flag's value. The argv's option set may never grow beyond the one the builder chose."""
    baseline = ex._BUILDERS[tool]({}, PINNED).argv
    baseline_opts = {a for a in baseline if a.startswith("-")}
    for key in READ_KEYS[tool]:
        for value in FLAGGY:
            build = ex._BUILDERS[tool]({key: value}, PINNED)
            if build is None:
                continue                                   # refused — the preferred outcome
            opts = {a for a in build.argv if a.startswith("-")}
            assert opts <= baseline_opts, f"{tool}:{key}={value!r} introduced options {opts - baseline_opts}"
            assert value not in build.argv, f"{tool}:{key}={value!r} reached the argv verbatim"


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_keys_the_builder_does_not_read_are_ignored_entirely(tool):
    """A caller cannot reach a flag the builder did not choose by naming it: unknown keys change
    nothing, including the report artifact's path."""
    hostile = {"output": "/etc/cron.d/pwn", "o": "/etc/cron.d/pwn", "report": "/etc/passwd",
               "report_path": "/etc/passwd", "quickout": "/etc/passwd", "dir": "/",
               "config": "spider.maxDuration=99999", "extra_args": ["--proxy", "http://evil.example"],
               "args": "--proxy http://evil.example", "proxy": "http://evil.example",
               "binary": "/bin/sh", "cmd": "sh -c id"}
    assert ex._BUILDERS[tool](hostile, PINNED).argv == ex._BUILDERS[tool]({}, PINNED).argv


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_the_report_artifact_is_named_by_vigil_and_stays_inside_its_private_root(tool):
    build = ex._BUILDERS[tool]({"output": "/tmp/anywhere.json", "o": "../../etc/passwd"}, PINNED)
    assert build.report_path == expected_report(tool, URL)
    assert os.path.dirname(build.report_path) == root()
    # the root is private: no group/other access, so no other local user can plant a symlink in it
    assert os.stat(root()).st_mode & 0o077 == 0


def test_a_report_root_that_is_not_a_private_directory_refuses_the_build(monkeypatch):
    """No private place for the report ⇒ no scan. (The builder refuses; it does not fall back to a
    world-writable path or to running without a report.)"""
    monkeypatch.setattr(ex, "_report_root", lambda: None)
    for tool in REPORT_TOOLS:
        assert ex._BUILDERS[tool]({}, PINNED) is None


# ==================================================================================================
# 3. refuse rather than guess
# ==================================================================================================


REFUSED_ARGS = [
    ("nikto", {"max_time": 0}), ("nikto", {"max_time": 3601}), ("nikto", {"max_time": "soon"}),
    ("nikto", {"max_time": True}), ("nikto", {"request_timeout": 0}), ("nikto", {"timeout": 121}),
    ("nikto", {"tuning": "1;2"}), ("nikto", {"tuning": "--evasion"}), ("nikto", {"tuning": "9" * 20}),
    ("wapiti", {"scope": "domain"}), ("wapiti", {"scope": "subdomain"}), ("wapiti", {"scope": "punk"}),
    ("wapiti", {"scope": "everything"}), ("wapiti", {"depth": 6}), ("wapiti", {"depth": -1}),
    ("wapiti", {"max_scan_time": 0}), ("wapiti", {"max_scan_time": 3601}),
    ("wapiti", {"modules": "all,-xxe"}), ("wapiti", {"modules": "sql xss"}),
    ("wapiti", {"modules": "/etc/passwd"}),
    ("zaproxy", {"max_minutes": 0}), ("zaproxy", {"max_minutes": 61}),
    ("zaproxy", {"max_minutes": "5m"}), ("zaproxy", {"max_scan_minutes": -1}),
]


@pytest.mark.parametrize("tool,args", REFUSED_ARGS)
def test_an_input_that_does_not_validate_is_refused_not_best_effort(tool, args):
    assert ex._BUILDERS[tool](args, PINNED) is None


ACCEPTED_ARGS = [
    ("nikto", {"max_time": 60}, ["-maxtime", "60s"]),
    ("nikto", {"request_timeout": "5"}, ["-timeout", "5"]),
    # An EXCLUDE-form tuning. `123b` used to be the fixture here; it is refused now, because an
    # include-only tuning cannot keep nikto's DoS checks off — see section 3b.
    ("nikto", {"tuning": "x6b"}, ["-Tuning", "x6b"]),
    ("wapiti", {"scope": "PAGE"}, ["--scope", "page"]),
    ("wapiti", {"depth": 0}, ["-d", "0"]),
    ("wapiti", {"modules": "sql,xss"}, ["-m", "sql,xss"]),
    ("wapiti", {"max_scan_time": 60}, ["--max-scan-time", "60", "--max-attack-time", "60"]),
    ("zaproxy", {"max_minutes": 10}, ["-config", "spider.maxDuration=10"]),
]


@pytest.mark.parametrize("tool,args,expected", ACCEPTED_ARGS)
def test_a_valid_knob_lands_as_the_value_of_the_flag_the_builder_chose(tool, args, expected):
    argv = ex._BUILDERS[tool](args, PINNED).argv
    for i in range(0, len(expected), 2):
        flag, value = expected[i], expected[i + 1]
        assert any(argv[j] == flag and argv[j + 1] == value for j in range(len(argv) - 1)), \
            f"{flag} {value} is not an adjacent flag/value pair in {argv}"


def test_wapiti_never_offers_a_scope_that_can_leave_the_pinned_host():
    """domain/subdomain/punk let wapiti crawl hosts the executor never resolved or pinned — the egress
    guard cannot stop a crawler that addresses those hosts itself, so they are not on offer at all."""
    assert ex._WAPITI_SCOPES == frozenset({"url", "page", "folder"})


def test_wapiti_refuses_the_signature_downloading_module_too():
    """`wapp` is the module that shows why a DECLARED set is not automatically a SAFE one.

    It needs no out-of-band collaborator, so the first pass at the safe list included it — and it
    still egresses: ``mod_wapp.attack`` runs against the root URL of every scan and calls
    ``_verify_wapp_database``, which on a missing/unreadable local database falls through to
    ``update_wappalyzer()``, an HTTPS fetch from ``raw.githubusercontent.com`` (``attack.py``'s
    ``wapp_url`` default). That database lives in wapiti's CONFIG dir, and this builder PINS the
    config dir to a VIGIL-owned directory VIGIL never populates — so under this builder the download
    path is the only path there is. Refused, not merely dropped from the default: the charter's
    no-egress limit is not the caller's to waive."""
    assert "wapp" in ex._WAPITI_EGRESSING_MODULES
    assert "wapp" not in {m.strip() for m in ex._WAPITI_SAFE_MODULES.split(",")}
    assert ex._BUILDERS["wapiti"]({"modules": "xss,wapp"}, PINNED) is None
    # and it is the MODULE that is refused, not every explicit list: a clean one still builds.
    assert ex._BUILDERS["wapiti"]({"modules": "xss,sql"}, PINNED) is not None


#: wapiti's OWN default module set, captured from `wapiti --list-modules` on wapiti 3.2.10 (the
#: entries marked "(used by default)"; cross-checked against `wapitiCore.attack.modules.core`, whose
#: `presets["common"]` is the superset these are drawn from). Written down here because the
#: invariant below is about what WAPITI runs, and a test that asked the installed wapiti would go
#: quiet on a box that has none.
WAPITI_OWN_DEFAULT_MODULES = frozenset({
    "exec", "file", "permanentxss", "redirect", "sql", "ssl", "ssrf", "upload", "xss",
})


def test_the_allowlist_covers_every_module_wapiti_itself_runs_by_default():
    """AN ALLOWLIST THAT OMITS A SAFE MODULE IS A DEFECT, because the refusal is TOTAL.

    `_build_wapiti` returns None for the WHOLE call when any one named token is not on the list — so
    a missing name does not narrow a scan, it cancels it. `upload` was missing: it is in wapiti's own
    default set and in its `common` preset, `mod_upload` imports only `RequestError` from httpx and
    attacks the crawled forms of the pinned target, and yet a caller naming wapiti's own defaults got
    a flat refusal. Measured in tools/livefire: the wapiti row was refused on BOTH legs and the
    driver went from proven to unprovable, with the failure reading "argv builder for 'wapiti'
    refused the arguments" — pointing at the caller rather than at this list.

    So the invariant is stated rather than left to a live-fire run to discover: everything wapiti
    runs by default is nameable here, EXCEPT the ones that reach a third party — and those are
    refused by name, which is the other half of the same rule."""
    assert not (ex._WAPITI_ALLOWED_MODULES & ex._WAPITI_EGRESSING_MODULES)
    assert WAPITI_OWN_DEFAULT_MODULES & ex._WAPITI_EGRESSING_MODULES == {"ssrf"}
    missing = (WAPITI_OWN_DEFAULT_MODULES - ex._WAPITI_EGRESSING_MODULES) - ex._WAPITI_ALLOWED_MODULES
    assert not missing, (
        f"wapiti runs {sorted(missing)} by default and none of them egresses, but the allowlist "
        f"refuses them — and the refusal cancels the whole call, not just those modules")
    # the live-fire row's list (wapiti's defaults minus the egressing ssrf) therefore BUILDS
    row_list = ",".join(sorted(WAPITI_OWN_DEFAULT_MODULES - ex._WAPITI_EGRESSING_MODULES))
    build = ex._BUILDERS["wapiti"]({"modules": row_list}, PINNED)
    assert build is not None and ["-m", row_list] == build.argv[-3:-1]
    # MUTATION CONTROL: covering the defaults must not have widened the door for a preset name, and
    # `passive` is a third preset the first version of this guard did not know existed.
    for preset in ("all", "common", "passive"):
        assert ex._BUILDERS["wapiti"]({"modules": preset}, PINNED) is None


# ==================================================================================================
# 3b. nikto never offers the DENIAL OF SERVICE category
# ==================================================================================================
# Nikto's `-Tuning` category `6` is Denial of Service (`nikto -H`; 51 of the 7232 db_tests entries
# carry it). VIGIL does not classify nikto destructive, so reaching that category through this
# builder would deliver a destructive capability down a non-destructive path. The builder refuses it
# instead of promoting the tool — a misconfiguration sweep has no need of a DoS category.


def test_nikto_is_not_a_destructive_tool_which_is_why_dos_is_refused_here():
    """The two halves have to stay consistent: as long as nikto is NOT on the destructive manifest
    (no m-of-n leg, no destructive gate), no path through its builder may select a DoS scan. If
    someone adds nikto to the manifest, this test says where to look; until then, refuse."""
    from vigil_integration.live.wiring import DEFAULT_DESTRUCTIVE_VIEW
    assert DEFAULT_DESTRUCTIVE_VIEW.get("nikto") is not True
    assert ex._NIKTO_DOS_CATEGORY == "6"
    assert not ex._nikto_tuning_runs(ex._NIKTO_DEFAULT_TUNING, ex._NIKTO_DOS_CATEGORY)


def test_nikto_excludes_denial_of_service_by_default():
    """MUTATION CONTROL included: nikto's no-`-Tuning` default is EVERY category, so simply omitting
    the flag — which is what the builder used to do — runs the DoS checks. The flag is therefore not
    optional; it is always emitted, and it always excludes 6."""
    argv = ex._BUILDERS["nikto"]({}, PINNED).argv
    assert "-Tuning" in argv, "omitting -Tuning is what leaves the DoS category on"
    assert argv[argv.index("-Tuning") + 1] == "x6"
    # the control: what "no -Tuning" actually means to nikto
    assert ex._nikto_tuning_runs("", ex._NIKTO_DOS_CATEGORY) is True
    # …and what the builder emits instead. Non-DoS categories are untouched.
    assert ex._nikto_tuning_runs("x6", ex._NIKTO_DOS_CATEGORY) is False
    for other in "012345789abcde":
        assert ex._nikto_tuning_runs("x6", other) is True, f"category {other} lost its coverage"


# Tuning strings that ENABLE the DoS category outright, and therefore must be refused. Each is a real
# way nikto reaches category 6 — including the ones with no "6" in them at all.
DOS_ENABLING_TUNING = ["6", "16", "x16", "69", "b6", "0123456", "6d",
                       "x1", "x0", "xb", "x1b", "x9"]

# Tuning strings that leave DoS off. Every one is an EXCLUDE form, because that is the only form that
# can. `x6` is the important one: it is the string that DISABLES the category, and the
# obvious-but-wrong "reject any tuning containing 6" rule would refuse it.
DOS_FREE_TUNING = ["x6", "1x6", "x6b", "0x6", "ax6", "x63"]

# The DEFECT CLASS this section grew to cover, as DATA. A check's tuning tag is a SET of categories,
# and 25 of nikto 2.6.0's 51 DoS-tagged checks carry a second one — so an INCLUDE-only tuning that
# never mentions 6 still drags them in. Each entry is `(tuning, DoS checks it would run)`, measured by
# running nikto's own `set_scan_items` selection loop — transcribed verbatim out of
# `/usr/share/nikto/plugins/nikto_core.plugin` — over its real `db_tests`. `_nikto_tuning_runs` says
# False for every one of these (it answers a per-CATEGORY question), which is exactly why the gate no
# longer asks it: it requires the DoS category to be EXCLUDED instead.
DOS_VIA_MULTI_CATEGORY_TAG = [("1", 20), ("2", 20), ("3", 22), ("7", 21), ("b", 21), ("d", 1),
                              ("123", 22), ("0123457", 23)]


@pytest.mark.parametrize("tuning", DOS_ENABLING_TUNING)
def test_a_nikto_tuning_that_would_enable_denial_of_service_is_refused(tuning):
    assert ex._nikto_tuning_runs(tuning, "6") is True, "fixture must actually enable DoS"
    assert ex._valid_nikto_tuning(tuning) is False
    assert ex._BUILDERS["nikto"]({"tuning": tuning}, PINNED) is None


@pytest.mark.parametrize("tuning,dos_checks", DOS_VIA_MULTI_CATEGORY_TAG,
                         ids=[t for t, _ in DOS_VIA_MULTI_CATEGORY_TAG])
def test_an_include_only_tuning_is_refused_because_a_tag_can_carry_dos_too(tuning, dos_checks):
    """The hole a per-category rule leaves open, pinned as a test.

    `-Tuning 1` names one category and looks obviously safe. It is not: nikto matches each tuning
    character against the WHOLE tag, and 20 of its DoS checks are tagged `1234576890ab`, so that
    tuning runs 20 of them. The gate must refuse it, and the assertion below is deliberately written
    so the OLD rule cannot satisfy it — `_nikto_tuning_runs` is asserted to disagree, which is the
    whole point: the two answer different questions, and only one of them is the gate's."""
    assert dos_checks > 0
    assert ex._nikto_tuning_runs(tuning, "6") is False, \
        "the per-category model must still say 'no' here — that is what made this reachable"
    assert ex._valid_nikto_tuning(tuning) is False, \
        f"-Tuning {tuning} would run {dos_checks} denial-of-service check(s)"
    assert ex._BUILDERS["nikto"]({"tuning": tuning}, PINNED) is None


@pytest.mark.parametrize("tuning", DOS_FREE_TUNING)
def test_a_nikto_tuning_that_leaves_denial_of_service_off_still_works(tuning):
    """Refusing must not swallow the legitimate capability: a caller can still tune the scan, so long
    as the tuning EXCLUDES the DoS category — which, in nikto's grammar, is the only way to say it."""
    assert ex._nikto_tuning_runs(tuning, "6") is False
    _inc, exc = ex._nikto_tuning_sets(tuning)
    assert ex._NIKTO_DOS_CATEGORY in exc, "the fixture must be an exclude form"
    build = ex._BUILDERS["nikto"]({"tuning": tuning}, PINNED)
    assert build is not None
    assert build.argv[build.argv.index("-Tuning") + 1] == tuning


def test_the_naive_nikto_dos_rule_is_wrong_in_both_directions():
    """MUTATION CONTROL for the refusal. `x` is nikto's per-character negation, so "reject any
    tuning containing '6'" gets the answer backwards twice: it refuses `x6` (which turns DoS OFF)
    and accepts `x1` (which excludes category 1 and therefore leaves DoS ON). Replace
    `_valid_nikto_tuning` with that rule and this test fails on both lines."""
    assert ex._valid_nikto_tuning("x6") is True, "'6' appears, yet DoS is OFF — must be allowed"
    assert ex._valid_nikto_tuning("x1") is False, "no '6' appears, yet DoS is ON — must be refused"


def test_a_repeated_category_is_refused_because_nikto_cannot_be_read_there():
    """Nikto classifies each category with a /g match against the SAME scalar, so `pos()` carries
    across iterations and a repeated character silently flips its own include/exclude sense (`x66`
    ends up excluding 6, `x11` ends up INCLUDING everything but 1 — DoS on). A repeated category
    means nothing to a category selector, so the builder refuses rather than model that."""
    for tuning in ("66", "x66", "x11", "1x1", "bb", "xx6", "123123"):
        assert ex._BUILDERS["nikto"]({"tuning": tuning}, PINNED) is None


def test_a_nikto_tuning_that_would_scan_nothing_is_refused():
    """`x` alone selects neither an include nor an exclude list, so nikto loads zero checks and
    reports nothing. A silent no-op scan is worse than a refusal — the caller would believe a scan
    happened. (This is the same failure the ZAP proxy-port pin exists to prevent.)"""
    assert ex._BUILDERS["nikto"]({"tuning": "x"}, PINNED) is None
    assert ex._valid_nikto_tuning("x") is False


def test_the_nikto_tuning_validator_still_refuses_everything_off_the_alphabet():
    """The pre-existing guard has to survive the new one: only the tuning alphabet, bounded length,
    and no trailing newline (`$` would have allowed one into the signed record)."""
    for tuning in ("--evasion", "1;2", "1 2", "X6", "x6\n", "9" * 20, "", "/etc/passwd", "1\n2"):
        assert ex._BUILDERS["nikto"]({"tuning": tuning}, PINNED) is None or tuning == "", tuning
    # an empty string is "no tuning given" to `_opt`, which means the safe default, not a refusal
    empty = ex._BUILDERS["nikto"]({"tuning": ""}, PINNED)
    assert empty is not None and empty.argv[empty.argv.index("-Tuning") + 1] == "x6"
    for tuning in (6, True, None, ["6"], {"t": "6"}):
        build = ex._BUILDERS["nikto"]({"tuning": tuning}, PINNED)
        # None means "absent" to `_opt` → the safe default; every other non-string is a refusal
        if tuning is None:
            assert build is not None and build.argv[build.argv.index("-Tuning") + 1] == "x6"
        else:
            assert build is None, tuning


# ==================================================================================================
# 4. an invalid target is refused before anything spawns
# ==================================================================================================


BAD_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata — the never-liftable floor
    "http://8.8.8.8/",                            # non-loopback public
    "http://127.0.0.1@evil.example/",             # a smuggled second host
    "http://[::1]:8080/",                         # IPv6 loopback, outside the IPv4 pin
    "http://127.0.0.1:99999/",                    # malformed port
    "",                                           # no target at all
]


@pytest.mark.parametrize("tool", REPORT_TOOLS)
@pytest.mark.parametrize("target", BAD_TARGETS)
def test_an_invalid_target_is_denied_and_nothing_is_spawned(tool, target):
    runner = FakeRun()
    res = run_exec(tool, {"url": target}, run=runner)
    assert res.ran is False and res.outcome == "deny"
    assert runner.calls == [], "a refused target must never reach the runner"


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_a_denying_gate_stops_the_scan(tool):
    runner = FakeRun()
    res = run_exec(tool, {"url": "http://127.0.0.1:8080/"}, run=runner, g=gate(allowed=False))
    assert res.ran is False and runner.calls == []


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_a_refusing_builder_denies_the_call_after_the_gate(tool):
    """A validation refusal inside the builder is an executor DENY — never a silent scan with defaults."""
    runner = FakeRun()
    bad = {"nikto": {"tuning": "--evasion"}, "wapiti": {"scope": "domain"},
           "zaproxy": {"max_minutes": 0}}[tool]
    res = run_exec(tool, {"url": "http://127.0.0.1:8080/", **bad}, run=runner)
    assert res.ran is False and res.outcome == "deny"
    assert "builder" in res.reason and runner.calls == []


# ==================================================================================================
# 5. the output is what the import adapter actually parses
# ==================================================================================================


# The shape a real nikto writes, captured from a live nikto 2.6.0 run on this host: a TOP-LEVEL
# ARRAY of per-host blocks (its report plugin pushes each host onto an arrayref and encodes that,
# so even a single-host scan is an array), each item's `url` a bare PATH, the host on the block.
# This fixture used to be a bare object — a shape nikto never emits — which is precisely why
# `test_the_output_parses_with_the_real_import_adapter` below passed while `detect_format` sent
# every real nikto report to the generic parser.
NIKTO_REPORT = json.dumps([{
    "end_time": "2026-08-13 17:13:14 -0400", "host": "127.0.0.1", "ip": "127.0.0.1",
    "port": "8080", "server_banner": None, "start_time": "2026-08-13 17:13:05 -0400",
    "vulnerabilities": [
        {"id": "999986", "method": "GET", "url": "/admin/", "references": "",
         "msg": "/admin/: This might be interesting: potential admin console."},
        {"id": "007342", "method": "GET", "url": "/",
         "references": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options",
         "msg": "The X-Frame-Options header is not set."},
    ],
}])

WAPITI_REPORT = json.dumps({
    "vulnerabilities": {
        "SQL Injection": [
            {"method": "GET", "path": "/item.php", "parameter": "id=1", "level": 1,
             "info": "SQL Injection via injection in the parameter id"},
        ],
        "Cross Site Scripting": [],
    },
    "infos": {"target": "http://127.0.0.1:8080/app"},
})

ZAP_REPORT = json.dumps({
    "@version": "2.17.0",
    "site": [{
        "@name": "http://127.0.0.1:8080", "@host": "127.0.0.1", "@port": "8080",
        "alerts": [{
            "alert": "Cross Site Scripting (Reflected)", "riskdesc": "High (Medium)",
            "instances": [{"uri": "http://127.0.0.1:8080/app?q=1", "param": "q",
                           "evidence": "<script>alert(1)</script>"}],
        }],
    }],
})

REPORTS = {"nikto": (NIKTO_REPORT, "nikto"), "wapiti": (WAPITI_REPORT, "wapiti"),
           "zaproxy": (ZAP_REPORT, "zap")}   # zaproxy's import-format name is "zap"


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_the_report_becomes_the_calls_machine_readable_stdout(tool):
    """The tool writes JSON to a file and prose to stdout. VIGIL returns the JSON as ``stdout`` — the one
    stream oracle intake and the import path consume — and demotes the prose to stderr, so nothing
    non-machine-readable can be mistaken for a report."""
    report, _ = REPORTS[tool]
    runner = FakeRun(stdout="- Nikto v2.5.0\n+ Target IP: 127.0.0.1\n", report=report)
    res = run_exec(tool, {"url": "http://127.0.0.1:8080/app"}, run=runner)
    assert res.ran is True
    assert res.stdout == report
    assert "Target IP" in res.stderr and "Target IP" not in res.stdout
    # the artifact is consumed: nothing is left behind for a later run to pick up
    assert report_path_in(runner.calls[0]) is not None
    assert not os.path.exists(report_path_in(runner.calls[0]))


def test_nikto_report_is_found_even_when_nikto_appends_its_own_json_extension():
    """Nikto appends the format extension to -output inconsistently across versions (the same quirk
    ``eval.adapters_ext.NiktoAdapter`` works around); both spellings are read back."""
    runner = FakeRun(report=NIKTO_REPORT, report_suffix=".json")
    res = run_exec("nikto", {"url": "http://127.0.0.1:8080/app"}, run=runner)
    assert res.stdout == NIKTO_REPORT
    assert not os.path.exists(report_path_in(runner.calls[0]) + ".json")


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_the_output_parses_with_the_real_import_adapter(tool):
    """The whole point of choosing these flags: run the executor's output through the SAME parsers the
    operator's import path uses. A builder whose output no adapter can read would be useless."""
    parsers = pytest.importorskip("framework.v2.imports.parsers",
                                  reason="CRUCIBLE not importable here")
    report, fmt = REPORTS[tool]
    res = run_exec(tool, {"url": "http://127.0.0.1:8080/app"}, run=FakeRun(report=report))
    assert parsers.detect_format(res.stdout) == fmt, "the report must be self-describing to the importer"
    findings, source = parsers.parse_export(fmt, res.stdout)
    assert source == fmt and findings, f"{fmt} adapter parsed nothing out of the builder's report"
    assert {f.tool for f in findings} == {fmt}
    assert all(f.location for f in findings)


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_a_stale_report_is_never_returned_as_this_runs_output(tool):
    """The artifact path is deterministic, so a report from an EARLIER run sits exactly where this run's
    would. If the tool dies before writing, the call must yield an EMPTY report — never last run's bytes,
    which would be a fabricated finding with a genuine signature over it."""
    stale = json.dumps({"vulnerabilities": [{"msg": "/stale/: from a previous run", "url": "/stale/"}]})
    build = ex._BUILDERS[tool]({}, PINNED)
    with open(build.report_path, "w", encoding="utf-8") as fh:
        fh.write(stale)
    runner = FakeRun(stdout="the tool crashed", report=None)   # writes no report this time
    res = run_exec(tool, {"url": "http://127.0.0.1:8080/app"}, run=runner)
    assert res.ran is True
    assert res.stdout == "", "a stale artifact must never be read back as this run's output"
    assert "no machine-readable report" in res.stderr
    assert "stale" not in res.stdout


def test_a_failure_to_read_the_report_is_never_reported_as_a_denied_spawn(monkeypatch):
    """The absorption happens AFTER the subprocess ran, so a read failure must degrade to an honest
    "ran, no report" — never to a deny, which would claim a spawn that did happen did not."""
    def boom(*_a, **_k):
        raise RuntimeError("disk gone")
    monkeypatch.setattr(ex, "_absorb_report", boom)
    runner = FakeRun(stdout="console", report=NIKTO_REPORT)
    res = run_exec("nikto", {"url": "http://127.0.0.1:8080/app"}, run=runner)
    assert res.ran is True and res.outcome == "ran"
    assert res.stdout == "" and "report absorption failed" in res.stderr
    assert runner.calls, "the run really did happen"


@pytest.mark.parametrize("tool", REPORT_TOOLS)
def test_the_signed_record_commits_to_the_report_and_hides_nothing_relevant(tool):
    report, _ = REPORTS[tool]
    res = run_exec(tool, {"url": "http://127.0.0.1:8080/app"}, run=FakeRun(report=report))
    assert res.record is not None and res.signed is True
    assert res.record.stdout_sha256 == hashlib.sha256(report.encode("utf-8")).hexdigest()
    # the redacted argv kept in the record still shows every OPTION the run used (only values may be
    # masked), so the record cannot misdescribe what was executed
    assert [a for a in res.record.argv if a.startswith("-")] == \
           [a for a in res.argv if a.startswith("-")]
    assert {a for a in res.record.argv if a.startswith("-")} == \
           {a for a in ex._BUILDERS[tool]({}, PINNED).argv if a.startswith("-")}


# ==================================================================================================
# 5b. ffuf — the fourth report-file builder, and the one whose bound is load-bearing
# ==================================================================================================
#
# ffuf was already registered and already ran; what it lacked was output anything in VIGIL could read
# (its default is the progress table it draws on the console). It now writes the same JSON report the
# other three do. It is tested HERE rather than in the parametrized blocks above because its argument
# shape differs — it is the only one of the four that REQUIRES a caller value (a wordlist) to build at
# all.

FFUF_ARGS = {"url": "http://127.0.0.1:8080/app", "wordlist": __file__}

# Captured VERBATIM from ffuf 2.1.0-dev writing `-of json -o <path>` against a loopback target (one
# result trimmed for width). Two properties are load-bearing and neither is guessed: the discovered
# word is written PLAINLY under `input.FUZZ` (ffuf's `-json` stdout mode base64-encodes it), and a scan
# that matched nothing writes this same object with `"results": []`.
FFUF_REPORT = json.dumps({
    "commandline": "ffuf -u http://127.0.0.1:8080/app/FUZZ -w wl.txt -of json -o out.json",
    "time": "2026-08-13T18:54:18-04:00",
    "results": [{"input": {"FFUFHASH": "3906c2", "FUZZ": "api/users"}, "position": 2, "status": 200,
                 "length": 15, "words": 1, "lines": 1, "content-type": "text/html",
                 "redirectlocation": "", "scraper": {}, "duration": 766489, "resultfile": "",
                 "url": "http://127.0.0.1:8080/app/api/users", "host": "127.0.0.1:8080"}],
    "config": {"url": "http://127.0.0.1:8080/app/FUZZ"},
})
FFUF_CLEAN_REPORT = json.dumps({"commandline": "ffuf", "time": "2026-08-13T18:54:19-04:00",
                                "results": [], "config": {}})


def test_ffuf_argv_is_exactly_the_bounded_json_report_invocation():
    build = ex._BUILDERS["ffuf"]({"wordlist": __file__}, PINNED)
    url = "http://127.0.0.1:8080/app/FUZZ"        # FUZZ appended to the PINNED path, not caller text
    assert build.argv == [
        "ffuf", "-u", url, "-w", __file__,
        "-noninteractive",                        # never blocks on its interactive console
        "-maxtime", "90",                         # in-tool bound — see the test below for why
        "-of", "json", "-o", expected_report("ffuf", url),   # the report parse_ffuf_export reads
    ]
    assert build.report_path == expected_report("ffuf", url)
    assert build.target == url


def test_ffuf_keeps_an_in_tool_bound_because_a_killed_ffuf_writes_no_report_at_all():
    """The reason this bound is not hygiene. ffuf writes its report ONCE, at the end of the job. The
    executor kills an over-running child at its wall clock and ``subprocess.run`` kills with SIGKILL,
    which ffuf cannot catch — measured on ffuf 2.1.0 against a loopback target with a 400k-entry
    wordlist, ``timeout -s KILL 6`` left NO report file (exit 137) and the call returned empty
    machine-readable output with nothing to say the scan had been cut short. The same run under
    ``-maxtime 5`` exited 0 and DID write its report. A wordlist that outlasts ``DEFAULT_TIMEOUT`` is
    the normal case for content discovery, so dropping this bound silently returns nothing for the
    common run — which is exactly the silent no-op the ZAP proxy-port pin also exists to prevent."""
    argv = ex._BUILDERS["ffuf"]({"wordlist": __file__}, PINNED).argv
    assert "-maxtime" in argv, "ffuf lost its in-tool bound; a wall-clock kill then yields no report"
    assert ex._FFUF_MAX_TIME <= ex.DEFAULT_TIMEOUT, "the default bound must fit inside the wall clock"
    assert int(argv[argv.index("-maxtime") + 1]) == ex._FFUF_MAX_TIME


# NB not asserted here, because it is NOT what the shared `_bounded_opt` does: a FLOAT bound
# (`max_time: 1.5`) is truncated by its `int()` coercion to 1 and accepted, rather than refused. That
# is the one input class where "refuse rather than guess" does not hold, it predates ffuf and is shared
# with nikto/wapiti/zaproxy, and its impact is a scan bounded to 1s instead of 1.5s. Writing a test that
# asserted a refusal here would be asserting a fix nobody has made.
@pytest.mark.parametrize("bad", [0, 3601, "soon", True, -1, [90], {"s": 90}, "90s", ""])
def test_ffuf_refuses_a_bound_it_cannot_validate_rather_than_guessing(bad):
    build = ex._BUILDERS["ffuf"]({"wordlist": __file__, "max_time": bad}, PINNED)
    if bad == "":
        # an empty string is "absent" to `_opt`, which means the builder's own default — not a refusal
        assert build is not None and build.argv[build.argv.index("-maxtime") + 1] == str(ex._FFUF_MAX_TIME)
    else:
        assert build is None


def test_ffuf_accepts_a_bound_inside_the_range_and_places_it_as_a_value():
    build = ex._BUILDERS["ffuf"]({"wordlist": __file__, "max_time": 12}, PINNED)
    assert build.argv[build.argv.index("-maxtime") + 1] == "12"


def test_a_caller_value_that_looks_like_a_flag_can_never_become_one_for_ffuf():
    """The same property the three scanners are swept for, for the keys ffuf reads.

    The wordlist keys are exercised ALONE. Passing them alongside a valid ``wordlist`` would prove
    nothing: ``_opt`` returns the first non-empty key it is given, so ``wordlist`` would shadow the
    alias under test and the hostile value would never be looked at.

    The assertion counts tokens rather than testing membership, because the builder's own argv already
    contains ``-o`` — one of the flag-shaped values swept here. "The value never reached the argv" and
    "the argv happens to contain that flag for its own reasons" are different facts, and only the first
    is a defect.

    As it stands ffuf REFUSES every case: a wordlist that is not an existing local file and a bound that
    is not an integer in range are both rejected before any argv exists. That is the stronger of the two
    permitted outcomes, and the loop is still written to accept the weaker one so that a future key which
    takes a free-form value is covered the day it is added rather than the day someone remembers."""
    baseline = ex._BUILDERS["ffuf"]({"wordlist": __file__}, PINNED).argv
    baseline_opts = {a for a in baseline if a.startswith("-")}
    cases = [({key: value}, key, value)
             for key in ("wordlist", "wordlist_path", "wordlist_file") for value in FLAGGY]
    cases += [({"wordlist": __file__, key: value}, key, value)
              for key in ("max_time", "maxtime") for value in FLAGGY]
    for args, key, value in cases:
        build = ex._BUILDERS["ffuf"](args, PINNED)
        if build is None:
            continue                                       # refused — the preferred outcome
        opts = {a for a in build.argv if a.startswith("-")}
        assert opts <= baseline_opts, f"ffuf:{key}={value!r} introduced {opts - baseline_opts}"
        assert build.argv.count(value) <= baseline.count(value), (
            f"ffuf:{key}={value!r} added a token to the argv")
    # MUTATION CONTROL. Everything above passes trivially for a builder that refuses ALL input, so pin
    # that valid arguments still build — the sweep must be measuring a working builder, not a dead one.
    assert baseline and baseline[0] == "ffuf", "the sweep's baseline is not a real ffuf argv"
    assert len(cases) >= 5 * len(FLAGGY), "the sweep stopped covering the keys the builder reads"


def test_the_ffuf_report_becomes_the_calls_machine_readable_stdout():
    runner = FakeRun(stdout=":: Progress: [3/3] :: Job [1/1] ::\nabout [Status: 200]\n",
                     report=FFUF_REPORT)
    res = run_exec("ffuf", FFUF_ARGS, run=runner)
    assert res.ran is True
    assert res.stdout == FFUF_REPORT
    assert "Progress" in res.stderr and "Progress" not in res.stdout
    assert not os.path.exists(report_path_in(runner.calls[0])), "the artifact is consumed"


def test_the_ffuf_report_parses_with_the_real_import_adapter_as_OBSERVATIONS():
    """A discovered path is an OBSERVATION, never a vulnerability — this asserts the engine's own
    reader agrees. It must read the discovery back (so the run is not silent) while grading it as an
    unverified lead, which is what keeps a 200 on /api/users from being reported as a weakness."""
    parsers = pytest.importorskip("framework.v2.imports.parsers",
                                  reason="framework not importable from this env (two-env boundary)")
    res = run_exec("ffuf", FFUF_ARGS, run=FakeRun(report=FFUF_REPORT))
    assert parsers.detect_format(res.stdout) == "ffuf", "the report must be self-describing"
    findings, _source = parsers.parse_export("ffuf", res.stdout)
    assert findings, "the engine read nothing back out of a report holding a discovered path"
    blob = json.dumps([f.model_dump() if hasattr(f, "model_dump") else vars(f) for f in findings])
    assert "api/users" in blob, "the discovered path is what the observation is about"
    for f in findings:
        sev = str(getattr(f, "severity", "")).lower()
        assert "critical" not in sev and "high" not in sev, (
            f"content discovery graded as a vulnerability: {sev}")


def test_a_clean_ffuf_scan_parses_to_nothing_at_all():
    """The negative control's whole basis. ffuf writes `"results": []` for a scan that matched
    nothing — a POSITIVE artifact that proves the tool ran, unlike stdout silence — and the reader
    must turn that into zero observations rather than into an empty-but-present finding."""
    parsers = pytest.importorskip("framework.v2.imports.parsers",
                                  reason="framework not importable from this env (two-env boundary)")
    res = run_exec("ffuf", FFUF_ARGS, run=FakeRun(report=FFUF_CLEAN_REPORT))
    assert res.stdout == FFUF_CLEAN_REPORT, "a clean scan still returns its artifact"
    findings, _ = parsers.parse_export("ffuf", res.stdout)
    assert findings == [], f"a clean ffuf scan produced {len(findings)} finding(s)"


# ==================================================================================================
# 6. registration (and the mirror the gate reads)
# ==================================================================================================


def test_the_three_tools_are_registered_as_typed_builders():
    assert set(ex._BUILDERS) == {"nmap", "nuclei", "httpx", "ffuf", "sqlmap", "hydra",
                                 "nikto", "wapiti", "zaproxy"}
    for tool in REPORT_TOOLS:
        assert callable(ex._BUILDERS[tool])
    # NOTE: framework/v2/tools/profile.py mirrors these keys in _TYPED_BUILDER_TOOLS and a drift-guard
    # test asserts the two sets are equal. That mirror must gain nikto/wapiti/zaproxy for the Tools
    # screen to stop refusing them; this file deliberately does not edit that file.


# Which builders route their machine-readable output through a VIGIL-ALLOCATED report FILE rather than
# stdout. Not the same set as REPORT_TOOLS (the three scanners this file was written for): ``ffuf`` joined
# them when it was given a reader. It is listed HERE, explicitly, rather than derived from the builders —
# derivation would make the assertion tautological, and the point of the assertion is that a builder
# cannot gain or lose a file-write side effect without a human saying so in this list.
#
# WHY FFUF IS ONE OF THEM. ffuf can print JSONL on stdout (`-json`), so the file is a deliberate choice:
# a clean scan writes `"results": []` to the report but emits ZERO BYTES on stdout, and a negative control
# whose silence is byte-identical to "the tool never ran" is not evidence. (`-json` also base64-encodes
# each result's input values, which the report file does not.) See ``_build_ffuf``.
REPORT_FILE_BUILDERS = frozenset(REPORT_TOOLS) | {"ffuf"}


def test_only_the_report_file_builders_declare_a_report_artifact():
    """The stdout-native builders are untouched by the report machinery — no behaviour change for them."""
    for name, builder in ex._BUILDERS.items():
        args = {"nikto": {}, "wapiti": {}, "zaproxy": {},
                "hydra": {"service": "http-get", "username": "u", "password": "p"},
                "ffuf": {"wordlist": __file__}}.get(name, {})
        build = builder(args, PINNED)
        assert isinstance(build, ex._Build), f"{name}: {build!r}"
        assert (build.report_path is not None) is (name in REPORT_FILE_BUILDERS), name


def test_a_report_file_builder_that_cannot_allocate_an_artifact_refuses(monkeypatch):
    """The refusal ``_report_root`` exists for, asserted for EVERY builder that writes one — ffuf
    included. A scanner told to write a report with nowhere private to put it must not run anyway and
    quietly lose its output; it must refuse. (The three scanners' version of this is asserted above; this
    one covers the whole set, so a builder added to it inherits the check.)"""
    monkeypatch.setattr(ex, "_report_root", lambda: None)
    for name in sorted(REPORT_FILE_BUILDERS):
        args = {"ffuf": {"wordlist": __file__}}.get(name, {})
        assert ex._BUILDERS[name](args, PINNED) is None, name
