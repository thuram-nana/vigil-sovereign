"""W11-2: the live-fire tool preflight fails closed on a missing required tool.

``tools/livefire/require_tools.py`` is what makes the scheduled live-fire jobs refuse to report success
when a required binary is absent. The path it replaces TOLERATED that: ``livefire-full`` set
``VIGIL_LIVEFIRE_ALLOW_MISSING`` and the exposed-secret live-fire SKIPPED cleanly when ``gh`` was gone —
a green run that measured nothing. This proves, in a REQUIRED job, that a missing required tool is
REJECTED (non-zero exit) and a present one is accepted.

THE NEGATIVE CONTROL IS THE WHOLE POINT. ``test_negative_control_*`` feeds the pure core a
deliberately-absent binary in the SAME run and asserts it is reported as absent — so the raise in the
fail-closed test is caused by the tool being gone, not by the gate always raising. Remove a required
tool and the gate goes red; that is the property the scheduled jobs depend on.

Stdlib only: it loads the harness by path (``tools/`` is not on the test path) and imports no trust
domain, so it runs in the sovereign leg of the required 'integration two-env boundary (P5)' job.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_HARNESS = _REPO / "tools" / "livefire" / "require_tools.py"

# A name no real system ships, used as the deliberately-absent required tool throughout.
_ABSENT = "vigil-livefire-absent-tool-zzz-9f3c2a17"


def _load():
    assert _HARNESS.is_file(), f"the preflight harness is missing: {_HARNESS}"
    spec = importlib.util.spec_from_file_location("vigil_livefire_require_tools", _HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_present_required_tool_is_accepted():
    mod = _load()
    # python3 is guaranteed present wherever these tests run — it is running them.
    assert mod.require_tools(["python3"]) is True


def test_missing_required_tool_fails_closed():
    """The gate must RAISE (non-zero exit), not return, when a required tool is absent."""
    mod = _load()
    with pytest.raises(SystemExit) as exc:
        mod.require_tools(["python3", _ABSENT])
    # SystemExit carrying a message => truthy code => a NON-ZERO process exit.
    assert exc.value.code not in (0, None), "a missing required tool must exit NON-ZERO"


def test_negative_control_absent_tool_is_named_not_swallowed():
    """The gate is not a no-op: the pure core reports EXACTLY the absent tool, and only it — and reports
    nothing when every tool is present, so the fail-closed raise above is caused by the tool, not a bug."""
    mod = _load()
    assert mod.missing_tools(["python3", _ABSENT]) == [_ABSENT]
    assert mod.missing_tools(["python3"]) == []


def test_allow_missing_downgrades_only_the_named_tool():
    """Acknowledging one optional tool must NOT excuse a different missing required tool."""
    mod = _load()
    other = _ABSENT + "-other"
    assert mod.missing_tools([_ABSENT, other], allow_missing=[_ABSENT]) == [other]
    # an acknowledged-only run passes the gate
    assert mod.require_tools([_ABSENT], allow_missing=[_ABSENT]) is True


def test_cli_exits_nonzero_and_annotates_on_missing_tool(capsys):
    """The CLI the workflows call is fail-closed too, and prints a GitHub ::error:: annotation naming it."""
    mod = _load()
    with pytest.raises(SystemExit) as exc:
        mod.main(["python3", _ABSENT])
    assert exc.value.code not in (0, None)
    err = capsys.readouterr().err
    assert "::error::" in err and _ABSENT in err


def test_cli_succeeds_when_all_present(capsys):
    mod = _load()
    assert mod.main(["python3"]) == 0
    assert "preflight OK" in capsys.readouterr().out


def test_the_gate_is_actually_wired_into_scripts_and_scheduled_jobs():
    """The gate is not just a library. Each of the three previously-unreferenced live-fire scripts calls
    the preflight, and each is driven by a scheduled job that also runs it — so a missing required tool
    turns that JOB red, not merely a hypothetical harness call. This is what makes the claim's 'guards
    the scheduled live-fire jobs' true of the code."""
    scripts = ("range.sh", "k8s_rbac_livefire.sh", "secret_github_livefire.sh")
    for script in scripts:
        text = (_REPO / "tools" / "livefire" / script).read_text(encoding="utf-8")
        assert "require_tools.py" in text, f"{script} does not call the fail-closed preflight"

    wf = (_REPO / ".github" / "workflows" / "livefire.yml").read_text(encoding="utf-8")
    for script in scripts:
        assert f"tools/livefire/{script}" in wf, f"{script} is still referenced by no workflow"
    # one preflight per scheduled job (range / k8s / secret-github), at minimum.
    assert wf.count("require_tools.py") >= 3, \
        "each scheduled live-fire job must run the fail-closed preflight before the script"
