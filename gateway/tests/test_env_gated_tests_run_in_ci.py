"""Guard (W1-4 #413): no test is gated on an environment variable that NO workflow sets.

WHY THIS TEST EXISTS. `test_docker_bringup.py::test_real_docker_build_and_fail_closed` was gated on
`VIGIL_GATEWAY_DOCKER_IT=1`, a variable set NOWHERE — so the container that carries the egress gate had
no executed bring-up proof, and the dashboard showed the same colour whether the proof passed or never
ran. "A skipped proof and a passing proof are the same colour on a dashboard." This guard makes that
whole class loud: every environment variable a test's `skipif` consults must EITHER be set by a CI
workflow (so the test actually runs) OR be a documented `_CANNOT_RUN_ON_HOSTED_CI` exemption — a LOUD,
reasoned skip for a proof that genuinely cannot run on a GitHub-hosted runner (a live network target,
a real systemd/init, or a heavy container image build), never a silent green.

STDLIB ONLY (`re`, `pathlib`), so it rides the REQUIRED `gateway egress gate (P6)` job (which runs
`pytest gateway/tests`) and imports no trust domain. It reads files only — the workflows and the test
tree — so it also runs unchanged under the cross-version `python-compat` matrix (W1-7 #416).

Every assertion is paired with a NEGATIVE CONTROL that perturbs the pure predicate in-process, so a
green is evidence the gate bites rather than a vacuous pass.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"

# Trees that are not this repo's own shipped tests: vendored third parties and build/venv dirs.
_EXCLUDE_DIRS = {"vendor", "node_modules", ".git", ".venv-sovereign", ".venv-offense", ".venv"}

# An env var read: `os.environ.get("X")`, `os.getenv("X")`, or `os.environ["X"]`.
_ENV_REF = re.compile(r"(?:os\.environ(?:\.get)?|os\.getenv)\s*[(\[]\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")

# Documented exemptions: env vars whose gated tests genuinely CANNOT run on a GitHub-hosted CI runner,
# so they stay opt-in for an operator with the right environment. Each is a LOUD, documented skip
# (visible with `-rs`/`-rA`) — never a silent green — with a real, specific reason. This is the "if a job
# genuinely cannot get X, make the skip loud + documented, never a silent green" branch of W1-4 (#413).
_CANNOT_RUN_ON_HOSTED_CI: dict[str, str] = {
    "VIGIL_LIVE_SYSTEMD": (
        "Exercises `vigil up` / `vigil down` as REAL systemd units — unit install, service start/stop, "
        "a live init and root. GitHub-hosted runners do not provide a usable systemd session for that, so "
        "these tests are opt-in for an operator on real hardware."
    ),
    "VIGIL_STRIX_SBOM_DOCKER_IT": (
        "Introspects the LIVE Strix sandbox container image (`vigil/strix-sandbox:local`, ~1000 Debian "
        "packages built from vendor/strix/containers/Dockerfile). Building/pulling that image is far too "
        "heavy and registry-dependent for a hermetic PR runner; the committed SBOM is proven offline by "
        "the rest of the same file, and the live introspection stays opt-in for an operator with docker."
    ),
    "CRUCIBLE_LIVE_FULL_PIPELINE": (
        "Runs the offense engine's full URL→report pipeline against a LIVE target — real network egress to "
        "an authorised host. The hermetic CI runners forbid egress by design (see the loopback/livefire "
        "jobs), so this stays opt-in for an operator who supplies an authorised target."
    ),
    "CRUCIBLE_LIVE_HTTP": (
        "Drives the full pipeline over LIVE HTTP against an operator-authorised URL (real network egress). "
        "It cannot run on a hermetic, egress-free PR runner and is opt-in for an authorised operator."
    ),
    "CRUCIBLE_LIVE_INTAKE_URL": (
        "Runs intake against a LIVE, operator-authorised URL (real network egress). It cannot run on a "
        "hermetic, egress-free PR runner and is opt-in for an authorised operator."
    ),
}


def _skipif_arg_spans(text: str):
    """The argument text of every `skipif(...)` call, via balanced-paren matching from each `skipif(`. The
    reason strings in this repo carry only balanced parens, and every env read sits in the CONDITION
    (before the reason=), so the condition is always captured intact."""
    for m in re.finditer(r"\bskipif\(", text):
        depth, j = 1, m.end()
        while j < len(text) and depth:
            ch = text[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            j += 1
        yield text[m.end():j - 1]


def _scan_env_gates(text: str) -> set[str]:
    """Every env var name referenced inside a `skipif(...)` call, in ANY position — including
    `not os.environ.get("X")` and `os.environ["X"]`. A runtime-probe skipif with no environ read (e.g.
    `skipif(not _docker_usable(), …)`) contributes nothing: it degrades gracefully on its own."""
    out: set[str] = set()
    for arg in _skipif_arg_spans(text):
        out.update(_ENV_REF.findall(arg))
    return out


def _test_files() -> list[Path]:
    out: list[Path] = []
    for p in REPO.rglob("test_*.py"):
        if _EXCLUDE_DIRS & set(p.relative_to(REPO).parts):
            continue
        if p.name == Path(__file__).name:
            continue  # this guard carries illustrative skipif strings in its own negative controls
        out.append(p)
    return out


def _env_var_skip_gates() -> dict[str, list[str]]:
    """{env var: [repo-relative test files that gate on it]} across the whole shipped test tree."""
    gates: dict[str, list[str]] = {}
    for p in _test_files():
        for var in _scan_env_gates(p.read_text(encoding="utf-8", errors="replace")):
            gates.setdefault(var, []).append(p.relative_to(REPO).as_posix())
    return gates


def _workflow_texts() -> list[str]:
    return [p.read_text(encoding="utf-8")
            for ext in ("*.yml", "*.yaml") for p in sorted(WORKFLOWS.glob(ext))]


def _workflow_assigns(var: str, wf_texts: list[str]) -> bool:
    """True IFF some workflow SETS `var` — as an env-mapping key (`VAR: value`) or inline in a run step
    (`VAR=value`). The fully-anchored name means a sibling like VIGIL_GATEWAY_DOCKER_BASE never satisfies
    a query for VIGIL_GATEWAY_DOCKER_IT."""
    pat = re.compile(rf"(?m)(^\s*{re.escape(var)}\s*:\s|\b{re.escape(var)}=)")
    return any(pat.search(t) for t in wf_texts)


def _env_gates_without_a_setter(gates: set[str], wf_texts: list[str], exempt: set[str]) -> set[str]:
    """The offending env vars: a test gates on them, NO workflow sets them, and they are NOT a documented
    cannot-run-on-hosted-CI exemption. A non-empty result is the silent-skip class W1-4 makes loud."""
    return {v for v in gates if not _workflow_assigns(v, wf_texts) and v not in exempt}


# --------------------------------------------------------------------------------------------------
# Positive guards.
# --------------------------------------------------------------------------------------------------
def test_detector_finds_the_known_env_gates() -> None:
    """Anti-vacuous: the scanner really discovers the env-var skip gates (both the `!= "1"` and the
    `not os.environ.get(...)` forms), so the guard below checks a real set and never passes over an empty
    one."""
    gates = _env_var_skip_gates()
    for expected in ("VIGIL_GATEWAY_DOCKER_IT", "VIGIL_LIVE_SYSTEMD", "CRUCIBLE_LIVE_HTTP"):
        assert expected in gates, (
            f"scanner missed the {expected} skip gate — it is broken. Found: {sorted(gates)}"
        )


def test_no_test_is_gated_on_an_env_var_no_workflow_sets() -> None:
    """Every env var a test's `skipif` gates on is EITHER set by a CI workflow (so the test runs) OR a
    documented cannot-run-on-hosted-CI exemption. Neither ⇒ the test is silently disabled forever — the
    exact class that hid the gateway bring-up proof (W1-4 #413). FAILS on the pre-fix tree, where nothing
    set VIGIL_GATEWAY_DOCKER_IT."""
    all_gates = _env_var_skip_gates()
    offenders = _env_gates_without_a_setter(set(all_gates), _workflow_texts(), set(_CANNOT_RUN_ON_HOSTED_CI))
    detail = {v: all_gates[v] for v in offenders}
    assert not offenders, (
        "these env vars gate a test's skipif but NO workflow sets them and they are not a documented "
        f"cannot-run-on-hosted-CI exemption, so the tests never run in CI (a silent green): {detail}. "
        "Set the var in a CI job, or add it to _CANNOT_RUN_ON_HOSTED_CI with a real reason."
    )


def test_the_gateway_bringup_gate_is_set_by_a_workflow() -> None:
    """The specific W1-4 fix: the bring-up IT's gate is SET by a CI workflow (so it executes), not merely
    exempted away."""
    assert _workflow_assigns("VIGIL_GATEWAY_DOCKER_IT", _workflow_texts()), (
        "no workflow sets VIGIL_GATEWAY_DOCKER_IT — the gateway container bring-up test would never run"
    )
    assert "VIGIL_GATEWAY_DOCKER_IT" not in _CANNOT_RUN_ON_HOSTED_CI, (
        "the bring-up gate must be RUN in CI, not parked in the cannot-run exemption ledger"
    )


def test_cannot_run_exemptions_are_real_and_still_needed() -> None:
    """Each documented exemption has a substantive reason, is actually still gated by some test (a stale
    exemption is drift), and is NOT set by any workflow — if it were, it should RUN, not sit here."""
    gates = _env_var_skip_gates()
    wf = _workflow_texts()
    for var, reason in _CANNOT_RUN_ON_HOSTED_CI.items():
        assert len(reason.strip()) >= 40, f"exemption reason for {var!r} is too thin: {reason!r}"
        assert var in gates, f"{var!r} is exempted but no test gates on it — stale exemption"
        assert not _workflow_assigns(var, wf), (
            f"{var!r} IS set by a workflow, so it should RUN — remove it from the cannot-run ledger"
        )


# --------------------------------------------------------------------------------------------------
# Negative controls — the pure predicate must REPORT the silent-skip class, and clear when it is fixed.
# --------------------------------------------------------------------------------------------------
def test_env_gate_guard_is_not_vacuous_negative_control() -> None:
    """NEGATIVE CONTROL. The guard FIRES when a gated var is set by no workflow and unexempted (not a
    no-op), and CLEARS when a workflow sets it or it is documented-exempt (not always-red). The scanner
    catches every env skipif form and ignores a runtime-probe skipif and a plain test."""
    # (a) unset + unexempted → flagged (the exact bug: the var set NOWHERE)
    assert _env_gates_without_a_setter({"VIGIL_GATEWAY_DOCKER_IT"}, [""], set()) == {"VIGIL_GATEWAY_DOCKER_IT"}
    # (b) a workflow that SETS it clears the flag — env-mapping and inline `run:` forms both count
    assert _env_gates_without_a_setter({"X"}, ['    env:\n      X: "1"\n'], set()) == set()
    assert _env_gates_without_a_setter({"X"}, ["        run: X=1 python -m pytest\n"], set()) == set()
    # (c) a documented exemption clears it (the cannot-run-on-hosted-CI branch)
    assert _env_gates_without_a_setter({"X"}, [""], {"X"}) == set()
    # scanner: every env skipif form is caught; runtime-probe skipif and a plain test are not
    assert _scan_env_gates('@pytest.mark.skipif(os.environ.get("AAA") != "1", reason="x")\ndef t(): ...\n') == {"AAA"}
    assert _scan_env_gates('@pytest.mark.skipif(not os.environ.get("BBB"), reason="x")\ndef t(): ...\n') == {"BBB"}
    assert _scan_env_gates('@pytest.mark.skipif(os.environ["CCC"] != "1", reason="x")\ndef t(): ...\n') == {"CCC"}
    assert _scan_env_gates('@pytest.mark.skipif(not _docker_usable(), reason="x")\ndef t(): ...\n') == set()
    assert _scan_env_gates("def test_plain():\n    pass\n") == set()
    # anchored name: a sibling var sharing a prefix does not satisfy the query
    assert not _workflow_assigns(
        "VIGIL_GATEWAY_DOCKER_IT", ['      VIGIL_GATEWAY_DOCKER_BASE: "python:3.13-slim"\n']
    )
