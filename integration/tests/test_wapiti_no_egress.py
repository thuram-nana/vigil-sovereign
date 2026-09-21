"""The wapiti driver must never reach a host outside the pinned target.

THE DEFECT THIS PINS, observed live rather than theorised. With no module list supplied, the builder
ran wapiti's DEFAULT module set, which includes `ssrf` — and that module asks an external endpoint of
the tool author's choosing for out-of-band results:

    [*] Launching module ssrf
    [*] Asking endpoint URL https://wapiti3.ovh/get_ssrf.php?session_id=... for results, please wait...

That host was reachable on 443 from the machine running the scan. It breaks the charter's hard limit
— "no external egress; no tool, no DNS, no callback may leave the host" — and neither existing guard
covers it: the scope pin constrains the TARGET, while this is the tool contacting a host of its own
choosing, and `--no-bugreport` is an unrelated path.

WHY A REFUSAL AND NOT A WARNING. The no-egress limit belongs to the charter, not to the caller, so an
explicitly-named out-of-band module is refused too. A caller cannot opt into leaving the host.

These tests are pure argv construction: no tool is executed and no packet is sent.
"""

from __future__ import annotations

import pytest

ex = pytest.importorskip("vigil_integration.live.executor")

PINNED = ex._Pinned(host="127.0.0.1", port=8080, scheme="http", path="/app", query="",
                    raw_host="127.0.0.1")


def _modules_of(argv: list[str]) -> str:
    """The value passed to wapiti's module flag, or "" when none is present."""
    return argv[argv.index("-m") + 1] if "-m" in argv else ""


def test_the_default_scan_declares_its_modules_instead_of_inheriting_wapitis():
    """The whole defect was an INHERITED default. If the builder ever stops naming modules, wapiti
    silently reverts to a set that egresses — and nothing in the argv would show it."""
    argv = ex._BUILDERS["wapiti"]({}, PINNED).argv
    assert "-m" in argv, "no module list: wapiti falls back to its own defaults, which egress"
    assert _modules_of(argv), "an empty module list is the same as inheriting the defaults"


def test_no_out_of_band_module_is_in_the_default_set():
    """MUTATION CONTROL for the test above: naming *some* modules is not enough — it has to be a set
    that cannot reach off-host. This fails if a future edit adds one back for coverage."""
    modules = {m.strip().lower() for m in _modules_of(ex._BUILDERS["wapiti"]({}, PINNED).argv).split(",")}
    leaked = modules & ex._WAPITI_EGRESSING_MODULES
    assert not leaked, f"default module set reaches a third-party collaborator: {sorted(leaked)}"


@pytest.mark.parametrize("spec", ["ssrf", "xss,ssrf", "SSRF", " ssrf , sql ", "log4shell",
                                  "sql,log4shell", "wapp", "xss,wapp"])
def test_an_explicitly_named_out_of_band_module_is_refused(spec):
    """The charter's no-egress limit is not the caller's to waive, so an explicit request is refused
    rather than honoured or quietly dropped. Case and spacing must not defeat it.

    `wapp` is here because it egresses by a DIFFERENT mechanism from the other two: it needs no
    out-of-band collaborator at all, it looks for a local technology database, finds none under the
    directory this builder pins, and downloads one. Blocking the callback class alone missed it."""
    assert ex._BUILDERS["wapiti"]({"modules": spec}, PINNED) is None, \
        f"an out-of-band module was accepted via {spec!r} — this reaches a host the operator never authorised"


@pytest.mark.parametrize("preset", ["all", "common", "passive", "xss,all", "ALL", " all ", "sql,common"])
def test_a_preset_group_name_is_refused(preset):
    """THE BYPASS THAT MADE A BLOCKLIST UNSOUND, and the reason the guard is an allowlist.

    wapiti's `-m` is not a list of module names — it is a small language that also accepts PRESET
    GROUP names, which wapiti expands itself. Measured against the installed wapiti 3.2.10:
    `all` resolves to 36 modules including ssrf, log4shell and wapp; `common` to 16 including ssrf.

    Both are ordinary tokens, so they passed the plain-CSV check and intersected with no blocked
    name. A caller could re-open the charter's no-egress limit with three letters, while the test
    above — which only ever tried literal module names — went on passing.

    This is the mutation control for the allowlist: revert the guard to a name blocklist and this
    fails while everything else stays green."""
    assert ex._BUILDERS["wapiti"]({"modules": preset}, PINNED) is None, \
        f"preset {preset!r} was accepted — wapiti expands it into modules that leave the host"


def test_an_unknown_or_future_module_is_refused():
    """The allowlist's other half: a module this engine has never assessed is refused rather than
    passed through. A future wapiti release adding an off-host module must not widen the guard by
    simply existing."""
    assert ex._BUILDERS["wapiti"]({"modules": "some_future_module"}, PINNED) is None
    assert ex._BUILDERS["wapiti"]({"modules": "xss,some_future_module"}, PINNED) is None


@pytest.mark.parametrize("spec", ["xss", "sql,xss", "exec,file,redirect"])
def test_a_safe_explicit_module_list_still_works(spec):
    """MUTATION CONTROL for the refusal: a blanket "reject every module list" would pass the test
    above while removing a legitimate capability. The refusal must be specific to out-of-band modules."""
    build = ex._BUILDERS["wapiti"]({"modules": spec}, PINNED)
    assert build is not None, f"a safe module list was refused: {spec!r}"
    assert _modules_of(build.argv) == spec


def test_the_target_still_comes_from_the_pin():
    """Regression guard: the module change must not have disturbed how the target is derived. The URL
    in the argv comes from the validated pin, never from caller text."""
    build = ex._BUILDERS["wapiti"]({"modules": "xss", "url": "http://127.0.0.1@evil.example/x"}, PINNED)
    assert build is not None
    assert not any("evil.example" in str(a) for a in build.argv)


# ---------------------------------------------------------------------------------------------------
# nuclei's builder route — the third tool whose startup update check egresses, pinned here so the
# no-egress guarantee covers every route into the engine.
# ---------------------------------------------------------------------------------------------------

def test_the_nuclei_builder_suppresses_its_startup_update_check():
    """nuclei phones ProjectDiscovery's update host on startup by default. The builder already passes
    `-disable-update-check`, but nothing pinned it — so it could be dropped and the charter's
    no-egress limit silently re-opened, invisibly, because it is the tool's own default rather than
    anything the argv asked for. (The sensor's two routes are pinned alongside their own tests.)

    `-no-interactsh` is pinned for the SAME invisible-default-egress reason, one layer down: nuclei's
    OAST/interactsh templates register with a public interaction server (oast.pro) by default to catch
    blind/out-of-band findings, opening an outbound connection `-disable-update-check` does not cover.
    In the nightly full-table job the egress guard logs that connection as BLOCKED and the assert step
    fails on it — but the defect is the connection itself, and dropping the flag would re-open it."""
    argv = ex._BUILDERS["nuclei"]({}, PINNED).argv
    assert "-disable-update-check" in argv, "nuclei builder would contact an outside host on every run"
    assert "-no-interactsh" in argv, "nuclei builder would register with oast.pro (OAST) on every run"
