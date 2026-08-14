"""A typed builder must reach the tool it was WRITTEN for — not a program that shares its name.

IT HAPPENED TWICE, SO THIS FILE NOW GUARDS THE CLASS AND NOT THE CASE. The httpx defect is written out
below; ``_build_zaproxy`` then repeated it exactly, emitting a bare ``zaproxy`` while the registry
declares — and resolves — ``zap.sh``/``zap-cli`` for the same tool. A host carrying only ZAP's own
upstream ``zap.sh`` was therefore told ZAP was installed and controllable while every run of it failed
to spawn. The first fix and the first version of this guard were both httpx-shaped, which is exactly
why neither could see the second occurrence one builder away. The guard at the bottom is now DERIVED
FROM THE REGISTRY FOR EVERY TOOL IN ``_BUILDERS``: it fails for any builder whose resolution disagrees
with what the registry declares — one that exists today, or one added tomorrow.

THE ORIGINAL DEFECT. ``_build_httpx`` emitted ``argv[0] = "httpx"``. On Kali — the platform this
framework itself runs on — ``/usr/bin/httpx`` is the PYTHON HTTP CLIENT's CLI, an unrelated program,
and ProjectDiscovery's httpx installs as ``/usr/bin/httpx-toolkit`` precisely because of that
collision. So the builder could never reach its tool on a stock box: it spawned a program that prints
"The httpx command line client could not run…" and exits, or nothing at all. Every other token of the
argv had been verified correct against the real binary, which is what makes this class of defect
dangerous — the command line looks right, and the engine simply sees nothing.

WHAT MAY NOT BE DONE ABOUT IT. Silently executing a differently-named binary is a supply-chain
decision the operator must make explicitly, so there is no implicit fallback. What is honoured instead
is the operator's OWN declaration: ``framework/v2/tools/registry.py`` already lists ``httpx-toolkit``
as an ``alt_binaries`` entry for httpx, and lists the version-banner substrings that identify an
impostor — curated, reviewed metadata that drives the installer and the operator's tools screen. The
executor cannot import it across the two-env boundary, so it MIRRORS it; the drift guard at the bottom
of this file is what keeps the mirror honest.

The three behaviours that matter, each tested against a PINNED path rather than against the box:
it picks the real tool when both names exist, it never picks the impostor, and it refuses — naming
both names — when neither is installed.
"""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_integration.agent.state import Phase
from vigil_integration.live import executor as ex
from vigil_integration.live.executor import execute

PLAIN = "/usr/bin/httpx"             # the name ProjectDiscovery's tool WANTS, and Kali's Python client owns
TOOLKIT = "/usr/bin/httpx-toolkit"   # the name Kali's package installs the real tool under
PD_BANNER = "projectdiscovery.io\n\n[INF] Current Version: v1.9.0\n"
# What the Python HTTP client's CLI actually printed for `-version` on the box this was written on.
PY_BANNER = ("The httpx command line client could not run because the required dependencies were not "
             "installed.\nMake sure you've installed everything with: pip install 'httpx[cli]'\n")

PINNED = ex._Pinned(host="127.0.0.1", port=18080, scheme="http", path="/app", query="x=1",
                    raw_host="127.0.0.1")

#: The least a builder needs to produce an argv at all, for the tools that require an option. Used only
#: by the whole-roster guards, which must be able to build EVERY tool to check its argv[0].
MINIMAL_ARGS: dict[str, dict] = {
    "ffuf": {"wordlist": __file__},
    "hydra": {"service": "http-get", "username": "u", "password": "p"},
}


@pytest.fixture(autouse=True)
def _isolated_report_root(tmp_path):
    """The report-file builders (ffuf/nikto/wapiti/zaproxy) allocate a 0700 artifact directory under
    ``tempfile.gettempdir()``; point that at a per-test directory so building one here neither reads nor
    litters the real one. Uses its OWN MonkeyPatch rather than the test's, because one test deliberately
    calls ``monkeypatch.undo()`` to get the real ``_which`` back and must not undo this too."""
    mp = pytest.MonkeyPatch()
    mp.setattr(tempfile, "tempdir", str(tmp_path))
    yield
    mp.undo()


def pin_path(monkeypatch, world: dict[str, tuple[str, str]]):
    """Pin the box: ``{declared name: (absolute path, version banner)}``. A name absent from ``world``
    is not on PATH. BOTH seams are pinned together — pinning only ``_which`` would leave the banner
    probe reading the real machine, which is how a test starts depending on the box again."""
    by_path = {path: banner for path, banner in world.values()}
    monkeypatch.setattr(ex, "_which", lambda name: world.get(name, (None, ""))[0])
    monkeypatch.setattr(ex, "_version_banner", lambda path, args: by_path.get(path, ""))


def build(monkeypatch, world):
    pin_path(monkeypatch, world)
    return ex._BUILDERS["httpx"]({}, PINNED)


# ===================================================================================================
# resolution: the real tool, never the impostor, an honest refusal when neither is installed
# ===================================================================================================


def test_the_real_tool_is_found_under_its_alternate_name_when_the_impostor_owns_the_plain_one(monkeypatch):
    """The Kali reality: `httpx` is the Python client, `httpx-toolkit` is the tool we mean."""
    b = build(monkeypatch, {"httpx": (PLAIN, PY_BANNER), "httpx-toolkit": (TOOLKIT, PD_BANNER)})
    assert isinstance(b, ex._Build)
    assert b.argv[0] == TOOLKIT, "the declared alternate name is what makes the tool reachable at all"
    assert PLAIN not in b.argv


def test_the_plain_name_is_used_when_it_really_is_the_tool(monkeypatch):
    """On a box where ProjectDiscovery's httpx owns the plain name, nothing is stepped over: the
    resolution honours the DECLARED ORDER, primary name first."""
    b = build(monkeypatch, {"httpx": (PLAIN, PD_BANNER), "httpx-toolkit": (TOOLKIT, PD_BANNER)})
    assert b.argv[0] == PLAIN, "a real tool on the primary name must not be skipped for an alternate"


def test_the_impostor_is_never_selected_even_when_it_is_the_only_thing_on_path(monkeypatch):
    """The refusal that matters. A same-named DIFFERENT program is not a fallback — the builder refuses
    rather than hand the engine the output of a tool nobody asked for."""
    out = build(monkeypatch, {"httpx": (PLAIN, PY_BANNER)})
    assert not isinstance(out, ex._Build), "the impostor must never produce an argv"
    assert "httpx-toolkit" in out, "the refusal must name the binary the operator should install"


def test_neither_name_present_refuses_with_a_reason_naming_both(monkeypatch):
    out = build(monkeypatch, {})
    assert isinstance(out, str), "a missing tool is a REFUSAL, not an argv that will fail to spawn"
    assert "httpx" in out and "httpx-toolkit" in out, f"the reason must name both names: {out!r}"
    assert "apt-get install -y httpx-toolkit" in out, "an honest refusal says how to fix it"


def test_an_alternate_that_is_also_an_impostor_still_refuses(monkeypatch):
    """Two declared names, both squatted. Nothing usable exists, so nothing runs."""
    out = build(monkeypatch, {"httpx": (PLAIN, PY_BANNER), "httpx-toolkit": (TOOLKIT, PY_BANNER)})
    assert isinstance(out, str) and "different tool" in out.lower()


def test_an_unidentifiable_banner_is_trusted_exactly_as_the_registry_trusts_it(monkeypatch):
    """A candidate whose version probe produced NOTHING cannot be disambiguated. The registry's
    documented default is to trust PATH there (no known impostor is silent, and the real tool prints a
    version), and the executor must resolve identically: a resolver that diverged from the one the
    operator's tools screen reports would put a different binary on the wire than the screen claims —
    the very defect class this work exists to remove."""
    b = build(monkeypatch, {"httpx": (PLAIN, "")})
    assert isinstance(b, ex._Build) and b.argv[0] == PLAIN


def test_a_broken_path_lookup_degrades_to_a_refusal_not_a_crash(monkeypatch):
    """Totality. ``_which`` is the one place that touches the environment; a hostile/broken PATH must
    read as "not found" (a refusal), never as an exception out of a builder."""
    monkeypatch.undo()                      # drop the suite's PATH pin — this test wants the REAL _which

    def _boom(_name):
        raise OSError("PATH is not a string")

    monkeypatch.setattr(ex.shutil, "which", _boom)
    assert ex._which("httpx") is None
    out = ex._BUILDERS["httpx"]({}, PINNED)
    assert isinstance(out, str) and "not on PATH" in out


# ===================================================================================================
# what the engine actually runs, and what the signed record says it ran
# ===================================================================================================


def _gate(tool_name, target, destructive):
    return SimpleNamespace(outcome="allow", allowed=True, reason="ok")


def _signer(data: bytes) -> str:
    import hashlib
    return "sig-" + hashlib.sha256(data).hexdigest()[:24]


class _FakeRun:
    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, timeout, output_cap):
        self.calls.append(list(argv))
        return ex.RunOutcome(exit_code=0, stdout='{"url":"http://127.0.0.1:18080/"}', stderr="")


def _exec(monkeypatch, world):
    pin_path(monkeypatch, world)
    runner = _FakeRun()
    res = execute("httpx", {"url": "http://127.0.0.1:18080/app"}, Phase.INFORMATIONAL,
                  gate=_gate, view={"httpx": [p.value for p in Phase]},
                  destructive_view={"httpx": False}, run=runner, signer=_signer, seq=1, now=7)
    return res, runner


def test_the_signed_record_shows_which_binary_actually_ran(monkeypatch):
    """After the fact the record must answer "what ran?" — the whole point of resolving. A bare
    ``httpx`` in the record cannot distinguish the tool from the impostor."""
    res, runner = _exec(monkeypatch, {"httpx-toolkit": (TOOLKIT, PD_BANNER)})
    assert res.ran is True and runner.calls[0][0] == TOOLKIT
    assert res.record.argv[0] == TOOLKIT, "the redacted spine argv must keep the resolved path"
    assert TOOLKIT.encode() in res.record.signing_bytes(), "the signature must commit to what ran"


def test_a_missing_tool_denies_the_call_and_spawns_nothing(monkeypatch):
    """The refusal reaches the operator as a DENY carrying the builder's own reason — not as a spawn
    that fails, and not as the generic "unsafe/smuggled host or a missing required option" sentence,
    which would send them hunting for a bug in their arguments."""
    res, runner = _exec(monkeypatch, {})
    assert res.ran is False and res.outcome == "deny"
    assert not runner.calls, "nothing may be spawned when no declared binary exists"
    assert res.record is None
    assert "httpx-toolkit" in res.reason and "not on PATH" in res.reason, res.reason


def test_the_impostor_denies_the_call_and_spawns_nothing(monkeypatch):
    res, runner = _exec(monkeypatch, {"httpx": (PLAIN, PY_BANNER)})
    assert res.ran is False and res.outcome == "deny" and not runner.calls
    assert PLAIN not in str(runner.calls)


def test_the_argv_still_asks_for_machine_readable_output(monkeypatch):
    """Resolution must not have cost the thing that makes a run READABLE. httpx's ``-json`` writes JSONL
    (one JSON object per probed URL) on stdout — the stream ``_execute`` hashes into the record and hands
    to the reader — and ``-silent`` keeps its banner off that stream."""
    b = build(monkeypatch, {"httpx-toolkit": (TOOLKIT, PD_BANNER)})
    assert "-json" in b.argv and "-silent" in b.argv
    # `-probe` is part of being readable in the NEGATIVE direction: without it a host with nothing
    # listening yields zero bytes, which is byte-identical to the tool never having run, and a silence
    # that cannot be told apart from a dead tool is not evidence of anything.
    assert "-probe" in b.argv
    assert b.argv[b.argv.index("-u") + 1] == "http://127.0.0.1:18080/app?x=1"


def test_resolution_cannot_change_the_pinned_target(monkeypatch):
    """argv[0] is the ONLY thing resolution may decide. The host in the URL still comes from the
    validated pin, so a resolved binary is not a route to a different target."""
    b = build(monkeypatch, {"httpx-toolkit": (TOOLKIT, PD_BANNER)})
    assert b.target == "http://127.0.0.1:18080/app?x=1"
    # The `-H User-Agent: …` pair is in this set because httpx's own `-random-agent` DEFAULTS TRUE:
    # without an explicit header every probe goes out under a randomly-chosen browser identity, which
    # is the opposite of the correlatability an authorised owner-test owes the operator.
    assert all(tok in (TOOLKIT, "-u", "http://127.0.0.1:18080/app?x=1", "-silent", "-no-color",
                       "-disable-update-check", "-H",
                       f"User-Agent: {ex._CORRELATABLE_USER_AGENT}",
                       "-json", "-probe") for tok in b.argv), b.argv


def test_the_probe_identifies_itself_rather_than_impersonating_a_browser(monkeypatch):
    """CONSTITUTION §VI.4 — "make yourself correlatable … you are not evading them".

    httpx ships `-random-agent` defaulting to TRUE, so a builder that says nothing about the header
    sends a different fake browser identity on every run. In a system whose entire claim is that it
    is authorised and auditable, a tool quietly behaving like an evasive one is a defect even though
    it trips no gate — and it hid in plain sight because it is a DEFAULT, not a flag anyone wrote.

    This fails if the header is ever dropped, or if it stops naming the engine."""
    b = build(monkeypatch, {"httpx-toolkit": (TOOLKIT, PD_BANNER)})
    assert "-H" in b.argv, "no explicit User-Agent: httpx falls back to a random browser identity"
    header = b.argv[b.argv.index("-H") + 1]
    assert header.lower().startswith("user-agent:"), header
    assert "OBSIDIAN" in header, f"the probe does not identify the engine: {header!r}"


# ===================================================================================================
# ZAP — the SECOND occurrence of the same defect, in the builder one down from httpx
# ===================================================================================================
#
# `zaproxy` is the Debian/Kali package's launcher name. ZAP's own upstream distribution installs
# `zap.sh`, and `zap-cli` is a third name; the registry declares those two as `alt_binaries` and its
# resolver finds them, which is why the operator's tools screen reported ZAP installed and controllable
# on a host that had only `zap.sh` — while `_build_zaproxy` emitted a bare `zaproxy` and every run of it
# failed to spawn. The screen said one thing and the run did another, which is the whole defect class.
#
# ZAP differs from httpx in one way that matters to the resolver: the registry declares
# `version_args=None` for it, because it is a GUI/daemon wrapper that must not be launched merely to
# read a version. With no banner there is nothing to disambiguate, so it declares no `wrong_markers`
# either, and resolution is "the first declared name on PATH" — byte-identical to what the registry's
# own resolver does for such a spec. That equality is the point: the binary the screen names is the
# binary that runs.

ZAP_DEB = "/usr/bin/zaproxy"              # the Debian/Kali package launcher
ZAP_SH = "/usr/share/zaproxy/zap.sh"      # what ZAP's upstream distribution installs
ZAP_CLI = "/usr/local/bin/zap-cli"        # the third declared name


def zap(monkeypatch, world):
    pin_path(monkeypatch, world)
    return ex._BUILDERS["zaproxy"]({}, PINNED)


def test_zap_is_found_under_its_upstream_name_when_the_package_launcher_is_absent(monkeypatch):
    """THE DEFECT. A host with ZAP installed from upstream has `zap.sh` and no `zaproxy`; the tools
    screen calls that installed, so the builder must reach it too."""
    b = zap(monkeypatch, {"zap.sh": (ZAP_SH, "")})
    assert isinstance(b, ex._Build), f"ZAP is installed under a DECLARED name; refusing it is wrong: {b!r}"
    assert b.argv[0] == ZAP_SH, "the declared alternate is what makes ZAP reachable on this host at all"


def test_zap_is_found_under_its_third_declared_name(monkeypatch):
    b = zap(monkeypatch, {"zap-cli": (ZAP_CLI, "")})
    assert isinstance(b, ex._Build) and b.argv[0] == ZAP_CLI


def test_the_package_launcher_wins_when_it_is_present(monkeypatch):
    """Declared ORDER, primary first — the registry's own resolution order, so the executor and the
    tools screen never name different binaries on the same host."""
    b = zap(monkeypatch, {"zaproxy": (ZAP_DEB, ""), "zap.sh": (ZAP_SH, ""), "zap-cli": (ZAP_CLI, "")})
    assert b.argv[0] == ZAP_DEB


def test_zap_refuses_naming_every_name_it_tried_when_none_is_installed(monkeypatch):
    """A missing tool is a REFUSAL that says what to install — not an argv that fails to spawn, and not
    a silent empty result. (ZAP is `optional` in the REGISTRY, which governs roster READINESS: the
    engine degrades without it. An agent that explicitly calls it on a host that lacks it still cannot
    run it, and a refusal naming all three names beats a spawn failure or an empty report.)"""
    out = zap(monkeypatch, {})
    assert isinstance(out, str), "a missing ZAP must refuse, not emit an argv"
    for name in ("zaproxy", "zap.sh", "zap-cli"):
        assert name in out, f"the refusal must name every name tried; missing {name!r}: {out!r}"
    assert "apt-get install -y zaproxy" in out, "an honest refusal says how to fix it"


def test_an_undeclared_name_is_never_executed(monkeypatch):
    """The supply-chain line. A ZAP-ish binary under a name nobody declared is not a fallback: the
    builder refuses rather than run a program the operator never approved."""
    out = zap(monkeypatch, {"zap": ("/usr/bin/zap", ""), "owasp-zap": ("/usr/bin/owasp-zap", "")})
    assert isinstance(out, str), f"an undeclared name must not become an argv: {out!r}"
    assert "/usr/bin/" not in out, f"the refusal must not point at an undeclared binary: {out!r}"


def test_zap_is_never_launched_to_read_a_version(monkeypatch):
    """The registry declares `version_args=None` for ZAP precisely so nothing starts a GUI/daemon
    wrapper to read a banner. Resolution must honour that: no probe, ever."""
    def _must_not_run(path, args):
        raise AssertionError(f"the ZAP wrapper was launched for a version banner: {path} {args}")

    monkeypatch.setattr(ex, "_which", lambda name: {"zap.sh": ZAP_SH}.get(name))
    monkeypatch.setattr(ex, "_version_banner", _must_not_run)
    assert ex._BUILDERS["zaproxy"]({}, PINNED).argv[0] == ZAP_SH


def test_resolution_changes_argv_ZERO_and_nothing_else(monkeypatch):
    """Resolution decides argv[0]. It must decide NOTHING else — not the target, not a bound, not the
    report artifact — so the two argvs built for two different resolutions of the same tool differ at
    exactly one index. Stated as a differential rather than as a list of tokens deliberately: what ZAP
    is asked to DO belongs to the ZAP builder's own tests, and pinning its flags here would make this
    file fail every time that scan is improved, for a reason that has nothing to do with resolution."""
    a = zap(monkeypatch, {"zap.sh": (ZAP_SH, "")})
    b = zap(monkeypatch, {"zaproxy": (ZAP_DEB, "")})
    assert isinstance(a, ex._Build) and isinstance(b, ex._Build)
    assert a.argv[0] == ZAP_SH and b.argv[0] == ZAP_DEB
    assert a.argv[1:] == b.argv[1:], (
        f"resolution changed more than argv[0]:\n  {a.argv[1:]}\n  {b.argv[1:]}")
    assert a.redacted_argv[0] == ZAP_SH, "the spine argv must show WHICH binary ran"
    assert a.target == b.target == "http://127.0.0.1:18080/app?x=1", "the target comes from the PIN"
    assert a.report_path == b.report_path and a.report_path.endswith(".json")
    for tok in ("-cmd", "-silent", "-notel"):
        assert tok in a.argv, f"resolution must not have cost {tok}"
    assert any(f"mainProxy.port={ex._ZAP_PROXY_PORT}" in str(x) for x in a.argv), (
        "the proxy-port pin is what keeps a busy 8080 from turning this scan into a silent no-op")


def test_the_zap_run_spawns_the_resolved_path_and_the_record_says_so(monkeypatch):
    """End to end through the real executor: what runs is the resolved binary, and the signed record
    commits to it — so "which ZAP produced these bytes?" is answerable after the fact."""
    pin_path(monkeypatch, {"zap.sh": (ZAP_SH, "")})
    runner = _FakeRun()
    res = execute("zaproxy", {"url": "http://127.0.0.1:18080/app"}, Phase.INFORMATIONAL,
                  gate=_gate, view={"zaproxy": [p.value for p in Phase]},
                  destructive_view={"zaproxy": False}, run=runner, signer=_signer, seq=1, now=7)
    assert res.ran is True, res.reason
    assert runner.calls[0][0] == ZAP_SH
    assert res.record.argv[0] == ZAP_SH
    assert ZAP_SH.encode() in res.record.signing_bytes()


def test_a_missing_zap_denies_the_call_and_spawns_nothing(monkeypatch):
    pin_path(monkeypatch, {})
    runner = _FakeRun()
    res = execute("zaproxy", {"url": "http://127.0.0.1:18080/app"}, Phase.INFORMATIONAL,
                  gate=_gate, view={"zaproxy": [p.value for p in Phase]},
                  destructive_view={"zaproxy": False}, run=runner, signer=_signer, seq=1, now=7)
    assert res.ran is False and res.outcome == "deny" and not runner.calls
    assert res.record is None
    assert "zap.sh" in res.reason and "zap-cli" in res.reason, res.reason


# ===================================================================================================
# DRIFT GUARD — for EVERY builder, not for the one that was broken most recently
# ===================================================================================================
#
# The previous version of this section checked httpx and only httpx, which is why ZAP could carry the
# identical defect two hundred lines away and stay green. What follows is derived from the registry
# SOURCE for every entry in ``_BUILDERS``, so the failure arrives when a tool GAINS an alternate name —
# not after someone runs it on a host where the primary name is missing.


def _registry_source() -> str:
    path = Path(__file__).resolve().parents[2] / "engine/crucible/framework/v2/tools/registry.py"
    if not path.exists():
        pytest.skip(f"tool registry source not present at {path} (framework-free checkout)")
    return path.read_text(encoding="utf-8")


def _registry_specs() -> dict[str, dict]:
    """Parse the registry SOURCE (never import it — the two-env boundary) into
    ``{tool name: ToolSpec keyword arguments}``. The sandbox roster's specs are built in a comprehension
    from a loop variable, so their ``name`` is not a literal and they are skipped: only the HOST roster,
    the one the executor spawns from, is mirrored here."""
    specs: dict[str, dict] = {}
    for node in ast.walk(ast.parse(_registry_source())):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "ToolSpec"):
            continue
        kw = {}
        for k in node.keywords:
            try:
                kw[k.arg] = ast.literal_eval(k.value)
            except Exception:  # noqa: BLE001 — a non-literal is not something this mirror copies
                kw[k.arg] = None
        name = kw.get("name")
        if isinstance(name, str) and name not in specs:
            specs[name] = kw
    return specs


def _httpx_spec_from_registry() -> dict:
    spec = _registry_specs().get("httpx")
    if spec is None:
        pytest.fail("no ToolSpec(name='httpx') found in the tool registry source")
    return spec


def _declared_names(spec: dict) -> tuple[str, ...]:
    return (spec["binary"], *(spec.get("alt_binaries") or ()))


def _disagreements(specs: dict[str, dict], mirror: dict, builders) -> list[str]:
    """EVERY way the executor's binary resolution can disagree with the registry's declaration, as
    human-readable lines. Empty ⇒ they agree.

    Written as a pure function over (registry, mirror, builders) for two reasons: the real check below
    calls it with the real three, and the mutation control calls it with a SYNTHETIC registry to prove
    the check actually fires. A guard nobody has seen fail is not a guard."""
    out: list[str] = []
    for tool in sorted(builders):
        spec = specs.get(tool)
        if spec is None:
            out.append(f"{tool}: has an argv builder but NO ToolSpec in the registry — the operator's "
                       "tools screen cannot report a tool it does not know about")
            continue
        declared = _declared_names(spec)
        entry = mirror.get(tool)
        if entry is None:
            if len(declared) > 1:
                out.append(f"{tool}: the registry declares alternates {declared} and RESOLVES them, but "
                           "the executor mirrors none — so the tools screen reports this tool installed "
                           f"and controllable on a host that has only {declared[1]!r}, and every run of "
                           "it fails to spawn. Add it to executor._DECLARED_TOOLS and resolve through "
                           "resolve_tool_binary().")
            continue
        if tuple(entry.names) != declared:
            out.append(f"{tool}: declared-name drift — executor={tuple(entry.names)} registry={declared}")
        if tuple(entry.version_args) != tuple(spec.get("version_args") or ()):
            out.append(f"{tool}: version-flag drift — executor={tuple(entry.version_args)} "
                       f"registry={tuple(spec.get('version_args') or ())}")
        if tuple(entry.wrong_markers) != tuple(spec.get("wrong_markers") or ()):
            out.append(f"{tool}: impostor-marker drift — executor={tuple(entry.wrong_markers)} "
                       f"registry={tuple(spec.get('wrong_markers') or ())}")
        if (entry.apt or None) != spec.get("apt"):
            out.append(f"{tool}: install-package drift (the refusal's install hint) — "
                       f"executor={entry.apt!r} registry={spec.get('apt')!r}")
    for tool in sorted(set(mirror) - set(builders)):
        out.append(f"{tool}: mirrored in executor._DECLARED_TOOLS but no builder spawns it — a "
                   "declaration nothing honours rots silently")
    return out


def test_no_builders_resolution_disagrees_with_the_registrys_declaration():
    """THE WIDENED GUARD. Every tool, every field of the declaration, in one place."""
    bad = _disagreements(_registry_specs(), ex._DECLARED_TOOLS, ex._BUILDERS)
    assert not bad, "executor/registry binary-declaration drift:\n  " + "\n  ".join(bad)


@pytest.mark.parametrize("tool", sorted(ex._DECLARED_TOOLS))
def test_a_builder_whose_tool_declares_alternates_actually_resolves_through_them(tool, monkeypatch):
    """The BEHAVIOURAL half, and the half that was missing. A mirrored declaration proves nothing on
    its own: ZAP's alternates were declared and resolved by the registry the whole time, and the builder
    still emitted a bare name. So: put ONLY the last declared name on PATH — the case the operator hits
    when they installed the tool from upstream rather than from the distro — and require the builder to
    reach it, by absolute path, in argv[0]."""
    names = ex._DECLARED_TOOLS[tool].names
    last = names[-1]
    path = f"/opt/declared/{last}"
    # An EMPTY banner is the registry's own "cannot disambiguate ⇒ trust PATH" case, so this pin works
    # for a tool with impostor markers and for one without, without teaching the test either tool's
    # banner text.
    pin_path(monkeypatch, {last: (path, "")})
    build = ex._BUILDERS[tool](MINIMAL_ARGS.get(tool, {}), PINNED)
    assert isinstance(build, ex._Build), (
        f"{tool}: installed under its declared alternate {last!r} and the builder refused: {build!r}")
    assert build.argv[0] == path, (
        f"{tool}: argv[0]={build.argv[0]!r} — the builder hardcodes a name instead of resolving through "
        f"the registry's declared {names}. The tools screen will report it controllable on a host where "
        "only the alternate exists, and the run will fail to spawn.")


@pytest.mark.parametrize("tool", sorted(ex._DECLARED_TOOLS))
def test_a_builder_whose_tool_declares_alternates_refuses_naming_all_of_them(tool, monkeypatch):
    """The negative control has to be LOUD. Nothing declared is on PATH: the builder must refuse with a
    reason that names every name it tried — never an argv that fails to spawn, and never a silence a
    caller cannot tell apart from a clean scan."""
    pin_path(monkeypatch, {})
    out = ex._BUILDERS[tool](MINIMAL_ARGS.get(tool, {}), PINNED)
    assert isinstance(out, str), f"{tool}: a missing tool must REFUSE, got {out!r}"
    for name in ex._DECLARED_TOOLS[tool].names:
        assert name in out, f"{tool}: refusal does not name {name!r}: {out!r}"


@pytest.mark.parametrize("tool", sorted(set(ex._BUILDERS) - set(ex._DECLARED_TOOLS)))
def test_a_builder_with_no_declared_alternates_still_names_the_registrys_binary(tool, monkeypatch):
    """The other seven. They resolve by bare name because their registry entry declares exactly one —
    but that name must be the one the registry declares. A builder spelling it differently (or a
    registry that renames the package's binary) is the same divergence between what the screen reports
    and what runs, and fails here."""
    specs = _registry_specs()
    spec = specs.get(tool)
    assert spec is not None, f"{tool}: builder with no registry ToolSpec"
    assert len(_declared_names(spec)) == 1, (
        f"{tool}: the registry now declares alternates {_declared_names(spec)} — this tool belongs in "
        "executor._DECLARED_TOOLS and its builder must resolve through resolve_tool_binary()")
    name = spec["binary"]
    path = f"/opt/declared/{name}"
    pin_path(monkeypatch, {name: (path, "")})
    build = ex._BUILDERS[tool](MINIMAL_ARGS.get(tool, {}), PINNED)
    assert isinstance(build, ex._Build), f"{tool}: {build!r}"
    assert build.argv[0] in (name, path), (
        f"{tool}: argv[0]={build.argv[0]!r} is neither the registry's declared binary {name!r} nor the "
        "path that name resolves to")


def test_the_disagreement_check_actually_fires(monkeypatch):
    """MUTATION CONTROL, in-file. The guard above is only worth anything if it FAILS when the mirror
    and the registry part company, and every drift check ever written passes trivially when its parse
    silently returns nothing. Each case below is a real way this has gone (or could go) wrong."""
    real = _registry_specs()
    mirror = ex._DECLARED_TOOLS

    # 1. THE ZAP DEFECT ITSELF: a tool gains an alternate in the registry and no one mirrors it.
    gained = dict(real)
    gained["nuclei"] = {**real["nuclei"], "alt_binaries": ("nuclei-bin",)}
    bad = _disagreements(gained, mirror, ex._BUILDERS)
    assert any(line.startswith("nuclei:") for line in bad), bad

    # 2. A NAME REMOVED from the executor's mirror while the registry still declares it.
    thinned = {**mirror, "httpx": ex._DeclaredTool(names=("httpx",),
                                                   version_args=mirror["httpx"].version_args,
                                                   wrong_markers=mirror["httpx"].wrong_markers,
                                                   apt=mirror["httpx"].apt)}
    assert any("declared-name drift" in line for line in _disagreements(real, thinned, ex._BUILDERS))

    # 3. An impostor marker dropped: the executor would then hand the engine the impostor's output.
    unmarked = {**mirror, "httpx": ex._DeclaredTool(names=mirror["httpx"].names,
                                                    version_args=mirror["httpx"].version_args,
                                                    apt=mirror["httpx"].apt)}
    assert any("impostor-marker drift" in line for line in _disagreements(real, unmarked, ex._BUILDERS))

    # 4. A wrong install hint — an honest refusal that tells the operator to install the wrong package
    #    is not an honest refusal.
    misapt = {**mirror, "zaproxy": ex._DeclaredTool(names=mirror["zaproxy"].names, apt="zap")}
    assert any("install-package drift" in line for line in _disagreements(real, misapt, ex._BUILDERS))

    # 5. A builder for a tool the registry does not know at all.
    assert any("NO ToolSpec" in line for line in _disagreements(real, mirror, {**ex._BUILDERS, "zap2": 1}))

    # 6. A mirrored declaration no builder honours.
    orphan = {**mirror, "chromium": ex._DeclaredTool(names=("chromium",))}
    assert any(line.startswith("chromium:") for line in _disagreements(real, orphan, ex._BUILDERS))

    # 7. …and the real three agree, so none of the above is passing by accident.
    assert _disagreements(real, mirror, ex._BUILDERS) == []


def test_the_drift_guard_is_actually_reading_the_registry():
    """MUTATION CONTROL. Every assertion above passes trivially if the parse returns nothing, which
    would make this file a no-op that still reports green — worse than not having written it."""
    specs = _registry_specs()
    missing = sorted(set(ex._BUILDERS) - set(specs))
    assert not missing, f"the registry parse found no ToolSpec for {missing} — the parse is broken"
    assert specs["httpx"].get("binary") == "httpx" and specs["httpx"].get("alt_binaries"), specs["httpx"]
    assert len(specs["httpx"].get("wrong_markers") or ()) >= 2, specs["httpx"]
    assert specs["zaproxy"].get("alt_binaries") == ("zap.sh", "zap-cli"), specs["zaproxy"]
    assert len(ex._DECLARED_TOOLS) >= 2 and len(ex._DECLARED_TOOLS["httpx"].wrong_markers) >= 2
    # Both known-alternate tools are mirrored AND actually resolve — the two halves this file pins.
    assert {"httpx", "zaproxy"} <= set(ex._DECLARED_TOOLS)


def test_the_registry_still_marks_httpx_required():
    """If httpx ever becomes optional in the roster, a hard DENY stops being the right shape (an
    optional tool should degrade, not deny). Fail here so a human decides."""
    assert _httpx_spec_from_registry().get("optional") is False


def test_the_probe_timeout_matches_the_registry_budget():
    """The banner probe is the same read-only probe the registry runs; a divergent budget would let the
    executor call a slow-but-genuine tool an impostor that the tools screen calls installed."""
    lines = [ln for ln in _registry_source().splitlines() if ln.startswith("_VERSION_TIMEOUT_S")]
    assert lines, "registry no longer declares _VERSION_TIMEOUT_S"
    assert str(ex._BINARY_PROBE_TIMEOUT_S) in lines[0], f"probe-budget drift: {lines[0]!r}"
