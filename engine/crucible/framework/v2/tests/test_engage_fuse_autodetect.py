"""
NW-3 — auto-enable ``engage --fuse-sensors`` when ``targets/<slug>/fusion.json`` is present.

``engage.main()`` auto-activates sensor fusion when the operator has authored a
``targets/<slug>/fusion.json`` manifest (opt-in-by-presence). ``--no-fuse-sensors`` is the explicit
opt-OUT that overrides a present manifest. The LOAD-BEARING invariant under test: the DEFAULT
(manifest-absent) engage path is byte-identical to the pre-NW-3 flag-off run, and the in-process
benchmark/gate — which carries no target-dir slug and never reaches ``engage.main()`` — can never
auto-enable fusion. Fusion, when it does run, only ADDS oracle-grounded facts + graded leads (it is
covered by ``test_engage_fusion.py``); this file pins the ACTIVATION gate only.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.v2 import engage


@pytest.fixture
def targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ``targets/<slug>`` to an isolated tmp dir so each test controls whether a fusion.json
    exists — never touching the real benchmark slug (mirrors test_engage_fusion.py's isolation)."""
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    return tmp_path


def _manifest(root: Path, slug: str) -> None:
    d = root / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "fusion.json").write_text(
        '[{"sensor": "declared_service", "args": {"host": "10.0.0.5", "services": []}}]',
        encoding="utf-8")


# ---- the pure resolution: every opt-in / opt-out combination ----------------


def test_absent_manifest_no_flag_stays_off(targets: Path) -> None:
    # THE byte-identical case: no manifest, no flag -> fusion OFF, no auto-note. Identical to the
    # value a pre-NW-3 flag-off run computed (fuse_sensors False).
    assert engage._fusion_manifest_present("alpha") is False
    assert engage._resolve_fuse_sensors(
        "alpha", fuse_sensors=False, no_fuse_sensors=False) == (False, False)


def test_present_manifest_auto_enables(targets: Path) -> None:
    _manifest(targets, "alpha")
    assert engage._fusion_manifest_present("alpha") is True
    assert engage._resolve_fuse_sensors(
        "alpha", fuse_sensors=False, no_fuse_sensors=False) == (True, True)   # enabled + auto-noted


def test_explicit_flag_enables_but_is_not_marked_auto(targets: Path) -> None:
    # --fuse-sensors with no manifest: enabled, but NOT the manifest-auto note (activation was explicit).
    assert engage._resolve_fuse_sensors(
        "alpha", fuse_sensors=True, no_fuse_sensors=False) == (True, False)


def test_explicit_flag_with_present_manifest_is_not_marked_auto(targets: Path) -> None:
    _manifest(targets, "alpha")
    assert engage._resolve_fuse_sensors(
        "alpha", fuse_sensors=True, no_fuse_sensors=False) == (True, False)


def test_no_fuse_sensors_overrides_present_manifest(targets: Path) -> None:
    _manifest(targets, "alpha")
    assert engage._resolve_fuse_sensors(
        "alpha", fuse_sensors=False, no_fuse_sensors=True) == (False, False)


def test_no_fuse_sensors_overrides_even_an_explicit_flag(targets: Path) -> None:
    _manifest(targets, "alpha")
    assert engage._resolve_fuse_sensors(
        "alpha", fuse_sensors=True, no_fuse_sensors=True) == (False, False)


def test_malformed_slug_never_raises(targets: Path) -> None:
    # total/defensive: no slug -> False (the probe never raises, so the default path never breaks).
    assert engage._fusion_manifest_present("") is False
    assert engage._resolve_fuse_sensors("", fuse_sensors=False, no_fuse_sensors=False) == (False, False)


# ---- end-to-end through engage.main(), with the heavy scan stubbed ----------


def _fake_result() -> SimpleNamespace:
    """A minimal duck-typed EngagementResult the summary printer can walk (all empty/zero)."""
    report = SimpleNamespace(
        target="http://127.0.0.1/", pages_crawled=0, requests_audited=0, audit_requests_sent=0,
        active_findings=[], passive_findings=[], dom_xss_candidates=[], discovered_paths=[],
        js_secrets=[], arsenal_leads=[])
    return SimpleNamespace(
        report=report, finding_confidence=[], grounding=[], attack_paths=[], chained_conclusions=[],
        entities=[], predictions=[], defense=None, fused_leads=0, fused_facts=0)


@pytest.fixture
def stub_engagement(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Stub ``run_engagement`` so ``main()`` exercises arg-resolution + the summary WITHOUT a real
    scan. Records the ``fuse_sensors`` kwarg main() resolved and passed down."""
    calls: dict = {}

    def _fake(slug: str, seed_url: str, **kw: object) -> SimpleNamespace:
        calls["fuse_sensors"] = kw.get("fuse_sensors")
        return _fake_result()

    monkeypatch.setattr(engage, "run_engagement", _fake)
    return calls


def _run_main(*argv: str) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = engage.main(list(argv))
    return rc, buf.getvalue()


def test_main_absent_manifest_keeps_fusion_off_and_prints_no_fusion_line(
        targets: Path, stub_engagement: dict) -> None:
    rc, out = _run_main("alpha", "http://127.0.0.1/")
    assert rc == 0
    assert stub_engagement["fuse_sensors"] is False           # auto-detect left it off
    assert "fusion active" not in out and "fused sensors" not in out


def test_main_present_manifest_auto_enables_and_notes_it(
        targets: Path, stub_engagement: dict) -> None:
    _manifest(targets, "alpha")
    rc, out = _run_main("alpha", "http://127.0.0.1/")
    assert rc == 0
    assert stub_engagement["fuse_sensors"] is True            # auto-enabled by manifest presence
    assert "fusion active" in out
    assert "targets/alpha/fusion.json" in out


def test_main_no_fuse_sensors_flag_overrides_present_manifest(
        targets: Path, stub_engagement: dict) -> None:
    _manifest(targets, "alpha")
    rc, out = _run_main("alpha", "http://127.0.0.1/", "--no-fuse-sensors")
    assert rc == 0
    assert stub_engagement["fuse_sensors"] is False           # explicit opt-out wins over the manifest
    assert "fusion active" not in out


def test_main_default_output_is_byte_identical_to_the_flag_off_run(
        targets: Path, stub_engagement: dict) -> None:
    # The byte-identical guard, on real stdout: with no manifest, the DEFAULT run and an explicit
    # --no-fuse-sensors run produce IDENTICAL output, and neither emits any fusion summary line —
    # exactly the pre-NW-3 flag-off engage output.
    _, out_default = _run_main("alpha", "http://127.0.0.1/")
    _, out_optout = _run_main("alpha", "http://127.0.0.1/", "--no-fuse-sensors")
    assert out_default == out_optout
    assert "fusion active" not in out_default and "fused sensors" not in out_default


# ---- regression: the benchmark/gate can never auto-enable fusion ------------


def test_benchmark_names_carry_no_fusion_manifest() -> None:
    # NB: no `targets` fixture — this probes the REAL target-dir. The gate row prints tool 'crucible';
    # the corpus target is 'crucible-benchmark-app'. Neither is a real slug and the in-process
    # benchmark never reaches engage.main(), but pin it anyway: no fusion.json exists for any name the
    # benchmark could carry, so the gate/benchmark path can never auto-activate fusion.
    for name in ("crucible", "crucible-benchmark-app"):
        assert engage._fusion_manifest_present(name) is False


def test_no_fusion_manifest_exists_anywhere_under_targets() -> None:
    # The load-bearing byte-identical invariant, made concrete: the real targets/ tree contains NO
    # fusion.json, so no default engage run (and certainly no gate run) can auto-activate fusion.
    from framework.v2.common import paths
    assert list((paths.crucible_root() / "targets").rglob("fusion.json")) == []
