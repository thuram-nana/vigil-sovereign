"""HLTH-1 — the long-running service units auto-restart; the oneshot timer drains do NOT.

The production-readiness goal "a crashed long-running service auto-restarts" is a systemd-unit invariant:
every HTTP edge / daemon unit (`Type=simple`/`notify`/..., i.e. NOT oneshot) must carry a real `Restart=`
policy plus a `RestartSec=` so a crash is picked back up, while every `Type=oneshot` timer drain must NOT
(a drain is meant to run-and-exit — a Restart= there would turn a clean exit into a hot loop).

These are framework-free (pure file reads + a tiny stdlib unit parser), so they run in the sovereign CI
leg, and they guard against a future edit silently shipping a long-running edge with no supervision, or
wiring Restart= onto a run-and-exit drain.

Run: PYTHONPATH=integration python -m pytest integration/tests/test_restart_directives.py -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_UNIT_DIRS = (_REPO / "infra" / "systemd", _REPO / "apps" / "sigil" / "deploy" / "systemd")

# The known long-running HTTP edges / daemons (the LB-frontable surfaces + supervised services). An explicit
# roster, so deleting or flipping one of these to oneshot — quietly un-supervising a paid edge — reds here.
_EXPECTED_LONG_RUNNING = {
    "infra/systemd/aegis-saas-gateway@.service",
    "infra/systemd/vigil-command.service",
    "infra/systemd/vigil-witness@.service",
    "apps/sigil/deploy/systemd/sigil-bridge@.service",
    "apps/sigil/deploy/systemd/sigil-cockpit.service",
    "apps/sigil/deploy/systemd/sigil-customer.service",
    "apps/sigil/deploy/systemd/sigil-public.service",
}
# A sane, supervising restart policy — anything but the two that leave a crash dead on the floor.
_RESTART_SUPERVISING = {"always", "on-failure", "on-abnormal", "on-abort", "on-watchdog", "on-success"}


def _directives(text: str) -> dict[str, str]:
    """Map each assigned KEY to its EFFECTIVE value (systemd: last assignment wins). Comments/blank lines
    skipped; `Type`/`Restart`/`RestartSec` are single-line directives, so continuation lines are irrelevant."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _service_units() -> list[tuple[str, dict[str, str]]]:
    units = []
    for d in _UNIT_DIRS:
        for p in sorted(d.glob("*.service")):
            rel = str(p.relative_to(_REPO))
            units.append((rel, _directives(p.read_text(encoding="utf-8"))))
    return units


def _is_oneshot(dirs: dict[str, str]) -> bool:
    # Type defaults to "simple" when unset (ExecStart present) — so only an explicit oneshot is run-and-exit.
    return dirs.get("Type", "simple") == "oneshot"


def test_the_units_exist_and_parse():
    units = _service_units()
    assert units, f"no .service units found under {[str(d) for d in _UNIT_DIRS]}"
    names = {rel for rel, _ in units}
    missing = _EXPECTED_LONG_RUNNING - names
    assert not missing, f"expected long-running units missing from the tree: {sorted(missing)}"


def test_every_long_running_unit_auto_restarts():
    """THE GUARD: a crashed long-running edge/daemon must be picked back up — so every non-oneshot unit
    carries a supervising Restart= plus a RestartSec=. A new long-running unit shipped without supervision
    reds here."""
    offenders = []
    for rel, d in _service_units():
        if _is_oneshot(d):
            continue
        restart = d.get("Restart", "").lower()
        if restart not in _RESTART_SUPERVISING or "RestartSec" not in d:
            offenders.append((rel, {"Type": d.get("Type"), "Restart": d.get("Restart"),
                                    "RestartSec": d.get("RestartSec")}))
    assert not offenders, f"long-running units lacking a supervising Restart=/RestartSec=: {offenders}"


def test_every_expected_edge_is_long_running_and_restarts():
    by_name = dict(_service_units())
    for rel in sorted(_EXPECTED_LONG_RUNNING):
        d = by_name[rel]
        assert not _is_oneshot(d), f"{rel} must stay a long-running service, not oneshot"
        assert d.get("Restart", "").lower() in _RESTART_SUPERVISING, f"{rel} lost its supervising Restart="
        assert "RestartSec" in d, f"{rel} lost its RestartSec="


def test_oneshot_drains_do_not_restart_loop():
    """The flip side: a Type=oneshot timer drain (finding/settle/backup/checkpoint/…) must NOT carry a
    Restart= — it is meant to run and exit, and a Restart= would turn a clean exit into a hot loop."""
    offenders = [rel for rel, d in _service_units() if _is_oneshot(d) and "Restart" in d]
    assert not offenders, f"oneshot drains must not set Restart= (run-and-exit): {offenders}"


@pytest.mark.parametrize("rel", sorted(_EXPECTED_LONG_RUNNING))
def test_restartsec_is_a_sane_positive_delay(rel):
    d = dict(_service_units())[rel]
    raw = d.get("RestartSec", "")
    # our units use a plain integer-seconds value; accept a trailing unit suffix but require > 0.
    digits = "".join(ch for ch in raw if ch.isdigit())
    assert digits and int(digits) > 0, f"{rel} RestartSec={raw!r} must be a positive delay"
