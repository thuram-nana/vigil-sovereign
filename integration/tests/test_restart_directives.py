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
# The restart policies that actually pick a CRASH back up. Deliberately EXCLUDES "on-success": it restarts
# ONLY on a clean exit (code 0 / SIGHUP/SIGINT/SIGTERM/SIGPIPE) and NOT on a crash (non-zero exit, SIGSEGV/
# SIGABRT, OOM-kill, watchdog timeout) — so it never supervises a long-running edge the way this guard certifies.
_RESTART_SUPERVISING = {"always", "on-failure", "on-abnormal", "on-abort", "on-watchdog"}


def _positive_restartsec(raw: "str | None") -> bool:
    """True iff RestartSec is a POSITIVE delay. Presence alone is not enough: RestartSec=0 (or empty / a
    non-numeric value) restarts with zero backoff, burning systemd's StartLimitBurst in milliseconds on a
    crash-loop and then giving up — the edge stays DOWN, the opposite of what the guard certifies."""
    if raw is None:
        return False
    digits = "".join(ch for ch in raw if ch.isdigit())
    return bool(digits) and int(digits) > 0


def _directives(text: str) -> dict[str, str]:
    """Map each `[Service]` KEY to its EFFECTIVE value (systemd: last assignment wins).

    SECTION-AWARE: systemd honours Restart=/RestartSec=/Type= only inside ``[Service]``, so a same-named key
    under ``[Unit]``/``[Install]`` is ignored (a mis-sectioned directive must not fool the guard).
    CONTINUATION-AWARE: a line ending in a backslash folds into the next (systemd joins them with a space),
    so a stray trailing backslash on an ExecStart cannot make a following ``Restart=…`` parse as a standalone
    directive — exactly the layout that would quietly un-supervise a unit. Comments / blank lines skipped."""
    # 1) fold backslash line-continuations into single logical lines
    logical: list[str] = []
    buf = ""
    for raw in text.splitlines():
        buf += raw
        if raw.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1] + " "        # drop the trailing backslash; systemd joins with a space
            continue
        logical.append(buf)
        buf = ""
    if buf:
        logical.append(buf)
    # 2) parse [Service]-section KEY=VALUE only (last wins), skipping comments / blanks / other sections
    out: dict[str, str] = {}
    section = ""
    for line in logical:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("["):
            section = s.strip("[]").strip().lower()
            continue
        if section == "service" and "=" in s:
            k, v = s.split("=", 1)
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
        if restart not in _RESTART_SUPERVISING or not _positive_restartsec(d.get("RestartSec")):
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
    raw = d.get("RestartSec")
    assert _positive_restartsec(raw), f"{rel} RestartSec={raw!r} must be a positive delay"


# ---- red-pen fold: the guard's own parser/allowlist must be SOUND (synthetic-unit unit tests) --------
def test_directives_is_section_aware_ignores_restart_outside_service():
    """A Restart=/Type= placed under [Unit] or [Install] is NOT a [Service] directive — systemd ignores it,
    so the guard must too (else a mis-sectioned Restart could mask an un-supervised unit)."""
    text = "[Unit]\nRestart=always\nRestartSec=5\n[Service]\nExecStart=/x\nType=simple\n[Install]\nRestart=on-failure\n"
    d = _directives(text)
    assert d.get("Type") == "simple"
    assert "Restart" not in d and "RestartSec" not in d          # only the [Service] section is honoured


def test_directives_is_continuation_aware_folds_trailing_backslash():
    """A trailing backslash folds the next physical line into the ExecStart value, so a following Restart=
    is part of ExecStart (NOT a standalone directive) — exactly how systemd reads it."""
    text = "[Service]\nExecStart=/opt/app \\\nRestart=always\nType=simple\n"
    d = _directives(text)
    assert "Restart" not in d                                    # folded into ExecStart, not a real directive
    assert d["ExecStart"].endswith("Restart=always")
    assert d.get("Type") == "simple"


def test_on_success_is_not_a_supervising_policy():
    # Restart=on-success restarts ONLY on a clean exit — it must NOT count as crash-supervising.
    assert "on-success" not in _RESTART_SUPERVISING
    assert {"always", "on-failure"} <= _RESTART_SUPERVISING


def test_positive_restartsec_rejects_zero_and_empty():
    assert _positive_restartsec("5") and _positive_restartsec("30s")
    assert not _positive_restartsec("0")
    assert not _positive_restartsec("")
    assert not _positive_restartsec(None)
    assert not _positive_restartsec("infinity")                  # non-numeric ⇒ not a positive delay
