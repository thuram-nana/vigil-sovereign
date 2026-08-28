"""vigil_core.doctor — render-path negative controls (audit F-11).

``test_doctor.py`` pins the CHECK REGISTRY + the ``evaluate`` gate decision. This file pins the two
RENDER paths — ``render_gate_block`` and ``render_readme_posture_block`` — which turn a verdict into the
exact text a reviewer reads in `vigil doctor` output and in README.md. They are the anti-rot surface: a
mutation that stops marking an unmet control, drops the requirement hint, or lets the README block read
from the live env instead of the fixed fixture would corrupt the honesty signal without any registry test
noticing. Pure ``vigil_core``; runs in the required "vigil_core — shared integrity substrate" job.
"""
from __future__ import annotations

from vigil_core import doctor as dmod


# ── render_gate_block: the PASS vs REFUSE framing, and per-control marks ────────────────────────────────

def test_refuse_block_marks_every_unmet_control_and_shows_its_requirement():
    """An armed, fully-misconfigured gate must render as a REFUSAL: a `!!` mark AND the requirement hint on
    every unmet control (a reviewer must see WHY each blocks), and the unmet count in the header."""
    gate = dict(dmod.evaluate(dmod.README_POSTURE_FIXTURE, armed=True))
    lines = dmod.render_gate_block(gate)
    header = lines[0]
    assert "REFUSES to start" in header
    assert f"{len(dmod.REQUIRED_CONTROLS)} precondition(s) unmet" in header
    body = lines[1:]
    assert len(body) == len(dmod.REQUIRED_CONTROLS)
    for seg in body:
        assert seg.lstrip().startswith("!!"), seg          # every control is flagged unmet
        assert " — " in seg, seg                            # and carries its requirement hint
    # a control name a reviewer expects to see is present, formatted
    assert any("vault:" in s for s in body)


def test_pass_block_reads_all_met_and_omits_the_requirement_hint():
    """The mirror control: when every control is in its good-set the block reports it may start, marks each
    OK, and does NOT append the requirement hint — so the renderer is not simply always-refusing."""
    good = _all_good_states()
    gate = dict(dmod.evaluate(good, armed=True))
    assert gate["ok"] is True
    lines = dmod.render_gate_block(gate)
    assert "may start" in lines[0]
    for seg in lines[1:]:
        assert seg.lstrip().startswith("OK"), seg
        assert " — " not in seg, seg                        # no unmet-requirement suffix on a met control


def test_render_never_raises_on_a_degenerate_verdict():
    """Pure formatting must be total — an empty/garbage verdict renders a line, never an exception."""
    assert dmod.render_gate_block({}) != []
    assert dmod.render_gate_block({"controls": [{}]})       # a control with no keys still renders


# ── render_readme_posture_block: deterministic, env-independent, byte-stable ────────────────────────────

def test_readme_block_is_deterministic_and_independent_of_the_live_posture(monkeypatch):
    """The README block must come from the FIXED fixture + a pinned ``production`` label, never the live
    env — otherwise the committed README would differ per machine. Flipping the real posture env must not
    change a byte of it."""
    from vigil_core.posture import POSTURE_ENV
    monkeypatch.delenv(POSTURE_ENV, raising=False)
    a = dmod.render_readme_posture_block()
    monkeypatch.setenv(POSTURE_ENV, "production")
    b = dmod.render_readme_posture_block()
    assert a == b                                            # env-independent
    assert "VIGIL_POSTURE=production" in a                  # label is pinned, not read from env
    assert "REFUSES to start" in a                          # the fixture is fully misconfigured by design
    # every registry control appears in the rendered block (drives the CI anti-rot guard)
    for control, _good, _req in dmod.REQUIRED_CONTROLS:
        assert f"{control}:" in a, control


def _all_good_states() -> dict:
    """Put every required control into (one of) its good state(s) — the positive fixture."""
    return {control: sorted(good)[0] for (control, good, _req) in dmod.REQUIRED_CONTROLS}
