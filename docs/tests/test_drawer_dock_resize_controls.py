"""The detail/activity panel (#drawer) must be resizable, dockable (right/bottom) and maximizable — the
"expand the activity box from the side and top, with an expand icon" control set, with the choice persisted.

WHY THIS TEST EXISTS. The drawer was a fixed-width, right-only, non-resizable slide-in. The operator asked
to be able to expand it from the side and the top and via an expand icon. The controls live across three
files (a JS behaviour block in app.js, CSS states in components.css, and glyphs in ui.js); it is easy for a
later edit to drop one leg (e.g. remove the CSS for .dock-bottom) and silently half-break the feature. This
guard reads the files only — imports nothing, runs no tool, sends no packet — so it is correct in the
docs-only CI job (`pytest docs/tests -q`, which installs only pytest). It asserts every leg is present and
wired, and includes NEGATIVE-style drift checks (the state key, the persisted-size path) so the feature
cannot be quietly reduced back to a fixed panel.

Behavioural coverage (drag → resize → persist → restore, click → maximize/dock → persist) was verified
against the REAL sliced code in a headless jsdom harness during development; this file is the CI-runnable
drift guard for the same wiring.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
CSS = (REPO / "packages" / "vigil-ui" / "components.css").read_text(encoding="utf-8")
UIJS = (REPO / "packages" / "vigil-ui" / "ui.js").read_text(encoding="utf-8")


def test_control_icons_are_registered():
    # The header controls need real glyphs, not the dot fallback.
    for name in ('"dock-right"', '"dock-bottom"', "maximize:", "minimize:"):
        assert name in UIJS, f"ui.js icon map is missing {name}"


def test_drawer_dom_has_handle_and_controls():
    # The resize handle + the dock/maximize buttons must be built into the drawer, and the wiring installed.
    for needle in ("div.dz#drawer-dz", "button.iconbtn#drawer-dock", "button.iconbtn#drawer-max",
                   "onClick: cycleDrawerDock", "onClick: toggleDrawerMax", "installDrawerControls()"):
        assert needle in APPJS, f"app.js drawer DOM/wiring is missing: {needle}"


def test_drawer_behaviour_functions_exist():
    for fn in ("function applyDrawerState()", "function toggleDrawerMax()", "function cycleDrawerDock()",
               "function installDrawerControls()"):
        assert fn in APPJS, f"app.js is missing {fn}"
    # resize is driven by pointer events on the handle
    for ev in ('addEventListener("pointerdown"', 'addEventListener("pointermove"', 'addEventListener("pointerup"'):
        assert ev in APPJS, f"app.js resize is missing {ev}"


def test_choice_and_size_persist():
    # The dock/size choice must survive reloads: a localStorage key + a save on every change + a restore on open.
    assert '"vigil.drawer"' in APPJS, "drawer state localStorage key is gone — the panel will not remember"
    assert "localStorage.setItem(DRAWER_KEY" in APPJS, "drawer state is never saved"
    assert "localStorage.getItem(DRAWER_KEY" in APPJS, "drawer state is never read back"
    assert "applyDrawerState();" in APPJS and "function openDrawer" in APPJS, "openDrawer must re-apply the remembered state"


def test_css_defines_dock_max_and_handle():
    for rule in ("#drawer.dock-bottom", "#drawer.max", "#drawer .dz",
                 "cursor: ew-resize", "cursor: ns-resize"):
        assert rule in CSS, f"components.css is missing the drawer rule: {rule}"
    # bottom dock height is variable-driven so a dragged height can override it
    assert "--drawer-h" in CSS, "bottom-dock height is not variable-driven"
