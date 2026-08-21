"""W10-2 (#474): the sovereignty tier is re-resolved on an offense-plane restart, and every doc / UI
string that describes this is TRUE of the code.

WHY THIS TEST EXISTS. The sovereignty tier is delivered to the keyless offense children in their
environment when they are spawned. Before this change, a tier set in Settings after boot never reached
the running children — and worse, the UI's own "restart the offense plane" control respawned the
BOOT-TIME snapshot, so even a restart did not pick up the change; only a fresh `vigil up` did. An
AIR_GAPPED deployment could therefore be running PERMISSIVE, silently.

The fix (`integration/vigil_integration/uiproxy.py`):

  * `PlaneControl` re-resolves the dynamic offense env (model / keys / **sovereignty tier**) from the
    sovereign at each restart via `_resolve_offense_llm_env_result`, instead of respawning the captured
    boot snapshot;
  * it FAILS CLOSED — a transient sovereign error at restart retains the last known-good tier rather than
    dropping the children to a keyless/PERMISSIVE env;
  * the Settings screen surfaces the Settings ↔ Governance-pill disagreement, naming the pill (the tier
    the running engine is actually enforcing) as the truthful one.

This test reads files only — imports nothing, runs no tool, sends no packet — so it is correct to run in
the docs-only `briefing-completeness` CI job (which installs only pytest). It fails four ways, each a real
drift: a doc caveat is gone, a UI string is gone, a settings purpose is gone, or the code fact those
strings cite is no longer true in-tree.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

SAFETY_DOC = REPO / "docs" / "plain-english" / "08-safety-and-authorization.md"
APPJS = REPO / "packages" / "vigil-ui" / "app.js"
SETTINGS = REPO / "apps" / "sigil" / "sigil" / "ui" / "settings.py"
UIPROXY = REPO / "integration" / "vigil_integration" / "uiproxy.py"


def _collapsed(path: Path) -> str:
    """File text with every whitespace run collapsed to one space, so a phrase that wraps across
    indented lines still matches as a single needle."""
    assert path.is_file(), f"file missing: {path}"
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def test_safety_doc_carries_the_restart_caveat():
    """The security doc must now describe the deployment behaviour the product already implied: the tier
    reaches the offense engine at spawn, a change needs an offense-plane restart, the restart re-resolves
    and fails closed, and the Governance pill is the truth until then."""
    doc = _collapsed(SAFETY_DOC)
    for needle in (
        "the tier reaches the offense engine when it starts",
        "re-resolves the current tier from the sovereign",
        "fails closed",
        "the pill is the truth until the offense plane restarts",
    ):
        assert needle in doc, f"safety doc lost the W10-2 restart caveat: {needle!r}"


def test_settings_tier_purpose_states_the_restart_and_pill():
    """The Settings tier control's own help text must tell the operator the change applies on the next
    offense-plane start, and point at the Governance pill as the tier in force."""
    txt = _collapsed(SETTINGS)
    assert "takes effect the next time the offense plane starts" in txt
    assert "tier pill shows the tier actually in force" in txt


def test_ui_surfaces_the_settings_vs_pill_disagreement():
    """The UI must actually compute + show the disagreement (criterion 4), naming the pill as the truth."""
    js = _collapsed(APPJS)
    assert "surfaceSovereigntyTierDisagreement" in js, "the disagreement helper is gone from app.js"
    assert 'OFF("/api/governance")' in js, "the UI no longer reads the running (pill) tier to compare"
    # it must name the pill as the truthful one and point the operator at a restart (not only `vigil up`)
    assert "the Governance pill" in js
    assert "Restart it from the Status panel" in js
    assert "Until then the Governance pill is the truth" in js


def test_code_actually_reresolves_the_tier_on_restart():
    """The claim the docs/UI make is true in-tree: PlaneControl is wired to re-resolve the dynamic env
    (tier included) on restart, with the resolved-ok signalling function that lets it fail closed."""
    src = UIPROXY.read_text(encoding="utf-8")
    assert "def _resolve_offense_llm_env_result(" in src, "the resolved-ok resolver is gone"
    assert "env_resolver=_reresolve_offense_env" in src, "PlaneControl is no longer wired to re-resolve"
    # start_offense must re-resolve and fail closed (retain last-known-good on a resolver error)
    assert "self._last_dynamic_env" in src
    assert "self._env_resolver()" in src
