"""S8 @-mentions (files + linked chats) + S9 live plan/hypothesis checklist. Reads files only."""
from __future__ import annotations
from pathlib import Path
APPJS = (Path(__file__).resolve().parents[2] / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")

def test_at_mentions_over_files_and_linked_chats():
    assert "function mentionSources()" in APPJS and "function currentMention()" in APPJS
    assert "kind: \"file\"" in APPJS and "kind: \"linked chat\"" in APPJS
    assert "/@([\\w.\\-]*)$/" in APPJS, "the @-token matcher is gone"
    assert 'input.addEventListener("input", updateMention)' in APPJS

def test_plan_hypothesis_checklist():
    assert '"Plan · hypotheses"' in APPJS, "the plan checklist header is gone"
    assert "chk-done" in APPJS and "chk-no" in APPJS and "chk-open" in APPJS, "per-item state icons missing"
    assert '" / " + hyps.length + " confirmed"' in APPJS, "no progress count"
