"""The console's Token Budgets endpoints: the read provider (GET /api/token-budgets) and the setter
(POST /api/token-budgets). The setter is a pure config write to the shared vigil_core ledger — it can
change how loudly a tool is warned/throttled, but never whether a call is allowed (never-block)."""
from __future__ import annotations

import pytest

from framework.v2.console import api, actions


@pytest.fixture()
def budget_store(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_TOKEN_BUDGET_FILE", str(tmp_path / "token-budgets.json"))
    yield


def test_get_lists_the_registered_tools(budget_store):
    d = api.token_budgets_data()
    tools = {t["tool"] for t in d["tools"]}
    for expect in ("engine", "chat", "vulnfeed", "recon"):
        assert expect in tools
    assert "doctrine" in d and "throttle" in d["doctrine"].lower()


def test_set_edits_a_limit_and_it_persists(budget_store):
    r = actions.set_token_budget({"tool": "chat", "limit": 123, "mode": "warn"})
    assert r["ok"] is True
    chat = [t for t in r["tools"] if t["tool"] == "chat"][0]
    assert chat["limit"] == 123 and chat["mode"] == "warn"
    # a fresh GET reflects the operator's edit (it is stored, not hard-coded)
    again = [t for t in api.token_budgets_data()["tools"] if t["tool"] == "chat"][0]
    assert again["limit"] == 123


def test_set_rejects_block_mode_never_block(budget_store):
    r = actions.set_token_budget({"tool": "chat", "mode": "block"})
    assert r["ok"] is False
    assert "mode" in r["error"]                       # 'block' is not a valid mode: enforcement never blocks


def test_set_requires_a_tool_and_rejects_garbage(budget_store):
    assert actions.set_token_budget({})["ok"] is False
    assert actions.set_token_budget({"tool": "chat", "limit": "not-a-number"})["ok"] is False


def test_operator_can_add_a_custom_tool(budget_store):
    r = actions.set_token_budget({"tool": "my_api", "limit": 500, "mode": "throttle"})
    assert r["ok"] is True
    assert any(t["tool"] == "my_api" and t["limit"] == 500 for t in r["tools"])


def test_no_overclaim_every_registered_tool_is_metered():
    """Anti-overclaim guard (the red-pen finding that mattered most): every tool the UI advertises must
    have a REAL metering wire in the source tree, so a listed budget is never decorative. 'engine' is the
    default bucket — the kernel/think paths charge current_tool() with no explicit arg. A future tool
    added to DEFAULT_TOOLS without wiring it (or a removed wire) fails here."""
    import re
    from pathlib import Path
    from vigil_core import token_budget as tb

    # repo root: .../engine/crucible/framework/v2/console/tests/<this file>
    root = Path(__file__).resolve().parents[6]
    trees = ["engine/crucible/framework/v2", "integration/vigil_integration", "apps/sigil"]
    blobs: list[str] = []
    for t in trees:
        d = root / t
        if not d.is_dir():
            continue
        for p in d.rglob("*.py"):
            if "test" in p.name:
                continue
            try:
                blobs.append(p.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                pass
    src = "\n".join(blobs)
    assert src, "could not read any source to check tool metering"
    # Strip comments so a metering-verb literal that appears only in a COMMENT (e.g. an explanatory
    # `using_tool("vulnfeed")` note) can never false-pass the guard — a real WIRE must exist in code.
    src = "\n".join(re.sub(r"#.*$", "", ln) for ln in src.split("\n"))
    verbs = "record|throttle|clamp_output|record_usage|using_tool|tool_scope|current_tool"
    for tool in tb.DEFAULT_TOOLS:
        if tool == "engine":                     # the default bucket, wired via current_tool() (no arg)
            continue
        pat = re.compile(rf"(?:{verbs})\(\s*[\"']{re.escape(tool)}[\"']")
        assert pat.search(src), f"registered tool {tool!r} has NO metering wire — that is an overclaim"
