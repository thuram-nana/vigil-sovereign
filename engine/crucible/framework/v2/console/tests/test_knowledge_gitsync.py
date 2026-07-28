"""A6c — the console knowledge_gitsync action (shells the exec-only `vigil knowledge status|sync`).

Fail-closed: only status/sync (never push — the outward act stays a deliberate CLI act); and it refuses
cleanly when the `vigil` entrypoint is not resolvable. (The real git/secret-scan path is covered by the
integration knowledge_sync suite.)
"""

from __future__ import annotations

from framework.v2.console import actions


def test_knowledge_gitsync_rejects_a_bad_action():
    assert actions.knowledge_gitsync("push")["ok"] is False        # push stays a deliberate CLI act
    assert actions.knowledge_gitsync("")["ok"] is False
    assert actions.knowledge_gitsync("rm -rf")["ok"] is False


def test_knowledge_gitsync_fails_closed_without_a_vigil_bin(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    r = actions.knowledge_gitsync("status")
    assert r["ok"] is False and "resolvable" in r["error"]
