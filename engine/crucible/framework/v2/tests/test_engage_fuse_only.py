"""
Slice C2b — the SEEDLESS fusion-only engagement path (``engage.run_fusion_only`` / ``engage <slug>
--fuse-only``).

A cloud / Kubernetes / infra POSTURE run has no web seed URL: it runs ONLY the operator's declared
sensor fusion (``targets/<slug>/fusion.json``) and its deterministic promotion oracles, with NO crawl /
recon / scan. Doctrine under test:
  * fail-closed authorization: a tripped kill-switch OR a slug with no signed charter refuses;
  * with a charter + a real fusion.json, the fusion pass runs and its oracles promote FACTS — WITHOUT a
    seed (the web pass is skipped; report.target is an honest ``fusion://`` marker, nothing was crawled);
  * honest empty: an absent fusion.json yields 0 leads / 0 facts and never raises;
  * the CLI takes NO seed url with --fuse-only, and requires a seed without it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2 import engage as engage_mod
from framework.v2.engage import EngagementRefused, run_fusion_only

_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation
Signed: `tester`   Date: `2026-07-26`

## 2. In-scope systems
| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `10.0.0.5` | Declared host | Yes |

## 7. Posture
- [x] **TEST**
"""

# a sensitive datastore with encryption-at-rest DISABLED — the cloud-posture oracle promotes it to a FACT
# over the retained achieved state (no live cloud call).
_CLOUD_UNENCRYPTED = """
{"provider": "aws",
 "resources": [{"id": "s3/secrets", "kind": "datastore", "sensitive": true, "encrypted": false}]}
"""


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate per-slug paths to tmp and lay down a signed charter for 'alpha'."""
    from framework.v2.common import paths

    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    td = tmp_path / "alpha"
    td.mkdir(parents=True, exist_ok=True)
    (td / "charter.md").write_text(_CHARTER.format(slug="alpha"), encoding="utf-8")
    return tmp_path


def _write_fusion(tmp_path: Path, slug: str, tasks: list) -> None:
    (tmp_path / slug).mkdir(parents=True, exist_ok=True)
    (tmp_path / slug / "fusion.json").write_text(json.dumps({"tasks": tasks}), encoding="utf-8")


# ---- the fusion-only path runs fusion WITHOUT a seed ------------------------


def test_fuse_only_runs_fusion_and_promotes_a_fact_without_a_seed(_isolate) -> None:
    tmp_path = _isolate
    export = tmp_path / "alpha" / "cloud.json"
    export.write_text(_CLOUD_UNENCRYPTED, encoding="utf-8")
    _write_fusion(tmp_path, "alpha",
                  [{"sensor": "cloud_import", "args": {"inventory_file": str(export)}}])

    result = run_fusion_only("alpha")
    # nothing was crawled/audited — the report is an honest empty shell with a fusion:// marker
    assert result.report.target == "fusion://alpha"
    assert result.report.pages_crawled == 0 and result.report.active_findings == []
    # the fusion pass folded a LEAD and the cloud-posture oracle promoted a FACT (offline, over the export)
    assert result.fused_leads >= 1 and result.fused_facts >= 1
    assert result.world is not None and result.world.has_node("finding:cloud_posture:s3/secrets")


def test_fuse_only_no_fusion_manifest_is_honest_empty(_isolate) -> None:
    # charter present, but NO fusion.json -> an honest empty result (0 leads, 0 facts), never a raise
    result = run_fusion_only("alpha")
    assert result.fused_leads == 0 and result.fused_facts == 0
    assert result.report.target == "fusion://alpha"
    assert result.world is not None and result.world.all_nodes() == []


def test_fuse_only_empty_manifest_promotes_nothing(_isolate) -> None:
    tmp_path = _isolate
    _write_fusion(tmp_path, "alpha", [])   # a manifest with no tasks
    result = run_fusion_only("alpha")
    assert result.fused_leads == 0 and result.fused_facts == 0


# ---- fail-closed authorization ---------------------------------------------


def test_fuse_only_without_a_charter_is_refused(_isolate) -> None:
    with pytest.raises(EngagementRefused, match="charter"):
        run_fusion_only("no-charter-slug")


def test_fuse_only_with_a_present_but_unsigned_charter_is_refused(_isolate) -> None:
    # a charter that EXISTS but carries the unfilled `<name>` placeholder is NOT a signature — the
    # seedless preflight (the SOLE charter authority on this path) must refuse it exactly like a
    # missing charter (ethics.is_charter_signed rejects the placeholder). The distinct negative
    # control the C2b red-pen flagged: "no charter" and "present-but-unsigned" are different cases.
    slug = "unsigned-slug"
    (_isolate / slug).mkdir(parents=True, exist_ok=True)
    (_isolate / slug / "charter.md").write_text(
        "# charter\n\n## 1. Operator attestation\nSigned: `<name>`\n", encoding="utf-8")
    with pytest.raises(EngagementRefused, match="not signed"):
        run_fusion_only(slug)


def test_fuse_only_with_a_tripped_kill_switch_is_refused(_isolate) -> None:
    from framework.v2.authority import KillSwitch

    KillSwitch("alpha").trip("halt for test")
    with pytest.raises(EngagementRefused, match="kill-switch"):
        run_fusion_only("alpha")


def test_fuse_only_refusal_does_not_run_the_web_pass(_isolate, monkeypatch) -> None:
    # a fusion-only run must NEVER call run_engagement (the seed-dependent web pass) — refused or not.
    called = {"n": 0}
    monkeypatch.setattr(engage_mod, "run_engagement",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    run_fusion_only("alpha")
    assert called["n"] == 0


# ---- CLI: --fuse-only takes no seed; without it a seed is required ----------


def test_cli_fuse_only_runs_and_prints_summary(_isolate, capsys) -> None:
    tmp_path = _isolate
    export = tmp_path / "alpha" / "cloud.json"
    export.write_text(_CLOUD_UNENCRYPTED, encoding="utf-8")
    _write_fusion(tmp_path, "alpha",
                  [{"sensor": "cloud_import", "args": {"inventory_file": str(export)}}])
    rc = engage_mod.main(["alpha", "--fuse-only"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "fusion-only" in out and "oracle-promoted fact" in out


def test_cli_fuse_only_rejects_a_seed_url(_isolate, capsys) -> None:
    rc = engage_mod.main(["alpha", "https://target.example/", "--fuse-only"])
    assert rc == 2
    assert "no seed url" in capsys.readouterr().out.lower()


def test_cli_without_fuse_only_still_requires_a_seed(_isolate, capsys) -> None:
    rc = engage_mod.main(["alpha"])
    assert rc == 2
    assert "seed_url is required" in capsys.readouterr().out


def test_cli_fuse_only_honest_empty_note_when_no_manifest(_isolate, capsys) -> None:
    rc = engage_mod.main(["alpha", "--fuse-only"])
    assert rc == 0
    assert "honest empty" in capsys.readouterr().out
