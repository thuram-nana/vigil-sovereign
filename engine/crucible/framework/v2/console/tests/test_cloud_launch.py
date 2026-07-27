"""
Slice C2b — the console's seedless cloud / Kubernetes / infra POSTURE launch (``actions.launch_cloud``).

Doctrine under test (the launch only SPAWNS the already-gated engage --fuse-only; it cannot relax scope
nor bypass a gate):
  * a signed charter for the slug is REQUIRED (the gate) — no charter refuses;
  * an unknown mode / an unknown (or missing) cloud provider refuses;
  * the ``target`` is a cloud IDENTIFIER, never a seed — a URL, a CIDR, a path, or a shell metachar refuses;
  * the slug is path-safe — a traversal slug refuses (it can never escape targets/);
  * a valid launch writes a path-safe fusion.json with the RIGHT sensor task and spawns exactly
    ``engage <slug> --fuse-only --spine`` (argv list; the operator's label is NEVER on the command line);
  * an operator-authored fusion.json is respected (never clobbered).
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from framework.v2.console import actions


class _FakeProc:
    returncode = 0
    stdout = "engage alpha  (fusion-only, no web seed)\n"
    stderr = ""


class _SyncThread:
    """A Thread stand-in whose .start() runs the target INLINE — so the launcher's background work
    completes before launch_cloud returns, making meta.json deterministic (no read/write race)."""

    def __init__(self, target=None, daemon=None, **_kw) -> None:
        self._target = target

    def start(self) -> None:
        if self._target is not None:
            self._target()


@pytest.fixture
def cloud_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate per-slug paths + the console run dir to tmp, stub the subprocess spawn so no real python
    runs, and run the launcher's worker inline so the recorded cmd/meta is deterministic."""
    from framework.v2.common import paths

    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / "targets" / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / "targets" / slug / "charter.md")
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    monkeypatch.setattr(actions, "subprocess",
                        types.SimpleNamespace(run=lambda *a, **k: _FakeProc()))
    monkeypatch.setattr(actions, "threading", types.SimpleNamespace(Thread=_SyncThread))
    return tmp_path


def _charter(tmp_path: Path, slug: str) -> None:
    d = tmp_path / "targets" / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text("# charter\nSigned: tester\n", encoding="utf-8")


def _meta(tmp_path: Path, run_id: str) -> dict:
    return json.loads((tmp_path / ".console" / "runs" / run_id / "meta.json").read_text(encoding="utf-8"))


# ---- refusals ---------------------------------------------------------------


def test_unknown_mode_refused(cloud_env: Path) -> None:
    _charter(cloud_env, "acme")
    d = actions.launch_cloud("acme", "mainframe", "acct-1")
    assert "error" in d and "unknown assessment mode" in d["error"]


def test_cloud_needs_a_known_provider(cloud_env: Path) -> None:
    _charter(cloud_env, "acme")
    assert "provider" in actions.launch_cloud("acme", "cloud", "acct-1", provider="oraclecloud")["error"]
    assert "provider" in actions.launch_cloud("acme", "cloud", "acct-1", provider="")["error"]


def test_missing_charter_refused(cloud_env: Path) -> None:
    # no charter laid down for this slug -> the gate refuses BEFORE any spawn
    d = actions.launch_cloud("no-charter", "k8s", "prod-cluster")
    assert "error" in d and "charter" in d["error"]
    # and nothing was written / spawned
    assert not (cloud_env / "targets" / "no-charter" / "fusion.json").exists()


def test_present_but_unsigned_placeholder_charter_refused(cloud_env: Path) -> None:
    # a charter that EXISTS but carries the unfilled `<name>` placeholder is NOT a signature
    # (ethics.is_charter_signed rejects the placeholder) -> the console gate refuses it BEFORE any
    # spawn, exactly like a missing charter. This is the distinct negative control the red-pen flagged.
    d = cloud_env / "targets" / "acme"
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text("# charter\n\n## 1. Operator attestation\nSigned: `<name>`\n",
                                  encoding="utf-8")
    res = actions.launch_cloud("acme", "k8s", "prod-cluster")
    assert "error" in res and "charter" in res["error"]
    # fail-closed: no fusion.json written, no run spawned
    assert not (cloud_env / "targets" / "acme" / "fusion.json").exists()
    assert "run_id" not in res


def test_url_target_refused(cloud_env: Path) -> None:
    _charter(cloud_env, "acme")
    d = actions.launch_cloud("acme", "cloud", "https://evil.example/seed", provider="aws")
    assert "error" in d and "URL" in d["error"]


def test_cidr_target_refused(cloud_env: Path) -> None:
    _charter(cloud_env, "acme")
    d = actions.launch_cloud("acme", "infra", "10.0.0.0/8")
    assert "error" in d and "/" in d["error"]


def test_shell_metachar_target_refused(cloud_env: Path) -> None:
    _charter(cloud_env, "acme")
    for bad in ("acct; rm -rf /", "acct$(id)", "acct`id`", "acct|nc", "acct\nx"):
        d = actions.launch_cloud("acme", "k8s", bad)
        assert "error" in d, f"{bad!r} should be refused"


def test_traversal_slug_refused(cloud_env: Path) -> None:
    for bad in ("../../etc", "a/b", "..", ".", "with space", "x" * 80):
        d = actions.launch_cloud(bad, "cloud", "acct-1", provider="aws")
        assert "error" in d and "slug" in d["error"], f"{bad!r} should be refused"


def test_empty_target_refused(cloud_env: Path) -> None:
    _charter(cloud_env, "acme")
    assert "error" in actions.launch_cloud("acme", "cloud", "   ", provider="aws")


# ---- valid launches ---------------------------------------------------------


def test_valid_cloud_launch_writes_fusion_and_gated_cmd(cloud_env: Path) -> None:
    _charter(cloud_env, "acme-aws")
    d = actions.launch_cloud("acme-aws", "cloud", "123456789012", provider="aws")
    assert d["status"] == "running" and d["mode"] == "cloud" and d["slug"] == "acme-aws"
    assert d["provider"] == "aws" and d["stream"] == f"runs/{d['run_id']}"

    fusion = json.loads((cloud_env / "targets" / "acme-aws" / "fusion.json").read_text(encoding="utf-8"))
    tasks = fusion["tasks"]
    assert len(tasks) == 1 and tasks[0]["sensor"] == "cloud_import"
    inv = tasks[0]["args"]["inventory_file"]
    assert inv.endswith("/acme-aws/cloud-inventory.json")   # path-safe, under the slug's own target dir
    assert tasks[0]["args"]["provider"] == "aws"

    meta = _meta(cloud_env, d["run_id"])
    assert meta["cmd"] == [sys.executable, "-m", "framework.v2", "engage",
                           "acme-aws", "--fuse-only", "--spine"]
    # the operator's cloud label is NEVER on the argv (no argv-injection surface)
    assert "123456789012" not in " ".join(meta["cmd"])


def test_valid_k8s_launch_writes_kube_bench_task(cloud_env: Path) -> None:
    _charter(cloud_env, "cluster1")
    d = actions.launch_cloud("cluster1", "k8s", "prod-eks-1")
    assert d["status"] == "running" and d["mode"] == "k8s"
    fusion = json.loads((cloud_env / "targets" / "cluster1" / "fusion.json").read_text(encoding="utf-8"))
    t = fusion["tasks"][0]
    assert t["sensor"] == "kube_bench" and t["args"]["report"].endswith("/cluster1/kube-bench.json")


def test_valid_infra_launch_writes_declared_service_task(cloud_env: Path) -> None:
    _charter(cloud_env, "netposture")
    d = actions.launch_cloud("netposture", "infra", "10.0.0.5")
    assert d["status"] == "running" and d["mode"] == "infra"
    t = json.loads((cloud_env / "targets" / "netposture" / "fusion.json").read_text())["tasks"][0]
    assert t["sensor"] == "declared_service" and t["args"]["host"] == "10.0.0.5"
    assert t["args"]["services"] == []   # honest empty default the operator fills in


def test_existing_fusion_manifest_is_respected(cloud_env: Path) -> None:
    _charter(cloud_env, "acme")
    manifest = cloud_env / "targets" / "acme" / "fusion.json"
    manifest.write_text(json.dumps({"tasks": [{"sensor": "sbom_vuln", "args": {"report": "x"}}]}),
                        encoding="utf-8")
    d = actions.launch_cloud("acme", "cloud", "123456789012", provider="aws")
    assert d["status"] == "running"
    # the operator's manifest was NOT clobbered
    assert json.loads(manifest.read_text())["tasks"][0]["sensor"] == "sbom_vuln"
    assert _meta(cloud_env, d["run_id"])["wrote_fusion"] is False


def test_a_label_with_safe_punctuation_is_accepted(cloud_env: Path) -> None:
    # ARNs / subscription UUIDs / project ids use ':' '@' '.' '-' — all safe, none a separator
    _charter(cloud_env, "acme")
    for good in ("arn:aws:iam::123456789012:root", "my-project.dev", "sub_0a1b2c3d", "team@corp"):
        d = actions.launch_cloud("acme", "cloud", good, provider="aws")
        assert d.get("status") == "running", f"{good!r} should be accepted, got {d}"
