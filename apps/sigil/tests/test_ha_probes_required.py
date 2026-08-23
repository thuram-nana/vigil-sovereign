"""W6-2 — Dockerfile HEALTHCHECKs + REAL k8s liveness/readiness probes wired to /readyz + /healthz.

The pre-fix defect (issue #453): the k8s probes did a shallow ``GET /`` on the STATIC bundle, so a proxy
whose sovereign backend is dead stayed Ready; the single-writer sovereign StatefulSet — the one workload
where a wedged process is most dangerous — had NO liveness probe at all; and no Dockerfile declared a
HEALTHCHECK. This suite pins the fix and fails on a tree without it.

Each behavioural assertion is paired with a NEGATIVE CONTROL in the SAME run: a deliberately-broken
manifest/Dockerfile is REJECTED by the exact checker (``tools/ha/require_probes.py``) that accepts the real
one — proving the gate is not a rubber stamp. These are pure file/logic checks (stdlib + PyYAML + the gate
module — no sigil/offense imports, no live cluster), so they run in the required ``sigil-governor`` CI job
that executes the whole ``apps/sigil/tests/`` directory. The readyz endpoint's OWN behaviour (503 when the
dependency is down) is proved separately by the W6-1 per-server suites; this suite proves the probes are
WIRED to that endpoint and that no workload ships without both.
"""
from __future__ import annotations

import copy
import re
import sys
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[3]              # apps/sigil/tests -> apps/sigil -> apps -> repo
sys.path.insert(0, str(_REPO / "tools" / "ha"))
import require_probes as rp  # noqa: E402  (path injected above; the module IS the gate under test)

_K8S = _REPO / "infra" / "ha" / "k8s"


# --------------------------------------------------------------------------------------------------------
# 1. Every workload ships BOTH probes (+ negative control).
# --------------------------------------------------------------------------------------------------------

def test_every_workload_declares_both_probes():
    workloads = rp.iter_workloads(_K8S)
    assert workloads, f"no Deployment/StatefulSet workloads found under {_K8S}"
    for path, doc, _app in workloads:
        ok, why = rp.check_workload_probes(doc)
        assert ok, f"{path.name}: {why}"


def test_no_workload_ships_without_both_probes_via_require():
    """The whole gate over the real tree — the single call the deploy preflight makes — must not raise."""
    rp.require(_K8S, _REPO)


def test_missing_liveness_is_rejected_negative_control():
    """NEGATIVE CONTROL: strip the liveness probe off a real workload — the SAME checker now refuses it."""
    _, doc, _ = next(iter(rp.iter_workloads(_K8S)))
    assert rp.check_workload_probes(doc)[0], "precondition: the real workload passes"
    broken = copy.deepcopy(doc)
    for c in rp.serving_containers(broken):
        c.pop("livenessProbe", None)
    ok, why = rp.check_workload_probes(broken)
    assert not ok and "livenessProbe" in why, why


def test_missing_readiness_is_rejected_negative_control():
    _, doc, _ = next(iter(rp.iter_workloads(_K8S)))
    broken = copy.deepcopy(doc)
    for c in rp.serving_containers(broken):
        c.pop("readinessProbe", None)
    ok, why = rp.check_workload_probes(broken)
    assert not ok and "readinessProbe" in why, why


# --------------------------------------------------------------------------------------------------------
# 2. The single-writer sovereign StatefulSet specifically gains a liveness probe (the cited defect).
# --------------------------------------------------------------------------------------------------------

def _workload(app: str) -> dict:
    for _p, doc, a in rp.iter_workloads(_K8S):
        if a == app:
            return doc
    raise AssertionError(f"no workload with app={app!r} in {_K8S}")


def test_sovereign_statefulset_has_a_liveness_probe():
    """The exact evidence in #453: 'no liveness probe at all on the single-writer sovereign StatefulSet'."""
    doc = _workload("vigil-sovereign")
    assert doc.get("kind") == "StatefulSet"
    containers = rp.serving_containers(doc)
    assert containers, "the sovereign writer must have a serving container"
    for c in containers:
        assert "livenessProbe" in c, f"sovereign container {c.get('name')!r} still has no livenessProbe"


# --------------------------------------------------------------------------------------------------------
# 3. VIGIL-owned workloads are wired to /readyz (readiness) + /healthz (liveness) — never the shallow GET /.
# --------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("app", rp.VIGIL_OWNED_APPS)
def test_vigil_owned_workload_wired_to_readyz_and_healthz(app):
    doc = _workload(app)
    ok, why = rp.check_vigil_wiring(doc)
    assert ok, f"{app}: {why}"
    # And concretely: readiness path is /readyz, liveness path is /healthz, on the serving port.
    for c in rp.serving_containers(doc):
        rk, rpath, rport = rp.probe_target(c.get("readinessProbe"))
        lk, lpath, lport = rp.probe_target(c.get("livenessProbe"))
        assert (rk, rpath) == ("httpGet", "/readyz"), f"{app} readiness = {rk} {rpath}"
        assert (lk, lpath) == ("httpGet", "/healthz"), f"{app} liveness = {lk} {lpath}"
        assert rport in rp._container_ports(c) and lport in rp._container_ports(c)


def test_shallow_root_readiness_is_rejected_negative_control():
    """NEGATIVE CONTROL: revert a VIGIL-owned readiness probe to the pre-fix shallow ``GET /`` — the wiring
    checker must reject it (a proxy whose backend is dead would otherwise stay Ready)."""
    doc = copy.deepcopy(_workload("vigil-proxy"))
    assert rp.check_vigil_wiring(doc)[0], "precondition: the real proxy passes"
    for c in rp.serving_containers(doc):
        c["readinessProbe"]["httpGet"]["path"] = "/"
    ok, why = rp.check_vigil_wiring(doc)
    assert not ok and "SHALLOW" in why, why


def test_wrong_liveness_endpoint_is_rejected_negative_control():
    """NEGATIVE CONTROL: point liveness at /readyz (a dependency outage would then kill an otherwise-healthy
    process) — the wiring checker requires liveness to be /healthz and refuses it."""
    doc = copy.deepcopy(_workload("vigil-sovereign"))
    for c in rp.serving_containers(doc):
        c["livenessProbe"]["httpGet"]["path"] = "/readyz"
    ok, why = rp.check_vigil_wiring(doc)
    assert not ok and "/healthz" in why, why


# --------------------------------------------------------------------------------------------------------
# 4. Shipped VIGIL server Dockerfiles declare a HEALTHCHECK (+ negative control).
# --------------------------------------------------------------------------------------------------------

def test_shipped_server_dockerfiles_declare_a_healthcheck():
    for rel, expect in rp.SERVER_DOCKERFILES.items():
        p = _REPO / rel
        assert p.is_file(), f"shipped server Dockerfile missing: {rel}"
        ok, why = rp.check_dockerfile(p.read_text(encoding="utf-8"), expect)
        assert ok, f"{rel}: {why}"


def test_aegis_healthcheck_exercises_readyz():
    hc = rp.dockerfile_healthcheck((_REPO / "engine/crucible/framework/v2/aegis/Dockerfile").read_text("utf-8"))
    assert hc is not None and "/readyz" in hc, f"AEGIS gateway HEALTHCHECK must exercise /readyz: {hc}"


def test_egress_gateway_healthcheck_is_a_tcp_connect():
    """The egress forward proxy has no /readyz (it is a CONNECT proxy); its HEALTHCHECK is a TCP connect to
    the listening bind — the same readiness surface infra/docker/docker-compose.yml probes."""
    hc = rp.dockerfile_healthcheck((_REPO / "gateway/Dockerfile").read_text("utf-8"))
    assert hc is not None, "egress gateway Dockerfile must declare a HEALTHCHECK"
    assert any(tok in hc for tok in ("create_connection", "nc ", "/dev/tcp")), hc


def test_missing_healthcheck_is_rejected_negative_control():
    """NEGATIVE CONTROL: a Dockerfile with no HEALTHCHECK (or one disabled via ``HEALTHCHECK NONE``) is
    rejected by the same checker that accepts the real ones."""
    assert rp.check_dockerfile("FROM scratch\nCMD [\"x\"]\n", "readyz")[0] is False
    assert rp.check_dockerfile("FROM x\nHEALTHCHECK NONE\n", "tcp")[0] is False
    # and a HEALTHCHECK that does not actually hit /readyz is rejected for a readyz-expecting image:
    ok, why = rp.check_dockerfile("FROM x\nHEALTHCHECK CMD curl -f http://127.0.0.1:8080/ || exit 1\n", "readyz")
    assert not ok and "/readyz" in why, why


# --------------------------------------------------------------------------------------------------------
# 5. The deploy path RUNS the gate before applying (structure), mirroring the NetworkPolicy preflight.
# --------------------------------------------------------------------------------------------------------

def test_deploy_script_runs_the_probe_gate_before_apply():
    deploy = _REPO / "tools" / "ha" / "deploy.sh"
    assert deploy.exists(), f"missing {deploy}"
    txt = deploy.read_text(encoding="utf-8")
    code = "\n".join(ln for ln in txt.splitlines() if not ln.lstrip().startswith("#"))
    gate_at = code.find("require_probes.py")
    apply_at = code.find("kubectl apply")
    assert gate_at != -1, "deploy.sh must run the require_probes.py preflight"
    assert apply_at != -1, "deploy.sh must apply the stack"
    assert gate_at < apply_at, "the probe preflight must run BEFORE `kubectl apply`"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
