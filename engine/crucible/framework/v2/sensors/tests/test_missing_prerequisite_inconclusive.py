"""
W16-3 (#508) — a live cloud/K8s assessment WITHOUT its prerequisites must FAIL LOUDLY as an explicit
INCONCLUSIVE outcome that NAMES the missing prerequisite, NEVER a silent CLEAN.

The two undocumented prerequisites are AMBIENT read-only credentials and a provisioned egress scope
(``targets/<slug>/collector-hosts.txt``). For a product whose thesis is a SOUND NEGATIVE, a missing
prerequisite reported as "found nothing" is the worst failure mode. So a missing prerequisite mints a
structured INCONCLUSIVE ``ToolResult`` (``is_inconclusive`` True; ``output['missing_prerequisite']``
names it) that a verdict/report layer keys on to keep a not-assessed surface OUT of any clean negative.

THREE distinguishable outcomes are proven here:
  * INCONCLUSIVE — a prerequisite is missing → ``is_inconclusive`` True, ``ok`` False, prerequisite named.
  * ASSESSED (the NEGATIVE CONTROL) — the prerequisites ARE present → ``ok`` True, ``is_inconclusive``
    False. The gate is not a no-op that stamps every run inconclusive.
  * (the ASSESSED run then splits CLEAN vs FINDING downstream, at the oracle re-verify — covered by the
    end-to-end moto/binding tests in test_cloud_live.py / test_k8s_live.py.)

FAIL-BEFORE / PASS-AFTER: revert the sensor hunk and the missing-prerequisite return is a bare
``ToolResult(ok=False, note=...)`` with an EMPTY ``output`` — ``is_inconclusive`` is then False and the
outcome is indistinguishable from a plain failure/clean, so every ``*_is_inconclusive_*`` assertion here
fails. Proven by reverting only the hunk.

No SDK / network: boto3 and the kubernetes client are faked in-process (as the sibling fail-closed tests
already do), so every case — INCLUDING the assessed negative control — runs in the required crucible-core
CI job with no optional dependency installed.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

from framework.v2.sensors.base import INCONCLUSIVE, is_inconclusive
from framework.v2.sensors.cloud_live import CloudLiveSensor
from framework.v2.sensors.k8s_live import K8sLiveSensor


# ---------------------------------------------------------------------------
# 0. the shared primitive — is_inconclusive is total and does NOT fire on an assessed run
# ---------------------------------------------------------------------------


def test_is_inconclusive_is_total_and_specific():
    from framework.v2.agents.tools import ToolResult

    assert is_inconclusive(None) is False                                   # total on None
    assert is_inconclusive(ToolResult(ok=True, output={"export": "{}"})) is False   # assessed ok=True
    assert is_inconclusive(ToolResult(ok=False, note="plain failure")) is False     # plain failure (empty output)
    # a stray dict that merely resembles the marker but says it WAS assessed is not inconclusive
    assert is_inconclusive(ToolResult(ok=False, output={"status": INCONCLUSIVE, "assessed": True})) is False


# ---------------------------------------------------------------------------
# 1. cloud_live — no ambient credentials ⇒ INCONCLUSIVE, not clean
# ---------------------------------------------------------------------------


def _fake_boto3_no_credentials():
    """A boto3 whose default chain yields NO ambient credentials (the missing prerequisite)."""
    return SimpleNamespace(Session=lambda **_: SimpleNamespace(get_credentials=lambda: None))


class _Boom:
    """Any AWS client whose every call is denied — the collector degrades each datum away, never sinking."""

    def __getattr__(self, _name):
        def _raise(*_a, **_k):
            raise RuntimeError("AccessDenied")
        return _raise


def _fake_boto3_with_credentials():
    """A boto3 whose default chain YIELDS ambient credentials and a working STS identity — an ASSESSED
    account (empty, so the assessment is a genuine exercised-clean, not an inconclusive)."""
    sts = SimpleNamespace(get_caller_identity=lambda: {"Account": "123456789012"})

    class _Session:
        def __init__(self, **_):
            pass

        def get_credentials(self):
            return object()                              # truthy → ambient identity present

        def client(self, svc, **_kw):
            return sts if svc == "sts" else _Boom()      # STS works; the rest degrade (empty account)

    return SimpleNamespace(Session=_Session)


def test_cloud_live_missing_credentials_is_inconclusive_not_clean(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3_no_credentials())
    r = CloudLiveSensor().run({}, SimpleNamespace())
    # the fix: a structured, machine-readable INCONCLUSIVE outcome that NAMES the prerequisite
    assert is_inconclusive(r) is True                                       # NOT a clean negative
    assert r.ok is False
    assert r.output.get("status") == INCONCLUSIVE and r.output.get("assessed") is False
    assert "credential" in r.output.get("missing_prerequisite", "").lower()
    assert "INCONCLUSIVE" in r.note                                         # loud, human-facing
    assert "no ambient aws credentials" in r.note.lower()                   # names what was not assessed


def test_cloud_live_no_boto3_is_inconclusive(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)                         # import boto3 → raises
    r = CloudLiveSensor().run({}, SimpleNamespace())
    assert is_inconclusive(r) is True and r.ok is False
    assert r.output.get("missing_prerequisite") == "boto3"


def test_cloud_live_assessed_run_is_NOT_inconclusive(monkeypatch):
    """NEGATIVE CONTROL: with the prerequisite (ambient creds) PRESENT, the run is ASSESSED — ok=True and
    NOT inconclusive. Proves the gate is not a no-op that stamps every run inconclusive."""
    monkeypatch.delenv("CRUCIBLE_AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3_with_credentials())
    r = CloudLiveSensor().run({}, SimpleNamespace())
    assert r.ok is True, r.note
    assert is_inconclusive(r) is False                                      # an assessed clean, not inconclusive
    assert r.output.get("format") == "native"                              # it produced an inventory


# ---------------------------------------------------------------------------
# 2. k8s_live — no kubeconfig / apiserver not provisioned in collector-hosts.txt ⇒ INCONCLUSIVE
# ---------------------------------------------------------------------------


def _fake_k8s(*, load_ok: bool, host: str = "https://api.example:6443"):
    """A kubernetes client stand-in. ``load_ok`` decides whether ``load_kube_config`` succeeds; ``host``
    is what ``client.Configuration.get_default_copy().host`` reports (the apiserver the collector loaded)."""

    def _throw():
        raise RuntimeError("no config")

    conf = SimpleNamespace(host=host)
    client = SimpleNamespace(
        Configuration=SimpleNamespace(get_default_copy=lambda: conf),
        RbacAuthorizationV1Api=lambda: SimpleNamespace(
            list_cluster_role_binding=lambda: SimpleNamespace(items=[]),
            list_role_binding_for_all_namespaces=lambda: SimpleNamespace(items=[])))
    config = SimpleNamespace(
        load_incluster_config=_throw,
        load_kube_config=(lambda: None) if load_ok else _throw)
    return SimpleNamespace(client=client, config=config)


def test_k8s_live_no_cluster_config_is_inconclusive_not_clean(monkeypatch):
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.setenv("KUBECONFIG", "/nonexistent-kubeconfig")             # → empty egress_hosts, no ~/.kube fallback
    monkeypatch.setitem(sys.modules, "kubernetes", _fake_k8s(load_ok=False))
    r = K8sLiveSensor().run({}, SimpleNamespace())
    assert is_inconclusive(r) is True and r.ok is False
    assert "cluster credentials" in r.output.get("missing_prerequisite", "").lower()
    assert "INCONCLUSIVE" in r.note


def test_k8s_live_apiserver_not_provisioned_is_inconclusive_names_collector_hosts(monkeypatch):
    # kubeconfig LOADS, but the apiserver was never declared in collector-hosts.txt (empty egress scope)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.setenv("KUBECONFIG", "/nonexistent-kubeconfig")             # egress_hosts == ()
    monkeypatch.setitem(sys.modules, "kubernetes", _fake_k8s(load_ok=True))
    r = K8sLiveSensor().run({}, SimpleNamespace())
    assert is_inconclusive(r) is True and r.ok is False
    assert "collector-hosts.txt" in r.output.get("missing_prerequisite", "")
    assert "collector-hosts.txt" in r.note


def test_k8s_live_no_kubernetes_client_is_inconclusive(monkeypatch):
    monkeypatch.setitem(sys.modules, "kubernetes", None)                    # import kubernetes → raises
    r = K8sLiveSensor().run({}, SimpleNamespace())
    assert is_inconclusive(r) is True and r.ok is False
    assert r.output.get("missing_prerequisite") == "kubernetes client"


def test_k8s_live_assessed_run_is_NOT_inconclusive(monkeypatch):
    """NEGATIVE CONTROL: the apiserver IS the provisioned/declared egress host → the run is ASSESSED
    (ok=True, empty cluster) and NOT inconclusive."""
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")               # egress_hosts == ('10.0.0.1',)
    monkeypatch.delenv("KUBECONFIG", raising=False)
    monkeypatch.setitem(sys.modules, "kubernetes", _fake_k8s(load_ok=True, host="https://10.0.0.1:6443"))
    r = K8sLiveSensor().run({}, SimpleNamespace())
    assert r.ok is True, r.note
    assert is_inconclusive(r) is False                                      # assessed, not inconclusive
    assert r.output.get("provider") == "kubernetes"
