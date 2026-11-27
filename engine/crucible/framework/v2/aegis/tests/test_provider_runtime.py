"""AS-10a — the telemetry-PROVIDER RUNTIME (``framework.v2.aegis.provider_runtime``).

Proven here (strict acceptance):
  * INVENTORY (append-only) — ``build_provider_runtime_registry`` APPENDS the EDR / CloudTrail / IdP providers
    onto the AS-1a baseline; the baseline prefix is preserved (no central edit), the build is PURE (needs no
    flag, opens nothing) and DETERMINISTIC (byte-identical), and a duplicate id is refused (fail-closed).
  * HONEST CAPABILITY — every runtime provider declares the SAME intel-tier capability: class-5
    ``detected_without_enforcement`` + ``reported`` (it observes/alerts, never prevents, never verified).
  * DEFAULT-OFF / INERT — ``VIGIL_AEGIS_PROVIDER_RUNTIME`` is strict default-off; off ⇒ ``run_all`` runs NO
    source and opens nothing (the negative control: the SAME sources DO run once armed).
  * E2E over real sources — an armed runtime drives real CloudTrail + IdP readers, landing their LEADs through
    the real AS-9b receiver; the unified report tallies them.
  * SOURCE GATING + FAULT ISOLATION — a default-off source is SKIPPED inert (never asked to run); a single
    source's SYSTEMIC fault is CONTAINED (counted as that provider's error) so the others still run.
  * GATE-INVARIANCE / FATAL-2 — off the make-gate path (nothing under ``aegis/__init__`` imports it), adds no
    OracleKind, and importing it pulls in NO ``sigil`` module.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from vigil_core.protection_contract import (
    DuplicateProviderError,
    EffectVerification,
    OutcomeClass,
    baseline_provider_registry,
)

from framework.v2.aegis import provider_runtime as PR
from framework.v2.aegis.cloudtrail_source import CloudTrailSource
from framework.v2.aegis.edr_provider import EdrPollResult
from framework.v2.aegis.idp_source import IdpSource
from framework.v2.aegis.monitoring_report import domain_slug
from framework.v2.aegis.receiver import IngestReceiver

ORG, HOST = "org_a", "api.example.com"
REPORT_SECRET = b"R" * 32


def _receiver(spool=None):
    return IngestReceiver(spool or tempfile.mkdtemp(), org_id=ORG, host=HOST, report_secret=REPORT_SECRET,
                          require_mtls_or_hmac=False, enabled=True)


def _ct_delivery() -> str:
    return json.dumps({"Records": [{"eventVersion": "1.08", "eventSource": "signin.amazonaws.com",
                                    "eventName": "ConsoleLogin", "eventTime": "2024-05-01T12:00:00Z",
                                    "eventID": "ct-1"}]})


def _idp_delivery() -> str:
    return json.dumps([{"uuid": "idp-1", "published": "2024-05-01T12:00:00.000Z",
                        "eventType": "user.session.start", "outcome": {"result": "SUCCESS"}}])


class _RaisingSource:
    """A ProviderSource whose run_once raises — used to prove per-source fault isolation and the skip-inert path
    (its run_once must NOT be called when the source reports itself default-off)."""

    def __init__(self, provider_id: str, *, enabled: bool) -> None:
        self.provider_id = provider_id
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    def run_once(self) -> PR.SourceRunResult:
        raise RuntimeError("boom (a down broker / dead transport this cycle)")


# --- flag ------------------------------------------------------------------------------------------
def test_runtime_flag_strict_default_off(monkeypatch):
    monkeypatch.delenv(PR.PROVIDER_RUNTIME_ENV, raising=False)
    assert PR.provider_runtime_enabled() is False
    for off in ("0", "off", "", "nope", "2"):
        monkeypatch.setenv(PR.PROVIDER_RUNTIME_ENV, off)
        assert PR.provider_runtime_enabled() is False
    for on in ("1", "true", "YES", "On"):
        monkeypatch.setenv(PR.PROVIDER_RUNTIME_ENV, on)
        assert PR.provider_runtime_enabled() is True


# --- inventory (append-only, pure, deterministic) --------------------------------------------------
def test_inventory_appends_providers_append_only():
    base = baseline_provider_registry()
    reg = PR.build_provider_runtime_registry()
    # the baseline prefix is preserved EXACTLY (append-only; no central edit), then edr/cloudtrail/idp follow
    assert reg.provider_ids == base.provider_ids + ("edr", "cloudtrail", "idp")
    # the baseline singleton is untouched (a NEW registry is returned)
    assert base.provider_ids == ("sigil_gateway",)


def test_inventory_is_pure_and_deterministic_needs_no_flag(monkeypatch):
    monkeypatch.delenv(PR.PROVIDER_RUNTIME_ENV, raising=False)       # even with the runtime off, the build works
    a = PR.build_provider_runtime_registry()
    b = PR.build_provider_runtime_registry()
    assert a.model_dump_json() == b.model_dump_json()               # byte-identical (deterministic)


def test_runtime_providers_are_class5_reported():
    reg = PR.build_provider_runtime_registry()
    for pid in ("edr", "cloudtrail", "idp"):
        prov = reg.get(pid)
        assert prov is not None
        assert prov.outcome_classes == (OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,)   # observes, never prevents
        assert all(c.effect_verification == EffectVerification.REPORTED for c in prov.capabilities)  # never verified


def test_inventory_duplicate_provider_refused():
    # append-only fail-closed: building onto a base that already carries one of the runtime providers refuses.
    seeded = PR.build_provider_runtime_registry()
    with pytest.raises(DuplicateProviderError):
        PR.build_provider_runtime_registry(base=seeded)


def test_runtime_inventory_readable_when_off():
    rt = PR.ProviderRuntime([], enabled=False)
    assert rt.inventory().provider_ids == PR.build_provider_runtime_registry().provider_ids


# --- DEFAULT-OFF / inert ---------------------------------------------------------------------------
def test_default_off_runtime_is_inert_runs_no_source():
    # A source whose run_once would raise MUST NOT be touched when the runtime is default-off.
    rt = PR.ProviderRuntime([_RaisingSource("edr", enabled=True)], enabled=False)
    report = rt.run_all()
    assert report.enabled is False and report.results == []


def test_default_off_negative_control_armed_runtime_runs_sources():
    # NEGATIVE CONTROL: the SAME armed source IS run once the runtime is armed (so the off-gate is load-bearing).
    spool = tempfile.mkdtemp()
    src = PR.IngestProviderSource("idp", IdpSource(_receiver(spool), enabled=True), _idp_delivery)
    report = PR.ProviderRuntime([src], enabled=True).run_all()
    assert report.enabled is True and report.total_spooled == 1
    assert list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))


# --- E2E over real CloudTrail + IdP readers --------------------------------------------------------
def test_e2e_armed_runtime_drives_real_ingest_sources():
    ct_spool, idp_spool = tempfile.mkdtemp(), tempfile.mkdtemp()
    sources = [
        PR.IngestProviderSource("cloudtrail", CloudTrailSource(_receiver(ct_spool), enabled=True), _ct_delivery),
        PR.IngestProviderSource("idp", IdpSource(_receiver(idp_spool), enabled=True), _idp_delivery),
    ]
    report = PR.ProviderRuntime(sources, enabled=True).run_all()
    assert report.enabled is True
    assert report.armed_provider_ids == ("cloudtrail", "idp")
    assert report.total_spooled == 2 and report.total_errors == 0
    by_id = {r.provider_id: r for r in report.results}
    assert by_id["cloudtrail"].spooled == 1 and by_id["idp"].spooled == 1
    assert list((Path(ct_spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))
    assert list((Path(idp_spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))


# --- per-source gating + fault isolation -----------------------------------------------------------
def test_default_off_source_is_skipped_inert_not_run():
    # A source that reports itself default-off is recorded inert WITHOUT calling run_once (so it opens nothing).
    rt = PR.ProviderRuntime([_RaisingSource("cloudtrail", enabled=False)], enabled=True)
    report = rt.run_all()          # _RaisingSource.run_once would raise if called — it must not be
    assert len(report.results) == 1
    assert report.results[0].enabled is False and report.results[0].spooled == 0


def test_single_source_fault_is_contained_others_still_run():
    # A single source's SYSTEMIC fault is CONTAINED (counted as that provider's error); the provider AFTER it in
    # the pass still runs and lands its finding. Remove the per-source try/except guard and the good source below
    # would never run (the exception would abort run_all).
    spool = tempfile.mkdtemp()
    good = PR.IngestProviderSource("idp", IdpSource(_receiver(spool), enabled=True), _idp_delivery)
    report = PR.ProviderRuntime([_RaisingSource("edr", enabled=True), good], enabled=True).run_all()
    by_id = {r.provider_id: r for r in report.results}
    assert by_id["edr"].errors == 1 and "contained source fault" in by_id["edr"].note
    assert by_id["idp"].spooled == 1          # the source ordered AFTER the fault still ran
    assert report.total_spooled == 1 and report.total_errors == 1


# --- poll-source (EDR) result mapping --------------------------------------------------------------
def test_poll_source_maps_edr_result():
    # The PollProviderSource maps an EdrPollResult-shaped value: push_count -> spooled, plus skipped/dropped/
    # errors. A ``push`` sentinel list of length 2 gives push_count == 2.
    edr_result = EdrPollResult(tenant=ORG, enabled=True, pushed=[object(), object()],
                               skipped=3, dropped=1, errors=2)
    src = PR.PollProviderSource("edr", enabled=True, run=lambda: edr_result)
    assert src.enabled is True
    res = src.run_once()
    assert res.provider_id == "edr" and res.enabled is True
    assert res.spooled == 2 and res.skipped == 3 and res.dropped == 1 and res.errors == 2


def test_runtime_runs_a_mixed_poll_and_ingest_fleet():
    spool = tempfile.mkdtemp()
    edr = PR.PollProviderSource(
        "edr", enabled=True, run=lambda: EdrPollResult(tenant=ORG, enabled=True, pushed=[object()], skipped=1))
    idp = PR.IngestProviderSource("idp", IdpSource(_receiver(spool), enabled=True), _idp_delivery)
    report = PR.ProviderRuntime([edr, idp], enabled=True).run_all()
    assert report.armed_provider_ids == ("edr", "idp")
    assert report.total_spooled == 2          # 1 EDR push + 1 IdP lead
    assert {r.provider_id for r in report.results} == {"edr", "idp"}


# --- GATE-INVARIANCE + FATAL-2 ---------------------------------------------------------------------
def test_runtime_is_off_the_gate_path():
    import importlib

    importlib.import_module("framework.v2.aegis")
    import framework.v2.aegis as pkg
    assert not hasattr(pkg, "provider_runtime") or "provider_runtime" not in getattr(pkg, "__all__", [])


def test_import_pulls_in_no_sigil():
    import importlib
    import sys

    importlib.import_module("framework.v2.aegis.provider_runtime")
    assert not any(m == "sigil" or m.startswith("sigil.") for m in sys.modules)


def test_adds_no_new_oracle():
    from framework.v2.aegis.registry import verify_registration

    verify_registration()      # the AEGIS registry self-check still passes (no new OracleKind/class)
