"""AS-7a — the §7 licence gate + advisory tracking.

The slice's TT-STG DONE condition is "Deploy-time ledger check passes": the shipped engine-pins
ledger is complete (a record for every deployed engine — R1), consistent (use_mode matches), and
policy-clean (every non-advisory record passes the §7 service-vs-distribution policy). This suite
asserts that, and — as NEGATIVE CONTROLS — the four failures §7 names explicitly:

  * GPL-3 in the kit (strong copyleft in distribution);
  * an Elastic-2.0 rule in a service image;
  * an unknown licence (fail closed unless ledgered);
  * a DRL-1.1 rule with no author (attribution duty unmet);

plus completeness (a deployed artefact with no record), consistency (a service engine shipped as
distribution), and the advisory channel (an advisory-only entry is tracked but never blocks).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.aegis.license_gate import (
    DeployItem,
    LicenseGate,
    LicenseRecord,
    bundle_digests,
    ledger_digest,
    load_ledger,
    main,
)
from framework.v2.aegis.license_policy import (
    Disposition,
    LicenseClass,
    LicensePolicy,
    UseMode,
)


@pytest.fixture(scope="module")
def gate() -> LicenseGate:
    return LicenseGate()


@pytest.fixture(scope="module")
def shipped() -> list[LicenseRecord]:
    return load_ledger()


# ---- the shipped ledger passes the deploy-time check (the TT-STG DONE condition) ----------------------

def test_shipped_ledger_passes_the_deploy_time_check(gate: LicenseGate, shipped: list[LicenseRecord]) -> None:
    result = gate.check(shipped)
    assert result.passed is True, [b.model_dump() for b in result.blocking]
    assert result.blocking == []
    assert result.checked == len(shipped)


def test_shipped_ledger_records_every_deployed_engine_r1(shipped: list[LicenseRecord]) -> None:
    # R1 — a record for every deployed engine (the §7 engines must all be present).
    arts = {r.artefact for r in shipped}
    for engine in ("coraza-v3", "caddy", "haproxy", "suricata"):
        assert engine in arts, f"{engine} missing from the ledger"


def test_shipped_ledger_tracks_obligations_as_non_blocking_advisories(
    gate: LicenseGate, shipped: list[LicenseRecord]
) -> None:
    result = gate.check(shipped)
    codes = {a.code for a in result.advisories}
    assert "obligation" in codes  # NOTICE / attribution / customer-terms duties are tracked
    assert all(a.blocking is False for a in result.advisories)


# ---- determinism: pure function of its input, no wallclock ------------------------------------------

def test_the_check_is_deterministic(gate: LicenseGate, shipped: list[LicenseRecord]) -> None:
    assert gate.check(shipped).model_dump_json() == gate.check(shipped).model_dump_json()


def test_ledger_digest_is_order_independent(shipped: list[LicenseRecord]) -> None:
    assert ledger_digest(shipped) == ledger_digest(list(reversed(shipped)))


def test_ledger_digest_moves_when_a_licence_changes(shipped: list[LicenseRecord]) -> None:
    before = ledger_digest(shipped)
    mutated = [r.model_copy(update={"license": "MIT"}) if r.artefact == "caddy" else r for r in shipped]
    assert ledger_digest(mutated) != before


def test_bundle_digests_cover_distributed_bundles(shipped: list[LicenseRecord]) -> None:
    digests = bundle_digests(shipped)
    assert set(digests) == {"aegis-kit", "pushed-rules"}
    assert all(isinstance(v, str) and len(v) == 64 for v in digests.values())


# ---- negative controls §7 names explicitly (each MUST block) ----------------------------------------

def test_gpl3_in_the_kit_is_blocked(gate: LicenseGate) -> None:
    ledger = [LicenseRecord(artefact="ha-kit", license="GPL-3.0", use_mode=UseMode.DISTRIBUTION)]
    result = gate.check(ledger)
    assert result.passed is False
    assert [b.code for b in result.blocking] == ["policy_denied"]


def test_gpl3_passes_in_service_use_fails_only_distribution(gate: LicenseGate) -> None:
    # §7: "GPL-3.0 fails only distribution" — the same licence is fine behind the service.
    svc = gate.check([LicenseRecord(artefact="gpl3", license="GPL-3.0", use_mode=UseMode.SERVICE)])
    dist = gate.check([LicenseRecord(artefact="gpl3", license="GPL-3.0", use_mode=UseMode.DISTRIBUTION)])
    assert svc.passed is True
    assert dist.passed is False


def test_elastic_rule_in_a_service_image_is_blocked(gate: LicenseGate) -> None:
    ledger = [LicenseRecord(artefact="es-rule", component_kind="rule",
                            license="Elastic-2.0", use_mode=UseMode.SERVICE)]
    result = gate.check(ledger)
    assert result.passed is False
    assert [b.code for b in result.blocking] == ["policy_denied"]


def test_unknown_licence_fails_closed(gate: LicenseGate) -> None:
    ledger = [LicenseRecord(artefact="mystery-engine", license="Weird-Custom-9.9", use_mode=UseMode.SERVICE)]
    result = gate.check(ledger)
    assert result.passed is False
    assert result.blocking[0].code == "policy_denied"
    assert result.blocking[0].policy is not None
    assert result.blocking[0].policy.license_class is LicenseClass.UNKNOWN


def test_drl_without_an_author_is_blocked(gate: LicenseGate) -> None:
    ledger = [LicenseRecord(artefact="sig-rule", component_kind="rule",
                            license="DRL-1.1", use_mode=UseMode.SERVICE)]  # no author
    result = gate.check(ledger)
    assert result.passed is False
    assert result.blocking[0].code == "policy_denied"


def test_drl_with_an_author_passes_with_a_tracked_attribution_duty(gate: LicenseGate) -> None:
    ledger = [LicenseRecord(artefact="sig-rule", component_kind="rule", license="DRL-1.1",
                            use_mode=UseMode.SERVICE, author="SigmaHQ contributors")]
    result = gate.check(ledger)
    assert result.passed is True
    assert any(a.code == "obligation" for a in result.advisories)


@pytest.mark.parametrize("lic", ["SSPL-1.0", "Elastic-2.0", "BUSL-1.1", "Commons-Clause", "CC-BY-NC-4.0"])
def test_denied_licences_fail_service_images(gate: LicenseGate, lic: str) -> None:
    result = gate.check([LicenseRecord(artefact="x", license=lic, use_mode=UseMode.SERVICE)])
    assert result.passed is False, f"{lic} must fail a service image"


def test_agpl_denies_service_only_when_modified(gate: LicenseGate) -> None:
    unmod = gate.check([LicenseRecord(artefact="agpl", license="AGPL-3.0", use_mode=UseMode.SERVICE)])
    mod = gate.check([LicenseRecord(artefact="agpl", license="AGPL-3.0",
                                    use_mode=UseMode.SERVICE, modified=True)])
    assert unmod.passed is True        # AGPL §13 does not bite unmodified service use
    assert mod.passed is False         # ...but it does once the engine is modified


# ---- completeness (R1) and consistency --------------------------------------------------------------

def test_a_deployed_artefact_with_no_record_fails_closed(gate: LicenseGate) -> None:
    # Completeness: deploy names suricata, but the ledger is empty.
    result = gate.check([], deploy=[DeployItem(artefact="suricata", use_mode=UseMode.SERVICE)])
    assert result.passed is False
    assert result.blocking[0].code == "missing_ledger_record"


def test_a_service_engine_shipped_as_distribution_is_inconsistent(
    gate: LicenseGate, shipped: list[LicenseRecord]
) -> None:
    # Consistency: coraza is ledgered service-use; deploying it in a distributed kit must block.
    result = gate.check(shipped, deploy=[DeployItem(artefact="coraza-v3", use_mode=UseMode.DISTRIBUTION)])
    assert result.passed is False
    assert result.blocking[0].code == "use_mode_inconsistent"


def test_a_duplicate_ledger_record_is_blocked(gate: LicenseGate) -> None:
    rec = LicenseRecord(artefact="dup", license="Apache-2.0", use_mode=UseMode.SERVICE)
    result = gate.check([rec, rec])
    assert result.passed is False
    assert any(b.code == "duplicate_record" for b in result.blocking)


def test_deploy_subset_only_checks_named_artefacts(gate: LicenseGate, shipped: list[LicenseRecord]) -> None:
    result = gate.check(shipped, deploy=[DeployItem(artefact="coraza-v3", use_mode=UseMode.SERVICE)])
    assert result.passed is True
    assert result.checked == 1


# ---- advisory channel: tracked but never blocking ---------------------------------------------------

def test_an_advisory_only_entry_is_tracked_but_non_blocking(gate: LicenseGate) -> None:
    # An advisory entry whose licence would otherwise DENY must NOT block the deploy; it is tracked.
    ledger = [
        LicenseRecord(artefact="good", license="Apache-2.0", use_mode=UseMode.SERVICE),
        LicenseRecord(artefact="under-review", license="Elastic-2.0", use_mode=UseMode.SERVICE,
                      advisory=True, notes="pending licence review"),
    ]
    result = gate.check(ledger)
    assert result.passed is True
    assert result.blocking == []
    tracked = [a for a in result.advisories if a.artefact == "under-review"]
    assert tracked and tracked[0].code == "policy_denied" and tracked[0].blocking is False


def test_the_same_entry_blocks_when_not_marked_advisory(gate: LicenseGate) -> None:
    # The control for the test above: drop the advisory flag and the gate must fail closed.
    ledger = [LicenseRecord(artefact="under-review", license="Elastic-2.0", use_mode=UseMode.SERVICE)]
    assert gate.check(ledger).passed is False


# ---- the policy classifier ------------------------------------------------------------------------

def test_policy_classifies_known_families_and_fails_unknown_closed() -> None:
    policy = LicensePolicy.load()
    assert policy.classify("Apache-2.0") is LicenseClass.PERMISSIVE
    assert policy.classify("GPL-3.0") is LicenseClass.STRONG_COPYLEFT
    assert policy.classify("AGPL-3.0") is LicenseClass.NETWORK_COPYLEFT
    assert policy.classify("DRL-1.1") is LicenseClass.ATTRIBUTION
    assert policy.classify("apache-2.0") is LicenseClass.PERMISSIVE  # case-insensitive
    assert policy.classify("not-a-real-licence") is LicenseClass.UNKNOWN
    assert policy.classify("") is LicenseClass.UNKNOWN


def test_permissive_service_use_is_a_clean_allow() -> None:
    policy = LicensePolicy.load()
    finding = policy.evaluate(LicenseRecord(artefact="c", license="Apache-2.0", use_mode=UseMode.SERVICE))
    assert finding.allowed is True
    assert finding.disposition is Disposition.ALLOW
    assert finding.obligation is None


# ---- the deploy-time entry point ------------------------------------------------------------------

def test_main_returns_zero_on_the_clean_shipped_ledger(capsys: pytest.CaptureFixture[str]) -> None:
    assert main() == 0
    assert '"passed": true' in capsys.readouterr().out


# ---- the human-readable ledger must not drift from the machine ledger ------------------------------

def test_third_party_doc_lists_every_ledgered_artefact(shipped: list[LicenseRecord]) -> None:
    doc = (Path(__file__).resolve().parents[1] / "THIRD-PARTY-ENGINES.md").read_text(encoding="utf-8")
    for record in shipped:
        assert f"`{record.artefact}`" in doc, f"{record.artefact} is ledgered but missing from THIRD-PARTY-ENGINES.md"
