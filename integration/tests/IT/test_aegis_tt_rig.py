"""AEGIS Test-Tenant (TT) CI rig — the AS-1a acceptance, over real loopback sockets.

Drives the real ``aegis.gateway`` in its default read-only ``observe`` mode across two isolated test
tenants and asserts the three TT-CI properties:

  * Observe => the attack event is VISIBLE to TT-A (a small attack corpus fires CONFIRMED verdicts
    into TT-A's own monitoring feed), and observe NEVER blocks — every request still forwards (200).
  * A SAME-SHAPE benign baseline is recorded (the same endpoints/params with inert values forward
    cleanly and fire NOTHING — the negative control).
  * The cross-tenant control TT-B SEES NOTHING (its feed stays empty; it only ever got the baseline).

Plus the ``VIGIL_REQUIRE_TT_UIDS`` contract: when distinct uids are REQUIRED but unavailable the rig
FAILS (raises), it does not silently skip; and, where this runner can provision uids (root + useradd),
the whole acceptance runs again with each tenant in its OWN process under a DISTINCT uid.

FATAL-2: this is the ENGINE plane (it imports ``framework.v2.aegis`` — the gateway it drives — and
never ``sigil``); it is ``importorskip``-guarded and runs in the offense leg. Playwright is OUT of
scope here (advisory/optional per the slice).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.aegis.tt_rig",
                    reason="CRUCIBLE (offense) not importable here")

from framework.v2.aegis import cli as aegis_cli                    # noqa: E402
from framework.v2.aegis.tt_rig import (                            # noqa: E402
    ATTACK_CORPUS,
    BENIGN_CORPUS,
    TTUidsUnavailable,
    TenantUids,
    run_tt_acceptance,
    tt_uids_provisionable,
)

_EXPECTED_CLASSES = {"automated_access", "path_traversal_attempt", "sqli_attempt"}


def _assert_acceptance(result: dict) -> None:
    assert result["ok"] is True, json.dumps(result, indent=2, sort_keys=True)
    checks = result["checks"]
    assert checks["attack_event_visible_to_attack_tenant"] is True
    assert checks["benign_baseline_recorded"] is True
    assert checks["cross_tenant_control_sees_nothing"] is True
    assert checks["observe_never_blocked"] is True
    # TT-A's feed carries exactly the three proven attack classes; TT-B's carries nothing.
    a = result["tenants"]["tt-a"]
    b = result["tenants"]["tt-b"]
    assert {e["attack_class"] for e in a["attack_events"]} == _EXPECTED_CLASSES
    assert all(e["decision"] == "confirmed" and e["action"] == "observe" for e in a["attack_events"])
    assert b["attack_events"] == []
    # the recorded benign baseline: all forwarded 200, zero events from the same-shape benign corpus.
    assert a["baseline"]["events_after_baseline"] == 0
    assert a["baseline"]["all_forwarded_200"] is True
    assert b["baseline"]["all_forwarded_200"] is True
    # observe forwarded every attack (never blocked) — availability-first.
    assert all(d["status"] == 200 and d["forwarded"] is True for d in a["attack_detail"])


def test_observe_acceptance_in_process(tmp_path: Path) -> None:
    """Observe end-to-end (same-uid, the default CI leg): TT-A sees the event, benign baseline
    recorded, TT-B sees nothing."""
    result = run_tt_acceptance(tmp_path / "root", require_distinct_uids=False)
    assert result["mode"] == "in-process"
    _assert_acceptance(result)


def test_benign_corpus_is_same_shape_negative_control() -> None:
    """The benign corpus is the SAME SHAPE as the attack corpus (same carrier param, and same
    endpoint for the parameter-borne attacks) — so a clean baseline proves the detector keys on the
    proven attack, not on the request's shape."""
    assert len(ATTACK_CORPUS) == len(BENIGN_CORPUS)
    for attack, benign in zip(ATTACK_CORPUS, BENIGN_CORPUS):
        assert attack.param == benign.param          # same carrier shape (query param, or a bare path)
        if attack.param is not None:
            assert attack.endpoint == benign.endpoint  # same endpoint for a parameter-borne attack
        assert attack.expect_class is not None        # the attack fires a class ...
        assert benign.expect_class is None            # ... its same-shape twin fires nothing


def test_determinism_same_checks_on_repeat(tmp_path: Path) -> None:
    """The acceptance decision is a pure function of the feed contents: two runs agree on every
    check (no wall-clock / RNG on the decision path)."""
    r1 = run_tt_acceptance(tmp_path / "r1", require_distinct_uids=False)
    r2 = run_tt_acceptance(tmp_path / "r2", require_distinct_uids=False)
    assert r1["checks"] == r2["checks"]
    assert r1["expected_attack_classes"] == r2["expected_attack_classes"]


def test_distinct_uids_required_is_fail_not_skip(tmp_path: Path) -> None:
    """When distinct uids are REQUIRED but cannot be provisioned, the rig RAISES (a failure) — it
    never silently skips. Simulated here with an allocator that reports them unavailable, so the
    semantics are proved without needing root."""
    def _unavailable(_n: int) -> TenantUids:
        raise TTUidsUnavailable("stub: useradd/distinct-uids unavailable on this runner")

    with pytest.raises(TTUidsUnavailable):
        run_tt_acceptance(tmp_path / "root", require_distinct_uids=True, uid_allocator=_unavailable)


def test_cli_tt_acceptance_entry(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The ``vigil tt-acceptance``-style entry (``python3 -m framework.v2 aegis tt-acceptance``) runs
    the acceptance and exits 0, printing the JSON result."""
    rc = aegis_cli.main(["tt-acceptance", "--root", str(tmp_path / "cli-root")])
    out = capsys.readouterr().out
    assert rc == 0, out
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["mode"] == "in-process"


@pytest.mark.skipif(not tt_uids_provisionable(),
                    reason="distinct-uid TT path needs a root runner with useradd")
def test_observe_acceptance_distinct_uids(tmp_path: Path) -> None:
    """The SAME acceptance with each tenant in its OWN process under a DISTINCT uid — the cross-tenant
    isolation is then a real OS boundary, not just in-process separation."""
    result = run_tt_acceptance(tmp_path / "root", require_distinct_uids=True)
    assert result["mode"] == "distinct-uids"
    _assert_acceptance(result)
    uid_a = result["tenants"]["tt-a"]["uid"]
    uid_b = result["tenants"]["tt-b"]["uid"]
    assert isinstance(uid_a, int) and isinstance(uid_b, int)
    assert uid_a != uid_b != 0 and uid_a != 0   # distinct, non-root tenant uids


@pytest.mark.skipif(not tt_uids_provisionable(),
                    reason="distinct-uid TT path needs a root runner with useradd")
def test_cli_require_uids_runs_distinct(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The CLI entry honours --require-uids / VIGIL_REQUIRE_TT_UIDS (runs the distinct-uid path)."""
    rc = aegis_cli.main(["tt-acceptance", "--root", str(tmp_path / "root"), "--require-uids"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert json.loads(out)["mode"] == "distinct-uids"


def test_cli_require_uids_env_fails_when_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                     capsys: pytest.CaptureFixture[str]) -> None:
    """VIGIL_REQUIRE_TT_UIDS set + uids unprovisionable => the CLI entry FAILS (exit 2), not a skip.
    Simulated by forcing the provisioner to report unavailable, so it holds on any runner."""
    monkeypatch.setenv("VIGIL_REQUIRE_TT_UIDS", "1")

    def _unavailable(_n: int) -> TenantUids:
        raise TTUidsUnavailable("stub: unavailable")

    monkeypatch.setattr("framework.v2.aegis.tt_rig.provision_tenant_uids", _unavailable)
    rc = aegis_cli.main(["tt-acceptance", "--root", str(tmp_path / "root")])
    assert rc == 2
    assert "REQUIRED but unavailable" in capsys.readouterr().err
