"""PCR / W3 — the batch remediation campaign + signed hash-chained ledger. Pure (framework-free: campaign.py
imports only vigil_core), so it runs in both CI legs. The load-bearing property: the ledger records the TRUE
per-finding status and any altered/dropped/reordered/inserted entry breaks verification."""
from __future__ import annotations

import types

import pytest

from vigil_core import generate_keypair
from vigil_integration.remediation.campaign import (
    rank_findings, run_campaign, build_ledger, verify_ledger, trust_root_from_pubkeys,
    STATUS_ATTESTED, STATUS_VERIFIED, STATUS_DEGRADED, STATUS_FAILED,
)


def _f(ref, sev="high", source="daa:R", target="a/b.py:1", bug="X"):
    return types.SimpleNamespace(ref=ref, severity=sev, source=source, target=target, bug_class=bug)


def _r(status, suite_ran=False, tests_passed=None):
    return types.SimpleNamespace(status=status, suite_ran=suite_ran, tests_passed=tests_passed,
                                 reason="", patched_paths=[])


# ---------- ranking / dedupe ----------
def test_rank_orders_by_severity_then_ref():
    fs = [_f("z", "low"), _f("a", "critical"), _f("m", "high")]
    assert [f.ref for f in rank_findings(fs, dedupe=False)] == ["a", "m", "z"]


def test_dedupe_by_rule_and_file_keeps_highest_severity():
    fs = [_f("r1", "high", source="daa:R", target="svc/x.py:5"),
          _f("r2", "low", source="daa:R", target="svc/x.py:9"),    # same rule+file → dropped
          _f("r3", "high", source="daa:S", target="svc/x.py:1")]   # different rule → kept
    refs = [f.ref for f in rank_findings(fs)]
    assert "r1" in refs and "r3" in refs and "r2" not in refs


# ---------- run_campaign statuses ----------
def test_campaign_statuses_and_attest_only_on_verified():
    fs = [_f("v", source="daa:V"), _f("f", source="daa:F"), _f("d", source="daa:D"), _f("a", source="daa:A")]
    def fix_one(f):
        return {"v": _r("verified-no-pr"), "f": _r("build-failed"),
                "d": _r("no-patch-proposed"), "a": _r("verified-no-pr")}[f.ref]
    attested_refs = []
    def attest_one(f, result):
        attested_refs.append(f.ref)
        return "attestation MINTED [vuln-gone] -> /tmp/x.json (verify offline: ...)" if f.ref == "a" else None
    camp = run_campaign(fs, fix_one=fix_one, attest_one=attest_one)
    by = {e["ref"]: e["status"] for e in camp["entries"]}
    assert by["a"] == STATUS_ATTESTED and by["v"] == STATUS_VERIFIED
    assert by["f"] == STATUS_FAILED and by["d"] == STATUS_DEGRADED
    assert set(attested_refs) == {"v", "a"}            # attest_one called ONLY on verified-no-pr
    assert camp["counts"] == {STATUS_ATTESTED: 1, STATUS_VERIFIED: 1, STATUS_DEGRADED: 1, STATUS_FAILED: 1}


def test_campaign_a_raising_fix_is_failed_not_a_crash():
    def fix_one(f):
        raise RuntimeError("boom")
    camp = run_campaign([_f("x")], fix_one=fix_one)
    assert camp["entries"][0]["status"] == STATUS_FAILED and "boom" in camp["entries"][0]["reason"]


def test_campaign_max_findings_caps_and_counts_skipped():
    fs = [_f(f"r{i}", "high", source=f"daa:{i}") for i in range(5)]
    camp = run_campaign(fs, fix_one=lambda f: _r("verified-no-pr"), max_findings=2)
    assert camp["total"] == 2 and camp["skipped"] == 3


# ---------- the signed, hash-chained ledger ----------
def _ledger(entries, kp):
    return build_ledger(entries, slug="s", signers=[("k1", kp.private_key_b64)])


def test_ledger_round_trip_verifies():
    kp = generate_keypair()
    camp = run_campaign([_f("v"), _f("f", source="daa:S")],
                        fix_one=lambda f: _r("verified-no-pr") if f.ref == "v" else _r("build-failed"))
    led = _ledger(camp["entries"], kp)
    ok, why = verify_ledger(led, trust_root=trust_root_from_pubkeys({"k1": kp.public_key_b64}))
    assert ok, why


def test_ledger_unsigned_is_refused():
    with pytest.raises(ValueError, match="UNSIGNED"):
        build_ledger([{"ref": "x"}], slug="s", signers=[])


def test_ledger_tamper_drop_reorder_all_fail():
    kp = generate_keypair(); tr = trust_root_from_pubkeys({"k1": kp.public_key_b64})
    entries = run_campaign([_f("a"), _f("b", source="daa:S"), _f("c", source="daa:T")],
                           fix_one=lambda f: _r("verified-no-pr"))["entries"]
    led = _ledger(entries, kp)
    # (1) alter an entry's content after signing
    t1 = {**led, "entries": [{**led["entries"][0], "status": "attested"}] + led["entries"][1:]}
    assert verify_ledger(t1, trust_root=tr)[0] is False
    # (2) drop the last entry (chain length mismatch)
    t2 = {**led, "entries": led["entries"][:-1]}
    assert verify_ledger(t2, trust_root=tr)[0] is False
    # (3) reorder entries (chain links break)
    t3 = {**led, "entries": list(reversed(led["entries"]))}
    assert verify_ledger(t3, trust_root=tr)[0] is False
    # (4) wrong trust root → head signature fails
    other = generate_keypair()
    assert verify_ledger(led, trust_root=trust_root_from_pubkeys({"k1": other.public_key_b64}))[0] is False
    # (5) malformed input → False, never a crash
    assert verify_ledger({"schema": "nope"}, trust_root=tr)[0] is False


def test_cli_remediate_campaign_verb_arg_guard(tmp_path):
    pytest.importorskip("framework")   # importing the CLI pulls the offense engine
    import types as _t
    from vigil_integration import cli
    ns = _t.SimpleNamespace(target_repo="", from_spine="s", repo_base_dir=str(tmp_path))
    assert cli._cmd_remediate_campaign(ns) == 2      # missing --target-repo → hard refusal
    ns2 = _t.SimpleNamespace(target_repo=str(tmp_path), from_spine="", repo_base_dir=str(tmp_path))
    assert cli._cmd_remediate_campaign(ns2) == 2     # missing --from-spine → hard refusal
