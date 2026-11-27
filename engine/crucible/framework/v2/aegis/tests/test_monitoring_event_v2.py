"""AEGIS AS-3b — v2 EMISSION: the gateway emits each verdict as an AS-2b ``aegis_event`` v2 record,
HYGIENE-CLEAN (AS-2e — no raw IP / seeded secret), DETERMINISTIC (monotonic seq + content-addressed
event_id, no wall-clock / RNG), and FAIL-CLOSED (a malformed / over-size / leaking event is dropped,
never emitted raw). Additive + default-OFF: v2 records land in a DISTINCT ``incoming_v2/`` subtree the
v1 drain never reads, so enabling v2 can never regress the v1 drain."""
from __future__ import annotations

import hashlib
import hmac
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from vigil_core.aegis_schemas import EVENT_V2_SCHEMA, AegisEventV2, OutcomeClass

from framework.v2.aegis import monitoring_event_v2 as E
from framework.v2.aegis import monitoring_report as R

SECRET = b"s" * 32


def _v(decision="confirmed", cls="sqli_attempt", action="observe", conf=0.97, cert=None,
       prov="grounded:aegis:x", contributing=None):
    # A verdict-shaped object carrying request-side detail the EMISSION must NEVER leak (path/body/actor).
    return SimpleNamespace(decision=decision, attack_class=cls, action=action, confidence=conf,
                           certificate=cert, provenance=prov,
                           contributing=list(contributing or []),
                           path="/secret?token=abc", body="password=hunter2", actor="203.0.113.9")


def _mac_ok_v2(env, secret=SECRET):
    want = hmac.new(secret, E.EVENT_V2_DOMAIN + env["body"].encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, env["mac"])


# ---- the record is AS-2b v2, metadata only --------------------------------------------------------------
def test_build_conforms_to_aegis_event_v2_schema_and_is_metadata_only():
    ev = E.build_event_v2(_v(cert={"oracle": "x"}, contributing=["sqli_boolean_oracle"]),
                          org_id="org_a", host="apme.cm", instance_id="gw1", epoch=4, seq=7)
    assert isinstance(ev, AegisEventV2)
    # round-trips through the shared AS-2b schema (extra='forbid' etc.), proving conformance by construction.
    assert AegisEventV2.parse(ev.model_dump(mode="json", by_alias=True)).digest() == ev.digest()
    blob = ev.canonical_bytes().decode("utf-8")
    for leak in ("secret?token", "hunter2", "203.0.113.9", "/secret", "password"):
        assert leak not in blob
    assert ev.schema_id == EVENT_V2_SCHEMA and ev.provenance_tier == "grounded"
    assert len(ev.certificate_sha256) == 64 and ev.rule_refs == ["sqli_boolean_oracle"]
    assert ev.instance_id == "gw1" and ev.epoch == 4 and ev.seq == 7


def test_event_id_is_a_deterministic_content_digest_not_random():
    a = E.build_event_v2(_v(), org_id="org_a", host="apme.cm", instance_id="gw", epoch=2, seq=5)
    b = E.build_event_v2(_v(), org_id="org_a", host="apme.cm", instance_id="gw", epoch=2, seq=5)
    assert a.event_id == b.event_id and a.canonical_bytes() == b.canonical_bytes()   # byte-identical, no RNG
    # a different monotonic seq is a different logical event -> a different stable id (ordering carries it).
    c = E.build_event_v2(_v(), org_id="org_a", host="apme.cm", instance_id="gw", epoch=2, seq=6)
    assert c.event_id != a.event_id


def test_no_wall_clock_in_the_body_only_seq_orders():
    # v1 carried a wall-clock ts + a random report_id; v2 carries NEITHER — the body's only time-like field is seq.
    ev = E.build_event_v2(_v(), org_id="org_a", host="apme.cm", instance_id="gw", epoch=1, seq=3)
    body = json.loads(ev.canonical_bytes())
    assert "ts" not in body and "report_id" not in body and body["seq"] == 3


# ---- seal / MAC round-trip + domain separation ----------------------------------------------------------
def test_seal_mac_roundtrip_tamper_and_wrong_secret():
    env = E.seal_event_v2(E.build_event_v2(_v(), org_id="org_a", host="apme.cm", instance_id="gw",
                                           epoch=0, seq=1), SECRET)
    assert env["schema"] == EVENT_V2_SCHEMA and _mac_ok_v2(env)
    body = json.loads(env["body"]); body["org_id"] = "org_b"
    assert not _mac_ok_v2({**env, "body": json.dumps(body, sort_keys=True, separators=(",", ":"))})
    assert not _mac_ok_v2(env, secret=b"t" * 32)


def test_v2_domain_is_separated_from_v1_so_a_v1_mac_never_verifies_a_v2_body():
    ev = E.build_event_v2(_v(), org_id="org_a", host="apme.cm", instance_id="gw", epoch=0, seq=1)
    env = E.seal_event_v2(ev, SECRET)
    v1_mac = hmac.new(SECRET, R.REPORT_DOMAIN + env["body"].encode("utf-8"), hashlib.sha256).hexdigest()
    assert v1_mac != env["mac"]          # the domain tag differs -> cross-schema confusion is impossible


@pytest.mark.parametrize("bad", [b"", b"short", "not-bytes", None])
def test_seal_secret_must_be_bytes_and_long_enough(bad):
    ev = E.build_event_v2(_v(), org_id="o", host="apme.cm", instance_id="gw", epoch=0, seq=1)
    with pytest.raises(ValueError):
        E.seal_event_v2(ev, bad)
    with pytest.raises(ValueError):
        E.EventV2Reporter("/tmp/x", org_id="o", host="apme.cm", instance_id="gw", secret=bad)


# ---- AS-2e HYGIENE: the negative control ----------------------------------------------------------------
def test_hygiene_redacts_a_raw_ip_and_a_seeded_secret_in_the_emitted_record(tmp_path):
    CANARY = "AEGIS-CANARY-SECRET-sentinel"
    # a verdict whose rule refs embed a RAW client IP and whose attack_class embeds the seeded canary secret.
    verdict = _v(cls=f"anomaly-{CANARY}", contributing=["rule@203.0.113.9", "scan from 2001:db8::1 host"])
    rp = E.EventV2Reporter(tmp_path, org_id="org_a", host="apme.cm", instance_id="gw", secret=SECRET,
                           redact_literals=(CANARY,), now_fn=lambda: 100.0)
    rp(verdict)
    assert rp.written == 1 and rp.leaked_dropped == 0          # POSITIVE: redacted, so still emitted
    env = json.loads(next((tmp_path / E.V2_INCOMING).glob("*.json")).read_bytes())
    body = env["body"]
    assert "203.0.113.9" not in body and "2001:db8::1" not in body      # NEGATIVE: no raw IP
    assert CANARY not in body                                            # NEGATIVE: no seeded secret
    assert "<ip>" in body and "<redacted>" in body                      # the scrubbed placeholders are present
    assert E.is_hygiene_clean(body, redact_literals=(CANARY,))


def test_is_hygiene_clean_flags_a_raw_ip_or_secret():
    assert E.is_hygiene_clean("rule_refs: clean", redact_literals=("S3CRET",))
    assert not E.is_hygiene_clean("saw 10.0.0.5 inbound", redact_literals=())
    assert not E.is_hygiene_clean("fe80::1 link-local", redact_literals=())
    assert not E.is_hygiene_clean("token=S3CRET here", redact_literals=("S3CRET",))
    assert E.contains_raw_ip("x 192.168.1.1 y") and not E.contains_raw_ip("v1.2.3-rc1 build 2024.11")


def test_fail_closed_final_gate_drops_a_record_that_slips_a_raw_ip(tmp_path, monkeypatch):
    # defense-in-depth: if the pre-scrub ever failed to catch an IP, the FINAL hygiene gate still drops the
    # record — nothing leaky is ever written. Simulate the slip by neutralising the pre-scrub IP redaction.
    monkeypatch.setattr(E, "_redact_ips", lambda s: s)
    rp = E.EventV2Reporter(tmp_path, org_id="org_a", host="apme.cm", instance_id="gw", secret=SECRET,
                           now_fn=lambda: 100.0)
    rp(_v(contributing=["exfil-to-198.51.100.7"]))
    assert rp.written == 0 and rp.leaked_dropped == 1 and rp.errors == 1   # dropped fail-closed
    assert not list((tmp_path / E.V2_INCOMING).glob("*.json"))             # and NOTHING written


# ---- honest outcome-class mapping (never over-claims prevention) -----------------------------------------
def test_outcome_class_mapping_is_honest():
    assert E.default_outcome_class(_v(action="observe")) is None
    assert E.default_outcome_class(_v(action="allow")) is None
    assert E.default_outcome_class(_v(action="throttle")) is OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT
    assert E.default_outcome_class(_v(action="challenge")) is OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT
    # a block claims the WEAKER response-withheld (class 3), NEVER prevented_before_execution (class 1).
    assert E.default_outcome_class(_v(action="block")) is OutcomeClass.RESPONSE_WITHHELD_AFTER_EXECUTION
    ev = E.build_event_v2(_v(action="observe"), org_id="o", host="apme.cm", instance_id="gw", epoch=0, seq=1)
    assert ev.outcome_class is None


# ---- reporter: spool policy, determinism of seq, append-only, fail-closed --------------------------------
def test_reporter_spools_confirmed_and_lead_but_not_clear_with_monotonic_seq(tmp_path):
    rp = E.EventV2Reporter(tmp_path, org_id="org_a", host="apme.cm", instance_id="gw", secret=SECRET,
                           now_fn=lambda: 100.0)
    rp(_v("confirmed")); rp(_v("lead", action="observe")); rp(_v("clear")); rp(None)
    files = sorted((tmp_path / E.V2_INCOMING).glob("*.json"))
    assert len(files) == 2 and rp.written == 2
    seqs = sorted(json.loads(json.loads(f.read_bytes())["body"])["seq"] for f in files)
    assert seqs == [1, 2]                                   # monotonic, 1-based, no clock
    for f in files:
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
        assert _mac_ok_v2(json.loads(f.read_bytes()))
    assert stat.S_IMODE((tmp_path / E.V2_INCOMING).stat().st_mode) == 0o700


def test_reporter_is_append_only_idempotent_on_identical_bytes(tmp_path):
    # the same verdict at the SAME seq addresses the same content -> the second write is a no-op (never clobbers).
    # The write goes through the shared monitoring_report.atomic_spool_write helper (reuse of the v1 machinery).
    ev = E.build_event_v2(_v(), org_id="org_a", host="apme.cm", instance_id="gw", epoch=0, seq=5)
    data = E.canonical_json(E.seal_event_v2(ev, SECRET))
    inc = tmp_path / E.V2_INCOMING
    E.atomic_spool_write(inc, data)
    E.atomic_spool_write(inc, data)
    assert len(list(inc.glob("*.json"))) == 1


def test_reporter_rate_cap_drops_and_counts(tmp_path):
    rp = E.EventV2Reporter(tmp_path, org_id="o", host="apme.cm", instance_id="gw", secret=SECRET,
                           max_per_minute=3, now_fn=lambda: 60.0)
    for _ in range(10):
        rp(_v())
    assert rp.written == 3 and rp.dropped == 7


def test_reporter_never_raises_into_the_gateway(tmp_path):
    blocker = tmp_path / "file"; blocker.write_text("x")      # spool path is a FILE -> write fails
    rp = E.EventV2Reporter(blocker, org_id="o", host="apme.cm", instance_id="gw", secret=SECRET)
    rp(_v())
    assert rp.errors == 1 and rp.written == 0


# ---- strict-domain routing (reuses the v1 slug machinery) -----------------------------------------------
def test_strict_domain_routes_into_incoming_v2_slug_subtree(tmp_path):
    rp = E.EventV2Reporter(tmp_path, org_id="org_a", host="apme.cm", instance_id="gw", secret=SECRET,
                           now_fn=lambda: 100.0, strict_domain=True)
    rp(_v("confirmed"))
    slug = R.domain_slug("org_a", "apme.cm")
    assert list((tmp_path / E.V2_INCOMING).iterdir()) == [tmp_path / E.V2_INCOMING / slug]
    assert rp.written == 1 and len(list((tmp_path / E.V2_INCOMING / slug).glob("*.json"))) == 1


def test_default_is_flat_incoming_v2_distinct_from_v1_incoming(tmp_path):
    rp = E.EventV2Reporter(tmp_path, org_id="org_a", host="apme.cm", instance_id="gw", secret=SECRET,
                           now_fn=lambda: 100.0)
    rp(_v("confirmed"))
    assert (tmp_path / E.V2_INCOMING).is_dir()
    assert not (tmp_path / "incoming").exists()              # v2 never writes the v1 drain's incoming/


# ---- FATAL-2: engine plane only --------------------------------------------------------------------------
def test_fatal2_no_sovereign_import():
    import re
    src = Path(E.__file__).read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+sigil\b", src, re.M)
    assert "vigil_integration" not in src and "apps.sigil" not in src
