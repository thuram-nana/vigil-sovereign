"""W13-8 (#501) property 4 — schema-ALLOWLISTED telemetry with an explicit NO-COLLECT list.

Runs in the SOVEREIGN leg of the required "integration two-env boundary (P5)" CI job. Pins, per #501:

  * The emitted payload contains ONLY allowlisted field names; an unknown field is dropped (allowlist, not
    denylist).
  * NEGATIVE CONTROL (the AC's own words): plant a no-collect-list field in the source data and assert it is
    ABSENT from the emitted payload — at the top level AND nested inside an engagement row AND as an opaque
    count-map label. An allowlisted field survives in the same run (so the scrubber is not emitting nothing).
  * The allowlist and the no-collect list are DISJOINT (a field cannot be both) — stated in the module and
    asserted here.

FAILS WITHOUT THE FIX: imports ``vigil_integration.sovereign_deploy.telemetry`` at module scope.
"""
from __future__ import annotations

from vigil_integration.sovereign_deploy.telemetry import (
    NO_COLLECT_FIELDS,
    TELEMETRY_SCHEMA_ALLOWLIST,
    build_telemetry_payload,
    no_collect_fields,
    schema_allowlist,
    scrub_snapshot_for_export,
)


def _source_with_planted_secrets() -> dict:
    return {
        # allowlisted aggregate metrics (must survive)
        "schema": 1,
        "events": 12,
        "facts": 4,
        "leads": 8,
        "by_kind": {"finding": 4, "refusal": 1, "token": 99},   # 'token' is a no-collect label -> dropped
        "engagements": [
            {"slug": "eng-1", "facts": 2, "credential": "hunter2", "target_url": "http://victim.example"},
        ],
        "totals": {"events": 12, "facts": 4},
        # planted no-collect fields at the TOP level (must be absent)
        "operator": {"os_login": "root", "git_email": "a@b.c", "key_fingerprint": "deadbeef"},
        "credential": "s3cr3t",
        "target_url": "http://victim.example/admin",
        "password": "p@ss",
        "authorization": "Bearer abc.def",
        # an unknown field (must be dropped by the allowlist)
        "some_new_field": "not allowlisted",
    }


# ---------------------------------------------------------------------------------------------------------
# THE NEGATIVE CONTROL the AC names — planted no-collect fields are ABSENT from the emitted payload.
# ---------------------------------------------------------------------------------------------------------
def test_planted_no_collect_fields_are_absent_from_the_payload():
    out = build_telemetry_payload(_source_with_planted_secrets())

    # every no-collect field planted at the top level is gone
    for banned in ("operator", "credential", "target_url", "password", "authorization"):
        assert banned not in out, f"no-collect field {banned!r} leaked into telemetry: {out}"

    # nested inside the engagement row too
    eng = out["engagements"][0]
    assert "credential" not in eng and "target_url" not in eng, eng
    assert eng == {"slug": "eng-1", "facts": 2}

    # the opaque count map keeps legit kinds but drops a no-collect-named label
    assert out["by_kind"] == {"finding": 4, "refusal": 1}

    # an unknown (non-allowlisted) field is dropped
    assert "some_new_field" not in out


def test_allowlisted_fields_survive_so_the_scrubber_is_not_a_no_op():
    out = build_telemetry_payload(_source_with_planted_secrets())
    assert out["schema"] == 1
    assert out["events"] == 12 and out["facts"] == 4 and out["leads"] == 8
    assert out["totals"] == {"events": 12, "facts": 4}
    assert out["engagements"][0]["slug"] == "eng-1"


def test_no_no_collect_field_name_appears_anywhere_in_the_output():
    out = build_telemetry_payload(_source_with_planted_secrets())

    def _keys(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield k
                yield from _keys(v)
        elif isinstance(obj, (list, tuple)):
            for e in obj:
                yield from _keys(e)

    banned_norm = {k.lower() for k in NO_COLLECT_FIELDS}
    leaked = [k for k in _keys(out) if str(k).lower() in banned_norm]
    assert not leaked, f"no-collect field names present in output: {leaked}"


# ---------------------------------------------------------------------------------------------------------
# STATED invariants — the two lists exist, are non-empty, and are disjoint.
# ---------------------------------------------------------------------------------------------------------
def test_allowlist_and_no_collect_are_disjoint_and_nonempty():
    allow = {k.lower() for k in schema_allowlist()}
    nocollect = {k.lower() for k in no_collect_fields()}
    assert allow and nocollect
    assert allow.isdisjoint(nocollect), f"overlap: {sorted(allow & nocollect)}"


def test_no_collect_list_covers_the_obvious_sensitive_families():
    nc = {k.lower() for k in NO_COLLECT_FIELDS}
    for must in ("credential", "password", "token", "target_url", "operator", "body", "email"):
        assert must in nc, f"{must!r} must be on the no-collect list"


def test_scrub_snapshot_alias_matches_build_payload():
    src = _source_with_planted_secrets()
    assert scrub_snapshot_for_export(src) == build_telemetry_payload(src)


def test_non_mapping_source_is_empty_and_total():
    assert build_telemetry_payload(None) == {}
    assert build_telemetry_payload("a string") == {}
    assert build_telemetry_payload(42) == {}
    assert build_telemetry_payload([{"credential": "x"}]) == {}
