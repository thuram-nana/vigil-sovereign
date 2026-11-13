"""E3bc — ``live/settle_progress``: the settle drain's record of the recorded settles it could not finish, and since when.

The drain writes it beside its completion spool every pass and ``vigil doctor`` reads it (stdlib only, both planes).
A lease keeps the time it was first left unfinished across passes and leaves the record on the first pass that does
not leave it unfinished; a finish pass that could not run keeps the leases and the time it first failed; with nothing
to record the file is removed; the record is bounded. Real files; framework-free (integration leg).

Mutation-verify targets (each neuter reds a NAMED test here):
  * first_seen not carried / a finished lease not dropped     -> test_a_lease_keeps_when_it_was_first_left_unfinished
  * pass_error since not kept / leases dropped on an error    -> test_a_failing_pass_keeps_the_leases_and_its_first_failure
  * the lease cap dropped / the newest kept                   -> test_the_record_is_bounded_keeping_the_longest_held
  * the file kept when nothing is left                        -> test_a_lease_keeps_when_it_was_first_left_unfinished
"""
from __future__ import annotations

import os

from vigil_integration.live import settle_progress as sp


def test_a_lease_keeps_when_it_was_first_left_unfinished(tmp_path):
    a, b = ("cust_a", "n1"), ("cust_b", "n2")
    sp.update_state(tmp_path, now=100.0, unfinished=[a])
    st = sp.update_state(tmp_path, now=200.0, unfinished=[a, b])
    assert {(e["slug"], e["nonce"]): e["first_seen"] for e in st["leases"]} == {a: 100.0, b: 200.0}
    assert sp.read_state(tmp_path) == st
    assert sp.overdue(st, now=100.0 + sp.UNFINISHED_SETTLE_GRACE_S) == ([a], None)
    st = sp.update_state(tmp_path, now=300.0, unfinished=[b])                 # a finished: it leaves the record
    assert [(e["slug"], e["first_seen"]) for e in st["leases"]] == [("cust_b", 200.0)]
    st = sp.update_state(tmp_path, now=400.0, unfinished=[])                  # nothing left: the file goes
    assert st["leases"] == [] and not sp.state_path(tmp_path).exists()
    assert sp.read_state(tmp_path) == {"schema": "vigil-settle-unfinished-v1", "leases": [], "pass_error": None}


def test_a_failing_pass_keeps_the_leases_and_its_first_failure(tmp_path):
    a = ("cust_a", "n1")
    sp.update_state(tmp_path, now=100.0, unfinished=[a])
    sp.update_state(tmp_path, now=150.0, unfinished=None, error="SpineError")
    st = sp.update_state(tmp_path, now=900.0, unfinished=None, error="SpineError")
    assert st["pass_error"] == {"since": 150.0, "error": "SpineError"} and st["leases"][0]["first_seen"] == 100.0
    assert sp.overdue(st, now=150.0 + sp.UNFINISHED_SETTLE_GRACE_S) == ([a], "SpineError")
    assert sp.overdue(st, now=100.0 + sp.UNFINISHED_SETTLE_GRACE_S) == ([a], None)   # the error is younger
    assert sp.overdue(st, now=100.0 + sp.UNFINISHED_SETTLE_GRACE_S - 1) == ([], None)
    st = sp.update_state(tmp_path, now=1000.0, unfinished=[a])                # the pass runs again: error cleared
    assert st["pass_error"] is None and st["leases"][0]["first_seen"] == 100.0


def test_the_record_is_bounded_keeping_the_longest_held(tmp_path):
    many = [(f"cust_{i:04d}", "n") for i in range(sp.MAX_LEASES + 40)]
    sp.update_state(tmp_path, now=10.0, unfinished=many[:40])                # held longest
    st = sp.update_state(tmp_path, now=20.0, unfinished=many)
    assert len(st["leases"]) == sp.MAX_LEASES
    assert {e["slug"] for e in st["leases"] if e["first_seen"] == 10.0} == {s for s, _ in many[:40]}
    assert os.path.getsize(sp.state_path(tmp_path)) <= sp.MAX_BYTES
    assert len(sp.read_state(tmp_path)["leases"]) == sp.MAX_LEASES
