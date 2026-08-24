"""W16-STD-5 (d) — ``postmortem.run()`` credits calibrated priors WITHOUT double-counting, with KNOWN
expected values, and idempotently.

The bug: a single confirmed finding is recorded BOTH as a confirmed hypothesis AND as a successful
payload on the SAME (bug_class, surface); the postmortem credited each independently, inflating the
prior to two successes/two attempts for ONE outcome (observed on the built-in seed:
webhook-forgery succ=2 att=2). The fix merges outcomes per (bug_class, surface) key — one credit per
key per engagement, success-dominant — and applies an engagement's priors at most once.

Fail-without-fix: on the unfixed tree these assertions read succ=2/att=2 for the doubled key, and a
second postmortem.run() doubles the priors again.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.memory import postmortem, priors, recorder
from framework.v2.memory.store import Store, open_store


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    s = open_store(tmp_path / "store.sqlite")
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _isolate_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # postmortem.run writes targets/<slug>/postmortem.md — keep it in tmp.
    from framework.v2.common import paths as _paths
    monkeypatch.setattr(_paths, "target_dir", lambda slug: tmp_path / slug)


_ARCH = "Test archetype"


def _prior(s: Store, bug_class: str, surface: str):
    return priors.get_prior(s, _ARCH, bug_class, surface)


def test_confirmed_finding_plus_matching_payload_is_credited_once(store: Store) -> None:
    """A confirmed hypothesis AND a successful payload for the SAME (bug_class, surface) are ONE outcome —
    credited succ=1 att=1, NOT succ=2 att=2 (the double-count)."""
    recorder.record_engagement_start(store, slug="eng", archetype=_ARCH)
    recorder.record_hypothesis(store, "eng", handle="H1", bug_class="idor",
                               surface="/api/orders/{id}", status="confirmed")
    recorder.record_payload(store, "eng", bug_class="idor", payload_text="p",
                            target_surface="/api/orders/{id}", archetype=_ARCH, outcome="success")

    postmortem.run(store, "eng")

    p = _prior(store, "idor", "/api/orders/{id}")
    assert p is not None
    assert (p.successes, p.attempts) == (1, 1), f"double-counted: succ={p.successes} att={p.attempts}"


def test_priors_do_not_over_merge_distinct_keys(store: Store) -> None:
    """NEGATIVE CONTROL — the dedup is keyed on (bug_class, surface), so DISTINCT keys stay distinct:
    a confirmed idor on surface A and a FAILED sqli payload on surface B produce TWO separate priors,
    each credited once. (Proves the fix is not a blanket 'credit everything once' no-op.)"""
    recorder.record_engagement_start(store, slug="eng", archetype=_ARCH)
    recorder.record_hypothesis(store, "eng", handle="H1", bug_class="idor",
                               surface="/a", status="confirmed")
    recorder.record_payload(store, "eng", bug_class="sqli", payload_text="p",
                            target_surface="/b", archetype=_ARCH, outcome="failure")

    postmortem.run(store, "eng")

    a = _prior(store, "idor", "/a")
    b = _prior(store, "sqli", "/b")
    assert a is not None and (a.successes, a.attempts) == (1, 1)      # a confirmed success
    assert b is not None and (b.successes, b.attempts) == (0, 1)      # a failed attempt, not a success


def test_postmortem_is_idempotent_across_reruns(store: Store) -> None:
    """Re-running postmortem must NOT re-bump priors (the across-run double-count)."""
    recorder.record_engagement_start(store, slug="eng", archetype=_ARCH)
    recorder.record_hypothesis(store, "eng", handle="H1", bug_class="idor",
                               surface="/a", status="confirmed")
    recorder.record_payload(store, "eng", bug_class="idor", payload_text="p",
                            target_surface="/a", archetype=_ARCH, outcome="success")

    postmortem.run(store, "eng")
    first = _prior(store, "idor", "/a")
    postmortem.run(store, "eng")
    postmortem.run(store, "eng")
    again = _prior(store, "idor", "/a")

    assert (first.successes, first.attempts) == (1, 1)
    assert (again.successes, again.attempts) == (1, 1), "priors re-bumped on a second postmortem.run()"


def test_seed_engagement_priors_have_known_expected_values(store: Store) -> None:
    """End-to-end over the built-in seed (target_dir redirected to tmp by the autouse fixture): exactly
    succ=1/att=1 for each of the three confirmed findings and succ=0/att=1 for each of the three refuted
    classes (was succ=2/att=2 for the confirmed ones before the fix)."""
    from framework.v2.memory import seed_mrbeanpanel

    seed_mrbeanpanel.seed(store)   # seed() calls postmortem.run() internally
    got = {(p.bug_class, p.successes, p.attempts) for p in priors.all_priors(store, limit=50)}

    expected = {
        ("webhook-forgery", 1, 1), ("IDOR", 1, 1), ("mass-assignment", 1, 1),
        ("SQLi", 0, 1), ("XXE", 0, 1), ("XSS", 0, 1),
    }
    assert got == expected, f"seed priors drifted / double-counted: {sorted(got)}"
