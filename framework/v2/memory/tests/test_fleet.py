"""
Tests for cross-engagement / FLEET learning transfer (memory.fleet + its opt-in wiring
into memory.priors.smoothed_priors_for / get_prior_smoothed).

A single MLS store pools archetype_priors across the engagements that wrote to IT; the
fleet pools across MANY stores / portable shards — the whole deployment's history. These
prove the additive, evidence-gated, deterministic contract:

  * pooling sums recorded counts across stores AND shards (never fabricates);
  * a fleet source warm-starts the bandit via the EXISTING seed_from_priors bridge,
    deterministically and only when the pooled evidence clears the effective-attempts gate;
  * the default path is byte-identical (fleet resolves to None unless CRUCIBLE_FLEET set);
  * the optional semantic embedder degrades to the deterministic LexicalEmbedder when the
    dep is absent;
  * pooled calibration labels let split-conformal reach its >=8-label guarantee sooner —
    honestly (coverage_guaranteed stays False below the threshold, dedup by finding_id,
    model_version filtering to preserve exchangeability).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.memory import fleet as fleet_mod
from framework.v2.memory import priors
from framework.v2.memory.fleet import FleetError, FleetLabels, FleetPriors
from framework.v2.memory.store import Store, open_store


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    s = open_store(tmp_path / "store.sqlite")
    yield s
    s.close()


# Two lexically SIMILAR archetypes (share "laravel"/"commerce") + one DISSIMILAR.
_QUERY = "laravel commerce marketplace"
_SIMILAR = "laravel commerce shop"
_OTHER = "static wordpress blog site"


def _bump(store: Store, archetype: str, bug_class: str, *, successes: int, attempts: int,
          surface: str = "") -> None:
    for _ in range(successes):
        priors.bump_success(store, archetype, bug_class, surface)
    for _ in range(attempts - successes):
        priors.bump_attempt(store, archetype, bug_class, surface)


# ---------------------------------------------------------------------------
# FleetPriors — pooling, honesty, shard round-trip
# ---------------------------------------------------------------------------


def test_fleet_pools_counts_across_stores_and_shards(tmp_path: Path) -> None:
    # One node's store, another node's exported shard — same (archetype,class,surface)
    # key. The pool must SUM the recorded counts (integer, exact), never invent.
    node_a = open_store(tmp_path / "a.sqlite")
    _bump(node_a, _SIMILAR, "boolean_sqli", successes=3, attempts=5)
    shard = {
        "schema_version": fleet_mod.FLEET_PRIORS_SCHEMA,
        "kind": fleet_mod.FLEET_PRIORS_KIND,
        "source_id": "node-b",
        "priors": [
            {"archetype": _SIMILAR, "bug_class": "boolean_sqli",
             "surface_pattern": "", "successes": 4, "attempts": 6},
        ],
    }
    fl = FleetPriors()
    fl.add_store(node_a, source_id="node-a")
    fl.add_shard(shard)
    node_a.close()

    pooled = fl.get_prior(_SIMILAR, "boolean_sqli")
    assert pooled is not None
    assert (pooled.successes, pooled.attempts) == (7, 11)   # 3+4, 5+6 — exact sum
    assert fl.distinct_archetypes() == [_SIMILAR]
    assert fl.class_surface_keys() == [("boolean_sqli", "")]
    assert set(fl.sources()) == {"node-a", "node-b"}


def test_fleet_never_fabricates_zero_evidence_key() -> None:
    # A key recorded with attempts=0 carries no evidence -> get_prior returns None.
    fl = FleetPriors()
    fl.add_shard({
        "schema_version": 1, "kind": fleet_mod.FLEET_PRIORS_KIND,
        "priors": [{"archetype": "x", "bug_class": "idor", "successes": 0, "attempts": 0}],
    })
    assert fl.get_prior("x", "idor") is None


def test_fleet_rejects_impossible_and_malformed_shards() -> None:
    fl = FleetPriors()
    with pytest.raises(FleetError):   # successes may never exceed attempts
        fl.add_shard({
            "schema_version": 1, "kind": fleet_mod.FLEET_PRIORS_KIND,
            "priors": [{"archetype": "x", "bug_class": "y", "successes": 9, "attempts": 2}],
        })
    with pytest.raises(FleetError):   # negative counts
        fl.add_shard({
            "schema_version": 1, "kind": fleet_mod.FLEET_PRIORS_KIND,
            "priors": [{"archetype": "x", "bug_class": "y", "successes": -1, "attempts": 2}],
        })
    with pytest.raises(FleetError):   # wrong kind
        fl.add_shard({"schema_version": 1, "kind": "not-fleet", "priors": []})
    with pytest.raises(FleetError):   # unsupported schema
        fl.add_shard({"schema_version": 999, "kind": fleet_mod.FLEET_PRIORS_KIND, "priors": []})


def test_fleet_shard_roundtrips_bytewise(tmp_path: Path) -> None:
    fl = FleetPriors()
    fl.add_shard({
        "schema_version": 1, "kind": fleet_mod.FLEET_PRIORS_KIND,
        "priors": [
            {"archetype": _SIMILAR, "bug_class": "boolean_sqli", "successes": 4, "attempts": 6},
            {"archetype": _OTHER, "bug_class": "xxe", "successes": 1, "attempts": 3},
        ],
    })
    p = fl.write_shard(tmp_path / "out.json", source_id="me")
    # A reload folds the same counts back in (idempotent shape).
    fl2 = FleetPriors()
    fl2.add_shard(p)
    assert fl2.get_prior(_SIMILAR, "boolean_sqli").attempts == 6
    assert fl2.get_prior(_OTHER, "xxe").successes == 1
    # Serialisation is deterministic: same pool + same source_id -> byte-identical.
    again = fl.write_shard(tmp_path / "out2.json", source_id="me")
    assert p.read_text() == again.read_text()


# ---------------------------------------------------------------------------
# Fleet as an opt-in transfer source (the warm-start path)
# ---------------------------------------------------------------------------


def test_fleet_pools_same_archetype_across_nodes_into_exact_prior(store: Store) -> None:
    # The core "not just per-slug" point: the SAME archetype seen on TWO fleet nodes.
    # Neither alone clears exact_min_attempts (5); pooled they do, and the exact prior is
    # returned as-is (no borrowing) with SUMMED counts.
    _bump(store, _QUERY, "boolean_sqli", successes=2, attempts=3)   # local node
    fl = FleetPriors()
    fl.add_shard({
        "schema_version": 1, "kind": fleet_mod.FLEET_PRIORS_KIND,
        "priors": [{"archetype": _QUERY, "bug_class": "boolean_sqli",
                    "successes": 3, "attempts": 4}],
    })
    sm = priors.get_prior_smoothed(store, _QUERY, "boolean_sqli", fleet=fl)
    assert sm is not None
    assert sm.is_transferred is False          # pooled exact cleared the floor
    assert (sm.successes, sm.attempts) == (5.0, 7.0)   # 2+3, 3+4


def test_fleet_neighbour_warm_starts_bandit_via_existing_bridge(store: Store) -> None:
    # Local store has NO boolean_sqli history. A fleet node carries a strong SIMILAR
    # archetype prior. Transfer must borrow it (evidence-gated) and warm-start the arm via
    # the UNCHANGED seed_from_priors bridge.
    from framework.v2.scanner.learning import ContextualBandit

    fl = FleetPriors()
    fl.add_shard({
        "schema_version": 1, "kind": fleet_mod.FLEET_PRIORS_KIND,
        "priors": [{"archetype": _SIMILAR, "bug_class": "boolean_sqli",
                    "successes": 8, "attempts": 10}],
    })
    transfer = priors.smoothed_priors_for(store, _QUERY, fleet=fl)
    assert transfer, "expected an evidence-sufficient fleet transfer"
    sqli = [p for p in transfer if p.bug_class == "boolean_sqli"]
    assert sqli and sqli[0].is_transferred is True
    assert sqli[0].sources == [_SIMILAR]

    bandit = ContextualBandit()
    seeded = bandit.seed_from_priors(transfer, lambda p: ("ctx", p.bug_class))
    assert seeded == len(transfer)
    assert bandit.expected_value("ctx", "boolean_sqli") > 0.5


def test_fleet_transfer_is_deterministic(store: Store) -> None:
    fl = FleetPriors()
    fl.add_shard({
        "schema_version": 1, "kind": fleet_mod.FLEET_PRIORS_KIND,
        "priors": [{"archetype": _SIMILAR, "bug_class": "boolean_sqli",
                    "successes": 8, "attempts": 10}],
    })
    a = priors.get_prior_smoothed(store, _QUERY, "boolean_sqli", fleet=fl)
    b = priors.get_prior_smoothed(store, _QUERY, "boolean_sqli", fleet=fl)
    assert a is not None and b is not None
    assert (a.successes, a.attempts, a.sources, a.sim_weight) == (
        b.successes, b.attempts, b.sources, b.sim_weight)


def test_fleet_underevidenced_blend_is_withheld(store: Store) -> None:
    # A fleet neighbour with a single attempt: after the similarity*weight discount the
    # effective attempts fall below the floor, so the honest gate drops it.
    fl = FleetPriors()
    fl.add_shard({
        "schema_version": 1, "kind": fleet_mod.FLEET_PRIORS_KIND,
        "priors": [{"archetype": _SIMILAR, "bug_class": "open_redirect",
                    "successes": 1, "attempts": 1}],
    })
    sm = priors.get_prior_smoothed(store, _QUERY, "open_redirect", fleet=fl)
    assert sm is not None and sm.is_transferred is True
    assert sm.evidence_sufficient() is False
    assert all(p.bug_class != "open_redirect"
               for p in priors.smoothed_priors_for(store, _QUERY, fleet=fl))


def test_fleet_does_not_borrow_from_dissimilar(store: Store) -> None:
    fl = FleetPriors()
    fl.add_shard({
        "schema_version": 1, "kind": fleet_mod.FLEET_PRIORS_KIND,
        "priors": [{"archetype": _OTHER, "bug_class": "xxe",
                    "successes": 5, "attempts": 8}],
    })
    assert priors.get_prior_smoothed(store, _QUERY, "xxe", fleet=fl) is None


# ---------------------------------------------------------------------------
# Default byte-identity + opt-in resolution
# ---------------------------------------------------------------------------


def test_default_path_ignores_fleet_unless_opted_in(store: Store, monkeypatch) -> None:
    # With a similar archetype present ONLY in the fleet and CRUCIBLE_FLEET unset, the
    # default call must behave exactly as fleet=None (byte-identical) — it must NOT reach
    # out to any fleet source on its own.
    monkeypatch.delenv("CRUCIBLE_FLEET", raising=False)
    _bump(store, _SIMILAR, "boolean_sqli", successes=8, attempts=10)
    default = priors.smoothed_priors_for(store, _QUERY)
    explicit_none = priors.smoothed_priors_for(store, _QUERY, fleet=None)
    assert [(p.bug_class, p.successes, p.attempts, p.sources) for p in default] == \
           [(p.bug_class, p.successes, p.attempts, p.sources) for p in explicit_none]


def test_load_fleet_from_env_gated_and_deterministic(tmp_path: Path, monkeypatch) -> None:
    shard_dir = tmp_path / "fleet"
    shard_dir.mkdir()
    (shard_dir / "b.json").write_text(
        '{"schema_version":1,"kind":"crucible-fleet-priors","priors":'
        '[{"archetype":"z","bug_class":"idor","successes":2,"attempts":4}]}')
    monkeypatch.setenv("CRUCIBLE_FLEET_DIR", str(shard_dir))

    monkeypatch.delenv("CRUCIBLE_FLEET", raising=False)
    assert fleet_mod.load_fleet_from_env() is None            # gated off by default

    monkeypatch.setenv("CRUCIBLE_FLEET", "1")
    fl = fleet_mod.load_fleet_from_env()
    assert fl is not None and fl.get_prior("z", "idor").attempts == 4


def test_env_fleet_flows_through_default_smoothed_call(store: Store, tmp_path: Path,
                                                       monkeypatch) -> None:
    # The opt-in path engage.py rides: no explicit fleet= arg, activated purely by env.
    shard_dir = tmp_path / "fleet"
    shard_dir.mkdir()
    (shard_dir / "sim.json").write_text(
        '{"schema_version":1,"kind":"crucible-fleet-priors","priors":'
        f'[{{"archetype":"{_SIMILAR}","bug_class":"boolean_sqli","successes":8,"attempts":10}}]}}')
    monkeypatch.setenv("CRUCIBLE_FLEET_DIR", str(shard_dir))
    monkeypatch.setenv("CRUCIBLE_FLEET", "1")

    transfer = priors.smoothed_priors_for(store, _QUERY)   # no fleet= arg
    assert any(p.bug_class == "boolean_sqli" and p.is_transferred for p in transfer)


def test_malformed_shard_in_fleet_dir_is_skipped_not_fatal(store: Store, tmp_path: Path,
                                                           monkeypatch) -> None:
    shard_dir = tmp_path / "fleet"
    shard_dir.mkdir()
    (shard_dir / "bad.json").write_text("{ this is not json ")
    (shard_dir / "good.json").write_text(
        '{"schema_version":1,"kind":"crucible-fleet-priors","priors":'
        f'[{{"archetype":"{_SIMILAR}","bug_class":"boolean_sqli","successes":8,"attempts":10}}]}}')
    # A label shard (different kind) living alongside must be ignored by the priors loader.
    (shard_dir / "labels.json").write_text(
        '{"schema_version":1,"kind":"crucible-fleet-labels","priors":[]}')
    monkeypatch.setenv("CRUCIBLE_FLEET_DIR", str(shard_dir))
    monkeypatch.setenv("CRUCIBLE_FLEET", "1")

    fl = fleet_mod.load_fleet_from_env()
    assert fl is not None and fl.get_prior(_SIMILAR, "boolean_sqli").attempts == 10


# ---------------------------------------------------------------------------
# Optional semantic embedder — degrades to lexical when the dep is absent
# ---------------------------------------------------------------------------


def test_transfer_embedder_defaults_to_lexical(monkeypatch) -> None:
    monkeypatch.delenv("CRUCIBLE_EMBEDDER", raising=False)
    emb = priors._transfer_embedder(None)
    assert emb.name == "lexical-256"


def test_transfer_embedder_degrades_to_lexical_when_semantic_absent(monkeypatch) -> None:
    # Ask for semantic, but has_semantic() reports the dep missing -> lexical, no raise.
    monkeypatch.setenv("CRUCIBLE_EMBEDDER", "semantic")
    monkeypatch.setattr("framework.v2.common.capabilities.has_semantic", lambda: False)
    emb = priors._transfer_embedder(None)
    assert emb.name == "lexical-256"


def test_transfer_embedder_uses_semantic_when_present(monkeypatch) -> None:
    # When has_semantic() is True and the flag opts in, the env-selected embedder is used.
    sentinel = priors._lexical_embedder()
    sentinel.name = "st:stub"                            # stand-in for a semantic backend
    monkeypatch.setenv("CRUCIBLE_EMBEDDER", "semantic")
    monkeypatch.setattr("framework.v2.common.capabilities.has_semantic", lambda: True)
    monkeypatch.setattr("framework.v2.memory.embed.get_embedder", lambda: sentinel)
    emb = priors._transfer_embedder(None)
    assert emb.name == "st:stub"


def test_explicit_embedder_always_wins(monkeypatch) -> None:
    monkeypatch.setenv("CRUCIBLE_EMBEDDER", "semantic")
    monkeypatch.setattr("framework.v2.common.capabilities.has_semantic", lambda: True)
    pinned = priors._lexical_embedder()
    assert priors._transfer_embedder(pinned) is pinned


# ---------------------------------------------------------------------------
# FleetLabels — pooled calibration labels, honest coverage
# ---------------------------------------------------------------------------


def _mk_ledger(specs):
    """Build an OutcomeLedger from (finding_id, raw_score, label, model_version) specs."""
    from framework.v2.calibration.ledger import OutcomeLedger
    from framework.v2.calibration.models import Outcome, OutcomeLabel, Prediction

    led = OutcomeLedger()
    for i, (fid, score, label, mv) in enumerate(specs):
        led.add_prediction(
            Prediction(finding_id=fid, raw_score=score, feature_hash="h",
                       model_version=mv, oracle_confirmed=False),
            seq=2 * i,
        )
        led.record_outcome(Outcome(finding_id=fid, label=label), seq=2 * i + 1)
    return led


def test_pooled_labels_reach_conformal_guarantee_honestly() -> None:
    from framework.v2.calibration.conformal import conformal_band
    from framework.v2.calibration.models import OutcomeLabel

    EXP, FP = OutcomeLabel.EXPLOITABLE, OutcomeLabel.FALSE_POSITIVE

    # Local engagement: only 3 resolved labels -> below MIN_LABELS(8) -> NOT guaranteed.
    local = _mk_ledger([
        ("L1", 0.9, EXP, "m1"), ("L2", 0.2, FP, "m1"), ("L3", 0.8, EXP, "m1"),
    ]).pairs()
    band_local = conformal_band(0.5, local, fallback=(0.3, 0.7))
    assert band_local.coverage_guaranteed is False
    assert band_local.n_labels == 3

    # A fleet of past engagements contributes 5 more REAL same-model labels.
    labels = FleetLabels()
    labels.add_ledger(_mk_ledger([
        ("F1", 0.7, EXP, "m1"), ("F2", 0.3, FP, "m1"), ("F3", 0.6, EXP, "m1"),
        ("F4", 0.4, FP, "m1"), ("F5", 0.5, EXP, "m1"),
    ]))
    pooled = labels.augment(local, model_version="m1")
    assert len(pooled) == 8
    band_pooled = conformal_band(0.5, pooled, fallback=(0.3, 0.7))
    assert band_pooled.coverage_guaranteed is True          # >=8 REAL labels now back it
    assert band_pooled.n_labels == 8
    assert band_pooled.method == "split_conformal"


def test_pooled_labels_still_starved_stay_unguaranteed() -> None:
    # Not enough even after pooling -> still honest: coverage_guaranteed=False, no fabrication.
    from framework.v2.calibration.conformal import conformal_band
    from framework.v2.calibration.models import OutcomeLabel

    EXP = OutcomeLabel.EXPLOITABLE
    local = _mk_ledger([("L1", 0.9, EXP, "m1"), ("L2", 0.8, EXP, "m1")]).pairs()
    labels = FleetLabels()
    labels.add_ledger(_mk_ledger([("F1", 0.7, EXP, "m1"), ("F2", 0.6, EXP, "m1")]))
    pooled = labels.augment(local, model_version="m1")
    assert len(pooled) == 4
    band = conformal_band(0.5, pooled, fallback=(0.3, 0.7))
    assert band.coverage_guaranteed is False and band.method == "bayesian_fallback"


def test_model_version_filter_preserves_exchangeability() -> None:
    from framework.v2.calibration.models import OutcomeLabel

    EXP = OutcomeLabel.EXPLOITABLE
    labels = FleetLabels()
    labels.add_ledger(_mk_ledger([
        ("A", 0.5, EXP, "m1"), ("B", 0.5, EXP, "m2"), ("C", 0.5, EXP, "m1"),
    ]))
    only_m1 = labels.pooled_pairs(model_version="m1")
    assert {p.finding_id for p, _o in only_m1} == {"A", "C"}     # m2 excluded
    assert len(labels.pooled_pairs()) == 3                       # unfiltered pools all


def test_fleet_labels_dedup_by_finding_id() -> None:
    from framework.v2.calibration.models import OutcomeLabel

    EXP = OutcomeLabel.EXPLOITABLE
    local = _mk_ledger([("SHARED", 0.9, EXP, "m1")]).pairs()
    labels = FleetLabels()
    # SHARED appears both locally and in the fleet -> counted ONCE (append-only).
    labels.add_ledger(_mk_ledger([("SHARED", 0.9, EXP, "m1"), ("NEW", 0.5, EXP, "m1")]))
    pooled = labels.augment(local)
    fids = [p.finding_id for p, _o in pooled]
    assert fids == ["SHARED", "NEW"]                            # local first, no duplicate

    # And within the fleet, a re-seen finding_id across shards is not double-counted.
    labels.add_ledger(_mk_ledger([("NEW", 0.5, EXP, "m1")]))
    assert len(labels) == 2


def test_load_fleet_labels_from_env_gated(tmp_path: Path, monkeypatch) -> None:
    from framework.v2.calibration.models import OutcomeLabel

    led = _mk_ledger([("X", 0.5, OutcomeLabel.EXPLOITABLE, "m1")])
    d = tmp_path / "fleet"
    d.mkdir()
    (d / "eng.ledger.json").write_text(led.to_json())
    monkeypatch.setenv("CRUCIBLE_FLEET_LABELS_DIR", str(d))

    monkeypatch.delenv("CRUCIBLE_FLEET", raising=False)
    assert fleet_mod.load_fleet_labels_from_env() is None       # gated off

    monkeypatch.setenv("CRUCIBLE_FLEET", "1")
    labels = fleet_mod.load_fleet_labels_from_env()
    assert labels is not None and len(labels) == 1
