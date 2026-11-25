"""AS-0 — the AEGIS slice-graph gate (FORGEMASTER's structural contract).

``slice_graph.json`` encodes the §9.3/§9.4 program: every slice's merge-deps, hot-set membership, token
membership and wave, plus the per-hot-set/token chains and the critical path. This test is the gate that
asserts the graph is well-formed, so the program's parallelization (one holder per hot set and per token
per wave) and its wave ordering can be TRUSTED by FORGEMASTER and by every later slice.

Properties asserted (and, as negative controls, shown to be CAUGHT when violated):
  * acyclicity — the dependency graph is a DAG;
  * wave levels — wave(s) == 1 + max(wave(dep)); roots are wave 0;
  * disjoint manifests — at most one slice per hot set per wave;
  * token uniqueness — at most one holder per token per wave;
  * chain/edge agreement — each chain is wave-ascending and each step transitively depends on the prior,
    and both ends hold the chain's hot set / token;
  * critical path — AS-0 … AS-24, wave non-decreasing, covering every wave.
"""
from __future__ import annotations

import copy
import functools
import json
from collections import defaultdict, deque
from pathlib import Path

import pytest

_GRAPH_PATH = Path(__file__).resolve().parents[1] / "slice_graph.json"


@pytest.fixture(scope="module")
def graph() -> dict:
    return json.loads(_GRAPH_PATH.read_text(encoding="utf-8"))


# ---- validators (pure: dict -> list[str] of violations) ------------------------------------------------

def _ids(g) -> list[str]:
    return list(g["slices"].keys())


def _deps_of(g, s) -> list[str]:
    d = g["slices"][s]["deps"]
    return [x for x in _ids(g) if x != s] if d == ["__ALL__"] else list(d)


def check_dep_targets(g) -> list[str]:
    out = []
    for s in _ids(g):
        for d in _deps_of(g, s):
            if d not in g["slices"]:
                out.append(f"{s}: unknown dep {d}")
    return out


def check_acyclic(g) -> list[str]:
    ids = _ids(g)
    adj = defaultdict(list)
    indeg = {s: 0 for s in ids}
    for s in ids:
        for d in _deps_of(g, s):
            adj[d].append(s)
            indeg[s] += 1
    q = deque([s for s in ids if indeg[s] == 0])
    seen = 0
    while q:
        n = q.popleft()
        seen += 1
        for m in adj[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                q.append(m)
    return [] if seen == len(ids) else [f"cycle: only {seen}/{len(ids)} slices topo-sorted"]


def check_waves(g) -> list[str]:
    if check_acyclic(g):  # wave() would recurse forever on a cycle
        return ["cannot derive waves: graph has a cycle"]

    @functools.lru_cache(maxsize=None)
    def wave(s):
        d = _deps_of(g, s)
        return 0 if not d else 1 + max(wave(x) for x in d)

    out = []
    for s in _ids(g):
        dec, der = g["slices"][s]["wave"], wave(s)
        if dec != der:
            out.append(f"{s}: declared wave {dec} != derived {der}")
    return out


def check_hot_disjoint(g) -> list[str]:
    bywave = defaultdict(lambda: defaultdict(list))
    for s in _ids(g):
        for h in g["slices"][s]["hot"]:
            bywave[g["slices"][s]["wave"]][h].append(s)
    return [f"wave {w} hot-set {h} held by {hs}"
            for w, hm in bywave.items() for h, hs in hm.items() if len(hs) > 1]


def check_token_unique(g) -> list[str]:
    bywave = defaultdict(lambda: defaultdict(list))
    for s in _ids(g):
        for t in g["slices"][s]["tokens"]:
            bywave[g["slices"][s]["wave"]][t].append(s)
    return [f"wave {w} token {t} held by {hs}"
            for w, tm in bywave.items() for t, hs in tm.items() if len(hs) > 1]


def check_chains(g) -> list[str]:
    @functools.lru_cache(maxsize=None)
    def ancestors(b):
        acc = set()
        for d in _deps_of(g, b):
            acc.add(d)
            acc |= ancestors(d)
        return frozenset(acc)

    out = []
    tokens = set(g["tokens"])
    for name, chain in g["chains"].items():
        is_token = name in tokens
        for a, b in zip(chain, chain[1:]):
            if g["slices"][b]["wave"] <= g["slices"][a]["wave"]:
                out.append(f"chain {name}: {b} wave !> {a} wave")
            if a not in ancestors(b):
                out.append(f"chain {name}: {b} does not transitively depend on {a}")
            key = "tokens" if is_token else "hot"
            if name not in g["slices"][a][key]:
                out.append(f"chain {name}: {a} not in set")
            if name not in g["slices"][b][key]:
                out.append(f"chain {name}: {b} not in set")
    return out


def _holders(g, name, key) -> set[str]:
    return {s for s in _ids(g) if name in g["slices"][s][key]}


def check_chain_completeness(g) -> list[str]:
    """A listed chain must contain EXACTLY the holders of its hot set / token — no holder omitted, no
    non-holder invented. Without this, a hot-set holder dropped into a currently-free wave but left out of
    the chain would pass every other check silently (check_hot_disjoint only forbids same-wave collisions)."""
    out = []
    tokens = set(g["tokens"])
    for name, chain in g["chains"].items():
        key = "tokens" if name in tokens else "hot"
        holders, members = _holders(g, name, key), set(chain)
        if holders - members:
            out.append(f"chain {name}: holders missing from chain {sorted(holders - members)}")
        if members - holders:
            out.append(f"chain {name}: chain lists non-holders {sorted(members - holders)}")
    return out


def check_serialization(g) -> list[str]:
    """EVERY hot set and token must totally-order its holders by dependency (cross-wave serialization), so a
    shared file / token is only ever modified in a dependency-ordered sequence — whether or not an explicit
    chain is listed (covers MA, CON, and any future hot set). Holders are sorted by wave; each consecutive
    distinct-wave pair must be dependency-ordered. Same-wave collisions are check_hot_disjoint's job."""
    @functools.lru_cache(maxsize=None)
    def ancestors(b):
        acc = set()
        for d in _deps_of(g, b):
            acc.add(d); acc |= ancestors(d)
        return frozenset(acc)

    out = []
    groups = {h: "hot" for h in g["hot_sets"]}
    groups.update({t: "tokens" for t in g["tokens"]})
    for name, key in groups.items():
        holders = sorted(_holders(g, name, key), key=lambda s: g["slices"][s]["wave"])
        for a, b in zip(holders, holders[1:]):
            if g["slices"][a]["wave"] == g["slices"][b]["wave"]:
                continue
            if a not in ancestors(b):
                out.append(f"{key} {name}: holders not serialized — {b} does not depend on {a}")
    return out


def check_critical_path(g) -> list[str]:
    cp = g["critical_path"]
    out = []
    if cp[0] != "AS-0" or cp[-1] != "AS-24":
        out.append(f"critical_path endpoints {cp[0]}..{cp[-1]} != AS-0..AS-24")
    for a, b in zip(cp, cp[1:]):
        if a not in g["slices"] or b not in g["slices"]:
            out.append(f"critical_path: unknown {a} or {b}")
        elif g["slices"][b]["wave"] < g["slices"][a]["wave"]:
            out.append(f"critical_path: wave backwards {a}->{b}")
    maxw = max(s["wave"] for s in g["slices"].values())
    missing = set(range(maxw + 1)) - {g["slices"][s]["wave"] for s in cp if s in g["slices"]}
    if missing:
        out.append(f"critical_path: waves not covered {sorted(missing)}")
    return out


_ALL_CHECKS = (check_dep_targets, check_acyclic, check_waves, check_hot_disjoint,
               check_token_unique, check_chains, check_chain_completeness, check_serialization,
               check_critical_path)


# ---- the graph is well-formed --------------------------------------------------------------------------

def test_the_shipped_graph_has_72_slices_in_24_waves(graph):
    assert len(graph["slices"]) == 72
    assert max(s["wave"] for s in graph["slices"].values()) == 23  # waves 0..23 = 24 waves
    assert graph["slices"]["AS-0"]["wave"] == 0
    assert graph["slices"]["AS-27a"]["wave"] == 1  # the break-glass slice already merged (#1228)


@pytest.mark.parametrize("check", _ALL_CHECKS, ids=[c.__name__ for c in _ALL_CHECKS])
def test_the_shipped_graph_passes_every_structural_check(graph, check):
    assert check(graph) == [], f"{check.__name__} found violations"


# ---- negative controls: each validator CATCHES its violation -------------------------------------------

def test_a_same_wave_dependency_is_caught(graph):
    """Make AS-2b (wave 2) depend on AS-2i (also wave 2): the wave-level check must flag it."""
    bad = copy.deepcopy(graph)
    bad["slices"]["AS-2b"]["deps"] = bad["slices"]["AS-2b"]["deps"] + ["AS-2i"]
    assert check_waves(bad), "a same-wave dependency must break the derived-wave check"


def test_a_shared_hot_file_in_one_wave_is_caught(graph):
    """Give AS-2b (wave 2, no hot set) the GW hot set that AS-2j already holds in wave 2."""
    bad = copy.deepcopy(graph)
    bad["slices"]["AS-2b"]["hot"] = ["GW"]
    viol = check_hot_disjoint(bad)
    assert any("GW" in v and "wave 2" in v for v in viol), viol


def test_a_second_token_holder_in_one_wave_is_caught(graph):
    """Give AS-2j (wave 2) the GP token that AS-28 already holds in wave 2."""
    bad = copy.deepcopy(graph)
    bad["slices"]["AS-2j"]["tokens"] = ["GP"]
    viol = check_token_unique(bad)
    assert any("GP" in v and "wave 2" in v for v in viol), viol


def test_a_cycle_is_caught(graph):
    """Make AS-0 depend on a downstream slice: acyclicity (and wave derivation) must flag it."""
    bad = copy.deepcopy(graph)
    bad["slices"]["AS-0"]["deps"] = ["AS-27a"]
    assert check_acyclic(bad), "a back-edge into AS-0 must break acyclicity"
    assert check_waves(bad), "a cycle must be reported by the wave check too"


def test_a_broken_chain_edge_is_caught(graph):
    """Drop AS-2j from the GW chain's dependency of AS-2c: chain agreement must flag the gap."""
    bad = copy.deepcopy(graph)
    bad["slices"]["AS-2c"]["deps"] = [d for d in bad["slices"]["AS-2c"]["deps"] if d != "AS-2j"]
    assert check_chains(bad), "a chain step that no longer depends on its predecessor must be caught"


def test_a_hot_set_holder_omitted_from_its_chain_is_caught(graph):
    """Give AS-0 (wave 0, no other GW holder) the GW hot set WITHOUT adding it to the GW chain. Same-wave
    disjointness and serialization both still pass (AS-0 precedes every GW slice), so ONLY the completeness
    check can catch that a hot-set holder is missing from its serialization chain."""
    bad = copy.deepcopy(graph)
    bad["slices"]["AS-0"]["hot"] = ["GW"]
    assert check_hot_disjoint(bad) == [] and check_serialization(bad) == []  # these do NOT catch it
    viol = check_chain_completeness(bad)
    assert any("GW" in v and "AS-0" in v for v in viol), viol


def test_an_unserialized_hot_set_holder_is_caught(graph):
    """Give AS-10b (wave 7) the CON hot set, which already has AS-4b (wave 10). CON has no chain (so
    completeness does not apply) and the two holders are in different waves (so disjointness does not apply),
    and neither depends on the other — only the serialization check can catch the missing cross-wave order."""
    bad = copy.deepcopy(graph)
    bad["slices"]["AS-10b"]["hot"] = ["CON"]
    assert check_chain_completeness(bad) == [] and check_hot_disjoint(bad) == []  # these do NOT catch it
    viol = check_serialization(bad)
    assert any("CON" in v for v in viol), viol
