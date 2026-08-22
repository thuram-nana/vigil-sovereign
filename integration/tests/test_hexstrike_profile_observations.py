"""H3 — the hexstrike brain profiles from VERIFIED, PROVENANCED OBSERVATIONS, not a blank slate.

On the production ``vigil engage --brain hexstrike`` path the brain's ``analyze_target`` used to be passed
NO observations, so every profile came out empty and the console showed a fabricated ``risk=low`` for a
target nobody had observed. These tests pin the FEED (``brains.profile_observations``) and its wiring through
the real ``BrainThink`` seam:

  * a profile built from observations REFLECTS them (open ports, services, technologies, cms, cloud), and
  * an empty observation set yields HONEST UNKNOWNS — never a fabricated risk (the negative control).

Import-clean (stdlib + the brain's own enums + the pydantic AgentState the seam already uses): no framework,
no network — so it runs in the sovereign leg.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain, TargetType, TechnologyStack
from vigil_integration.brains.profile_observations import (
    ObsKind,
    ProfileObservation,
    collect_engage_observations,
    from_scope,
    load_sidecar,
    make_observation,
    reduce_to_profile_kwargs,
)


def _state(objective: str = ""):
    return SimpleNamespace(objective=objective)


# ---- the FEED: a profile built from observations reflects them ----------------------------------

def test_profile_reflects_the_observations_fed_to_it():
    obs = [
        make_observation("open_port", "80", "sensor:nmap", 0.9),
        make_observation("service", "443/https", "sensor:nmap", 0.9),
        make_observation("tls", "8443", "sensor:sslscan", 0.8),
        make_observation("technology", "nginx", "sensor:httpx", 0.7),
        make_observation("cms", "WordPress", "sensor:wpscan", 0.85),
        make_observation("ip_address", "10.0.0.5", "authority-scope", 0.7),
    ]
    kw = reduce_to_profile_kwargs([o for o in obs if o is not None])
    prof = HexstrikeBrain().analyze_target("http://t.example/", **kw)

    assert prof.open_ports == [80, 443, 8443]          # explicit + service + tls ports all learned
    assert prof.services == {443: "https", 8443: "tls"}
    assert prof.technologies == [TechnologyStack.NGINX]
    assert prof.cms_type == "wordpress"
    assert prof.ip_addresses == ["10.0.0.5"]
    # a real observed surface earns a real (non-unknown) risk + a non-zero confidence
    assert prof.attack_surface_score > 0.0
    assert prof.risk_level != "unknown" and prof.confidence_score > 0.0


def test_unknown_stays_unknown_never_guessed():
    # an unrecognised technology fingerprint maps to nothing (not shoved in as UNKNOWN)
    kw = reduce_to_profile_kwargs([make_observation("technology", "some-bespoke-appserver", "s", 0.9)])
    assert kw["technologies"] == []
    # two equally-confident CONFLICTING scalar observations => the field stays unknown (fail-closed)
    amb = [make_observation("cloud_provider", "aws", "s1", 0.8),
           make_observation("cloud_provider", "gcp", "s2", 0.8)]
    assert reduce_to_profile_kwargs(amb)["cloud_provider"] is None
    # a higher-confidence value DOES win (no false tie)
    clear = [make_observation("cloud_provider", "aws", "s1", 0.9),
             make_observation("cloud_provider", "gcp", "s2", 0.4)]
    assert reduce_to_profile_kwargs(clear)["cloud_provider"] == "aws"


def test_target_type_derives_from_observations_or_falls_back_honestly():
    # an OpenAPI/Swagger descriptor => api_endpoint; a K8s/IaC manifest => cloud_service
    assert reduce_to_profile_kwargs(
        [make_observation("api_descriptor", "openapi.json", "s", 0.9)])["target_type"] == "api_endpoint"
    assert reduce_to_profile_kwargs(
        [make_observation("container_orch", "deployment.yaml", "s", 0.9)])["target_type"] == "cloud_service"
    # an explicit, higher-confidence target_type wins over a derived one
    mixed = [make_observation("api_descriptor", "openapi.json", "s", 0.5),
             make_observation("target_type", "network_host", "s", 0.9)]
    assert reduce_to_profile_kwargs(mixed)["target_type"] == "network_host"
    # no target_type observation => None, so analyze_target's own deterministic _infer_type runs (honest,
    # from the url string) — not a fabrication
    prof = HexstrikeBrain().analyze_target("http://t.example/api", target_type=None)
    assert prof.target_type is TargetType.API_ENDPOINT


# ---- the NEGATIVE CONTROL: empty observations => honest unknowns, not fabricated risk -----------

def test_empty_observation_set_yields_honest_unknowns_not_fabricated_risk():
    kw = collect_engage_observations(slug="loopback", base_dir="/nonexistent-vigil-base", scope=[])
    assert kw == {"target_type": None, "ip_addresses": [], "open_ports": [], "services": {},
                  "technologies": [], "cms_type": None, "cloud_provider": None}
    prof = HexstrikeBrain().analyze_target("http://t.example/", **kw)
    assert prof.risk_level == "unknown", "an unobserved target must not report a fabricated 'low' risk"
    assert prof.confidence_score == 0.0
    assert prof.open_ports == [] and prof.services == {} and prof.technologies == []


def test_empty_observations_do_not_change_the_proposed_chain():
    """The honest-unknown change must not alter what a plain --brain engage proposes: the chain is driven by
    target type + objective, so an empty (honest-unknown) profile proposes the SAME steps as before."""
    brain = HexstrikeBrain()
    none_seam = BrainThink(brain, target="http://t.example/", objective="comprehensive", observations=None)
    empty_seam = BrainThink(brain, target="http://t.example/", objective="comprehensive",
                            observations=collect_engage_observations(slug="s", base_dir="/nope", scope=[]))

    def _drive(seam):
        out = []
        for _ in range(40):
            d = seam(_state())
            if d.action.value != "use_tool":
                break
            out.append((d.tool.tool_name, tuple(sorted(d.tool.tool_args.items()))))
        return out

    assert _drive(none_seam) == _drive(empty_seam)


# ---- the WIRING: observations flow through BrainThink into the persisted proposal ---------------

def test_brainthink_persists_a_profile_that_reflects_the_observations(tmp_path):
    kw = reduce_to_profile_kwargs([
        make_observation("open_port", "443", "sensor:nmap", 0.9),
        make_observation("technology", "django", "sensor:repo", 0.8),
        make_observation("cloud_provider", "gcp", "sensor:cloud", 0.9),
    ])
    run_dir = tmp_path / "run"
    seam = BrainThink(HexstrikeBrain(), target="http://t.example/", objective="comprehensive",
                      observations=kw, proposal_out=run_dir)
    seam(_state())  # first call builds the chain + persists the proposal

    doc = json.loads((run_dir / "brain-proposal.json").read_text(encoding="utf-8"))
    prof = doc["profile"]
    assert prof["open_ports"] == [443]
    assert prof["technologies"] == ["python"]          # django -> the PYTHON stack
    assert prof["cloud_provider"] == "gcp"
    assert prof["target_type"] == "cloud_service"       # cloud_provider present => inferred cloud service
    assert prof["risk_level"] != "unknown"              # a real surface => a real risk


def test_brainthink_empty_feed_persists_honest_unknowns(tmp_path):
    """The negative control at the persistence seam: the console panel must never read a fabricated risk."""
    run_dir = tmp_path / "run"
    seam = BrainThink(HexstrikeBrain(), target="http://t.example/", objective="comprehensive",
                      observations=collect_engage_observations(slug="s", base_dir="/nope", scope=[]),
                      proposal_out=run_dir)
    seam(_state())
    prof = json.loads((run_dir / "brain-proposal.json").read_text(encoding="utf-8"))["profile"]
    assert prof["risk_level"] == "unknown"
    assert prof["confidence_score"] == 0.0
    assert prof["open_ports"] == [] and prof["technologies"] == []


# ---- the SOURCES: scope literal-IPs + a normalized sidecar (fail-soft) --------------------------

def test_scope_yields_only_literal_ip_observations_never_resolves_names():
    obs = from_scope(["10.0.0.5", "example.com", "*.wild.com", "127.0.0.1", "10.0.0.5"])
    assert [(o.kind, o.value) for o in obs] == [
        (ObsKind.IP_ADDRESS, "10.0.0.5"), (ObsKind.IP_ADDRESS, "127.0.0.1")]
    assert all(o.provenance == "authority-scope" and 0.0 < o.confidence <= 1.0 for o in obs)


def test_sidecar_loads_normalized_rows_and_drops_malformed(tmp_path):
    sc = tmp_path / "observations.json"
    sc.write_text(json.dumps([
        {"kind": "open_port", "value": 8080, "provenance": "sensor:nmap", "confidence": 0.9},
        {"kind": "not-a-kind", "value": "x", "provenance": "s", "confidence": 0.9},   # dropped: bad kind
        {"kind": "cms", "value": "drupal", "provenance": "s", "confidence": 1.5},      # dropped: conf > 1
        {"kind": "cms", "value": "", "provenance": "s", "confidence": 0.5},            # dropped: empty value
        {"kind": "technology", "value": "php", "provenance": "s", "confidence": 0.0},  # dropped: conf == 0
        "not-a-dict",                                                                   # dropped: not a row
    ]), encoding="utf-8")
    rows = load_sidecar(sc)
    assert [(r.kind, r.value) for r in rows] == [(ObsKind.OPEN_PORT, "8080")]
    # absent / unreadable file => [] (fail-soft), never a crash
    assert load_sidecar(tmp_path / "does-not-exist.json") == []


def test_collect_merges_scope_and_sidecar_via_precedence(tmp_path):
    sc = tmp_path / "custom-obs.json"
    sc.write_text(json.dumps({"observations": [
        {"kind": "service", "value": "22/ssh", "provenance": "sensor:nmap", "confidence": 0.95}]}),
        encoding="utf-8")
    kw = collect_engage_observations(slug="s", base_dir=str(tmp_path), scope=["10.0.0.9"],
                                     sidecar_path=str(sc))
    assert kw["ip_addresses"] == ["10.0.0.9"]           # from scope
    assert kw["open_ports"] == [22] and kw["services"] == {22: "ssh"}   # from the explicit sidecar


def test_make_observation_is_total_on_bad_input():
    assert make_observation("open_port", None, "s", 0.5) is None
    assert make_observation("open_port", "80", "s", "not-a-number") is None
    assert make_observation("bad-kind", "80", "s", 0.5) is None
    assert make_observation("open_port", "80", "s", 0.5) == ProfileObservation(
        kind=ObsKind.OPEN_PORT, value="80", provenance="s", confidence=0.5)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
