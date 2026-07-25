"""S2 — the offense `default_classify` derives its DANGER determination from the ONE shared classifier of
record (`vigil_core.warden_tiers`), closing the drift the old recon→A1/else→A2 stub had, with NO change to
the gate OUTCOME (a dangerous name was A2→queue and is now A3→queue under the A1 ceiling).

Run: PYTHONPATH=integration python -m pytest integration/tests/test_warden_classifier_of_record.py -q
"""
from vigil_integration.live.wiring import default_classify
from vigil_integration.warden_gate import decide_tool


def test_dangerous_offense_names_classify_a3_like_the_kernel():
    # the drift the old stub had: these were wrongly A2; now A3, matching the sovereign kernel vocabulary.
    for name in ("git.push", "data.delete", "secrets.read", "deploy.prod", "vault.read", "config.overwrite"):
        assert default_classify(name) == "A3", name


def test_recon_tools_stay_auto_eligible_a1():
    for name in ("nmap", "httpx", "nuclei", "ffuf", "curl", "subfinder", "gau", "katana"):
        assert default_classify(name) == "A1", name


def test_non_recon_non_danger_offense_names_stay_a2():
    # read/write/egress-shaped offense names keep the pre-S2 offense floor of A2 (posture unchanged).
    for name in ("http.get", "dns.query", "port.list", "email.send", "unknownish"):
        assert default_classify(name) == "A2", name


def test_a_recon_shaped_dangerous_name_is_never_lowered():
    assert default_classify("nmap.delete") == "A3", "a danger token beats the recon override"
    assert default_classify("curl.exec") == "A3"


def test_gate_outcome_is_unchanged_under_the_live_posture():
    """Under the live offense posture (floor A2, ceiling A1) a dangerous tool still QUEUES — the A2→A3 tier
    correction changes the label, not the decision."""
    d = decide_tool("git.push", classify=default_classify, floor="A2", ceiling="A1")
    assert d.tier == "A3" and d.outcome == "queue"
    # recon on a TWIN (floor lowered to A1) still auto-runs; a dangerous tool still queues.
    assert decide_tool("nmap", classify=default_classify, floor="A1", ceiling="A1").outcome == "auto"
    assert decide_tool("git.push", classify=default_classify, floor="A1", ceiling="A1").outcome == "queue"
