"""codescan — the deterministic local-codebase scan that grounds a gated fix (end-to-end round-trip).

A DAA static-rule match over the operator's own source is a re-runnable STATIC fact. run_codescan writes each
into the engagement's signed <base>/<slug>.spine so `vigil patch --from-spine` (and finding_from_spine) can
ground a gated fix on it, and verify_finding_cleared re-runs the rule to confirm a fix removed it.

Needs the framework (DAA analyzers), so it importorskips it and runs in the OFFENSE CI leg."""
from __future__ import annotations

import pytest

pytest.importorskip("framework")   # framework.v2.analysis (DAA) — offense leg only

from vigil_integration import codescan                              # noqa: E402
from vigil_integration.live.trusted_finding import finding_from_spine  # noqa: E402


def _vuln(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "import subprocess\n"
        "def run(x):\n"
        "    return subprocess.call('ls ' + x, shell=True)\n", encoding="utf-8")
    return src


def test_ref_roundtrip():
    ref = codescan.make_ref("DAA-SHELL-TRUE", "pkg/app.py", 3)
    rule, path, line = codescan.parse_ref(ref)
    assert rule == "DAA-SHELL-TRUE" and path == "pkg/app.py" and line == 3
    # argv-safe: no separators / traversal / leading dash
    assert " " not in ref and "/" not in ref and ".." not in ref and not ref.startswith("-")


def test_scan_writes_signed_spine_and_finding_from_spine_reads_it(tmp_path):
    src = _vuln(tmp_path)
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="cb", base_dir=str(base), max_files=50)
    assert res["total"] >= 1
    from pathlib import Path
    assert Path(res["spine"]).is_file()
    # every codescan finding is a re-runnable static fact, CWE-tagged, with an argv-safe ref
    f0 = res["findings"][0]
    assert f0["grounding"] == "fact" and f0["verified_by_oracle"] is True
    assert f0["cwe"] and f0["ref"]
    # the signed spine round-trips: finding_from_spine verifies + rebuilds it into a CONFIRMED finding
    tf = finding_from_spine(base_dir=str(base), slug="cb", target_repo=str(src), finding_ref=f0["ref"])
    assert tf.confirmed is True and tf.ref == f0["ref"] and (tf.evidence_ref or "").strip()
    assert tf.target                                   # "path:line" — so the fix proposer can locate the file


def test_verify_oracle_fires_then_clears(tmp_path):
    src = _vuln(tmp_path)
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="cb", base_dir=str(base), max_files=50)
    shell = [f for f in res["findings"] if f["ref"].startswith("DAA-SHELL-TRUE")][0]
    before = codescan.verify_finding_cleared(root=str(src), ref=shell["ref"], max_files=50)
    assert before["cleared"] is False and before["still_fires_at"]
    # apply the fix (drop shell=True; pass args as a list) and re-verify -> cleared
    (src / "app.py").write_text(
        "import subprocess\n"
        "def run(x):\n"
        "    return subprocess.call(['ls', x])\n", encoding="utf-8")
    after = codescan.verify_finding_cleared(root=str(src), ref=shell["ref"], max_files=50)
    assert after["cleared"] is True and after["still_fires_at"] == []


def test_a_fact_finding_requires_signed_evidence(tmp_path):
    """Doctrine at the type level: the spine Finding used for a codescan fact cannot carry an empty evidence
    reference (a forged evidence-less fact is refused by the model validator)."""
    from vigil_integration.agent.state import Finding
    with pytest.raises(Exception):
        Finding(ref="x", status="fact", evidence_ref="   ")


def test_rescan_supersedes_by_recency_not_hash(tmp_path):
    """A re-scan (or a slug reused across repos) must SUPERSEDE the prior scan by recency — not let a stale
    or foreign snapshot shadow the latest via hash-ordered global-latest (crypto-notary MEDIUM). The monotonic
    seq makes the latest scan win, and a superseded ref is honestly no longer found."""
    from vigil_integration.live.trusted_finding import TrustedFindingError
    a = tmp_path / "a"; a.mkdir()
    (a / "x.py").write_text("import subprocess\ndef f(y):\n    return subprocess.call('ls '+y, shell=True)\n", encoding="utf-8")
    b = tmp_path / "b"; b.mkdir()
    (b / "y.py").write_text("import yaml\ndef g(s):\n    return yaml.load(s)\n", encoding="utf-8")
    base = tmp_path / "base"
    ra = codescan.run_codescan(root=str(a), slug="shared", base_dir=str(base), max_files=20)
    rb = codescan.run_codescan(root=str(b), slug="shared", base_dir=str(base), max_files=20)
    # the LATEST scan's finding reads back
    tf = finding_from_spine(base_dir=str(base), slug="shared", target_repo=str(b), finding_ref=rb["findings"][0]["ref"])
    assert tf.ref == rb["findings"][0]["ref"]
    # a ref from the SUPERSEDED prior scan is no longer selectable (no wrong-repo / stale patch)
    with pytest.raises(TrustedFindingError):
        finding_from_spine(base_dir=str(base), slug="shared", target_repo=str(a), finding_ref=ra["findings"][0]["ref"])


def test_daa_static_qualifier_survives_to_triagefinding(tmp_path):
    """Honesty (crypto-notary MEDIUM): the daa:<rule_id> static qualifier must survive the spine->patch
    boundary so a code fix is never mistaken for a live-exploit fact."""
    src = _vuln(tmp_path); base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="cb", base_dir=str(base), max_files=50)
    tf = finding_from_spine(base_dir=str(base), slug="cb", target_repo=str(src), finding_ref=res["findings"][0]["ref"])
    assert tf.source.startswith("daa:")     # not a bare/anonymous "confirmed" — labelled as a static match


def test_dirty_rule_ids_roundtrip_and_stay_argv_safe():
    """make_ref/parse_ref are exact inverses AND argv-safe over EVERY rule_id, incl. external ids with
    ~, spaces, or leading dashes (crypto-notary/red-pen 1c+2b)."""
    for rid in ["DAA-EVAL", "sem~grep~rule", "rule with space", "-Xdash", "py.lang.security.audit.eval"]:
        ref = codescan.make_ref(rid, "pkg/app.py", 7)
        assert codescan._ref_is_argv_safe(ref), rid
        rr, pp, ll = codescan.parse_ref(ref)
        assert (rr, pp, ll) == (rid, "pkg/app.py", 7), (rid, ref, rr, pp, ll)


def _reverify(res: dict):
    """Re-run the pure oracle over the scan's retained static-FACT contexts exactly as `python3 -m framework.v2
    verify <scan.json>` does — serialise the scan result to JSON, reload it, and drive reverify_document (the
    CLI's own re-verification entry point). Returns the list of ReverifyResult."""
    import json
    from framework.v2.verify.reverify import reverify_document
    doc = json.loads(json.dumps(res))          # prove it survives the on-disk JSON round-trip the CLI reads
    return reverify_document(doc)


def test_weak_crypto_region_emits_reverifiable_static_fact(tmp_path):
    """INV2: a codescan over a planted weak-crypto (MD5) region emits an oracle-confirmed STATIC FACT that
    carries its retained source region and RE-VERIFIES OFFLINE via `framework.v2 verify`; a tamper that removes
    the broken-crypto property no longer re-fires (tamper-reject)."""
    src = tmp_path / "src"; src.mkdir()
    (src / "sign.py").write_text(
        "import hashlib\n"
        "def sign(data):\n"
        "    return hashlib.md5(data).hexdigest()\n", encoding="utf-8")
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="wc", base_dir=str(base), max_files=20)

    # the DAA weak-hash finding is ALSO confirmed by the pure STATIC_RULE oracle and surfaced as a static FACT
    daa = [f for f in res["findings"] if f["ref"].startswith("DAA-WEAK-HASH")]
    assert daa and daa[0]["static_oracle_confirmed"] is True
    sfs = res["static_facts"]
    assert len(sfs) == 1
    sf = sfs[0]
    assert sf["bug_class"] == "static_broken_crypto"
    assert sf["confirmed_by"] == "static_rule" and sf["kind"] == "active"
    assert sf["oracle_context"]["static_rule"]["rule_id"] == "broken-crypto-invocation"
    # the scan JSON is directly re-verifiable (the standard `active_findings` convention)
    assert res["active_findings"] == sfs

    # re-verifies OFFLINE from the retained bytes
    results = _reverify(res)
    assert len(results) == 1 and results[0].ok and results[0].reproduced
    assert results[0].confirmed_by == "static_rule"

    # TAMPER-REJECT: mutate the retained source so the broken-crypto property is gone → no re-fire
    import copy
    tampered = copy.deepcopy(res)
    tampered["active_findings"][0]["oracle_context"]["static_rule"]["source"] = (
        "import hashlib\ndef sign(data):\n    return hashlib.sha256(data).hexdigest()\n")
    tresults = _reverify(tampered)
    assert len(tresults) == 1 and not tresults[0].reproduced


def test_strong_primitive_safe_twin_stays_silent(tmp_path):
    """INV2 negative control: a safe twin using a STRONG primitive (SHA-256) is not even flagged by DAA, so it
    emits NO static FACT — the scan stays silent on it (never a false static FACT)."""
    src = tmp_path / "src"; src.mkdir()
    (src / "sign.py").write_text(
        "import hashlib\n"
        "def sign(data):\n"
        "    return hashlib.sha256(data).hexdigest()\n", encoding="utf-8")
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="safe", base_dir=str(base), max_files=20)
    assert not [f for f in res["findings"] if f["ref"].startswith("DAA-WEAK-HASH")]
    assert res["static_facts"] == [] and res["summary"]["static_facts"] == 0


def test_usedforsecurity_false_daa_match_stays_lead(tmp_path):
    """INV2 negative control: a DAA regex match the SOUND oracle refuses (a hash explicitly marked
    ``usedforsecurity=False`` — a non-security checksum) is retained as a DAA finding but is NEVER promoted to a
    static FACT. The oracle's authority overrides the regex: a static FACT is minted only when the property
    genuinely holds."""
    src = tmp_path / "src"; src.mkdir()
    (src / "ck.py").write_text(
        "import hashlib\n"
        "def checksum(data):\n"
        "    return hashlib.md5(data, usedforsecurity=False).hexdigest()\n", encoding="utf-8")
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="ufs", base_dir=str(base), max_files=20)
    daa = [f for f in res["findings"] if f["ref"].startswith("DAA-WEAK-HASH")]
    assert daa, "DAA regex still flags md5( — it only says WHERE to look"
    assert daa[0]["static_oracle_confirmed"] is False
    assert res["static_facts"] == []
    assert _reverify(res) == []                # nothing re-verifiable; never a false static FACT


def test_static_fact_is_python_only(tmp_path):
    """INV2: the STATIC_RULE oracle re-parses Python only, so a weak-crypto pattern in a non-Python file is not
    promoted to a static FACT (it stays a DAA finding). Keeps the single-region offline oracle sound."""
    src = tmp_path / "src"; src.mkdir()
    (src / "app.js").write_text("const h = md5(payload);\n", encoding="utf-8")
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="js", base_dir=str(base), max_files=20)
    # whether or not a DAA rule matches the .js, NO static FACT may be minted for a non-Python file
    assert res["static_facts"] == []
    assert all(f.get("static_rule_id") is None for f in res["findings"])


def test_moved_vuln_is_not_reported_cleared(tmp_path):
    """A vulnerable file that MOVES (rename/refactor) must NOT report cleared — cleared requires the
    rule to fire NOWHERE, not merely at the recorded path (red-pen 1a HIGH)."""
    import os
    src = tmp_path / "src"; src.mkdir()
    (src / "app.py").write_text("def f(x):" + chr(10) + "    return eval(x)" + chr(10), encoding="utf-8")
    base = tmp_path / "base"
    res = codescan.run_codescan(root=str(src), slug="mv", base_dir=str(base), max_files=20)
    ref = [f for f in res["findings"] if f["ref"].startswith("DAA-EVAL")][0]["ref"]
    assert codescan.verify_finding_cleared(root=str(src), ref=ref, max_files=20)["cleared"] is False
    os.rename(src / "app.py", src / "renamed.py")   # eval() still present, just moved
    v = codescan.verify_finding_cleared(root=str(src), ref=ref, max_files=20)
    assert v["cleared"] is False and v["moved"] is True


def test_include_paths_diff_scopes_the_scan(tmp_path):
    """repo-connect Slice 3a: include_paths keeps ONLY findings in the PR's changed files (diff-scope),
    while a full scan (include_paths=None) is byte-identical to before."""
    src = tmp_path / "src"
    src.mkdir()
    for name in ("app.py", "other.py"):
        (src / name).write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
    base = tmp_path / "base"
    full = codescan.run_codescan(root=str(src), slug="full", base_dir=str(base), max_files=20)
    full_paths = {f["location"].rsplit(":", 1)[0] for f in full["findings"]}
    assert "app.py" in full_paths and "other.py" in full_paths          # a full scan flags both files
    # diff-scope to app.py only → other.py's finding is excluded, the spine snapshot is scoped to the PR
    scoped = codescan.run_codescan(root=str(src), slug="scoped", base_dir=str(base),
                                   max_files=20, include_paths={"app.py"})
    scoped_paths = {f["location"].rsplit(":", 1)[0] for f in scoped["findings"]}
    assert scoped_paths == {"app.py"} and scoped["total"] < full["total"]
    # an empty include set scopes to NOTHING (a PR with no in-scope changed files → no findings)
    none_scoped = codescan.run_codescan(root=str(src), slug="none", base_dir=str(base),
                                        max_files=20, include_paths=set())
    assert none_scoped["total"] == 0


def test_include_paths_namespace_mismatch_fails_closed(tmp_path):
    """repo-connect Slice 3a (red-pen HIGH): a non-empty include_paths that resolves to NO file under the
    scan root is a checkout-root/repo-root namespace MISMATCH (e.g. a tarball-checkout prefix) — it must
    RAISE (refuse a silent clean), never return an empty 'clean' result on a vulnerable PR."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
    base = tmp_path / "base"
    with pytest.raises(FileNotFoundError):
        codescan.run_codescan(root=str(src), slug="mm", base_dir=str(base), max_files=20,
                              include_paths={"owner-repo-deadbeef/app.py"})   # prefixed form → resolves to nothing
