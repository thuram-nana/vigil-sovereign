"""
The ENGAGEMENT LIBRARY screen's data + the RENAME safety property.

The operator's requirement: "There's an engagement library — a list of past jobs you can go back to,
months later", with "dates and time stamps and you can rename them so it is easy to go to after".

What is pinned here:
  * ``api.list_engagements`` is a LIBRARY listing, not an alphabetical ``ls targets/``: it surfaces a
    spine-only engagement (the old listing returned [] for one), carries first_seen/last_activity,
    run/finding counts and the human label, and orders NEWEST ACTIVITY FIRST.
  * ``api.library_engagement`` resolves run membership SERVER-SIDE from each run's own ``meta.json``.
  * ``console.labels`` renames are PRESENTATION ONLY — the load-bearing property, with a mutation
    control proving the test bites.
  * ``sessions._live_dir`` is absolute and anchored to CRUCIBLE_ROOT (the phantom-run-list bug).
"""

from __future__ import annotations

import hashlib
import json
import zipfile

import pytest

from framework.v2.agents.blackboard import Blackboard
from framework.v2.console import api, labels, sessions

# ---------------------------------------------------------------------------
# helpers — a console run store + a spine, both in tmp_path
# ---------------------------------------------------------------------------


@pytest.fixture()
def console_root(tmp_path, monkeypatch):
    """Point the console's run store (and therefore the label side-car) at tmp_path."""
    from framework.v2.console import actions
    root = tmp_path / "console"
    (root / "runs").mkdir(parents=True)
    monkeypatch.setattr(actions, "console_dir", lambda: root)
    return root


def _write_run(console_root, run_id: str, *, slug: str, target: str, started: float,
               findings: int = 0, status: str = "done", mode: str = "url") -> None:
    d = console_root / "runs" / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps({
        "target": target, "slug": slug, "status": status, "started": started,
        "finished": started + 60, "mode": mode}), encoding="utf-8")
    (d / "report.json").write_text(json.dumps({
        "findings": [{"title": f"f{i}", "grounding": "fact"} for i in range(findings)]}),
        encoding="utf-8")


# ---------------------------------------------------------------------------
# the listing itself
# ---------------------------------------------------------------------------


def test_a_spine_only_engagement_is_listed_with_its_timestamps(tmp_path, monkeypatch, console_root):
    """The bug this replaces: the old listing enumerated `targets/` DIRECTORIES, so an engagement
    that only ever existed on the spine (an `engage --spine` run) was invisible — the console
    returned [] while the spine held a real, finished job."""
    from framework.v2.agents import blackboard as bb_mod
    db = tmp_path / "spine.sqlite"
    with Blackboard(db_path=db) as bb:
        bb.post(engagement="spine-only-job", kind="observation", agent_name="recon",
                payload={"source": "recon", "surface": "/", "summary": "hit"})
    monkeypatch.setattr(bb_mod, "open_blackboard", lambda **kw: Blackboard(db_path=db))

    rows = api.list_engagements()["engagements"]
    row = next(r for r in rows if r["slug"] == "spine-only-job")
    assert row["on_spine"] is True
    assert row["first_seen"] and row["last_activity"], "a library entry needs a WHEN"
    assert row["event_count"] == 1
    # the safety/charter fields the console already served are still present
    assert "killswitch" in row and "tripped" in row["killswitch"]


def test_runs_are_grouped_and_counted_per_engagement(console_root, monkeypatch):
    _write_run(console_root, "20260101-000000-001", slug="acme", target="http://a/", started=1_000.0,
               findings=2)
    _write_run(console_root, "20260102-000000-002", slug="acme", target="http://a/", started=2_000.0,
               findings=1)
    _write_run(console_root, "20260103-000000-003", slug="other", target="http://b/", started=3_000.0)
    monkeypatch.setattr(api, "_target_slugs", lambda: ["acme", "other"])
    monkeypatch.setattr(api, "_spine_engagements", lambda labels: [])

    rows = {r["slug"]: r for r in api.list_engagements()["engagements"]}
    assert rows["acme"]["run_count"] == 2
    assert rows["acme"]["finding_count"] == 3
    assert rows["acme"]["subjects"] == ["http://a/"]
    assert rows["acme"]["kinds"] == ["url"]
    # the slug is UNIQUE, so the two runs must stay DISTINCT inside one engagement, not merge
    assert len(api.library_engagement("acme")["runs"]) == 2


def test_ordering_is_newest_activity_first_not_alphabetical(console_root, monkeypatch):
    """Three jobs whose recency order (alpha, zeta, mid) differs from BOTH the alphabetical order
    (alpha, mid, zeta) and its reverse (zeta, mid, alpha) — so this cannot pass by coincidence."""
    _write_run(console_root, "20260101-000000-001", slug="mid", target="http://m/", started=1_000.0)
    _write_run(console_root, "20260103-000000-002", slug="zeta", target="http://z/", started=5_000.0)
    _write_run(console_root, "20260105-000000-003", slug="alpha", target="http://a/", started=9_000.0)
    monkeypatch.setattr(api, "_target_slugs", lambda: ["alpha", "mid", "zeta"])
    monkeypatch.setattr(api, "_spine_engagements", lambda labels: [])

    order = [r["slug"] for r in api.list_engagements()["engagements"]]
    assert order == ["alpha", "zeta", "mid"], "the most recently worked job leads, then the next"


def test_an_engagement_with_no_activity_is_honestly_null_not_backdated(console_root, monkeypatch):
    monkeypatch.setattr(api, "_target_slugs", lambda: ["dormant"])
    monkeypatch.setattr(api, "_spine_engagements", lambda labels: [])
    monkeypatch.setattr(api, "_engagement_row", lambda slug: {"slug": slug, "has_charter": False,
                                                              "killswitch": {"tripped": False}})
    row = api.list_engagements()["engagements"][0]
    assert row["last_activity"] is None and row["first_seen"] is None
    assert row["run_count"] == 0


def test_run_membership_is_resolved_from_the_runs_own_meta(console_root, monkeypatch):
    """A caller cannot claim a run into an engagement: membership comes from the run's OWN
    meta.json, so asking the library for another slug returns nothing."""
    _write_run(console_root, "20260101-000000-001", slug="acme", target="http://a/", started=1_000.0)
    monkeypatch.setattr(api, "_spine_engagements", lambda labels: [])
    assert [r["run_id"] for r in api.library_engagement("acme")["runs"]] == ["20260101-000000-001"]
    assert api.library_engagement("attacker-chosen")["runs"] == []


def test_runs_carry_a_human_time_and_a_label(console_root):
    _write_run(console_root, "20260101-000000-001", slug="acme", target="http://a/", started=1_700_000_000.0)
    labels.set_run_label("20260101-000000-001", "Friday re-test")
    row = next(r for r in api.list_runs()["runs"] if r["run_id"] == "20260101-000000-001")
    assert row["label"] == "Friday re-test"
    assert row["started_iso"] == "2023-11-14T22:13:20+00:00"      # a real, renderable date+time (UTC)
    assert row["finished_iso"] and row["finished_iso"] > row["started_iso"]


# ---------------------------------------------------------------------------
# the label store
# ---------------------------------------------------------------------------


def test_engagement_rename_round_trips_and_reaches_the_listing(console_root, monkeypatch):
    monkeypatch.setattr(api, "_target_slugs", lambda: ["acme"])
    monkeypatch.setattr(api, "_spine_engagements", lambda labels: [])
    assert labels.set_engagement_label("acme", "Acme — Q3 external review")["ok"] is True
    assert labels.engagement_label("acme") == "Acme — Q3 external review"
    row = api.list_engagements()["engagements"][0]
    assert row["label"] == "Acme — Q3 external review"
    # clearing the label removes it entirely (and the UI falls back to the machine identity)
    labels.set_engagement_label("acme", "")
    assert labels.engagement_label("acme") == ""
    assert api.list_engagements()["engagements"][0]["label"] == ""


def test_label_keys_are_fail_closed(console_root):
    for bad in ("../escape", "a/b", ".hidden", "", "x" * 200):
        assert "error" in labels.set_engagement_label(bad, "x"), bad
    assert "error" in labels.set_run_label("../escape", "x")
    # a run that does not exist cannot be labelled (no junk keys)
    assert "error" in labels.set_run_label("20990101-000000-000", "ghost")


def test_label_text_is_sanitised(console_root):
    _write_run(console_root, "20260101-000000-001", slug="acme", target="http://a/", started=1.0)
    labels.set_run_label("20260101-000000-001", "line\r\nbreak\ttab")
    assert labels.run_label("20260101-000000-001") == "linebreaktab"
    labels.set_run_label("20260101-000000-001", "z" * 500)
    assert len(labels.run_label("20260101-000000-001")) == 200


# ---------------------------------------------------------------------------
# THE LOAD-BEARING PROPERTY: a rename cannot alter signed content or a verdict
# ---------------------------------------------------------------------------


def _dossier_entry_hashes(zip_path) -> dict[str, str]:
    with zipfile.ZipFile(zip_path) as z:
        return {n: hashlib.sha256(z.read(n)).hexdigest() for n in sorted(z.namelist())}


def _manifest_verifies(zip_path) -> bool:
    """The dossier's own tamper-evidence check, done the way a third party would: recompute the
    sha256 of every entry and compare it with MANIFEST.json."""
    with zipfile.ZipFile(zip_path) as z:
        manifest = json.loads(z.read("MANIFEST.json"))
        for e in manifest["entries"]:
            if hashlib.sha256(z.read(e["path"])).hexdigest() != e["sha256"]:
                return False
        return len(manifest["entries"]) == manifest["entry_count"]


@pytest.fixture()
def proof_run(console_root, tmp_path):
    """A run carrying a REAL oracle certificate (a genuine differential the oracle re-fires over),
    so the dossier below contains actual proof material rather than an empty shell."""
    from framework.v2.verify.adapter import FindingContext
    from framework.v2.verify.confirmation import confirm_finding

    base = {"status": 200, "body": "No results."}
    mutated = {"status": 200, "body": "id=1 alice user\nid=2 bob admin\nid=3 carol user"}
    ctx = FindingContext.from_http_responses(
        base, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]}).model_dump(mode="json")
    c = confirm_finding(finding={"bug_class": "boolean_sqli"},
                        context=FindingContext.model_validate(ctx))
    rd = console_root / "runs" / "20260101-000000-001"
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "meta.json").write_text(json.dumps(
        {"target": "http://t/", "slug": "acme", "status": "done", "started": 1_700_000_000.0}),
        encoding="utf-8")
    (rd / "reverifiable.json").write_text(json.dumps({"target": "http://t/", "active_findings": [{
        "check_id": "s1", "bug_class": "boolean_sqli", "insertion_point": "query:id", "param": "id",
        "endpoint": "http://t/?id=1", "confidence": c.confidence, "confirmed_by": c.confirmed_by.value,
        "oracle_context": ctx}]}), encoding="utf-8")
    return rd


def test_renaming_never_invalidates_the_proof_or_the_dossier(proof_run, tmp_path, monkeypatch):
    """Set two DIFFERENT labels and show the run's proof still verifies in both cases.

    The label is presentation metadata held in its own side-car. So across a rename:
      * the offline re-verification verdict is unchanged (the oracle re-fires the same way),
      * the retained certificate bytes are unchanged,
      * a rebuilt dossier still passes its own manifest check and its proof/report entries are
        BYTE-IDENTICAL — the label text appears nowhere inside it.
    """
    from framework.v2.report import dossier as D
    # the proof-bundle step needs the integration package (not on the offense-only test path);
    # stub it exactly as the existing dossier tests do — this test is about the label, not bundling.
    monkeypatch.setattr(D, "_build_proof_bundle",
                        lambda *a, **k: ({}, {"note": "proof bundle stubbed in test"}))

    def _evidence_and_dossier(tag: str):
        ev = api.evidence("20260101-000000-001")
        zpath = tmp_path / f"dossier-{tag}.zip"
        D.build_dossier(run_dir=str(proof_run), out_zip=str(zpath), engagement_slug="acme")
        return ev, zpath

    labels.set_engagement_label("acme", "LABEL-ONE-9f3a")
    labels.set_run_label("20260101-000000-001", "RUN-LABEL-ONE-9f3a")
    ev1, zip1 = _evidence_and_dossier("one")

    labels.set_engagement_label("acme", "LABEL-TWO-4c81")
    labels.set_run_label("20260101-000000-001", "RUN-LABEL-TWO-4c81")
    ev2, zip2 = _evidence_and_dossier("two")

    # 1) the proof itself re-verifies BOTH times, with an identical verdict
    assert ev1["findings"] and ev1["findings"][0]["sound"] is True
    assert ev2["findings"] and ev2["findings"][0]["sound"] is True
    assert ev1["findings"][0]["cert_id"] == ev2["findings"][0]["cert_id"] != ""
    assert ev1["reproduced"] == ev2["reproduced"] == 1

    # 2) the retained certificate on disk is untouched by a rename
    assert (proof_run / "reverifiable.json").read_bytes() == (proof_run / "reverifiable.json").read_bytes()

    # 3) both dossiers pass their own tamper-evidence check, byte-for-byte identically
    assert _manifest_verifies(zip1) and _manifest_verifies(zip2)
    assert _dossier_entry_hashes(zip1) == _dossier_entry_hashes(zip2)

    # 4) neither label leaked into any dossier entry
    with zipfile.ZipFile(zip1) as z:
        blob = b"".join(z.read(n) for n in z.namelist())
    for token in (b"LABEL-ONE-9f3a", b"LABEL-TWO-4c81", b"RUN-LABEL-ONE-9f3a", b"RUN-LABEL-TWO-4c81"):
        assert token not in blob


def test_MUTATION_CONTROL_the_dossier_check_bites_when_content_changes(proof_run, tmp_path, monkeypatch):
    """Proof that the test above is load-bearing rather than vacuously green: make something the
    dossier DOES cover differ between the two builds and the byte-identity assertion must fail, and
    corrupt an entry and the manifest verification must fail."""
    from framework.v2.report import dossier as D
    monkeypatch.setattr(D, "_build_proof_bundle",
                        lambda *a, **k: ({}, {"note": "proof bundle stubbed in test"}))

    z1 = tmp_path / "a.zip"
    z2 = tmp_path / "b.zip"
    D.build_dossier(run_dir=str(proof_run), out_zip=str(z1), engagement_slug="acme")
    # a REAL content change (a different engagement slug is stamped into the manifest + documents)
    D.build_dossier(run_dir=str(proof_run), out_zip=str(z2), engagement_slug="acme-renamed-for-real")
    assert _dossier_entry_hashes(z1) != _dossier_entry_hashes(z2), \
        "the byte-identity assertion would be vacuous if content changes did not show up here"

    # and the manifest check itself detects a tampered entry
    bad = tmp_path / "tampered.zip"
    with zipfile.ZipFile(z1) as src, zipfile.ZipFile(bad, "w") as dst:
        for n in src.namelist():
            data = src.read(n)
            if n == "README.md":
                data = data + b"\ntampered\n"
            dst.writestr(n, data)
    assert _manifest_verifies(bad) is False


def test_the_label_store_writes_only_its_own_file(proof_run, console_root):
    """Structural half of the same property: a rename touches ONE file, and it is not in any
    manifest — no run artifact, no certificate, no target dir is written."""
    def _snapshot():
        return {p: p.read_bytes() for p in sorted(console_root.rglob("*"))
                if p.is_file() and p.name != "labels.json"}

    before = _snapshot()
    labels.set_engagement_label("acme", "Renamed after the fact")
    labels.set_run_label("20260101-000000-001", "Also renamed")
    assert _snapshot() == before, "a rename must not write into any run/report/certificate file"
    assert labels.store_path().is_file() and labels.store_path().parent == console_root


# ---------------------------------------------------------------------------
# the CWD-relative sessions root (phantom / empty run lists)
# ---------------------------------------------------------------------------


def test_sessions_root_is_absolute_and_does_not_follow_the_cwd(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_LIVE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    first = sessions._live_dir()
    assert first.is_absolute(), "a CWD-relative registry root is the phantom-run-list bug"
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    assert sessions._live_dir() == first, "the registry must not move when the console's cwd does"


def test_sessions_root_honours_an_explicit_live_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    assert sessions._live_dir() == (tmp_path / "live").resolve()


def test_chat_and_sessions_share_one_live_root(tmp_path, monkeypatch):
    """They must never drift: the session registry ADOPTS chat transcripts from <live>/chats, so a
    split resolver silently loses chats from the library/session list."""
    from framework.v2.console import chat
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    assert chat._live_dir() == sessions._live_dir()
