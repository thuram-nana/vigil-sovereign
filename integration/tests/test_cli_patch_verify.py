"""GAP B — `vigil patch --verify-base-url`: the LIVE fix-verification leg that makes a signed `remediated`
REACHABLE instead of capping at an unverified proposal.

Before this leg existed, ``_cmd_patch`` called ``autopatch_live`` WITHOUT ``verify_oracle``, so
``verify_patch`` always returned ``unverified`` and ``remediated`` could never be True — `vigil patch` could
open a PR but never certify a fix. These tests drive the REAL ``_cmd_patch`` (through the real argparse) over
a PROVENANCE-GROUNDED finding rebuilt from the engagement's OWN signed spine + its retained re-verifiable
proof material, and assert BOTH halves of the contract:

  * the OFF path is unchanged — no flag ⇒ ``verify_oracle`` is None (byte-identical behaviour); and
  * the ON path is SOUND — the oracle is built and passed, a still-firing target is never `remediated`, a
    silent target earns a SIGNED remediation, and every case the re-drive cannot soundly adjudicate REFUSES
    before anything is patched (unsupported channel, absent/non-firing positive control, a retained entry
    belonging to a DIFFERENT finding, an out-of-charter-scope verification target).

NO REAL EGRESS: the gated ``HttpExecutor`` is replaced by a fake for the drive tests (so the re-drive's
capture→oracle path is exercised over bytes the test controls), and the scope-refusal test uses the REAL
charter/scope gate, which refuses BEFORE any I/O. ``autopatch_live`` itself is replaced by a recorder — this
file is about what `vigil patch` HANDS the ladder and how the built oracle adjudicates, not about git/LLM.

Needs framework (reverify + the translator + the scope gate) → PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE (offense) not importable here")

from framework.v2.common import paths as _paths  # noqa: E402

from vigil_integration.autopatch.loop import verify_patch  # noqa: E402
from vigil_integration.cli import build_parser  # noqa: E402
from vigil_integration.live import codefix_runner as _codefix_runner  # noqa: E402

SLUG = "patch-verify-cli"
FACT_REF = "f-errsqli"
BUG = "error_based_sqli"
_ORIG_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near '' at line 1"
_BENIGN = b'HTTP/1.1 200\r\n\r\n{"results": [], "ok": true}'


def _error_context(body: bytes) -> dict:
    """The oracle_context the ORIGINAL error_signature oracle judges — built by the SAME translator the live
    mint uses (never hand-written), so a 'firing' control genuinely fires and a benign one genuinely does not."""
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda _r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


# --------------------------------------------------------------------------------------------------------
# hermetic engagement home: signed charter (127.0.0.1 in scope) + signed spine + retained proof material
# --------------------------------------------------------------------------------------------------------
_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Loopback test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


def _seed_spine(base: Path) -> None:
    """A real {SLUG}.spine holding ONE confirmed fact — the provenance-grounded finding `vigil patch` drives."""
    from vigil_core.vault import Vault

    from vigil_integration.agent.state import AgentState, Finding
    from vigil_integration.live.spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
    from vigil_integration.live.spine_vigilcore import VigilCoreSpine
    base.mkdir(parents=True, exist_ok=True)
    kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=Vault(base / "vault"))
    spine = VigilCoreSpine(kp, str(base / f"{SLUG}.spine"))
    st = AgentState(engagement_slug=SLUG, iteration=1)
    st.record_fact(Finding(ref=FACT_REF, bug_class=BUG, title="error-based SQLi", severity="high"),
                   evidence_ref="cert:evi-errsqli")
    spine.write_state(st, seq=1)


def _write_reverifiable(base: Path, **over) -> None:
    """The retained re-verifiable entry: the ORIGINAL firing oracle_context (positive control) + the
    reconstructable exploit request + the confirmed channel. Same plain-dict shape the live pipeline persists."""
    octx = _error_context(_ORIG_SQL_ERROR)
    octx["payload_param"] = "q"
    octx["request_payload"] = "x' OR '1'='1"
    entry = {
        "check_id": FACT_REF,
        "bug_class": BUG,
        "channel": "error_signature",
        "insertion_point": "/search",
        "confirmed_by": "error_signature",
        "confidence": 0.9,
        "action_id": "poc-errsqli",
        "oracle_context": octx,
    }
    entry.update(over)
    proofs = base / "proofs"
    proofs.mkdir(parents=True, exist_ok=True)
    (proofs / "reverifiable.json").write_text(
        json.dumps({"active_findings": [entry]}, sort_keys=True), encoding="utf-8")


@pytest.fixture()
def gated_home(tmp_path, monkeypatch):
    targets = tmp_path / "targets"
    (targets / SLUG).mkdir(parents=True)
    (targets / SLUG / "charter.md").write_text(_CHARTER.format(slug=SLUG), encoding="utf-8")
    authdir = tmp_path / "authority"
    authdir.mkdir()
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")
    monkeypatch.setattr(_paths, "authority_path", lambda s: authdir / f"{s}.authority.json")
    base = tmp_path / "home"
    _seed_spine(base)
    _write_reverifiable(base)
    return base


@pytest.fixture()
def recorder(monkeypatch):
    """Replace ``autopatch_live`` with a recorder: the ladder itself (git/LLM/sandbox) is out of scope here —
    what matters is WHETHER a verify_oracle reaches it, and what that oracle decides."""
    calls: list[dict] = []

    def _fake_autopatch_live(finding, **kw):
        calls.append({"finding": finding, **kw})
        return SimpleNamespace(status="opened-pr-unverified", patched_paths=["app.py"], opened_pr=True,
                              pr_ref="pr-1", remediated=False, reason="", verification=None)

    monkeypatch.setattr(_codefix_runner, "autopatch_live", _fake_autopatch_live)
    return calls


class _FakeExecutor:
    """Stands in for the gated CRUCIBLE HttpExecutor — returns a canned response, performs NO network I/O.
    Records the URLs the re-drive built so the exploit request can be asserted."""

    responses: list = []
    seen: list = []

    def __init__(self, **kw):
        type(self).init_kwargs = kw

    def gated_fetch(self, request):
        type(self).seen.append(getattr(request, "url", ""))
        return dict(type(self).responses.pop(0)) if type(self).responses else {"status": 0, "refused": "none left"}


@pytest.fixture()
def fake_executor(monkeypatch):
    import framework.v2.agents as _agents
    _FakeExecutor.responses = []
    _FakeExecutor.seen = []
    _FakeExecutor.init_kwargs = {}
    monkeypatch.setattr(_agents, "HttpExecutor", _FakeExecutor)
    return _FakeExecutor


def _patch(argv, capsys, home, extra=()):
    args = build_parser().parse_args(
        ["patch", "--from-spine", SLUG, "--base-dir", str(home), "--target-repo", str(home / "repo"),
         *extra, *argv])
    rc = args.func(args)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


# ============================ the OFF path stays byte-identical ============================
def test_without_the_flag_no_verify_oracle_is_wired(gated_home, recorder, capsys):
    """Regression guard for the hard requirement: absent --verify-base-url the ladder is handed NO oracle, so
    `remediated` stays False exactly as before. (This assertion holds before AND after the change — it is the
    guard that the opt-in did not leak into the default path.)"""
    rc, out, err = _patch([], capsys, gated_home)
    assert rc == 0, (rc, out, err)
    assert len(recorder) == 1
    assert recorder[0].get("verify_oracle") is None
    assert "verify_target" not in out and "verification   :" not in out


# ============================ the ON path builds and passes the oracle ============================
def test_verify_flag_builds_and_passes_a_fix_oracle(gated_home, recorder, fake_executor, capsys):
    """The defect, directly: with the flag the ladder now RECEIVES a fix-verification oracle. Fails before the
    change (the flag does not exist → argparse SystemExit)."""
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    # rc is 1, not 0: verification WAS requested, and the recorded ladder result is not `remediated`.
    # The strict exit contract makes that a FAILURE so `vigil patch --verify-base-url ... && echo fixed`
    # can never print "fixed" for an unverified or still-vulnerable target. (This run is driven only to
    # capture the BUILT oracle; the adjudication below is what this test is really about.)
    assert rc == 1, (rc, out, err)
    assert len(recorder) == 1
    oracle = recorder[0].get("verify_oracle")
    assert oracle is not None and callable(oracle)
    assert "verify_target  : http://127.0.0.1:9/" in out


def test_a_silent_patched_deployment_earns_a_signed_remediation(gated_home, recorder, fake_executor, capsys):
    """The whole point of GAP B: `remediated` is now REACHABLE. The re-driven deployment answers with benign
    bytes, the ORIGINAL oracle goes silent over them, and a SIGNED remediation certificate is minted."""
    rc, _out, _err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    # rc is 1, not 0: verification WAS requested, and the recorded ladder result is not `remediated`.
    # The strict exit contract makes that a FAILURE so `vigil patch --verify-base-url ... && echo fixed`
    # can never print "fixed" for an unverified or still-vulnerable target. (This run is driven only to
    # capture the BUILT oracle; the adjudication below is what this test is really about.)
    assert rc == 1
    oracle = recorder[0]["verify_oracle"]
    fake_executor.responses = [{"status": 200, "body": _BENIGN.decode()}]
    v = verify_patch(SimpleNamespace(), "build-ref", oracle=oracle)
    assert v.remediated is True and v.status == "remediated"
    assert v.evidence_ref.startswith("remediation:")
    # the re-drive really re-fired the ORIGINAL exploit request (reconstructed, never fabricated)
    assert len(fake_executor.seen) == 1
    assert "/search?" in fake_executor.seen[0] and "q=x%27+OR+%271%27%3D%271" in fake_executor.seen[0]


def test_the_exit_code_is_the_verified_verdict_not_merely_did_not_refuse(
        gated_home, recorder, fake_executor, monkeypatch, capsys):
    """BOTH directions of the strict exit contract, so the guard is not just "verifying always fails".

    Before this leg, `_cmd_patch` returned 0 for anything whose status did not start with "refused" — so
    `opened-pr-still-vulnerable` exited 0 and a CI step `vigil patch ... && echo fixed` would announce a fix
    for a STILL-VULNERABLE target. Now, when verification is requested, ONLY a signed `remediated` exits 0.
    """
    from vigil_integration.live import codefix_runner as _cr

    def _remediated_ladder(finding, **kw):
        recorder.append({"finding": finding, **kw})
        return SimpleNamespace(status="remediated", patched_paths=["app.py"], opened_pr=True, pr_ref="pr-1",
                               remediated=True, reason="oracle went SILENT", verification=None)

    # (a) a genuinely remediated ladder result EXITS 0 — the contract is a verdict, not a blanket failure.
    monkeypatch.setattr(_cr, "autopatch_live", _remediated_ladder)
    rc, _out, _err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 0, "a signed `remediated` must be success"

    # (b) the SAME invocation whose ladder is NOT remediated exits non-zero (the regression this closes).
    def _still_vulnerable_ladder(finding, **kw):
        recorder.append({"finding": finding, **kw})
        return SimpleNamespace(status="opened-pr-still-vulnerable", patched_paths=["app.py"], opened_pr=True,
                               pr_ref="pr-1", remediated=False, reason="still fires", verification=None)

    monkeypatch.setattr(_cr, "autopatch_live", _still_vulnerable_ladder)
    rc2, _out2, _err2 = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc2 == 1, "a still-vulnerable target must NEVER exit 0 when verification was requested"


def test_a_still_firing_deployment_is_never_remediated(gated_home, recorder, fake_executor, capsys):
    """The deployment still answers with the datastore error → the original oracle FIRES over fresh bytes →
    still-vulnerable. `remediated` must stay False."""
    rc, _out, _err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    # rc is 1, not 0: verification WAS requested, and the recorded ladder result is not `remediated`.
    # The strict exit contract makes that a FAILURE so `vigil patch --verify-base-url ... && echo fixed`
    # can never print "fixed" for an unverified or still-vulnerable target. (This run is driven only to
    # capture the BUILT oracle; the adjudication below is what this test is really about.)
    assert rc == 1
    oracle = recorder[0]["verify_oracle"]
    fake_executor.responses = [{"status": 200, "body": _ORIG_SQL_ERROR.decode()}]
    v = verify_patch(SimpleNamespace(), "build-ref", oracle=oracle)
    assert v.remediated is False and v.status == "still-vulnerable"


def test_an_unanswered_or_gate_refused_redrive_is_unverified_never_remediated(
        gated_home, recorder, fake_executor, capsys):
    """A gate refusal and a dead target both land as status 0. That is NOT silence — it must be `unverified`,
    never a fix (fail-closed: a fix you cannot exercise is unproven)."""
    rc, _out, _err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    # rc is 1, not 0: verification WAS requested, and the recorded ladder result is not `remediated`.
    # The strict exit contract makes that a FAILURE so `vigil patch --verify-base-url ... && echo fixed`
    # can never print "fixed" for an unverified or still-vulnerable target. (This run is driven only to
    # capture the BUILT oracle; the adjudication below is what this test is really about.)
    assert rc == 1
    oracle = recorder[0]["verify_oracle"]
    fake_executor.responses = [{"status": 0, "body": "", "refused": "REFUSED: scope_gate refused"}]
    v = verify_patch(SimpleNamespace(), "build-ref", oracle=oracle)
    assert v.remediated is False and v.status == "unverified"


# ============================ fail-closed refusals — nothing is patched ============================
def test_unsupported_channel_refuses_and_never_patches(gated_home, recorder, fake_executor, capsys, tmp_path):
    """The live re-drive supports ONE oracle family. A finding confirmed on another channel must REFUSE, not be
    mis-driven over bytes that family never reads (a vacuous non-fire would look exactly like silence)."""
    _write_reverifiable(gated_home, channel="http_differential", bug_class="boolean_sqli")
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "error_signature" in err and "mis-driving" in err
    assert recorder == []          # the ladder never ran: nothing proposed, cloned, built or opened
    assert "remediated" not in out


def test_absent_positive_control_refuses(gated_home, recorder, fake_executor, capsys):
    """No retained firing oracle_context ⇒ a later silence could not be distinguished from a broken probe."""
    rev = gated_home / "proofs" / "reverifiable.json"
    doc = json.loads(rev.read_text(encoding="utf-8"))
    doc["active_findings"][0].pop("oracle_context")
    rev.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "positive control" in err and "broken probe" in err
    assert recorder == []


def test_a_positive_control_that_does_not_fire_refuses(gated_home, recorder, fake_executor, capsys):
    """Stronger than presence: the retained control must STILL make the original oracle fire when re-executed.
    A well-formed but NON-firing control is a broken probe, and silence against it proves nothing."""
    dead = _error_context(_BENIGN)                    # well-formed context, but the oracle does not fire on it
    dead["payload_param"] = "q"
    dead["request_payload"] = "x' OR '1'='1"
    _write_reverifiable(gated_home, oracle_context=dead)
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "does NOT re-fire" in err
    assert recorder == []


def test_retained_entry_for_a_different_finding_refuses(gated_home, recorder, fake_executor, capsys):
    """The positive control of ANOTHER finding must never be substituted (it could mint a false 'remediated'
    for a still-vulnerable finding). An exact check_id match is required."""
    _write_reverifiable(gated_home, check_id="some-other-finding")
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "no retained re-verifiable proof material" in err
    assert recorder == []


def test_out_of_charter_scope_verify_target_refuses_before_any_io(gated_home, recorder, capsys):
    """Scope/authorization is gated exactly as the prove verb gates it — the REAL charter/scope gate (no fake
    executor here). An out-of-scope target is refused as a pure pre-flight, so no request is ever built and no
    new ungated egress path exists."""
    rc, out, err = _patch(["--verify-base-url", "http://out-of-scope.example/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "NOT authorized under the engagement charter" in err
    assert recorder == []


def test_a_malformed_verify_url_refuses(gated_home, recorder, capsys):
    rc, out, err = _patch(["--verify-base-url", "not-a-url"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "must be an http(s) URL with a host" in err
    assert recorder == []
