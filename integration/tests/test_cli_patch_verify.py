"""GAP B — `vigil patch --verify-base-url`: the LIVE fix-verification leg that makes a signed `remediated`
REACHABLE instead of capping at an unverified proposal.

Before this leg existed, ``_cmd_patch`` called ``autopatch_live`` WITHOUT ``verify_oracle``, so
``verify_patch`` always returned ``unverified`` and ``remediated`` could never be True — `vigil patch` could
open a PR but never certify a fix.

There is deliberately NO second, weaker verification path: the oracle `vigil patch` builds DELEGATES to the
same four-state machinery ``vigil remediate --prove`` drives (``prove_remediation`` over ``LiveHttpAdapter``
— LIVE positive control, a per-run freshness challenge the target must ECHO in the judged bytes, the
protocol-required silent trials, a signed certificate) and merely ADAPTS its verdict:
REMEDIATED → silent ``FixVerdict`` (only if the certificate independently re-verifies) · STILL_VULNERABLE →
firing · INCONCLUSIVE/REFUSED → raise → ``unverified``.

These tests drive the REAL ``_cmd_patch`` (through the real argparse) over a PROVENANCE-GROUNDED finding
rebuilt from the engagement's OWN signed spine (or a signed inert envelope) + its retained re-verifiable
proof material, against a GENUINE stdlib loopback HTTP target (the same pattern test_cli_remediate.py uses —
127.0.0.1 is in the hermetic signed charter, so nothing leaves the machine), and assert:

  * the OFF path is unchanged — no flag ⇒ ``verify_oracle`` is None (byte-identical behaviour);
  * a PATCHED, challenge-echoing deployment earns a SIGNED remediation and exit 0;
  * a STILL-FIRING deployment is never remediated;
  * **an ANSWERED but NON-ECHOING response** (a 403 WAF block page / a 404 that reflects nothing) is
    ``unverified`` and exits non-zero — never a signed remediation. This is the ONE hole the freshness floor
    closes; the ECHOING case is a KNOWN RESIDUAL, pinned below by a test that demonstrates it minting, so the
    documented limit and the behaviour cannot drift apart;
  * a finding whose injectable param IS the freshness-challenge param (``rc``) REFUSES before anything is
    patched — a collision would silently drop the exploit payload and guarantee the oracle's silence;
  * a dead target is ``unverified``;
  * ``--verify-base-url`` without ``--open-pr`` WARNS on stdout and exits non-zero (it does not refuse);
  * ``--finding-ref`` can never redirect the verification at ANOTHER finding's retained positive control;
  * the pre-existing ``--r`` abbreviation still resolves to ``--repo-base-dir``;
  * and every case the oracle cannot be BUILT for REFUSES before anything is patched.

``autopatch_live`` itself is replaced by a double — this file is about what `vigil patch` HANDS the ladder and
how the built oracle adjudicates, not about git/LLM/PR mechanics.

Needs framework (reverify + the translator + the scope gate + HttpExecutor) →
PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE (offense) not importable here")

from framework.v2.common import paths as _paths  # noqa: E402

from vigil_integration.autopatch.loop import verify_patch  # noqa: E402
from vigil_integration.cli import build_parser  # noqa: E402
from vigil_integration.live import codefix_runner as _codefix_runner  # noqa: E402
from vigil_integration.live import trusted_finding as _trusted_finding  # noqa: E402

SLUG = "patch-verify-cli"
FACT_REF = "f-errsqli"
OTHER_REF = "f-other-finding"
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
# A genuine loopback HTTP target (stdlib only — mirrors test_cli_remediate's _Handler/_Server).
# --------------------------------------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler contract
        srv = self.server
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        exploit_present = any(v for v in q.get("q", []))
        nonce = (q.get("rc") or [""])[0]
        if srv.mode == "echoing-404":
            # ANSWERED, ECHOING, and NOT the application: a 404 page that reflects the request URI (so this
            # run's nonce comes back) while nothing ever reaches the injectable sink. It satisfies the
            # F1_TARGET_ECHOES floor without establishing that the app or the vulnerable endpoint was
            # reached. This is the DOCUMENTED RESIDUAL, not a closed case.
            raw = (f"<html><h1>404 Not Found</h1><p>No handler for "
                   f"{self.path}</p></html>").encode("utf-8")
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if srv.mode == "blocked":
            # ANSWERED, but by something that is NOT the vulnerable endpoint: a WAF/blocklist page. It never
            # reflects the run challenge, so this run establishes NO reachability of the injectable sink.
            raw = b"<html><h1>403 Forbidden</h1><p>Request blocked by edge policy.</p></html>"
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if srv.mode == "vulnerable" and exploit_present:
            body = "HTTP 500 Internal Server Error\nYou have an error in your SQL syntax near '' at line 1\n"
        else:
            body = '{"results": [], "ok": true}\n'
        if nonce:
            body += f"\n<!-- vigil-echo:{nonce} -->\n"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start(mode: str) -> _Server:
    """mode: 'patched' (benign + echo) · 'vulnerable' (datastore error + echo) · 'blocked' (403, NO echo) ·
    'echoing-404' (404 that reflects the request URI — answered AND echoing, but NOT the app)."""
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.mode = mode  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _url(srv: _Server) -> str:
    return f"http://127.0.0.1:{srv.server_address[1]}/"


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


def _entry(check_id: str, *, endpoint: str = "/search", **over) -> dict:
    """A retained re-verifiable entry: the ORIGINAL firing oracle_context (positive control) + the
    reconstructable exploit request + the confirmed channel. Same plain-dict shape the live pipeline persists."""
    octx = _error_context(_ORIG_SQL_ERROR)
    octx["payload_param"] = "q"
    octx["request_payload"] = "x' OR '1'='1"
    entry = {
        "check_id": check_id,
        "bug_class": BUG,
        "channel": "error_signature",
        "insertion_point": endpoint,
        "confirmed_by": "error_signature",
        "confidence": 0.9,
        "action_id": f"poc-{check_id}",
        "oracle_context": octx,
    }
    entry.update(over)
    return entry


def _write_reverifiable(base: Path, *entries: dict, **over) -> None:
    """Persist the retained material. Defaults to ONE entry for THIS finding; extra positional entries model a
    multi-finding run, and keyword overrides mutate the FIRST entry."""
    ents = list(entries) or [_entry(FACT_REF)]
    if over:
        ents[0] = {**ents[0], **over}
    proofs = base / "proofs"
    proofs.mkdir(parents=True, exist_ok=True)
    (proofs / "reverifiable.json").write_text(
        json.dumps({"active_findings": ents}, sort_keys=True), encoding="utf-8")


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
    """Replace ``autopatch_live`` with a recorder that does NOT verify: the ladder itself (git/LLM/sandbox) is
    out of scope here — what matters is WHETHER a verify_oracle reaches it."""
    calls: list[dict] = []

    def _fake_autopatch_live(finding, **kw):
        calls.append({"finding": finding, **kw})
        return SimpleNamespace(status="opened-pr-unverified", patched_paths=["app.py"], opened_pr=True,
                               pr_ref="pr-1", remediated=False, reason="", verification=None)

    monkeypatch.setattr(_codefix_runner, "autopatch_live", _fake_autopatch_live)
    return calls


@pytest.fixture()
def verifying_ladder(monkeypatch):
    """A ladder double that reaches STEP (6): it calls the REAL ``verify_patch`` with the oracle `vigil patch`
    handed it and returns exactly the status/remediated the verification produced (the same mapping
    ``autopatch/loop.py`` applies). The git/LLM/PR legs are stood in for; the ADJUDICATION is real, so the
    exit contract is exercised end-to-end from the live target's bytes."""
    calls: list[dict] = []

    def _verifying_autopatch_live(finding, **kw):
        calls.append({"finding": finding, **kw})
        v = verify_patch(SimpleNamespace(), "build-ref", oracle=kw.get("verify_oracle"))
        calls[-1]["verification"] = v
        return SimpleNamespace(status=("remediated" if v.remediated else f"opened-pr-{v.status}"),
                               patched_paths=["app.py"], opened_pr=True, pr_ref="pr-1",
                               remediated=v.remediated, reason=v.reason, verification=v,
                               evidence_ref=v.evidence_ref)

    monkeypatch.setattr(_codefix_runner, "autopatch_live", _verifying_autopatch_live)
    return calls


@pytest.fixture()
def pr_provisioned(monkeypatch, tmp_path):
    """Stand in for the --open-pr m-of-n destruction provisioning so a test can drive the REAL code path where
    verification is actually reachable (the ladder verifies at step (6), AFTER the PR leg). Only the quorum
    LOADERS are faked; the verification leg under test is untouched."""
    monkeypatch.setattr(_trusted_finding, "load_destruction_authority", lambda **kw: SimpleNamespace())
    monkeypatch.setattr(_trusted_finding, "load_signed_authorization", lambda p: SimpleNamespace())
    monkeypatch.setattr(_codefix_runner, "file_backed_quorum", lambda **kw: SimpleNamespace())
    root = tmp_path / "trust-root.json"
    root.write_text("{}", encoding="utf-8")
    signed = tmp_path / "signed-auth.json"
    signed.write_text("{}", encoding="utf-8")
    return ["--open-pr", "--authority-trust-root", str(root), "--signed-authorization", str(signed),
            "--ledger", str(tmp_path / "ledger")]


def _patch(argv, capsys, home, extra=()):
    args = build_parser().parse_args(
        ["patch", "--from-spine", SLUG, "--base-dir", str(home), "--target-repo", str(home / "repo"),
         *extra, *argv])
    rc = args.func(args)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def _cert_state(home: Path, ref: str = FACT_REF) -> str:
    """The four-state prove-certificate the verification persists — written for EVERY state, so an
    INCONCLUSIVE reason cannot be stripped and re-read as success."""
    p = home / "proofs" / f"patch-verify-prove-{ref}.json"
    if not p.is_file():
        return "(no certificate)"
    return str(json.loads(p.read_text(encoding="utf-8")).get("state"))


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
def test_verify_flag_builds_and_passes_a_fix_oracle(gated_home, recorder, capsys):
    """The defect, directly: with the flag the ladder now RECEIVES a fix-verification oracle. Fails before the
    change (the flag does not exist → argparse SystemExit)."""
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    # rc is 1, not 0: verification WAS requested and the (recorded) ladder result is not `remediated`.
    assert rc == 1, (rc, out, err)
    assert len(recorder) == 1
    oracle = recorder[0].get("verify_oracle")
    assert oracle is not None and callable(oracle)
    assert "verify_target  : http://127.0.0.1:9/" in out


def test_a_silent_patched_deployment_earns_a_signed_remediation(gated_home, verifying_ladder,
                                                                pr_provisioned, capsys):
    """The whole point of GAP B: `remediated` is now REACHABLE. The patched deployment answers benignly AND
    echoes this run's freshness challenge, the delegated four-state prove run reaches REMEDIATED, its signed
    certificate independently re-verifies, and `vigil patch` exits 0."""
    srv = _start("patched")
    try:
        rc, out, err = _patch(["--verify-base-url", _url(srv)], capsys, gated_home, extra=pr_provisioned)
    finally:
        srv.shutdown(); srv.server_close()
    assert rc == 0, (rc, out, err)
    v = verifying_ladder[0]["verification"]
    assert v.remediated is True and v.status == "remediated"
    assert v.evidence_ref.startswith("prove-cert:")
    assert "verify_state   : REMEDIATED" in out
    assert _cert_state(gated_home) == "REMEDIATED"


def test_a_still_firing_deployment_is_never_remediated(gated_home, verifying_ladder, pr_provisioned, capsys):
    """The deployment still answers with the datastore error → the ORIGINAL oracle FIRES over fresh evidence →
    STILL_VULNERABLE → still-vulnerable. `remediated` must stay False and the verb must exit non-zero."""
    srv = _start("vulnerable")
    try:
        rc, out, err = _patch(["--verify-base-url", _url(srv)], capsys, gated_home, extra=pr_provisioned)
    finally:
        srv.shutdown(); srv.server_close()
    assert rc == 1, (rc, out, err)
    v = verifying_ladder[0]["verification"]
    assert v.remediated is False and v.status == "still-vulnerable"
    assert _cert_state(gated_home) == "STILL_VULNERABLE"


# ====== THE HOLE: an ANSWERED response that establishes NO reachability must NEVER mint a remediation ======
def test_an_answered_but_unreachable_target_is_unverified_never_remediated(
        gated_home, verifying_ladder, pr_provisioned, capsys):
    """A 403 WAF/blocklist page ANSWERS every probe — including the benign positive control — but never
    reflects this run's freshness challenge, so nothing here shows the probe reached the vulnerable endpoint.
    A verification that only re-executed the RETAINED positive control offline would see "control fires,
    re-drive silent" and mint a SIGNED remediation with exit 0. The delegated prove protocol requires the
    challenge to be echoed in the JUDGED bytes (Freshness F1), so this is INCONCLUSIVE → RAISE → `unverified`,
    exit non-zero, and NO signed remediation.
    """
    srv = _start("blocked")
    try:
        rc, out, err = _patch(["--verify-base-url", _url(srv)], capsys, gated_home, extra=pr_provisioned)
    finally:
        srv.shutdown(); srv.server_close()
    assert rc == 1, (rc, out, err)
    v = verifying_ladder[0]["verification"]
    assert v.status == "unverified" and v.remediated is False, (v.status, v.reason)
    assert not v.evidence_ref, f"an unreachable target minted an evidence ref: {v.evidence_ref!r}"
    assert "remediated     : False" in out
    # the persisted four-state certificate says so too — it is NEVER a REMEDIATED one.
    assert _cert_state(gated_home) in ("INCONCLUSIVE", "REFUSED"), out
    # ...and for exactly the load-bearing reason: the run challenge was never echoed in the judged bytes.
    assert "freshness_echo_missing" in v.reason, v.reason


def test_a_dead_target_is_unverified_never_remediated(gated_home, verifying_ladder, pr_provisioned, capsys):
    """A target that does not answer at all is NOT silence — it is `unverified` (a fix you cannot exercise is
    unproven), and the verb exits non-zero."""
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:1/"], capsys, gated_home,
                          extra=pr_provisioned)
    assert rc == 1, (rc, out, err)
    v = verifying_ladder[0]["verification"]
    assert v.status == "unverified" and v.remediated is False
    assert _cert_state(gated_home) in ("INCONCLUSIVE", "REFUSED")


# ============================ the exit contract, both directions ============================
def test_the_exit_code_is_the_verified_verdict_not_merely_did_not_refuse(
        gated_home, recorder, monkeypatch, capsys):
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


# ============================ --verify-base-url without --open-pr: warn, proceed, fail ============================
def test_verify_without_open_pr_warns_on_stdout_and_exits_non_zero(gated_home, recorder, capsys):
    """The ladder verifies at step (6), AFTER the PR leg, so without --open-pr NOTHING is verified. The code
    does not refuse up front: it warns and proceeds, and the strict exit code makes the run a failure. The
    notice is printed on STDOUT immediately beside the verify_target line (and mirrored on stderr) so the two
    cannot be read apart — and the docstring says exactly this."""
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 1, (rc, out, err)                       # requested a verified result, produced none
    assert "verify_target  : http://127.0.0.1:9/" in out
    assert "verify_status  : WILL NOT RUN" in out        # beside it, on stdout
    assert "NOTHING is verified" in out and "--open-pr" in out
    assert "WILL NOT RUN" in err                         # and as a warning on stderr
    assert len(recorder) == 1                            # the run PROCEEDED (it did not refuse up front)
    # the docstring must not claim the opposite (a doc overclaim is itself a defect here).
    from vigil_integration.cli import _cmd_patch
    assert "REQUIRES ``--open-pr``" not in (_cmd_patch.__doc__ or "")
    assert "WILL NOT RUN" in (_cmd_patch.__doc__ or "")


# ============================ --finding-ref must never redirect the positive control ============================
def _signed_envelope_and_delegation(tmp_path, *, slug: str, finding_ref: str):
    """A signed inert finding envelope + the owner-signed delegation that anchors it. This is the ONE trusted
    source whose ref is NOT derived from --finding-ref, so it is where an operator-supplied --finding-ref
    could otherwise OVERRIDE which retained positive control drives the verification."""
    from vigil_core import AuthorizerKey, evidence_signing_bytes, generate_keypair, sign
    from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, sign_delegation

    from vigil_integration.inert_finding import build_envelope

    owner = generate_keypair()
    keys = [generate_keypair(), generate_keypair()]
    auths = [AuthorizerKey(key_id=f"gov{i}", name=f"gov{i}", public_key_b64=k.public_key_b64)
             for i, k in enumerate(keys)]
    cert = {"schema_version": 1, "engagement_slug": slug, "finding_ref": finding_ref, "bug_class": BUG,
            "title": "error-based SQLi", "severity": "high", "target": "/search",
            "oracle_context_digest": "a" * 64, "confidence": 0.9}
    msg = evidence_signing_bytes(cert)
    sigs = [{"key_id": a.key_id, "signature_b64": sign(k.private_key_b64, msg)}
            for a, k in zip(auths, keys)]
    ep = tmp_path / "env.json"
    ep.write_text(build_envelope(cert, sigs), encoding="utf-8")
    deleg = sign_delegation(owner, role=OFFENSE_GOVERNANCE_ROLE, scope=slug, authorizers=auths, threshold=2,
                            not_after=int(time.time() + 3600))
    dp = tmp_path / "deleg.json"
    dp.write_text(deleg.model_dump_json(), encoding="utf-8")
    return owner.public_key_b64, str(ep), str(dp)


def test_finding_ref_cannot_redirect_the_verification_at_another_findings_control(
        gated_home, recorder, capsys, tmp_path):
    """BLOCK regression: the retained positive control is chosen by the TRUSTED finding's OWN ref, never by
    an operator-supplied --finding-ref. With TWO complete retained entries, naming the OTHER one must REFUSE
    (rc 2) and patch NOTHING — otherwise finding B's control + exploit could mint a signed remediation
    attributed to finding A."""
    _write_reverifiable(gated_home, _entry(FACT_REF), _entry(OTHER_REF, endpoint="/other"))
    pub, ep, dp = _signed_envelope_and_delegation(tmp_path, slug=SLUG, finding_ref=FACT_REF)
    args = build_parser().parse_args(
        ["patch", "--finding-envelope", ep, "--owner-pubkey", pub, "--delegation", dp, "--scope", SLUG,
         "--base-dir", str(gated_home), "--target-repo", str(gated_home / "repo"),
         "--verify-base-url", "http://127.0.0.1:9/", "--finding-ref", OTHER_REF])
    rc = args.func(args)
    cap = capsys.readouterr()
    assert rc == 2, (rc, cap.out, cap.err)
    assert "does not match the trusted finding's own ref" in cap.err
    assert recorder == []                      # the ladder never ran: nothing proposed, cloned, built, opened
    assert "remediated" not in cap.out


def test_a_matching_finding_ref_is_still_accepted(gated_home, recorder, capsys, tmp_path):
    """The guard REFUSES a mismatch — it does not break the legitimate use (the ref that names THIS finding)."""
    pub, ep, dp = _signed_envelope_and_delegation(tmp_path, slug=SLUG, finding_ref=FACT_REF)
    args = build_parser().parse_args(
        ["patch", "--finding-envelope", ep, "--owner-pubkey", pub, "--delegation", dp, "--scope", SLUG,
         "--base-dir", str(gated_home), "--target-repo", str(gated_home / "repo"),
         "--verify-base-url", "http://127.0.0.1:9/", "--finding-ref", FACT_REF])
    rc = args.func(args)
    cap = capsys.readouterr()
    assert rc == 1, (rc, cap.out, cap.err)     # the oracle was built; nothing verified without --open-pr
    assert len(recorder) == 1 and recorder[0].get("verify_oracle") is not None


# ============================ the OFF path's argparse surface is unchanged ============================
def test_the_preexisting_r_abbreviation_still_resolves_to_repo_base_dir():
    """`vigil patch` had exactly ONE `--r…` option (--repo-base-dir), so `--r` was an unambiguous abbreviation.
    A new `--run-dir` would silently make it AMBIGUOUS (argparse SystemExit) — a behaviour change on the OFF
    path, breaking the byte-identical claim. The verification flags are namespaced `--verify-*`."""
    args = build_parser().parse_args(["patch", "--from-spine", SLUG, "--r", "/tmp/clone"])
    assert args.repo_base_dir == "/tmp/clone"
    args2 = build_parser().parse_args(["patch", "--from-spine", SLUG, "--verify-run-dir", "/tmp/run"])
    assert args2.verify_run_dir == "/tmp/run"
    assert not hasattr(args2, "run_dir"), "the new flag must not re-introduce a bare --run-dir on `patch`"


def test_verify_run_dir_selects_the_retained_material(gated_home, recorder, capsys, tmp_path):
    """--verify-run-dir points at the run holding proofs/reverifiable.json (default: --base-dir). Pointing it
    at a dir with NO retained material must refuse, proving the flag is really the lookup root."""
    empty = tmp_path / "empty-run"
    empty.mkdir()
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/", "--verify-run-dir", str(empty)],
                          capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "no retained re-verifiable proof material" in err
    assert recorder == []


# ============================ fail-closed refusals — nothing is patched ============================
def test_unsupported_channel_refuses_and_never_patches(gated_home, recorder, capsys):
    """The live re-drive supports ONE oracle family. A finding confirmed on another channel must REFUSE, not be
    mis-driven over bytes that family never reads (a vacuous non-fire would look exactly like silence)."""
    _write_reverifiable(gated_home, channel="http_differential", bug_class="boolean_sqli")
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "error_signature" in err and "mis-driving" in err
    assert recorder == []          # the ladder never ran: nothing proposed, cloned, built or opened
    assert "remediated" not in out


def test_absent_positive_control_refuses(gated_home, recorder, capsys):
    """No retained firing oracle_context ⇒ the live prove-run's harness check could not confirm the oracle
    re-fires on known-vulnerable bytes, so a later silence could not be distinguished from a broken probe."""
    rev = gated_home / "proofs" / "reverifiable.json"
    doc = json.loads(rev.read_text(encoding="utf-8"))
    doc["active_findings"][0].pop("oracle_context")
    rev.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "positive control" in err and "broken probe" in err
    assert recorder == []


def test_a_positive_control_that_does_not_fire_refuses(gated_home, recorder, capsys):
    """Stronger than presence: the retained control must STILL make the original oracle fire when re-executed.
    A well-formed but NON-firing control is a broken harness, and silence against it proves nothing. (This is
    an OFFLINE pre-check — the LIVE control + the freshness echo inside the prove run are what establish that
    the probe reached the deployment.)"""
    dead = _error_context(_BENIGN)                    # well-formed context, but the oracle does not fire on it
    dead["payload_param"] = "q"
    dead["request_payload"] = "x' OR '1'='1"
    _write_reverifiable(gated_home, oracle_context=dead)
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "does NOT re-fire" in err
    assert recorder == []


def test_retained_entry_for_a_different_finding_refuses(gated_home, recorder, capsys):
    """The positive control of ANOTHER finding must never be substituted (it could mint a false 'remediated'
    for a still-vulnerable finding). An exact check_id match is required."""
    _write_reverifiable(gated_home, _entry("some-other-finding"))
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "no retained re-verifiable proof material" in err
    assert recorder == []


def test_out_of_charter_scope_verify_target_refuses_before_any_io(gated_home, recorder, capsys):
    """Scope/authorization is gated exactly as the prove verb gates it — the REAL charter/scope gate. An
    out-of-scope target is refused as a pure pre-flight, so no request is ever built and no new ungated egress
    path exists."""
    rc, out, err = _patch(["--verify-base-url", "http://out-of-scope.example/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "NOT authorized under the engagement charter" in err
    assert recorder == []


def test_a_malformed_verify_url_refuses(gated_home, recorder, capsys):
    rc, out, err = _patch(["--verify-base-url", "not-a-url"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "must be an http(s) URL with a host" in err
    assert recorder == []


# ============================ no user-facing overclaim about the retained material ============================
def _flat(text: str) -> str:
    """Whitespace-normalised text, so an assertion on a sentence is not defeated by line wrapping (docstrings
    wrap at 110 cols; argparse re-wraps help to the terminal width)."""
    return " ".join(str(text or "").split())


def _verb_refusal_with_no_retained_material(argv, capsys, tmp_path, home):
    """Drive ONE verb with its retained-material lookup pointed at an EMPTY run dir, and return (rc, err).
    Every verb refuses on that lookup BEFORE it validates the live target, so no traffic is sent."""
    empty = tmp_path / f"empty-{abs(hash(tuple(argv))) % 10 ** 8}"
    empty.mkdir(exist_ok=True)
    args = build_parser().parse_args([*argv, "--base-dir", str(home), *_RUNDIR_FLAG[argv[0]], str(empty)])
    rc = args.func(args)
    cap = capsys.readouterr()
    return rc, cap.err


# every verb in cli.py that reads proofs/reverifiable.json, with the flag that names its lookup root.
_RUNDIR_FLAG = {"patch": ("--verify-run-dir",), "remediate": ("--run-dir",), "reprove": ("--run-dir",)}
_EVERY_REVERIFIABLE_VERB = {
    "patch": ["patch", "--from-spine", SLUG, "--verify-base-url", "http://127.0.0.1:9/"],
    "remediate": ["remediate", "--prove", "--from-spine", SLUG, "--target-base-url", "http://127.0.0.1:9/"],
    "reprove": ["reprove", "--once", "--from-spine", SLUG, "--target-base-url", "http://127.0.0.1:9/"],
}


def test_the_reverifiable_reader_list_is_complete():
    """The claim above is "EVERY verb that reads proofs/reverifiable.json" — so the list must not be a
    hand-maintained one that silently goes stale. Derive the readers from cli.py's own AST: if a FOURTH
    reader appears, this fails and forces it into the parametrised coverage below."""
    import ast

    import vigil_integration.cli as _cli

    src = Path(_cli.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    readers = {n.name for n in tree.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and "read_reverifiable" in ast.get_source_segment(src, n)}
    # _build_patch_fix_oracle is the `patch` verb's reader; the other two read it inline.
    assert readers == {"_build_patch_fix_oracle", "_cmd_remediate", "_cmd_reprove"}, readers
    assert set(_EVERY_REVERIFIABLE_VERB) == {"patch", "remediate", "reprove"}


@pytest.mark.parametrize("verb", sorted(_EVERY_REVERIFIABLE_VERB))
def test_no_verb_claims_the_positive_control_cannot_be_fabricated(verb, gated_home, tmp_path, capsys):
    """proofs/reverifiable.json is UNSIGNED local run output for EVERY verb that reads it — not just
    `vigil patch`. None of them may tell the operator the positive control 'cannot be fabricated' (it can:
    it is an unsigned local file), and each must carry the honest TRUST NOTE wording instead."""
    argv = list(_EVERY_REVERIFIABLE_VERB[verb])
    if verb == "patch":
        argv += ["--target-repo", str(gated_home / "repo")]
    rc, err = _verb_refusal_with_no_retained_material(argv, capsys, tmp_path, gated_home)
    assert rc == 2, (verb, rc, err)
    assert "no retained re-verifiable proof material" in err, (verb, err)
    assert "cannot be fabricated" not in _flat(err), (verb, err)
    assert "UNSIGNED local run output" in _flat(err), (verb, err)


def test_no_unfabricable_positive_control_claim_and_the_trust_note_is_carried(gated_home, recorder, capsys):
    """proofs/reverifiable.json is UNSIGNED local run output. The refusal text must not claim the positive
    control 'cannot be fabricated', and the sibling verb's TRUST NOTE must be carried onto this path."""
    from vigil_integration.cli import _build_patch_fix_oracle

    _write_reverifiable(gated_home, _entry("some-other-finding"))
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2
    assert "cannot be fabricated" not in err
    assert "UNSIGNED local run output" in err
    doc = _build_patch_fix_oracle.__doc__ or ""
    assert "TRUST NOTE" in doc and "UNSIGNED LOCAL RUN OUTPUT" in doc
    assert "cannot be fabricated" not in doc
    # the persistent side effect is disclosed at the flag and in the docstring (it is not silent).
    assert "OVERWRITING" in doc
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        build_parser().parse_args(["patch", "--help"])
    txt = buf.getvalue()
    assert "OVERWRITING" in txt and "UNSIGNED LOCAL RUN OUTPUT" in txt


# ================= the nonce-param collision: a finding whose injectable param IS `rc` =================
def test_a_finding_whose_param_is_the_nonce_param_refuses_before_anything_is_patched(
        gated_home, recorder, capsys):
    """BLOCK regression (a concrete FALSE-REMEDIATED path). The re-drive carries the per-run freshness
    challenge on a SEPARATE query param, hard-coded `rc`, while the exploit rides the finding's own
    injectable param. If the finding's param IS literally `rc` the two collide in the re-drive URL and the
    challenge OVERWRITES the exploit payload: the exploit is never sent, so oracle silence says nothing about
    a fix — yet that silence WAS minted as a SIGNED remediation (state REMEDIATED, exit 0) over a
    still-vulnerable target on the pre-fix code. It must REFUSE before anything is proposed, cloned, applied
    or opened."""
    octx = _error_context(_ORIG_SQL_ERROR)
    octx["payload_param"] = "rc"                     # the collision
    octx["request_payload"] = "x' OR '1'='1"
    _write_reverifiable(gated_home, oracle_context=octx)
    rc, out, err = _patch(["--verify-base-url", "http://127.0.0.1:9/"], capsys, gated_home)
    assert rc == 2, (rc, out, err)
    assert "freshness challenge" in err and "OVERWRITE the exploit payload" in _flat(err), err
    assert recorder == [], "the ladder ran: something was proposed/cloned/applied before the refusal"
    assert _cert_state(gated_home) == "(no certificate)"
    assert "remediated" not in out


def test_the_sibling_verbs_refuse_the_same_collision(gated_home, tmp_path, capsys):
    """`vigil remediate` and `vigil reprove` build the SAME adapter with the SAME hard-coded `rc` nonce
    param, so they carry the identical defect. Both must refuse it as a pre-flight, before target traffic."""
    octx = _error_context(_ORIG_SQL_ERROR)
    octx["payload_param"] = "rc"
    octx["request_payload"] = "x' OR '1'='1"
    _write_reverifiable(gated_home, oracle_context=octx)
    for verb, argv in (("remediate", ["remediate", "--prove", "--from-spine", SLUG]),
                       ("reprove", ["reprove", "--once", "--from-spine", SLUG])):
        args = build_parser().parse_args(
            [*argv, "--base-dir", str(gated_home), "--target-base-url", "http://127.0.0.1:9/"])
        rc = args.func(args)
        cap = capsys.readouterr()
        assert rc == 2, (verb, rc, cap.out, cap.err)
        assert "OVERWRITE the exploit payload" in _flat(cap.err), (verb, cap.err)


def test_both_live_adapters_refuse_a_param_nonce_collision_at_construction(monkeypatch):
    """Defence in depth: the guard lives in the ADAPTERS too, so every caller inherits it — not only the
    three CLI verbs. `LiveHttpAdapter` drops the exploit payload on a collision; `DifferentialHttpAdapter`
    drops the baseline/true/false value from EVERY round, which would make the rounds identical and the SPRT
    refute trivially — both are false-'remediated' paths."""
    from vigil_integration.remediation.differential_adapter import DifferentialHttpAdapter
    from vigil_integration.remediation.live_adapter import LiveHttpAdapter

    with pytest.raises(ValueError, match="MUST differ"):
        LiveHttpAdapter(executor=None, base_url="http://127.0.0.1/", endpoint_path="/search", param="rc",
                        payload="x' OR '1'='1", nonce_param="rc", original_firing_context={"bug_class": BUG})
    with pytest.raises(ValueError, match="MUST differ"):
        DifferentialHttpAdapter(
            executor=None, base_url="http://127.0.0.1/", endpoint_path="/search", param="rc",
            nonce_param="rc", base_value="1",
            true_payload_templates=("1 AND 1=1 -- {challenge}", "1 AND 9=9 -- {challenge}"),
            false_payload_templates=("1 AND 1=2 -- {challenge}", "1 AND 9=8 -- {challenge}"))
    # ...and the legitimate, non-colliding construction is untouched.
    ok = LiveHttpAdapter(executor=None, base_url="http://127.0.0.1/", endpoint_path="/search", param="q",
                         payload="x' OR '1'='1", nonce_param="rc",
                         original_firing_context={"bug_class": BUG})
    assert ok.param == "q" and ok.nonce_param == "rc"


# ============ what F1 actually buys: the honest claim, and the residual it does NOT close ============
def test_the_echoing_unrelated_responder_residual_is_real_and_is_documented_as_such(
        gated_home, verifying_ladder, pr_provisioned, capsys):
    """THE HONEST LIMIT, DEMONSTRATED — not merely asserted in prose.

    The F1_TARGET_ECHOES floor establishes RESPONSIVENESS/FRESHNESS only: SOME responder returned this run's
    nonce in the judged bytes. It does NOT establish that the responder was the application or that the
    request reached the vulnerable endpoint. A 404 page that reflects the request URI therefore satisfies the
    floor while nothing reaches the sink — and the run DOES mint a signed 'remediated' + exit 0.

    This test pins that behaviour together with the docstrings that disclose it, so the code and the claim
    cannot drift apart: if someone later closes this residual, this test fails and forces the doc to be
    updated (rather than the doc quietly over-claiming again, which is what the last two rounds did)."""
    from vigil_integration.cli import _build_patch_fix_oracle, _cmd_patch

    srv = _start("echoing-404")
    try:
        rc, out, err = _patch(["--verify-base-url", _url(srv)], capsys, gated_home, extra=pr_provisioned)
    finally:
        srv.shutdown(); srv.server_close()
    # The residual is REAL: an answered, echoing, unrelated responder mints a signed remediation.
    assert rc == 0, (rc, out, err)
    assert verifying_ladder[0]["verification"].remediated is True
    assert _cert_state(gated_home) == "REMEDIATED"
    # ...so BOTH docstrings must disclose it, in those words, prominently.
    for doc in (_flat(_cmd_patch.__doc__), _flat(_build_patch_fix_oracle.__doc__)):
        assert "KNOWN RESIDUAL" in doc, doc[:400]
        assert "echoing 404" in doc.lower()
        assert "did NOT fire over freshly captured bytes from the host the operator nominated" in doc


def test_the_f1_guarantee_is_stated_honestly_and_the_old_overclaim_is_gone():
    """Pin the WORDING of the headline claim in both docstrings. The previous round claimed the delegation
    establishes that 'the ORIGINAL exploit no longer fires against THIS deployment' — which F1 does not
    support (it does not attribute the echo to the application). The narrower true statement must stand."""
    from vigil_integration.cli import _build_patch_fix_oracle, _cmd_patch

    pdoc, odoc = _flat(_cmd_patch.__doc__), _flat(_build_patch_fix_oracle.__doc__)
    for doc in (pdoc, odoc):
        # the true, narrow statement
        assert "RESPONSIVENESS" in doc and "FRESHNESS ONLY" in doc
        assert "does NOT establish that the responder was the application" in doc \
            or "does NOT prove the responder was the application" in doc
        # and the false, broad one is gone
        assert "the ORIGINAL exploit no longer fires against" not in doc
        assert "the original exploit no longer fires against" not in doc
    # the NON-echoing case IS closed, and the docs still say so (do not weaken the capability).
    assert "unverified" in odoc and "freshness_echo_missing" in odoc
    # the operator-facing flag help carries the same honesty, not just the source.
    import contextlib
    import io as _io
    buf = _io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        build_parser().parse_args(["patch", "--help"])
    h = _flat(buf.getvalue())
    assert "RESPONSIVENESS/FRESHNESS ONLY" in h
    assert "NOT that it was your application" in h
    assert "KNOWN RESIDUAL" in h


def test_the_load_bearing_gates_are_named_and_the_self_minted_ones_are_disclosed():
    """The soundness argument must not LEAD with gates that cannot fail here. The owner key, wielder keypair,
    identity attestation and capability are minted and verified inside the same closure, so on THIS path they
    carry no independent assurance; they matter to a third party verifying the emitted certificate."""
    from vigil_integration.cli import _build_patch_fix_oracle

    doc = _flat(_build_patch_fix_oracle.__doc__)
    assert "WHICH GATES ARE LOAD-BEARING ON THIS PATH" in doc
    for gate in ("CLASS CERTIFIABILITY", "BUDGET", "LIVE CONTROL", "FRESHNESS ECHO", "SILENT trials",
                 "verify_prove_certificate"):
        assert gate in doc, gate
    assert "NOT load-bearing here" in doc
    assert "MINTED INSIDE this same closure" in doc
    assert "carry no independent assurance of anything HERE" in doc
    # and the identity link is split honestly: continuity is real only for HTTPS.
    assert "VACUOUS for a plain-HTTP one" in doc


# ==================== --finding-ref: what it selects, on every verb that takes it ====================
@pytest.mark.parametrize("verb", ["patch", "remediate", "reprove"])
def test_finding_ref_help_never_claims_to_select_the_retained_entry(verb):
    """`--finding-ref` selects the FACT FROM THE SPINE only. It can never redirect which retained
    re-verifiable entry drives the proof, and a value disagreeing with the trusted finding's own ref is
    REFUSED. `vigil remediate`'s help claimed the opposite ('also selects the matching re-verifiable
    entry') after the guard made it false."""
    import contextlib
    import io as _io
    buf = _io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        build_parser().parse_args([verb, "--help"])
    h = _flat(buf.getvalue())
    assert "also selects the matching re-verifiable entry" not in h
    assert "can NEVER redirect which retained re-verifiable entry drives" in h
    assert "REFUSED" in h
