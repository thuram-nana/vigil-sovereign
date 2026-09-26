"""Soundness controls for ``live.runtime_redrive`` — a signature is only a FACT when it is ATTRIBUTABLE.

An adversarial red-pen constructed working FALSE FACTs against the shipped ``path_traversal`` and
``exposure`` arms — signed certificates that pass offline re-verification — at rate 1.0. The defects it
measured, and the control this file pins for each:

  * **D1 — payload CORRELATION masqueraded as a file READ.** The only guard was a benign, NON-path control
    value (``vigilctl<nonce>.txt``), which retrieves nothing anywhere, so any endpoint whose output
    correlates with what the payload MEANS minted: a read-only KB/search page whose corpus holds an
    ``/etc/passwd`` hardening article, and a benign ``403 path rejected`` page that quotes a sample passwd
    line. The fix is two independent requirements — a PATH-SHAPED but unreadable control, and a SECOND,
    semantically-different encoding of the same path that must reproduce the same signature.
  * **D2 — the exposure "random soft-404 control" was a STATUS check.** ``PathProbeCheck.probe`` returns a
    context for ANY non-404 status and the signature predicate rides UNEVALUATED inside it, so behind a
    200-catch-all SPA a REAL ``.env`` leak was refused with a FABRICATED audit note ("signature also served
    at a random path") while the control body contained no such signature — and ``/.env`` was never even
    fetched. The runner now evaluates the signature on the control BODY itself and only writes the note it
    actually observed.
  * **D3 — the "value-shaped signature" did not exist** (a bare ``icontains "DB_PASSWORD="``): docs prose, a
    CI template, a JS bundle and a ``.env.example`` all minted.
  * **D4 — duplicate certificates**: the traversal/ssi arms did not ``break`` on the first FACT, so ONE bug
    produced one certificate per candidate parameter (measured: 12).

Every control here drives a REAL loopback origin through the REAL gated send, and asserts POSITIVELY that
the arm RAN and REFUSED (the examined surface + the specific refusal note), never merely that the result is
falsy — so stubbing the arm to ``return None`` fails every one of them.
"""
from __future__ import annotations

import http.server
import posixpath
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---------------------------------------------------------------------------------------------------
# gate isolation + charter (mirrors test_engine_runtime_redrive_seam)
# ---------------------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


# ---------------------------------------------------------------------------------------------------
# loopback origins
# ---------------------------------------------------------------------------------------------------

_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")

# A read-only knowledge base whose corpus HAPPENS to document /etc/passwd hardening — and therefore quotes
# the very signature the traversal arm looks for. Nothing is ever read from disk.
_KB_ARTICLE = ("Hardening guide: etc/passwd permissions\n"
               "The first line of a typical etc/passwd reads root:x:0:0:root:/root:/bin/bash — make sure the "
               "file is mode 0644 and owned by root.\n")


class _Base(http.server.BaseHTTPRequestHandler):
    """Answers from ``reply(path, values)`` -> ``(status, body)``. ``values`` is EVERY query value, so a
    control/treatment injected into any candidate parameter name reaches the endpoint's logic (a realistic
    document endpoint does not care which of its aliases was used)."""

    def reply(self, path: str, values: "list[str]") -> "tuple[int, str]":  # pragma: no cover - overridden
        raise NotImplementedError

    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        q = parse_qs(parts.query, keep_blank_values=True)
        values = [v for vs in q.values() for v in vs]
        status, body = self.reply(parts.path, values)
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):  # silence
        return


def _strip_leading_dots(v: str) -> str:
    """A realistic 'clean the user-supplied path prefix' normalisation: strip LEADING ``./`` / ``../``
    segments only. Interior dot-segments survive, exactly as a literal-keyed search would leave them."""
    out = v
    while True:
        if out.startswith("../"):
            out = out[3:]
        elif out.startswith("./"):
            out = out[2:]
        else:
            return out


class _KbSearchApp(_Base):
    """A1 — a READ-ONLY documentation/KB search endpoint. It never touches the filesystem; it matches the
    (prefix-normalised) query LITERALLY against its corpus, and its corpus contains an /etc/passwd hardening
    article that quotes ``root:x:0:0:root:/root:/bin/bash``. The output therefore CORRELATES with what the
    traversal payload MEANS, with no file read at all."""

    def reply(self, path, values):
        for v in values:
            term = _strip_leading_dots(v)
            if len(term) >= 4 and term.lower() in _KB_ARTICLE.lower():
                return 200, f"1 result\n\n{_KB_ARTICLE}"
        return 200, "0 results"


class _BlockedApp(_Base):
    """A2 — a BENIGN, correctly-defended endpoint: it rejects any path-ish input with a 403 that EXPLAINS
    what it blocked and quotes a sample passwd line. No file is ever read."""

    def reply(self, path, values):
        if any(("../" in v) or v.startswith("/") for v in values):
            return 403, ("Path rejected.\n\nYour request contained a directory-traversal sequence. System "
                         "files such as etc/passwd — whose first line looks like "
                         "root:x:0:0:root:/root:/bin/bash — are never served by this application.\n")
        return 200, "document served"


# A GENUINE file-read sink: the value is joined to the docroot and RESOLVED (POSIX dot-segment semantics),
# then looked up. Any encoding of the same path resolves to the same file; a name that does not exist 404s.
_DOCROOT = "/srv/app/public/docs"
_FS = {
    "/etc/passwd": _PASSWD,
    "/srv/app/public/docs/report.pdf": "quarterly report\n",
}


class _LfiApp(_Base):
    """The TRUE POSITIVE — a real local-file-inclusion sink (join + resolve + read)."""

    def reply(self, path, values):
        for v in values:
            if not v:
                continue
            resolved = posixpath.normpath(posixpath.join(_DOCROOT, v))
            content = _FS.get(resolved)
            if content is not None:
                return 200, content
        return 404, "document not found"


# ---- exposure origins ------------------------------------------------------------------------------

_ENV_DOCS = ("<html><body><h1>Configuration</h1>"
             "<p>Set <code>DB_PASSWORD=</code> in your environment before starting the service.</p>"
             "</body></html>")
_ENV_CI = ("# deploy pipeline template\nDB_HOST=db.internal\n"
           "DB_PASSWORD=${{ secrets.DB_PASSWORD }}\n")
_ENV_JS = ('!function(){var cfg={};cfg.env="DB_PASSWORD="+process.env.DB_PASSWORD;return cfg}();')
_ENV_EXAMPLE = "APP_ENV=development\nDB_PASSWORD=changeme_in_production\nJWT_SECRET=\n"
_ENV_REAL = ("APP_ENV=production\nDB_HOST=db.internal\n"
             "DB_PASSWORD=S3cr3t-Real-Prod-Key\nJWT_SECRET=lab-decoy\n")
_SPA_SHELL = ("<!doctype html><html><head><title>console</title></head>"
              "<body><div id=root></div><script src=/static/app.js></script></body></html>")


def _env_app(dotenv_body: str, *, catch_all: bool):
    """An origin that serves ``dotenv_body`` at ``/.env``. ``catch_all`` makes every OTHER path answer 200
    with an SPA shell (the modern default that defeats a status-only soft-404 control); otherwise unknown
    paths 404."""

    class _EnvApp(_Base):
        def reply(self, path, values):
            if path == "/.env":
                return 200, dotenv_body
            if catch_all:
                return 200, _SPA_SHELL
            return 404, "Not Found"

    return _EnvApp


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _rr(monkeypatch, tmp_path, handler, url: str, bug_class: str):
    """Drive the REAL arm against a REAL loopback origin and return its ``RuntimeRedriveResult``."""
    from vigil_integration.live.runtime_redrive import runtime_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve(handler)
    port = srv.server_address[1]
    try:
        return runtime_redrive(url.format(port=port), slug="alpha", engagement_slug="alpha",
                               signers=_signers(), claimed_class=bug_class)
    finally:
        srv.shutdown()


def _assert_ran_and_refused(res, bug_class: str, note_prefix: str) -> None:
    """The arm RAN (it examined a surface) and REFUSED for the stated reason — never merely 'nothing came
    back'. A stubbed arm (``return None``) fails on the first line; an arm that silently stopped examining
    fails on the second; an arm that refused for a DIFFERENT reason fails on the third."""
    from vigil_integration.live.runtime_redrive import RuntimeRedriveResult
    assert isinstance(res, RuntimeRedriveResult), f"the arm did not run at all (got {res!r})"
    assert res.surfaces.get(bug_class), (
        f"the arm examined NO {bug_class} surface — it was stubbed out, not refusing")
    assert any(n.startswith(note_prefix) for n in res.notes), (
        f"expected a {note_prefix!r} refusal; notes were {res.notes!r}")
    assert res.n_facts == 0, f"a false FACT was minted: {[f.finding_ref for f in res.facts]}"


# ===================================================================================================
# D1 — path_traversal: payload CORRELATION is not a file READ
# ===================================================================================================

def test_a1_payload_correlated_kb_search_is_a_lead(monkeypatch, tmp_path):
    """A read-only KB/search page whose corpus documents /etc/passwd answers the traversal payload with an
    article that quotes root:x:0:0:. No file was read: the second ENCODING must not reproduce it."""
    res = _rr(monkeypatch, tmp_path, _KbSearchApp, "http://127.0.0.1:{port}/kb?q=seed", "path_traversal")
    _assert_ran_and_refused(res, "path_traversal", "path_traversal: encoding-corroboration refused")


def test_a2_benign_403_path_rejected_page_is_a_lead(monkeypatch, tmp_path):
    """A correctly-defended 403 that explains the block and quotes a sample passwd line. The PATH-SHAPED
    control reproduces it, so it is not attributable to a read."""
    res = _rr(monkeypatch, tmp_path, _BlockedApp, "http://127.0.0.1:{port}/doc?file=a.txt", "path_traversal")
    _assert_ran_and_refused(res, "path_traversal", "path_traversal: control-differential refused")


def test_a3_constant_emission_docs_page_is_a_lead(monkeypatch, tmp_path):
    """The already-shipped control still holds: a page that prints the signature regardless of input."""
    class _DocsApp(_Base):
        def reply(self, path, values):
            return 200, f"Docs: an etc/passwd line looks like {_PASSWD.splitlines()[0]}"

    res = _rr(monkeypatch, tmp_path, _DocsApp, "http://127.0.0.1:{port}/docs", "path_traversal")
    _assert_ran_and_refused(res, "path_traversal", "path_traversal: control-differential refused")


def test_a_substring_matcher_that_never_reads_is_a_lead(monkeypatch, tmp_path):
    """The shape the seam test's own 'vulnerable' fixture used to have — ``any(t in value for t in ("..",
    "%2e", "/etc/", "passwd"))`` then serve the passwd text. It reads nothing; it answers what the payload
    MEANS. It reproduces under every encoding, so only the PATH-SHAPED control refuses it."""
    class _CorrelatedApp(_Base):
        def reply(self, path, values):
            if any(t in v for v in values for t in ("..", "%2e", "/etc/", "passwd")):
                return 200, _PASSWD
            return 200, "report contents"

    res = _rr(monkeypatch, tmp_path, _CorrelatedApp, "http://127.0.0.1:{port}/download?file=report.pdf",
              "path_traversal")
    _assert_ran_and_refused(res, "path_traversal", "path_traversal: control-differential refused")


def test_a_real_traversal_still_mints_exactly_one_certificate(monkeypatch, tmp_path):
    """The false-negative half + D4: a genuine read mints, and ONE bug is ONE certificate.

    The URL carries no parameter, so the arm walks all 12 candidate names and the sink answers every one
    of them — the exact shape that produced 12 certificates for one bug before the ``break``."""
    res = _rr(monkeypatch, tmp_path, _LfiApp, "http://127.0.0.1:{port}/download", "path_traversal")
    assert res.n_facts == 1, (
        f"a genuine traversal must mint exactly ONE signed FACT, got {res.n_facts} "
        f"({[f.finding_ref for f in res.facts]})")
    assert res.family_verdict("path_traversal") == "FACT"


def test_a_real_traversal_fact_reverifies_offline(monkeypatch, tmp_path):
    from framework.v2.evidence.certify import verify_certificate
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.runtime_redrive import runtime_redrive
    srv = _serve(_LfiApp)
    port = srv.server_address[1]
    try:
        res = runtime_redrive(f"http://127.0.0.1:{port}/download?file=report.pdf", slug="alpha",
                              engagement_slug="alpha", signers=[("gov0", kp.private_key_b64)],
                              claimed_class="path_traversal")
    finally:
        srv.shutdown()
    assert res.n_facts == 1
    fact = res.facts[0]
    ctx = res.contexts[fact.finding_ref]
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=tr).ok is True
    tampered = dict(ctx)
    tampered["observed_sink"] = "document not found"
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=tr).ok is False


# ===================================================================================================
# D2/D3 — exposure: a real control-BODY differential, and a real value shape
# ===================================================================================================

@pytest.mark.parametrize("label,body", [
    ("docs-prose", _ENV_DOCS),
    ("ci-template", _ENV_CI),
    ("js-bundle", _ENV_JS),
    ("env-example", _ENV_EXAMPLE),
])
def test_env_bodies_without_a_real_value_are_leads(monkeypatch, tmp_path, label, body):
    """D3: ``DB_PASSWORD=`` with no real value on the right-hand side — prose, a CI template, a JS string
    concatenation, a ``.env.example`` placeholder — is not a secret leak."""
    res = _rr(monkeypatch, tmp_path, _env_app(body, catch_all=False), "http://127.0.0.1:{port}/", "exposure")
    _assert_ran_and_refused(res, "exposure", "exposure: value-shape refused")


def test_real_env_leak_behind_a_200_catch_all_spa_mints(monkeypatch, tmp_path):
    """D2(a): the false-NEGATIVE half. Behind an SPA that 200s unknown paths the genuine leak must STILL
    mint — the control is a signature differential over the control BODY, not a status check."""
    res = _rr(monkeypatch, tmp_path, _env_app(_ENV_REAL, catch_all=True), "http://127.0.0.1:{port}/",
              "exposure")
    assert res.n_facts == 1, f"a real .env leak behind a 200 catch-all must mint; notes={res.notes!r}"
    assert res.family_verdict("exposure") == "FACT"


def test_real_env_leak_on_a_404ing_origin_mints(monkeypatch, tmp_path):
    res = _rr(monkeypatch, tmp_path, _env_app(_ENV_REAL, catch_all=False), "http://127.0.0.1:{port}/",
              "exposure")
    assert res.n_facts == 1, f"a real .env leak must mint; notes={res.notes!r}"


def test_a_true_catch_all_that_serves_the_signature_everywhere_is_a_lead(monkeypatch, tmp_path):
    """D2(b): when the signature really IS served at the random control path, the refusal — and its audit
    note — are TRUE."""
    class _EverywhereApp(_Base):
        def reply(self, path, values):
            return 200, _ENV_REAL

    res = _rr(monkeypatch, tmp_path, _EverywhereApp, "http://127.0.0.1:{port}/", "exposure")
    _assert_ran_and_refused(res, "exposure", "exposure: control-differential refused")


@pytest.mark.parametrize("body,accepted", [
    ("APP_ENV=production\nDB_PASSWORD=S3cr3t-Real-Prod-Key\n", True),   # a real unquoted value
    ('DB_PASSWORD="Quoted-Real-Value"\n', True),                        # a real quoted value
    ("<p>Set <code>DB_PASSWORD=</code> in your env</p>", False),        # docs prose
    ("DB_PASSWORD=${{ secrets.DB_PASSWORD }}\n", False),                # CI template
    ('cfg.env="DB_PASSWORD="+process.env.DB_PASSWORD;', False),         # JS concatenation
    ("DB_PASSWORD=changeme_in_production\n", False),                    # shipped placeholder
    ("DB_PASSWORD=\n", False),                                          # empty value
    ("DB_PASSWORD=abc\n", False),                                       # below the length floor
])
def test_secret_assignment_shape(body, accepted):
    """The hermetic half of D3 — the extractor itself, with no network in the loop."""
    from vigil_integration.live.runtime_redrive import _secret_assignment
    assignment, value, why = _secret_assignment(body, "DB_PASSWORD=")
    if accepted:
        assert assignment and value and not why
        assert assignment in body, "the assignment must be a verbatim substring of the captured body"
        assert value in assignment
    else:
        assert not assignment and why, f"expected a refusal for {body!r}"
        assert "DB_PASSWORD" not in why or "not present" in why, (
            "a refusal note must not quote the candidate value")


def test_secret_value_predicate_is_a_pure_json_ast():
    """The value shape must RE-EXECUTE offline, so it has to be JSON and it has to decide correctly."""
    import json

    from framework.v2.verify.oracles import predicate_oracle
    from vigil_integration.live.runtime_redrive import _secret_value_predicates

    preds = _secret_value_predicates("DB_PASSWORD=")
    json.dumps(preds)     # pure JSON AST — no code, no callables
    good = {"body": "DB_PASSWORD=S3cr3t-Real-Prod-Key\n", "control_body": "nope",
            "secret_assignment": "DB_PASSWORD=S3cr3t-Real-Prod-Key", "secret_value": "S3cr3t-Real-Prod-Key"}
    assert predicate_oracle(good, {"all": preds}).fired is True
    # A value substituted into the context that does NOT occur in the retained body is refused.
    forged = dict(good, secret_assignment="DB_PASSWORD=totally-made-up", secret_value="totally-made-up")
    assert predicate_oracle(forged, {"all": preds}).fired is False
    # A placeholder value is refused by the AST itself, not only by the runner.
    placeholder = {"body": "DB_PASSWORD=changeme_in_production\n", "control_body": "nope",
                   "secret_assignment": "DB_PASSWORD=changeme_in_production",
                   "secret_value": "changeme_in_production"}
    assert predicate_oracle(placeholder, {"all": preds}).fired is False


def test_no_unobserved_soft_404_note_is_ever_written(monkeypatch, tmp_path):
    """The most serious defect: a FABRICATED sentence in the persisted audit trail. The soft-404 note may
    appear ONLY when the signature was actually observed in the control body."""
    res = _rr(monkeypatch, tmp_path, _env_app(_ENV_REAL, catch_all=True), "http://127.0.0.1:{port}/",
              "exposure")
    # The arm RAN (it examined the probe paths and reached a verdict) — otherwise "no note" is vacuous.
    assert res.surfaces.get("exposure"), "the arm examined no exposure surface — it was stubbed out"
    assert res.n_facts == 1, f"the real leak behind the catch-all must still mint; notes={res.notes!r}"
    for note in res.notes:
        if note.startswith("exposure: control-differential refused"):
            pytest.fail(f"an UNOBSERVED soft-404 claim was written into the audit trail: {note!r}")
