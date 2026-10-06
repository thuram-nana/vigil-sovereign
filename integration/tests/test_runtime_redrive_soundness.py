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
  * **D5 — the D1 fix did not hold, and could not.** A second red-pen drove EIGHT benign origins that read
    no file through the "fixed" arm and every one minted a signed FACT at rate 1.0: five that CANONICALISE
    the requested name before deciding (so every alternate encoding corroborates by construction) and three
    with no normaliser at all (``endswith("passwd")``, an anchored WAF regex, a raw-basename match — all of
    which the PATH-SHAPED control misses, because that control is built by APPENDING a suffix and so mutates
    exactly the token they key on). Neither guard tests the relationship between the RESPONSE and the FILE;
    both test only the SHAPE OF THE INPUT. ``path_traversal.file_signature`` is therefore registered
    ``fact_capable: false`` and the arm is LEAD-only. The controls below are kept as LEAD-QUALITY filters
    and each is pinned by a fixture that fails if it is removed.
  * **D6 — a transport failure reported as proof of correlation.** ``_encoding_corroboration`` returned
    ``(None, why)`` for a lost channel / transport error identically to "signature absent", and the caller
    then wrote "so it correlates with the payload rather than with a read" — an unobserved claim that also
    silently discarded a REAL arbitrary-file read on every throttled or WAF'd target. It now returns
    COULD-NOT-OBSERVE distinctly from REFUTED, and could-not-observe is INCONCLUSIVE.
  * **D7 — the exposure value-shape truncated real credentials.** The unquoted right-hand side was cut at
    ``&``/``#``/``;``, none of which delimits a value in ``.env`` semantics. ``DB_PASSWORD=abc;defghij`` was
    cut to ``abc`` and then refused with "its right-hand side is only 3 character(s) long" (an unobserved
    claim — the runner's own cut made it 3), and a Django ``SECRET_KEY`` was minted into a signed
    certificate as the TRUNCATED value ``django-insecure-8k``.

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


_KB_DOCROOT = "/srv/app/public/docs"
_KB_ADVISORY = {"/etc/passwd": _KB_ARTICLE}


class _KbSearchApp(_Base):
    """A1 — a READ-ONLY hardening-advisory endpoint that CANONICALISES before deciding. It never touches
    the filesystem: it resolves the requested name with ``posixpath.normpath`` (the textbook-correct thing
    to do before comparing against anything) and, when the canonical result names a known sensitive system
    path, serves the KB advisory for it — which quotes ``root:x:0:0:root:/root:/bin/bash``, as hardening
    documentation does.

    The normaliser here is REAL ``posixpath.normpath``. It used to be ``_strip_leading_dots`` — a
    prefix-only strip, the one normalisation in the corpus WEAKER than normpath, i.e. exactly the shape
    chosen to avoid the failure mode. With a real normaliser this benign origin satisfies BOTH surviving
    guards (the path-shaped control misses; every alternate encoding canonicalises to the same path and so
    corroborates), which is why the branch is LEAD-only. See
    :func:`test_a1_canonicalising_advisory_satisfies_every_guard_and_still_mints_nothing`."""

    def reply(self, path, values):
        for v in values:
            if not v:
                continue
            canon = posixpath.normpath(posixpath.join(_KB_DOCROOT, v))
            article = _KB_ADVISORY.get(canon)
            if article is not None:
                return 200, f"1 result\n\n{article}"
        return 200, "0 results"


class _SuffixMatcherApp(_Base):
    """A benign matcher with NO normalisation at all: it keys on the SUFFIX of the raw value. The
    path-shaped control is built by APPENDING ``.vigilctl<nonce>`` to the target name, so it changes exactly
    the token this endpoint reads — the control misses, the treatment hits, and both alternate encodings
    still end in ``passwd``. Nothing is ever read."""

    def reply(self, path, values):
        for v in values:
            if v.endswith("passwd"):
                return 200, ("Blocked. Requests for account databases are refused.\n"
                             f"A stock line looks like {_PASSWD.splitlines()[0]}\n")
        return 200, "document served"


class _ExactLiteralApp(_Base):
    """A matcher keyed on the EXACT literal payload string. The canonical payload reproduces the signature;
    neither re-encoding does. This is the one shape the encoding-corroboration guard genuinely refutes, and
    it is what pins that guard (delete ``_encoding_corroboration`` and this control fails)."""

    def reply(self, path, values):
        for v in values:
            if v == "../../../../etc/passwd":
                return 200, _PASSWD
        return 200, "document served"


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

def test_the_traversal_branch_is_registered_lead_only():
    """D5, at the source: the arm is dispatched but the branch may not mint. This is the guard that every
    benign-origin control below actually depends on, so it is asserted directly — flipping
    ``fact_capable`` back to true in the registry fails HERE first, with the reason."""
    from vigil_integration.live.runtime_redrive import (
        RUNTIME_FACT_CLASSES, RUNTIME_LEAD_CLASSES, RUNTIME_REDRIVE_CLASSES)
    from vigil_integration.live.tool_manifest import load_branch_registry
    from vigil_integration.live.verdict import admit

    assert "path_traversal" not in RUNTIME_FACT_CLASSES
    assert "path_traversal" in RUNTIME_LEAD_CLASSES
    assert "path_traversal" in RUNTIME_REDRIVE_CLASSES, "the arm must still be DRIVEN, only demoted"

    reg = {b["id"]: b for b in load_branch_registry(
        Path(__file__).resolve().parents[2] / "docs" / "capability-matrix" / "evidence-branches.json")}
    row = reg["path_traversal.file_signature"]
    assert row["fact_capable"] is False
    assert len(row["blocking_work"]) > 40
    low = row["blocking_work"].lower()
    assert "canonical" in low, "blocking_work must name the read-vs-canonical-lookup discriminator"
    assert "negation" in low and "conjunction" in low, (
        "blocking_work must name the multi-capture oracle row that can express a negation + conjunction")

    # A FIRED oracle over this branch is demoted by admission itself, not by the arm's own bookkeeping.
    verdict = admit("path_traversal.file_signature", fired=True, conclusive=True,
                    observed={"channel_established": True, "body_semantically_available": True,
                              "gate_authorized": True})
    assert verdict.verdict.value == "LEAD"


def test_a1_canonicalising_advisory_satisfies_every_guard_and_still_mints_nothing(monkeypatch, tmp_path):
    """D5 in test form — the justification for the demotion.

    A benign hardening-advisory KB that CANONICALISES the requested name reads no file, yet it satisfies
    BOTH surviving guards: the path-shaped control (a nonce filename) misses, and every alternate encoding
    canonicalises to the same path and so reproduces the signature. The arm therefore runs to completion
    and CORROBORATES — and still mints nothing, because the branch is not FACT-capable. Revert the
    demotion and this becomes a signed false FACT again."""
    res = _rr(monkeypatch, tmp_path, _KbSearchApp, "http://127.0.0.1:{port}/kb?q=seed", "path_traversal")
    from vigil_integration.live.runtime_redrive import RuntimeRedriveResult
    assert isinstance(res, RuntimeRedriveResult)
    assert res.surfaces.get("path_traversal"), "the arm examined no surface — it was stubbed out"
    assert any(n.startswith("path_traversal: signature reproduced under the alternate encoding")
               for n in res.notes), (
        f"the guards must have been SATISFIED by this benign origin (that is the point); notes={res.notes!r}")
    assert res.n_facts == 0, (
        f"a canonicalising KB that reads nothing minted a FACT: {[f.finding_ref for f in res.facts]}")
    assert res.family_verdict("path_traversal") == "LEAD"
    assert len(res.leads) == 1, f"exactly one LEAD record, got {len(res.leads)}"
    assert "not FACT-capable" in (res.leads[0].reason or ""), res.leads[0].reason


def test_a1b_suffix_matcher_with_no_normaliser_mints_nothing(monkeypatch, tmp_path):
    """The other half of D5: no normaliser at all. ``v.endswith("passwd")`` defeats the path-shaped control
    (which APPENDS a suffix) and both re-encodings still end in ``passwd``."""
    res = _rr(monkeypatch, tmp_path, _SuffixMatcherApp, "http://127.0.0.1:{port}/doc?file=report.pdf",
              "path_traversal")
    assert res.n_facts == 0, [f.finding_ref for f in res.facts]
    assert res.family_verdict("path_traversal") == "LEAD"


def test_a1c_exact_literal_matcher_is_refuted_by_the_encoding_guard(monkeypatch, tmp_path):
    """PINS ``_encoding_corroboration``. An endpoint keyed on the EXACT literal payload reproduces the
    signature under the canonical payload and under NEITHER re-encoding, so the guard refutes it and the
    arm never reaches admission. Delete the guard and this refusal disappears."""
    res = _rr(monkeypatch, tmp_path, _ExactLiteralApp, "http://127.0.0.1:{port}/doc?file=report.pdf",
              "path_traversal")
    _assert_ran_and_refused(res, "path_traversal", "path_traversal: encoding-corroboration refused")
    assert not res.leads, "a refused surface must not produce a verdict record"


def test_a1d_a_throttled_genuine_read_is_inconclusive_not_a_refutation(monkeypatch, tmp_path):
    """D6, PINS the COULD-NOT-OBSERVE branch. A REAL normpath+read LFI whose origin starts answering 429
    after the treatment request: the re-encodings are not answers about the path, so VIGIL concludes
    NOTHING. Collapse could-not-observe back into "signature absent" and this test sees the fabricated
    "it correlates with the payload" claim instead."""
    class _ThrottledLfi(_Base):
        seen = 0

        def reply(self, path, values):
            type(self).seen += 1
            if type(self).seen > 3:                     # 2 controls + treatment, then the limiter engages
                return 429, "rate limit exceeded"
            for v in values:
                if not v:
                    continue
                content = _FS.get(posixpath.normpath(posixpath.join(_DOCROOT, v)))
                if content is not None:
                    return 200, content
            return 404, "document not found"

    _ThrottledLfi.seen = 0
    res = _rr(monkeypatch, tmp_path, _ThrottledLfi, "http://127.0.0.1:{port}/download?file=report.pdf",
              "path_traversal")
    assert res.surfaces.get("path_traversal"), "the arm examined no surface — it was stubbed out"
    assert any(n.startswith("path_traversal: encoding corroboration COULD NOT BE OBSERVED")
               for n in res.notes), f"expected a could-not-observe note; notes={res.notes!r}"
    for note in res.notes:
        assert "correlates with the payload" not in note, (
            f"a transport failure was reported as proof of correlation: {note!r}")
    assert res.n_facts == 0 and not res.leads
    assert res.family_verdict("path_traversal") == "INCONCLUSIVE"


def test_a2_benign_403_path_rejected_page_is_a_lead(monkeypatch, tmp_path):
    """A correctly-defended 403 that explains the block and quotes a sample passwd line. The PATH-SHAPED
    control reproduces it, so it is not attributable to a read."""
    res = _rr(monkeypatch, tmp_path, _BlockedApp, "http://127.0.0.1:{port}/doc?file=a.txt", "path_traversal")
    _assert_ran_and_refused(res, "path_traversal", "path_traversal: control-differential refused")


def test_a3_constant_emission_docs_page_is_a_lead(monkeypatch, tmp_path):
    """A page that prints the signature regardless of input. The dedicated "constant-emission" control was
    DELETED as dominated (mutation: removing it failed zero tests); the PATH-SHAPED control catches this
    shape too, which is the measurement that justified the deletion — so this control now pins the
    path-shaped control instead, and fails if THAT is removed."""
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


def test_a_real_traversal_produces_exactly_one_lead_and_no_certificate(monkeypatch, tmp_path):
    """The false-negative half + D4 + D5 together.

    A GENUINE read still runs the whole pipeline, still fires the oracle, and still produces exactly ONE
    verdict record — but that record is a LEAD, because VIGIL cannot tell this program apart from the
    benign canonicalising origin in ``test_a1_...`` (they differ only by a dict value). The URL carries no
    parameter, so the arm walks the candidate names and the sink answers every one of them — the exact
    shape that produced 12 records for one bug before the ``break``.

    This is the honest statement of the capability: a real traversal is DETECTED and REPORTED, it is not
    CERTIFIED."""
    res = _rr(monkeypatch, tmp_path, _LfiApp, "http://127.0.0.1:{port}/download", "path_traversal")
    assert res.n_facts == 0, (
        f"path_traversal is registered fact_capable:false — no certificate may be minted, got "
        f"{[f.finding_ref for f in res.facts]}")
    assert len(res.leads) == 1, (
        f"a genuine traversal must produce exactly ONE lead record, got {len(res.leads)} "
        f"({[l.finding_ref for l in res.leads]})")
    assert res.family_verdict("path_traversal") == "LEAD"
    assert getattr(res.leads[0], "signed", None) is None, (
        "a LEAD must carry no signed certificate — a demoted verdict that still signs is the defect")
    assert any(n.startswith("path_traversal: signature reproduced under the alternate encoding")
               for n in res.notes), res.notes


def test_a_real_traversal_and_a_benign_canonicalising_kb_are_indistinguishable(monkeypatch, tmp_path):
    """The measurement behind the demotion, asserted as a property rather than described in a comment.

    ``_LfiApp`` (a real join+normpath+read) and ``_KbSearchApp`` (a canonicalising advisory that reads
    nothing) are the SAME PROGRAM with a different dict value, and the arm's guards — which vary only the
    SHAPE OF THE INPUT — produce the SAME outcome for both. If a future slice adds a guard that really
    discriminates a read from a canonical-path lookup, this test fails, and that is the signal to re-open
    ``fact_capable``."""
    real = _rr(monkeypatch, tmp_path, _LfiApp, "http://127.0.0.1:{port}/doc?file=report.pdf",
               "path_traversal")
    benign = _rr(monkeypatch, tmp_path, _KbSearchApp, "http://127.0.0.1:{port}/doc?file=report.pdf",
                 "path_traversal")

    def shape(r):
        return (r.n_facts, len(r.leads), r.family_verdict("path_traversal"),
                tuple(sorted(n.split(" [")[0] for n in r.notes)))

    assert shape(real) == shape(benign), (
        f"the guards DO discriminate a read from a canonical-path lookup — re-open the demotion.\n"
        f"  real   = {shape(real)}\n  benign = {shape(benign)}")
    assert real.n_facts == 0 and benign.n_facts == 0


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
    ("DB_PASSWORD=abc;defghij\nNEXT=1\n", True),                        # D7: ';' is NOT an .env delimiter
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

    sig = "DB_PASSWORD="
    # Lane S: the value-shape conjunction is ALWAYS composed WITH the present/absent control differential
    # that runtime_redrive prepends (icontains[body, SIG] AND not(icontains[control_body, SIG])). That PD4
    # differential is the exposure arm's positive discriminator; the value-shape clauses only narrow it. Test
    # the predicate AS COMPOSED — an isolated value-shape conjunction is the self-consistency tautology the
    # structural grammar correctly refuses (contains[body, secret_assignment] with secret_assignment lifted
    # FROM body).
    preds = [{"icontains": [{"var": "body"}, sig]},
             {"not": {"icontains": [{"var": "control_body"}, sig]}},
             *_secret_value_predicates(sig)]
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


# ===================================================================================================
# D7 — the value shape must never TRUNCATE, and never carry a truncated value into a certificate
# ===================================================================================================

@pytest.mark.parametrize("value", [
    "abc;defghij",                                     # ';' is not a delimiter in .env
    "django-insecure-8k#l2@v3q_w5zr7tn1m4be6y",        # '#' mid-value is not a comment
    "aaaa&bbbbbbbb",                                   # '&' is a query separator, not an .env one
])
def test_an_unquoted_value_is_never_cut_at_an_env_non_delimiter(value):
    """D7: the extracted value must be the WHOLE right-hand side. Either the arm accepts it verbatim, or
    it refuses it — but it must never quietly shorten it, because a shortened value both produces a
    fabricated "only N character(s) long" refusal and, when it survives, lands in a SIGNED certificate as
    the evidence."""
    from vigil_integration.live.runtime_redrive import _secret_assignment
    assignment, extracted, why = _secret_assignment(f"APP_ENV=production\nDB_PASSWORD={value}\nNEXT=1\n",
                                                    "DB_PASSWORD=")
    if assignment:
        assert extracted == value, f"the certificate would carry a TRUNCATED secret: {extracted!r}"
    else:
        assert "character(s) long" not in why, (
            f"a truncated value produced a length refusal that is not about the real value: {why!r}")


def test_a_refused_value_never_reaches_a_certificate(monkeypatch, tmp_path):
    """The end-to-end half of D7: a value the shape refuses must produce NO certificate at all — not a
    certificate over a shortened prefix of it."""
    leaked = "django-insecure-8k#l2@v(3q_w!5z)r7t+n%1m^4b"
    res = _rr(monkeypatch, tmp_path,
              _env_app(f"APP_ENV=production\nDB_PASSWORD={leaked}\n", catch_all=False),
              "http://127.0.0.1:{port}/", "exposure")
    _assert_ran_and_refused(res, "exposure", "exposure: value-shape refused")
    for ctx in res.contexts.values():
        blob = repr(ctx)
        assert "django-insecure" not in blob, f"a truncated secret reached the evidence: {blob[:200]}"


# ===================================================================================================
# B3 — a note may never assert an observation the branch that wrote it did not make
# ===================================================================================================

class _SafeSpaNoSecrets(_Base):
    """A perfectly SAFE modern SPA: it 200s EVERY path with the app shell. There is no /.env, no
    /actuator/env, no /.git/config, and no secret signature ANYWHERE in any body it serves."""

    def reply(self, path, values):
        return 200, _SPA_SHELL


def test_a_benign_spa_with_no_secret_writes_no_note_at_all(monkeypatch, tmp_path):
    """The reintroduced D2 defect, pinned. ``_secret_assignment`` was called WITHOUT first checking the
    signature was in the body, so against this origin the arm wrote:

        "the signature 'DB_PASSWORD=' is present but 'DB_PASSWORD=' is not present in the body"

    — two unmade observations contradicting each other inside one sentence, persisted into the audit
    trail. Presence is now CHECKED before it is CLAIMED, so there is nothing to say and nothing is said."""
    res = _rr(monkeypatch, tmp_path, _SafeSpaNoSecrets, "http://127.0.0.1:{port}/", "exposure")
    assert res.surfaces.get("exposure"), "the arm examined no exposure surface — it was stubbed out"
    assert res.n_facts == 0 and not res.leads
    for note in res.notes:
        assert not ("is present" in note and "is not present" in note), (
            f"a note asserted an observation the branch that wrote it never made: {note!r}")
    assert not [n for n in res.notes if n.startswith("exposure: value-shape refused")], (
        f"a value-shape refusal was written for a body that never carried the signature: {res.notes!r}")


def test_every_refusal_note_promises_only_what_the_result_contains(monkeypatch, tmp_path):
    """Non-blocking (1): refusal notes used to end "→ LEAD" while no ``AdapterResult`` was created on any
    refusal path (measured leads=0, family_verdict='INCONCLUSIVE'). A note may not promise a record that
    does not exist."""
    res = _rr(monkeypatch, tmp_path, _ExactLiteralApp, "http://127.0.0.1:{port}/doc?file=report.pdf",
              "path_traversal")
    refusals = [n for n in res.notes if "refused" in n]
    assert refusals, f"expected at least one refusal note; notes={res.notes!r}"
    for note in refusals:
        if note.rstrip().endswith("→ LEAD"):
            assert res.leads, f"the note promises a LEAD record but none exists: {note!r}"


def test_refusal_notes_are_not_duplicated_per_candidate_parameter(monkeypatch, tmp_path):
    """Non-blocking (2): one endpoint used to emit the identical refusal note 12 times (once per candidate
    parameter name)."""
    res = _rr(monkeypatch, tmp_path, _BlockedApp, "http://127.0.0.1:{port}/doc?file=a.txt",
              "path_traversal")
    assert len(res.notes) == len(set(res.notes)), f"duplicate notes in the audit trail: {res.notes!r}"


# ===================================================================================================
# B1 — a Unicode off-by-N minted a signed, offline-re-verifying FALSE `exposure` FACT
# ===================================================================================================
#
# ``_secret_assignment`` searched the LOWERCASED body and then SLICED THE ORIGINAL one. ``str.lower()`` is
# a per-codepoint map whose image is 1..3 codepoints, and U+0130 (``İ``, the Turkish dotted capital I)
# lowercases to TWO characters — so every ``İ`` before the signature shifted the slice by one and the
# extractor returned an arbitrary window. Through the real gated arm, a ``/.env`` carrying NO credential at
# all minted a signed FACT whose ``secret_value`` was ``'B_PASSWORD=documented_here'`` and which re-verified
# OFFLINE (rc=0, 1/1 reproduced). On the non-minting side the same bug returned a TRUNCATED real credential
# on the ACCEPT branch (``why=""``), violating D7 and the two tests written to pin it.

_ENV_TURKISH_NO_SECRET = ("#" + "İ" * 8 + " dagitim notlari (deployment notes)\n"
                          "DB_PASSWORD=\n"
                          "notes:DB_PASSWORD=documented_here\n")
_ENV_TURKISH_REAL = ("# İstanbul region — production\n"
                     "DB_HOST=db.internal\n"
                     "DB_PASSWORD=Pr0dKey-Real-Value-9x\n")


def test_b1_str_lower_is_not_length_preserving_but_the_arm_s_fold_is():
    """The root cause, enumerated rather than asserted from memory. Exactly one codepoint in all of Unicode
    makes ``str.lower()`` change length — U+0130 — and :func:`_lower_aligned` is length-preserving for
    every one of the 0x110000 codepoints, which is the property every offset in ``_secret_assignment``
    depends on. Re-introduce ``hay.lower()`` anywhere in that function and the live controls below fail;
    weaken the fold and this one does."""
    from vigil_integration.live.runtime_redrive import _lower_aligned

    expanding = [i for i in range(0x110000) if len(chr(i).lower()) != 1]
    assert expanding == [0x130], (
        f"the set of codepoints whose lower() is not length-1 changed: {[hex(i) for i in expanding]}")
    assert len("İ".lower()) == 2, "U+0130 must still be the expanding case this guard is about"
    bad = [hex(i) for i in range(0x110000) if len(_lower_aligned(chr(i))) != 1]
    assert not bad, f"_lower_aligned is NOT length-preserving at {bad[:8]}"
    assert _lower_aligned("İstanbul") == "istanbul"
    assert _lower_aligned("ABC") == "abc"


@pytest.mark.parametrize("prefix", ["", "# İ region\n", "#" + "İ" * 40 + "\n", "Kİİ=1\n"])
def test_b1_a_dotted_capital_i_never_shifts_the_extracted_value(prefix):
    """The hermetic half: whatever precedes it, the extracted value is the WHOLE right-hand side. Under the
    offset bug ``"# İ region\\nDB_PASSWORD=Pr0dKey-Real-Value-9x\\n"`` returned ``'r0dKey-Real-Value-9x'``
    — a TRUNCATED secret, on the ACCEPT branch, which is exactly what D7 forbids."""
    from vigil_integration.live.runtime_redrive import _secret_assignment
    body = f"{prefix}DB_PASSWORD=Pr0dKey-Real-Value-9x\n"
    assignment, value, why = _secret_assignment(body, "DB_PASSWORD=")
    assert why == "", f"a real credential was refused: {why!r}"
    assert value == "Pr0dKey-Real-Value-9x", f"the certificate would carry a shifted/truncated value: {value!r}"
    assert assignment == "DB_PASSWORD=Pr0dKey-Real-Value-9x"
    assert assignment in body, "the assignment must be a verbatim substring of the captured body"


@pytest.mark.parametrize("body", [
    "notes:DB_PASSWORD=documented_here\n",            # prose naming the key
    "OLD_DB_PASSWORD=Real-Value-Here\n",              # a LONGER key that ends with the signature
    "# DB_PASSWORD=your-value-goes-here\n",           # a commented example
    "path=/etc/DB_PASSWORD=Real-Value-Here\n",        # the key inside a path
])
def test_b1_a_signature_that_does_not_begin_an_assignment_is_the_key_being_named(body):
    """The second half of the PoC: with the offset fixed, the ``/.env`` still had to be refused, because
    its only line-start ``DB_PASSWORD=`` is EMPTY and the other occurrence is a prose line. In .env /
    shell-export grammar an assignment BEGINS A LINE (optionally after whitespace, optionally after
    ``export``); anything else is the key being NAMED."""
    from vigil_integration.live.runtime_redrive import _secret_assignment
    assignment, value, why = _secret_assignment(body, "DB_PASSWORD=")
    assert not assignment and why, f"expected a refusal for {body!r}, got {assignment!r}"
    assert "DB_PASSWORD" not in why, "a refusal note must not quote the candidate"


@pytest.mark.parametrize("body", [
    "DB_PASSWORD=S3cr3t-Real-Prod-Key\n",             # first line
    "APP_ENV=production\nDB_PASSWORD=S3cr3t-Real-Prod-Key\n",
    "export DB_PASSWORD=S3cr3t-Real-Prod-Key\n",      # shell export form
    "   DB_PASSWORD=S3cr3t-Real-Prod-Key\n",          # indented
])
def test_b1_the_anchor_still_accepts_every_real_assignment_form(body):
    """The recall half of the anchor rule: it must not cost a single ordinary ``.env`` shape."""
    from vigil_integration.live.runtime_redrive import _secret_assignment
    assignment, value, why = _secret_assignment(body, "DB_PASSWORD=")
    assert why == "" and value == "S3cr3t-Real-Prod-Key", (why, value)


def test_b1_an_env_with_no_credential_behind_a_dotted_capital_i_mints_nothing(monkeypatch, tmp_path):
    """THE NEGATIVE CONTROL, end to end through the real gated arm. This exact body minted a signed
    certificate whose ``secret_value`` was ``'B_PASSWORD=documented_here'`` and which passed
    ``framework.v2 verify`` with rc=0. It must now be REFUSED, with the arm demonstrably having run."""
    res = _rr(monkeypatch, tmp_path, _env_app(_ENV_TURKISH_NO_SECRET, catch_all=False),
              "http://127.0.0.1:{port}/", "exposure")
    _assert_ran_and_refused(res, "exposure", "exposure: value-shape refused")
    for ctx in res.contexts.values():
        blob = repr(ctx)
        assert "B_PASSWORD=documented" not in blob and "documented_here" not in blob, (
            f"a mis-extracted window reached the evidence: {blob[:300]}")


def test_b1_a_real_credential_behind_a_dotted_capital_i_still_mints_unshifted(monkeypatch, tmp_path):
    """THE POSITIVE CONTROL. Fixing the off-by-N by refusing every body containing an ``İ`` would be the
    cheap non-fix; a genuine leak behind one must still mint, and the certified value must be the WHOLE
    credential, byte for byte."""
    res = _rr(monkeypatch, tmp_path, _env_app(_ENV_TURKISH_REAL, catch_all=False),
              "http://127.0.0.1:{port}/", "exposure")
    assert res.n_facts == 1, f"a real .env leak behind an 'İ' must still mint; notes={res.notes!r}"
    assert res.family_verdict("exposure") == "FACT"
    ctx = res.contexts[res.facts[0].finding_ref]
    ev = ctx.get("observed_evidence", {})
    assert ev.get("secret_value") == "Pr0dKey-Real-Value-9x", (
        f"the certificate carries a shifted/truncated value: {ev.get('secret_value')!r}")
    assert ev.get("secret_assignment") == "DB_PASSWORD=Pr0dKey-Real-Value-9x"
    assert ev["secret_assignment"] in ev["body"], "the assignment must occur verbatim in the retained body"


# ===================================================================================================
# B2 — could-not-observe must be FAIL-CLOSED, not an enumerated list of "throttle" statuses
# ===================================================================================================
#
# ``_encoding_corroboration`` scored an answer as an OBSERVATION whenever its status was outside
# {0, 408, 425, 429} ∪ [500, ...) — and it never consulted ``body_semantically_available`` at all. Measured
# against a GENUINE normpath+read LFI, that concluded a REFUTATION (and persisted "sent, answered, and
# OBSERVED not to carry it ... so it tracks the literal payload rather than the path") at 403 — the
# canonical WAF block — and at 401 / 302 / 451 / 404 / a Brotli body / two concatenated gzip members.
# VIGIL had observed nothing, and a real arbitrary-file read behind a WAF that flags dot-segment
# obfuscation but not the plain payload was written up as a correlation and dropped.


def _lfi_with_staged_alternates(alt_status: int, alt_raw: bytes, alt_headers):
    """A GENUINE local-file-inclusion origin (join + POSIX resolve + read) that answers the two CONTROLS
    and the TREATMENT normally and then serves ``alt_status``/``alt_raw``/``alt_headers`` — i.e. exactly
    the alternate-ENCODING re-sends get the WAF/CDN answer under test."""

    class _H(http.server.BaseHTTPRequestHandler):
        n = 0

        def do_GET(self):  # noqa: N802
            parts = urlsplit(self.path)
            q = parse_qs(parts.query, keep_blank_values=True)
            values = [v for vs in q.values() for v in vs]
            type(self).n += 1
            if type(self).n > 3:                   # 2 controls + the treatment, then the re-encodings
                self.send_response(alt_status)
                for k, v in alt_headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(alt_raw)))
                self.end_headers()
                if alt_raw:
                    self.wfile.write(alt_raw)
                return
            content = None
            for v in values:
                if not v:
                    continue
                content = _FS.get(posixpath.normpath(posixpath.join(_DOCROOT, v)))
                if content is not None:
                    break
            status, text = (200, content) if content is not None else (404, "document not found")
            raw = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            return

    _H.n = 0
    return _H


_PLAIN = [("Content-Type", "text/plain; charset=utf-8")]

_B2_UNOBSERVABLE = [
    ("403-waf-block", 403, b"Forbidden by WAF rule 930110 (path traversal)\n", _PLAIN),
    ("302-redirect", 302, b"", [("Location", "/download?file=report.pdf")]),
    # An EMPTY 2xx decodes cleanly to "" and so satisfies every OTHER clause of the rule. It is still a
    # NON-OBSERVATION: it is not evidence that the read failed to reproduce, it is evidence that nothing
    # came back — and it is what a WAF or an edge worker typically returns when it drops a dot-segment
    # payload. The corroboration leg therefore requires a NON-EMPTY decoded body; the CONTROL leg does
    # not (see test_b2_the_control_leg_still_accepts_an_empty_body).
    ("empty-200", 200, b"", _PLAIN),
    ("brotli-undecodable", 200, b"\x1b\x2e\x00\xf8\x25\x71\x6e\x6f\x74\x62\x72", _PLAIN
     + [("Content-Encoding", "br")]),
    ("concatenated-gzip", 200,
     __import__("gzip").compress(b"root:x:0:0:root:/root:/bin/bash\n") + __import__("gzip").compress(b""),
     _PLAIN + [("Content-Encoding", "gzip")]),
    ("401-auth", 401, b"Unauthorized\n", _PLAIN),
    ("451-legal", 451, b"Unavailable For Legal Reasons\n", _PLAIN),
    ("404-not-found", 404, b"Not Found\n", _PLAIN),
    ("429-rate-limit", 429, b"slow down\n", _PLAIN),
    ("503-unavailable", 503, b"unavailable\n", _PLAIN),
]


@pytest.mark.parametrize("label,status,raw,headers", _B2_UNOBSERVABLE,
                         ids=[c[0] for c in _B2_UNOBSERVABLE])
def test_b2_a_genuine_read_whose_reencodings_are_not_answers_is_inconclusive(monkeypatch, tmp_path,
                                                                             label, status, raw, headers):
    """A REAL arbitrary-file read whose alternate-encoding re-sends come back as something that is not a
    document VIGIL read. VIGIL must conclude NOTHING — never that the signature "tracks the literal
    payload". Collapse the rule back to an enumerated status list, or stop consulting the decode
    provenance, and the 403 / 302 / brotli / concatenated-gzip cases here see the fabricated claim."""
    res = _rr(monkeypatch, tmp_path, _lfi_with_staged_alternates(status, raw, headers),
              "http://127.0.0.1:{port}/download?file=report.pdf", "path_traversal")
    # POSITIVE: the arm RAN — it examined the surface and got far enough to fire the oracle and reach the
    # corroboration leg (a stubbed arm has no surface and no note).
    assert res.surfaces.get("path_traversal"), "the arm examined no surface — it was stubbed out"
    assert any(n.startswith("path_traversal: encoding corroboration COULD NOT BE OBSERVED")
               for n in res.notes), f"expected a could-not-observe note; notes={res.notes!r}"
    for note in res.notes:
        assert "tracks the literal payload" not in note, (
            f"an unobservable re-encoding was reported as a refutation: {note!r}")
        assert "OBSERVED not to carry" not in note, (
            f"an observation VIGIL never made was persisted into the audit trail: {note!r}")
    assert res.n_facts == 0 and not res.leads
    assert res.family_verdict("path_traversal") == "INCONCLUSIVE"


class _EmptyControlLfi(http.server.BaseHTTPRequestHandler):
    """A GENUINE join+resolve+read LFI whose MISSES are the ordinary bare 404: no ``Content-Type``, no
    body at all. Both controls therefore come back EMPTY and with an undeclared charset — the single most
    common shape on the real web."""

    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        q = parse_qs(parts.query, keep_blank_values=True)
        content = None
        for v in (x for vs in q.values() for x in vs):
            if not v:
                continue
            content = _FS.get(posixpath.normpath(posixpath.join(_DOCROOT, v)))
            if content is not None:
                break
        if content is None:
            self.send_response(404)                 # no Content-Type, no Content-Length, NO BODY
            self.end_headers()
            return
        raw = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        return


def test_b2_the_control_leg_still_accepts_an_empty_body(monkeypatch, tmp_path):
    """THE OTHER DIRECTION OF THE ASYMMETRY, pinned so a later edit cannot collapse the two rules.

    The two legs ask different questions. The CONTROL leg asks "does this origin emit the signature
    REGARDLESS OF INPUT?" — and an empty body answers that: no, it does not. The CORROBORATION leg asks
    "did the READ reproduce?" — and an empty body answers nothing (see the ``empty-200`` case above).

    Here BOTH controls come back as the ordinary bare 404 (no Content-Type, no body), which is the most
    common miss shape on the web. If someone "tidies" ``_observed_signature`` into ``_read_a_document``,
    both controls become unobservable, the arm stops before the treatment is ever sent, and this genuine
    arbitrary-file read silently becomes INCONCLUSIVE on every ordinary origin."""
    res = _rr(monkeypatch, tmp_path, _EmptyControlLfi,
              "http://127.0.0.1:{port}/download?file=report.pdf", "path_traversal")
    assert res.surfaces.get("path_traversal"), "the arm examined no surface — it was stubbed out"
    assert not [n for n in res.notes if n.startswith("path_traversal: control COULD NOT BE OBSERVED")], (
        f"an EMPTY control body was scored as unobservable — the control leg's raw_len==0 acceptance was "
        f"removed, and every ordinary bare-404 origin now dies before the treatment: {res.notes!r}")
    assert any(n.startswith("path_traversal: signature reproduced under the alternate encoding")
               for n in res.notes), (
        f"the arm never got past the controls to the treatment; notes={res.notes!r}")
    assert res.n_facts == 0, "path_traversal is fact_capable:false"
    assert len(res.leads) == 1 and res.family_verdict("path_traversal") == "LEAD", (
        f"the genuine read must still reach exactly one LEAD, got {len(res.leads)}")


def test_b2_positive_control_a_readable_2xx_still_refutes_a_literal_keyed_page(monkeypatch, tmp_path):
    """The other direction: FAIL-CLOSED must not mean "never refute anything". When the re-encodings come
    back as a 2xx whose body VIGIL completely decoded and which genuinely LACKS the signature, that IS an
    observation and the refutation stands — otherwise a literal-payload-keyed page would become a LEAD."""
    res = _rr(monkeypatch, tmp_path,
              _lfi_with_staged_alternates(200, b"document served\n", _PLAIN),
              "http://127.0.0.1:{port}/download?file=report.pdf", "path_traversal")
    _assert_ran_and_refused(res, "path_traversal", "path_traversal: encoding-corroboration refused")
    assert not res.leads, "a refused surface must not produce a verdict record"
    assert any("body decoded" in n for n in res.notes), (
        f"the refutation must record that VIGIL actually decoded the body; notes={res.notes!r}")


# ===================================================================================================
# B3 — the benign NON-path ("constant emission") control is NOT dominated; here is the counterexample
# ===================================================================================================
#
# A previous revision DELETED it, on a mutation matrix ("removing it failed ZERO tests") plus the
# analytical claim that "any origin that emits the signature under the canonical traversal treatment also
# emits it under the path-shaped control unless it is basename/suffix-keyed". Both were overclaims: the
# mutation matrix measured the TEST SUITE, not the shape space, and the analytical claim has a
# counterexample that is neither basename- nor suffix-keyed.

_EXT_ALLOWED = frozenset({".txt", ".pdf", ".md", ".csv", ".png"})
_EXT_HELP = ("File not served.\nExample of a system record this server will never expose:\n"
             + _PASSWD.splitlines()[0] + "\n")


def _ext_allowlist_reply(values: "list[str]") -> "tuple[int, str]":
    """An EXTENSION-ALLOWLIST static server, as a pure function so the redundancy claim can be tested
    directly. A known extension (or no extension at all) gets the boilerplate help page, which quotes a
    sample passwd line as such pages do; an UNKNOWN extension gets a clean 403 with no sample. It reads
    nothing, ever, and it keys on neither the basename nor a suffix of the requested name."""
    for v in values:
        if not v:
            continue
        base = v.rsplit("/", 1)[-1]
        if "." in base and ("." + base.rsplit(".", 1)[-1]) not in _EXT_ALLOWED:
            return 403, "File type not permitted.\n"      # NO sample line
    return 200, _EXT_HELP


class _ExtAllowlistApp(_Base):
    def reply(self, path, values):
        return _ext_allowlist_reply(values)


def test_b3_the_two_controls_are_not_redundant_the_deleted_one_uniquely_refuses(monkeypatch, tmp_path):
    """The counterexample, measured on the pure endpoint logic: the SURVIVING path-shaped control MISSES
    this origin (``…/etc/passwd.vigilctlN`` is an unknown extension → the clean 403), the treatment FIRES
    (``…/etc/passwd`` has no extension → the help page), and only the RESTORED constant-emission control
    (``vigilctlN.txt`` — a known extension → the help page) refuses it. Delete it again and the arm emits
    a false LEAD against a correctly-defended server."""
    sig = _PASSWD.splitlines()[0]
    path_shaped = _ext_allowlist_reply(["../../../../etc/passwd.vigilctlabc123"])[1]
    constant = _ext_allowlist_reply(["vigilctlabc123.txt"])[1]
    treatment = _ext_allowlist_reply(["../../../../etc/passwd"])[1]
    assert sig not in path_shaped, "the path-shaped control would already catch this — no counterexample"
    assert sig in constant, "the constant-emission control must be the one that sees the signature"
    assert sig in treatment, "the treatment must fire, or there is nothing to refuse"


def test_b3_extension_allowlist_origin_is_refused_by_the_constant_emission_control(monkeypatch, tmp_path):
    """The same counterexample end to end through the real gated arm: it must produce NO lead and NO
    certificate, and the refusal note must name the control that actually caught it."""
    res = _rr(monkeypatch, tmp_path, _ExtAllowlistApp, "http://127.0.0.1:{port}/doc?file=a.txt",
              "path_traversal")
    _assert_ran_and_refused(res, "path_traversal", "path_traversal: control-differential refused")
    assert not res.leads, (
        f"a false LEAD against a correctly-defended server: {[l.finding_ref for l in res.leads]}")
    assert any("constant-emission" in n for n in res.notes), (
        f"the constant-emission control is the one that refuses this shape; notes={res.notes!r}")


def test_b3_both_controls_are_actually_sent_on_every_probed_parameter(monkeypatch, tmp_path):
    """Structural: the arm must SEND both controls, not merely define them. A benign origin that answers
    everything with a fixed page is probed with exactly two control values before the treatment."""
    seen: "list[str]" = []

    class _Recorder(_Base):
        def reply(self, path, values):
            seen.extend(v for v in values if v)
            return 200, "document served"

    res = _rr(monkeypatch, tmp_path, _Recorder, "http://127.0.0.1:{port}/doc?file=a.txt", "path_traversal")
    assert res.surfaces.get("path_traversal"), "the arm examined no surface — it was stubbed out"
    assert any(v.startswith("../../../../etc/passwd.vigilctl") for v in seen), (
        f"the PATH-SHAPED control was never sent: {seen!r}")
    assert any(v.startswith("vigilctl") and v.endswith(".txt") for v in seen), (
        f"the CONSTANT-EMISSION control was never sent: {seen!r}")
    assert res.n_facts == 0 and not res.leads


# ===================================================================================================
# N4 — the bounded-work break must fire on the ADMITTED verdict, not on `signal.fired`
# ===================================================================================================

def test_n4_an_inconclusive_admission_does_not_end_the_candidate_parameter_walk(monkeypatch, tmp_path):
    """A fired oracle over a body that was NOT semantically available admits INCONCLUSIVE — no record is
    produced at all — and breaking there ended the whole walk on the first unreadable response, losing
    every remaining insertion point.

    The origin: a real join+resolve+read LFI behind a caching tier that serves the CANONICAL payload's
    response uncompressed and over the read bound (so the capture is TRUNCATED: the signature is in the
    prefix VIGIL holds, but the document is incomplete) while the re-encoded variants come back from a
    small cached entry. The first candidate parameter therefore fires-but-admits-INCONCLUSIVE; the second
    is an ordinary read and must still be reached."""
    big = _PASSWD + ("A" * 2_100_000)

    class _TruncatingLfi(http.server.BaseHTTPRequestHandler):
        """Only the FIRST candidate parameter (``file``) is served from the oversized cache entry; every
        other parameter is an ordinary read. So parameter 1 fires-but-admits-INCONCLUSIVE and parameter 2
        must still be reached."""

        def do_GET(self):  # noqa: N802
            parts = urlsplit(self.path)
            status, text = 404, "document not found"
            for key, vals in parse_qs(parts.query, keep_blank_values=True).items():
                for v in vals:
                    if not v:
                        continue
                    content = _FS.get(posixpath.normpath(posixpath.join(_DOCROOT, v)))
                    if content is None:
                        continue
                    oversized = key.lower() == "file" and v == "../../../../etc/passwd"
                    status, text = 200, (big if oversized else content)
                    break
                if status == 200:
                    break
            raw = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            return

    res = _rr(monkeypatch, tmp_path, _TruncatingLfi, "http://127.0.0.1:{port}/download", "path_traversal")
    surfaces = res.surfaces.get("path_traversal") or set()
    assert len(surfaces) >= 2, (
        f"the walk stopped at the first INCONCLUSIVE admission — only {sorted(surfaces)} was examined")
    verdicts = [v for _b, v, _r in res.admissions]
    assert "INCONCLUSIVE" in verdicts, (
        f"the fixture did not produce the fired-but-unreadable admission it exists for: {res.admissions!r}")
    assert verdicts.count("INCONCLUSIVE") >= 1 and len(verdicts) >= 2, (
        f"the arm admitted only once, so the walk did not continue: {res.admissions!r}")
    assert res.n_facts == 0, "path_traversal is fact_capable:false"
    assert len(res.leads) == 1, (
        f"the walk must still reach a readable parameter and record exactly ONE lead, got "
        f"{[l.finding_ref for l in res.leads]}")


# ===================================================================================================
# B4 — the registry must not contradict the behaviour: scope the demotion honestly
# ===================================================================================================
#
# `fact_capable:false` is enforced at exactly ONE place — `live/verdict.py::admit`, the only reader of the
# registry — so it binds runtime_redrive, wiring and the Strix rail and NOTHING else. The core engine never
# imports the integration layer, and measured per route on the same commit: `framework.v2 scan` emits
# grounding:"fact"/High/0.90 for 11/11 benign origins via scanner/checks.py:ContentSignatureCheck,
# `framework.v2 verify` re-verifies them ok=True, and aegis/inspect.py:547 / scanner/library.py:404 return
# decision='confirmed' / action='block' on legitimate traffic. That route is PRE-EXISTING and other-owned;
# what this slice must not do is leave the registry naming an implementation that mints at rate 1.0 beside
# a column saying it cannot.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BRANCH_REGISTRY = _REPO_ROOT / "docs" / "capability-matrix" / "evidence-branches.json"


def _traversal_row() -> dict:
    from vigil_integration.live.tool_manifest import load_branch_registry
    return {b["id"]: b for b in load_branch_registry(_BRANCH_REGISTRY)}["path_traversal.file_signature"]


def test_b4_the_row_no_longer_names_an_implementation_that_still_mints():
    row = _traversal_row()
    assert row["fact_capable"] is False
    for ref in row["implementation_refs"]:
        assert "scanner/checks.py" not in ref, (
            f"the row declares fact_capable:false while naming {ref!r}, whose scan route still mints at "
            f"rate 1.0 — registry and behaviour must not contradict each other")
    assert any("runtime_redrive.py:runtime_redrive" in r for r in row["implementation_refs"]), (
        "the row must still name the implementation the demotion DOES bind")
    assert row["check"] != "ContentSignatureCheck", (
        "the `check` column named the core check too; this row describes the runtime_redrive arm")


def test_b4_the_open_core_route_is_recorded_as_a_missing_control_requirement():
    row = _traversal_row()
    missing = [c for c in row["control_requirements"] if c.startswith("MISSING:")]
    assert any("second_refusal" in c for c in missing), (
        f"the open core route must be an explicit MISSING: control requirement, got {missing!r}")


def test_b4_both_the_registry_and_the_module_scope_the_demotion_to_the_admission_layer():
    row = _traversal_row()
    lim = row["limitation"]
    for token in ("verdict.py:admit", "framework.v2 scan", "framework.v2 verify",
                  "aegis/inspect.py:547", "scanner/library.py:404"):
        assert token in lim, f"the registry limitation does not name the open route {token!r}"
    src = (_REPO_ROOT / "integration" / "vigil_integration" / "live" / "runtime_redrive.py").read_text(
        encoding="utf-8")
    assert "SCOPE OF THE path_traversal DEMOTION" in src, (
        "the module docstring must state the scope too — the registry is not the only thing a reader reads")
    for token in ("aegis/inspect.py:547", "scanner/library.py:404", "framework.v2 scan"):
        assert token in src, f"the module docstring does not name the open route {token!r}"


def test_b4_the_follow_up_names_the_exact_rows_and_file_lines_to_change():
    """The hand-off must be actionable without re-deriving it: the owning slice needs the exact
    BUG_CLASS_ORACLES rows, the file, and the lines."""
    bw = _traversal_row()["blocking_work"]
    assert "verify/verifier.py" in bw and "139-140" in bw, bw[-400:]
    assert "BUG_CLASS_ORACLES['path_traversal']" in bw and "BUG_CLASS_ORACLES['lfi']" in bw, bw[-400:]
    assert "SIDE_EFFECT" in bw
    assert "384" in bw and "401" in bw, "the precedent (postmessage_exploited / csp_bypass) must be cited"
    # …and the claim about the precedent must still be true of the file it cites.
    verifier = (_REPO_ROOT / "engine" / "crucible" / "framework" / "v2" / "verify" / "verifier.py").read_text(
        encoding="utf-8")
    assert '"path_traversal": (OracleKind.SIDE_EFFECT,)' in verifier or \
           "'path_traversal': (OracleKind.SIDE_EFFECT,)" in verifier, (
        "the follow-up describes a BUG_CLASS_ORACLES row that no longer exists — either it landed (delete "
        "the MISSING: requirement and re-open fact_capable deliberately) or the description drifted")


def test_b4_the_registry_limitation_matches_what_the_seam_actually_does():
    """BLOCK-5: the registry says the arm 'is still driven'. That sentence is only true if the engage seam
    dispatches the lead-only classes, so assert the code path rather than the prose."""
    import inspect

    from vigil_integration.live import wiring
    from vigil_integration.live.runtime_redrive import RUNTIME_LEAD_CLASSES, RUNTIME_REDRIVE_CLASSES

    src = inspect.getsource(wiring._live_runtime_redrive_fact)
    assert "RUNTIME_REDRIVE_CLASSES" in src and "not in RUNTIME_REDRIVE_CLASSES" in src, (
        "the engage seam gates on the FACT-capable set, so the lead-only classes are never driven and the "
        "registry's 'the arm is still driven' is false on the operator's primary route")
    assert set(RUNTIME_LEAD_CLASSES) <= set(RUNTIME_REDRIVE_CLASSES)
    assert "still driven" in _traversal_row()["limitation"]


@pytest.mark.parametrize("label,body,accepted", [
    ("lf",     "APP_ENV=prod\nDB_PASSWORD=S3cr3t-Real-Prod-Key\n",        True),
    ("crlf",   "APP_ENV=prod\r\nDB_PASSWORD=S3cr3t-Real-Prod-Key\r\n",    True),
    ("cr-only", "APP_ENV=prod\rDB_PASSWORD=S3cr3t-Real-Prod-Key\r",       False),
    ("stray-u-feff", "APP_ENV=prod\n﻿DB_PASSWORD=S3cr3t-Real-Prod-Key\n", False),
])
def test_b1_the_disclosed_line_terminator_false_refuses_stay_disclosed(label, body, accepted):
    """PINS A DISCLOSED LIMITATION, not a desired behaviour.

    The assignment anchor finds the line start with ``rfind("\\n")`` only and rejects a prefix that
    ``str.strip()`` leaves non-blank, so two shapes are measured FALSE REFUSES of a genuine credential:
    a CR-ONLY body (classic-Mac / some exporters) presents as a single line, and a stray U+FEFF before a
    line-start key is not stripped. Both are recorded in exposure.secret_signature's ``limitation``.

    A real UTF-8 byte-order mark does NOT reach here — ``body_decode`` selects ``utf-8-sig`` and strips
    it — so only a genuine mid-document U+FEFF triggers the second case.

    IF YOU FIX EITHER, update that ``limitation`` in the SAME commit and flip the expectation here. The
    point of this control is that a measured claim in the registry cannot rot silently, which is exactly
    the failure NB-1 caught one paragraph further down the same row."""
    from vigil_integration.live.runtime_redrive import _secret_assignment
    assignment, value, why = _secret_assignment(body, "DB_PASSWORD=")
    if accepted:
        assert why == "" and value == "S3cr3t-Real-Prod-Key", (label, why, value)
    else:
        assert not assignment and "does not begin an assignment" in why, (label, why)


_NOT_ADMITTED_SENTINEL = "{_NOT_ADMITTED}"


def test_the_value_shape_refusal_note_never_out_claims_its_reason():
    """NB-3, as a property over EVERY refusal reason the extractor can produce. The note wrapper used to
    append "so what was observed is a key being NAMED (documentation, a CI template, a bundled string, a
    shipped placeholder)" to all of them — an inference, false whenever the reason is narrower (a
    CR-terminated .env with a real credential is refused for a non-blank line prefix, which is not
    evidence of documentation). Same class as D2."""
    src = (_REPO_ROOT / "integration" / "vigil_integration" / "live" / "runtime_redrive.py").read_text(
        encoding="utf-8")
    import re
    note = src[src.index('f"exposure: value-shape refused'):]
    note = note[:note.index(_NOT_ADMITTED_SENTINEL)]
    note = re.sub(r'"\s*\n\s*f"', "", note)      # join the adjacent f-string fragments
    for inference in ("key being NAMED (", "documentation, a CI template", "shipped placeholder"):
        assert inference not in note, (
            f"the refusal note asserts {inference!r} for every value of `why`, including reasons that do "
            f"not support it")
    assert "does not evidence a leaked value" in note, (
        "the note must state only what follows from `why` for every value of `why`")
