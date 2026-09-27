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
            if type(self).seen > 2:                     # control + treatment, then the limiter engages
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
