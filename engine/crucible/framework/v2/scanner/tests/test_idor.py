"""
IDOR / BOLA producer — a three-identity, oracle-confirmed unauthorized read.

A three-user app serves documents. alice + bob share a tenant; carol is in another.
Acting as alice, the check requests bob's document. On the VULNERABLE app object-level
authz is broken WITHIN a tenant (alice reads bob's doc — the achieved BOLA) while a
CROSS-tenant read RENDERS the same object (same shape) with the private body WITHHELD,
so carol (a THIRD, authenticated-but-UNAUTHORIZED principal) gets a SUBSTANTIVE SAME-SHAPE
200 lacking bob's secret — the round-5 same-ref unauthorized-authenticated baseline that
proves bob's secret is genuinely access-gated PRIVATE content, not a reflected per-object
token (a reflected token would appear in carol's same-shape render too). On the SECURE app
alice's request is 403'd and nothing is confirmed. Authorization is proven by the SAME-SHAPE
3-view differential (owner-present, attacker-present, peer-same-shape-absent), not by a
numeric id's presence. A DENIAL (401/403) unauthorized-authenticated baseline is NOT a valid
clause-(c) control (it never renders the object, so a reflected token is absent from it
vacuously) — accepting it (as round-4 did) let a reflected slug mint a durable false FACT;
round-5 requires the baseline to be a substantive same-shape read or the class is a LEAD.
"""

from __future__ import annotations

import contextlib
import re
import secrets
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.checks import IdorCheck
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind
from framework.v2.scanner.session import AuthSession, LoginSequence

# doc id -> (owner, secret content)
_DOCS = {"1": ("alice", "alice-tax-return"), "2": ("bob", "bob-medical-record")}
_CREDS = {"alice": "pw-alice", "bob": "pw-bob", "carol": "pw-carol"}
# user -> tenant. alice+bob share a tenant (the intra-tenant BOLA); carol is in another.
_TENANTS = {"alice": "acme", "bob": "acme", "carol": "globex"}


def _slug(doc_id: str) -> str:
    """A per-object PUBLIC token (a slug/display-id) — the round-3 fourth-variant reflected token."""
    return f"slug-{doc_id}-public-reference"


def _make_handler(mode: str) -> type[BaseHTTPRequestHandler]:
    """``mode`` selects the app's object-level authz behaviour:

    * ``vuln``   — broken intra-tenant authz: a same-tenant peer reads another user's FULL doc (the
      achieved BOLA); a cross-tenant read RENDERS the same object (SAME SHAPE, 200) with the private
      body WITHHELD (carol's round-5 same-shape unauthorized-authenticated baseline).
    * ``secure`` — strict own-only authz: any non-owner read is 403'd.
    * ``reflect_same_shape`` — SECURED (own-only), but every non-owner gets a SUBSTANTIVE 200 soft-deny
      that ECHOES the requested object's public slug (a reflected per-object token) and reads NOTHING
      private. alice AND carol get the SAME-SHAPE soft-deny, so the slug appears in carol's baseline too.
    * ``reflect_deny_baseline`` — the DANGEROUS variant: SECURED (own-only); a same-tenant non-owner
      (alice) gets the reflecting 200 soft-deny, but a cross-tenant read (carol) is a HARD 403 that
      never renders the object. This is exactly the round-4 hole — a reflected slug present in alice's
      read and absent from carol's non-rendering 403 — which round-5 must refuse (403 is not a valid
      same-shape clause-(c) control), keeping it a LEAD.
    """

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            return

        def _user(self) -> str | None:
            m = re.search(r"session=([^;]+)", self.headers.get("Cookie", ""))
            tok = m.group(1) if m else None
            return self.server.tokens.get(tok) if tok else None  # type: ignore[attr-defined]

        def _reply(self, status: int, body: bytes, extra=()) -> None:
            self.send_response(status)
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            n = int(self.headers.get("Content-Length", 0) or 0)
            p = urllib.parse.parse_qs(self.rfile.read(n).decode())
            user, pw = p.get("user", [""])[0], p.get("password", [""])[0]
            if _CREDS.get(user) == pw:
                tok = secrets.token_hex(8)
                self.server.tokens[tok] = user  # type: ignore[attr-defined]
                self._reply(200, b"ok", [("Set-Cookie", f"session={tok}; Path=/")])
            else:
                self._reply(401, b"bad creds")

        def do_GET(self) -> None:  # noqa: N802
            sp = urllib.parse.urlsplit(self.path)
            user = self._user()
            if sp.path != "/document" or user is None:
                self._reply(401, b"please log in")
                return
            doc_id = urllib.parse.parse_qs(sp.query).get("id", [""])[0]
            doc = _DOCS.get(doc_id)
            if doc is None:
                self._reply(404, b"no such doc")
                return
            owner, secret = doc
            slug = _slug(doc_id)
            if owner == user:
                # the owner always sees the full record (slug + the private secret).
                self._reply(200, f"doc {doc_id} owner={owner} {slug} secret={secret}".encode())
                return
            if mode == "vuln":
                if _TENANTS.get(user) != _TENANTS.get(owner):
                    # cross-tenant: SAME-SHAPE render, private body withheld (carol's round-5 baseline).
                    self._reply(200, f"doc {doc_id} owner={owner} {slug} secret=[restricted]".encode())
                    return
                # broken intra-tenant authz: a same-tenant peer reads the FULL doc (the achieved BOLA).
                self._reply(200, f"doc {doc_id} owner={owner} {slug} secret={secret}".encode())
                return
            if mode == "secure":
                self._reply(403, b"forbidden")  # strict object-level authz (own-only)
                return
            if mode == "reflect_same_shape":
                # SECURED: every non-owner gets the SAME-SHAPE soft-deny echoing the slug, no secret.
                self._reply(200, f"you cannot open {slug} - please request access from the owner".encode())
                return
            if mode == "reflect_deny_baseline":
                if _TENANTS.get(user) == _TENANTS.get(owner):
                    # same-tenant non-owner: the reflecting 200 soft-deny (echoes the slug, no secret).
                    self._reply(200, f"you cannot open {slug} - please request access from the owner".encode())
                    return
                # cross-tenant: a HARD 403 that never renders the object (the round-4 hole).
                self._reply(403, b"cross-tenant read blocked")
                return
            raise AssertionError(f"unknown mode {mode!r}")

    return _H


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler) -> None:
        super().__init__(addr, handler)
        self.tokens: dict[str, str] = {}


@contextlib.contextmanager
def _app(mode: str) -> Iterator[str]:
    srv = _Server(("127.0.0.1", 0), _make_handler(mode))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _raw_send(req: HttpRequest) -> dict:
    r = urllib.request.Request(req.url, method=req.method, headers=dict(req.headers))
    if req.body is not None:
        r.data = req.body.encode("utf-8")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 (loopback)
            return {"status": resp.status, "headers": list(resp.headers.items()),
                    "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": list(e.headers.items()),
                "body": e.read().decode("utf-8", "replace")}


def _session(base: str, user: str) -> AuthSession:
    return AuthSession(_raw_send, LoginSequence(
        url=f"{base}/login", body=f"user={user}&password={_CREDS[user]}",
        logged_out_markers=("please log in", "forbidden")))


def _idor_check(base: str, *, discriminator: str = "bob-medical-record",
                with_unauth: bool = True) -> IdorCheck:
    # attacker is the auditor's session (alice); victim/owner is bob, ref = bob's doc "2". The victim-unique
    # discriminator is bob's private secret content (never in alice's own doc), so a fire is the achieved
    # cross-tenant read of bob's PRIVATE marker — not a whole-body containment on shared boilerplate. The
    # no-credential baseline is the RAW send (no session cookie): the app 401s a logged-out request (round-2).
    # The round-5 unauthorized-authenticated baseline is carol (a DIFFERENT tenant): her same-ref read is a
    # SUBSTANTIVE SAME-SHAPE 200 that renders the object with the private body withheld, so bob's marker is
    # ABSENT from it — proving the content is genuinely access-gated PRIVATE data, not a reflected per-object
    # token (which would appear in carol's same-shape render too). Both baselines lacking the marker + alice
    # reaching it => a sound BOLA. ``discriminator`` and ``with_unauth`` let the negative tests vary the marker
    # (e.g. a reflected slug) and drop the unauthorized-authenticated baseline.
    bob = _session(base, "bob")
    carol = _session(base, "carol")
    return IdorCheck(id="idor-doc", ref_param="id", victim_ref="2", victim_send=bob.send,
                     victim_discriminator=discriminator, control_ref="1",
                     nocred_send=_raw_send, unauth_send=(carol.send if with_unauth else None))


def _run(base: str, check: IdorCheck) -> list:
    alice = _session(base, "alice")
    req = HttpRequest(method="GET", url=f"{base}/document?id=1")  # alice's own doc as the seed
    return AuditEngine(alice.send).audit(
        req, checks=(check,), insertion_kinds=(InsertionKind.QUERY_VALUE,))


def test_idor_confirmed_on_vulnerable_app() -> None:
    with _app("vuln") as base:
        findings = _run(base, _idor_check(base))
        idor = [f for f in findings if f.bug_class == "idor"]
        assert idor, "cross-tenant read was not confirmed on the vulnerable app"
        assert idor[0].confirmed_by == "achieved_state" and idor[0].param == "id"


def test_idor_not_confirmed_when_authz_enforced() -> None:
    with _app("secure") as base:
        findings = _run(base, _idor_check(base))
        assert findings == [], "IDOR falsely confirmed against an app that enforces object authz"


def test_idor_lead_when_reflected_token_in_same_shape_baseline() -> None:
    # A SECURED app that reads NOTHING private but echoes the object's public slug into a 200 soft-deny.
    # alice AND carol get the SAME-SHAPE soft-deny, so the reflected slug appears in carol's baseline too:
    # clause (c) fails and the reflected token can NOT mint (a LEAD, never a FACT).
    with _app("reflect_same_shape") as base:
        findings = _run(base, _idor_check(base, discriminator=_slug("2")))
        assert findings == [], "a reflected per-object token in a same-shape baseline falsely minted a FACT"


def test_idor_lead_when_unauth_baseline_is_a_denial() -> None:
    # THE ROUND-4 HOLE: alice's same-tenant soft-deny reflects the slug; carol's cross-tenant read is a HARD
    # 403 that never renders the object, so the slug is absent from it VACUOUSLY. Round-5 refuses a denial as a
    # clause-(c) control (it is not a substantive same-shape read), so this stays a LEAD — the durable false
    # FACT the previous round would have minted.
    with _app("reflect_deny_baseline") as base:
        findings = _run(base, _idor_check(base, discriminator=_slug("2")))
        assert findings == [], "a reflected slug + a non-rendering 403 baseline falsely minted a FACT (round-4 hole)"


def test_idor_lead_without_unauth_baseline() -> None:
    # No unauthorized-authenticated baseline supplied ⇒ the class fails closed to a LEAD even on the
    # genuinely-vulnerable app (the enforced round-4/5 boundary — no same-ref baseline, no achieved-read FACT).
    with _app("vuln") as base:
        findings = _run(base, _idor_check(base, with_unauth=False))
        assert findings == [], "a cross-read without an unauthorized-authenticated baseline must be a LEAD"


# ---------------------------------------------------------------------------
# DURABLE offline re-verification: the retained (evidence, predicate) must re-fire for a
# genuine same-shape achieved read and REFUSE both a reflected-token same-shape baseline
# and — decisively — a reflected-token DENIAL (different-shape) baseline (the round-4 hole).
# The predicate AST is what a signed certificate carries, so re-running it offline is the
# durable check; no false FACT may survive it in ANY supported config.
# ---------------------------------------------------------------------------

def _mock_send(bodies: dict) -> "callable":
    """A Send returning a canned (status, body) keyed on the request's ``id`` query value."""
    def send(req: HttpRequest) -> dict:
        did = urllib.parse.parse_qs(urllib.parse.urlsplit(req.url).query).get("id", [""])[0]
        status, body = bodies[did]
        return {"status": status, "body": body}
    return send


def _genuine_probe_context():
    """Drive IdorCheck.probe over a GENUINE same-shape achieved read and return its retained
    (observed_evidence, predicate) — the durable certificate artifact."""
    from framework.v2.scanner.insertion import RequestTemplate

    disc = "bob-medical-record"
    tmpl = RequestTemplate(HttpRequest(method="GET", url="http://t/document?id=2"))
    point = next(p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "id")
    attacker = _mock_send({"2": (200, f"doc 2 owner=bob {_slug('2')} secret={disc}"),
                           "1": (200, f"doc 1 owner=alice {_slug('1')} secret=alice-tax-return")})
    victim = _mock_send({"2": (200, f"doc 2 owner=bob {_slug('2')} secret={disc}")})
    nocred = _mock_send({"2": (401, "please log in")})
    # carol: SAME-SHAPE 200 render of the same object with the private body withheld.
    unauth = _mock_send({"2": (200, f"doc 2 owner=bob {_slug('2')} secret=[restricted]")})
    check = IdorCheck(id="idor-doc", ref_param="id", victim_ref="2", victim_send=victim,
                      victim_discriminator=disc, control_ref="1", nocred_send=nocred, unauth_send=unauth)
    ctx = check.probe(tmpl, point, attacker)
    assert ctx is not None, "the genuine same-shape achieved read did not build a context"
    return ctx.observed_evidence, ctx.predicate


def test_idor_durable_offline_reverify_fires_genuine_and_refuses_reflected() -> None:
    from framework.v2.verify.oracles import predicate_oracle

    evidence, predicate = _genuine_probe_context()

    # 1. the genuine same-shape achieved read RE-FIRES offline over its retained certificate.
    assert predicate_oracle(evidence, predicate).fired, "genuine achieved-read did not re-verify offline"

    # 2. a DURABLE certificate forged with a reflected-token + DIFFERENT-SHAPE 403 baseline (the round-4
    #    hole) is REFUSED offline: the unauth substantive-same-shape clause fails on a 403 status. The
    #    discriminator here is the reflected per-object slug (present in the attacker's + owner's reads).
    slug = _slug("2")
    reflected_403 = {
        "attacker_status": 200, "victim_status": 200, "attacker_own_status": 200,
        "nocred_status": 401, "unauth_status": 403,
        "victim_body": f"doc 2 owner=bob {slug} secret=bob-medical-record",
        "attacker_body": f"you cannot open {slug} - please request access from the owner",
        "attacker_own_body": f"doc 1 owner=alice {_slug('1')} secret=alice-tax-return",
        "nocred_body": "please log in",
        "unauth_body": "cross-tenant read blocked",  # a 403 that never rendered the object => no slug
        "victim_ref": "2", "discriminator": slug,
    }
    assert not predicate_oracle(reflected_403, predicate).fired, (
        "DURABLE false FACT: a reflected token + a non-rendering 403 baseline re-fired offline (round-4 hole)")

    # 3. a reflected-token SAME-SHAPE 200 baseline is ALSO refused: the slug appears in the baseline too.
    reflected_same_shape = dict(reflected_403)
    reflected_same_shape["unauth_status"] = 200
    reflected_same_shape["unauth_body"] = f"you cannot open {slug} - please request access from the owner"
    assert not predicate_oracle(reflected_same_shape, predicate).fired, (
        "a reflected token echoed into the same-shape baseline re-fired offline")
