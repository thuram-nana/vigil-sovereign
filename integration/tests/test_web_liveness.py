"""HexStrike W2 — endpoint response-DISTINGUISHABILITY (historical id ``achieved_state.endpoint_liveness``;
the L7 analogue of the TCP tcp_handshake reachability FACT).

NARROWED CLAIM (after three red-pen BLOCKs): the FACT asserts EXACTLY that VIGIL's own gated GET served
content DISTINGUISHABLE from the server's own stable, SAME-BRANCH response to randomized same-shape siblings —
never "live endpoint"/"real"/"exists". A web-discovery tool (httpx / ffuf) PROPOSES a URL; VIGIL re-drives it
with its OWN plain gated GETs (the target resampled + many DISTINCT NARROW-CLASS same-shape controls, each
resampled) and the EXISTING ACHIEVED_STATE predicate_oracle mints only when the target is a stable 2xx/3xx, at
least the floor of controls answered in the TARGET'S OWN response branch with one shared body-hash, every
DISCARDED control is proven off-branch, no control is ambiguous, and the target's body differs from that
same-branch baseline. The proofs are genuinely live: real loopback HTTP servers.

Headline properties (each FP class below minted a FALSE offline-re-verifiable FACT on some pre-fix HEAD):
  * a really-distinguishable URL → a signed FACT that re-verifies OFFLINE, and tamper is rejected;
  * a tool-claimed-but-UNREACHABLE URL → a LEAD (deceptive_no_fact — the tool's say-so never confirms);
  * every soft-404 CLASS is a LEAD: uniform blanket-200, path-echo, numeric-route (RP1), length/shape
    signature (RP1), HEX-route + UUID-route narrow-class route-miss (RP2), a bounded per-request body space
    (RP2), and CHECKSUM/validation routes — Luhn card + base58, with the validation-reject on a hard 404, a
    distinct-body 404 AND (the worst case) a 200 INSIDE the target's own status branch — closed by the
    SAME-BRANCH baseline plus VALIDATOR-AWARE controls (RP3), each proven over 80 runs (no intermittency);
    a strict UNKNOWN validator with < floor in-branch controls fails closed;
  * the one class that CANNOT be closed by any same-class observation — an UNKNOWN app-specific validator
    that rejects INSIDE the target's own status branch — is pinned as the branch's documented residual, with
    the proof of its irreducibility (it is byte-identical to the legitimate case this FACT exists for);
  * a special-cased error page is a TRUE-if-modest NARROWED FACT, never a "live endpoint" overclaim (RP2 BLOCK-3);
  * a channel-confirmed hard 404 → a CLEAN bounded to the EXACT probed URL, never an enumeration claim;
  * a root/directory or ambiguous-class segment FAILS CLOSED to a LEAD;
  * httpx + ffuf each PASS the full conformance battery through the REAL gated runner; the two operator
    surfaces (capability matrix + the body's oracle-mapped set) AGREE.

Offense-process test (loads framework.* + vigil_integration.live.*): CI runs it in the offense group.
"""
from __future__ import annotations

import http.server
import json
import re
import threading
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
pytest.importorskip("vigil_gateway", reason="vigil_gateway (gated transport) not importable here")


# ---- gate isolation + charter (mirrors test_web_redrive / test_conformance) -----------------------
@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-09-25`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


# ---- loopback web apps: a CORRECT server (404s the unknown) and a SOFT-404 server (200s EVERYTHING) -
class _CorrectApp(http.server.BaseHTTPRequestHandler):
    """Serves 200 for /live and /, 404 for every other path (including the random liveness control) — a
    server that correctly distinguishes a real resource from a nonexistent one."""

    def log_message(self, *a):  # noqa: D401 — silence the test server
        pass

    def do_GET(self):  # noqa: N802
        if self.path in ("/live", "/"):
            body = b"<html><body>a real, live resource</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"<html><body>404 not found</body></html>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class _SoftNotFoundApp(http.server.BaseHTTPRequestHandler):
    """The TRIVIAL soft-404 trap: answers 200 with the SAME 'not found' page for EVERY path (uniform body,
    no path echo). Target and same-shape controls share status+body, so the re-drive must mint NO fact."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        body = b"<html><body>Sorry, that page was not found.</body></html>"   # UNIFORM — no path echo
        self.send_response(200)                       # <-- 200 for a nonexistent page: the soft-404 lie
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _PathEchoSoftApp(http.server.BaseHTTPRequestHandler):
    """A soft-404 that ECHOES the requested path in its 200 body. A single control would look 'different' from
    the target and false-FACT; the two same-shape controls echo DIFFERENT paths, so no stable baseline forms."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        body = f"<html><body>Sorry, page {self.path} was not found.</body></html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_NUMERIC_ROUTE = re.compile(r"^/api/users/(\d+)/?$")


class _NumericRouteSoftApp(http.server.BaseHTTPRequestHandler):
    """FP1 — a numeric-ID REST route (Django <int:pk> / Rails /:id(\\d+) / Express :id(\\d+)): 200 for ANY
    numeric user id (even a nonexistent one — the soft-404 lie {"user": null}), 404 for a non-numeric segment
    (the route does not match). A DISTINCTIVE non-numeric control 404s while a nonexistent numeric target 200s
    -> the old status-only predicate false-FACTed. A SAME-SHAPE numeric control also matches the route -> 200
    {"user": null} == the target's body -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if _NUMERIC_ROUTE.match(path):
            body, code = b'{"user": null}', 200        # nonexistent numeric id STILL 200s (soft-404)
        else:
            body, code = b'{"error": "not found"}', 404
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _NumericRouteLiveApp(http.server.BaseHTTPRequestHandler):
    """The NON-REGRESSION twin of _NumericRouteSoftApp: /api/users/1 is a REAL user (distinct body), every
    other numeric id is the soft-404 {"user": null}. A same-shape numeric control 200s with {"user": null},
    but the target /api/users/1 body DIFFERS -> the body differential still mints a FACT for the live id."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = _NUMERIC_ROUTE.match(self.path.split("?")[0])
        if m and m.group(1) == "1":
            body, code = b'{"user": {"id": 1, "name": "alice"}}', 200
        elif m:
            body, code = b'{"user": null}', 200
        else:
            body, code = b'{"error": "not found"}', 404
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _LengthSignatureApp(http.server.BaseHTTPRequestHandler):
    """FP2 — a blanket-200 soft-404 whose ONLY 404 is a WAF/edge rule that blocks any last path segment longer
    than 20 chars (long/high-entropy = 'suspicious'), equivalently a signature block on a fixed control prefix.
    The old fixed 39-char `vigil-liveness-<hex>` control was 404'd while the short target 200'd -> false FACT.
    A SAME-LENGTH control (e.g. 5 chars for /admin) is under the limit -> 200 == target -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        seg = self.path.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
        if len(seg) > 20:
            body, code = b"blocked", 404               # the edge/WAF 404s the long/high-entropy segment
        else:
            body, code = b"<html>page not found (but 200)</html>", 200   # blanket soft-404 for normal paths
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_HEX_ROUTE = re.compile(r"^/token/[0-9a-f]+/?$")


class _HexRouteSoftApp(http.server.BaseHTTPRequestHandler):
    """RP2 BLOCK-1 — a HEX-id route: 200 soft-404 ({"token":null}) for ANY well-formed hex token (nothing is
    live), 404 for a NON-hex segment (route miss). The pre-fix coarse alnum mirror produced non-hex controls
    that 404'd as route-misses while a nonexistent hex target 200'd -> a false FACT (20/20). A NARROW-CLASS
    hex control (dead1234-shaped) also matches the route -> 200 == target -> LEAD; an ambiguous all-a-f target
    (deadbeef) fails closed -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        p = self.path.split("?")[0]
        body, code = (b'{"token":null}', 200) if _HEX_ROUTE.match(p) else (b'{"error":"not found"}', 404)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_UUID_ROUTE = re.compile(r"^/r/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/?$")


class _UuidRouteSoftApp(http.server.BaseHTTPRequestHandler):
    """RP2 BLOCK-1 — a UUID route: 200 soft-404 ({"obj":null}) for ANY well-formed UUID (nothing is live),
    404 for a non-UUID segment. Needs a control that preserves the dash STRUCTURE + hex; a coarse alnum control
    404s as a route miss (false FACT, pre-fix)."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        p = self.path.split("?")[0]
        body, code = (b'{"obj":null}', 200) if _UUID_ROUTE.match(p) else (b'nf', 404)
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _BoundedBodySoftApp(http.server.BaseHTTPRequestHandler):
    """RP2 BLOCK-2 — a soft-404 whose not-found body is one of a SMALL (2-element) set, chosen at RANDOM PER
    REQUEST. NOTHING is live. With only two controls they collide on one body ~1/2 of the time -> a spurious
    'stable baseline' the target differs from -> an INTERMITTENT false FACT (pre-fix). Multi-sampling (many
    distinct controls, each resampled, ALL must agree) fails to find a stable baseline here -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        import random
        body = random.choice([b'{"m":"A"}', b'{"m":"B"}'])
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_NUMERIC_ROUTE_B3 = re.compile(r"^/api/users/(\d+)/?$")


class _NumericRouteErrApp(http.server.BaseHTTPRequestHandler):
    """RP2 BLOCK-3 — a special-cased ERROR: /api/users/0 -> 200 {"error":"invalid id"} while any other numeric
    id -> 200 {"user":null} (the not-found baseline). Under the NARROWED claim this is a TRUE-if-modest FACT
    ("served content distinguishable from a same-shape not-found baseline"), NOT a "live endpoint" overclaim —
    the fix is the claim string, checked by the test."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = _NUMERIC_ROUTE_B3.match(self.path.split("?")[0])
        if m and m.group(1) == "0":
            body, code = b'{"error":"invalid id"}', 200
        elif m:
            body, code = b'{"user":null}', 200
        else:
            body, code = b'nf', 404
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SoftLiveApp(http.server.BaseHTTPRequestHandler):
    """A SOFT-404-style server with a REAL endpoint: /live serves distinct real content; every other
    well-formed same-shape sibling soft-404s 200 with a uniform not-found body. The same-branch baseline
    (the 200 soft-404 body) is in the target's OWN served branch, and /live's real body differs -> FACT.
    This is the scenario the narrowed FACT is FOR (a hard-404 server yields no served baseline -> LEAD)."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        body = (b"<html><body>the real, distinct live resource</body></html>" if self.path == "/live"
                else b"<html><body>soft 404 not-found body</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _luhn_ok(num: str) -> bool:
    if not num.isdigit():
        return False
    digits = [int(c) for c in num][::-1]
    total = 0
    for i, x in enumerate(digits):
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        total += x
    return total % 10 == 0


def _make_luhn16() -> str:
    import random
    base = [random.randint(0, 9) for _ in range(15)]
    for c in range(10):
        cand = "".join(map(str, base)) + str(c)
        if _luhn_ok(cand):
            return cand
    raise AssertionError("unreachable")


class _LuhnHardApp(http.server.BaseHTTPRequestHandler):
    """RP3 — a Luhn-checksum card route: a Luhn-VALID (even nonexistent) 16-digit id -> 200 {"card":null}
    (soft-404); a Luhn-INVALID id -> HARD 404 (a validation-reject, a DIFFERENT response branch). Random
    same-digit controls mostly fail Luhn -> 404; when they ALL 404 the old predicate distinguished the
    valid-nonexistent target (200) from that 404 'baseline' -> FALSE FACT (~37%). Same-branch baseline
    discards the 404 validation-rejects -> < floor served controls -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = re.match(r"^/card/(\d{16})/?$", self.path.split("?")[0])
        body, code = (b'{"card":null}', 200) if (m and _luhn_ok(m.group(1))) else (b"not found", 404)
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _LuhnSoftApp(http.server.BaseHTTPRequestHandler):
    """RP3 — the Luhn route with a 200-vs-404 validation-reject that carries a DISTINCT body: Luhn-valid
    nonexistent -> 200 {"card":null}; Luhn-invalid -> 404 {"error":"invalid card"}. Same-branch baseline
    still discards the 404 branch -> < floor served controls -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = re.match(r"^/card/(\d{16})/?$", self.path.split("?")[0])
        body, code = (b'{"card":null}', 200) if (m and _luhn_ok(m.group(1))) else (b'{"error":"invalid card"}', 404)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_B58 = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")   # excludes 0 O I l


class _Base58App(http.server.BaseHTTPRequestHandler):
    """RP3 — a base58-id route: a base58-VALID (nonexistent) id -> 200 {"obj":null}; a base58-INVALID id
    (contains 0/O/I/l — which the alnum mirror emits) -> 404 {"error":"bad id"}. Same-branch baseline discards
    the 404 validation-rejects -> < floor served controls -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = re.match(r"^/obj/([0-9A-Za-z]+)/?$", self.path.split("?")[0])
        ok = bool(m) and all(c in _B58 for c in m.group(1))
        body, code = (b'{"obj":null}', 200) if ok else (b'{"error":"bad id"}', 404)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Luhn200RejectApp(http.server.BaseHTTPRequestHandler):
    """RP3, the WORST checksum variant — the validation-reject lives INSIDE the target's own status branch:
    a Luhn-INVALID id -> 200 {"error":"invalid card number"}; a Luhn-VALID (nonexistent) id -> 200
    {"card":null}. The same-branch classifier alone cannot save this (every control IS in the 200 branch and
    they agree on the reject body, which the nonexistent target differs from -> a false FACT ~35% of runs).
    It is closed by the OTHER half of the RP3 fix: VALIDATOR-AWARE controls. Every control is required to
    satisfy each well-known validator the TARGET satisfies, so the controls are Luhn-valid, the baseline is
    the route's TRUE not-found body {"card":null}, and the target MATCHES it -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = re.match(r"^/card/(\d{16})/?$", self.path.split("?")[0])
        if not m:
            body, code = b"nf", 404
        elif _luhn_ok(m.group(1)):
            body, code = b'{"card":null}', 200         # valid but NONEXISTENT — the true not-found body
        else:
            body, code = b'{"error":"invalid card number"}', 200   # the reject, IN the target's own branch
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Base58_200RejectApp(http.server.BaseHTTPRequestHandler):
    """RP3 — the base58 twin of _Luhn200RejectApp: the reject is a 200 inside the target's own branch, so only
    VALIDATOR-AWARE controls (drawn without 0/O/I/l) reach the route's true not-found body."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = re.match(r"^/obj/([0-9A-Za-z]+)/?$", self.path.split("?")[0])
        if not m:
            body, code = b"nf", 404
        elif all(c in _B58 for c in m.group(1)):
            body, code = b'{"obj":null}', 200
        else:
            body, code = b'{"error":"bad id"}', 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _UnknownValidator200RejectApp(http.server.BaseHTTPRequestHandler):
    """RP3 RESIDUAL (documented, IRREDUCIBLE). An APP-SPECIFIC validator VIGIL cannot know — an id must start
    with "ZQ" — whose reject lives INSIDE the target's own status branch: /item/<10 alnum> -> 200
    {"item":null} when it starts with ZQ (the true not-found body), else 200 {"error":"bad"}.

    No same-class observation can separate this from _SoftLiveApp (a REAL endpoint whose same-shape siblings
    all soft-404 with one uniform body): in BOTH, ten same-shape controls answer 200 with one shared body and
    the target answers 200 with a different one. The captures are byte-identical in structure, so any rule
    that LEADs here also LEADs on the legitimate case the FACT exists for. The honest handling is therefore
    (a) mint only the narrowed claim the capture actually proves, (b) name this residual in the FACT note
    itself, and (c) pin it in the branch's limitations — all asserted by the residual test below."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = re.match(r"^/item/([0-9A-Za-z]{10})/?$", self.path.split("?")[0])
        if not m:
            body, code = b"nf", 404
        else:
            body, code = ((b'{"item":null}', 200) if m.group(1).startswith("ZQ")
                          else (b'{"error":"bad"}', 200))
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _StrictValidatorApp(http.server.BaseHTTPRequestHandler):
    """RP3 — a validator so strict that almost no random same-shape control passes: /item/<3 digits> serves
    200 {"item":null} ONLY for ids < 10 (i.e. 000..009 of the 1000 possible), else 404. A random 3-digit
    control is valid ~1% of the time, so < floor land in the target's served branch -> FAIL CLOSED to a LEAD
    (not a crash), even for a served valid-nonexistent target like /item/005."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = re.match(r"^/item/(\d{3})/?$", self.path.split("?")[0])
        served = bool(m) and int(m.group(1)) < 10
        body, code = (b'{"item":null}', 200) if served else (b"not found", 404)
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _partially_varying_app():
    """RP3 hardening — a bounded not-found body space {A,B} that is STABLE for MOST same-shape siblings and
    VARIES per request for the rest. NOTHING is live: the target's body is simply the OTHER element of the
    not-found space, served deterministically.

    This is the trap that "classify each control, DISCARD the ones that did not land in the target's branch"
    walks into if instability counts as off-branch: drop the 3 varying controls and the 7 stable ones look
    like a unanimous baseline (A) that the stable target (B) "differs" from -> a FALSE FACT for a nonexistent
    URL. The rule must be that a control which is unstable INSIDE the target's own status branch is AMBIGUOUS
    and fails the whole run closed. Arrival-indexed (not random) so the mix is deterministic: every 3rd
    distinct path varies. The target segment is 'wxyz' — deliberately NOT all-a-f, whose class is
    AMBIGUOUS (both lower-alpha and lower-hex) and would fail closed before a single control was even
    fetched, making the test pass for the wrong reason."""
    state: dict = {}

    class _App(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # noqa: D401
            pass

        def do_GET(self):  # noqa: N802
            import random
            path = self.path.split("?")[0]
            idx = state.setdefault(path, len(state))
            if path == "/x/wxyz":
                body = b'{"m":"B"}'                                   # the (nonexistent) TARGET: stable
            elif idx % 3 == 0:
                body = random.choice([b'{"m":"A"}', b'{"m":"B"}'])    # a VARYING control
            else:
                body = b'{"m":"A"}'                                   # a stable control
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _App


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


# ---- canned tool backends (the tool is only a PROPOSER; VIGIL's own gated GET is the fact authority) ---
class _CannedBackend:
    """Returns a fixed stdout for ANY argv — supplies a tool's real-format proposal with no binary present."""
    name = "canned"

    def __init__(self, stdout: str) -> None:
        self._stdout = stdout

    def available(self):
        return True, "canned"

    def run(self, argv, *, timeout=0):
        from vigil_integration.live.external_tool import ToolOutcome
        return ToolOutcome(list(argv), 0, self._stdout, "", self.name)


def _httpx_jsonl(url: str) -> str:
    return json.dumps({"url": url, "input": url, "status_code": 200, "failed": False}) + "\n"


def _ffuf_report(url: str) -> str:
    return json.dumps({"results": [{"input": {"FUZZ": "live"}, "status": 200, "url": url,
                                    "host": "127.0.0.1"}], "config": {}})


def _scope_gate(hosts):
    from vigil_gateway.scope_source import StaticScopeSource
    from vigil_integration.live.external_tool import ScopeGate
    return ScopeGate(scope=StaticScopeSource(list(hosts)), loopback_allowed_if_scoped=True)


# ===================================================================================================
# The direct re-drive proofs (the endpoint_liveness_redrive itself).
# ===================================================================================================
def test_live_url_mints_a_signed_liveness_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, tr = _signers_and_trust()
    srv = _serve(_SoftLiveApp)          # /live real content; siblings soft-404 200 (the SAME served branch)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.is_fact, f"expected a distinguishability FACT; outcome={wl.outcome} note={wl.note}"
    # the baseline is the SAME served branch (200 soft-404); the target's real body differs.
    assert wl.outcome == "positive" and wl.target_status == 200 and wl.control_statuses == [200]
    assert wl.same_branch_controls >= 4
    low = wl.note.lower()
    assert "distinguishable" in low and "not a claim that the endpoint is 'live'" in low  # NARROWED claim
    assert "same-branch" in low
    # the FACT re-verifies OFFLINE from the retained JSON-safe capture — no network, no VIGIL runner
    assert verify_certificate(wl.fact.signed, oracle_context=wl.context, trust_root=tr).ok is True


def test_liveness_fact_is_rejected_when_the_retained_context_is_tampered(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, tr = _signers_and_trust()
    srv = _serve(_SoftLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.is_fact
    # flip the target's body-hash to match the baseline in the retained context: it would NO LONGER be
    # distinguishable — the cert bound the original context, so verify must FAIL.
    tampered = json.loads(json.dumps(wl.context))
    tampered["observed_evidence"]["target_0_sha"] = tampered["observed_evidence"]["control_0_sha"]
    assert verify_certificate(wl.fact.signed, oracle_context=tampered, trust_root=tr).ok is False


# Every soft-404 / phantom CLASS all three red-pens raised. Each mints a FALSE offline-re-verifiable FACT on
# some pre-fix HEAD; each must be a LEAD after the fix. (RP1: uniform, path-echo, numeric-route, length-sig.
# RP2: hex-route, uuid-route, bounded per-request body. RP3: Luhn hard-404, Luhn soft-reject, base58 — the
# checksum/validation-route class the SAME-BRANCH baseline closes.)
_SOFT_404_CLASSES = [
    (_SoftNotFoundApp, "/anything", "uniform blanket-200"),
    (_PathEchoSoftApp, "/anything", "path-echoing 200"),
    (_NumericRouteSoftApp, "/api/users/999999999", "numeric-route soft-404 (RP1)"),
    (_LengthSignatureApp, "/admin", "length/shape-signature 404 (RP1)"),
    (_HexRouteSoftApp, "/token/dead1234", "hex-route soft-404 (RP2)"),
    (_HexRouteSoftApp, "/token/deadbeef", "hex-route ambiguous-class fail-closed (RP2)"),
    (_UuidRouteSoftApp, "/r/550e8400-e29b-41d4-a716-446655440000", "uuid-route soft-404 (RP2)"),
    (_BoundedBodySoftApp, "/admin", "bounded per-request 2-elt body (RP2)"),
    (_LuhnHardApp, "/card/4111111111111111", "Luhn checksum route, hard-404 reject (RP3)"),
    (_LuhnSoftApp, "/card/4111111111111111", "Luhn checksum route, distinct-body reject (RP3)"),
    (_Base58App, "/obj/3vQB7fMrk9xZa5dCFg2h", "base58 checksum route (RP3)"),
    (_Luhn200RejectApp, "/card/4111111111111111", "Luhn route, reject INSIDE the target's branch (RP3)"),
    (_Base58_200RejectApp, "/obj/3vQB7fMrk9xZa5dCFg2h", "base58 route, reject INSIDE the branch (RP3)"),
    (_StrictValidatorApp, "/item/005", "strict validator, < floor valid controls (RP3 fail-closed)"),
]


@pytest.mark.parametrize("app,path,label", _SOFT_404_CLASSES)
def test_soft_404_classes_mint_no_liveness_fact(app, path, label, monkeypatch, tmp_path):
    """Every soft-404 / phantom CLASS both red-pens raised must be a LEAD, never a FACT."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(app)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}{path}",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact, f"{label}: must NOT mint a FACT (got {wl.outcome}, {wl.note})"
    assert wl.outcome == "inconclusive" and wl.lead is not None and not wl.lead.is_fact


def test_bounded_body_soft_404_is_never_a_fact_over_80_runs(monkeypatch, tmp_path):
    """RP2 BLOCK-2 intermittency: the per-request 2-element body-space soft-404 minted an INTERMITTENT false
    FACT (~30% with 2 controls). Multi-sampling must drive it to ZERO — run it 80x and require 0 false FACTs
    (an intermittent false FACT is still a false FACT)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_BoundedBodySoftApp)
    port = srv.server_address[1]
    facts = 0
    try:
        for _ in range(80):
            wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/admin",
                                           slug="alpha", engagement_slug="alpha", signers=signers)
            if wl.is_fact:
                facts += 1
    finally:
        srv.shutdown()
    assert facts == 0, f"bounded-body soft-404 minted {facts}/80 false FACTs — multi-sampling did not close it"


@pytest.mark.parametrize("app,pathfn,label", [
    (_LuhnHardApp, _make_luhn16, "Luhn hard-404 reject"),
    (_LuhnSoftApp, _make_luhn16, "Luhn distinct-body reject"),
    (_Luhn200RejectApp, _make_luhn16, "Luhn 200 reject INSIDE the branch"),
    (_Base58App, lambda: "3vQB7fMrk9xZa5dCFg2h", "base58"),
    (_Base58_200RejectApp, lambda: "3vQB7fMrk9xZa5dCFg2h", "base58 200 reject INSIDE the branch"),
])
def test_checksum_routes_never_mint_a_fact_over_80_runs(app, pathfn, label, monkeypatch, tmp_path):
    """RP3 intermittency: a checksum/validation route (Luhn ~37%, base58 ~7%) minted an INTERMITTENT false
    FACT when random controls all validation-rejected (a 404 branch the valid-nonexistent 200 target was
    'distinguished' from). The SAME-BRANCH baseline must drive it to ZERO — run 80x, require 0 false FACTs."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(app)
    port = srv.server_address[1]
    facts = 0
    prefix = "/obj/" if app in (_Base58App, _Base58_200RejectApp) else "/card/"
    try:
        for _ in range(80):
            wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}{prefix}{pathfn()}",
                                           slug="alpha", engagement_slug="alpha", signers=signers)
            if wl.is_fact:
                facts += 1
    finally:
        srv.shutdown()
    assert facts == 0, f"{label} checksum route minted {facts}/80 false FACTs — same-branch baseline failed"


def test_checksum_route_leads_for_the_RIGHT_reason_target_matches_the_true_not_found_baseline(
        monkeypatch, tmp_path):
    """RP3, the capability half. It is not enough that a checksum route fails CLOSED below the floor — the
    VALIDATOR-AWARE controls must actually land in the route's ACCEPTED set, so the baseline is the route's
    TRUE not-found response and the checksum-valid-but-nonexistent target is seen to MATCH it. Assert the
    reason, not just the absence of a FACT: a full in-branch baseline formed, and the target's body equals
    it. (Without validator-aware controls the same-branch count here is ~1 and the note is the floor one.)"""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _MIN_LIVENESS_CONTROLS, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    for app, path in ((_LuhnHardApp, "/card/" + _make_luhn16()),
                      (_LuhnSoftApp, "/card/" + _make_luhn16()),
                      (_Luhn200RejectApp, "/card/" + _make_luhn16()),
                      (_Base58App, "/obj/3vQB7fMrk9xZa5dCFg2h"),
                      (_Base58_200RejectApp, "/obj/3vQB7fMrk9xZa5dCFg2h")):
        srv = _serve(app)
        port = srv.server_address[1]
        try:
            wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}{path}",
                                           slug="alpha", engagement_slug="alpha", signers=signers)
        finally:
            srv.shutdown()
        assert not wl.is_fact, f"{app.__name__}: minted a FACT for a checksum-valid PHANTOM ({wl.note})"
        assert wl.same_branch_controls >= _MIN_LIVENESS_CONTROLS, (
            f"{app.__name__}: validator-aware controls must land IN the route's accepted set "
            f"(got {wl.same_branch_controls} in-branch) — the route was only refused by the floor")
        assert "matches the same-branch not-found baseline" in wl.note.lower(), wl.note


def test_validator_aware_controls_satisfy_every_validator_the_target_satisfies():
    """The controls a checksum route would otherwise validation-reject must satisfy the SAME well-known
    validator the target does (Luhn / base58 / UUIDv4) — and a segment the validator does not meaningfully
    apply to (a single digit like /api/users/0) must NOT be narrowed, or the non-regression cases starve."""
    from vigil_integration.live.web_redrive import (_liveness_control_urls, _luhn_valid, _MIN_LIVENESS_CONTROLS,
                                                    _base58_valid, _uuid_v4_valid)
    luhn = _make_luhn16()
    seg = lambda u: u.rsplit("/", 1)[-1]  # noqa: E731
    cs = _liveness_control_urls(f"http://h/card/{luhn}")
    assert len(cs) >= _MIN_LIVENESS_CONTROLS and all(_luhn_valid(seg(u)) for u in cs), cs
    assert all(seg(u) != luhn for u in cs) and len({seg(u) for u in cs}) == len(cs)
    cs = _liveness_control_urls("http://h/obj/3vQB7fMrk9xZa5dCFg2h")
    assert len(cs) >= _MIN_LIVENESS_CONTROLS and all(_base58_valid(seg(u)) for u in cs), cs
    cs = _liveness_control_urls("http://h/r/550e8400-e29b-41d4-a716-446655440000")
    assert len(cs) >= _MIN_LIVENESS_CONTROLS and all(_uuid_v4_valid(seg(u)) for u in cs), cs
    # a 1-digit id is not card/IMEI-shaped: Luhn must NOT be inferred from the coincidence that "0" sums to 0.
    cs = _liveness_control_urls("http://h/api/users/0")
    assert len(cs) >= _MIN_LIVENESS_CONTROLS and any(not _luhn_valid(seg(u)) for u in cs), cs


def test_a_control_unstable_inside_the_targets_own_branch_fails_the_run_closed(monkeypatch, tmp_path):
    """A bounded not-found body space that is stable for MOST siblings and varies for the rest: discarding
    the varying controls would leave a unanimous FLUKE baseline the (nonexistent) target differs from — a
    false FACT. An unstable control inside the target's own status branch is AMBIGUOUS and fails the whole
    run closed. 20 runs, 0 FACTs."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    facts, notes = 0, []
    for _ in range(20):
        srv = _serve(_partially_varying_app())
        port = srv.server_address[1]
        try:
            wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/x/wxyz",
                                           slug="alpha", engagement_slug="alpha", signers=signers)
        finally:
            srv.shutdown()
        facts += 1 if wl.is_fact else 0
        notes.append(wl.note)
    assert facts == 0, f"a fluke baseline from unstable controls minted {facts}/20 false FACTs: {notes[:2]}"
    assert any("ambiguous" in n.lower() for n in notes), notes[:2]


def test_the_certificate_binds_same_branch_membership(monkeypatch, tmp_path):
    """The partition is part of the PROOF: flip a retained in-branch control's status away from the target's
    and the certificate must FAIL to re-verify (the baseline is no longer in the target's branch)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, tr = _signers_and_trust()
    srv = _serve(_SoftLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.is_fact
    tampered = json.loads(json.dumps(wl.context))
    tampered["observed_evidence"]["control_0_status"] = 404      # pretend the baseline was a 404 reject
    assert verify_certificate(wl.fact.signed, oracle_context=tampered, trust_root=tr).ok is False


def test_the_predicate_proves_the_partition_and_refuses_a_cherry_picked_one():
    """The generated AST must prove the WHOLE in/off-branch partition offline, so a runner cannot present a
    cherry-picked baseline: (a) an honest partition fires; (b) calling a control OFF-branch when it carried
    the target's status does not; (c) an in-branch control whose body differs from the anchor does not;
    (d) a partition with no in-branch control does not (the anchor var is absent)."""
    from framework.v2.verify.oracles import predicate_oracle
    from vigil_integration.live.web_redrive import _MIN_LIVENESS_CONTROLS, _build_liveness_predicate

    n_in = _MIN_LIVENESS_CONTROLS
    in_blocks = [[2 * k, 2 * k + 1] for k in range(n_in)]
    off_blocks = [[2 * n_in, 2 * n_in + 1]]
    ev = {"target_0_status": 200, "target_0_sha": "REAL", "target_1_status": 200, "target_1_sha": "REAL",
          "target_2_status": 200, "target_2_sha": "REAL", "same_branch_controls": n_in}
    for b in in_blocks:
        for k in b:
            ev[f"control_{k}_status"], ev[f"control_{k}_sha"] = 200, "NOTFOUND"
    for k in off_blocks[0]:
        ev[f"control_{k}_status"], ev[f"control_{k}_sha"] = 404, "REJECT"
    pred = _build_liveness_predicate(in_blocks, off_blocks, 3, _MIN_LIVENESS_CONTROLS)
    assert predicate_oracle(ev, pred).fired is True                      # (a)

    cherry = dict(ev)                                                    # (b) the "discarded" control was
    for k in off_blocks[0]:                                              #     really IN the target's branch
        cherry[f"control_{k}_status"] = 200
    assert predicate_oracle(cherry, pred).fired is False

    disagree = dict(ev)                                                  # (c)
    disagree[f"control_{in_blocks[-1][0]}_sha"] = "OTHER"
    assert predicate_oracle(disagree, pred).fired is False

    empty = _build_liveness_predicate([], off_blocks, 3, _MIN_LIVENESS_CONTROLS)   # (d)
    assert predicate_oracle({**ev, "same_branch_controls": 0}, empty).fired is False
    assert predicate_oracle({**ev, "same_branch_controls": 99}, empty).fired is False


def test_unknown_in_branch_validation_reject_is_the_documented_irreducible_residual(monkeypatch, tmp_path):
    """THE RESIDUAL, pinned honestly rather than hidden. An APP-SPECIFIC validator VIGIL cannot know, whose
    reject lives INSIDE the target's own status branch, produces a capture that is structurally IDENTICAL to
    the legitimate case this FACT exists for (a real endpoint whose same-shape siblings all soft-404 with one
    uniform body): same in-branch count, same off-branch count, target distinguishable by body. No rule over
    same-class observations can LEAD on one without LEADing on the other, so the honest handling is (1) the
    FACT states only the narrowed claim the capture proves and never 'live'/'real'/'exists', (2) the note
    names the residual, and (3) the branch's limitations record it. All three are asserted here."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()

    def _drive(app, path):
        srv = _serve(app)
        port = srv.server_address[1]
        try:
            return endpoint_liveness_redrive(f"http://127.0.0.1:{port}{path}",
                                             slug="alpha", engagement_slug="alpha", signers=signers)
        finally:
            srv.shutdown()

    residual = _drive(_UnknownValidator200RejectApp, "/item/ZQabcdefgh")
    legit = _drive(_SoftLiveApp, "/live")
    # (0) the two captures are structurally the same observation — the irreducibility itself.
    assert legit.is_fact and legit.same_branch_controls == residual.same_branch_controls
    if residual.is_fact:
        low = residual.note.lower()
        # (1) never an existence claim ...
        assert "not a claim that the endpoint is 'live'/real/exists" in low, residual.note
        # (2) ... and the residual is named in the FACT's own note.
        assert "residual:" in low and "same status branch" in low, residual.note
    # (3) the branch's limitation entry records the class.
    root = Path(__file__).resolve().parents[2]
    doc = json.loads((root / "docs" / "capability-matrix" / "evidence-branches.json").read_text())
    entry = next(b for b in doc["branches"] if b["id"] == "achieved_state.endpoint_liveness")
    lim = entry["limitation"].lower()
    assert "residual" in lim and "app-specific" in lim and "same status branch" in lim, entry["limitation"]
    assert "irreducible" in lim, entry["limitation"]


def test_block3_special_cased_error_is_a_true_narrowed_fact_not_an_overclaim(monkeypatch, tmp_path):
    """RP2 BLOCK-3: /api/users/0 serves a special-cased error DISTINGUISHABLE from the same-shape not-found
    baseline. Under the NARROWED claim this is a TRUE-if-modest FACT — but the claim must NOT say 'live
    endpoint' / 'real' / 'exists'. The fix is the claim string; assert it is honest."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, tr = _signers_and_trust()
    srv = _serve(_NumericRouteErrApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/api/users/0",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.is_fact, f"a distinguishable special-cased response is a narrowed FACT; got {wl.outcome} {wl.note}"
    assert verify_certificate(wl.fact.signed, oracle_context=wl.context, trust_root=tr).ok is True
    low = wl.note.lower()
    # the narrowed claim states 'distinguishable' and explicitly DISCLAIMS 'live'/'real' — no overclaim.
    assert "distinguishable" in low, "the narrowed claim must state 'distinguishable from a not-found baseline'"
    assert "not a claim that the endpoint is 'live'" in low, "the note must disclaim 'live'/'real'"


def test_numeric_route_live_id_still_mints_a_fact(monkeypatch, tmp_path):
    """NON-REGRESSION for the same-shape + body differential: a GENUINELY live numeric id (/api/users/1) is
    served 200 with a distinct body while a same-shape numeric control 200s with {"user": null}; the body
    differential distinguishes them, so the live id still mints a FACT that re-verifies OFFLINE."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, tr = _signers_and_trust()
    srv = _serve(_NumericRouteLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/api/users/1",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.is_fact, f"a genuinely-live numeric id must mint a FACT; outcome={wl.outcome} note={wl.note}"
    assert wl.control_statuses == [200]     # same-status baseline (distinct set); distinguished by the BODY diff
    assert verify_certificate(wl.fact.signed, oracle_context=wl.context, trust_root=tr).ok is True


def test_root_url_fails_closed_to_a_lead(monkeypatch, tmp_path):
    """A root/directory URL has no last segment to mirror into a same-shape control, so the liveness FACT
    FAILS CLOSED to a LEAD rather than mint over an unsound control."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _liveness_control_urls, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_CorrectApp)          # serves 200 at "/"
    port = srv.server_address[1]
    assert _liveness_control_urls(f"http://127.0.0.1:{port}/") == [], "root URL must yield no same-shape control"
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact and wl.outcome == "inconclusive"
    assert "no sound" in wl.note.lower() and "same-shape control" in wl.note.lower()


def test_hard_404_is_a_clean_bounded_to_the_exact_url(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_CorrectApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/definitely-not-here",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact
    assert wl.outcome == "clean" and wl.target_status == 404
    assert "bounded to the probed URL" in wl.note and "no other endpoint" in wl.note


def test_unreachable_url_is_a_lead_deceptive_no_fact(monkeypatch, tmp_path):
    """A URL the tool claims live but VIGIL's OWN gated GET cannot reach (closed port) → NO fact."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    import socket
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()
    wl = endpoint_liveness_redrive(f"http://127.0.0.1:{closed_port}/live",
                                   slug="alpha", engagement_slug="alpha", signers=signers)
    assert not wl.is_fact and wl.outcome == "deceptive_no_fact"
    assert wl.lead is not None and "not reproducible" in wl.note


def test_out_of_scope_url_is_refused_before_any_traffic(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")          # only 127.0.0.1 is in scope
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    wl = endpoint_liveness_redrive("http://10.99.99.99/live",
                                   slug="alpha", engagement_slug="alpha", signers=signers)
    assert wl.refused is True and not wl.is_fact and wl.outcome == "refused"


# ===================================================================================================
# End-to-end through the R4 gated runner (httpx / ffuf → run_external_tool → the liveness re-drive).
# ===================================================================================================
@pytest.mark.parametrize("tool,canned", [("httpx", _httpx_jsonl), ("ffuf", _ffuf_report)])
def test_web_tool_live_url_mints_a_fact_through_the_runner(tool, canned, monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    signers, tr = _signers_and_trust()
    srv = _serve(_SoftLiveApp)          # /live real content vs a same-branch (200) soft-404 baseline
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/live"
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="/tmp/wl.txt")
    try:
        res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                signers=signers, timeout=30.0)
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert any(getattr(p, "url", "") == url for p in res.proposed), f"{tool} did not propose {url}: {res.proposed}"
    assert len(res.facts) == 1, f"expected 1 liveness FACT via {tool}; facts={res.facts} leads={res.leads}"
    fact = res.facts[0]
    assert fact.is_fact and fact.confirmed_by == "achieved_state"
    ctx = res.contexts[fact.finding_ref]
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=tr).ok is True


@pytest.mark.parametrize("tool,canned", [("httpx", _httpx_jsonl), ("ffuf", _ffuf_report)])
@pytest.mark.parametrize("app,path,label", _SOFT_404_CLASSES)
def test_web_tool_soft_404_classes_are_a_lead_through_the_runner(tool, canned, app, path, label,
                                                                 monkeypatch, tmp_path):
    """Every soft-404 / phantom CLASS (both red-pens) is a LEAD through BOTH the httpx and ffuf runner legs —
    uniform, path-echo, numeric-route, length-signature, hex-route, uuid-route, and bounded-body — each of
    which minted a FALSE FACT on some pre-fix HEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    signers, _ = _signers_and_trust()
    srv = _serve(app)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}{path}"
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="/tmp/wl.txt")
    try:
        res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                signers=signers, timeout=30.0)
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert res.proposed, "the tool must still PROPOSE the URL"
    assert res.facts == [], f"{label} via {tool}: must mint NO liveness FACT (the tool's say-so never confirms)"
    assert any(o.get("outcome") == "inconclusive" for o in res.outcomes)


@pytest.mark.parametrize("tool,canned", [("httpx", _httpx_jsonl), ("ffuf", _ffuf_report)])
def test_web_tool_numeric_route_live_id_still_a_fact_through_the_runner(tool, canned, monkeypatch, tmp_path):
    """NON-REGRESSION through both runner legs: a genuinely-live numeric id (distinct body vs a same-shape
    numeric not-found control) still mints one signed liveness FACT."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    signers, tr = _signers_and_trust()
    srv = _serve(_NumericRouteLiveApp)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/api/users/1"
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="/tmp/wl.txt")
    try:
        res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                signers=signers, timeout=30.0)
    finally:
        srv.shutdown()
    assert len(res.facts) == 1, f"expected 1 liveness FACT via {tool}; facts={res.facts} leads={res.leads}"
    fact = res.facts[0]
    assert verify_certificate(fact.signed, oracle_context=res.contexts[fact.finding_ref], trust_root=tr).ok is True


# ===================================================================================================
# The conformance battery over the REAL gated runner (the gate the matrix requires before fact_capable).
# ===================================================================================================
@pytest.mark.parametrize("tool", ["httpx", "ffuf"])
def test_web_tool_passes_the_full_conformance_battery(tool, monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.authority import KillSwitch
    from vigil_integration.live.conformance import REQUIRED_PROPERTIES, run_toolspec_conformance
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan
    signers, tr = _signers_and_trust()

    srv = _serve(_SoftLiveApp)          # /live real content vs a same-branch (200) soft-404 baseline
    port = srv.server_address[1]
    live_url = f"http://127.0.0.1:{port}/live"
    # a definitely-CLOSED port for the deceptive fixture (the tool proposes it; VIGIL's GET cannot reach it)
    import socket
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()
    dead_url = f"http://127.0.0.1:{closed_port}/live"

    if tool == "httpx":
        spec = httpx_url_scan()
        pos_backend = _CannedBackend(_httpx_jsonl(live_url))
        dec_backend = _CannedBackend(_httpx_jsonl(dead_url))
    else:
        spec = ffuf_content_scan(wordlist="/tmp/wl.txt")
        pos_backend = _CannedBackend(_ffuf_report(live_url))
        dec_backend = _CannedBackend(_ffuf_report(dead_url))

    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name=tool,
            positive_spec=spec, positive_backend=pos_backend,
            deceptive_spec=spec, deceptive_backend=dec_backend,
            target="127.0.0.1",
            scope_gate_in=_scope_gate(["127.0.0.1"]),
            scope_gate_out=_scope_gate(["10.99.99.99"]),
            engagement_slug="alpha", signers=signers, trust_root=tr,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=30.0)
    finally:
        srv.shutdown()

    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    for prop in REQUIRED_PROPERTIES:
        assert report.checks.get(prop) is True, f"{tool}: {prop} not satisfied: {report.summary()}"


# ===================================================================================================
# Two operator surfaces AGREE: the capability matrix and the body's oracle-mapped set both say
# httpx + ffuf are fact_capable web-discovery tools (ACHIEVED_STATE endpoint-liveness).
# ===================================================================================================
def test_two_surfaces_agree_httpx_ffuf_are_fact_capable_web_discovery():
    from vigil_integration.brains.hexstrike_body import _ORACLE_MAPPED_TOOLS, _spec_for_kind
    from vigil_integration.live.oracle_families import family_for, is_fact_capable_family
    from vigil_integration.live.tool_manifest import load_manifests

    root = Path(__file__).resolve().parents[2]
    matrix = root / "docs" / "capability-matrix" / "hexstrike.json"
    by = {m.name: m for m in load_manifests(str(matrix))}
    for tool in ("httpx", "ffuf"):
        # surface 1 — the capability matrix
        assert by[tool].fact_capable, f"{tool}: matrix must mark it fact_capable"
        assert by[tool].oracle_family.upper() == "ACHIEVED_STATE"
        # surface 2 — the body's runner-owned oracle-mapped set + family routing
        assert tool in _ORACLE_MAPPED_TOOLS, f"{tool}: body must treat it as oracle-mapped"
        assert is_fact_capable_family(tool) and family_for(tool).name == "web_discovery"
        spec = _spec_for_kind(tool, {})
        assert spec is not None and spec.name == tool and spec.propose_urls is not None
