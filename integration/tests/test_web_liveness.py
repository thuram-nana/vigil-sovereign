"""HexStrike W2 — SIBLING RESPONSE DIFFERENTIAL (evidence branch ``achieved_state.endpoint_liveness``).

*** LEAD-ONLY, PERMANENTLY. *** Five adversarial rounds, and every one found a NEW class of URL where
NOTHING EXISTS and this predicate minted a signed, offline-RE-VERIFYING FACT. Round 5 found two more: a
per-position FORMAT route (``^report\\d$`` / ``^user\\d{3}$`` / ``^dashboard\\d$``) at 11/100, 32/100 and
55/100 direct plus 29-40/80 through BOTH runner legs, because the sibling cohorts draw every alphanumeric
position from a per-SEGMENT UNION alphabet rather than mirroring the target's per-position class; and a
SKEWED per-PATH bounded not-found body space at 13/100 direct, 9/80 httpx, 13/80 ffuf. On one route where
``/o/dashboard9`` EXISTS and ``/o/dashboard1`` does not it minted 40/40 for the existing id and 21/40 for
the nonexistent one. The branch is therefore declared fact_capable=false AND clean_capable=false, and
``verdict.admit()`` is the choke that enforces it.

WHAT IS KEPT: the whole evidence pipeline runs as a LEAD ENRICHER. The gated GETs, the same-branch
baseline, the k=4 multi-sampling, the validator-aware controls and the NO-TWIN minimal-edit-distance cohort
all still execute, and their retained capture (predicate AST + every raw per-sample status and body hash +
``control_urls`` + ``probe_urls``) rides on the LEAD and re-verifies offline. The proofs below are
genuinely live: real loopback HTTP servers.

Headline properties:
  * NOTHING mints. A really-distinguishable URL, a soft-404 phantom, a checksum route, a format route and
    the whole RP1-RP5 class table are all LEADs, and the demotion reason travels in words;
  * the retained capture is still real evidence: the predicate fires over it offline and a TAMPERED context
    stops firing, so a LEAD's evidence is falsifiable rather than decorative;
  * a hard 404/410 is INCONCLUSIVE, not CLEAN — the sibling and twin cohorts are never probed on that path,
    so nothing measured the differential, and a 404 is also what a server returns for an existing but
    unauthorised resource;
  * a tool-claimed-but-UNREACHABLE URL → a LEAD (deceptive_no_fact — the tool's say-so never confirms);
  * every soft-404 / phantom CLASS is a LEAD through the direct re-drive AND through BOTH runner legs, at
    VOLUME (a 4% class is invisible to single-shot coverage, and volume is what surfaced every round);
  * the two round-5 classes are permanent regression fixtures, so a future re-promotion cannot forget them;
  * the shipped bug-class token is ``sibling_response_differential``, never ``endpoint_liveness``;
  * httpx's R4 argv PINS the correlatable User-Agent (httpx's own ``-random-agent`` defaults TRUE, and
    identity rotation is forbidden), and ffuf's pins ``-maxtime`` so a SIGKILL cannot lose the report;
  * the runner CAPS how many proposed urls it re-drives, against a documented per-run request budget, and
    the truncation is visible in the result — never silent;
  * a hostile brain-supplied ``scheme``/``wordlist`` is refused before any argv or any send (a scope escape);
  * the two operator surfaces (capability matrix + the body's oracle-mapped set) AGREE that httpx/ffuf are
    LEAD-only web-discovery tools.

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
    """The TRUE-POSITIVE twin of _NumericRouteSoftApp: /api/users/1 is a REAL user (distinct body), every
    other numeric id is the soft-404 {"user": null}. A same-shape numeric control 200s with {"user": null},
    but the target /api/users/1 body DIFFERS -> the differential is real and the oracle still fires. It is
    nonetheless only a LEAD: this fixture now pins the CAPABILITY COST of the downgrade, not a FACT."""

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
    id -> 200 {"user":null} (the sibling cohort's own stable same-status answer). The NARROWED claim is a
    TRUE-if-modest OBSERVATION here (its response differs from the stable same-status sibling response and
    no minimal-edit-distance neighbour returned it) — but the branch is LEAD-ONLY, so it mints NOTHING, and
    it is not a "live endpoint" overclaim either. The fix is the claim string, checked below."""

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


def _unknown_validator_app(accepts):
    """RP3/RP4 — an APP-SPECIFIC validator VIGIL cannot know, whose REJECT lives INSIDE the target's own
    status branch: /item/<10 alnum> answers 200 {"item":null} when ``accepts(id)`` (the route's TRUE
    not-found body for an id it considers well-formed) and 200 {"error":"bad"} when it does not.

    This is the class the 3rd round called irreducible. It is NOT: a uniform random control maximises
    INDEPENDENCE from the target, so it always lands in the reject set — but a MINIMAL-EDIT-DISTANCE
    neighbour stays inside the validity neighbourhood of a prefix / suffix / positional rule, comes back
    with the target's OWN body, and the NO-TWIN rule kills the FACT."""
    class _App(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # noqa: D401
            pass

        def do_GET(self):  # noqa: N802
            m = re.match(r"^/item/([0-9A-Za-z]{10})/?$", self.path.split("?")[0])
            if not m:
                body, code = b"nf", 404
            else:
                body, code = ((b'{"item":null}', 200) if accepts(m.group(1))
                              else (b'{"error":"bad"}', 200))
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return _App


def _prefix_validator_app():
    return _unknown_validator_app(lambda s: s.startswith("ZQ"))


def _suffix_validator_app():
    return _unknown_validator_app(lambda s: s.endswith("QZ"))


def _positional_validator_app():
    return _unknown_validator_app(lambda s: s[4] == "K")


def _checksum26(s: str) -> bool:
    return sum(ord(c) - 97 for c in s) % 26 == 0


def _make_checksum26() -> str:
    import random
    import string
    while True:
        cand = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
        if _checksum26(cand):
            return cand


class _UnknownChecksum200RejectApp(http.server.BaseHTTPRequestHandler):
    """THE RESIDUAL, rewritten as what it actually is (RP4). An unknown WHOLE-STRING CHECKSUM — here
    sum(ord(c)-97) % 26 == 0 over 10 lowercase letters — whose reject lives INSIDE the target's own status
    branch: valid ⇒ 200 {"k":null} (the route's not-found body), invalid ⇒ 200 {"error":"bad"}.

    Why the twin search cannot reach it: the constraint couples ALL positions, so changing any ONE character
    shifts the sum by a non-zero value mod 26 and the neighbour is always rejected. No minimal-edit-distance
    sibling is accepted, so none can return the target's body, so no twin exists to find. The prefix /
    suffix / positional validators above are all closed; only a joint-across-positions checksum VIGIL does
    not know survives, and only while it is not one of the well-known ones (_known_validators)."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = re.match(r"^/k/([a-z]{10})/?$", self.path.split("?")[0])
        if not m:
            body, code = b"nf", 404
        else:
            body, code = ((b'{"k":null}', 200) if _checksum26(m.group(1)) else (b'{"error":"bad"}', 200))
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


# --- RP5: the two classes that decided the DOWNGRADE. Permanent regression fixtures. -------------------
_FORMAT_ROUTE = re.compile(r"^/o/dashboard(\d)/?$")


def _format_route_app():
    """RP5 (A) — a PER-POSITION FORMAT route: ``/o/dashboard<digit>``. Answers 200 with a REJECT body for
    any ``/o/<10-char alnum>`` that does not match the format, and 200 with its own NOT-FOUND body for a
    format-matching id that does not exist. NOTHING at ``/o/dashboard1`` exists.

    THIS IS THE CLASS THAT ENDED THE FACT. The cohorts do NOT mirror the target's per-position class:
    ``_alnum_class_alphabet`` unions the whole segment's alnum characters (``dashboard1`` → lower_alnum,
    36 characters) and BOTH cohorts draw EVERY position from that one alphabet. So an edit at one of the
    nine LETTER positions always breaks the format, and an edit at the single DIGIT position produces a
    letter 26/35 of the time — the twin cohort's ~2 passes over that position therefore find no accepted
    neighbour about 55% of the time, the "baseline" is the route's REJECT body, the target's own not-found
    body looks like a differential, and a signed FACT was minted for a url where nothing exists.
    Measured 11/100, 32/100 and 55/100 direct and 29-40/80 through both runner legs before the downgrade.
    """
    class _App(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # noqa: D401
            pass

        def do_GET(self):  # noqa: N802
            path = self.path.split("?")[0]
            if not re.match(r"^/o/[0-9A-Za-z]{10}/?$", path):
                body, code = b"nf", 404
            elif _FORMAT_ROUTE.match(path):
                body, code = b'{"dashboard":null}', 200     # well-formed id, nothing there
            else:
                body, code = b'{"error":"bad id"}', 200     # the route's REJECT, INSIDE the 200 branch
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return _App


def _skewed_bounded_body_app():
    """RP5 (B) — a SKEWED, PER-PATH bounded not-found body space. ``/s/<8 lowercase>`` always 200s with one
    of two not-found bodies, chosen DETERMINISTICALLY per path (so every resample of a given sibling
    agrees — it is stable IN-BRANCH, never ambiguous) with P(B) = 1/20. NOTHING exists here at all.

    The multi-sampling that closed the per-REQUEST bounded space does nothing against a per-PATH one: the
    rare bucket is stable, so when the TARGET lands in B and the sibling cohort unanimously lands in A, the
    predicate sees a perfectly stable same-branch baseline the target "differs" from, and no neighbour
    returns B either. Measured 13/100 direct, 9/80 httpx, 13/80 ffuf. The target path below is chosen to
    sit in the rare bucket, which is exactly the situation the class describes."""
    def _bucket(path: str) -> bytes:
        import hashlib
        h = int.from_bytes(hashlib.sha256(path.encode()).digest()[:4], "big")
        return b'{"m":"B"}' if h % 20 == 0 else b'{"m":"A"}'

    class _App(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # noqa: D401
            pass

        def do_GET(self):  # noqa: N802
            path = self.path.split("?")[0]
            body = _bucket(path) if re.match(r"^/s/[a-z]{8}/?$", path) else b"nf"
            self.send_response(200 if body != b"nf" else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return _App


def _skewed_rare_bucket_path() -> str:
    """A ``/s/<8 lowercase>`` path the skewed app puts in the RARE bucket (body B) — i.e. the nonexistent
    url the class mints for. Derived the same way the app derives it, so the fixture cannot drift.

    Every candidate contains letters OUTSIDE a-f, deliberately: an all-a-f segment is BOTH lower-alpha and
    lower-hex, ``_alnum_class_alphabet`` calls that AMBIGUOUS and the run fails closed before a single
    control is fetched — the fixture would then pass for the wrong reason (the lesson of the RP4 round)."""
    import hashlib
    import itertools
    for combo in itertools.product("ghijklmnop", repeat=4):
        seg = "".join(combo) + "wxyz"
        path = f"/s/{seg}"
        h = int.from_bytes(hashlib.sha256(path.encode()).digest()[:4], "big")
        if h % 20 == 0:
            return path
    raise AssertionError("no rare-bucket path found")   # pragma: no cover


def _handler(app):
    """A table entry is either a handler CLASS or a zero-arg FACTORY that builds a fresh one (needed when
    the fixture keeps per-server state, e.g. the arrival-indexed partially-varying app — a shared class
    would leak its state across runs and change what the fixture models)."""
    return app() if (not isinstance(app, type)) else app


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


# ---- canned tool backends (the tool is only a PROPOSER; VIGIL's own gated GET is the LEAD enricher) ----
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
def test_a_genuinely_distinguishable_url_is_a_lead_not_a_fact(monkeypatch, tmp_path):
    """THE DOWNGRADE, at the choke. ``/live`` is the branch's BEST case — a real endpoint whose body differs
    from a stable same-branch sibling baseline with no twin — and it is a LEAD. Nothing on this branch
    mints, so the loss of the true positive is the DELIBERATE capability cost of the downgrade, and the
    demotion reason travels in words rather than being inferable from an empty facts list."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_SoftLiveApp)          # /live real content; siblings soft-404 200 (the SAME served branch)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact and wl.fact is None, "the branch is LEAD-only: nothing may mint"
    assert wl.outcome == "inconclusive" and wl.lead is not None and not wl.lead.is_fact
    # the measurement still HAPPENED — same-branch baseline, same served branch, twin cohort searched
    assert wl.target_status == 200 and wl.control_statuses == [200]
    assert wl.same_branch_controls >= 4 and wl.twin_probes >= 4 and wl.twin_found is False
    low = wl.note.lower()
    # THE NARROWING still travels, verbatim, and so does the demotion reason.
    assert "differs from the server's stable same-status response" in low
    assert "no minimal-edit-distance sibling" in low
    assert "asserts nothing about" in low and "existence or liveness" in low
    assert "demoted to a lead" in low
    asserted = low.partition("this asserts nothing about")[0]
    for banned in ("not-found baseline", "soft-404", "live endpoint", "is live", "is real"):
        assert banned not in asserted, f"the claim still asserts {banned!r}: {wl.note}"
    assert wl.lead.note == wl.note, "the demotion reason must reach every consumer of the LEAD"


def test_the_lead_carries_its_retained_capture_and_it_re_verifies_offline(monkeypatch, tmp_path):
    """The evidence pipeline is KEPT as a LEAD ENRICHER, so the LEAD must carry the same retained,
    offline-re-verifiable capture a FACT would have: the predicate AST plus every raw per-sample status and
    body hash, the control urls AND the probe urls. Re-running the deterministic oracle over the retained
    context (no network, no runner) must reproduce the runner's own signal — otherwise the 'evidence' is
    decorative."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _oracle_signal, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_SoftLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.context is not None, "a LEAD must still carry its retained capture"
    ev = wl.context["observed_evidence"]
    assert ev["target_url"].endswith("/live") and ev["control_urls"] and ev["probe_urls"]
    assert len(ev["probe_urls"]) == ev["twin_probes"] >= 4
    for i, u in enumerate(ev["probe_urls"]):
        assert f"probe_{i}_sha" in ev and f"probe_{i}_status" in ev, "probe_urls must align with the samples"
        assert u != ev["target_url"], "a twin probe is a NEIGHBOUR, never the target itself"
    # JSON-safe (it has to survive a certificate / a report / a file) and re-verifiable OFFLINE.
    ctx = json.loads(json.dumps(wl.context))
    assert _oracle_signal(ctx).fired is True, "the retained capture must reproduce the runner's own signal"


def test_a_tampered_lead_capture_stops_re_verifying(monkeypatch, tmp_path):
    """The LEAD's evidence is FALSIFIABLE, not decorative: flip the target's body-hash to the baseline's in
    the retained context and the differential is gone, so the deterministic oracle must stop firing over
    it. (On a FACT this was the signature check; on a LEAD there is no signature, so the property that
    matters is that the retained capture is what the conclusion actually rests on.)"""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _oracle_signal, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_SoftLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.context is not None and _oracle_signal(wl.context).fired is True
    tampered = json.loads(json.dumps(wl.context))
    tampered["observed_evidence"]["target_0_sha"] = tampered["observed_evidence"]["control_0_sha"]
    assert _oracle_signal(tampered).fired is False


# Every soft-404 / phantom CLASS the five red-pen rounds raised. Each minted a FALSE offline-re-verifiable
# FACT on some preceding HEAD; each must be a LEAD. (RP1: uniform, path-echo, numeric-route, length-sig.
# RP2: hex-route, uuid-route, bounded per-request body. RP3: Luhn hard-404, Luhn soft-reject, base58.
# RP4: unknown prefix/suffix/positional validator in-branch, partially-varying space. RP5: the per-position
# FORMAT route and the SKEWED per-path bounded body space — the two that ended the FACT.)
#
# The 4th element is LEG_RUNS: how many times the httpx/ffuf leg table runs this class. A DETERMINISTIC
# class is settled in one run; a PROBABILISTIC one is not, and single-shot coverage is exactly how a 2.3%
# class shipped through RP3 and how the two RP5 classes reached a fifth round. Volume is what surfaced
# every block, so the adversarial rows carry it here, in the table the legs are parametrized over.
_ADVERSARIAL_LEG_RUNS = 20       # rate-based classes: enough to see a ~15% class essentially always
_CHECKSUM_LEG_RUNS = 4           # off-branch reject classes: rate-based but were 0/80 at the floor already
_SOFT_404_CLASSES = [
    (_SoftNotFoundApp, "/anything", "uniform blanket-200", 1),
    (_PathEchoSoftApp, "/anything", "path-echoing 200", 1),
    (_NumericRouteSoftApp, "/api/users/999999999", "numeric-route soft-404 (RP1)", 1),
    (_LengthSignatureApp, "/admin", "length/shape-signature 404 (RP1)", 1),
    (_HexRouteSoftApp, "/token/dead1234", "hex-route soft-404 (RP2)", 1),
    (_HexRouteSoftApp, "/token/deadbeef", "hex-route ambiguous-class fail-closed (RP2)", 1),
    (_UuidRouteSoftApp, "/r/550e8400-e29b-41d4-a716-446655440000", "uuid-route soft-404 (RP2)", 1),
    (_BoundedBodySoftApp, "/admin", "bounded per-request 2-elt body (RP2)", _ADVERSARIAL_LEG_RUNS),
    (_LuhnHardApp, "/card/4111111111111111", "Luhn checksum route, hard-404 reject (RP3)", _CHECKSUM_LEG_RUNS),
    (_LuhnSoftApp, "/card/4111111111111111", "Luhn checksum route, distinct-body reject (RP3)",
     _CHECKSUM_LEG_RUNS),
    (_Base58App, "/obj/3vQB7fMrk9xZa5dCFg2h", "base58 checksum route (RP3)", _CHECKSUM_LEG_RUNS),
    (_Luhn200RejectApp, "/card/4111111111111111", "Luhn route, reject INSIDE the target's branch (RP3)",
     _ADVERSARIAL_LEG_RUNS),
    (_Base58_200RejectApp, "/obj/3vQB7fMrk9xZa5dCFg2h", "base58 route, reject INSIDE the branch (RP3)",
     _ADVERSARIAL_LEG_RUNS),
    (_StrictValidatorApp, "/item/005", "strict validator, < floor valid controls (RP3 fail-closed)", 1),
    # RP4 — the classes the 3rd round shipped as MINTING. Each is a nonexistent URL.
    # They go in THIS table deliberately: it is the table the httpx and ffuf legs are parametrized over,
    # and "the two classes that still mint are exactly the two the runner legs never exercise" was the
    # gap that let them ship.
    (_prefix_validator_app, "/item/ZQabcdefgh", "unknown PREFIX validator, 200 reject in-branch (RP4)",
     _ADVERSARIAL_LEG_RUNS),
    (_suffix_validator_app, "/item/abcdefghQZ", "unknown SUFFIX validator, 200 reject in-branch (RP4)",
     _ADVERSARIAL_LEG_RUNS),
    (_positional_validator_app, "/item/abcdKfghij", "unknown POSITIONAL validator, 200 reject (RP4)",
     _ADVERSARIAL_LEG_RUNS),
    (_partially_varying_app, "/x/wxyz", "partially-varying not-found space (RP4)", _ADVERSARIAL_LEG_RUNS),
    # RP5 — THE TWO CLASSES THAT ENDED THE FACT. They are LEADs trivially now (nothing mints), and they
    # stay here permanently so a future re-promotion attempt has to walk past them.
    (_format_route_app, "/o/dashboard1", "per-position FORMAT route, 200 reject in-branch (RP5)",
     _ADVERSARIAL_LEG_RUNS),
    (_skewed_bounded_body_app, _skewed_rare_bucket_path(), "SKEWED per-path bounded body space (RP5)",
     _ADVERSARIAL_LEG_RUNS),
]


@pytest.mark.parametrize("app,path,label,_runs", _SOFT_404_CLASSES)
def test_soft_404_classes_mint_no_liveness_fact(app, path, label, _runs, monkeypatch, tmp_path):
    """Every soft-404 / phantom CLASS both red-pens raised must be a LEAD, never a FACT."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_handler(app))
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
        assert "identical to the same-branch sibling baseline" in wl.note.lower(), wl.note


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
    run closed.

    300 RUNS, not 20 (RP4 BLOCK-2). At _LIVENESS_RESAMPLES=2 this class still minted 7/300 = 2.3% — and a
    20-iteration test passes ~62% of the time against a 2.3% rate, which is why it shipped green twice. The
    per-control misclassification bound is b^(1-k) (b=2, k=2 ⇒ 1/2; k=4 ⇒ 1/8), and a false FACT needs
    EVERY varying control misclassified AND landing on the deterministic value AND no twin probe returning
    the target's body."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    facts, notes = 0, []
    for _ in range(300):
        srv = _serve(_partially_varying_app())
        port = srv.server_address[1]
        try:
            wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/x/wxyz",
                                           slug="alpha", engagement_slug="alpha", signers=signers)
        finally:
            srv.shutdown()
        facts += 1 if wl.is_fact else 0
        notes.append(wl.note)
    assert facts == 0, f"a fluke baseline from unstable controls minted {facts}/300 false FACTs: {notes[:2]}"
    assert any("ambiguous" in n.lower() for n in notes), notes[:2]


def test_the_retained_capture_binds_same_branch_membership(monkeypatch, tmp_path):
    """The partition is part of the retained evidence, not a runner assertion: flip a retained in-branch
    control's status away from the target's and the predicate must stop firing over the capture (the
    baseline is no longer in the target's branch). Bounded by the retention trust boundary the module
    header states — this proves the relations among RETAINED samples, never that they are all of them."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _oracle_signal, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_SoftLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.context is not None and _oracle_signal(wl.context).fired is True
    tampered = json.loads(json.dumps(wl.context))
    tampered["observed_evidence"]["control_0_status"] = 404      # pretend the baseline was a 404 reject
    assert _oracle_signal(tampered).fired is False


def test_the_predicate_proves_the_partition_and_refuses_a_cherry_picked_one():
    """The generated AST must prove the WHOLE in/off-branch partition offline, so a runner cannot present a
    cherry-picked baseline: (a) an honest partition fires; (b) calling a control OFF-branch when it carried
    the target's status does not; (c) an in-branch control whose body differs from the anchor does not;
    (d) a partition with no in-branch control does not (the anchor var is absent)."""
    from framework.v2.verify.oracles import predicate_oracle
    from vigil_integration.live.web_redrive import (_MIN_LIVENESS_CONTROLS, _MIN_TWIN_PROBES,
                                                    _build_liveness_predicate)

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
    n_probes = _MIN_TWIN_PROBES
    probes = list(range(n_probes))
    for k in probes:
        ev[f"probe_{k}_status"], ev[f"probe_{k}_sha"] = 200, f"NEIGHBOUR{k}"
    ev["twin_probes"] = n_probes
    pred = _build_liveness_predicate(in_blocks, off_blocks, probes, 3, _MIN_LIVENESS_CONTROLS,
                                     _MIN_TWIN_PROBES)
    assert predicate_oracle(ev, pred).fired is True                      # (a)

    twin = dict(ev)                                                      # (a2) NO-TWIN: one neighbour came
    twin["probe_0_sha"] = ev["target_0_sha"]                             #      back with the target's body
    assert predicate_oracle(twin, pred).fired is False
    dead = dict(ev)                                                      # (a3) a neighbour never answered
    dead["probe_1_status"] = 0
    assert predicate_oracle(dead, pred).fired is False
    thin = dict(ev, twin_probes=_MIN_TWIN_PROBES - 1)                     # (a4) neighbourhood not searched
    assert predicate_oracle(thin, pred).fired is False

    cherry = dict(ev)                                                    # (b) the "discarded" control was
    for k in off_blocks[0]:                                              #     really IN the target's branch
        cherry[f"control_{k}_status"] = 200
    assert predicate_oracle(cherry, pred).fired is False

    disagree = dict(ev)                                                  # (c)
    disagree[f"control_{in_blocks[-1][0]}_sha"] = "OTHER"
    assert predicate_oracle(disagree, pred).fired is False

    empty = _build_liveness_predicate([], off_blocks, probes, 3, _MIN_LIVENESS_CONTROLS,
                                      _MIN_TWIN_PROBES)                  # (d)
    assert predicate_oracle({**ev, "same_branch_controls": 0}, empty).fired is False
    assert predicate_oracle({**ev, "same_branch_controls": 99}, empty).fired is False


@pytest.mark.parametrize("factory,path,label", [
    (_prefix_validator_app, "/item/ZQabcdefgh", "unknown PREFIX validator"),
    (_suffix_validator_app, "/item/abcdefghQZ", "unknown SUFFIX validator"),
    (_positional_validator_app, "/item/abcdKfghij", "unknown POSITIONAL validator"),
])
def test_unknown_in_branch_validator_is_closed_by_the_no_twin_cohort_over_80_runs(
        factory, path, label, monkeypatch, tmp_path):
    """RP4 BLOCK-1 — the class the previous round shipped as an "irreducible" residual, minting 39/40 for a
    NONEXISTENT url. It is not irreducible: the uniform-random cohort maximises INDEPENDENCE from the
    target, which on a validating route guarantees every control lands in the REJECT set, so the "baseline"
    is a reject baseline. The MINIMAL-EDIT-DISTANCE cohort does the opposite — each probe differs from the
    target at exactly ONE position, so it stays inside the validity neighbourhood of a prefix / suffix /
    positional rule, returns the route's own not-found body, and NO-TWIN kills the FACT. 80 runs, 0 FACTs,
    and the LEAD must say a twin was found (the right reason, not an accident)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(factory())
    port = srv.server_address[1]
    facts, twins, searched = 0, 0, 0
    try:
        for _ in range(80):
            wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}{path}",
                                           slug="alpha", engagement_slug="alpha", signers=signers)
            facts += 1 if wl.is_fact else 0
            twins += 1 if wl.twin_found else 0
            searched += 1 if wl.twin_probes else 0
    finally:
        srv.shutdown()
    assert facts == 0, f"{label}: minted {facts}/80 false FACTs for a NONEXISTENT url"
    # The RIGHT reason, stated exactly. A run only REACHES the twin search when the baseline cohort itself
    # formed; on a positional rule roughly one run in six instead draws a control the route ACCEPTS, the
    # baseline is then not unanimous and the run LEADs earlier. EVERY run that did reach the search must
    # have found a twin — that is the cohort doing the work, and it is what makes this class 0, not luck.
    assert searched >= 40, f"{label}: only {searched}/80 runs reached the twin search"
    assert twins == searched, (f"{label}: {searched} runs searched the neighbourhood but only {twins} found "
                               f"a twin — the minimal-edit-distance cohort is not closing this class")


@pytest.mark.parametrize("factory,pathfn,label,min_fire", [
    (_format_route_app, lambda: "/o/dashboard1",
     "per-position FORMAT route, 200 reject in-branch (RP5-A)", 8),
    (_skewed_bounded_body_app, _skewed_rare_bucket_path,
     "SKEWED per-path bounded not-found body space (RP5-B)", 4),
])
def test_rp5_classes_that_ended_the_fact_are_permanent_regressions(factory, pathfn, label, min_fire,
                                                                   monkeypatch, tmp_path):
    """RP5 — THE TWO CLASSES THAT DECIDED THE DOWNGRADE, pinned forever on the DIRECT path.

    Both are urls where NOTHING EXISTS, and on the preceding HEAD both minted signed, offline-re-verifying
    FACTs: the per-position FORMAT route at 11/100, 32/100 and 55/100 (the cohorts draw from a per-SEGMENT
    UNION alphabet, so a Hamming-1 edit at a digit slot becomes a letter ~74% of the time and no twin is
    found), and the SKEWED per-PATH bounded body space at 13/100 (multi-sampling does nothing against a
    space that is stable per path).

    TWO assertions, and the second one is the point. (1) ZERO FACTs — trivially true today because nothing
    on this branch mints, which is exactly why it must be pinned: it is the assertion a re-promotion would
    break. (2) The fixture BITES: the deterministic oracle must still FIRE for a nonexistent url on a
    material fraction of runs. Without (2) this test would keep passing if the fixture silently stopped
    modelling the class — which is precisely how the RP4 ambiguity fixture passed for the wrong reason."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _oracle_signal, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    path = pathfn()
    # RUNS=80, NOT 40 (red-pen advisory). The bite assertion is a binomial tail: RP5-B measures a fire-rate
    # of p~=0.167 and asserts min_fire=4, so at runs=40 P(fired < 4) ~= 8% — a spurious red roughly one CI
    # run in twelve. At runs=80 the same min_fire=4 gives P ~= 0.3%. min_fire is deliberately NOT lowered:
    # it is the only thing stopping the zero-FACT assertion from passing vacuously. (RP5-A measured 71/120
    # ~= 59%, so it is nowhere near its own floor either way.)
    runs = 80
    facts, fired = 0, 0
    try:
        srv = _serve(factory())
        port = srv.server_address[1]
        for _ in range(runs):
            wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}{path}",
                                           slug="alpha", engagement_slug="alpha", signers=signers)
            facts += 1 if wl.is_fact else 0
            if wl.context is not None and _oracle_signal(wl.context).fired:
                fired += 1
                # whenever it fires, the LEAD must SAY it was demoted — never "no differential".
                assert "demoted to a lead" in (wl.note or "").lower(), wl.note
    finally:
        srv.shutdown()
    assert facts == 0, f"{label}: minted {facts}/{runs} FACT(s) for a NONEXISTENT url — the branch must not mint"
    assert fired >= min_fire, (
        f"{label}: the predicate fired on only {fired}/{runs} runs (expected >= {min_fire}). This fixture "
        f"exists to keep a MEASURED false-FACT class reproducible; if it stopped reproducing, the fixture "
        f"has drifted and the zero-FACT assertion above is passing for the wrong reason")


def test_the_twin_cohort_is_a_search_only_and_never_counts_toward_the_control_floor():
    """The Hamming-1 probes must NEVER be mistaken for baseline controls: counting them would let a
    sub-floor run (too few same-branch siblings) be pushed OVER the floor by probes that were never
    classified into a branch at all. Assert the two cohorts are built by different functions, that the
    predicate's floor clause reads the CONTROL count only, and that a probe index can only ever appear in a
    NEGATIVE (no-twin) clause."""
    import json as _json
    from vigil_integration.live.web_redrive import (_MIN_LIVENESS_CONTROLS, _MIN_TWIN_PROBES,
                                                    _build_liveness_predicate, _hamming1_probe_urls,
                                                    _liveness_control_urls)
    url = "http://h/item/ZQabcdefgh"
    controls, probes = _liveness_control_urls(url), _hamming1_probe_urls(url)
    assert len(controls) >= _MIN_LIVENESS_CONTROLS and len(probes) >= _MIN_TWIN_PROBES
    assert not (set(controls) & set(probes)), "the two cohorts must be distinct URL sets"
    pred = _build_liveness_predicate([[0, 1], [2, 3]], [[4, 5]], [0, 1, 2], 3,
                                     _MIN_LIVENESS_CONTROLS, _MIN_TWIN_PROBES)
    blob = _json.dumps(pred)
    assert '"same_branch_controls"' in blob and '"twin_probes"' in blob
    # A probe may appear POSITIVELY only as a channel check (ge status 100); every probe BODY-HASH
    # reference must sit inside a NOT(eq(...)), i.e. it can only ever REFUSE a fact, never support one.
    for clause in pred["all"]:
        txt = _json.dumps(clause)
        if "probe_" not in txt:
            continue
        if "not" in clause:
            assert "_sha" in txt, clause            # the no-twin refusal
        else:
            assert clause.get("ge", [None, None])[1] == 100 and "_status" in txt, clause
    # and the CONTROL floor is read off the CONTROL count — the probe count has its own, separate clause,
    # so no number of probes can ever satisfy the baseline floor.
    ge_by_var = {c["ge"][0]["var"]: c["ge"][1] for c in pred["all"]
                 if "ge" in c and isinstance(c["ge"][0], dict) and "var" in c["ge"][0]}
    assert ge_by_var.get("same_branch_controls") == _MIN_LIVENESS_CONTROLS
    assert ge_by_var.get("twin_probes") == _MIN_TWIN_PROBES


def test_the_no_twin_rule_is_bound_into_the_offline_predicate(monkeypatch, tmp_path):
    """NO-TWIN is part of the retained evidence, not a runner-side afterthought: rewrite one retained
    probe's body-hash to the target's and the predicate must stop firing over the capture."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _oracle_signal, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_SoftLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.twin_probes >= 4 and wl.twin_found is False and wl.context is not None
    assert _oracle_signal(wl.context).fired is True
    tampered = json.loads(json.dumps(wl.context))
    tampered["observed_evidence"]["probe_0_sha"] = tampered["observed_evidence"]["target_0_sha"]
    assert _oracle_signal(tampered).fired is False


def test_the_narrowing_travels_on_the_lead_and_the_token_does_not_overclaim(monkeypatch, tmp_path):
    """RP4 BLOCK-3 — a note the runner drops is not a disclosure, and that survives the downgrade. What a
    consumer receives must carry the narrowing: (1) the bug-class TOKEN is not `endpoint_liveness` (a token
    that reads as liveness is exactly the overclaim), (2) the claim SENTENCE reaches the AdapterResult, and
    (3) NO certificate is minted at all, because a LEAD has nothing to sign."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import ENDPOINT_LIVENESS_BUG_CLASS, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_SoftLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact and wl.lead is not None
    assert ENDPOINT_LIVENESS_BUG_CLASS == "sibling_response_differential"
    assert wl.lead.bug_class == ENDPOINT_LIVENESS_BUG_CLASS != "endpoint_liveness"
    assert getattr(wl.lead, "signed", None) is None, "a LEAD must carry NO signed certificate"
    claim = wl.note
    # the ASSERTIVE half must not carry any of the falsified phrasings (the DISCLAIMER half is allowed to
    # name them — "asserts nothing about not-found-ness, phantom-ness, existence or liveness" is the point).
    asserted, _, disclaimed = claim.lower().partition("this asserts nothing about")
    assert disclaimed, "the claim must carry its own disclaimer"
    for banned in ("live endpoint", "phantom of", "not-found baseline", "endpoint exists",
                   "is live", "is real", "soft-404"):
        assert banned not in asserted, f"the narrowing still asserts {banned!r}: {claim}"
    low_claim = claim.lower()
    assert "differs from the server's stable same-status response" in low_claim
    assert "no minimal-edit-distance sibling" in low_claim
    assert "asserts nothing about" in low_claim
    assert "demoted to a lead" in low_claim
    assert wl.lead.note == claim


def test_the_class_has_no_oracle_that_can_prove_it(monkeypatch, tmp_path):
    """DEFENCE IN DEPTH for the downgrade. Admission is the choke, but the class is ALSO absent from
    ``verify.verifier.BUG_CLASS_ORACLES``, so a caller that skipped admission and went straight to
    ``confirm_and_certify`` still cannot mint it. Two independent refusals, because one flipped flag
    should not be able to resurrect a class five rounds of measurement retired."""
    from framework.v2.verify.verifier import BUG_CLASS_ORACLES
    from vigil_integration.live.verdict import Verdict, admit
    from vigil_integration.live.web_redrive import ENDPOINT_LIVENESS_BRANCH, ENDPOINT_LIVENESS_BUG_CLASS

    assert ENDPOINT_LIVENESS_BUG_CLASS not in BUG_CLASS_ORACLES, (
        "sibling_response_differential must have NO oracle able to prove it")
    # ... and the branch itself refuses both directions, whatever the oracle saw.
    obs = {"channel_established": True, "gate_authorized": True}
    fired = admit(ENDPOINT_LIVENESS_BRANCH, fired=True, conclusive=True, observed=obs)
    assert fired.verdict is Verdict.LEAD and "not FACT-capable" in fired.reason
    clean = admit(ENDPOINT_LIVENESS_BRANCH, fired=False, conclusive=True, observed=obs)
    assert clean.verdict is Verdict.INCONCLUSIVE, "a hard-404 non-firing may not be reported CLEAN"


def test_the_unknown_whole_string_checksum_class_is_a_lead_and_the_docs_state_it_honestly(
        monkeypatch, tmp_path):
    """THE FORMER RESIDUAL, kept as a regression. A whole-string checksum route (no Hamming-1 neighbour is
    accepted, so no twin exists to find) used to MINT for a checksum-valid-but-nonexistent id. It is now a
    LEAD like everything else — trivially, because nothing mints — and the fixture stays so a future
    re-promotion attempt has to face it again. The docs half is the load-bearing part: the limitation must
    carry the CORRECTED residual condition (a neighbourhood over the MIRROR/UNION alphabet, which also
    covers ordinary word+digits FORMAT routes) and must not carry any of the falsified sentences."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_UnknownChecksum200RejectApp)
    port = srv.server_address[1]
    facts, fired = 0, 0
    try:
        for _ in range(12):
            wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/k/{_make_checksum26()}",
                                           slug="alpha", engagement_slug="alpha", signers=signers)
            facts += 1 if wl.is_fact else 0
            # the MEASUREMENT still happens and is still recorded honestly on the LEAD; only the verdict
            # changed. "demoted to a lead" is the run where the oracle DID fire for a nonexistent url.
            fired += 1 if "demoted to a lead" in (wl.note or "").lower() else 0
    finally:
        srv.shutdown()
    assert facts == 0, f"the branch is LEAD-only but minted {facts}/12 FACT(s) for a NONEXISTENT url"
    assert fired > 0, ("the whole-string-checksum class did not reproduce at all — this fixture exists to "
                       "keep the demoted class visible, so a silent change of behaviour must fail here")
    # the docs must describe the CORRECTED residual and must not carry any falsified sentence.
    root = Path(__file__).resolve().parents[2]
    doc = json.loads((root / "docs" / "capability-matrix" / "evidence-branches.json").read_text())
    entry = next(b for b in doc["branches"] if b["id"] == "achieved_state.endpoint_liveness")
    lim = entry["limitation"]
    low = lim.lower()
    assert "union" in low and "hamming-1" in low, lim
    assert "format routes" in low, "the corrected residual must say it covers ordinary FORMAT routes too"
    for falsified in ("cannot be closed by any observation of this kind",
                      "any rule that refused it would also refuse every true positive",
                      "irreducible"):
        assert falsified not in low, f"the limitation still carries the FALSIFIED sentence {falsified!r}"


def test_block3_special_cased_error_is_a_lead_carrying_an_honest_narrowing(monkeypatch, tmp_path):
    """RP2 BLOCK-3: /api/users/0 serves a special-cased error DISTINGUISHABLE from the same-shape not-found
    baseline. It is now a LEAD — and the narrowing it carries must still NOT say 'live endpoint' / 'real' /
    'exists'. The claim string discipline outlives the FACT it used to be attached to."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _oracle_signal, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_NumericRouteErrApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/api/users/0",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact and wl.lead is not None
    assert wl.context is not None and _oracle_signal(wl.context).fired is True
    low = wl.note.lower()
    # the narrowing states the DIFFERENTIAL and the twin search, and disclaims existence/liveness outright.
    assert "differs from the server's stable same-status response" in low, wl.note
    assert "no minimal-edit-distance sibling" in low, wl.note
    assert "asserts nothing about" in low and "existence or liveness" in low, wl.note
    assert "demoted to a lead" in low, wl.note
    asserted = low.partition("this asserts nothing about")[0]
    for banned in ("not-found baseline", "soft-404", "live endpoint", "is live", "is real"):
        assert banned not in asserted, f"the claim still asserts {banned!r}: {wl.note}"


def test_numeric_route_live_id_is_now_a_lead_the_capability_cost_of_the_downgrade(monkeypatch, tmp_path):
    """THE PRICE, pinned. A GENUINELY live numeric id (/api/users/1) is served 200 with a distinct body
    while a same-shape numeric control 200s with {"user": null}. The differential is real and the oracle
    still fires over the retained capture — and it is still only a LEAD. Pinning the lost true positive
    keeps the cost of the downgrade visible instead of letting it read as 'nothing was lost'."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _oracle_signal, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_NumericRouteLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/api/users/1",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact, "the branch is LEAD-only — even a genuine true positive does not mint"
    assert wl.control_statuses == [200]     # same-status baseline (distinct set); distinguished by the BODY diff
    assert wl.context is not None and _oracle_signal(wl.context).fired is True
    assert "demoted to a lead" in (wl.note or "").lower()


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


def test_hard_404_is_inconclusive_not_clean(monkeypatch, tmp_path):
    """THE CLEAN DIRECTION IS WITHDRAWN TOO. A hard 404 at the exact probed URL is control-independent, but
    on that path the sibling and twin cohorts are NEVER PROBED — the run returns before any control GET —
    so a 'conclusive non-firing' of a DIFFERENTIAL predicate would assert the absence of something nothing
    measured. A 404 is also what a server routinely returns for a resource that EXISTS but is not
    authorised. clean_capable=false, and the note must say WHY rather than silently degrade."""
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
    assert wl.outcome == "inconclusive" and wl.target_status == 404
    low = wl.note.lower()
    assert "inconclusive, not clean" in low, wl.note
    assert "not probed on this path" in low or "are not probed" in low, wl.note
    assert "not authorised" in low, wl.note
    # and the branch registry is where the policy lives, not this function
    root = Path(__file__).resolve().parents[2]
    doc = json.loads((root / "docs" / "capability-matrix" / "evidence-branches.json").read_text())
    entry = next(b for b in doc["branches"] if b["id"] == "achieved_state.endpoint_liveness")
    assert entry["clean_capable"] is False and entry["target_clean_capable"] is False
    assert len((entry.get("target_downgrade_rationale") or "").strip()) > 40


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
def test_web_tool_live_url_is_a_lead_enricher_through_the_runner(tool, canned, monkeypatch, tmp_path):
    """The LEAD-ENRICHER contract, end to end: the tool proposes, the runner re-drives with its own gated
    GETs, and what comes back is a LEAD that CARRIES its retained, offline-re-verifiable capture plus the
    narrowing in words. No FACT, no certificate, and no empty-handed lead either."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    from vigil_integration.live.web_redrive import _oracle_signal
    signers, _ = _signers_and_trust()
    srv = _serve(_SoftLiveApp)          # /live real content vs a same-branch (200) soft-404 baseline
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/live"
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="")
    try:
        res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                signers=signers, timeout=30.0)
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert any(getattr(p, "url", "") == url for p in res.proposed), f"{tool} did not propose {url}: {res.proposed}"
    assert res.facts == [], f"the branch is LEAD-only; {tool} minted {res.facts}"
    assert len(res.leads) == 1, f"expected 1 enriched LEAD via {tool}; leads={res.leads}"
    lead = res.leads[0]
    assert not lead.is_fact and lead.bug_class == "sibling_response_differential"
    assert "demoted to a lead" in (lead.note or "").lower()
    # the LEAD's retained capture travels with it and re-verifies offline.
    ctx = res.contexts[lead.finding_ref]
    assert ctx["observed_evidence"]["probe_urls"], "the LEAD must carry the probed neighbourhood"
    assert _oracle_signal(json.loads(json.dumps(ctx))).fired is True
    assert res.truncated_proposals == 0 and res.budget_note == ""


@pytest.mark.parametrize("tool,canned", [("httpx", _httpx_jsonl), ("ffuf", _ffuf_report)])
@pytest.mark.parametrize("app,path,label,runs", _SOFT_404_CLASSES)
def test_web_tool_soft_404_classes_are_a_lead_through_the_runner(tool, canned, app, path, label, runs,
                                                                 monkeypatch, tmp_path):
    """Every soft-404 / phantom CLASS of all five rounds is a LEAD through BOTH runner legs — AT VOLUME for
    the adversarial ones.

    Single-shot leg coverage is how a 2.3% class survived round 3 and how the two RP5 classes reached a
    fifth round: a class that mints 4% of the time passes a one-run test 96% of the time. Each row
    therefore carries its own run count (``_ADVERSARIAL_LEG_RUNS`` for the rate-based classes), and a FRESH
    server per run, because several fixtures keep per-server state."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    signers, _ = _signers_and_trust()
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="")
    facts, proposals, inconclusive = 0, 0, 0
    for _ in range(runs):
        srv = _serve(_handler(app))
        port = srv.server_address[1]
        url = f"http://127.0.0.1:{port}{path}"
        try:
            res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                    backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                    signers=signers, timeout=30.0)
        finally:
            srv.shutdown()
        assert res.status == "ran"
        facts += len(res.facts)
        proposals += len(res.proposed)
        inconclusive += sum(1 for o in res.outcomes if o.get("outcome") == "inconclusive")
    assert proposals >= runs, "the tool must still PROPOSE the URL on every run"
    assert facts == 0, (f"{label} via {tool}: minted {facts} FACT(s) over {runs} run(s) for a NONEXISTENT "
                        f"url — the tool's say-so never confirms and this branch never mints")
    assert inconclusive >= runs, f"{label} via {tool}: the demotion must be a TYPED outcome on every run"


@pytest.mark.parametrize("tool,canned", [("httpx", _httpx_jsonl), ("ffuf", _ffuf_report)])
@pytest.mark.parametrize("factory,path,label", [
    (_prefix_validator_app, "/item/ZQabcdefgh", "unknown PREFIX validator, 200 reject in-branch"),
    (_partially_varying_app, "/x/wxyz", "partially-varying not-found space"),
])
def test_rp4_classes_are_a_lead_through_the_runner_legs_over_80_runs(tool, canned, factory, path, label,
                                                                     monkeypatch, tmp_path):
    """RP4 — the two classes that were still minting are exactly the two the runner legs never exercised, so
    prove them THROUGH the legs, and at volume: single-shot leg coverage would have missed a 2.3% rate.
    80 runs per class per leg, 0 FACTs."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    signers, _ = _signers_and_trust()
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="")
    facts = 0
    for _ in range(80):
        srv = _serve(factory())          # a FRESH server each run: the fixture's state is per-server
        port = srv.server_address[1]
        url = f"http://127.0.0.1:{port}{path}"
        try:
            res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                    backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                    signers=signers, timeout=30.0)
        finally:
            srv.shutdown()
        facts += len(res.facts)
    assert facts == 0, f"{label} via {tool}: minted {facts} FACT(s) over 80 runs for a NONEXISTENT url"


@pytest.mark.parametrize("tool,canned", [("httpx", _httpx_jsonl), ("ffuf", _ffuf_report)])
def test_web_tool_numeric_route_live_id_is_a_lead_through_the_runner(tool, canned, monkeypatch, tmp_path):
    """THE PRICE, through both runner legs: a genuinely-live numeric id (distinct body vs a same-shape
    numeric not-found control) is a LEAD. The measurement still runs and its capture still rides on the
    lead; the branch simply may not mint."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    from vigil_integration.live.web_redrive import _oracle_signal
    signers, _ = _signers_and_trust()
    srv = _serve(_NumericRouteLiveApp)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/api/users/1"
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="")
    try:
        res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                signers=signers, timeout=30.0)
    finally:
        srv.shutdown()
    assert res.facts == [], f"the branch is LEAD-only; {tool} minted {res.facts}"
    assert len(res.leads) == 1, f"expected 1 enriched LEAD via {tool}; leads={res.leads}"
    lead = res.leads[0]
    ctx = res.contexts[lead.finding_ref]
    assert _oracle_signal(ctx).fired is True, "the differential was real — only the VERDICT changed"
    assert "demoted to a lead" in (lead.note or "").lower()


# ===================================================================================================
# The conformance battery over the REAL gated runner (the gate the matrix requires before fact_capable).
# ===================================================================================================
@pytest.mark.parametrize("tool", ["httpx", "ffuf"])
def test_the_conformance_battery_fails_the_fact_half_and_passes_every_safety_half(tool, monkeypatch,
                                                                                  tmp_path):
    """THE GATE, run honestly. ``run_toolspec_conformance`` is the battery a tool must pass before the
    matrix may mark it fact_capable, and its FIRST property is ``positive_fact``. A LEAD-only tool cannot
    satisfy that and must not pretend to: the battery's verdict here is NON-CONFORMANT, and that is the
    load-bearing reason httpx/ffuf are fact_capable=false in the matrix rather than a flag someone chose.

    Every SAFETY property must still hold, because those are the ones that matter for a tool that ships:
    the tool still PROPOSES (so the crit-6 firewall is actually exercised), an unreachable proposal yields
    no fact, a timed-out tool yields a typed ERROR, a tripped kill-switch refuses before traffic, and an
    out-of-scope target refuses before traffic."""
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
        spec = ffuf_content_scan(wordlist="")
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

    # The FACT half fails, by construction and on purpose — that IS the downgrade.
    assert report.checks.get("positive_fact") is False, (
        f"{tool}: the battery minted a FACT on a LEAD-only branch: {report.summary()}")
    assert report.checks.get("positive_verified_offline") is False
    assert not report.conformant, (
        f"{tool}: the battery reports CONFORMANT while the branch is LEAD-only — the gate the matrix "
        f"depends on has stopped gating: {report.summary()}")
    # Every SAFETY property still holds.
    for prop in sorted(REQUIRED_PROPERTIES - {"positive_fact", "positive_verified_offline"}):
        assert report.checks.get(prop) is True, f"{tool}: {prop} not satisfied: {report.summary()}"


# ===================================================================================================
# SAFETY (RP4 BLOCK-5): a brain/params-supplied VALUE must never reach an argv unvalidated.
# ===================================================================================================
def test_a_hostile_scheme_or_wordlist_is_refused_before_any_argv_or_send(monkeypatch, tmp_path):
    """The ScopeGate authorises the HOST STRING and the runner then EXECUTES the argv, so a scheme that
    carries its own authority — ``http://attacker.test/x#`` — put a packet on an OUT-OF-SCOPE host before
    the FACT-side host pin could refuse anything: ``httpx -u http://attacker.test/x#://127.0.0.1/``. The
    same argv seam takes ``wordlist``. Both must be refused at ToolSpec construction, BEFORE any argv
    exists and therefore before any send, and the brain path must turn that refusal into a blocked LEAD."""
    from vigil_integration.brains.hexstrike_body import _spec_for_kind
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan

    hostile_schemes = ["http://attacker.test/x#", "https://evil", "file", "javascript",
                       "http\nx", "http://127.0.0.1@evil.test", "ht tp", ""]
    for bad in hostile_schemes:
        with pytest.raises(ValueError):
            httpx_url_scan(scheme=bad)
        with pytest.raises(ValueError):          # ... and through the brain seam the body actually uses
            _spec_for_kind("httpx", {"scheme": bad})
    hostile_wordlists = ["/etc/passwd", "-u", "--help", "/usr/share/wordlists/../../etc/shadow",
                         "/usr/share/wordlists/a b.txt", "/usr/share/wordlists/x;id", "relative.txt",
                         "/usr/share/wordlists/$(id)"]
    for bad in hostile_wordlists:
        with pytest.raises(ValueError):
            ffuf_content_scan(wordlist=bad)
        with pytest.raises(ValueError):
            _spec_for_kind("ffuf", {"wordlist": bad})
    # the legitimate values still build, and the argv they build has exactly ONE authority — the target.
    argv = httpx_url_scan(scheme="https").build_argv("127.0.0.1")
    assert argv[argv.index("-u") + 1] == "https://127.0.0.1/"
    assert sum(tok.count("://") for tok in argv) == 1
    argv = ffuf_content_scan(wordlist="/usr/share/wordlists/dirb/common.txt").build_argv("127.0.0.1")
    assert argv[argv.index("-u") + 1] == "http://127.0.0.1/FUZZ"
    assert argv[argv.index("-w") + 1] == "/usr/share/wordlists/dirb/common.txt"
    assert sum(tok.count("://") for tok in argv) == 1
    # and the default (no params at all) is still buildable through the brain seam.
    assert _spec_for_kind("httpx", {}) is not None and _spec_for_kind("ffuf", {}) is not None


# ===================================================================================================
# OPSEC + OFFENSIVE-DRIFT (constitution §VI). These ship even though the branch is only a LEAD: they are
# about the traffic VIGIL puts on the operator's own production, not about what it concludes.
# ===================================================================================================
def test_the_r4_httpx_spec_pins_the_correlatable_user_agent():
    """CONSTITUTION §VI.4 — "Make yourself correlatable ... you are not evading them".

    httpx's own ``-random-agent`` DEFAULTS TRUE, so an argv that does not pin a User-Agent sends every
    probe under a randomly chosen BROWSER identity. That is identity rotation, which this project forbids
    outright, and it is invisible precisely because it is a DEFAULT rather than a flag anyone wrote. The
    governed executor already fixed and documented exactly this defect; the R4 runner spec shipped without
    it. Pin the header, pin that it is the SAME identity the rest of the engine sends, and pin that no
    random-agent behaviour can be requested."""
    from vigil_integration.live.executor import _CORRELATABLE_USER_AGENT as _GOVERNED_UA
    from vigil_integration.live.external_tool import _CORRELATABLE_USER_AGENT as _R4_UA
    from vigil_integration.live.external_tool import httpx_url_scan

    assert _R4_UA == _GOVERNED_UA == "OBSIDIAN/1.0 (authorized owner-test)", (
        "the R4 runner and the governed executor must present ONE identity, not two")
    argv = httpx_url_scan().build_argv("127.0.0.1")
    assert "-H" in argv, f"the httpx argv sends no User-Agent header at all: {argv}"
    assert argv[argv.index("-H") + 1] == f"User-Agent: {_R4_UA}", argv
    # an explicit -H overrides httpx's random agent; nothing may ask for the random one back.
    assert "-random-agent" not in argv, argv
    for tok in argv:
        assert "random" not in tok.lower(), f"the argv mentions a random identity: {tok!r}"
    # the https spec pins it too (the scheme must not be able to drop the header)
    assert "-H" in httpx_url_scan(scheme="https").build_argv("127.0.0.1")


def test_the_httpx_user_agent_pin_is_structural_not_merely_positional():
    """The UA pin must survive a CALLER, not just the default argv (red-pen advisory A).

    ``build_argv`` APPENDS ``extra_args`` AFTER the pinned ``-H User-Agent: …``, so before this the pin was
    only POSITIONALLY safe: ``extra_args=("-random-agent",)`` turns httpx's identity rotation back on, and
    ``extra_args=("-H", "User-Agent: Mozilla/5.0")`` sets a SECOND User-Agent header that WINS. Either one
    silently defeats constitution §VI.4. Nothing reaches ``extra_args`` on today's brain seam (only
    ``scheme``/``wordlist`` are threaded), which is exactly why this has to be enforced STRUCTURALLY — at
    ToolSpec CONSTRUCTION, before any argv or any packet exists — rather than left to the call sites."""
    import pytest as _pytest
    from vigil_integration.live.external_tool import _CORRELATABLE_USER_AGENT, httpx_url_scan

    for banned in (("-random-agent",), ("--random-agent",), ("-silent", "-random-agent")):
        with _pytest.raises(ValueError, match="random-agent"):
            httpx_url_scan(extra_args=banned)
    for shadow in (("-H", "User-Agent: Mozilla/5.0"),
                   ("-header", "user-agent: curl/8"),
                   ("--header", "  User-Agent: x  "),
                   ("-H=User-Agent: Mozilla/5.0",),
                   ("-silent", "-H", "User-Agent: Mozilla/5.0")):
        with _pytest.raises(ValueError, match="second User-Agent"):
            httpx_url_scan(extra_args=shadow)
    # a NON-UA header and other benign flags still build, and the pin is still the ONLY User-Agent.
    argv = httpx_url_scan(extra_args=("-H", "X-Trace: 1", "-silent")).build_argv("127.0.0.1")
    uas = [argv[i + 1] for i, t in enumerate(argv[:-1]) if t == "-H"
           and argv[i + 1].lower().startswith("user-agent:")]
    assert uas == [f"User-Agent: {_CORRELATABLE_USER_AGENT}"], argv
    assert "X-Trace: 1" in argv and "-silent" in argv, argv
    # and the refusal happens at CONSTRUCTION — no ToolSpec, therefore no argv, therefore no packet.
    with _pytest.raises(ValueError):
        httpx_url_scan(scheme="https", extra_args=("-random-agent",))


def test_the_r4_ffuf_spec_pins_maxtime_so_a_sigkill_cannot_lose_the_report():
    """ffuf writes its results ONCE, when the job ends, and the runner kills an over-running subprocess
    with SIGKILL, which ffuf cannot catch — the governed executor measured a 400k-entry wordlist under
    `timeout -s KILL` producing NO output at all, byte-identical to "ffuf never ran". ``-maxtime`` makes it
    exit cleanly with what it has. The bound must also fit inside the runner's own default wall clock,
    otherwise it is decorative."""
    from vigil_integration.live.external_tool import _DEFAULT_TIMEOUT, _FFUF_MAX_TIME, ffuf_content_scan

    argv = ffuf_content_scan(wordlist="").build_argv("127.0.0.1")
    assert "-maxtime" in argv, f"ffuf may outrun the wall clock and lose its whole report: {argv}"
    assert argv[argv.index("-maxtime") + 1] == str(_FFUF_MAX_TIME)
    assert 0 < _FFUF_MAX_TIME <= _DEFAULT_TIMEOUT, (
        f"an in-tool budget ({_FFUF_MAX_TIME}s) at or past the runner's wall clock "
        f"({_DEFAULT_TIMEOUT}s) is decorative — the SIGKILL still wins")


def test_the_runner_caps_re_driven_proposals_against_a_documented_request_budget(monkeypatch, tmp_path):
    """CONSTITUTION §VI.1 — "Don't break their production. Throttle."

    The web leg re-drives EVERY url a discovery tool proposed, each re-drive costing up to
    MAX_GATED_GETS_PER_URL SERIAL gated GETs with no inter-request delay. Uncapped, one ffuf run that
    proposed 200 paths is ~12,600 requests at a production target from one source IP as fast as it will
    answer. Cap the proposals against a reviewed per-run request BUDGET, derive the cap from the budget so
    the two cannot drift, and make the truncation VISIBLE — a cap a consumer cannot see is
    indistinguishable from a tool that found nothing."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.external_tool import (
        _LIVENESS_REQUEST_BUDGET, _max_redriven_proposals, ffuf_content_scan, run_external_tool)
    from vigil_integration.live.web_redrive import MAX_GATED_GETS_PER_URL
    signers, _ = _signers_and_trust()

    cap = _max_redriven_proposals()
    assert cap >= 1
    assert cap * MAX_GATED_GETS_PER_URL <= _LIVENESS_REQUEST_BUDGET, (
        "the cap must be DERIVED from the budget: proposals x worst-case-per-url must fit inside it")

    srv = _serve(_CorrectApp)                       # every unknown path hard-404s: cheap per re-drive
    port = srv.server_address[1]
    n = cap + 7
    report = json.dumps({"results": [{"input": {"FUZZ": f"p{i:04d}"}, "status": 404,
                                      "url": f"http://127.0.0.1:{port}/p{i:04d}", "host": "127.0.0.1"}
                                     for i in range(n)], "config": {}})
    try:
        res = run_external_tool(ffuf_content_scan(wordlist=""), "127.0.0.1",
                                scope_gate=_scope_gate(["127.0.0.1"]),
                                backend=_CannedBackend(report), engagement_slug="alpha",
                                signers=signers, timeout=30.0)
    finally:
        srv.shutdown()
    assert len(res.proposed) == n, "every proposal is still RECORDED — the cap throttles, it does not hide"
    # exactly `cap` urls were re-driven, and the rest were skipped LOUDLY.
    redriven = [o for o in res.outcomes if "#sibling_response_differential" in str(o.get("check_id", ""))]
    assert len(redriven) == cap, f"re-drove {len(redriven)} url(s), budget admits {cap}"
    assert res.truncated_proposals == n - cap
    assert res.budget_note and "OPSEC CAP" in res.budget_note
    assert "SKIPPED" in res.budget_note and "NOT examined" in res.budget_note
    assert res.budget_note in res.reason, "the truncation must be visible in the run's own detail"
    skipped = [o for o in res.outcomes if o.get("outcome") == "skipped"]
    assert len(skipped) == 1 and "budget" in skipped[0]["check_id"], res.outcomes


# ===================================================================================================
# Two operator surfaces AGREE: the capability matrix and the body's oracle-mapped set both say
# httpx + ffuf are LEAD-ONLY web-discovery tools whose re-drive is a LEAD ENRICHER.
# ===================================================================================================
def test_two_surfaces_agree_httpx_ffuf_are_lead_only_web_discovery():
    from vigil_integration.brains.hexstrike_body import (
        _LEAD_ENRICHER_TOOLS, _ORACLE_MAPPED_TOOLS, _RUNNER_DISPATCHED_TOOLS, _spec_for_kind)
    from vigil_integration.live.oracle_families import SPEC_BUILDER_TOOLS, family_for
    from vigil_integration.live.tool_manifest import load_manifests

    root = Path(__file__).resolve().parents[2]
    matrix = root / "docs" / "capability-matrix" / "hexstrike.json"
    by = {m.name: m for m in load_manifests(str(matrix))}
    # the two sets are disjoint by construction: a tool may mint, or it may enrich, never both.
    assert not (_ORACLE_MAPPED_TOOLS & _LEAD_ENRICHER_TOOLS)
    for tool in ("httpx", "ffuf"):
        # surface 1 — the capability matrix
        assert not by[tool].fact_capable, f"{tool}: the matrix must NOT mark it fact_capable"
        # surface 2 — the body: NOT oracle-mapped, but still DISPATCHED as a lead enricher, and absent
        # from the SSOT that derives "can mint a FACT".
        assert tool not in _ORACLE_MAPPED_TOOLS and tool not in SPEC_BUILDER_TOOLS
        assert tool in _LEAD_ENRICHER_TOOLS and tool in _RUNNER_DISPATCHED_TOOLS
        assert family_for(tool).name == "web_discovery"
        # the evidence pipeline is KEPT: the spec still builds and still carries the url re-drive.
        spec = _spec_for_kind(tool, {})
        assert spec is not None and spec.name == tool and spec.propose_urls is not None


def test_the_body_still_dispatches_the_lead_enrichers_to_the_gated_runner():
    """Removing httpx/ffuf from the FACT-mapping SSOT must NOT delete the evidence pipeline: the body's
    dispatch set is ``_ORACLE_MAPPED_TOOLS | _LEAD_ENRICHER_TOOLS``, so the two tools still reach the R4
    gated runner (and therefore the gated GETs, both cohorts and the retained capture). Proved by the
    REASON the body gives: an un-provisioned runner must fail on the RUNNER, not on membership — a
    "no oracle-mapped ToolSpec" refusal here would mean the pipeline had been silently deleted."""
    from framework.v2.agent_body.interface import GateDecision, ProposedAction
    from vigil_integration.brains.hexstrike_body import HexstrikeAgentBody

    body = HexstrikeAgentBody(posture="staging")     # deliberately NO RunnerDeps
    for tool in ("httpx", "ffuf"):
        out = body.execute(ProposedAction(kind=tool, target="127.0.0.1", params={"danger": "recon"}),
                           GateDecision(authorized=True))
        assert out.executed is False
        assert "runner not provisioned" in out.blocked_reason, (
            f"{tool}: the body refused for the WRONG reason ({out.blocked_reason!r}) — the LEAD-ENRICHER "
            f"dispatch is gone, and the whole evidence pipeline with it")
    # ... while a tool with neither a mint nor an enricher role is still refused on membership.
    out = body.execute(ProposedAction(kind="whatweb", target="127.0.0.1", params={"danger": "recon"}),
                       GateDecision(authorized=True))
    assert "no oracle-mapped ToolSpec" in out.blocked_reason
