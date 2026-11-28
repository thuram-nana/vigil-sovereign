"""Edge integration: the central request-boundary sanitizer wired into the PUBLIC plane (``pubui``).

The one same-origin access-request POST runs the same ``input_safety`` pass (defense-in-depth ON TOP of
``trust_access_requests_store.validate``, which keeps doing the authoritative length / format / control-char
validation). These tests prove, through the real HTTP path, that:

  * dangerous characters (zero-width / bidi) in an access field are stripped before the request is recorded, so the
    stored record holds clean text;
  * a JSON-bomb body is refused with a 4xx and nothing is stored.

The CRLF header-injection guard stays the store's job (``\\r`` / ``\\n`` are ordinary whitespace the sanitizer keeps),
so this file also pins that the two layers compose without conflict.

Dangerous characters are written as ``\\u`` escapes (never raw in source — ruff PLE2502 / Trojan-Source).
"""
from __future__ import annotations

import http.client
import json
import threading
import time

from sigil.ui import trust_access_requests_store as store
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.pubui import build_public_server

_GOOD = {"full_name": "Dana Okoro", "organisation": "Acme Security GmbH",
         "email": "dana.okoro@acme-security.example", "job_title": "Head of Security",
         "reason": "Vendor security review ahead of a procurement decision."}


def _loose_limiter(tmp):
    return LoginRateLimiter(tmp, max_fails=1000, window_s=3600, base_lock_s=1, max_lock_s=1)


def _serve(*, access_requests_dir, access_limiter):
    srv = build_public_server(host="127.0.0.1", port=0, access_requests_dir=access_requests_dir,
                              access_limiter=access_limiter)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _post(port, body, *, ctype="application/json"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": f"127.0.0.1:{port}", "Content-Type": ctype, "Accept": "application/json",
         "Origin": f"http://127.0.0.1:{port}"}
    conn.request("POST", "/api/trust/access-request", body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    out = (r.status, data)
    conn.close()
    return out


def test_access_fields_are_sanitized_before_recording(tmp_path):
    reqdir = tmp_path / "req"
    srv, port = _serve(access_requests_dir=reqdir, access_limiter=_loose_limiter(tmp_path / "lim"))
    try:
        payload = dict(_GOOD,
                       organisation="Ac\u200bme Security GmbH",     # zero-width
                       full_name="Dana\u202e Okoro",                # bidi override
                       job_title="Head of\u200d Security")          # zero-width joiner
        code, data = _post(port, json.dumps(payload))
        assert code == 200, (code, data)
        assert json.loads(data)["ok"] is True
        assert store.pending_count(reqdir) == 1
    finally:
        srv.shutdown()
    rec = json.loads(next(reqdir.glob("*.json")).read_text(encoding="utf-8"))
    # the dangerous characters are gone; the real text survives
    assert rec["organisation"] == "Acme Security GmbH"
    assert rec["full_name"] == "Dana Okoro"
    assert rec["job_title"] == "Head of Security"


def test_crlf_header_injection_still_rejected_by_the_store(tmp_path):
    # the sanitizer keeps \r / \n (ordinary whitespace); the store's single-line validation is what refuses a CRLF
    # header-injection attempt — the two layers compose, neither masks the other.
    reqdir = tmp_path / "req"
    srv, port = _serve(access_requests_dir=reqdir, access_limiter=_loose_limiter(tmp_path / "lim"))
    try:
        payload = dict(_GOOD, organisation="Acme\r\nBcc: evil@x")
        code, data = _post(port, json.dumps(payload))
        assert code == 400, (code, data)
        assert json.loads(data)["fields"].get("organisation")
        assert store.pending_count(reqdir) == 0
    finally:
        srv.shutdown()


def test_json_bomb_is_refused_and_nothing_stored(tmp_path):
    reqdir = tmp_path / "req"
    srv, port = _serve(access_requests_dir=reqdir, access_limiter=_loose_limiter(tmp_path / "lim"))
    try:
        node: dict = {}
        cur = node
        for _ in range(40):                 # far deeper than the public guard allows
            cur["a"] = {}
            cur = cur["a"]
        code, data = _post(port, json.dumps({**_GOOD, "nested": node}))
        assert 400 <= code < 500, (code, data)
        assert store.pending_count(reqdir) == 0
    finally:
        srv.shutdown()
