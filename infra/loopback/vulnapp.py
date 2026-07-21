"""
infra/loopback/vulnapp.py — the authorized LOOPBACK test target for VIGIL-LIVE (WS-0c).

A deliberately-but-SAFELY vulnerable HTTP app, stdlib-only, that binds 127.0.0.1 ONLY. It is genuinely
injectable in a CONTROLLED way so a live offensive tool (sqlmap/nuclei/ffuf/hydra) confirms a real vuln
AND the AEGIS Detection Mirror can prove the attack's signature from the two log files this app writes:

  * access.log — Common Log Format-ish, one line per request (recon / forced-browsing / scanner / SQLi /
    XSS / traversal signatures live here).
  * auth.log   — one line per /login attempt (brute-force / password-spray signatures live here).

Safety: it never reads real files, runs no real shell, and only serves an in-memory SQLite DB of FAKE
rows; a path-traversal attempt returns a DECOY passwd string (so the signature fires without leaking a
real file). Bind is hard-pinned to 127.0.0.1. This is a target, not a service — it wields nothing.

Run:  python3 infra/loopback/vulnapp.py --port 8080 --logdir /path/to/logs
"""

from __future__ import annotations

import argparse
import datetime
import html
import http.server
import os
import sqlite3
import threading
import urllib.parse

# Discoverable path tree — a mix of real (200) and absent (404) so forced-browsing/scanner oracles have
# a 404-rate + path-entropy signature to fire on.
_REAL_PATHS = {"/", "/index.html", "/about", "/search", "/file", "/login", "/api/users", "/robots.txt"}
_DECOY_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_VALID_CRED = ("admin", "secret123")   # the single valid loopback cred (fake)


def _now_clf() -> str:
    return datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z") or "10/Oct/2000:00:00:00 +0000"


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "vulnapp/1.0"
    protocol_version = "HTTP/1.1"

    # --- logging: every request → access.log (the Detection Mirror's edge telemetry) ---------------
    def _access(self, status: int, size: int) -> None:
        line = (f'{self.client_address[0]} - - [{_now_clf()}] "{self.requestline}" {status} {size} '
                f'"{self.headers.get("Referer", "-")}" "{self.headers.get("User-Agent", "-")}"\n')
        with self.server.access_lock:                       # type: ignore[attr-defined]
            with open(self.server.access_log, "a") as f:    # type: ignore[attr-defined]
                f.write(line)

    def _auth(self, user: str, result: str) -> None:
        line = f'{_now_clf()} src={self.client_address[0]} user={user} result={result}\n'
        with self.server.auth_lock:                         # type: ignore[attr-defined]
            with open(self.server.auth_log, "a") as f:      # type: ignore[attr-defined]
                f.write(line)

    def log_message(self, *args) -> None:   # silence the default stderr logger (we write our own)
        return

    def _send(self, status: int, body: str, ctype: str = "text/html") -> None:
        raw = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)
        self._access(status, len(raw))

    # --- routes ------------------------------------------------------------------------------------
    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)
        if path in ("/", "/index.html"):
            self._send(200, "<h1>VIGIL loopback target</h1><a href='/search?q=test'>search</a>")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n", "text/plain")
        elif path == "/about":
            self._send(200, "<p>A deliberately-vulnerable loopback app for VIGIL live validation.</p>")
        elif path == "/search":
            self._search(qs.get("q", [""])[0])
        elif path == "/file":
            self._file(qs.get("path", [""])[0])
        elif path == "/api/users":
            self._send(200, '[{"id":1,"user":"admin"},{"id":2,"user":"alice"}]', "application/json")
        else:
            self._send(404, f"<h1>404 Not Found</h1><p>{html.escape(path)}</p>")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/login":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            form = urllib.parse.parse_qs(body)
            user = form.get("username", form.get("user", [""]))[0]
            pw = form.get("password", form.get("pass", [""]))[0]
            if (user, pw) == _VALID_CRED:
                self._auth(user, "success")
                self._send(200, "<p>welcome admin</p>")
            else:
                self._auth(user or "-", "failure")
                self._send(401, "<p>invalid credentials</p>")
        else:
            self._send(404, "not found")

    # --- the (controlled) vulnerabilities ----------------------------------------------------------
    def _search(self, q: str) -> None:
        # GENUINE SQLi: string-concatenated query over a FAKE in-memory DB (sqlmap will confirm), plus a
        # reflected-XSS of q. Real signatures, zero real-data risk (the DB holds only test rows).
        con: sqlite3.Connection = self.server.db          # type: ignore[attr-defined]
        rows, err = [], ""
        try:
            cur = con.cursor()
            cur.execute("SELECT id, name FROM items WHERE name = '" + q + "'")   # noqa: S608 — intentional
            rows = cur.fetchall()
        except Exception as exc:   # a broken injection surfaces the SQL error (a real SQLi tell)
            err = f"SQL error: {exc}"
        body = (f"<h1>Results for: {q}</h1>"                          # reflected XSS (q unescaped)
                f"<ul>{''.join(f'<li>{r[0]}:{r[1]}</li>' for r in rows)}</ul>"
                f"{('<pre>' + html.escape(err) + '</pre>') if err else ''}")
        self._send(200, body)

    def _file(self, path: str) -> None:
        # A path-traversal surface that returns a DECOY on an escape attempt — the signature (../, encoded
        # dots, %2e, absolute /etc/passwd) fires for both the offensive and the detection oracle, but no
        # real file is ever read.
        low = path.lower()
        if ".." in low or "%2e" in low or low.startswith("/etc/") or "passwd" in low:
            self._send(200, _DECOY_PASSWD, "text/plain")   # decoy: proves the traversal, leaks nothing real
        elif path in ("readme", "readme.txt", ""):
            self._send(200, "This is the public readme.", "text/plain")
        else:
            self._send(404, "no such file")


def _build_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    con.executemany("INSERT INTO items VALUES (?,?)", [(1, "apple"), (2, "banana"), (3, "test")])
    con.commit()
    return con


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--logdir", default=os.path.join(os.path.dirname(__file__), "logs"))
    args = ap.parse_args()
    os.makedirs(args.logdir, exist_ok=True)

    srv = _Server(("127.0.0.1", args.port), _Handler)      # HARD-PINNED to loopback
    srv.db = _build_db()                                   # type: ignore[attr-defined]
    srv.access_log = os.path.join(args.logdir, "access.log")   # type: ignore[attr-defined]
    srv.auth_log = os.path.join(args.logdir, "auth.log")       # type: ignore[attr-defined]
    srv.access_lock = threading.Lock()                    # type: ignore[attr-defined]
    srv.auth_lock = threading.Lock()                      # type: ignore[attr-defined]
    print(f"vulnapp on http://127.0.0.1:{args.port}  logs={args.logdir}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
