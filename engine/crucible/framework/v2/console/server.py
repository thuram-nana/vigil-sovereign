"""
console.server — a loopback-only, credentialed HTTP server for the Ops Console.

Stdlib `ThreadingHTTPServer` bound to 127.0.0.1 ONLY (never a routable interface).
Serves the self-contained SPA from `static/`, a set of read-only `/api/*` JSON
endpoints (each delegating to `console.api`), and a Server-Sent-Events stream that
tails the structured log. It issues zero outbound calls and performs no destructive
action — a read-only console is inherently in-scope. Safe operator actions (launch /
re-verify / kill-switch trip) live behind explicit POST routes.

CREDENTIAL (the audit gap this closes): the console used to have NO credential of any
kind — every local process, and every page that could get past the Host/Origin guard,
could read findings, evidence, terminal history and dossiers. It now mints (or is
handed) a SESSION TOKEN and requires it on EVERY `/api/*` request, exactly as the
sovereign cockpit does (`apps/sigil/sigil/ui/server.py`): the header `X-SIGIL-Token`,
or `?token=` for the SSE streams and file downloads, which cannot set a header.
Compared with `hmac.compare_digest`. There is NO way to run without a credential —
an unset/blank `VIGIL_CONSOLE_TOKEN` MINTS one (fail-closed); it never disables the
check. Static assets and the index bootstrap stay token-free: they carry no secret,
and the token is injected into the served page as a data attribute a cross-origin
page cannot read. The CSRF / DNS-rebinding guards are unchanged and still apply —
the token is an ADDITIONAL conjunct, never a replacement.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

# S1 — per-action RBAC vocabulary. `vigil_core` is the ONE module both trust domains may import (the
# offense console already imports it in `console.api`); it is namespace-pure (no framework/strix/sigil), so
# this crosses no boundary and FATAL-2 holds. `offense_perm_for` maps a POST route to its required
# permission (None ⇒ unmapped ⇒ default-deny) and `role_can` is the same predicate the sovereign gate uses.
from vigil_core.rbac import offense_perm_for, role_can


# X6 — a custom request header the same-origin SPA fetch sets and a cross-site HTML form cannot.
_CSRF_HEADER = "X-Requested-With"
# The session credential. Header form (SPA fetch) + query form (EventSource / <a download>, which
# physically cannot set a request header) — the same two carriers the sovereign cockpit accepts.
_TOKEN_HEADER = "X-SIGIL-Token"
_TOKEN_QUERY = "token"
# The placeholder the served index.html carries; substituted with the live token per response so the
# same-origin page can authenticate. A cross-origin page cannot read the response body, so this is
# the cockpit's own bootstrap pattern, not a leak.
_TOKEN_PLACEHOLDER = "__CONSOLE_TOKEN__"
# Env carrier: `vigil up` hands the console the SAME token it embeds in the unified UI's index.html,
# so one credential covers both planes. Blank/unset ⇒ the console MINTS its own (never "no auth").
_TOKEN_ENV = "VIGIL_CONSOLE_TOKEN"

# S1 — the proxy↔console per-request role assertion. The `vigil up` proxy is the per-user auth boundary:
# it resolves the caller against the sovereign accounts spine and STAMPS `X-VIGIL-Role` on the offense hop.
# Because the session TOKEN is SHARED with the proxy, token-presence alone cannot tell a genuine proxy hop
# from a direct loopback client that also holds the token — so the proxy also binds the stamped identity
# under a DISTINCT hop secret (`VIGIL_CONSOLE_HOP_KEY`, random per `vigil up`, handed to this console child
# at spawn, never to the browser). Only a request carrying a VALID, FRESH HMAC over
# `principal\nrole\nmethod\npath\nts` under that key has its `X-VIGIL-Role` trusted for per-action RBAC. A
# request with NO role assertion at all is a direct token-holder (owner-equivalent — it holds the shared
# console credential) and keeps full access (no regression). A blank/unset hop key ⇒ NO stamped role is
# ever trusted (fail-closed: the RBAC hop is simply absent, the coarse floors still apply).
_PRINCIPAL_HDR = "X-VIGIL-Principal"
_ROLE_HDR = "X-VIGIL-Role"
_ROLE_SIG_HDR = "X-VIGIL-Role-Sig"
_ROLE_TS_HDR = "X-VIGIL-Role-Ts"
_HOP_KEY_ENV = "VIGIL_CONSOLE_HOP_KEY"
_HOP_MAX_SKEW_S = 30.0          # a role assertion older/newer than this is refused (replay window closed)
# A9: bound the POST body — the console's actions take small JSON; a huge/negative Content-Length must not be
# read into memory. A body above the cap is refused (treated as empty → the action gets no valid params).
_MAX_CONSOLE_BODY = 1 << 20   # 1 MiB

# Strict Content-Security-Policy (mirrors the sovereign cockpit). Self-contained assets only; no inline
# script/style trust, no external origins, un-framable. Sent on EVERY response (reads + SSE + actions).
_CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


def _is_loopback_host(host: str) -> bool:
    """True for a genuine loopback host: the name ``localhost`` or ANY loopback IP —
    127.0.0.0/8 (not just 127.0.0.1) and every IPv6 loopback form (``::1``, expanded,
    bracketed). Rejects a routable host / a DNS-rebinding domain."""
    h = (host or "").strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False

from . import actions, api, chat, labels, sessions
from .blackboard_sse import BlackboardTailer
from .sse import EventTailer, stream_path


def _resolve_token(explicit: str | None = None) -> str:
    """The console's session credential. Order: an explicit argument → ``$VIGIL_CONSOLE_TOKEN`` → a
    freshly minted 256-bit URL-safe token.

    FAIL-CLOSED BY CONSTRUCTION: this never returns an empty string, so there is no configuration —
    not an unset env var, not a blank one, not a missing flag — under which the console serves
    ``/api/*`` without a credential. (An earlier design where "" meant "auth disabled" would be a
    fail-open switch one typo away from the audit gap we are closing.)"""
    for candidate in (explicit, os.environ.get(_TOKEN_ENV)):
        tok = (candidate or "").strip()
        if tok:
            return tok
    return secrets.token_urlsafe(32)


def _resolve_hop_key() -> str:
    """The proxy↔console hop secret from `$VIGIL_CONSOLE_HOP_KEY`, or "" if unset. UNLIKE the session token
    this is NEVER minted: it must be the SAME value the proxy holds (shared out-of-band via the child's env),
    so a minted-here value could never verify. Blank ⇒ the console trusts NO stamped role (fail-closed) — a
    proxy-forwarded per-user request cannot be role-verified and is refused; only the direct token-holder
    (no role assertion) path stays open."""
    return (os.environ.get(_HOP_KEY_ENV) or "").strip()

STATIC_DIR = Path(__file__).resolve().parent / "static"

_CTYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".ico": "image/x-icon",
    ".map": "application/json; charset=utf-8",
}

# Read-only GET routes: exact path -> zero-arg api provider.
_EXACT_ROUTES = {
    "/api/status": api.status_data,
    "/api/engagements": api.list_engagements,
    "/api/sessions": api.sessions_list,
    "/api/benchmark": api.benchmark_data,
    "/api/memory": api.memory_data,
    "/api/kernel": api.kernel_data,
    "/api/tools": api.tools_data,
    "/api/toolprofiles": api.tool_profiles_data,
    "/api/capabilities": api.capabilities_data,
    "/api/aegis/status": api.aegis_status,
    "/api/feed/status": api.feed_status,        # K1: read-only vuln-feed schedule/egress posture
    "/api/telemetry": api.telemetry,            # G2: live assurance/metrics snapshot over the signed spine
    "/api/terminal/history": actions.terminal_history,   # T2: recent signed terminal.run records (read-only)
    "/api/certs": api.certs,                    # Trust Center: signed offline-verifiable certificates (metadata only)
    "/api/posture": api.posture,                # Proof of Posture: signed Certificate(s) of Non-Exploitability (metadata only)
    "/api/brain/decision": api.brain_decision,  # Brain: the propose-only decision engine + its live proposal (if any)
    "/api/governance": api.governance_data,     # Governance & Gate audit: READ-ONLY posture + m-of-n destruction quorum
    "/api/mcp": api.mcp_data,                    # MCP: the gated capabilities exposed over the stdio MCP server (read-only)
    "/api/services": api.services_data,          # System: readiness (venvs/dirs/ports/binaries) + docker-service state (read-only)
    "/api/token-budgets": api.token_budgets_data,  # Token Budgets: per-tool daily token caps + today's usage (read-only)
}

# Read-only GET routes that take ONE optional `?slug=` ENGAGEMENT SCOPE: exact path -> provider
# taking that slug. This is the console's active-engagement scope (the operator's current job), and it
# is a FILTER, not an assertion: the provider selects among the engagement each run RECORDED FOR
# ITSELF, so a caller can never claim a run into an engagement it does not belong to. An absent/blank
# `?slug=` is the unscoped listing, byte-identical to the zero-arg call these routes had before; an
# unknown slug is an honest empty list, never an error and never the unfiltered list.
_SCOPED_ROUTES = {
    "/api/runs": api.list_runs,
}

# Prefixed GET routes: "/api/<name>/<arg>" -> api provider taking one string arg.
# NB (A6 / B7 cleanup): the unified UI calls `/api/engagements` (plural, list) and `/api/report/<run>`
# (singular), never `/api/engagement/`, `/api/reports/`, `/api/session/<id>`, or `/api/authority/<slug>` —
# those had zero unified-UI GET callers (only the retired per-plane SPA), so their HTTP surface is dropped.
# The PROVIDERS REMAIN + keep their unit tests and their INTERNAL callers: api.session_detail is used by the
# dossier/report assembly (actions.py) and api.authority_full by charter_status + framework.v2.api.reads; the
# unified UI reaches the same governance picture via `/api/charter/<slug>` (charter_status), not authority_full.
_PREFIX_ROUTES = {
    "/api/library/": api.library_engagement,    # the engagement library: one past job + its runs (newest first)
    "/api/inbox/": api.inbox,                   # U3: read-only agent-to-agent coordination messages (advisory)
    "/api/approvals/": api.approvals,           # A2: read-only pending per-action owner-approval requests (KEYLESS — lists only, never signs)
    "/api/report/": api.run_report,
    "/api/worldmodel/": api.worldmodel,
    "/api/coverage/": api.coverage_data,
    "/api/charter/": api.charter_status,        # the remote-charter picture (scope, loopback-only?, ceremony)
    "/api/planner/": api.planner_data,
    "/api/intel/": api.intel_data,
    "/api/vulnintel/": api.vulnintel_data,
    "/api/evolve/": api.evolve_data,
    "/api/compliance/": api.compliance_data,
    "/api/drift/": api.drift_data,
    "/api/evidence/": api.evidence,
    "/api/proof/": api.proof_list,
    "/api/remediate/": api.remediate_plan,
    "/api/toolresearch/": api.tool_research_data,
}

# CHUNKED-UPLOAD POST routes: exact path -> the chat handler taking the JSON body.
# The console's POST body cap is 1 MiB and is NOT raised, so a zip / file / image arrives in pieces:
# begin (open an upload) → chunk × N (a base64 slice each, bounded well inside the cap) → finish (assemble,
# digest, extract, return the manifest). These are dispatched inside `do_POST` AFTER the same same-origin
# conjunction + session token every other POST passes — there is no second, weaker path — and they use the
# DRAINING body reader, so an oversize chunk is a clean 400 instead of a silently-empty body.
_CHAT_ATTACH_POST = {
    "/api/chat/attach/begin": chat.attach_begin,
    "/api/chat/attach/chunk": chat.attach_chunk,
    "/api/chat/attach/finish": chat.attach_finish,
    # `abort` drops an upload still in flight. `remove` takes a FINISHED attachment back off the chat,
    # and it is a real deletion rather than a list edit: a chat turn reasons over everything the chat
    # still holds, so an attachment the operator removed from the screen but that the store kept would
    # keep going to the model on every later turn while the interface said it was gone.
    "/api/chat/attach/abort": chat.attach_abort,
    "/api/chat/attach/remove": chat.attach_remove,
    # chat management (same same-origin + token conjunction as every other POST). `rename` appends a custom
    # title (append-only meta record; unknown chat / empty title → ValueError → 404). `delete` removes the
    # transcript + its staged attachments + the registry entry (idempotent).
    "/api/chat/rename": chat.rename,
    "/api/chat/delete": chat.delete,
}


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "CrucibleConsole/0.1"

    # keep the console quiet — no request logging noise on the operator's terminal
    def log_message(self, *_args) -> None:  # noqa: D401
        return

    # ---- response helpers -------------------------------------------------

    def _sec_headers(self) -> None:
        """Strict security headers on every response (parity with the sovereign cockpit)."""
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._sec_headers()
        self.end_headers()
        self.wfile.write(body)

    def _static(self, rel: str) -> None:
        # map the URL onto STATIC_DIR: "/" -> index.html, "/static/x" -> x
        rel = rel.lstrip("/")
        if rel.startswith("static/"):
            rel = rel[len("static/"):]
        if rel in ("", "index.html"):
            rel = "index.html"
        target = (STATIC_DIR / rel).resolve()
        # path-traversal guard: the resolved file must stay under STATIC_DIR
        if STATIC_DIR not in target.parents and target != STATIC_DIR:
            self._json({"error": "not found"}, status=404)
            return
        if not target.is_file():
            self._json({"error": "not found"}, status=404)
            return
        body = target.read_bytes()
        if target.name == "index.html":
            # Bootstrap the same-origin page with the session token (the cockpit's own pattern): the
            # page can then authenticate its /api/* calls. A cross-origin page cannot read this body,
            # and the token never lands in a log line (log_message is silenced above).
            body = body.replace(_TOKEN_PLACEHOLDER.encode("utf-8"),
                                self.server.token.encode("utf-8"))
        self.send_response(200)
        self.send_header("Content-Type", _CTYPES.get(target.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        # The strict `'self'` CSP is deliberately NOT sent on these STATIC (HTML/SPA) responses: this dir
        # still serves the LEGACY console SPA (inline handlers/styles/data: icons) that strict CSP would
        # break. The strict CSP belongs to the CSP-clean unified bundle (packages/vigil-ui) — served by the
        # `vigil up` reverse proxy (which sets the canonical CSP) or once that bundle retires this SPA. Data
        # responses (_json/_sse) DO carry the CSP as harmless defense-in-depth (JSON/events render nothing).
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, path, *, allow_replay: bool = False, from_start: bool = False) -> None:
        """Stream a run's progress log. By default the tailer starts at EOF (live follow). With
        ``from_start`` it replays the file from byte 0 first — needed for a run that has ALREADY finished,
        whose whole record is in the file and would otherwise stream nothing at all (a viewer would see an
        empty screen and a "0 refusals" tile for a run that was blocked ten times). Read-only either way.

        A REPLAYING stream (``from_start``, or a reconnect carrying ``Last-Event-ID``) additionally stamps
        each event with an ``id:`` line + a ``_seq`` payload field — its ordinal among the PARSEABLE events
        in the log (blank and malformed lines are skipped by the tailer, so this is NOT a raw line number) — so the reconnect resumes instead of re-delivering. Without that cursor a replaying
        stream re-counts every event on each reconnect, turning the tiles it exists to fill into a
        FABRICATED total ("Refusals 9" for three blocks) — no better than the fabricated zero.

        The plain live tail deliberately keeps NO cursor and opens at EOF, exactly as it always has:
          * cost — a cursor implies reading and parsing the WHOLE file on every connection (order
            hundreds of MB of peak allocation for a multi-tens-of-MB log; the wall time is
            machine-dependent), which a tail that was never going to emit those events must not pay,
            once per connection, per reconnect, per open stream;
          * correctness — ``EventTailer`` restarts from byte 0 when the file is truncated or ROTATED
            (``common.logging`` rotates the engagement log at 64MB). A monotonic counter cannot survive
            that: ids would continue past the new file's length, and the next reconnect would suppress
            every genuinely-new event, permanently. A cursorless tail simply resumes tailing.
        So the cursor is scoped to replay, where the file is a per-run progress log that does not rotate."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._sec_headers()
        self.end_headers()
        try:
            delivered = max(0, int(self.headers.get("Last-Event-ID") or 0))
        except (TypeError, ValueError):
            delivered = 0
        # BOTH doors into replay are gated by `allow_replay`, not just the query flag. `Last-Event-ID` is
        # a REQUEST HEADER, so gating only `from_start` left the whole replay path — the whole-file read
        # AND the counter that cannot survive a rotation — reachable on any stream with one header. A
        # non-replayable stream ignores the cursor entirely and stays a pure tail.
        replay = bool(allow_replay and (from_start or delivered))
        # Replay reads from the top and numbers what it emits; a live tail opens at EOF and numbers
        # nothing — byte-for-byte the pre-cursor behaviour, at the pre-cursor cost.
        tailer = EventTailer(path, from_end=not replay)
        seq = 0
        last_beat = time.monotonic()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                for ev in tailer.read_new():
                    if not replay:
                        payload = json.dumps(ev, ensure_ascii=False, default=str)
                        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                        continue
                    seq += 1
                    if seq <= delivered:
                        continue          # this client already has it — never re-deliver, never re-count
                    if isinstance(ev, dict):
                        # Always overwrite: a producer-supplied _seq would DISAGREE with the id:
                        # we emit, and both UI consumers dedup on _seq — a repeated value would
                        # silently suppress genuine rows. Payload and cursor must be one number.
                        ev = {**ev, "_seq": seq}
                    payload = json.dumps(ev, ensure_ascii=False, default=str)
                    self.wfile.write(f"id: {seq}\ndata: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                now = time.monotonic()
                if now - last_beat > 15:
                    self.wfile.write(b": ping\n\n")  # heartbeat keeps the socket open
                    self.wfile.flush()
                    last_beat = now
                time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return  # client navigated away — end the stream quietly

    def _sse_blackboard(self, slug: str, since: int) -> None:
        """SSE over one engagement's append-only blackboard spine (the Live view's 14-kind
        timeline). Each event is emitted with an ``id:`` line so an EventSource reconnect resumes
        from ``Last-Event-ID`` — a durable cursor. Read-only; the blackboard stays append-only."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._sec_headers()
        self.end_headers()
        tailer = BlackboardTailer(slug, since_id=since)
        last_beat = time.monotonic()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                for event_id, ev in tailer.read_new():
                    payload = json.dumps(ev, ensure_ascii=False, default=str)
                    self.wfile.write(f"id: {event_id}\ndata: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                now = time.monotonic()
                if now - last_beat > 15:
                    self.wfile.write(b": ping\n\n")  # heartbeat keeps the socket open
                    self.wfile.flush()
                    last_beat = now
                time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        finally:
            tailer.close()

    # ---- routing ----------------------------------------------------------

    def _token_ok(self) -> bool:
        """The session credential on THIS request: the ``X-SIGIL-Token`` header, or ``?token=`` for
        the carriers that cannot set a header (EventSource, an ``<a download>`` navigation). Compared
        in constant time. Fail-closed: a missing/blank/wrong token is False."""
        q = parse_qs(urlsplit(self.path).query)
        tok = self.headers.get(_TOKEN_HEADER) or (q.get(_TOKEN_QUERY) or [""])[0]
        expected = getattr(self.server, "token", "") or ""
        if not tok or not expected:
            return False
        return hmac.compare_digest(str(tok), str(expected))

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        parts = urlsplit(self.path)
        path = parts.path
        # A9: DNS-rebinding defense for READ routes — a rebinding page (attacker.com re-resolving to
        # 127.0.0.1) sends its OWN Host, so a Host that does not name the loopback console (or an allowlisted
        # proxy domain) is refused before ANY status/runs/findings/event-stream/terminal/dossier data is read.
        ok, why = self._host_is_console()
        if not ok:
            self._json({"error": f"cross-origin read refused ({why})"}, status=403)
            return
        # The session credential gates every DATA route (JSON, SSE and the dossier download alike).
        # Static bootstrap assets stay token-free — they carry no secret, and index.html is where the
        # token is handed to the same-origin page. This is checked BEFORE any provider runs, so an
        # unauthenticated caller learns nothing about the tree (not even whether a run id exists).
        if path.startswith("/api/") and not self._token_ok():
            self._json({"error": "missing/invalid token"}, status=401)
            return
        try:
            if path.startswith("/api/events"):
                q = parse_qs(parts.query)
                run_q = (q.get("run") or [None])[0]
                slug_q = (q.get("slug") or [None])[0]
                # Replay (from_start OR a Last-Event-ID resume) is honoured for a RUN only. `run` is
                # validated (_safe_run_id) whereas `slug` indexes straight into targets_root(), so a replay
                # there would emit the whole contents of a file addressed by an unvalidated name — and put
                # a ROTATING log into cursor mode, whose counter cannot survive the rotation. Gating only
                # the query flag left the header as a second, ungated door. No caller needs it: the UI only
                # ever replays `run=`, and the legacy SPA's `slug=` stream is a live tail.
                # bool(run_q), not `is not None`: stream_path's own predicate is `if run:`, so matching it
                # exactly keeps the gate and the path selection from ever disagreeing (today they
                # agree only because parse_qs drops blank values).
                allow_replay = bool(run_q) and not slug_q
                self._sse(stream_path(run=run_q, slug=slug_q),
                          allow_replay=allow_replay,
                          from_start=(allow_replay
                                      and (q.get("from_start") or [""])[0] in ("1", "true", "yes")))
                return
            if path == "/api/blackboard":
                q = parse_qs(parts.query)
                slug = (q.get("slug") or [""])[0]
                # durable cursor: the Last-Event-ID reconnect header wins over the ?since= seed.
                since = 0
                for src in ((q.get("since") or ["0"])[0], self.headers.get("Last-Event-ID")):
                    try:
                        if src is not None:
                            since = int(src)
                    except (TypeError, ValueError):
                        pass
                self._sse_blackboard(slug, since)
                return
            if path == "/api/chat/sessions":
                self._json(chat.list_sessions())
                return
            if path.startswith("/api/chat/session/"):
                self._json(chat.get_session(path[len("/api/chat/session/"):].strip("/")))
                return
            if path == "/api/chat/attachments":
                # One chat's finished attachment MANIFESTS (name/digest/size/kind/counts — pointers, never
                # bytes) plus the gated-scan offer when an extracted codebase is present. Read-only; the
                # token + Host checks above already gated it. An unsafe chat id raises ValueError → 404.
                q = parse_qs(parts.query)
                self._json(chat.attachments_list((q.get("chat_id") or [""])[0]))
                return
            if path == "/api/chat/hypotheses":
                # Phase C: one chat's hypothesis ledger (open first, then closed with their finding ref).
                # Read-only; reconciles against the engine's confirmed FACTs so a hypothesis a run has since
                # settled shows as confirmed. An unsafe chat id raises ValueError → 404.
                q = parse_qs(parts.query)
                self._json(chat.chat_hypotheses((q.get("chat_id") or [""])[0]))
                return
            if path == "/api/chat/models":
                # E3: the per-session model picker's data — each selectable model with its sovereignty trust
                # class, whether the current tier permits it (and why not), and the consequence of choosing it
                # ("local · nothing leaves this machine" vs "cloud · sent to a third party"). Read-only.
                self._json(chat.chat_models())
                return
            if path == "/api/aegis/verdicts":
                # the live Defense verdict feed — tail the managed gateway's browser-safe verdicts JSONL
                # (oracle-context already stripped at the sink). EventTailer is robust to a missing file.
                vpath = actions.aegis_verdicts_path()
                if not vpath:
                    self._json({"error": "no AEGIS gateway is running"}, status=404)
                    return
                self._sse(vpath)
                return
            if path.startswith("/api/dossier/") and path.endswith(".zip"):
                # R3: stream a PRE-BUILT dossier ZIP as an attachment (the first client download). Never
                # builds here — building is the CSRF-guarded POST /api/dossier/<run>/build. A bad run id
                # raises ValueError in dossier_path/run_dir → caught below → 404.
                self._download_dossier(path[len("/api/dossier/"):-len(".zip")].strip("/"))
                return
            # Scoped routes are matched BEFORE the zero-arg exact table, so re-listing one of them
            # there by accident could never silently drop the engagement scope back to "all".
            if path in _SCOPED_ROUTES:
                # `?slug=` scopes the listing to the active engagement; anything else in the query is
                # ignored, and a repeated slug takes the first value (one scope, never a set).
                q = parse_qs(parts.query)
                self._json(_SCOPED_ROUTES[path]((q.get("slug") or [""])[0]))
                return
            if path in _EXACT_ROUTES:
                self._json(_EXACT_ROUTES[path]())
                return
            for prefix, fn in _PREFIX_ROUTES.items():
                if path.startswith(prefix):
                    self._json(fn(path[len(prefix):].strip("/")))
                    return
            if path.startswith("/api/"):
                self._json({"error": "unknown endpoint"}, status=404)
                return
            self._static(path)
        except BrokenPipeError:
            return
        except ValueError as e:  # an unsafe run id (run_dir guard) → honest 404, not a 500 or a traversal
            self._json({"error": str(e)}, status=404)
        except Exception as e:  # never 500 the whole console on one bad read
            self._json({"error": f"{type(e).__name__}: {e}"}, status=500)

    def _download_dossier(self, run_id: str) -> None:
        """Stream a PRE-BUILT dossier ZIP as an attachment. Confined to ``<run_dir>/dossier.zip`` (the fixed
        name; ``dossier_path`` traversal-guards the run id), so it can never stream an arbitrary file. Never
        builds — that is the CSRF-guarded POST. The download filename is sanitised to a safe token."""
        p = actions.dossier_path(run_id)          # run_dir guard; raises ValueError on a bad id → 404 in do_GET
        if not p.is_file():
            self._json({"error": "no dossier built yet for this run — build it first (the Download button)"},
                       status=404)
            return
        data = p.read_bytes()
        safe = "".join(c if (c.isalnum() or c in "._-") else "-" for c in f"vigil-dossier-{run_id}.zip")[:120]
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{safe}"')
        self.send_header("Cache-Control", "no-store")
        self._sec_headers()
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n < 0 or n > _MAX_CONSOLE_BODY:   # A9: refuse a huge/negative body (never read it into memory)
                return {}
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw or b"{}")
        except Exception:
            return {}

    def _read_json_body(self) -> tuple[dict | None, str]:
        """Read + parse a bounded JSON object body, returning ``(obj, error)`` — the DRAINING reader from
        ``framework.v2.api.server``, adopted here for the chunked-upload routes.

        Why these routes need it and ``_read_body`` will not do: ``_read_body`` maps EVERY failure —
        including an oversize body — to ``{}``, so a client that slices its chunks too large would see its
        upload silently treated as an empty request instead of being told the chunk is too big. Here an
        oversize body is DRAINED (a bounded amount, discarded, never buffered) so the client gets a clean
        4xx rather than a connection reset, and every failure carries a reason. The 1 MiB cap itself is
        UNCHANGED — this reports it honestly, it does not raise it."""
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return None, "invalid Content-Length"
        if n < 0:
            return None, "invalid Content-Length"
        if n > _MAX_CONSOLE_BODY:
            # Bounded drain so a lying Content-Length cannot loop us.
            remaining = min(n, _MAX_CONSOLE_BODY * 4)
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            return None, (f"body exceeds {_MAX_CONSOLE_BODY} bytes — slice the file into smaller chunks "
                          f"(the upload is chunked for exactly this reason)")
        raw = self.rfile.read(n) if n else b""
        try:
            obj = json.loads(raw or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return None, f"malformed JSON body: {e}"
        if not isinstance(obj, dict):
            return None, "JSON body must be an object"
        return obj, ""

    def _host_is_console(self) -> tuple[bool, str]:
        """A9: the DNS-rebinding defense for READ routes (GET/SSE) — and the Host/Origin half of the POST
        guard. The console binds loopback, but a page the operator visits on a DNS-rebinding domain
        (attacker.com that re-resolves to 127.0.0.1) sends its OWN Host, so requiring the Host to name the
        loopback console with the EXACT port (or an operator-allowlisted proxy domain) refuses it — closing
        read access to status/runs/findings/event-streams/terminal-history/dossiers. An Origin, when
        present, must likewise match. UNLIKE the POST guard this does NOT require the SPA custom header,
        because a legitimate EventSource / navigation GET cannot set one; the Host check is the rebinding
        defense that does not depend on a header the read client can't send."""
        port = self.server.server_address[1]

        def _port_ok(parsed, scheme_default: int) -> bool:
            # a missing port means the scheme default (so a legit SPA on a default port — where the
            # browser omits the port in Host/Origin — is accepted); a malformed port fails closed.
            try:
                p = parsed.port
            except ValueError:
                return False
            return (p if p is not None else scheme_default) == port

        def _authority_ok(value: str, scheme_default: int) -> bool:
            # Parse a host[:port] authority and check loopback + matching port. urlsplit itself
            # raises ValueError on a malformed IPv6 authority (e.g. "127.0.0.1]"), so the parse is
            # guarded — a malformed Host/Origin fails CLOSED (a clean 403), never a 500/traceback.
            try:
                u = urlsplit("//" + value if "//" not in value else value)
                return _is_loopback_host(u.hostname or "") and _port_ok(u, scheme_default)
            except ValueError:
                return False

        # Federation allowlist (default EMPTY → loopback-only, byte-identical to before). When VIGIL runs
        # behind the unified reverse proxy, the operator adds the proxy's exact domain Host/Origin here so
        # a same-origin request forwarded by the proxy is accepted; every other Host/Origin is still refused.
        # The console still BINDS loopback — the proxy is the only public listener.
        allow_hosts = getattr(self.server, "allowed_hosts", frozenset())
        allow_origins = getattr(self.server, "allowed_origins", frozenset())

        host_hdr = self.headers.get("Host", "").strip()
        if not host_hdr:
            return False, "Host missing"
        if not (_authority_ok(host_hdr, 80) or host_hdr in allow_hosts):
            return False, f"Host={host_hdr!r}"                # missing / rebinding / wrong-port / malformed
        origin = self.headers.get("Origin", "").strip()
        if origin:
            scheme_default = 443 if origin.lower().startswith("https:") else 80
            if not (_authority_ok(origin, scheme_default) or origin.rstrip("/") in allow_origins):
                return False, f"Origin={origin}"
        return True, ""

    def _same_origin_as_console(self) -> tuple[bool, str]:
        """X6: refuse a cross-site POST. A malicious web page the operator visits (or a DNS-rebinding domain
        that resolves to 127.0.0.1) could POST to 127.0.0.1:<port> and drive the console's actions from the
        operator's browser. Accept a POST only when it is same-origin to the loopback console: a CUSTOM
        header the SPA's fetch sets and a cross-site HTML <form> physically CANNOT (forcing a CORS preflight
        the console never answers) — the load-bearing check that closes the gap where a cross-site form POST
        omits BOTH Origin and Sec-Fetch-Site (Safari <16.4, in-app WebViews); a cross-site Sec-Fetch-Site is
        refused; PLUS the strict Host/Origin rebinding check (``_host_is_console``)."""
        if not self.headers.get(_CSRF_HEADER):
            return False, f"missing {_CSRF_HEADER} (cross-site form / non-SPA client)"
        sfs = self.headers.get("Sec-Fetch-Site", "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):        # cross-site / same-site → refuse
            return False, f"Sec-Fetch-Site={sfs}"
        if not self._token_ok():
            return False, "missing/invalid token"
        return self._host_is_console()

    def _hop_assertion_valid(self, principal: str, role: str, ts: str, sig: str, path: str) -> bool:
        """Verify the proxy's per-request role assertion: a constant-time HMAC-SHA256, under the shared hop
        key, over EXACTLY `principal\\nrole\\nmethod\\npath\\nts` — the SAME fields the proxy signed — inside
        a ±`_HOP_MAX_SKEW_S` freshness window. Fail-closed: no hop key (nothing to verify with), an
        incomplete assertion, a non-numeric/stale `ts`, or a mismatching MAC all return False. Binding the
        METHOD and console-side PATH stops a captured header set from being re-aimed at another verb/route;
        binding `ts` (with the window) stops replay."""
        hop_key = getattr(self.server, "hop_key", "") or ""
        if not (hop_key and role and ts and sig):
            return False
        try:
            ts_f = float(ts)
        except (TypeError, ValueError):
            return False
        if abs(time.time() - ts_f) > _HOP_MAX_SKEW_S:
            return False
        msg = f"{principal}\n{role}\n{self.command}\n{path}\n{ts}".encode("utf-8")
        expected = base64.b64encode(
            hmac.new(hop_key.encode("utf-8"), msg, hashlib.sha256).digest()).decode("ascii")
        return hmac.compare_digest(expected, sig)

    def _rbac_ok(self, path: str) -> tuple[bool, str]:
        """S1 per-action RBAC on a same-origin, token-valid POST. Three mutually-exclusive cases:

          * NO role assertion (neither ``X-VIGIL-Role`` nor ``X-VIGIL-Role-Sig`` present) → a DIRECT
            console-token holder. Holding the shared console credential is owner-equivalent, so this keeps
            today's FULL access — no regression for the on-host operator / a test / the legacy direct client.
          * A role assertion that VERIFIES (fresh HMAC under the hop key) → enforce
            ``role_can(stamped_role, offense_perm_for(path))``. An UNMAPPED route ⇒ ``offense_perm_for`` is
            None ⇒ ``role_can`` False ⇒ DEFAULT-DENY.
          * A role assertion that is PRESENT but INVALID (forged/expired/incomplete, or the console has no
            hop key to verify it) → REFUSE. A forged ``X-VIGIL-Role: owner`` with no valid MAC never lifts
            the role.

        Returns ``(allowed, reason)``; the caller maps a False to 403."""
        role = self.headers.get(_ROLE_HDR)
        sig = self.headers.get(_ROLE_SIG_HDR)
        if not role and not sig:
            return True, ""                                   # direct token-holder → owner-equivalent
        principal = self.headers.get(_PRINCIPAL_HDR) or ""
        ts = self.headers.get(_ROLE_TS_HDR) or ""
        if not self._hop_assertion_valid(principal, role or "", ts, sig or "", path):
            return False, "unverified role assertion (bad/expired hop signature)"
        required = offense_perm_for(path)                     # None ⇒ unmapped route ⇒ default-deny
        if not role_can(role, required):
            need = required or "(unmapped route → default-deny)"
            return False, f"role {role!r} lacks required permission {need}"
        return True, ""

    def do_POST(self) -> None:  # noqa: N802
        """The SAFE actions — the only mutations the console makes. Each is non-destructive and
        cannot relax scope or bypass a gate: launch (scan / assessment) spawns only the already-gated
        CLIs, re-verify is a pure re-computation, and kill-switch trip is the emergency stop."""
        ok, why = self._same_origin_as_console()
        if not ok:
            self._json({"error": f"cross-site POST refused ({why})"}, status=403)
            return
        path = urlsplit(self.path).path
        # S1: per-action RBAC. Runs on EVERY POST (incl. the chat-attach subset below) once the same-origin +
        # token conjunction has passed. A proxy-forwarded per-user request carries a hop-signed role, which is
        # enforced against this route's required permission; a direct token-holder (no role assertion) keeps
        # full access; a present-but-unverified role assertion is refused.
        rbac_ok, rbac_why = self._rbac_ok(path)
        if not rbac_ok:
            self._json({"error": f"forbidden: {rbac_why}"}, status=403)
            return
        if path in _CHAT_ATTACH_POST:
            # Chunked attachment upload. Same auth as every other POST (checked above); the only difference
            # is the body reader — an oversize chunk must be an honest error, not an empty dict.
            attach_body, why_body = self._read_json_body()
            if why_body:
                self._json({"error": why_body}, status=400)
                return
            try:
                self._json(_CHAT_ATTACH_POST[path](attach_body or {}))
            except ValueError as e:      # unsafe chat / upload id → honest 404, consistent with the rest
                self._json({"error": str(e)}, status=404)
            except BrokenPipeError:
                return
            except Exception as e:  # noqa: BLE001
                self._json({"error": f"{type(e).__name__}: {e}"}, status=500)
            return
        body = self._read_body()
        try:
            if path == "/api/token-budgets":
                # Token Budgets: set one tool's daily token cap / mode from the UI. Pure config write to
                # the shared vigil_core ledger — no scope, gate, or fact is touched; it can only change how
                # loudly a tool is warned/throttled, never whether a call is allowed (never-block).
                self._json(actions.set_token_budget(body))
                return
            if path.startswith("/api/run/") and path.endswith("/cancel"):
                # W4: stop a running run (terminate its recorded pid). Non-destructive lifecycle control —
                # it stops a process the operator started; it touches no scope, gate, finding or fact.
                self._json(actions.cancel_run(path[len("/api/run/"):-len("/cancel")].strip("/")))
                return
            if path.startswith("/api/run/") and path.endswith("/retry"):
                # W4: relaunch a finished/interrupted run — RESUMED (argv + --resume) where the CLI supports
                # it, else RESTARTED. Spawns only the SAME already-gated argv the run recorded; it cannot
                # widen scope or bypass a gate (a resumed engage re-attests + re-gates every edge).
                self._json(actions.retry_run(path[len("/api/run/"):-len("/retry")].strip("/")))
                return
            if path == "/api/instruct":
                # B1: enqueue an operator message for a RUNNING integration engagement (mid-run steering).
                # Advisory-only — the engine folds it into the next think; it re-runs no completed tool,
                # relaxes no scope, fires nothing ungated. Same-origin + token gated (do_POST guard above).
                self._json(actions.engage_instruct(str(body.get("slug", "")), str(body.get("text", ""))))
                return
            if path == "/api/codebase/edit":
                # D2 dev-mode: propose a change to a codebase THIS chat cloned, as a unified diff for review.
                # Path-confined to the chat's clone area; the model call is sovereignty-gated; nothing is
                # applied here (propose only). Same-origin + token gated.
                self._json(actions.propose_codebase_edit(str(body.get("chat_id", "")),
                                                         str(body.get("path", "")),
                                                         str(body.get("instruction", ""))))
                return
            if path == "/api/codebase/apply":
                # D2 dev-mode: apply an operator-REVIEWED unified diff into the chat's cloned codebase. A2
                # code_edit, opened by operator-presence; path-confined + clone-only git-apply.
                self._json(actions.apply_codebase_edit(str(body.get("chat_id", "")),
                                                      str(body.get("path", "")),
                                                      str(body.get("diff", ""))))
                return
            if path == "/api/codebase/test":
                # D3: run the cloned codebase's tests in the network-isolated, workspace-confined bwrap
                # sandbox via the gated `vigil sandbox` verb (A3, signed, scope-pinned, kill-switch). The
                # operator clicked "run tests" → the A3 human-approval leg (operator_present=True). A green
                # test is a LEAD, not an oracle FACT.
                self._json(actions.run_codebase_tests(str(body.get("chat_id", "")),
                                                     str(body.get("path", "")),
                                                     str(body.get("command", "") or "pytest -q"),
                                                     operator_present=True))
                return
            if path == "/api/launch/assessment":
                # The New-Assessment wizard's one action. It spawns only the SAME gated CLIs; it
                # cannot relax scope (charter-signed, never an arg) or bypass a gate. A clean JSON
                # refusal (no charter / bad target / CIDR scope) is returned as a normal 200 body.
                self._json(actions.launch_assessment(body))
                return
            if path == "/api/launch/cloud":
                # Seedless cloud/Kubernetes/infra posture launch (slice C2b). Spawns the already-gated
                # `engage --fuse-only`; validation + the signed-charter gate live in actions.launch_cloud.
                self._json(actions.launch_cloud(
                    str(body.get("slug", "")),
                    str(body.get("mode", "")),
                    str(body.get("target", "")),
                    provider=str(body.get("provider", "")),
                ))
                return
            if path == "/api/replay":
                # Replay-the-Proof: re-fire an EXTERNALLY-supplied report/finding document's RETAINED oracle
                # certificates OFFLINE (pure re-computation — NO target, NO scope, NO traffic). Registered
                # BEFORE the `/api/reverify/` prefix branch so the exact path is not swallowed by it. Malformed
                # input fails closed inside actions.replay_document. CSRF/rebind-gated above.
                self._json(actions.replay_document(body))
                return
            if path.startswith("/api/reverify/"):
                self._json(actions.reverify_run(path[len("/api/reverify/"):].strip("/")))
                return
            if path.startswith("/api/remediate/") and path.endswith("/apply"):
                # Fixes screen (U1): run the GATED, non-destructive auto-patch ladder for one oracle-confirmed
                # finding by shelling `vigil patch` (never --open-pr). CSRF/rebind-gated above; a bad run id
                # raises ValueError in run_dir → caught below → clean 404.
                mid = path[len("/api/remediate/"):-len("/apply")].strip("/")
                run_id, _, fref = mid.partition("/")
                self._json(actions.apply_fix(run_id, fref))
                return
            if path == "/api/proof/export":
                # Proof Studio (C1): assemble a client-verifiable proof bundle for a run (offline zero-trust
                # re-verify). CSRF/rebind-gated above; shells the exec-only `vigil proof-export`. A bad run id
                # raises ValueError in run_dir → caught below → clean 404.
                self._json(actions.proof_export(str(body.get("run", ""))))
                return
            if path.startswith("/api/dossier/") and path.endswith("/build"):
                # R3: build the run's tamper-evident dossier ZIP (CSRF/rebind-gated above; shells the exec-only
                # `vigil dossier`). The GET /api/dossier/<run>.zip route then streams the built file. A bad run
                # id raises ValueError in run_dir → caught below → 404.
                run_id = path[len("/api/dossier/"):-len("/build")].strip("/")
                self._json(actions.build_dossier(run_id))
                return
            if path == "/api/authority/provision":
                # Charter & Attestation screen: mint a LOOPBACK authority (scope hard-fixed to 127.0.0.1 in
                # the action — the UI cannot provision a remote charter). CSRF/rebind-gated above.
                self._json(actions.provision_loopback_authority(str(body.get("slug", ""))))
                return
            if path == "/api/verify-cert":
                # Trust Center: OFFLINE-verify ONE signed certificate from api.certs's own list. PURE /
                # offline / read-only — re-derives the digest + checks the m-of-n signature, and binds the
                # trust ROOT to an out-of-band pin where one exists (source pin for recall; the OPTIONAL
                # operator-supplied `oob_pin` for a per-run cert — its sibling .fingerprint.txt is NOT a pin).
                # Takes NO scope/target, issues NO traffic, mints NOTHING. CSRF/rebind-gated above; an unsafe
                # run id raises ValueError in run_dir → fail-closed refusal body.
                self._json(actions.verify_cert(str(body.get("name", "")), str(body.get("run_id", "")),
                                               str(body.get("oob_pin", ""))))
                return
            if path == "/api/authority/ledger":
                # replay the who/when/what usage-attestation ledger + verify its chain (read-only).
                self._json(actions.attestation_ledger())
                return
            if path == "/api/knowledge/gitsync":
                # A6c: run `vigil knowledge status|sync` (regenerate + secret-scan + local commit; NOT push).
                # CSRF/rebind-gated above; shells the exec-only vigil, surfacing the secret-scan refusal.
                self._json(actions.knowledge_gitsync(str(body.get("action", "status"))))
                return
            if path.startswith("/api/evolve/") and path.endswith("/tick"):
                # K5: RUN one self-evolve tick that PERSISTS (the GET evolve_data is read-only). CSRF/rebind-
                # gated above + kill-switch gated inside; it drafts proposals + records calibration
                # predictions, never merges/applies and mints no fact.
                slug = path[len("/api/evolve/"):-len("/tick")].strip("/")
                self._json(actions.run_evolve_tick(slug))
                return
            if path.startswith("/api/knowledge/") and path.endswith("/deeplearn"):
                # K3 (U2): DRAFT FIND/PREVENT advisory skills + a GATED DETECT proposal for ONE unlearned
                # vuln lead. CSRF/rebind-gated above + kill-switch gated inside; shells the SAME gated
                # `knowledge learn` CLI. Mints NO fact, bumps NO prior, fires NO oracle, applies nothing.
                slug = path[len("/api/knowledge/"):-len("/deeplearn")].strip("/")
                self._json(actions.run_deep_learn(slug, str(body.get("vuln_id", ""))))
                return
            if path.startswith("/api/feed/") and path.endswith("/pull"):
                # K1 (U2): ONE-SHOT gated 'Pull now' vuln-feed refresh (opt-in egress; recurring auto-pull
                # stays a sidecar). CSRF/rebind-gated above + kill-switch gated inside; shells the SAME gated
                # `intel refresh-vulnintel --live` CLI. Every entry is an intel-tier LEAD, never a fact.
                slug = path[len("/api/feed/"):-len("/pull")].strip("/")
                self._json(actions.run_feed_pull(slug))
                return
            if path.startswith("/api/feed/") and path.endswith("/start"):
                # B5: START the RECURRING vuln-feed sidecar (`intel feed-daemon --live`) as a console-tracked
                # background subprocess. CSRF/rebind-gated above + kill-switch gated inside; opt-in recurring
                # egress the operator turns on here. Every tick honours the kill-switch; LEADS only, no fact.
                slug = path[len("/api/feed/"):-len("/start")].strip("/")
                self._json(actions.run_feed_start(slug, interval=body.get("interval", 3600)))
                return
            if path.startswith("/api/feed/") and path.endswith("/stop"):
                # B5: STOP the tracked recurring vuln-feed sidecar for this engagement (SIGTERM→SIGKILL, then
                # untrack). CSRF/rebind-gated above; idempotent (an untracked slug is a clean no-op).
                slug = path[len("/api/feed/"):-len("/stop")].strip("/")
                self._json(actions.run_feed_stop(slug))
                return
            if path.startswith("/api/killswitch/") and path.endswith("/trip"):
                slug = path[len("/api/killswitch/"):-len("/trip")].strip("/")
                self._json(actions.trip_killswitch(slug, str(body.get("reason", ""))))
                return
            if path == "/api/tools/install":
                # on-demand tool provisioning (B2). CSRF/rebind-gated above. Fail-closed in provision_tool:
                # only a B1-admitted tool, only its declared apt/pip hint, only with explicit consent
                # (else it returns the exact command it WOULD run and installs nothing).
                self._json(actions.provision_tool(body))
                return
            if path == "/api/services/up":
                # System screen: create the docker services IF NONE EXIST (qdrant + gateway; +neo4j+otel
                # with all=true). CSRF/rebind-gated above; BOUNDED — only the fixed `all` flag selects from a
                # CLOSED service set, no request-controlled service/image/command; idempotent; fail-soft.
                self._json(actions.services_up(body))
                return
            if path == "/api/benchmark/run":
                # Brain > Benchmark screen: run the CRUCIBLE-only soundness benchmark LIVE (the same 11|0|0
                # the make-gate regression runs). CSRF/rebind-gated above; FIXED argv (no request input),
                # loopback-only + incumbent-free by construction, BOUNDED + fail-soft; no target/scope/egress.
                self._json(actions.benchmark_run(body))
                return
            if path == "/api/planner/run":
                # Brain > Planner tab: compute the READ-ONLY attack-plan projection for an engagement
                # (`plan <slug>` — loads the persisted --spine world-model, prints the ranked plan; NO
                # traffic, NO tools, NO persist). CSRF/rebind-gated above; only the allowlist-validated slug
                # reaches the argv; BOUNDED + fail-soft.
                self._json(actions.planner_compute(body))
                return
            if path == "/api/intel/run":
                # Brain > Intel tab: run OFFLINE intel recon for an engagement (`intel ingest` — passive
                # collectors over bundled fixtures; `--live` is NEVER passed, so it cannot egress). CSRF/
                # rebind-gated above; slug + seed-domain both allowlist-validated; BOUNDED + fail-soft.
                self._json(actions.intel_ingest_offline(body))
                return
            if path == "/api/label/engagement":
                # Engagement library: give a past job a HUMAN name. PRESENTATION ONLY — it writes one
                # key in the label side-car and touches no run artifact, no certificate and no spine
                # event, so a relabelled engagement still re-verifies. CSRF/rebind/token-gated above;
                # an unsafe slug is refused inside set_engagement_label (fail-closed).
                self._json(labels.set_engagement_label(str(body.get("slug", "")),
                                                       str(body.get("label", ""))))
                return
            if path == "/api/label/run":
                # Same, for ONE run. The run id passes the console's traversal guard and the run must
                # exist; its engagement slug is resolved SERVER-SIDE from the run's own meta.json —
                # the caller never supplies it, so a label cannot claim a run into another engagement.
                self._json(labels.set_run_label(str(body.get("run_id", "")),
                                                str(body.get("label", ""))))
                return
            if path == "/api/session/create":
                # F2: create a named session. CSRF/rebind-gated above; the registry mints no fact and
                # authorizes nothing — it only organises runs/chats under an operator-editable name.
                self._json(sessions.create_session(
                    name=str(body.get("name", "")), kind=str(body.get("kind", "engagement"))))
                return
            if path == "/api/session/rename":
                self._json(sessions.rename_session(str(body.get("id", "")), str(body.get("name", ""))))
                return
            if path == "/api/session/delete":
                # SOFT tombstone by default; HARD only on an explicit boolean true (removes the registry
                # entry + rebuildable graph partition, never the append-only spine or a FACT).
                self._json(sessions.delete_session(
                    str(body.get("id", "")), hard=(body.get("hard") is True)))
                return
            if path == "/api/session/connect":
                # F4: connect A → B (directional). The POST IS the consent; stores a read-time scope entry,
                # never a graph merge. CSRF/rebind-gated above; the registry authorizes nothing.
                self._json(sessions.connect_session(str(body.get("id", "")), str(body.get("other", ""))))
                return
            if path == "/api/session/disconnect":
                self._json(sessions.disconnect_session(str(body.get("id", "")), str(body.get("other", ""))))
                return
            if path == "/api/chat/stream":
                # F1: a STREAMED question turn. chat_stream emits SSE token events; the FIRST emit lazily
                # sends the event-stream headers. If the turn is NOT streamable (a launch/clone/need-target
                # turn — nothing emitted), chat_stream returns {"stream": False, "fallback": True} and we send
                # it as ordinary JSON so the SPA re-POSTs to /api/chat/send. Same-origin + token gated above;
                # the reasoning egress is sovereignty-gated inside chat (a local pick answers non-streamed,
                # no egress). Persistence is identical to /send (shared _finish_question_turn).
                started = {"on": False}

                def _emit(ev: dict) -> None:
                    if not started["on"]:
                        started["on"] = True
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("Connection", "keep-alive")
                        self._sec_headers()
                        self.end_headers()
                    try:
                        payload = json.dumps(ev, ensure_ascii=False, default=str)
                        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except (BrokenPipeError, OSError):
                        pass          # the operator navigated away mid-stream — the record is already persisted

                try:
                    result = chat.chat_stream(body, _emit)
                except ValueError as e:                         # unsafe chat id → 404 (parity with the rest)
                    if not started["on"]:
                        self._json({"error": str(e)}, status=404)
                    return
                except Exception as e:  # noqa: BLE001
                    if not started["on"]:
                        self._json({"error": f"{type(e).__name__}: {e}"}, status=500)
                    return
                if not started["on"]:
                    self._json(result)                          # fallback: nothing streamed → JSON, UI uses /send
                return
            if path == "/api/chat/send":
                # the operator chatbot turn — a natural-language front door to the SAME gated launcher.
                # CSRF/rebind-gated above; launches only via actions.launch_assessment (scope/charter/gate
                # enforced there), persists the transcript, and mints no facts. A turn with no launchable
                # target now REASONS over the chat's attachments + connected chats (sovereignty-gated model
                # egress inside chat._reason) — that answer is a LEAD, and the reply carries the gated
                # scan_offer for the same files; the chat still starts nothing itself.
                self._json(chat.chat_send(body))
                return
            if path == "/api/aegis/setup":
                # launch the managed AEGIS gateway (the SAME gated `aegis gateway` CLI). CSRF/rebind-gated
                # above; validated fail-closed in actions.aegis_setup before any spawn.
                self._json(actions.aegis_setup(body))
                return
            if path == "/api/terminal/dryrun":
                # T2: parse + allowlist-preview a command WITHOUT executing (read-only). Advisory badge; the
                # authoritative check runs inside `vigil terminal` at run time.
                self._json(actions.terminal_dryrun(str(body.get("command", ""))))
                return
            if path == "/api/terminal/propose":
                # T2b: the capability-router. Claude CLASSIFIES the intent (command / answer / route) over a
                # secret-REDACTED session context and returns a TYPED result. The LLM only PROPOSES; a command
                # is still dryrun/allowlist-checked, and answer/route run nothing. Honest need_key with no key.
                self._json(actions.terminal_propose(
                    str(body.get("intent", "")),
                    run_id=str(body.get("run_id", "")) or None,
                    session_id=str(body.get("session_id", "")) or None,
                ))
                return
            if path == "/api/terminal/run":
                # T2: run an allowlisted LOCAL command by shelling `vigil terminal <command> --approve` (the Run
                # click IS the operator approval). CSRF/rebind-gated above; the AUTHORITATIVE allowlist + gate +
                # signed record are enforced inside the verb — the console imports no integration code (FATAL-2).
                self._json(actions.terminal_run(str(body.get("command", ""))))
                return
            if path == "/api/aegis/stop":
                self._json(actions.aegis_stop(body))
                return
            self._json({"error": "unknown action"}, status=404)
        except ValueError as e:  # an unsafe run id (run_dir guard) → honest 404, consistent with do_GET
            self._json({"error": str(e)}, status=404)
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, status=500)


def serve(host: str = "127.0.0.1", port: int = 8787,
          allowed_hosts=(), allowed_origins=(), token: str | None = None) -> ThreadingHTTPServer:
    """Create (but do not block on) the loopback console server. The caller runs
    ``serve_forever()``. Refuses any non-loopback BIND — the console is a
    single-operator, on-host surface by design (sovereignty); the unified reverse
    proxy is the only public listener.

    ``allowed_hosts``/``allowed_origins`` are the operator's exact reverse-proxy
    domain Host/Origin forms (e.g. ``vigil.example.com`` / ``https://vigil.example.com``)
    unioned into the anti-CSRF/anti-rebind guard so a same-origin request forwarded
    by the proxy is accepted. Empty (the default) = loopback-only, unchanged.

    ``token`` is the session credential required on every ``/api/*`` request. Omit it
    (the normal case) and one is taken from ``$VIGIL_CONSOLE_TOKEN`` or MINTED — it is
    never empty, so the server cannot be started without a credential. The live value
    is exposed as ``srv.token`` for the launcher to print and for tests to present."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"console binds loopback only, refusing host {host!r}")
    srv = ThreadingHTTPServer((host, port), ConsoleHandler)
    srv.allowed_hosts = frozenset(h.strip() for h in allowed_hosts if h and h.strip())
    srv.allowed_origins = frozenset(o.strip().rstrip("/") for o in allowed_origins if o and o.strip())
    srv.token = _resolve_token(token)
    srv.hop_key = _resolve_hop_key()   # S1: verifies the proxy's per-request role assertion (or "" ⇒ trust none)
    # Reconcile any run left 'running' by a prior console/host whose process is now gone → 'interrupted' +
    # resumable, so a dead run is not shown as a live engagement (conservatively — a same-boot pid reuse or
    # an orphan-alive child can still strand one; see reconcile_orphaned_runs). Total; never blocks startup.
    try:
        actions.reconcile_orphaned_runs()
    except Exception:  # noqa: BLE001
        pass
    return srv
