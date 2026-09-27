"""scanner.rawhttp — the ONE raw-socket HTTP/1.1 response reader in the tree.

Request-smuggling evidence lives below the HTTP-client abstraction: a desync differential
is only real if the reader consumes EXACTLY the first response off the socket and then
reads VIGIL's OWN second response separately. Get the framing wrong and the two responses
merge, and a benign origin's echo of the FIRST request is attributed to the SECOND — the
producer then "observes" a leak that never happened.

That reader was DUPLICATED verbatim (~110 lines) in ``scanner.smuggling`` and in
``vigil_integration.live.smuggling_redrive``, and the duplicate carried the same three
framing defects, so fixing one left the other wrong. This module is the single corrected
implementation; every raw-socket consumer imports it (the integration side imports it
function-locally, per FATAL-2). ``scanner.tests.test_rawhttp_reader`` owns its unit tests
and a drift guard that fails if a second implementation reappears.

The corrections over the duplicated original, each one a MEASURED defect:

1. **A 1xx is INTERIM, not a response** (RFC 9112 §15). The original returned
   ``HTTP/1.1 100 Continue`` as a complete response with an empty body, so the FINAL
   response to the FIRST request became "response 2". Measured: an origin that emits an
   unsolicited ``100 Continue`` for a bodied request turned the benign echo-the-request
   400 page into a canary-bearing "second response". A 1xx is now skipped and reading
   continues for the final response (bounded by ``_MAX_INTERIM``). ``101 Switching
   Protocols`` is terminal — the connection leaves HTTP/1.1 — so it is returned as-is.

2. **A response must START with a real status line.** The original accepted any block
   ending in CRLFCRLF as a response, with ``status=None`` when the first line did not
   parse. An UNDER-DECLARED ``Content-Length`` on response 1 therefore turned the surplus
   bytes (which include the echoed request) into "response 2" carrying ``channel=True,
   status=None``, and an unconsumed chunked TRAILER block did the same. Surplus that is
   not a well-formed ``HTTP/x.y NNN`` status line is now NO CHANNEL, with the reason in
   :attr:`RawResponseReader.last_error` — never a fabricated second response.

3. **Chunked trailers are consumed.** The original deleted exactly 2 bytes after the
   terminating zero-chunk, so a trailer section stayed in the buffer and became the head
   of "response 2". The trailer section is now consumed through its empty line.

Two further framing bugs found while writing the unit tests this reader never had:

4. **A negative / malformed chunk size aborts the body.** ``int(b"-5", 16)`` is ``-5``,
   not a ``ValueError``, and the original then sliced with a negative length and reported
   a bogus body as complete.

5. **A truncated body is NOT a complete response.** A ``Content-Length`` the peer never
   satisfies, or a chunked body cut short, used to be returned as a finished response with
   whatever arrived. It is now NO CHANNEL — an honest INCONCLUSIVE.

The reader is transport-only: it renders no verdict, it decodes no evidence, and it never
decides whether anything is a vulnerability.
"""

from __future__ import annotations

import re
import socket

MAX_RAW_DEFAULT = 65536       # bounded read — a differential needs only the first responses
_MAX_INTERIM = 8              # consecutive 1xx interim responses tolerated before giving up
_MAX_TRAILER_LINES = 64       # bounded trailer section

# A response line per RFC 9112 §4: HTTP-version SP status-code [SP reason-phrase]. The code
# is exactly three digits and must be a real status class (1xx-5xx), so a body fragment that
# happens to contain "HTTP/1.1" cannot pass as the start of a response.
_STATUS_LINE = re.compile(rb"^HTTP/\d\.\d[ \t]+([1-5]\d\d)(?:[ \t]+(.*))?$")


class RawResponseReader:
    """Read DISCRETE HTTP/1.1 responses off a raw socket, EACH BY ITS OWN FRAMING (chunked /
    Content-Length / connection-close), buffering surplus bytes so a pipelined or
    desync-leftover response is returned by the NEXT :meth:`read_response` — never a lexical
    split of one accumulated blob on ``HTTP/1.``.

    That is what makes a second-request differential real: after the first request the reader
    consumes EXACTLY the first response and no more, so a benign server that echoes the first
    request in a 400/405 body cannot fool it — that echo lives in the FIRST response.

    :meth:`read_response` returns ``{"channel", "status", "reason", "body"}``.
    ``channel`` is False whenever no COMPLETE, well-formed response could be read; the reason
    is then in :attr:`last_error` (the caller reports it as an honest INCONCLUSIVE).
    """

    def __init__(self, sock: socket.socket, *, budget: int = MAX_RAW_DEFAULT) -> None:
        self._sock = sock
        self._buf = bytearray()
        self._closed = False
        self._budget = budget
        self.last_error = ""

    # -- transport ---------------------------------------------------------------------
    def _recv(self) -> bool:
        if self._closed or self._budget <= 0:
            return False
        try:
            chunk = self._sock.recv(min(4096, self._budget))
        except socket.timeout:
            return False
        except OSError:
            self._closed = True
            return False
        if not chunk:
            self._closed = True
            return False
        self._buf.extend(chunk)
        self._budget -= len(chunk)
        return True

    def _need(self, n: int) -> bool:
        while len(self._buf) < n:
            if not self._recv():
                return False
        return True

    def _need_marker(self, marker: bytes) -> bool:
        while marker not in self._buf:
            if not self._recv():
                return False
        return True

    @property
    def exhausted(self) -> bool:
        """The peer closed AND nothing is buffered — driving another request is pointless."""
        return self._closed and not self._buf

    # -- body framing ------------------------------------------------------------------
    def _read_line(self) -> "bytes | None":
        """One CRLF-terminated line (without the CRLF), or None if the peer stopped first."""
        if not self._need_marker(b"\r\n"):
            return None
        idx = bytes(self._buf).find(b"\r\n")
        line = bytes(self._buf[:idx])
        del self._buf[: idx + 2]
        return line

    def _consume_trailers(self) -> bool:
        """Consume the chunked TRAILER section through its terminating empty line.

        The original deleted a fixed 2 bytes here, so a trailer block stayed buffered and
        became the head of the next "response" — measured: ``X-Trailer: <canary>`` plus the
        genuinely pipelined response came back as ONE blob."""
        for _ in range(_MAX_TRAILER_LINES):
            line = self._read_line()
            if line is None:
                return False
            if not line:            # the empty line ends the trailer section
                return True
        return False

    def _read_chunked(self) -> "bytes | None":
        out = bytearray()
        while True:
            line = self._read_line()
            if line is None:
                return None                       # cut short mid-body: NOT a complete response
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                return None                       # malformed chunk size
            if size < 0:                          # int(b"-5", 16) == -5, not a ValueError
                return None
            if size == 0:
                return bytes(out) if self._consume_trailers() else None
            if not self._need(size + 2):
                return None
            out.extend(self._buf[:size])
            del self._buf[: size + 2]

    def _read_body(self, headers: "dict[str, str]", status: "int | None") -> "bytes | None":
        # A bodyless status carries no body whatever the headers say (RFC 9112 §6.3).
        if status in (204, 304, 101):
            return b""
        if "chunked" in headers.get("transfer-encoding", "").lower():
            return self._read_chunked()
        cl = headers.get("content-length")
        if cl is not None and cl.strip().isdigit():
            n = int(cl.strip())
            if not self._need(n):
                return None                       # declared more than the peer ever sent
            body = bytes(self._buf[:n])
            del self._buf[:n]
            return body
        # No length framing: the body runs to connection close, so draining it necessarily
        # closes the socket (the caller then sees ``exhausted`` and records no second leg).
        while self._recv():
            pass
        body = bytes(self._buf)
        self._buf.clear()
        self._closed = True
        return body

    # -- one response ------------------------------------------------------------------
    def _no_channel(self, why: str) -> dict:
        self.last_error = why
        return {"channel": False, "status": None, "reason": "", "body": ""}

    def _read_head(self) -> "tuple[int, str, dict[str, str]] | None":
        """Parse ONE header block. None (with ``last_error`` set) when the peer sent no block
        or the block does not START with a well-formed status line."""
        if not self._need_marker(b"\r\n\r\n"):
            self.last_error = ("no complete response header block was read "
                               "(peer silent or closed)" if not self._buf else
                               "the peer closed mid-header-block")
            return None
        head = bytes(self._buf).split(b"\r\n\r\n", 1)[0]
        del self._buf[: len(head) + 4]
        lines = head.split(b"\r\n")
        m = _STATUS_LINE.match(lines[0])
        if m is None:
            # Surplus bytes from an UNDER-DECLARED Content-Length, an unconsumed trailer
            # block, or plain junk. Reporting it as a response is how a benign echo of the
            # FIRST request becomes a "second response" carrying the canary.
            self.last_error = (f"the next bytes on the socket are not an HTTP status line "
                               f"({lines[0][:48]!r}) — framing is broken, not a response")
            return None
        status = int(m.group(1))
        reason = (m.group(2) or b"").decode("latin-1", "replace").strip()
        headers: dict[str, str] = {}
        for ln in lines[1:]:
            i = ln.find(b":")
            if i > 0:
                headers[ln[:i].strip().lower().decode("latin-1", "replace")] = \
                    ln[i + 1:].strip().decode("latin-1", "replace")
        return status, reason, headers

    def read_response(self) -> dict:
        """Read exactly ONE complete HTTP response, skipping 1xx INTERIM responses.

        Returns ``{"channel", "status", "reason", "body"}``. ``channel`` is False — with the
        reason in :attr:`last_error` — when the peer sent no header block, when the next bytes
        are not a status line, or when the body was truncated. A partial or unframed read is
        NEVER returned as a response."""
        self.last_error = ""
        for _ in range(_MAX_INTERIM + 1):
            parsed = self._read_head()
            if parsed is None:
                return self._no_channel(self.last_error)
            status, reason, headers = parsed
            # RFC 9112 §15: a 1xx (other than 101, which leaves HTTP/1.1 entirely) is INTERIM
            # — it has no body and the client MUST keep reading for the FINAL response.
            if 100 <= status < 200 and status != 101:
                continue
            body = self._read_body(headers, status)
            if body is None:
                return self._no_channel(
                    f"the {status} response's body was truncated (declared framing never "
                    f"completed) — not a complete response")
            return {"channel": True, "status": status, "reason": reason,
                    "body": body.decode("latin-1", "replace")}
        return self._no_channel(
            f"more than {_MAX_INTERIM} consecutive 1xx interim responses — no final response")
