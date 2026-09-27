"""scanner.rawhttp — the ONE raw-socket HTTP/1.1 response reader in the tree.

Request-smuggling evidence lives below the HTTP-client abstraction: a desync differential
is only real if the reader consumes EXACTLY the first response off the socket and then
reads VIGIL's OWN second response separately. Get the framing wrong and the two responses
merge, and a benign origin's echo of the FIRST request is attributed to the SECOND — the
producer then "observes" a leak that never happened.

That reader was DUPLICATED verbatim (~110 lines) in ``scanner.smuggling`` and in
``vigil_integration.live.smuggling_redrive``, and the duplicate carried the same three
framing defects, so fixing one left the other wrong. This module is the single corrected
implementation and the ONE reader the scanner tree uses.

MIGRATION STATUS, stated exactly (audit-A red-pen BLOCK-7a). An earlier version of this
paragraph said "every raw-socket consumer imports it". That was FALSE in the present tense:
``integration/vigil_integration/live/smuggling_redrive.py:119`` STILL DEFINES its own
``class _RawResponseReader``, still carrying the pre-fix framing, and that file is owned by a
concurrent change. ``scanner.tests.test_rawhttp_reader`` is the authority here: its drift
guard fails if a THIRD implementation appears, its ``_PENDING`` allowlist names the one
outstanding copy, and ``_PENDING_DIVERGENT`` pins the exact set of cases that copy still gets
wrong — so the day it is migrated to ``from framework.v2.scanner.rawhttp import
RawResponseReader`` (function-locally, per FATAL-2) the tripwire fires and the allowlist must
be deleted. Until then: the scanner path uses this reader; the gated live re-drive does not.

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

   **The exact limit of that guarantee** (audit-A red-pen BLOCK-7b — the earlier wording
   claimed more than is enforced). It bounds surplus that is NOT a status line. Surplus that
   IS one is still returned as read #2, because nothing on the wire distinguishes a genuinely
   pipelined response from an under-declared ``Content-Length``'s leftovers: an origin whose
   400 page quotes a complete ``HTTP/1.1 200 OK`` block, under a CL that stops before it,
   yields a read #2 built from that quoted block. Closing THAT needs the caller to tell the
   reader when it actually sent its next request (bytes already buffered cannot answer a
   request not yet sent) — deliberately NOT done here, because the campaign's B1 lead exists
   precisely to cover the origin that honours TE over CL and PIPELINES the remainder
   immediately, which such a rule would silently discard. Named as follow-up.

   The four framing shapes that DID fabricate a read #2 and are now refused:

   * **conflicting duplicate ``Content-Length``.** The header dict was last-wins, so
     ``Content-Length: 5`` + ``Content-Length: 40`` framed the response at 40 (or 5) and the
     rest became "response 2". RFC 9112 §6.3 requires treating differing or invalid
     Content-Lengths as an UNRECOVERABLE error; the response is now refused outright.
   * **``204``/``304`` with a declared body.** Those statuses carry no body whatever the
     headers say, so the declared bytes stayed buffered and were parsed as "response 2". A
     body-declaring 204/304 is unrecoverable framing (RFC 9112 §6.3): the response is
     returned, and the connection is then POISONED — every later read is NO CHANNEL.
   * **``101`` followed by bytes.** After ``101`` the connection has left HTTP/1.1 (RFC 9112
     §9.6), so trailing bytes are upgraded-protocol data, never a response. Also poisoned.
   * **non-RFC chunk sizes.** See correction 4.

3. **Chunked trailers are consumed.** The original deleted exactly 2 bytes after the
   terminating zero-chunk, so a trailer section stayed in the buffer and became the head
   of "response 2". The trailer section is now consumed through its empty line.

Two further framing bugs found while writing the unit tests this reader never had:

4. **A chunk size must be RFC chunk-size syntax, not whatever ``int(x, 16)`` accepts.**
   ``int(b"-5", 16)`` is ``-5``, not a ``ValueError``, and the original then sliced with a
   negative length and reported a bogus body as complete. ``int`` is far more permissive
   than HTTP: ``+5``, ``0x5``, ``1_0`` and Unicode decimal digits all parse for it and for
   no HTTP parser on earth, which is exactly the divergence a desync is built out of. The
   size token (before any ``;`` chunk-ext) must now match ``[0-9A-Fa-f]{1,15}`` with at most
   trailing BWS; anything else aborts the body as NO CHANNEL. The same applies to
   ``Content-Length``, which is matched against ``[0-9]+`` rather than ``str.isdigit()``
   (``"٥".isdigit()`` is True and ``int("٥")`` is 5).

5. **A truncated body is NOT a complete response.** A ``Content-Length`` the peer never
   satisfies, or a chunked body cut short, used to be returned as a finished response with
   whatever arrived. It is now NO CHANNEL — an honest INCONCLUSIVE. This now holds for the
   CLOSE-DELIMITED framing too (audit-A red-pen): a body that runs to connection close but
   was cut off by the READ BUDGET or by a socket timeout — i.e. the peer never actually
   closed — used to come back as ``channel=True`` with the partial bytes, which contradicted
   this very paragraph. All three framings now agree: only a body the peer finished
   delivering is a complete response.

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

# RFC 9112 §7.1: chunk-size is 1*HEXDIG. ``int(tok, 16)`` accepts far more than that
# (``-5`` -> -5, ``+5`` -> 5, ``0x5`` -> 5, ``1_0`` -> 16, Unicode digits), and a size a
# reader accepts but no origin's parser does is precisely how a desync is manufactured.
# Bounded to 15 hex digits so a size can never overflow the read budget's arithmetic; at
# most trailing BWS is tolerated (real servers emit it; it changes no parser's answer).
_CHUNK_SIZE = re.compile(rb"^([0-9A-Fa-f]{1,15})[ \t]*$")

# RFC 9112 §6.3: Content-Length is 1*DIGIT — ASCII digits only. ``str.isdigit()`` is True
# for Unicode decimal digits ("٥"), and ``int("٥")`` is 5.
_DIGITS = re.compile(r"^[0-9]+$")


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
        # Set once the connection's framing is UNRECOVERABLE (RFC 9112 §6.3 / §9.6): a
        # body-declaring 204/304, or anything after a 101. Every later read is NO CHANNEL,
        # because the bytes still on the socket are not HTTP/1.1 responses and parsing them
        # as one is exactly how a benign origin's leftovers become "response 2".
        self._poisoned = ""
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
            m = _CHUNK_SIZE.match(line.split(b";", 1)[0])
            if m is None:
                # Not RFC chunk-size syntax. Covers the ``int()`` leniency the original
                # inherited (``-5``/``+5``/``0x5``/``1_0``/Unicode digits) and plain junk.
                return None
            size = int(m.group(1), 16)
            if size == 0:
                return bytes(out) if self._consume_trailers() else None
            if not self._need(size + 2):
                return None
            out.extend(self._buf[:size])
            del self._buf[: size + 2]

    @staticmethod
    def _declares_a_body(headers: "dict[str, str]") -> bool:
        """The headers claim a message body — used only to decide whether a status that
        MUST NOT have one has poisoned the connection."""
        if "chunked" in headers.get("transfer-encoding", "").lower():
            return True
        cl = headers.get("content-length")
        return cl is not None and cl.strip() not in ("", "0")

    def _read_body(self, headers: "dict[str, str]", status: "int | None") -> "bytes | None":
        # A bodyless status carries no body whatever the headers say (RFC 9112 §6.3). The
        # bytes it wrongly declared are NOT consumed here — they are not part of this
        # response — so ``read_response`` poisons the connection instead of letting them be
        # re-parsed as "response 2".
        if status in (204, 304, 101):
            return b""
        if "chunked" in headers.get("transfer-encoding", "").lower():
            return self._read_chunked()
        cl = headers.get("content-length")
        if cl is not None:
            # A malformed Content-Length was already refused in ``_read_head``; this is the
            # validated value.
            n = int(cl)
            if not self._need(n):
                return None                       # declared more than the peer ever sent
            body = bytes(self._buf[:n])
            del self._buf[:n]
            return body
        # No length framing: the body runs to connection close. Draining it should therefore
        # END with the peer closing; if instead the READ BUDGET ran out or the socket timed
        # out, the body is TRUNCATED and correction #5 applies — it is not a complete
        # response. (The original returned the partial bytes as ``channel=True`` AND set
        # ``_closed``, which both contradicted #5 and lied about the peer having closed.)
        while self._recv():
            pass
        if not self._closed:
            return None
        body = bytes(self._buf)
        self._buf.clear()
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
        cl_values: list[str] = []
        for ln in lines[1:]:
            i = ln.find(b":")
            if i > 0:
                name = ln[:i].strip().lower().decode("latin-1", "replace")
                value = ln[i + 1:].strip().decode("latin-1", "replace")
                if name == "content-length":
                    # A single field may itself carry a comma-separated list (RFC 9112 §6.3
                    # treats "5, 5" as valid and "5, 6" as invalid), and the field may repeat.
                    cl_values.extend(v.strip() for v in value.split(","))
                headers[name] = value
        if cl_values:
            # RFC 9112 §6.3: multiple Content-Length fields with DIFFERING values, or a single
            # invalid value, make the message framing invalid and the recipient MUST treat it
            # as an UNRECOVERABLE error. The header dict above is last-wins, so before this
            # check `Content-Length: 5` + `Content-Length: 40` framed the response at one
            # length and handed the remainder to the next read as "response 2" — a fabricated
            # second response built out of the first one's body. Refuse the response AND
            # poison the connection: nothing after an unrecoverably framed message can be
            # located.
            if len(set(cl_values)) != 1 or not _DIGITS.match(cl_values[0]):
                self._poisoned = (
                    f"the {status} response's Content-Length is unrecoverable "
                    f"({cl_values!r}) — RFC 9112 §6.3 requires rejecting differing or "
                    f"invalid Content-Lengths, so the rest of this connection cannot be framed")
                self.last_error = self._poisoned
                return None
            headers["content-length"] = cl_values[0]
        return status, reason, headers

    def read_response(self) -> dict:
        """Read exactly ONE complete HTTP response, skipping 1xx INTERIM responses.

        Returns ``{"channel", "status", "reason", "body"}``. ``channel`` is False — with the
        reason in :attr:`last_error` — when the peer sent no header block, when the next bytes
        are not a status line, or when the body was truncated. A partial or unframed read is
        NEVER returned as a response."""
        self.last_error = ""
        if self._poisoned:
            return self._no_channel(self._poisoned)
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
            if status == 101:
                # RFC 9112 §9.6: after 101 the connection has LEFT HTTP/1.1. Anything that
                # follows is upgraded-protocol data; parsing it as a response manufactures
                # one out of frame bytes.
                self._poisoned = ("the 101 response switched protocols — the bytes that "
                                  "follow are not HTTP/1.1 responses")
            elif status in (204, 304) and self._declares_a_body(headers):
                # RFC 9112 §6.3: these statuses never carry a body. A sender that declares
                # one has made the connection's framing unrecoverable — and those declared
                # bytes are exactly what used to come back as "response 2".
                self._poisoned = (
                    f"the {status} response declared a message body, which RFC 9112 §6.3 "
                    f"forbids — the connection's framing is unrecoverable")
            return {"channel": True, "status": status, "reason": reason,
                    "body": body.decode("latin-1", "replace")}
        return self._no_channel(
            f"more than {_MAX_INTERIM} consecutive 1xx interim responses — no final response")
