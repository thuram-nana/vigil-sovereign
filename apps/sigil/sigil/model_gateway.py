"""PRICING M1b — the SOVEREIGN model gateway: every customer-run model request goes through here (design §5.1).

An Anthropic Messages API reverse proxy on loopback. The keyless offense runners (Strix through ``LLM_API_BASE``,
Claude Code through ``ANTHROPIC_BASE_URL``) send their requests here with an owner-signed per-run MODEL GRANT
(``vigil_core.model_grant``) as their API key. The runner is semi-trusted (a hostile scan target can prompt-inject
it), so everything below holds against a caller that sends whatever it likes. The gateway:

  * **authenticates** the grant against the owner key, and refuses an expired one, or one whose run was settled;
  * **holds the provider key** — it is added here and never leaves the sovereign plane: the upstream must be
    ``https`` (plain http only to loopback), a redirect is never followed, and only three response headers pass back;
  * **forwards only what the meter can price (an ALLOWLIST, never a denylist)** — the grant's model only; a known
    set of request fields (anything else is refused by name); messages that carry only a role and content; an
    allowlist of content-block types (every server-tool block — a web fetch result, a server tool call, an MCP
    block — and container uploads are refused, wherever they are nested); images only inline (base64: an image by
    URL would have Anthropic fetch a URL the runner chose); documents only as inline text; no citations (they add
    input tokens the bytes do not show); a cache marker only as exactly ``{"type": "ephemeral"}``; only tools the client
    executes, by exact type (a tool Anthropic runs on its side — web search, code execution, the advisor's second
    model, MCP — is refused, as is any tool that names a ``model``); only ``clear_*`` context edits (server-side
    compaction is billed outside the top-level usage); only known ``anthropic-beta`` values (others are dropped);
    no client query string except ``beta=true``;
  * **pins what changes a price** — ``output_config.effort`` = the grant's effort; thinking = adaptive (dropped
    under a forced tool choice); sampling parameters and ``speed`` dropped; ``service_tier`` forced to
    ``standard_only``; ``inference_geo`` forced to ``global`` (US-only inference costs 1.1x); every cache write forced
    to the 5-minute TTL (a 1-hour write costs 2x input);
  * **keeps tenants apart on the one account** — a per-tenant block is prepended to the system prompt and no tool
    definition may carry a cache breakpoint, so no two tenants ever share a prompt-cache prefix (the cache is scoped
    to VIGIL's workspace, not to a tenant);
  * **enforces the budget before it spends** — the worst case of each request is RESERVED against the grant's cap
    before it is forwarded: its output (``max_tokens`` × the output price, ``max_tokens`` lowered to fit) AND its
    input. The input bound is the request's size in bytes (a token is never shorter than a byte) plus an allowance
    per image and per Anthropic-defined tool definition; when that loose bound does not fit what is left, the
    provider's free ``count_tokens`` gives the tight one. Input is priced at the dearest rate it can be billed at,
    except a prompt-cache prefix the provider will read: one this launch wrote or read within the cache lifetime
    (less the longest the gateway can take to admit the request), that the request re-sends unchanged with the same
    render state (every other request field, the forwarded betas, the image count) and with a breakpoint within the
    provider's 20-block lookback of where the entry was written, and no server-side context edits; that part is
    reserved at the cache-read rate. Concurrent requests cannot jointly pass the cap. A request
    that does not fit only because another is still in flight waits, then gets a retryable 429; one the gateway
    cannot size (no count) gets a retryable 529; a spent budget is a 403;
  * **meters with a write-ahead record** — the launch's hash-chained meter file gets an ``open`` line (fsynced,
    stamped with this gateway process's boot id) BEFORE the request is forwarded and a ``usage`` or ``release``
    line after. A crash in between leaves a record: the next gateway to start, or the settle step, records it as
    an ``orphan`` — counted against the run's cap and the account's day, never billed to the customer. A meter that
    cannot be written refuses the request; a record that cannot be written after the call is kept and retried
    every few seconds, and the launch is refused (and its settle waits) until it is written;
  * **streams without buffering**, keeps reading an upstream stream after its client goes away or stops reading (so
    the tokens Anthropic bills are still metered), and treats a stream that ends without its final usage as
    unconfirmed spend up to its reservation (only the provider's own ``error`` event before any message frees it);
  * **protects VIGIL's one account** (design §5.2) — at most ``tenant_concurrency`` in-flight requests per tenant and
    ``global_concurrency`` across all of them (``count_tokens`` has its own, equal bounds), a request over a limit
    waits briefly, then gets a ``rate_limit_error`` with ``retry-after``; a bound on open connections (when it is
    full, the oldest connection that has not started a request gives up its place), one request per connection, a
    short deadline on the request line and headers, a deadline on the whole request and an idle deadline on every
    client socket; a bound on request bytes in memory per tenant and overall (a parsed body is many times its
    size); and an optional account-wide daily spend ceiling (``overloaded_error`` once reached, so the run fails on
    VIGIL's side);
  * **stops cleanly** — ``server_close`` cuts connections that have not started a request, refuses any that starts
    after it, waits for the requests in flight to be metered and for every record a failed write still owes to be
    written, and only then gives up the meter directory (if either is still pending at the deadline, it keeps the
    lock until the process exits), so a settle step can never mistake a live request for a crash's leftover; a
    forked child closes every meter lock file it inherited;
  * **tells a run its budget** — ``GET /v1/vigil/budget`` with the grant returns what the run has spent and has left,
    so the engine can stop testing at 90% and write its report (design §3);
  * answers every refusal in Anthropic's error shape, so the runners stop cleanly.

What is NOT bounded (each is VIGIL's cost — the settle clamps the customer's charge to the reservation):

  * the provider billing more input than its own ``count_tokens`` estimate said (the gateway adds 5% to it);
  * a prompt-cache read the provider does not make although every condition above holds (it evicts the entry
    early, or a cache rule the gateway does not model applies): that request costs up to its cached prefix ×
    (write − read rate) more than reserved;
  * the definition allowances of the Anthropic-defined tools being below what Anthropic adds (they are set above the
    published figures).

Relationship to ``vigil_core.ai_gateway``: that is the chokepoint for VIGIL's OWN model calls (classify, redact,
authorize, audit). This gateway carries the CUSTOMER-RUN agent traffic (Strix, Claude Code), which never went
through ``ai_gateway``; it adds key custody, pinning, metering and the account protections, and passes request
bodies through unredacted, because an agent's prompts are its working state.

DEFAULT-OFF: nothing here runs unless a caller starts it (``start``); M1c wires it. FATAL-2: sovereign-only.
"""
from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import logging
import os
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import weakref
from contextlib import contextmanager
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional, Sequence

from .reuse import assert_no_offense

assert_no_offense()

from vigil_core import model_metering as mm  # noqa: E402
from vigil_core.model_grant import ModelGrant, decode_token  # noqa: E402

__all__ = ["GatewayConfig", "GrantMeter", "MeterBusy", "MeterTotals", "ModelGateway", "config_from_env", "start",
           "start_from_env"]

_log = logging.getLogger(__name__)

MESSAGES_PATH = "/v1/messages"
COUNT_TOKENS_PATH = "/v1/messages/count_tokens"
BUDGET_PATH = "/v1/vigil/budget"
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
_PASS_RESPONSE_HEADERS = ("request-id", "retry-after", "x-should-retry")
_MIN_OUTPUT_TOKENS = 1024        # below this a request cannot do useful work: the run's budget is reached

# --- what a request may carry (allowlists: a field, tool or beta the meter cannot price never reaches the provider)
_DROPPED_KEYS = ("temperature", "top_p", "top_k",          # sampling: the run's model rejects them
                 "speed", "inference_geo")                 # fast mode and US-only inference bill at a premium
_ALLOWED_KEYS = frozenset({"model", "messages", "system", "max_tokens", "tools", "tool_choice", "stream",
                           "stop_sequences", "metadata", "thinking", "output_config", "cache_control",
                           "context_management", "service_tier"})
_ALLOWED_OUTPUT_CONFIG = frozenset({"effort", "format", "task_budget"})
# Tools the CLIENT executes, by exact type, with the input tokens Anthropic adds for each definition (the request's
# bytes do not show them). An untyped / ``custom`` tool's definition is in the request. Every tool Anthropic executes
# on its side is refused: web search / fetch (a server-side loop whose input is not in the request), code execution
# (container time), the advisor (another model's tokens), MCP (Anthropic connects to a URL the runner chose), and
# any type not listed here.
_CLIENT_TOOLS = {"bash_20250124": 400, "text_editor_20250124": 1_100, "text_editor_20250429": 1_100,
                 "text_editor_20250728": 1_100}
_TOOL_PREAMBLE_TOKENS = 500      # the tool-use system prompt Anthropic adds when a request declares any tool
# The content blocks a request may carry (by type); everything else — the server-tool blocks (server_tool_use,
# web_search / web_fetch / code execution results, MCP blocks), container uploads, compaction — is refused.
_BLOCK_TYPES = frozenset({"text", "image", "document", "tool_use", "tool_result", "thinking", "redacted_thinking",
                          "search_result"})
_MESSAGE_KEYS = frozenset({"role", "content"})
# betas that change no price and add no server-side step; any other value is DROPPED (a body that needs a dropped
# beta is then refused by the provider, which is the fail-closed outcome)
_BETA_PREFIXES = ("claude-code-", "interleaved-thinking-", "fine-grained-tool-streaming-", "context-management-",
                  "task-budgets-", "context-1m-", "token-efficient-tools-", "effort-", "adaptive-thinking-",
                  "structured-outputs-", "computer-use-", "thinking-display-")
_INLINE_DOCUMENT_SOURCES = ("text", "content")
_IMAGE_SOURCES = ("base64",)     # an image by URL would have Anthropic fetch a URL the runner chose
_IMAGE_TOKEN_ALLOWANCE = 6_000   # above the most one image costs on the run's model (high-resolution: ~4,800)
_INPUT_MARGIN_TOKENS = 1_000     # the tool-use preamble and message framing the request's bytes do not show
_COUNT_MARGIN = (105, 100)       # count_tokens is the provider's ESTIMATE: reserve 5% over it
_COUNT_FIELDS = ("model", "messages", "system", "tools", "tool_choice", "thinking")
_PREFIX_FIELDS = frozenset({"tools", "system", "messages", "max_tokens", "stream", "metadata"})
_CACHE_LOOKBACK = 20            # the provider looks back at most 20 blocks from a breakpoint for an earlier entry
_CACHE_LIFETIME_S = 300.0        # a 5-minute cache entry, measured from the start of the request that wrote or read it
_CACHE_MARGIN_S = 10.0
_PREFIXES_PER_LAUNCH = 8         # recent request prefixes remembered per launch (one per conversation, roughly)
_FORWARDED_QUERIES = ("beta=true",)   # the only query string forwarded upstream (Claude Code sends it)


class MeterBusy(RuntimeError):
    """A launch's meter cannot be closed yet: a request is still in flight in the gateway. Retry."""


# ---------------------------------------------------------------------------------------------------------------
# The meter
# ---------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class MeterTotals:
    """What one launch has spent so far.

    ``cost_nano`` is the CONFIRMED spend: the usage Anthropic reported, priced — what the customer's charge is
    computed from. ``unconfirmed_nano`` is spend VIGIL must assume but cannot prove: the reservation of a request
    whose record was lost to a crash, and the part of a cut-off response's reservation its usage did not confirm.
    It counts against the run's cap and the daily ceiling, and is never billed to the customer."""

    usage: mm.Usage
    cost_nano: int
    requests: int
    closed: bool
    unconfirmed_nano: int = 0
    open_requests: int = 0


@dataclass
class _LaunchState:
    spent_nano: int = 0
    unconfirmed_nano: int = 0
    pending_nano: int = 0
    usage: mm.Usage = field(default_factory=mm.Usage)
    requests: int = 0
    closed: bool = False
    poisoned: bool = False                                   # the file failed after a call: refuse the launch
    opens: "dict[str, int]" = field(default_factory=dict)   # request id -> reserved (unmatched ``open`` lines)
    boots: "dict[str, str]" = field(default_factory=dict)   # request id -> the gateway process that wrote its open
    orphaned: "dict[str, int]" = field(default_factory=dict)  # request id -> reserved, for ``orphan`` lines (replay)
    unwritten: list = field(default_factory=list)           # (line, extra unconfirmed) a failed write still owes
    cond: threading.Condition = field(default_factory=threading.Condition)


_LOCK_NAME = ".gateway.lock"
_LIVE_GATEWAY_METERS: "weakref.WeakSet[GrantMeter]" = weakref.WeakSet()


# Every file the meter locks is opened through these, so a fork can close the child's copies: an ``flock`` lives as long
# as ANY copy of its file description, so a forked helper would otherwise keep a lock another thread held at fork
# time (a launch's file mid-write, a settle's probe, the gateway's own lock) for as long as it lives.
_LOCKED_FDS: "set[int]" = set()
_LOCKED_FDS_GUARD = threading.Lock()


def _open_locked_file(path: Path, flags: int) -> int:
    with _LOCKED_FDS_GUARD:
        fd = os.open(path, flags, 0o600)
        _LOCKED_FDS.add(fd)
        return fd


def _close_locked_file(fd: int) -> None:
    with _LOCKED_FDS_GUARD:
        _LOCKED_FDS.discard(fd)
        os.close(fd)


def _drop_locks_in_child() -> None:
    """After a fork, the child drops every lock-file copy it inherited (the parent's own copies are untouched)."""
    fds = list(_LOCKED_FDS)
    _LOCKED_FDS.clear()
    _LOCKED_FDS_GUARD.release()
    for meter in list(_LIVE_GATEWAY_METERS):
        meter._gateway_fd = None
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


os.register_at_fork(before=_LOCKED_FDS_GUARD.acquire, after_in_parent=_LOCKED_FDS_GUARD.release,
                    after_in_child=_drop_locks_in_child)


def _utc_day(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


class GrantMeter:
    """Per-LAUNCH spend, persisted as an append-only, hash-chained JSONL file per launch (``<meter_id>.jsonl``, 0600),
    where ``meter_id`` is ``vigil_core.model_grant.meter_id(engagement_slug, nonce)``: every grant minted for one
    launch meters into one file, and the settle step finds it from the owner-signed lease alone.

    Each line is ``{"n", "ts", "kind", ..., "prev", "h"}`` with ``h = sha256(prev + canonical(line without h))`` and
    ``n`` counting lines from 1, so an edited, dropped or reordered line breaks the chain (:meth:`verify`). Kinds:

      * ``open``    — WRITE-AHEAD: a request (``rid``) was admitted with ``reserved`` nano-USD, before it is sent;
      * ``usage``   — that request's metered response (``cost_nano``; ``held_nano`` when it was cut off);
      * ``release`` — that request spent nothing (a provider error, an unreachable provider);
      * ``orphan``  — an ``open`` no live gateway owns (a crash between the call and its record): unconfirmed spend;
      * ``close``   — the settle step closed the meter; always the last line.

    What the chain cannot show on its own is a file cut off at a line boundary or deleted: the ``close`` line and
    the owner-signed settle that follows are the anchor for a finished run, and the directory is 0700.

    Two processes touch a meter: ONE gateway (it holds ``.gateway.lock`` in the directory for its lifetime, with its
    random BOOT id written in it; a second gateway on the same directory refuses to start) and the settle step. Every
    write holds an ``fcntl`` lock on the file and chains onto the LAST LINE ON DISK. Each ``open`` line carries the
    boot id of the gateway that wrote it, so an ``open`` is in flight only if the gateway that wrote it is the one
    alive now; any other is a dead process's leftover. A starting gateway records every such leftover as an
    ``orphan``. ``close`` creates ``<meter_id>.closed`` first — the gateway checks it, under the same file lock, before
    admitting a request — then refuses with :class:`MeterBusy` while the live gateway still has a request in flight
    for that launch (or still owes the launch a record it could not write), and records a dead process's leftovers
    as orphans itself, so the total the settle signs is never missing a response and never waits on a dead one.

    Across all launches the meter also keeps what VIGIL's account is committed to: the pending reservations and the
    spend of the current UTC day, for the gateway's daily ceiling (design §5.2)."""

    def __init__(self, meter_dir: Path, *, gateway: bool = False, lock_wait_s: float = 2.0):
        self.dir = Path(meter_dir)
        self._states: "dict[str, _LaunchState]" = {}
        self._guard = threading.Lock()
        self._money = threading.Lock()                 # guards the account-wide counters below
        self._global_pending = 0
        self._daily: "dict[str, int]" = {}
        self._gateway_fd: Optional[int] = None
        self._stopped = False
        self.boot = ""
        if gateway:
            self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = _open_locked_file(self.dir / _LOCK_NAME, os.O_RDWR | os.O_CREAT)
            deadline = time.monotonic() + lock_wait_s       # a settle step's liveness probe may hold it a moment
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        _close_locked_file(fd)
                        raise RuntimeError("another model gateway is already metering this directory") from None
                    time.sleep(0.05)
            boot = secrets.token_hex(8)
            try:
                os.ftruncate(fd, 0)
                os.pwrite(fd, boot.encode(), 0)
                os.fsync(fd)
            except BaseException:
                _close_locked_file(fd)                  # never keep the lock over a boot id that was not written
                raise
            self.boot = boot
            self._gateway_fd = fd
            _LIVE_GATEWAY_METERS.add(self)
            self._orphan_dead_opens()

    def shutdown(self) -> None:
        """Give up the gateway role (the process is stopping): nothing is admitted after it. Idempotent."""
        self._stopped = True
        fd, self._gateway_fd = self._gateway_fd, None
        if fd is not None:
            _close_locked_file(fd)

    def _live_boot(self) -> Optional[str]:
        """The boot id of the gateway alive on this directory, ``"?"`` when one is alive but its id cannot be read
        yet (it is starting), or None when none is alive. Probed with a SHARED lock, which a live gateway's
        exclusive lock refuses."""
        if self._gateway_fd is not None:
            return self.boot
        try:
            fd = _open_locked_file(self.dir / _LOCK_NAME, os.O_RDWR | os.O_CREAT)
        except OSError:
            return "?"                                  # cannot tell: assume one is (the settle retries)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError:
                boot = os.pread(fd, 64, 0).decode("ascii", "replace").strip()
                return boot or "?"
            fcntl.flock(fd, fcntl.LOCK_UN)
            return None
        finally:
            _close_locked_file(fd)

    def _orphan_dead_opens(self) -> None:
        """At gateway start: every unmatched ``open`` on disk belongs to a process that is gone (this one has written
        none yet), so it is recorded as an ``orphan`` now — counted against its run's cap and the daily ceiling, never
        billed — and a settle never waits on it."""
        for p in sorted(self.dir.glob("*.jsonl")):
            try:
                mid = p.stem
                self._path(mid)
                with self._locked(mid) as fd:
                    st = self._replay(mid)
                    if st.opens and not st.closed:
                        self._orphan(fd, st, list(st.opens), now=time.time())
            except (OSError, ValueError, KeyError):
                _log.exception("model gateway: a meter file could not be checked for a crash's leftovers")

    def _path(self, mid: str, suffix: str = ".jsonl") -> Path:
        if len(mid) != 32 or any(c not in "0123456789abcdef" for c in mid):
            raise ValueError("a meter id must be 32 lowercase hex characters")
        return self.dir / f"{mid}{suffix}"

    # -- the file --------------------------------------------------------------------------------------------
    @contextmanager
    def _locked(self, mid: str) -> "Iterator[int]":
        """The launch's file, opened for append and exclusively locked."""
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = _open_locked_file(self._path(mid), os.O_RDWR | os.O_CREAT | os.O_APPEND)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield fd
        finally:
            _close_locked_file(fd)

    @staticmethod
    def _hash(prev: str, line: Mapping[str, Any]) -> str:
        return hashlib.sha256((prev + json.dumps(line, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()

    @staticmethod
    def _tail(fd: int) -> "tuple[str, int]":
        """``(h, n)`` of the file's last line (``("", 0)`` for an empty file). A TORN final line — a write cut short by
        a crash, so it has no newline — is removed first: it was never a record. Called under the file lock."""
        size = os.lseek(fd, 0, os.SEEK_END)
        if size == 0:
            return "", 0
        chunk = min(size, 1 << 16)
        os.lseek(fd, size - chunk, os.SEEK_SET)
        tail = os.read(fd, chunk)
        if not tail.endswith(b"\n"):
            cut = tail.rfind(b"\n")
            if cut < 0 and chunk < size:
                raise ValueError("meter file has an over-long torn line")
            size = size - chunk + cut + 1
            os.ftruncate(fd, size)
            _log.error("model gateway: removed a torn final line from a meter file (a write was cut short)")
            if size == 0:
                return "", 0
            tail = tail[:cut + 1]
        last = json.loads(tail.rstrip(b"\n").rsplit(b"\n", 1)[-1])
        return str(last["h"]), int(last["n"])

    def _write(self, fd: int, line: dict) -> None:
        """Append one line, chained onto the last line on disk, all of it or none of it. Called under the file lock."""
        prev, n = self._tail(fd)
        line = {**line, "n": n + 1, "prev": prev}
        data = (json.dumps({**line, "h": self._hash(prev, line)}, sort_keys=True, separators=(",", ":")) + "\n").encode()
        size = os.lseek(fd, 0, os.SEEK_END)
        try:
            done = 0
            while done < len(data):
                done += os.write(fd, data[done:])
            os.fsync(fd)
        except OSError:
            try:
                os.ftruncate(fd, size)                  # never leave half a line behind
            except OSError:
                pass
            raise

    def _lines(self, mid: str):
        """Yield every line of a meter file after checking its hash chain and line numbers (raises ``ValueError`` if
        broken). A torn final line (no newline) is not a record and is skipped."""
        p = self._path(mid)
        try:
            raw = p.read_bytes()
        except FileNotFoundError:
            return
        if not raw.endswith(b"\n"):
            raw = raw[:raw.rfind(b"\n") + 1]
        last = ""
        for text in raw.decode("utf-8").splitlines():
            line = json.loads(text)
            h = line.pop("h")
            if self._hash(last, line) != h:             # ``line`` carries ``prev`` and ``n``: both are covered
                raise ValueError(f"meter file {mid[:8]}… is corrupt (hash chain broken)")
            last = h
            yield line, h

    def _replay(self, mid: str) -> _LaunchState:
        """The launch's state from its file. A record of the wrong shape is corruption, like a broken chain: it raises
        ``ValueError`` (never a TypeError or KeyError a caller would not expect)."""
        try:
            return self._replay_records(mid)
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"meter file {mid[:8]}… is corrupt (a malformed record: {type(exc).__name__})") from None

    def _replay_records(self, mid: str) -> _LaunchState:
        st = _LaunchState()
        for line, _h in self._lines(mid):
            kind = line["kind"]
            rid = str(line.get("rid"))
            if kind == "open":
                st.opens[rid] = int(line["reserved"])
                st.boots[rid] = str(line.get("boot", ""))
            elif kind in ("usage", "release"):
                st.opens.pop(rid, None)
                # a record that arrives after its request was given up as an orphan supersedes the orphan: the
                # request is counted once, as what it really was
                st.unconfirmed_nano -= st.orphaned.pop(rid, 0)
                if kind == "usage":
                    st.usage = st.usage + mm.Usage(**line["usage"])
                    st.spent_nano += int(line["cost_nano"])
                    st.unconfirmed_nano += int(line.get("held_nano", 0))
                    st.requests += 1
            elif kind == "orphan":
                st.opens.pop(rid, None)
                st.orphaned[rid] = int(line["reserved"])
                st.unconfirmed_nano += int(line["reserved"])
            elif kind == "close":
                st.closed = True
        return st

    def _orphan(self, fd: int, st: _LaunchState, rids: "list[str]", *, now: float) -> None:
        """Record each of ``rids`` (unmatched ``open`` lines no live gateway owns) as an ``orphan``: unconfirmed
        spend against the run's cap and the account's day. Under the file lock."""
        if not rids:
            return
        day = _utc_day(now)
        with self._money:
            self._day_spend(day)                        # seed the day BEFORE these lines are on disk
        for rid in rids:
            reserved = st.opens.pop(rid)
            self._write(fd, {"kind": "orphan", "ts": now, "rid": rid, "reserved": reserved})
            st.orphaned[rid] = reserved
            st.unconfirmed_nano += reserved
            with self._money:
                self._daily[day] = self._daily.get(day, 0) + reserved
            _log.error("model gateway: a request's record was lost (its gateway process ended between the call and "
                       "the meter); its reservation is counted as unconfirmed spend")

    def _state(self, mid: str) -> _LaunchState:
        with self._guard:
            st = self._states.get(mid)
            if st is None:
                if self._gateway_fd is not None and self._path(mid).exists():
                    # the ONE gateway, loading a launch it has no memory of: an open it did not write is dead
                    with self._locked(mid) as fd:
                        st = self._replay(mid)
                        if st.opens and not st.closed:
                            self._orphan(fd, st, [r for r in st.opens if st.boots.get(r) != self.boot],
                                         now=time.time())
                        st.opens.clear()
                else:
                    st = self._replay(mid)
                    st.opens.clear()                    # this process tracks only the requests it admits itself
                self._states[mid] = st
            return st

    def _closed_elsewhere(self, mid: str) -> bool:
        return self._path(mid, ".closed").exists()

    def mark_metered(self, mid: str) -> None:
        """Record, durably, that launch ``mid`` is billed metered (written when its grant is minted, before its lease
        is published). The settle decides flat or metered from this, never from a flag that may have changed since.
        Raises ``OSError`` if it cannot be written (the publish then refuses)."""
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self._path(mid, ".metered"), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        dfd = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def was_metered(self, mid: str) -> bool:
        """True iff launch ``mid`` was published metered or ever metered (its marker or its meter is on disk)."""
        return self._path(mid, ".metered").exists() or self._path(mid).exists()

    def is_closed(self, mid: str) -> bool:
        st = self._state(mid)
        with st.cond:
            if st.closed or self._closed_elsewhere(mid):
                st.closed = True
            return st.closed

    def _day_spend(self, day: str) -> int:
        """Spend on ``day`` (UTC) across every launch, confirmed and unconfirmed. Seeded once per day from the meter
        files modified on or after that day (a file not appended to since an earlier day cannot hold a line from this
        one), so a restarted gateway still knows the day's total. ``now`` and the file times are the same wall clock
        in production. Called under ``self._money``."""
        if day not in self._daily:
            total = 0
            if self.dir.exists():
                for p in self.dir.glob("*.jsonl"):
                    try:
                        if _utc_day(p.stat().st_mtime) < day:
                            continue
                        for line, _h in self._lines(p.stem):
                            if _utc_day(float(line["ts"])) != day:
                                continue
                            if line["kind"] == "usage":
                                total += int(line["cost_nano"]) + int(line.get("held_nano", 0))
                            elif line["kind"] == "orphan":
                                total += int(line["reserved"])
                    except (OSError, ValueError, KeyError, TypeError, AttributeError):
                        continue        # a corrupt file is the settle step's error to raise, not the ceiling's
            self._daily = {day: total}  # keep only today
        return self._daily[day]

    # -- admission -------------------------------------------------------------------------------------------
    def headroom(self, grant: ModelGrant) -> int:
        """What the run's cap still allows right now (cap − spent − unconfirmed − in flight)."""
        st = self._state(grant.meter_id)
        with st.cond:
            return grant.cap_nano_usd - st.spent_nano - st.unconfirmed_nano - st.pending_nano

    def reserve(self, grant: ModelGrant, max_output_cost: int, output_price: int, *, now: float,
                input_cost: int = 0, daily_limit_nano: Optional[int] = None,
                wait_s: float = 0.0) -> "tuple[str, int, str]":
        """Reserve the worst case of one request — ``input_cost`` plus its output — and write its ``open`` line.
        Returns ``(rid, reserved_nano, "")``, with the output part lowered to what the run's cap still allows, or
        ``("", 0, reason)`` when the request must be refused: ``closed`` (the run was settled), ``budget`` (the cap
        is spent), ``held`` (it would fit but for requests still in flight, after waiting ``wait_s``), ``capacity``
        (the account's daily ceiling) or ``meter`` (the meter cannot be written: nothing may be forwarded)."""
        mid = grant.meter_id
        if output_price <= 0:
            return "", 0, "meter"
        st = self._state(mid)
        deadline = time.monotonic() + max(0.0, wait_s)
        with st.cond:
            while True:
                if st.poisoned:
                    return "", 0, "meter"
                if st.closed:
                    return "", 0, "closed"
                left = grant.cap_nano_usd - st.spent_nano - st.unconfirmed_nano
                if (left - input_cost) // output_price < _MIN_OUTPUT_TOKENS:
                    return "", 0, "budget"
                affordable = (left - st.pending_nano - input_cost) // output_price
                if affordable >= _MIN_OUTPUT_TOKENS:
                    break
                wait = deadline - time.monotonic()
                if wait <= 0 or not st.cond.wait(timeout=wait):
                    return "", 0, "held"
            reserved = input_cost + min(max_output_cost, affordable * output_price)
            with self._money:
                if daily_limit_nano is not None and (
                        self._day_spend(_utc_day(now)) + self._global_pending + reserved > daily_limit_nano):
                    return "", 0, "capacity"
                self._global_pending += reserved
            rid = secrets.token_hex(8)
            try:
                with self._locked(mid) as fd:
                    if self._stopped:                   # gave up the directory: an open now would read as dead
                        raise _Stopped()
                    if self._closed_elsewhere(mid):     # re-checked under the file lock the settle step holds
                        st.closed = True
                        raise _Closed()
                    self._write(fd, {"kind": "open", "ts": now, "rid": rid, "reserved": reserved,
                                     "org_id": grant.org_id, "grant_id": grant.grant_id, "boot": self.boot})
            except _Closed:
                with self._money:
                    self._global_pending -= reserved
                return "", 0, "closed"
            except _Stopped:
                with self._money:
                    self._global_pending -= reserved
                return "", 0, "meter"
            except (OSError, ValueError):
                with self._money:
                    self._global_pending -= reserved
                _log.exception("model gateway: a launch's meter cannot be written; refusing its requests")
                return "", 0, "meter"
            st.pending_nano += reserved
            st.opens[rid] = reserved
            return rid, reserved, ""

    def _settle(self, grant: ModelGrant, rid: str, line: dict, *, cost: int, held: int, usage: Optional[mm.Usage],
                now: float) -> None:
        """Write one request's closing line and move its reservation out of ``pending``. If the line cannot be
        written the spend is still counted in memory (at no less than the reservation), the launch is refused until
        the line is written (:meth:`flush_unwritten` retries it), and its settle waits for that — never free, never
        settled on a total that is missing it."""
        mid = grant.meter_id
        st = self._state(mid)
        with st.cond:
            reserved = st.opens.pop(rid, 0)
            with self._money:
                day = _utc_day(now)
                self._day_spend(day)                    # seed the day BEFORE this line is on disk
            record = {**line, "ts": now, "rid": rid}
            try:
                with self._locked(mid) as fd:
                    self._write(fd, record)
            except (OSError, ValueError):
                _log.exception("model gateway: could not record a metered response; stopping this launch")
                st.poisoned = True
                extra = max(held, reserved - cost, 0) - held
                st.unwritten.append((record, extra))
                held += extra
            st.pending_nano = max(0, st.pending_nano - reserved)
            if usage is not None:
                st.usage = st.usage + usage
                st.requests += 1
            st.spent_nano += cost
            st.unconfirmed_nano += held
            with self._money:
                self._global_pending = max(0, self._global_pending - reserved)
                self._daily[day] = self._daily.get(day, 0) + cost + held
            st.cond.notify_all()

    def release(self, grant: ModelGrant, rid: str, *, now: float) -> None:
        """The request spent nothing: give its reservation back."""
        self._settle(grant, rid, {"kind": "release"}, cost=0, held=0, usage=None, now=now)

    def commit(self, grant: ModelGrant, rid: str, usage: mm.Usage, cost_nano: int, *, request_id: str, now: float,
               held_nano: int = 0) -> None:
        """Record one metered response and release its reservation. ``held_nano`` is spend the response did not
        confirm (it was cut off): counted against the cap, not billed. Recorded even when the meter was closed
        while the request was in flight: Anthropic bills it either way, so the meter must show it."""
        line = {"kind": "usage", "org_id": grant.org_id, "grant_id": grant.grant_id, "model": grant.model,
                "request_id": request_id, "usage": usage.as_dict(), "cost_nano": cost_nano}
        if held_nano:
            line["held_nano"] = held_nano
        self._settle(grant, rid, line, cost=cost_nano, held=held_nano, usage=usage, now=now)

    def owed(self) -> int:
        """How many records a failed write still owes, across every launch."""
        with self._guard:
            states = list(self._states.values())
        return sum(len(st.unwritten) for st in states)

    def flush_unwritten(self) -> int:
        """Retry every record a failed write still owes (the gateway calls this every few seconds). A launch whose
        records are all written again is admitted again. Returns how many records were written."""
        with self._guard:
            states = list(self._states.items())
        written = 0
        for mid, st in states:
            with st.cond:
                if not st.unwritten:
                    continue
                try:
                    with self._locked(mid) as fd:
                        while st.unwritten:
                            record, extra = st.unwritten[0]
                            self._write(fd, record)
                            st.unwritten.pop(0)
                            st.unconfirmed_nano -= extra        # the record now says what the request really cost
                            with self._money:
                                day = _utc_day(float(record["ts"]))
                                if day in self._daily:
                                    self._daily[day] -= extra
                            written += 1
                except (OSError, ValueError):
                    continue
                st.poisoned = False
                st.cond.notify_all()
        return written

    # -- settle ----------------------------------------------------------------------------------------------
    def close(self, mid: str, *, now: float) -> MeterTotals:
        """Close the meter (idempotent, from any process) and return its final totals, read back from the file.
        Admission stops first (the ``.closed`` file). While the LIVE gateway still has a request of this launch in
        flight (an ``open`` carrying its boot id) this raises :class:`MeterBusy` — the caller retries — so the total
        it signs is never missing a response. An ``open`` written by any other (dead) gateway process is a leftover
        and is recorded as an ``orphan``."""
        with self._locked(mid) as fd:
            sentinel = os.open(self._path(mid, ".closed"), os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(sentinel)
            st = self._replay(mid)
            if not st.closed:
                if st.opens:
                    live = self._live_boot()
                    alive = [r for r in st.opens if live == "?" or (live is not None and st.boots.get(r) == live)]
                    if alive:
                        raise MeterBusy(f"meter {mid[:8]}… still has {len(alive)} request(s) in flight")
                    self._orphan(fd, st, list(st.opens), now=now)
                self._write(fd, {"kind": "close", "ts": now})
        mem = self._states.get(mid)
        if mem is not None:
            with mem.cond:
                mem.closed = True
                mem.cond.notify_all()
        return self.verify(mid)

    def totals(self, mid: str) -> MeterTotals:
        st = self._state(mid)
        with st.cond:
            return MeterTotals(st.usage, st.spent_nano, st.requests, st.closed, st.unconfirmed_nano, len(st.opens))

    def pending(self, mid: str) -> int:
        st = self._state(mid)
        with st.cond:
            return st.pending_nano

    def verify(self, mid: str) -> MeterTotals:
        """Re-read the launch's file from disk, checking the hash chain (raises ``ValueError`` if broken)."""
        st = self._replay(mid)
        return MeterTotals(st.usage, st.spent_nano, st.requests, st.closed, st.unconfirmed_nano, len(st.opens))


class _Closed(Exception):
    pass


class _Stopped(Exception):
    pass


# ---------------------------------------------------------------------------------------------------------------
# The gateway
# ---------------------------------------------------------------------------------------------------------------

@dataclass
class GatewayConfig:
    api_key: str = field(repr=False)            # never in a repr, a log line or a traceback
    owner_pubkey: str
    meter_dir: Path
    upstream: str = "https://api.anthropic.com"
    prices: Optional[Mapping[str, mm.PriceRow]] = None
    max_body_bytes: int = 16 * 1024 * 1024
    tenant_body_bytes: int = 32 * 1024 * 1024   # request bodies one tenant may have in memory at once ...
    global_body_bytes: int = 128 * 1024 * 1024  # ... and all of them together (a parsed body is many times its bytes)
    upstream_timeout_s: float = 600.0
    client_timeout_s: float = 60.0              # a client socket that neither reads nor writes for this long is dropped
    request_deadline_s: float = 60.0            # the whole request (line, headers, body) must arrive within this
    header_deadline_s: float = 5.0              # ... and its request line and headers within this
    shutdown_drain_s: float = 660.0             # how long ``server_close`` waits for requests in flight
    egress_check: Optional[Callable[[str], None]] = None        # raises to refuse (the sovereignty tier)
    opener: Any = None                                         # urllib opener (tests inject one)
    clock: Callable[[], float] = time.time
    tenant_concurrency: int = 4                 # in-flight model requests per tenant (org_id)
    global_concurrency: int = 32                # in-flight model requests across every tenant (the account's tier)
    concurrency_wait_s: float = 30.0            # how long a request over a limit waits before a rate_limit_error
    max_connections: int = 256                  # open client connections; one over is closed unanswered
    daily_limit_nano: Optional[int] = None      # account-wide spend ceiling per UTC day (None = no ceiling)


class _Refusal(Exception):
    def __init__(self, status: int, kind: str, message: str, *, retry_after: Optional[int] = None):
        super().__init__(message)
        self.status, self.kind, self.message, self.retry_after = status, kind, message, retry_after


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: urllib would re-send the provider key to whatever host the redirect names."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _error_body(kind: str, message: str) -> bytes:
    return json.dumps({"type": "error", "error": {"type": kind, "message": message}}).encode()


def _bad(message: str) -> _Refusal:
    return _Refusal(400, "invalid_request_error", message)


def _check_upstream(url: str) -> None:
    """The provider key only ever travels over TLS; plain http is for a loopback upstream (tests, a local relay)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https" and u.hostname:
        return
    if u.scheme == "http" and u.hostname in ("127.0.0.1", "::1"):
        return
    raise ValueError("the model gateway's upstream must be https (http only to loopback)")


class ModelGateway:
    def __init__(self, config: GatewayConfig):
        key = config.api_key
        if not key:
            raise ValueError("the model gateway needs the provider API key")
        if not key.isascii() or not key.isprintable() or " " in key:
            # a newline in a header value makes http.client raise WITH the value in its message, which would be logged
            raise ValueError("the provider API key contains a character that cannot be sent in a header")
        if not config.owner_pubkey:
            raise ValueError("the model gateway needs the owner public key to verify grants")
        if config.tenant_concurrency < 1 or config.global_concurrency < 1 or config.max_connections < 1:
            raise ValueError("the gateway's concurrency limits must be at least 1")
        _check_upstream(config.upstream)
        self.config = config
        self.prices = dict(config.prices) if config.prices is not None else mm.price_table()
        self.meter = GrantMeter(config.meter_dir, gateway=True)
        if config.opener is not None:
            self._opener = config.opener
        elif urllib.parse.urlsplit(config.upstream).scheme == "http":
            # a loopback http upstream is never reached through a proxy: the key would cross it in clear text
            self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        else:
            self._opener = urllib.request.build_opener(_NoRedirect())     # https: a proxy only tunnels the TLS
        self._global_slots = threading.BoundedSemaphore(config.global_concurrency)
        self._count_slots = threading.BoundedSemaphore(config.global_concurrency)
        self._tenant_slots: "dict[str, threading.BoundedSemaphore]" = {}
        self._tenant_count_slots: "dict[str, threading.BoundedSemaphore]" = {}
        self._slots_guard = threading.Lock()
        self._tenant_body: "dict[str, int]" = {}
        self._body_total = 0
        self._prefixes: "dict[str, list[tuple]]" = {}
        self._prefix_guard = threading.Lock()
        self._stop = threading.Event()
        self._flusher = threading.Thread(target=self._flush_loop, name="model-gateway-flush", daemon=True)
        self._flusher.start()

    def _flush_loop(self) -> None:
        while not self._stop.wait(5.0):
            try:
                self.meter.flush_unwritten()
            except Exception:  # noqa: BLE001 — the flusher never dies; the next pass retries
                _log.exception("model gateway: re-writing an owed meter record failed")

    def stop(self) -> None:
        self._stop.set()

    def acquire_slots(self, org_id: str) -> "Callable[[], None]":
        """Take one tenant slot and one account slot (waiting up to ``concurrency_wait_s``) and return the function
        that gives them back, or raise a ``rate_limit_error`` refusal — so one tenant can never take the whole
        account's rate limit, and all tenants together stay inside it (design §5.2)."""
        with self._slots_guard:
            tenant = self._tenant_slots.setdefault(org_id, threading.BoundedSemaphore(self.config.tenant_concurrency))
        wait = self.config.concurrency_wait_s
        if not tenant.acquire(timeout=wait):
            raise _Refusal(429, "rate_limit_error", "this account has too many requests in flight; retry shortly",
                           retry_after=5)
        if not self._global_slots.acquire(timeout=wait):
            tenant.release()
            raise _Refusal(429, "rate_limit_error", "VIGIL is busy; retry shortly", retry_after=5)

        def give_back() -> None:
            self._global_slots.release()
            tenant.release()
        return give_back

    def acquire_body_bytes(self, org_id: str, n: int) -> "Callable[[], None]":
        """Take ``n`` bytes of the tenant's and the account's request-body budget before a body is read (a parsed
        body holds many times its bytes), or raise a retryable ``rate_limit_error``."""
        with self._slots_guard:
            mine = self._tenant_body.get(org_id, 0)
            if mine + n > self.config.tenant_body_bytes or self._body_total + n > self.config.global_body_bytes:
                raise _Refusal(429, "rate_limit_error", "too much request data is in flight; retry shortly",
                               retry_after=5)
            self._tenant_body[org_id] = mine + n
            self._body_total += n

        def give_back() -> None:
            with self._slots_guard:
                self._tenant_body[org_id] -= n
                if not self._tenant_body[org_id]:
                    del self._tenant_body[org_id]
                self._body_total -= n
        return give_back

    def acquire_count_slot(self, org_id: str) -> "Callable[[], None]":
        """``count_tokens`` is free but shares the account's rate limits: its own bound, apart from the model slots,
        per tenant and across all of them."""
        with self._slots_guard:
            tenant = self._tenant_count_slots.setdefault(
                org_id, threading.BoundedSemaphore(self.config.tenant_concurrency))
        wait = self.config.concurrency_wait_s
        if not tenant.acquire(timeout=wait):
            raise _Refusal(429, "rate_limit_error", "this account has too many requests in flight; retry shortly",
                           retry_after=5)
        if not self._count_slots.acquire(timeout=wait):
            tenant.release()
            raise _Refusal(429, "rate_limit_error", "VIGIL is busy; retry shortly", retry_after=5)

        def give_back() -> None:
            self._count_slots.release()
            tenant.release()
        return give_back

    # -- what a launch has cached (so a request that re-sends a cached prefix is not reserved as fresh input) --
    @staticmethod
    def prefix_key(shaped: dict, *, betas: str = "", images: int = 0) -> tuple:
        """``(render hash, tools hash, system hash, (message hashes...))`` of a shaped request: the parts of its
        prompt-cache prefix, in the provider's cache order. The render hash covers everything else the provider
        renders into the prompt or that changes what it can read from the cache — every other request field
        (tool_choice, the thinking setting as shaped, output_config, top-level cache_control, ...), the forwarded
        betas and the number of images (citations, which also change it, are refused) — so a change to any of them
        is a miss, never a discount."""
        def h(v: Any) -> str:
            return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]
        render = {k: v for k, v in shaped.items() if k not in _PREFIX_FIELDS}
        return (h([render, betas, images]), h(shaped.get("tools") or []), h(shaped.get("system") or []),
                tuple(h(m) for m in shaped.get("messages") or []))

    @staticmethod
    def breakpoints(shaped: dict) -> "list[int]":
        """The block positions of a shaped request's cache breakpoints, in the provider's cache order (each tool,
        each system block, each message content block; a mark nested in a block counts at that block; top-level
        automatic caching marks the last block)."""
        def marked(b: Any) -> bool:
            if not isinstance(b, dict):
                return False
            inner = b.get("content")
            return "cache_control" in b or (isinstance(inner, list) and any(marked(x) for x in inner))
        blocks: "list[Any]" = list(shaped.get("tools") or [])
        system = shaped.get("system")
        blocks += [system] if isinstance(system, str) else list(system or [])
        for m in shaped.get("messages") or []:
            content = m.get("content") if isinstance(m, dict) else None
            blocks += [content] if isinstance(content, str) else list(content or [])
        marks = [i for i, b in enumerate(blocks) if marked(b)]
        if "cache_control" in shaped and blocks:
            marks.append(len(blocks) - 1)
        return marks

    def cached_tokens(self, mid: str, key: tuple, now: float, marks: "Sequence[int]" = ()) -> int:
        """The prompt-cache prefix this launch wrote or read within the cache's lifetime that this request can read:
        the largest ``cache_read + cache_write`` count of a recent request whose render state, tools, system prompt
        and every message are a prefix of this one's, and whose last breakpoint lies within the provider's lookback
        of one of this request's breakpoints (``marks``). 0 when there is none."""
        best = 0
        # the request reaches the provider only after its admission: the count (at most 30 s) and the budget wait
        ttl = (_CACHE_LIFETIME_S - min(30.0, self.config.upstream_timeout_s) - self.config.concurrency_wait_s
               - _CACHE_MARGIN_S)
        with self._prefix_guard:
            for k, tokens, started, last in self._prefixes.get(mid, ()):
                if now - started < ttl and k[:3] == key[:3] and \
                        len(k[3]) <= len(key[3]) and key[3][:len(k[3])] == k[3] and \
                        any(last <= b < last + _CACHE_LOOKBACK for b in marks):
                    best = max(best, tokens)
        return best

    def remember_prefix(self, mid: str, key: tuple, started: float, usage: mm.Usage, last: int) -> None:
        """Remember what a request read or wrote, with the position of its last breakpoint (where it wrote)."""
        tokens = usage.cache_read_tokens + usage.cache_write_5m_tokens + usage.cache_write_1h_tokens
        if tokens <= 0:
            return
        with self._prefix_guard:
            entries = [e for e in self._prefixes.get(mid, []) if e[0] != key]
            entries.append((key, tokens, started, last))
            self._prefixes[mid] = entries[-_PREFIXES_PER_LAUNCH:]

    def budget(self, grant: ModelGrant) -> dict:
        """The run's own budget position, for the engine's wrap-up and the live meter (no provider call).
        ``fraction_spent`` is what has been spent; ``fraction_used`` also counts the requests still in flight."""
        t = self.meter.totals(grant.meter_id)
        pending = self.meter.pending(grant.meter_id)
        cap = grant.cap_nano_usd
        spent = t.cost_nano + t.unconfirmed_nano
        used = spent + pending
        return {"cap_nano_usd": cap, "spent_nano_usd": spent, "pending_nano_usd": pending,
                "remaining_nano_usd": max(0, cap - used), "fraction_used": (min(1.0, used / cap) if cap else 1.0),
                "fraction_spent": (min(1.0, spent / cap) if cap else 1.0),
                "requests": t.requests, "closed": self.meter.is_closed(grant.meter_id)}

    # -- request shaping -------------------------------------------------------------------------------------
    def authenticate(self, headers: Mapping[str, str], *, allow_expired: bool = False) -> ModelGrant:
        token = headers.get("x-api-key") or ""
        auth = headers.get("authorization") or ""
        if not token and auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        grant, reason = decode_token(token, self.config.owner_pubkey)
        if grant is None:
            raise _Refusal(401, "authentication_error", f"invalid model grant: {reason}")
        now = self.config.clock()
        if not allow_expired and now >= grant.not_after:
            raise _Refusal(403, "permission_error", "this run's model grant has expired")
        if grant.issued_at > now + 300:
            raise _Refusal(403, "permission_error", "this run's model grant is not valid yet")
        if grant.model not in self.prices:
            raise _Refusal(403, "permission_error", f"no price for the grant's model {grant.model!r}")
        return grant

    @staticmethod
    def _tenant_block(grant: ModelGrant) -> dict:
        """The block prepended to every request's system prompt: a value unique to the tenant, so no cache
        breakpoint at or after the system prompt can ever match another tenant's request."""
        tag = hashlib.sha256(b"vigil-tenant\x00" + grant.org_id.encode("utf-8")).hexdigest()[:32]
        return {"type": "text", "text": f"[workspace {tag}]"}

    def _walk_content(self, content: Any, found: "dict[str, int]", *, where: str) -> None:
        """Check every content block (an allowlist of block types), pin its cache TTL, count its images, and refuse
        a block whose input size or source the gateway cannot account for: an image by URL, a document that is not
        inline text, any server-tool block. Recurses into every field that carries content blocks (a tool result's
        and a search result's ``content``, an inline document's ``source.content``) — never into a tool call's
        ``input``, which is the model's own data."""
        if isinstance(content, str):
            return
        if not isinstance(content, list):
            raise _bad(f"{where} content must be a string or a list of blocks")
        for block in content:
            if not isinstance(block, dict):
                raise _bad(f"each {where} content block must be an object")
            kind = block.get("type")
            if kind not in _BLOCK_TYPES:
                raise _bad(f"the content block type {str(kind)[:60]!r} is not available to VIGIL runs")
            if where == "system" and kind != "text":
                raise _bad("a system prompt may only hold text blocks")
            self._pin_cache(block, found)
            cites = block.get("citations")
            if isinstance(cites, dict) and cites.get("enabled") or (cites is not None and not isinstance(cites, dict)):
                # citations chunk a document into sentences, adding input tokens its bytes do not show
                raise _bad("VIGIL runs may not enable citations")
            src = block.get("source")
            src_type = src.get("type") if isinstance(src, dict) else None
            if kind == "image":
                if src_type not in _IMAGE_SOURCES:
                    raise _bad("VIGIL runs may send images only inline (base64)")
                found["images"] += 1
            elif kind == "document":
                if not isinstance(src, dict) or src_type not in _INLINE_DOCUMENT_SOURCES:
                    raise _bad("VIGIL runs may send documents only as inline text")
                if src_type == "content":
                    self._walk_content(src.get("content"), found, where=where)
            elif kind in ("tool_result", "search_result") and "content" in block:
                self._walk_content(block.get("content"), found, where=where)

    @staticmethod
    def _pin_cache(block: Any, found: "dict[str, int]") -> None:
        """A cache marker is rebuilt as exactly ``{"type": "ephemeral"}``: the default 5-minute TTL (a 1-hour write
        costs 2x input) and no other option (an allowlist: no scope, nothing the meter does not know)."""
        if not isinstance(block, dict) or "cache_control" not in block:
            return
        cc = block["cache_control"]
        if not isinstance(cc, dict) or cc.get("type") != "ephemeral":
            raise _bad("cache_control must be {\"type\": \"ephemeral\"}")
        block["cache_control"] = {"type": "ephemeral"}
        found["cache_marks"] += 1

    def shape(self, body: Any, grant: ModelGrant, *, count_tokens: bool) -> "tuple[dict, dict]":
        """Validate and pin a request body (see the module docstring). Returns ``(a new dict, what was found in it:
        images, tool-definition tokens, cache markers)``."""
        if not isinstance(body, dict):
            raise _bad("the request body must be a JSON object")
        if body.get("model") != grant.model:
            raise _bad(f"this run may only use {grant.model!r}, not {body.get('model')!r}")
        out = {k: v for k, v in body.items() if k not in _DROPPED_KEYS}
        unknown = sorted(k for k in out if k not in _ALLOWED_KEYS)
        if unknown:
            raise _bad(f"VIGIL runs cannot use the request field(s): {', '.join(str(k)[:40] for k in unknown[:5])}")
        found = {"images": 0, "tool_tokens": 0, "cache_marks": 0}
        tools = out.get("tools")
        if tools is not None:
            if not isinstance(tools, list):
                raise _bad("tools must be a list")
            for t in tools:
                if not isinstance(t, dict):
                    raise _bad("each tool must be an object")
                kind = t.get("type")
                if kind is not None and kind != "custom" and kind not in _CLIENT_TOOLS:
                    raise _bad(f"the tool type {str(kind)[:60]!r} is not available to VIGIL runs")
                if "model" in t:
                    raise _bad("a tool that names its own model is not available to VIGIL runs")
                # no cache breakpoint on a tool: tools come BEFORE the per-tenant system block in the cache order,
                # so a tools-only entry would be shared across tenants
                t.pop("cache_control", None)
                found["tool_tokens"] += _CLIENT_TOOLS.get(kind, 0) if isinstance(kind, str) else 0
            if tools:
                found["tool_tokens"] += _TOOL_PREAMBLE_TOKENS
        cm = out.get("context_management")
        if cm is not None:
            edits = cm.get("edits") if isinstance(cm, dict) else None
            if not isinstance(edits, list) or set(cm) != {"edits"} or any(
                    not isinstance(e, dict) or not str(e.get("type", "")).startswith("clear_") for e in edits):
                raise _bad("VIGIL runs may only use clear_* context edits")
        messages = out.get("messages")
        if not isinstance(messages, list):
            raise _bad("messages must be a list")
        for m in messages:
            if not isinstance(m, dict) or not set(m) <= _MESSAGE_KEYS:
                raise _bad("a message may only carry a role and its content")
            self._walk_content(m.get("content"), found, where="message")
        system = out.get("system")
        if system is None:
            blocks: list = []
        elif isinstance(system, str):
            blocks = [{"type": "text", "text": system}]
        elif isinstance(system, list):
            blocks = system
            self._walk_content(blocks, found, where="system")
        else:
            raise _bad("system must be a string or a list of blocks")
        out["system"] = [self._tenant_block(grant), *blocks]
        self._pin_cache(out, found)
        tc = out.get("tool_choice")
        forced_tool = isinstance(tc, dict) and tc.get("type") in ("any", "tool")
        thinking = out.get("thinking")
        if forced_tool:
            out.pop("thinking", None)      # the API refuses thinking with a forced tool choice
        else:
            pinned: dict = {"type": "adaptive"}
            if isinstance(thinking, dict) and isinstance(thinking.get("display"), str):
                pinned["display"] = thinking["display"]
            out["thinking"] = pinned
        oc = out.get("output_config")
        if oc is not None and not isinstance(oc, dict):
            raise _bad("output_config must be an object")
        if oc and not set(oc) <= _ALLOWED_OUTPUT_CONFIG:
            raise _bad("VIGIL runs cannot use that output_config field")
        out["output_config"] = {**(oc or {}), "effort": grant.effort}
        if count_tokens:
            # counting is free: the same validation, but only the fields the count endpoint takes
            return self.count_body(out), found
        out["service_tier"] = "standard_only"
        out["inference_geo"] = "global"    # never the US-only premium, whatever the workspace default is
        if "stream" in out and not isinstance(out["stream"], bool):
            raise _bad("stream must be true or false")
        mt = out.get("max_tokens")
        if isinstance(mt, bool) or not isinstance(mt, int) or mt < 1:
            raise _bad("max_tokens must be a positive integer")
        return out, found

    @staticmethod
    def count_body(shaped: dict) -> dict:
        """The fields of a shaped request the count endpoint takes (effort and format only from output_config)."""
        out = {k: shaped[k] for k in _COUNT_FIELDS if k in shaped}
        oc = {k: v for k, v in (shaped.get("output_config") or {}).items() if k in ("effort", "format")}
        if oc:
            out["output_config"] = oc
        return out

    @staticmethod
    def _beta(headers: Mapping[str, str]) -> str:
        betas = [b.strip() for b in (headers.get("anthropic-beta") or "").split(",") if b.strip()]
        return ",".join(b for b in betas if b.lower().startswith(_BETA_PREFIXES) and b.isascii() and b.isprintable())

    def _upstream_request(self, path_qs: str, body: dict, headers: Mapping[str, str]) -> urllib.request.Request:
        url = self.config.upstream.rstrip("/") + path_qs
        if self.config.egress_check is not None:
            try:
                self.config.egress_check(url)
            except Exception as exc:  # noqa: BLE001 — the sovereignty tier refused: never egress
                raise _Refusal(403, "permission_error", f"model egress refused by the sovereignty tier: {exc}")
        version = headers.get("anthropic-version") or DEFAULT_ANTHROPIC_VERSION
        if not version.isascii() or not version.replace("-", "").isalnum():
            raise _bad("anthropic-version is not valid")
        h = {"content-type": "application/json", "x-api-key": self.config.api_key, "anthropic-version": version,
             "accept": "text/event-stream" if body.get("stream") is True else "application/json"}
        beta = self._beta(headers)
        if beta:
            h["anthropic-beta"] = beta
        return urllib.request.Request(url, data=json.dumps(body).encode(), headers=h, method="POST")

    def input_bound_tokens(self, raw_len: int, found: Mapping[str, int]) -> int:
        """An upper bound on a request's input tokens from what the gateway can see: a token is never shorter than
        one byte of the request's text, plus an allowance per image, the definition of each Anthropic-defined tool
        and the framing the bytes do not show."""
        return raw_len + found["images"] * _IMAGE_TOKEN_ALLOWANCE + found["tool_tokens"] + _INPUT_MARGIN_TOKENS

    def input_rate(self, model: str) -> int:
        """The dearest an input token can cost on a shaped request (cache writes are pinned to 5 minutes)."""
        row = self.prices[model]
        return max(row.input, row.cache_write_5m, row.cache_read)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "VIGIL-model-gateway"
    sys_version = ""

    @property
    def gw(self) -> ModelGateway:
        return self.server.gateway                       # type: ignore[attr-defined]

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.gw.config.client_timeout_s)   # a deadline on every client read and write
        # ... and one on the whole request: a client that trickles its request line, headers or body (each read
        # inside the idle timeout) is cut off when this fires, so it can hold a connection or a slot only so long
        self._request_read = False
        self._deadline = threading.Timer(self.gw.config.request_deadline_s, self._request_too_slow)
        self._deadline.daemon = True
        self._deadline.start()
        # a connection that has not even sent its headers soon is cut: it holds one of the bounded connection places
        # before any grant is checked
        self._head_deadline = threading.Timer(self.gw.config.header_deadline_s, self.server.cut_if_waiting,  # type: ignore[attr-defined]
                                              args=(self.connection,))
        self._head_deadline.daemon = True
        self._head_deadline.start()

    def _request_too_slow(self) -> None:
        if not self._request_read:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _request_complete(self) -> None:
        self._request_read = True
        self._deadline.cancel()

    def finish(self) -> None:
        self._deadline.cancel()
        self._head_deadline.cancel()
        super().finish()

    def log_message(self, fmt: str, *args: Any) -> None:  # never log request lines (they can carry query data)
        return

    def _headers_lower(self) -> "dict[str, str]":
        return {k.lower(): v for k, v in self.headers.items()}

    def _send(self, status: int, body: bytes, headers: "Optional[Mapping[str, str]]" = None) -> None:
        self.send_response(status)
        self.send_header("content-type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _refuse(self, r: _Refusal) -> None:
        self.close_connection = True              # the request body may be unread: never reuse this connection
        try:
            self._send(r.status, _error_body(r.kind, r.message),
                       {"retry-after": str(r.retry_after)} if r.retry_after is not None else None)
        except OSError:
            pass                                  # the client is gone or stalled: nothing to tell it

    def do_GET(self) -> None:  # noqa: N802
        self.server.request_started(self.connection)   # type: ignore[attr-defined]
        self._request_complete()
        self.close_connection = True              # one request per connection: no idle keep-alive holds a slot
        try:
            if self.path.partition("?")[0] != BUDGET_PATH:
                raise _Refusal(404, "not_found_error", "not found")
            grant = self.gw.authenticate(self._headers_lower(), allow_expired=True)
            self._send(200, json.dumps(self.gw.budget(grant)).encode())
        except _Refusal as r:
            self._refuse(r)
        except OSError:
            self.close_connection = True
        except Exception:  # noqa: BLE001 — e.g. a corrupt meter: fail closed, no detail
            _log.exception("model gateway: internal error")
            self._refuse(_Refusal(500, "api_error", "the VIGIL model gateway failed"))

    def _release_ticket(self) -> None:
        """Release this request's reservation (a no-op once the response was metered, and idempotent) BEFORE a
        refusal is written: a client that sees the refusal and calls again must find its budget already free."""
        ticket = getattr(self, "_ticket", None)
        if ticket is not None:
            ticket.release()

    def do_POST(self) -> None:  # noqa: N802
        path, _, query = self.path.partition("?")
        path_qs = path + (("?" + query) if query in _FORWARDED_QUERIES else "")   # never a client-chosen query
        self.close_connection = True              # one request per connection: no idle keep-alive holds a slot
        self._ticket: Optional[_Ticket] = None
        self._streaming = False
        self._prefix: Optional[tuple] = None
        give_back: "Optional[Callable[[], None]]" = None
        self._body_back: "Optional[Callable[[], None]]" = None
        try:
            if not self.server.request_started(self.connection):   # type: ignore[attr-defined]
                raise _Refusal(529, "overloaded_error", "the VIGIL model gateway is stopping; retry")
            if path not in (MESSAGES_PATH, COUNT_TOKENS_PATH):
                raise _Refusal(404, "not_found_error", "not found")
            headers = self._headers_lower()
            grant = self.gw.authenticate(headers)
            try:
                closed = self.gw.meter.is_closed(grant.meter_id)
            except (OSError, ValueError):
                _log.exception("model gateway: a launch's meter cannot be read; refusing its requests")
                raise _Refusal(529, "overloaded_error", "VIGIL cannot meter this run right now") from None
            if closed:
                raise _Refusal(403, "permission_error", "this run's model grant is closed (the run was settled)")
            count_tokens = path == COUNT_TOKENS_PATH
            # a slot BEFORE the body is read: a tenant holds at most its slots' worth of request bodies in memory
            give_back = (self.gw.acquire_count_slot(grant.org_id) if count_tokens
                         else self.gw.acquire_slots(grant.org_id))
            raw = self._read_body(grant.org_id)
            self._request_complete()
            try:
                body = json.loads(raw)
            except (ValueError, RecursionError):
                raise _bad("the request body is not valid JSON") from None
            shaped, found = self.gw.shape(body, grant, count_tokens=count_tokens)
            del body
            if count_tokens:
                self._forward_plain(path_qs, shaped, headers, grant=None)
                return
            self._admit(grant, shaped, headers, raw_len=len(raw), found=found)
            del raw
            if shaped.get("stream") is True:
                self._forward_stream(path_qs, shaped, headers, grant)
            else:
                self._forward_plain(path_qs, shaped, headers, grant=grant)
        except _Refusal as r:
            if not self._streaming:
                self._release_ticket()            # before the refusal reaches the client, not after
                self._refuse(r)
        except OSError:                           # the client went away or stalled past its deadline
            self.close_connection = True
        except Exception:  # noqa: BLE001 — fail closed: an internal error never forwards and never leaks detail
            _log.exception("model gateway: internal error")
            if not self._streaming:
                self._release_ticket()
                self._refuse(_Refusal(500, "api_error", "the VIGIL model gateway failed"))
            self.close_connection = True
        finally:
            if self._ticket is not None:
                self._ticket.release()                 # a no-op once the response was metered
            if give_back is not None:
                give_back()
            if self._body_back is not None:
                self._body_back()

    def _admit(self, grant: ModelGrant, shaped: dict, headers: Mapping[str, str], *, raw_len: int,
               found: Mapping[str, int]) -> None:
        """Reserve the request's worst case against the run's cap (and write its open line), lowering ``max_tokens``
        to what fits, or raise the refusal.

        The input is reserved at the dearest rate it can be billed at, except for the prompt-cache prefix this launch
        wrote or read within the cache's lifetime and this request re-sends unchanged: that part is reserved at the
        cache-read rate (an agent re-sends its whole context every turn; reserving it as fresh input would stop a run
        at a fraction of its budget). If the provider evicted the entry early, that request costs more than reserved
        — VIGIL's cost, bounded by the cached prefix at the write-minus-read rate."""
        gw = self.gw
        row = gw.prices[grant.model]
        rate = gw.input_rate(grant.model)
        now = gw.config.clock()
        key = gw.prefix_key(shaped, betas=gw._beta(headers), images=found["images"])
        marks = gw.breakpoints(shaped)
        # server-side context edits change the rendered prefix while the client re-sends it unchanged: no discount
        cached = (gw.cached_tokens(grant.meter_id, key, now, marks)
                  if marks and "context_management" not in shaped else 0)

        def input_cost(tokens: int) -> int:
            read = min(cached, tokens)
            return read * row.cache_read + (tokens - read) * rate

        cost = input_cost(gw.input_bound_tokens(raw_len, found))
        headroom = gw.meter.headroom(grant)
        if cost + _MIN_OUTPUT_TOKENS * row.output > headroom:
            # the loose bound does not fit what is left: ask the provider for the tight one (free)
            counted = self._count_input(shaped, headers)
            if counted is not None:
                cost = input_cost(counted * _COUNT_MARGIN[0] // _COUNT_MARGIN[1] + _INPUT_MARGIN_TOKENS)
            elif headroom >= _MIN_OUTPUT_TOKENS * row.output:
                # no count, and the budget is not spent: "cannot size this request now" is retryable, never the
                # terminal "budget is reached"
                raise _Refusal(529, "overloaded_error", "VIGIL cannot size this request right now; retry shortly",
                               retry_after=5)
        rid, reserved, reason = gw.meter.reserve(
            grant, shaped["max_tokens"] * row.output, row.output, now=now, input_cost=cost,
            daily_limit_nano=gw.config.daily_limit_nano, wait_s=gw.config.concurrency_wait_s)
        if reason == "capacity":
            _log.error("model gateway: the daily spend ceiling is reached; refusing new model requests")
            raise _Refusal(529, "overloaded_error", "VIGIL is at capacity; the run will be retried")
        if reason == "meter":
            raise _Refusal(529, "overloaded_error", "VIGIL cannot meter this run right now")
        if reason == "held":
            raise _Refusal(429, "rate_limit_error", "this run's remaining budget is held by its requests in flight; "
                           "retry shortly", retry_after=5)
        if reason == "closed":
            raise _Refusal(403, "permission_error", "this run's model grant is closed (the run was settled)")
        if reason:
            raise _Refusal(403, "permission_error", "this run's budget is reached")
        self._ticket = _Ticket(gw.meter, grant, rid, reserved, gw.config.clock)
        self._prefix = (key, now, max(marks) if marks else -1)
        shaped["max_tokens"] = min(shaped["max_tokens"], (reserved - cost) // row.output)

    def _remember(self, grant: ModelGrant, usage: mm.Usage) -> None:
        if self._prefix is not None:
            self.gw.remember_prefix(grant.meter_id, self._prefix[0], self._prefix[1], usage, self._prefix[2])

    def _count_input(self, shaped: dict, headers: Mapping[str, str]) -> Optional[int]:
        """The provider's own count of a shaped request's input tokens, or None when it cannot be had."""
        try:
            req = self.gw._upstream_request(COUNT_TOKENS_PATH, self.gw.count_body(shaped), headers)
            with self.gw._opener.open(req, timeout=min(30.0, self.gw.config.upstream_timeout_s)) as resp:
                n = json.loads(resp.read()).get("input_tokens")
        except _Refusal:
            raise
        except Exception:  # noqa: BLE001 — no count: the caller keeps the loose bound
            return None
        return n if isinstance(n, int) and not isinstance(n, bool) and n >= 0 else None

    def _read_body(self, org_id: str) -> bytes:
        try:
            n = int(self.headers.get("content-length") or "-1")
        except ValueError:
            n = -1
        if n < 0:
            raise _Refusal(411, "invalid_request_error", "a content-length is required")
        if n > self.gw.config.max_body_bytes:
            raise _Refusal(413, "request_too_large", "the request body is too large")
        self._body_back = self.gw.acquire_body_bytes(org_id, n)
        raw = self.rfile.read(n)
        if len(raw) != n:
            raise ConnectionResetError("the client closed before its body was complete")
        return raw

    def _open(self, req: urllib.request.Request):
        """``(response, None)``, ``(None, the provider's HTTP error)``, or a refusal. ``sent`` on the refusal says the
        request may have reached the provider (so its outcome is unknown) rather than never having left."""
        try:
            return self.gw._opener.open(req, timeout=self.gw.config.upstream_timeout_s), None
        except urllib.error.HTTPError as e:                           # an Anthropic error: pass it through
            return None, e
        except urllib.error.URLError as exc:                          # connecting / sending failed: nothing ran
            _log.warning("model gateway: upstream unreachable (%s)", type(exc.reason).__name__)
            raise _Refusal(502, "api_error", "the model provider could not be reached") from None
        except (OSError, http.client.HTTPException) as exc:           # sent, but no answer: the outcome is unknown
            _log.warning("model gateway: no answer from the upstream (%s)", type(exc).__name__)
            r = _Refusal(504, "api_error", "the model provider did not answer")
            r.sent = True                                             # type: ignore[attr-defined]
            raise r from None

    def _relay_error(self, e: urllib.error.HTTPError) -> None:
        body = e.read() or _error_body("api_error", "upstream error")
        hdrs = {k: e.headers[k] for k in _PASS_RESPONSE_HEADERS if e.headers and e.headers.get(k)}
        status = e.code if e.code >= 400 else 502                     # a redirect is never followed, nor relayed
        self._send(status, body if e.code >= 400 else _error_body("api_error", "upstream error"), hdrs)

    def _forward_plain(self, path_qs: str, body: dict, headers: Mapping[str, str], *,
                       grant: Optional[ModelGrant]) -> None:
        ticket = self._ticket if grant is not None else None
        try:
            resp, err = self._open(self.gw._upstream_request(path_qs, body, headers))
        except _Refusal as r:
            if ticket is not None and getattr(r, "sent", False):
                ticket.hold()                          # it may have run: unconfirmed spend, never free
            raise
        if err is not None:
            # a provider error is not billed: the ticket is released in do_POST (also if relaying it fails)
            self._relay_error(err)
            return
        try:
            with resp:
                raw = resp.read()
                hdrs = {k: resp.headers[k] for k in _PASS_RESPONSE_HEADERS if resp.headers.get(k)}
        except (OSError, http.client.HTTPException):
            if ticket is not None:
                ticket.hold()                          # the answer broke off: the provider may have billed it
            raise _Refusal(502, "api_error", "the model provider's answer was cut off") from None
        if ticket is not None and grant is not None:
            self._meter_body(grant, raw, hdrs.get("request-id", ""))
        self._send(resp.status, raw, hdrs)

    def _meter_body(self, grant: ModelGrant, raw: bytes, request_id: str) -> None:
        assert self._ticket is not None
        try:
            doc = json.loads(raw)
            usage = mm.usage_from_api(doc.get("usage") if isinstance(doc, dict) else None)
            cost = mm.cost_nano_usd(usage, grant.model, self.gw.prices)
        except Exception:  # noqa: BLE001 — malformed, nested too deep, unpriced: never free
            # a 200 the meter cannot read: charge the reservation (the most this request was allowed to cost), so
            # an unreadable response never runs free; logged for the owner.
            _log.error("model gateway: unreadable usage on a response for grant %s; charging the reservation",
                       grant.grant_id[:8])
            usage, cost = mm.Usage(), self._ticket.reserved
        self._ticket.commit(usage, cost, request_id=request_id)
        self._remember(grant, usage)

    def _forward_stream(self, path_qs: str, body: dict, headers: Mapping[str, str], grant: ModelGrant) -> None:
        assert self._ticket is not None
        ticket = self._ticket
        try:
            resp, err = self._open(self.gw._upstream_request(path_qs, body, headers))
        except _Refusal as r:
            if getattr(r, "sent", False):
                ticket.hold()
            raise
        if err is not None:
            self._relay_error(err)
            return
        self._streaming = True
        meter = mm.StreamMeter()
        unreadable = False
        terminal = False
        refused = False                           # the provider said, in an ``error`` event, that nothing ran
        client_gone = False
        request_id = resp.headers.get("request-id") or ""
        try:
            self.send_response(resp.status)
            self.send_header("content-type", resp.headers.get("content-type") or "text/event-stream")
            self.send_header("cache-control", "no-cache")
            self.send_header("connection", "close")
            if request_id:
                self.send_header("request-id", request_id)
            self.end_headers()
        except OSError:
            client_gone = True
        try:
            # a reset or a malformed chunk ends this loop with an exception (or reads as a clean end): either way
            # the ``finally`` settles the request from what the stream said — never free
            with resp:
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    if line.startswith(b"data:"):
                        try:
                            event = json.loads(line[5:].strip() or b"null")
                            meter.feed(event)
                            kind = event.get("type")
                            if kind == "message_stop":
                                terminal = True
                            elif kind == "error" and not meter.started:
                                refused = True
                        except Exception:  # noqa: BLE001 — malformed, nested too deep, unpriced
                            unreadable = True
                    if not client_gone:
                        try:
                            self.wfile.write(line)
                            if line in (b"\n", b"\r\n"):
                                self.wfile.flush()
                        except OSError:           # gone, or not reading (the socket deadline): never write again,
                            client_gone = True    # but keep reading — Anthropic bills the rest of the stream
        finally:
            self.close_connection = True
            usage = meter.usage
            try:
                cost = mm.cost_nano_usd(usage, grant.model, self.gw.prices)
            except mm.MeteringError:
                unreadable, cost = True, 0
            if not meter.started and not unreadable and refused:
                ticket.release()                  # the provider refused before any message: nothing ran
            elif not meter.started and not unreadable:
                # it ended before saying what ran — a reset or a malformed chunk reads exactly like a clean end, so
                # only the provider's own error event proves nothing was generated: unconfirmed, never free
                ticket.hold()
            elif unreadable:
                _log.error("model gateway: unreadable stream usage for grant %s; charging at least the "
                           "reservation", grant.grant_id[:8])
                ticket.commit(usage, max(cost, ticket.reserved), request_id=request_id)
            elif not terminal:
                # cut off before its final usage: what was generated is billed by the provider but unknown here.
                # The reported part is charged; the rest of the reservation is held as unconfirmed spend.
                ticket.commit(usage, cost, request_id=request_id, held_nano=max(0, ticket.reserved - cost))
            else:
                ticket.commit(usage, cost, request_id=request_id)
                self._remember(grant, usage)


class _Ticket:
    """One request's reservation, settled exactly once: :meth:`commit` (metered), :meth:`hold` (its outcome is
    unknown: the whole reservation becomes unconfirmed spend) or :meth:`release` (no usage). A second settle is a
    no-op, so an error after metering can never release the reservation again and eat into another in-flight
    request's."""

    def __init__(self, meter: GrantMeter, grant: ModelGrant, rid: str, reserved: int, clock: Callable[[], float]):
        self.meter, self.grant, self.rid, self.reserved, self._clock = meter, grant, rid, reserved, clock
        self._done = False
        self._lock = threading.Lock()

    def _first(self) -> bool:
        with self._lock:
            if self._done:
                return False
            self._done = True
            return True

    def commit(self, usage: mm.Usage, cost_nano: int, *, request_id: str, held_nano: int = 0) -> None:
        if self._first():
            self.meter.commit(self.grant, self.rid, usage, cost_nano, request_id=request_id, now=self._clock(),
                              held_nano=held_nano)

    def hold(self) -> None:
        if self._first():
            self.meter.commit(self.grant, self.rid, mm.Usage(), 0, request_id="", now=self._clock(),
                              held_nano=self.reserved)

    def release(self) -> None:
        if self._first():
            self.meter.release(self.grant, self.rid, now=self._clock())


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    gateway: ModelGateway
    _connections: threading.BoundedSemaphore
    _in_flight = 0                       # accepted connections whose handler has not finished
    _in_flight_cond: threading.Condition
    _waiting: "dict[Any, float]"         # accepted connections that have not started a request yet, oldest first
    _stopping = False

    def request_started(self, sock: Any) -> bool:
        """A connection starts its request: False once the server is stopping (the request must be refused)."""
        with self._in_flight_cond:
            self._waiting.pop(sock, None)
            return not self._stopping

    def cut_if_waiting(self, sock: Any) -> None:
        """Cut ``sock`` if it still has not started its request."""
        with self._in_flight_cond:
            waiting = sock in self._waiting
        if waiting:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._connections.acquire(blocking=False):
            # the bound is full: a connection that has not started its request gives up its place (oldest first), so
            # idle connections cannot lock every runner out; failing that, the new one is closed unanswered
            with self._in_flight_cond:
                oldest = next(iter(self._waiting), None)
            if oldest is None:
                self.shutdown_request(request)
                return
            self.cut_if_waiting(oldest)
            if not self._connections.acquire(timeout=1.0):
                self.shutdown_request(request)
                return
        with self._in_flight_cond:
            self._in_flight += 1                       # counted from the accept, not from the request line
            self._waiting[request] = time.monotonic()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_done(request)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_done(request)

    def _connection_done(self, request: Any) -> None:
        with self._in_flight_cond:
            self._in_flight -= 1
            self._waiting.pop(request, None)
            self._in_flight_cond.notify_all()
        self._connections.release()

    def server_close(self) -> None:
        if getattr(self, "_in_flight_cond", None) is None:   # the bind failed inside __init__: nothing was started
            super().server_close()
            return
        self._drain_and_close()

    def _drain_and_close(self) -> None:
        """Stop serving, wait (up to ``shutdown_drain_s``) for the requests in flight to be metered and for every
        record a failed write still owes to be written, and only then give up the meter directory. A connection that
        has not started its request is cut, and one that starts after this point is refused. If a request is still
        running, or a record still owed, at the deadline, the meter lock is KEPT (and the record retried) until the
        process exits, so a settle step can never mistake a live request for a crash's leftover."""
        super().server_close()
        with self._in_flight_cond:
            self._stopping = True
            for sock in list(self._waiting):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        deadline = time.monotonic() + self.gateway.config.shutdown_drain_s
        with self._in_flight_cond:
            while self._in_flight > 0:
                left = deadline - time.monotonic()
                if left <= 0:
                    _log.error("model gateway: %d request(s) still in flight at shutdown; keeping the meter lock "
                               "until the process exits", self._in_flight)
                    return
                self._in_flight_cond.wait(timeout=left)
        meter = self.gateway.meter
        while True:
            meter.flush_unwritten()
            owed = meter.owed()
            if not owed:
                break
            left = deadline - time.monotonic()
            if left <= 0:
                _log.error("model gateway: %d metered record(s) still unwritten at shutdown; keeping the meter lock "
                           "(and retrying them) until the process exits", owed)
                return
            time.sleep(min(0.5, left))
        self.gateway.stop()
        meter.shutdown()


def start(config: GatewayConfig, *, host: str = "127.0.0.1", port: int = 0) -> "tuple[_Server, threading.Thread]":
    """Start the gateway on ``127.0.0.1:port`` in a daemon thread; returns ``(server, thread)``.
    ``server.server_address[1]`` is the bound port (``port=0`` picks a free one). Stop it with ``server.shutdown()``
    then ``server.server_close()`` (which also gives up the meter directory)."""
    if host != "127.0.0.1":
        raise ValueError("the model gateway listens on loopback only")
    gateway = ModelGateway(config)
    try:
        server = _Server((host, port), _Handler)
    except OSError:
        gateway.stop()
        gateway.meter.shutdown()
        raise
    server.gateway = gateway
    server._connections = threading.BoundedSemaphore(config.max_connections)
    server._in_flight_cond = threading.Condition()
    server._waiting = {}
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, name="model-gateway",
                         daemon=True)
    t.start()
    return server, t


# ---------------------------------------------------------------------------------------------------------------
# Starting it in the cockpit (PRICING M1c)
# ---------------------------------------------------------------------------------------------------------------

_RUNNING: "dict[str, _Server]" = {}
_RUNNING_LOCK = threading.Lock()


def _int_env(name: str, default: int) -> int:
    """A whole-number setting, digits only, the same rule ``vigil doctor`` checks (the gateway refuses a limit below 1
    itself)."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    if not raw.isdigit():
        raise ValueError(f"{name} must be a whole number, got {raw!r}")
    return int(raw)


def _daily_limit_nano() -> Optional[int]:
    """``VIGIL_GATEWAY_DAILY_LIMIT_USD`` (a decimal number of dollars) as nano-USD, or None when unset."""
    raw = (os.environ.get("VIGIL_GATEWAY_DAILY_LIMIT_USD") or "").strip()
    if not raw:
        return None
    try:
        usd = Decimal(raw)
    except InvalidOperation:
        raise ValueError(f"VIGIL_GATEWAY_DAILY_LIMIT_USD is not a number: {raw!r}") from None
    if not usd.is_finite() or usd <= 0:
        raise ValueError(f"VIGIL_GATEWAY_DAILY_LIMIT_USD must be a positive amount, got {raw!r}")
    return int(usd * 1_000_000_000)


def config_from_env() -> GatewayConfig:
    """The gateway's configuration from the sovereign environment: the ONE provider key
    (``SIGIL_ANTHROPIC_API_KEY`` / ``ANTHROPIC_API_KEY``), the owner public key, the meter directory, the
    sovereignty tier as the egress check, and the account protections (design §5.2):
    ``VIGIL_GATEWAY_TENANT_CONCURRENCY`` (default 4), ``VIGIL_GATEWAY_GLOBAL_CONCURRENCY`` (default 32) and
    ``VIGIL_GATEWAY_DAILY_LIMIT_USD`` (unset = no ceiling). Raises ``ValueError`` on a missing key, no owner key or
    a bad value."""
    from . import config, sovereignty
    from .governor.identity import owner_pubkey
    key = (os.environ.get("SIGIL_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if not key:
        raise ValueError("the model gateway needs the provider key (SIGIL_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY)")

    owner = owner_pubkey()
    if not owner:
        raise ValueError("the model gateway needs the owner public key to verify grants (no owner keypair)")

    def egress_check(url: str) -> None:
        sovereignty.assert_endpoint_permitted(url, purpose="customer-run model call")

    return GatewayConfig(api_key=key, owner_pubkey=owner, meter_dir=config.MODEL_METER_DIR,
                         egress_check=egress_check, prices=mm.price_table(),
                         tenant_concurrency=_int_env("VIGIL_GATEWAY_TENANT_CONCURRENCY", 4),
                         global_concurrency=_int_env("VIGIL_GATEWAY_GLOBAL_CONCURRENCY", 32),
                         daily_limit_nano=_daily_limit_nano())


def start_from_env() -> "Optional[_Server]":
    """Start the gateway once per process iff ``VIGIL_MODEL_GATEWAY_ENABLED``, on ``VIGIL_MODEL_GATEWAY_PORT``
    (loopback). Returns the running server, or None when disabled or misconfigured — a misconfiguration is
    logged and the cockpit carries on; customer runs then fail closed (they cannot reach a gateway), and
    ``vigil doctor`` reports why. Never raises."""
    from . import config
    if not config.model_gateway_enabled():
        return None
    port = config.model_gateway_port()
    with _RUNNING_LOCK:
        running = _RUNNING.get(str(port))
        if running is not None:
            return running
        try:
            server, _t = start(config_from_env(), port=port)
        except (ValueError, OSError, mm.MeteringError) as exc:          # a misconfiguration: one line, no traceback
            _log.error("model gateway not started: %s", exc)
            return None
        except Exception:  # noqa: BLE001 — the cockpit must come up whatever the gateway's state; runs fail closed
            _log.exception("model gateway not started")
            return None
        _RUNNING[str(port)] = server
        return server
