"""
intel.transport — the seam between a collector and the outside world.

A collector never talks to the network directly. It asks a `Transport` for a
`RawRecord` and parses it into `Observation`s. That one indirection buys three
things at once:

  * **Offline-first + deterministic tests.** `FixtureTransport` serves captured
    JSON from disk; the entire collector suite runs with no network and no
    non-determinism (the world-model time doctrine — seq, never wallclock).
  * **Egress that is OFF by default.** `DisabledTransport` is the default. Live
    collection is a deliberate, gated opt-in — you must construct a
    `GuardedHttpTransport` with an explicit `collector_hosts` allowlist that is
    DISJOINT from the engagement's target scope (recon sources are third parties:
    a CT log, a DNS resolver, an RDAP server — never the target).
  * **Capture for replay.** `GuardedHttpTransport` can mirror every live fetch to
    a fixture directory, so a live run seeds the offline corpus.

The transport carries no intel semantics — it moves bytes under a policy. All
meaning (what a CT entry means, how a CNAME becomes a SAME_AS observation) lives
in the collectors.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from ..common.errors import CrucibleError, SovereigntyViolation
from .models import IntelSourceKind


class CollectorEgressRefused(SovereigntyViolation):
    """A collector tried to reach a host outside its `collector_hosts` allowlist,
    or tried to collect live while egress was disabled. Recon sources are third
    parties; this keeps a collector from ever touching the target itself, and
    keeps offline runs truly offline."""


class RawRecord(BaseModel):
    """One raw source response, before any intel interpretation. The collector's
    input; carries provenance (which source, what was asked, where it came from)
    so every downstream Observation traces back to a concrete artifact."""

    model_config = ConfigDict(extra="forbid")

    source_kind: IntelSourceKind
    query: str                                   # what was asked (a domain / ip / asn)
    payload: dict | list = Field(default_factory=dict)  # the raw structured response
    endpoint: str = ""                           # the host/URL it came from
    fetched_seq: int = 0                          # monotonic (never wallclock)
    ok: bool = True
    note: str = ""

    @property
    def ref(self) -> str:
        """A stable provenance ref for Observations minted from this record."""
        return f"{self.source_kind.value}:{self.query}"


@runtime_checkable
class Transport(Protocol):
    """Fetches a raw record for a (source, query). Collectors depend on this
    interface only — never on httpx, never on the filesystem directly."""

    def fetch(self, source_kind: IntelSourceKind, query: str, *, seq: int) -> RawRecord: ...


def _fixture_name(source_kind: IntelSourceKind, query: str) -> str:
    """Deterministic, filesystem-safe fixture filename for a (source, query)."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in query.lower())
    return f"{source_kind.value}__{safe}.json"


class DisabledTransport:
    """The default. Every fetch raises — recon egress is opt-in. A collector run
    with this transport can only ever be a programming error surfaced loudly, not
    a silent network call."""

    def fetch(self, source_kind: IntelSourceKind, query: str, *, seq: int) -> RawRecord:
        raise CollectorEgressRefused(
            f"live collection is disabled: refusing to fetch {source_kind.value} "
            f"for {query!r}. Construct a FixtureTransport for offline data or a "
            f"GuardedHttpTransport with an explicit collector_hosts allowlist to "
            f"enable gated live recon."
        )


class FixtureTransport:
    """Serves captured source responses from a directory — the offline path. A
    fixture is a JSON file named ``<source_kind>__<query>.json`` holding a
    `RawRecord` (or just its ``payload``). Missing fixtures return an ``ok=False``
    record rather than raising, so a collector degrades to 'found nothing' offline
    exactly as it would against a source with no data."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def fetch(self, source_kind: IntelSourceKind, query: str, *, seq: int) -> RawRecord:
        fp = self.root / _fixture_name(source_kind, query)
        if not fp.is_file():
            return RawRecord(source_kind=source_kind, query=query, ok=False,
                             fetched_seq=seq, note="fixture missing; offline mode")
        raw = json.loads(fp.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and "source_kind" in raw and ("payload" in raw or "ok" in raw):
            rec = RawRecord.model_validate(raw)
            return rec.model_copy(update={"fetched_seq": seq})
        # bare payload form
        return RawRecord(source_kind=source_kind, query=query, payload=raw,
                         fetched_seq=seq, endpoint=str(fp.name))


class MappingTransport:
    """In-memory transport for tests/embedding: a dict of pre-built RawRecords keyed
    by ``(source_kind, query)``. No disk, no network — the tightest possible fixture."""

    def __init__(self, records: dict[tuple[IntelSourceKind, str], RawRecord] | None = None) -> None:
        self._records = dict(records or {})

    def add(self, record: RawRecord) -> None:
        self._records[(record.source_kind, record.query)] = record

    def fetch(self, source_kind: IntelSourceKind, query: str, *, seq: int) -> RawRecord:
        rec = self._records.get((source_kind, query))
        if rec is None:
            return RawRecord(source_kind=source_kind, query=query, ok=False,
                             fetched_seq=seq, note="no record")
        return rec.model_copy(update={"fetched_seq": seq})


class GuardedHttpTransport:
    """Gated live recon. Wraps an egress-guarded ``httpx.Client`` whose allowlist is
    the engagement's ``collector_hosts`` (third-party recon sources) — DISJOINT from
    target scope. A fetch to any host not on that list raises
    `CollectorEgressRefused` before bytes leave the process. Live responses can be
    mirrored to ``capture_dir`` to seed the offline corpus.

    The endpoint-building (a domain → a CT-log URL) is the collector's job; this
    transport is handed a fully-formed URL via the ``endpoints`` map and only
    enforces policy + moves bytes. It imports httpx lazily so the offline paths
    carry no dependency on it."""

    def __init__(
        self,
        *,
        collector_hosts: tuple[str, ...],
        endpoints: dict[IntelSourceKind, str],
        client: object | None = None,
        capture_dir: Path | None = None,
        timeout: float = 8.0,
    ) -> None:
        if not collector_hosts:
            raise CrucibleError(
                "GuardedHttpTransport requires a non-empty collector_hosts allowlist; "
                "an empty allowlist would refuse every fetch — use FixtureTransport for "
                "offline data instead."
            )
        self._hosts = tuple(collector_hosts)
        self._endpoints = dict(endpoints)
        self._capture_dir = Path(capture_dir) if capture_dir else None
        self._timeout = timeout
        self._client = client  # injected guarded httpx.Client, or None to build lazily

    def _ensure_client(self) -> object:
        if self._client is not None:
            return self._client
        import httpx  # lazy: offline paths never import httpx

        from ..agents.egress_guard import EgressAllowlist, SovereignHttpxTransport

        allow = EgressAllowlist(target_hosts=(), collector_hosts=self._hosts)
        self._client = httpx.Client(
            transport=SovereignHttpxTransport(allowlist=allow),
            timeout=self._timeout,
        )
        return self._client

    def fetch(self, source_kind: IntelSourceKind, query: str, *, seq: int) -> RawRecord:
        template = self._endpoints.get(source_kind)
        if not template:
            raise CollectorEgressRefused(
                f"no endpoint configured for {source_kind.value}; refusing to guess a "
                f"recon URL. Add it to the transport's endpoints map explicitly."
            )
        url = template.format(query=query)
        host = _url_host(url)
        from ..common import ethics
        if not ethics.host_matches_scope(host, list(self._hosts)):
            raise CollectorEgressRefused(
                f"recon endpoint host {host!r} (for {source_kind.value}) is not in the "
                f"collector_hosts allowlist {self._hosts}. Recon sources must be "
                f"explicitly allowlisted and disjoint from target scope."
            )
        client = self._ensure_client()
        try:
            resp = client.get(url)  # type: ignore[attr-defined]
            payload = _decode(resp)
            rec = RawRecord(source_kind=source_kind, query=query, payload=payload,
                            endpoint=url, fetched_seq=seq, ok=200 <= resp.status_code < 300)
        except Exception as e:  # network / parse failure — recorded, never raised past here
            rec = RawRecord(source_kind=source_kind, query=query, endpoint=url,
                            fetched_seq=seq, ok=False, note=f"{type(e).__name__}: {e}")
        if self._capture_dir is not None and rec.ok:
            self._capture_dir.mkdir(parents=True, exist_ok=True)
            (self._capture_dir / _fixture_name(source_kind, query)).write_text(
                rec.model_dump_json(indent=2), encoding="utf-8")
        return rec


def _url_host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or ""


def _decode(resp: object) -> dict | list:
    try:
        return resp.json()  # type: ignore[attr-defined]
    except Exception:
        return {"text": getattr(resp, "text", "")}
