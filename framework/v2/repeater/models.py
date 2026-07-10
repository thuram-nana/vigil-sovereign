"""
repeater.models — the captured request, its editor, and the replay exchange (W4.D).

A REPEATER is the Burp-Repeater equivalent for AUTHORIZED testing: capture a base HTTP
request to an in-scope host, edit it, and REPLAY it through the existing gate chain. These
are the pure, deterministic data shapes it threads:

  * ``RepeaterRequest`` — an immutable captured/base request (method / url / headers / body).
    Capturing a request performs NO I/O; it is just the description of a request that COULD be
    replayed. Nothing here reaches the network — the gates and the executor do that (``tool.py``).
  * ``mutate`` — the Burp-style editor: a PURE function returning a NEW ``RepeaterRequest`` with
    field/header overrides. It never mutates in place (the base capture stays intact for the
    audit trail) and never introduces wallclock/rng.
  * ``RepeaterExchange`` — one (request, response) pair from a replay, plus whether a gate
    refused it. The response is a PROVENANCE-LABELLED OBSERVATION, never a fact: it becomes a
    finding only when a deterministic oracle re-verifies it (``oracle_context_with``).

Doctrine baked into the shapes: nothing here rotates identity or evades — the correlatable
User-Agent is forced later, in ``tool.py``, by the gated executor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

# A sentinel so ``mutate(body=None)`` (clear the body) is distinguishable from ``mutate()``
# (leave the body unchanged). ``None`` is a legitimate body value, so it cannot double as "unset".
_UNSET: Any = object()

HeaderPairs = tuple[tuple[str, str], ...]


def normalize_headers(headers: Mapping[str, str] | Iterable[Any] | None) -> HeaderPairs:
    """Normalise headers — a mapping OR an iterable of (name, value) pairs — into an ordered tuple
    of ``(str, str)`` pairs. PURE and total: a ``None`` yields ``()``; a malformed element (not a
    2-item pair) is skipped rather than raising, so a hand-built capture never crashes the editor.
    Order is preserved (repeaters care about header order)."""
    if headers is None:
        return ()
    if isinstance(headers, Mapping):
        return tuple((str(k), str(v)) for k, v in headers.items())
    out: list[tuple[str, str]] = []
    for item in headers:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            out.append((str(item[0]), str(item[1])))
    return tuple(out)


@dataclass(frozen=True)
class RepeaterRequest:
    """An immutable captured/base HTTP request the operator (or engine) can edit and replay.

    ``url`` is the AUTHORITATIVE target — it is what the scope gate validates and what the
    executor issues (they must be the same URL; ``tool.py`` enforces that). Capturing performs
    no I/O. ``headers`` is an ordered tuple of ``(name, value)`` pairs; ``body`` is the request
    body (``None`` for none)."""

    method: str = "GET"
    url: str = ""
    headers: HeaderPairs = ()
    body: str | None = None

    @classmethod
    def capture(
        cls,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | Iterable[Any] | None = None,
        body: str | None = None,
    ) -> "RepeaterRequest":
        """Capture a base request (no network I/O). Normalises the method to upper-case and the
        headers into an ordered pair-tuple."""
        return cls(
            method=str(method or "GET").upper().strip() or "GET",
            url=str(url or "").strip(),
            headers=normalize_headers(headers),
            body=body,
        )

    def header_list(self) -> list[list[str]]:
        """Headers as a JSON-friendly list of ``[name, value]`` (for tool args / the transcript)."""
        return [[k, v] for k, v in self.headers]

    def summary(self) -> str:
        """A short one-line view (never the body/header VALUES — those can carry secrets)."""
        names = ",".join(k for k, _ in self.headers)
        return f"{self.method} {self.url} [{len(self.headers)} hdr: {names}]"


def mutate(
    request: RepeaterRequest,
    *,
    method: str | None = None,
    url: str | None = None,
    body: Any = _UNSET,
    headers: Mapping[str, str] | Iterable[Any] | None | object = _UNSET,
    set_headers: Mapping[str, str] | None = None,
    drop_headers: Iterable[str] | None = None,
) -> RepeaterRequest:
    """Return a NEW ``RepeaterRequest`` with the given edits — the Burp-repeater "edit and resend"
    step, as a PURE function (the base capture is never modified, preserving the audit trail).

    Edits, applied in order:
      * ``method`` / ``url`` — replace when given.
      * ``body`` — replace when given (``body=None`` clears it; omitting ``body`` leaves it).
      * ``headers`` — replace the WHOLE header set when given.
      * ``set_headers`` — merge/override individual headers by name (case-insensitive; last wins).
      * ``drop_headers`` — remove headers by name (case-insensitive).

    Deterministic: no wallclock, no rng, no in-place mutation."""
    new_method = str(method).upper().strip() if method is not None else request.method
    new_url = str(url).strip() if url is not None else request.url
    new_body = request.body if body is _UNSET else body

    if headers is not _UNSET:
        pairs = list(normalize_headers(headers))  # type: ignore[arg-type]
    else:
        pairs = list(request.headers)

    if set_headers:
        overrides = normalize_headers(set_headers)
        override_names = {k.lower() for k, _ in overrides}
        pairs = [(k, v) for (k, v) in pairs if k.lower() not in override_names]
        pairs.extend(overrides)

    if drop_headers:
        drop = {str(name).lower() for name in drop_headers}
        pairs = [(k, v) for (k, v) in pairs if k.lower() not in drop]

    return RepeaterRequest(
        method=new_method or "GET",
        url=new_url,
        headers=tuple(pairs),
        body=new_body,
    )


@dataclass
class RepeaterExchange:
    """One replay: the request that was sent (or refused), and what came back.

    ``refused`` (with ``gate``) marks a fail-closed gate declining the replay BEFORE any request
    left the host — ``response`` is then ``None``. ``response`` (when present) is the executor's
    ``{status, body, headers, latency_ms}`` capture: a PROVENANCE-LABELLED OBSERVATION, never a
    fact. It becomes evidence for a finding only via a deterministic oracle (``oracle_context_with``)."""

    request: RepeaterRequest
    response: dict | None = None
    refused: bool = False
    gate: str = ""
    ok: bool = False
    note: str = ""
    evidence: dict = field(default_factory=dict)

    @property
    def status(self) -> int:
        return int(self.response.get("status", 0)) if isinstance(self.response, dict) else 0

    @property
    def sent(self) -> bool:
        """True iff a real request reached the target (a response came back and no gate refused)."""
        return self.response is not None and not self.refused

    def oracle_context_with(
        self,
        other: "RepeaterExchange",
        *,
        bug_class: str = "boolean_sqli",
        discriminator: Mapping[str, Any] | None = None,
    ) -> dict:
        """Build a serialized ``verify.adapter.FindingContext`` from THIS exchange (baseline) and
        ``other`` (mutated/probe) so the DETERMINISTIC differential oracle — not the LLM, not the
        repeater — can adjudicate whether the two responses diverge. Prove-don't-guess made
        concrete: the repeater produces the evidence; the oracle decides if it is a finding.

        Raises ``ValueError`` if either exchange has no captured response (a refused replay
        carries no evidence to adjudicate)."""
        if not (self.sent and other.sent):
            raise ValueError(
                "oracle_context_with needs a captured response on BOTH exchanges "
                "(a refused/never-sent replay has no evidence to adjudicate)"
            )
        from ..verify.adapter import FindingContext

        ctx = FindingContext.from_http_responses(
            self.response, other.response, bug_class=bug_class,
            discriminator=dict(discriminator) if discriminator is not None else {
                "dimensions": ["status", "length", "lexical"]
            },
        )
        return ctx.model_dump()
