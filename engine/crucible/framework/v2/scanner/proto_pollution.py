"""
scanner.proto_pollution — CLIENT-SIDE PROTOTYPE POLLUTION confirmed by the ACHIEVED
polluted state in a real browser.

Client-side prototype pollution (CWE-1321) is a code-integrity bug: a client-side
parser (a query-string / fragment / JSON deserialiser that walks nested keys) follows
a ``__proto__`` / ``constructor.prototype`` segment and writes an attacker-controlled
value onto ``Object.prototype`` itself. Every object then inherits that value — a
primitive that escalates to DOM-XSS, logic bypass, or DoS depending on the app's
gadgets.

Static analysis and reflection oracles find *leads*: a source flows toward a merge, or
the payload appears in the DOM. Neither proves the prototype was actually polluted — a
page can echo ``__proto__[x]=y`` as inert text while its parser guards the dangerous
keys. This module proves it end to end, judging the ACHIEVED runtime state, never the
payload's mere appearance:

  1. mint a UNIQUE per-probe ``(key, value)`` (fresh random tokens) plus a distinct
     BENIGN key that is NEVER injected — so a hit is attributable to THIS probe and
     cannot be an incidental pre-existing property;
  2. drive a ``__proto__[key]=value`` gadget into the page across each client SOURCE
     (URL query, URL fragment, and a JSON source), in the syntaxes real vulnerable
     parsers consume (bracket / dot / ``constructor[prototype]`` / JSON ``__proto__``);
  3. render the page in a real headless DOM (``scanner.cdp``) and READ BACK the
     achieved state THROUGH a planted CDP binding (``__crucible_pp``, registered via
     ``Runtime.addBinding`` — the same unforgeable channel ``browser_xss`` uses): a
     readback snippet reports ``Object.prototype[key]`` and whether the BENIGN key is
     still ``undefined``;
  4. fire the ``prototype_pollution`` oracle (``verify.oracles.prototype_pollution_oracle``,
     ``OracleKind.PROTOTYPE_POLLUTION``, conf 0.96) **only** when
     ``Object.prototype[key] === value`` (the ACHIEVED polluted state) AND the benign
     key stayed ``undefined`` — never on the payload merely appearing in the DOM/JSON.

A page that reflects the key without assigning it onto ``Object.prototype`` (the benign
twin), a mismatched value, or an ambient pollution that also touched the benign key all
report a non-firing readback and correctly do not fire.

The confirmation is a ``verify.FindingContext`` (``from_prototype_pollution``, bug_class
``prototype_pollution``), so a browser-confirmed prototype pollution carries the same
re-verifiable certificate every other CRUCIBLE finding does — the retained
``oracle_context`` re-fires the pure oracle offline and a tampered value no longer
confirms.

Soundness is total (a fire means ``Object.prototype`` actually carried the value VIGIL
drove in, attributable via the benign-key control); **coverage** is the limit — a
client source / gadget syntax VIGIL never drives, or a page VIGIL never crawls, stays a
LEAD, never a false negative. Requires a browser (``scanner.cdp.cdp_available``); with
none the caller skips the dynamic path (a browser check never guesses), so a browserless
run yields a LEAD, never a CLEAN.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from ..verify.adapter import FindingContext
from .cdp import CdpBrowser, CdpError

# The binding the readback snippet calls to report the achieved prototype state. Only the
# driver registers it (Runtime.addBinding), so a report carrying the probe's key is the
# driver's own out-of-page readback channel — not something the target page can forge.
_BINDING = "__crucible_pp"


# Gadget builders. Each takes the unique (key, value) and returns the raw SOURCE string a
# vulnerable client-side parser would consume, in a syntax real-world pollutable parsers
# accept. ``kind`` names the source the caller inserts it into.
def _gadgets(key: str, val: str) -> tuple[tuple[str, str], ...]:
    """The ``(syntax, source_string)`` gadgets driven per source. Covers the bracket, dot,
    ``constructor[prototype]`` and JSON ``__proto__`` forms — the syntaxes a nested-key
    query/fragment parser or a recursive JSON merge follows into ``Object.prototype``."""
    return (
        ("bracket", f"__proto__[{key}]={val}"),
        ("dot", f"__proto__.{key}={val}"),
        ("constructor", f"constructor[prototype][{key}]={val}"),
        ("json", json.dumps({"__proto__": {key: val}}, separators=(",", ":"))),
    )


# The client SOURCES a gadget is inserted into. ``query`` = a URL query parameter the app
# parses; ``fragment`` = ``location.hash`` (never sent to the server); ``json_query`` = a
# JSON value carried in a query parameter the app JSON-parses then merges.
_SOURCES: tuple[str, ...] = ("query", "fragment", "json_query")

# The readback executed in the page's realm AFTER it renders. It reports the ACHIEVED state
# through the planted binding: Object.prototype[key] (the polluted value, or null) and
# whether the BENIGN key — never injected — is still undefined. A fresh empty object's
# inherited lookup is used so the check is over the prototype chain, not an own-property.
_READBACK = """
(function(){{
  try {{
    var k = {key}, bk = {benign};
    var probe = {{}};
    var pv = probe[k];
    var bench = probe[bk];
    window.{binding}(JSON.stringify({{
      polluted_key: k,
      polluted_val: (pv === undefined ? null : String(pv)),
      benign_key: bk,
      benign_key_undefined: (bench === undefined)
    }}));
  }} catch (e) {{
    window.{binding}(JSON.stringify({{polluted_key: {key}, error: String(e)}}));
  }}
}})();
"""


@dataclass
class ProtoPollutionResult:
    """One prototype-pollution attempt: the source + gadget syntax, the injected URL/JSON,
    the unique key/value, the benign control key, whether the binding readback proved
    ``Object.prototype[key]`` was polluted to the value (with the benign key undefined), and
    the re-verifiable oracle context."""

    source: str
    syntax: str
    injection: str
    key: str
    value: str
    benign_key: str
    polluted: bool
    context: FindingContext
    bug_class: str = "prototype_pollution"


def _probe_ids() -> tuple[str, str, str]:
    """A UNIQUE ``(key, value, benign_key)`` per probe. Fresh random tokens so the key/value
    cannot pre-exist on the target and a match is attributable to THIS probe; the benign key
    is distinct and NEVER injected (the attribution control)."""
    tag = secrets.token_hex(6)
    return f"cpp_{tag}", f"ppv_{tag}", f"benign_{secrets.token_hex(6)}"


def _inject(url: str, source: str, gadget: str) -> str:
    """Render ``gadget`` into ``url`` for the given client ``source``.

    ``query`` inserts ``pp=<gadget>`` as a raw query (the page's own parser decodes+walks
    it); ``fragment`` sets the URL fragment (``location.hash``); ``json_query`` carries the
    gadget as the value of a ``json`` query parameter the page JSON-parses."""
    parts = urlsplit(url)
    if source == "fragment":
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, gadget))
    if source == "json_query":
        from urllib.parse import quote
        q = f"json={quote(gadget, safe='')}"
        query = f"{parts.query}&{q}" if parts.query else q
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
    # query: the gadget IS the raw query (bracket/dot forms are what a nested-key parser reads).
    query = f"{parts.query}&{gadget}" if parts.query else gadget
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _readback(sess, key: str, benign_key: str, *, settle: float) -> dict:
    """Execute the readback in the page realm and return the binding-reported achieved state.

    The snippet calls the planted ``__crucible_pp`` binding with a JSON blob; we then read
    that blob back off the ``Runtime.bindingCalled`` channel. Returns ``{}`` if no readback
    arrived (treated as no-pollution — never a CLEAN)."""
    try:
        sess.evaluate(_READBACK.format(
            binding=_BINDING, key=json.dumps(key), benign=json.dumps(benign_key)))
    except CdpError:
        return {}
    # The binding call is dispatched during evaluate; drain briefly in case it is still in flight.
    drain = getattr(sess, "drain_events", None)
    if callable(drain):
        try:
            drain(timeout=max(0.2, settle))
        except CdpError:
            pass
    calls = [c for c in sess.binding_calls(_BINDING) if key in c]
    if not calls:
        return {}
    try:
        return json.loads(calls[-1])
    except (ValueError, TypeError):
        return {}


def confirm_proto_pollution(
    url: str,
    *,
    browser: CdpBrowser | None = None,
    sources: tuple[str, ...] = _SOURCES,
    settle: float = 0.8,
) -> list[ProtoPollutionResult]:
    """Drive ``__proto__[uniqKey]=uniqVal`` gadgets into ``url`` across client sources in a
    real headless DOM and return one :class:`ProtoPollutionResult` per attempt.

    ``result.polluted`` (and the ``prototype_pollution`` oracle over ``result.context``) is
    True only when the binding readback proves ``Object.prototype[key] === value`` (the
    ACHIEVED polluted state) AND the benign-key control stayed ``undefined`` — never on the
    payload merely appearing in the DOM/JSON. A shared ``browser`` may be passed to amortise
    launch cost; otherwise one is started and torn down here.

    Raises :class:`CdpError` only if no browser is available (the caller then skips — a
    browserless run yields a LEAD, never a CLEAN)."""
    own = browser is None
    br = browser or CdpBrowser().start()
    results: list[ProtoPollutionResult] = []
    try:
        sess = br.session()
        sess.add_binding(_BINDING)
        for source in sources:
            for syntax, template in _gadgets("KEY", "VAL"):  # noqa: B007 — template shape only
                # JSON gadget goes only into json/fragment sources; bracket/dot/constructor go into
                # query/fragment (a JSON string in a bracket-query is not a nested-key gadget).
                is_json = syntax == "json"
                if source == "json_query" and not is_json:
                    continue
                if source in ("query",) and is_json:
                    continue
                key, val, benign = _probe_ids()
                gadget = dict(_gadgets(key, val))[syntax]
                target = _inject(url, source, gadget)
                try:
                    sess.navigate(target, settle=settle)
                except CdpError:
                    results.append(_result(source, syntax, target, key, val, benign, {}))
                    continue
                observed = _readback(sess, key, benign, settle=settle)
                results.append(_result(source, syntax, target, key, val, benign, observed))
    finally:
        if own:
            br.stop()
    return results


def _result(source: str, syntax: str, injection: str, key: str, val: str,
            benign: str, observed: dict) -> ProtoPollutionResult:
    ctx = FindingContext.from_prototype_pollution(
        polluted_key=key,
        expected_val=val,
        benign_key=benign,
        polluted_val=observed.get("polluted_val"),
        benign_key_undefined=observed.get("benign_key_undefined"),
    )
    polluted = (observed.get("polluted_val") == val
                and observed.get("benign_key_undefined") is True)
    return ProtoPollutionResult(
        source=source, syntax=syntax, injection=injection, key=key, value=val,
        benign_key=benign, polluted=bool(polluted), context=ctx,
    )


def proto_pollution_finding(result: ProtoPollutionResult, *, check_id: str = "") -> dict:
    """Build the finding dict (carrying the retained ``oracle_context``) for a prototype-
    pollution result, ready for the STD-WIRING admission choke
    (``verdict.admit("prototype_pollution.achieved_state", ...)`` →
    ``oracle_adapter.certify_admitted(provenance="live_redrive")``).

    The ``oracle_context`` is the pure, re-verifiable bundle the ``prototype_pollution``
    oracle re-fires over offline; ``framework.v2 verify`` re-runs it and
    ``reverify.matches_claim`` rejects any tamper (a mutated value no longer equals the
    expected polluted value)."""
    return {
        "check_id": check_id or f"prototype_pollution:{result.source}:{result.syntax}",
        "bug_class": "prototype_pollution",
        "title": "Client-side prototype pollution (browser-confirmed achieved Object.prototype pollution)",
        "severity": "High",
        "surface": f"source:{result.source} syntax:{result.syntax}",
        "summary": (
            "a __proto__ gadget driven across a client source polluted Object.prototype in a real "
            "browser DOM to a unique per-probe value (a benign-key control stayed undefined)"
        ),
        "oracle_context": result.context.to_verifier_context(),
    }
