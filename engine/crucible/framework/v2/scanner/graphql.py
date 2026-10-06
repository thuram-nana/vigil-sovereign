"""
scanner.graphql — GraphQL security checks.

A GraphQL endpoint is its own surface: introspection that hands an attacker the
whole schema, and field "did you mean?" suggestions that leak it even when
introspection is off. Neither is reachable by parameter fuzzing — they need a
GraphQL query POSTed and the JSON response inspected. These request-level checks
do that, confirmed via achieved-state on the actual leak (a returned schema / a
suggestion), not on the mere presence of a ``/graphql`` path.

Beyond disclosure, a GraphQL endpoint is a classic **denial-of-service / abuse**
surface: an unbounded query DEPTH (deeply-nested selections), ALIAS overloading
(the same field resolved N times in one response), request BATCHING (an array of
operations in one HTTP request), and the absence of a query COST/complexity limit
all let one small request do disproportionate work. The DoS checks below probe
these *minimally* — one bounded query each, using schema-independent meta-fields
(``__typename`` / ``__type.ofType`` cycles) so no schema knowledge is needed and
the actual server work stays negligible (doctrine: we do NOT flood). Where the
response carries a deterministic signal that a guard is absent (an amplified
response actually came back), the check routes to the predicate oracle and the
finding is CONFIRMED; where the signal is ambiguous (e.g. introspection disabled,
so depth cannot be assessed) or where minimal-probe acceptance cannot *prove*
absence of a limit (cost), it emits a provenance-tagged LEAD instead. Every probe
carries a recognisable ``CrucibleDos*`` operationName so the operator can grep it
out of their logs (correlatable, not stealthy).

These DoS checks are OFF by default: they are NOT in the campaign's default
request-check roster and run only when a scan opts in (``enable_graphql_dos``),
so the default scan — and the regression gate — send exactly the same traffic.

Stdlib only (json). The checks POST an introspection / typo / amplification query
to the request's URL through the injected, gated ``send``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..verify.adapter import FindingContext
from .checks import Send
from .insertion import HttpRequest, RequestTemplate

# A minimal introspection query — enough to prove the schema is exposed.
_INTROSPECTION = '{"query":"query{__schema{queryType{name} types{name}}}"}'
# A query naming a field that almost certainly does not exist, to elicit a
# "Did you mean" suggestion (schema leakage with introspection disabled).
_TYPO = '{"query":"query{__crucible_no_such_field_xyz}"}'


def _post_json(req: HttpRequest, body: str) -> HttpRequest:
    headers = [(k, v) for k, v in req.headers if k.lower() not in ("content-type", "content-length")]
    headers.append(("Content-Type", "application/json"))
    headers.append(("Content-Length", str(len(body.encode("utf-8")))))
    return req.model_copy(update={"method": "POST", "headers": headers, "body": body})


def _disclosed_schema_name(body: str) -> str:
    """The FIRST schema element name the target actually disclosed under
    ``data.__schema``, or ``""`` when the response disclosed no schema at all.

    Audit-A red-pen (BLOCK-1, CRITICAL). The previous form of this decision was three
    UNRELATED substring matches over the whole body — ``"data":``, ``"__schema":`` and an
    open brace/bracket after ``"queryType":`` / ``"types":``. Measured end-to-end against a
    loopback origin, four bodies that disclose **zero** schema minted a signed
    ``ACHIEVED_STATE`` FACT at conf 0.9 that re-verified offline:

      * ``{"data":{"__schema":{"queryType":null,"types":[]}},"errors":[{"message":
        "Introspection is disabled on this endpoint."}]}``  — a field-auth denial that
        preserves the SHAPE. ``[]`` *is* an open bracket, so the tightened clause that
        claimed to require "a real object or list" accepted it.
      * ``{"data":{"__schema":{"queryType":{},"types":null}}}`` — ditto with ``{}``.
      * ``{"data":{"__schema":{"types":[]}}}``.
      * a **non-JSON WAF page** whose prose QUOTES a sample introspection response
        (the previously-disclosed residual 3 — same root cause).

    This is the sound form the old docstring only wrote down: a full ``json.loads`` of the
    response, then a check that ``data`` is an object, ``data.__schema`` is an object, and
    that object is actually POPULATED — ``queryType.name`` is a non-empty string, or
    ``types`` holds at least one element with a non-empty ``name``. Anything else (a parse
    failure, a list, ``data: null``, an errors-only Apollo body, an empty or null
    ``__schema`` member) disclosed nothing and returns ``""``.

    The returned name is a value lifted VERBATIM out of the target's own bytes, so the
    oracle below can pin it back to the retained body (see :meth:`GraphQLIntrospectionCheck.probe`).
    """
    doc = _parse_body({"body": body})
    if not isinstance(doc, dict):
        return ""
    data = doc.get("data")
    if not isinstance(data, dict):
        return ""
    schema = data.get("__schema")
    if not isinstance(schema, dict) or not schema:
        return ""
    qt = schema.get("queryType")
    if isinstance(qt, dict):
        name = qt.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    types = schema.get("types")
    if isinstance(types, list):
        for t in types:
            if isinstance(t, dict):
                name = t.get("name")
                if isinstance(name, str) and name.strip():
                    return name.strip()
    return ""


def _schema_type_count(body: str) -> int:
    """Lane S: the number of NAMED types VIGIL's reducer finds under ``data.__schema.types`` in the response
    to its OWN introspection query — a VIGIL-COMPUTED reduction that is 0 for every non-disclosing body (a
    parse failure, an errors-only Apollo body, an empty/absent/`__schema`-shaped denial, a page that merely
    quotes a sample). It is declared a provenance-ref so the strict ``gt[count,0]`` is a sound PD3 (the
    reducer output, not a producer-authorable text substring, drives the fire)."""
    doc = _parse_body({"body": body})
    if not isinstance(doc, dict):
        return 0
    data = doc.get("data")
    schema = data.get("__schema") if isinstance(data, dict) else None
    types = schema.get("types") if isinstance(schema, dict) else None
    if not isinstance(types, list):
        return 0
    return sum(1 for t in types
               if isinstance(t, dict) and isinstance(t.get("name"), str) and t.get("name").strip())


# A benign, well-formed control query for the field-suggestion differential: the spec meta-field
# ``__typename`` is valid on every GraphQL schema, so a correct server answers it WITHOUT a "did you mean"
# hint. Fetched ONLY when the typo probe actually drew a suggestion, so a non-suggesting origin (every
# benchmark host) pays no control request and the cost row is unchanged.
_SUGGEST_CONTROL = '{"query":"query{__typename}"}'


@dataclass(frozen=True)
class GraphQLIntrospectionCheck:
    """Confirm introspection is enabled: POST the introspection query and check
    the response actually returns a POPULATED schema under ``data.__schema`` —
    not just a 200, not a ``__schema``-shaped denial, and not a page that merely
    quotes one."""

    id: str = "graphql-introspection"
    bug_class: str = "graphql_introspection"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        """F7 — the certificate retains the RAW response body and the ORACLE decides.

        This used to hand ``achieved_state_oracle`` ``{"introspection_enabled": True}`` vs
        ``{"introspection_enabled": <a Python bool this check had already computed>}``: the
        oracle could only re-assert the check's own verdict, and the certificate held no
        target bytes to re-verify or to fail on.

        Audit-A red-pen BLOCK-1 (CRITICAL — a LIVE false FACT on a DEFAULT-ON check; this
        check is in ``campaign.DEFAULT_REQUEST_CHECKS`` so it runs on every scan). The
        substring-only form confirmed "introspection enabled" against four bodies that
        disclosed zero schema; :func:`_disclosed_schema_name` documents each one, measured.
        The decision is now a FULL JSON PARSE with a POPULATED-``data.__schema`` test, and
        the value it yields — a schema element name lifted verbatim from the target's own
        bytes — is what the predicate is anchored on:

          * ``"data"`` / ``"__schema"`` must still appear in the retained raw body
            (structural anchors, whitespace-independent);
          * ``disclosed_schema_name`` must be NON-EMPTY (``min_len``) — this is the clause
            the parse drives, and it is ``""`` for every non-disclosing body, so a refusal
            is a certificate whose predicate is FALSE BY CONSTRUCTION rather than a missing
            certificate (the refusal is still re-verifiable evidence);
          * and that name must be ``contains``-pinned back INTO the retained body, so it
            cannot be an invention detached from the bytes.

        HONEST RESIDUAL (oracle side). ``verify.oracles._eval_predicate`` has no JSON op —
        ``all/any/not, eq/ieq, contains/icontains, in, min_len, gt/ge`` only — so the
        re-verification of a certificate re-evaluates the parse's RESULT pinned to the body
        rather than re-running the parse. Live this can only DEMOTE (the producer refuses
        before a firing certificate exists, exactly like the B3 CSWSH producer gate); but a
        HAND-EDITED certificate that sets ``disclosed_schema_name`` to some other substring
        of a non-disclosing body would re-verify. Closing that needs a ``json_populated``
        predicate op in ``verify/oracles.py:_eval_predicate`` (~line 1100) — out of this
        slice's edit scope; named as follow-up."""
        resp = send(_post_json(template.request, _INTROSPECTION))
        body = _body_of(resp)
        return FindingContext.from_predicate(
            {"response_body": body, "query": _INTROSPECTION,
             "disclosed_schema_name": _disclosed_schema_name(body),
             "introspection_type_count": _schema_type_count(body)},
            {"all": [
                {"contains": [{"var": "response_body"}, '"data"']},
                {"contains": [{"var": "response_body"}, '"__schema"']},
                {"min_len": [{"var": "disclosed_schema_name"}, 1]},
                {"contains": [{"var": "response_body"}, {"var": "disclosed_schema_name"}]},
                # Lane S: the sound discriminator is VIGIL's schema-type-count reduction, strictly > 0 (PD3).
                # The substring/self-consistency anchors above remain as corroborators (they only narrow).
                {"gt": [{"var": "introspection_type_count"}, 0]},
            ]},
            bug_class=self.bug_class,
            provenance_refs={"introspection_type_count": "reduction"})


@dataclass(frozen=True)
class GraphQLSuggestionsCheck:
    """Confirm field suggestions leak the schema: POST a typo'd field and check
    the error offers a 'Did you mean' hint — schema disclosure even when
    introspection is disabled."""

    id: str = "graphql-suggestions"
    bug_class: str = "graphql_suggestions"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        """F7 — same fix as the introspection check: the RAW error body is retained and the
        oracle re-derives the leak from it, instead of the check computing ``leaks`` in
        Python and having ``achieved_state_oracle`` rubber-stamp the boolean back."""
        resp = send(_post_json(template.request, _TYPO))
        body = _body_of(resp)
        # Lane S: a bare icontains[body, "did you mean"] is the producer-authorable text-echo shape the
        # grammar refuses (a page could carry the phrase for unrelated reasons). Confirm a PRESENT/ABSENT
        # differential: the suggestion appears for VIGIL's typo'd field but NOT for a benign ``__typename``
        # control on the SAME endpoint. The control is fetched ONLY when the typo actually drew a suggestion,
        # so a non-suggesting origin pays no control request (the cost row stays unchanged).
        if "did you mean" not in body.lower():
            return None   # no suggestion -> nothing to adjudicate (and no control request spent)
        control_body = _body_of(send(_post_json(template.request, _SUGGEST_CONTROL)))
        return FindingContext.from_predicate(
            {"response_body": body, "query": _TYPO,
             "control_body": control_body, "control_query": _SUGGEST_CONTROL},
            {"all": [
                {"icontains": [{"var": "response_body"}, "did you mean"]},
                {"not": {"icontains": [{"var": "control_body"}, "did you mean"]}},
            ]},
            bug_class=self.bug_class)


def _body_of(resp: object) -> str:
    """The response body as text — the target-DERIVED bytes a certificate retains."""
    return str(resp.get("body", "")) if isinstance(resp, dict) else ""


# ---------------------------------------------------------------------------
# GraphQL DoS / abuse surface — query DEPTH, ALIAS overloading, request
# BATCHING, and query COST. Additive, opt-in, and minimal-by-doctrine.
# ---------------------------------------------------------------------------

# Bounded probe sizes. Deliberately small — enough to demonstrate the *capability*
# / absence of a guard, never enough to actually stress the target. One request
# each; schema-independent meta-fields keep the server work negligible.
_DEPTH_PROBE = 12        # nested ``ofType`` levels — introspection meta-schema is cyclic
_ALIAS_PROBE = 40        # aliases of ``__typename`` (each a trivial scalar resolve)
_BATCH_PROBE = 3         # operations in one array-batched HTTP request
_COST_ALIAS_PROBE = 3    # aliased list-returning selections (a static-complexity probe)

# Error tokens a guard emits when it REJECTS the amplification (so a properly
# limited endpoint reads as protected, not as a finding).
_DEPTH_GUARD_TOKENS = (
    "depth", "too deep", "nesting", "nested too", "exceeds maximum",
    "max depth", "query is too complex", "operation depth",
)
_ALIAS_GUARD_TOKENS = ("alias", "too many alias", "aliases")
_COST_GUARD_TOKENS = (
    "cost", "complexity", "too complex", "exceeds maximum", "query is too expensive",
    "operation cost", "max cost",
)


@dataclass(frozen=True)
class GraphQLDosResult:
    """The outcome of one DoS probe: at most one of ``context`` (oracle-ready
    CONFIRMED evidence) or ``lead`` (a provenance-tagged operator lead) is set;
    ``reason`` is a short human note. Both ``None`` ⇒ nothing to say (not a
    GraphQL endpoint, or the guard is present and the endpoint is protected)."""

    context: FindingContext | None = None
    lead: str | None = None
    reason: str = ""


def _parse_body(resp: object) -> object | None:
    """Parse a ``send`` response body as JSON, or ``None`` if it is not JSON."""
    if not isinstance(resp, dict):
        return None
    try:
        return json.loads(str(resp.get("body", "")))
    except (ValueError, TypeError):
        return None


def _errors_text(doc: object) -> str:
    """All GraphQL error messages in a response document, lowercased and joined —
    the text a guard's rejection message would appear in."""
    errs = doc.get("errors") if isinstance(doc, dict) else None
    if not isinstance(errs, list):
        return ""
    out = []
    for e in errs:
        if isinstance(e, dict) and e.get("message") is not None:
            out.append(str(e["message"]))
        else:
            out.append(str(e))
    return " ".join(out).lower()


def _is_graphql_shaped(doc: object) -> bool:
    """A GraphQL response is a JSON object with ``data``/``errors`` (a single
    operation) or a JSON array of such (a batched response)."""
    if isinstance(doc, dict):
        return "data" in doc or "errors" in doc
    if isinstance(doc, list):
        return bool(doc) and all(
            isinstance(e, dict) and ("data" in e or "errors" in e) for e in doc
        )
    return False


def _has_token(text: str, tokens: tuple[str, ...]) -> bool:
    return any(t in text for t in tokens)


@dataclass(frozen=True)
class GraphQLDepthCheck:
    """Unbounded query DEPTH. POSTs a single deeply-nested query built from the
    introspection meta-schema's *cyclic* ``__type -> ofType -> __type`` edge —
    schema-independent and valid, yet collapses to nulls so the server work is
    negligible. If the endpoint EXECUTES a depth-``N`` query (data returned, no
    depth-guard rejection), query-depth limiting is not enforced at depth ``N`` —
    routed to the predicate oracle. If introspection is disabled the meta-schema
    path is unavailable and depth cannot be assessed this way → LEAD."""

    id: str = "graphql-depth"
    bug_class: str = "graphql_depth_limit"
    depth: int = _DEPTH_PROBE

    def build(self) -> str:
        inner = "kind"
        for _ in range(self.depth):
            inner = "ofType { " + inner + " }"
        query = 'query CrucibleDosDepthProbe { __type(name: "Query") { ' + inner + " } }"
        return json.dumps({"query": query, "operationName": "CrucibleDosDepthProbe"})

    def assess(self, resp: object) -> GraphQLDosResult:
        doc = _parse_body(resp)
        if not _is_graphql_shaped(doc):
            return GraphQLDosResult(reason="not a GraphQL response")
        data = doc.get("data") if isinstance(doc, dict) else None
        errors = _errors_text(doc)
        executed = isinstance(data, dict) and "__type" in data
        depth_rejected = _has_token(errors, _DEPTH_GUARD_TOKENS)
        if executed:
            ctx = FindingContext.from_predicate(
                {"executed": True, "depth_rejected": depth_rejected, "probe_depth": self.depth},
                {"all": [
                    {"eq": [{"var": "executed"}, True]},
                    {"not": {"eq": [{"var": "depth_rejected"}, True]}},
                ]},
                bug_class=self.bug_class)
            return GraphQLDosResult(context=ctx, reason=f"depth-{self.depth} query executed")
        if depth_rejected:
            return GraphQLDosResult(reason="depth guard rejected the probe (protected)")
        # GraphQL-shaped but the meta-schema path did not execute (introspection
        # disabled / __type unavailable): depth is not assessable this way.
        return GraphQLDosResult(
            lead="query-depth limiting not assessable (introspection disabled); "
                 "test depth against a known schema field manually",
            reason="introspection unavailable")

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        """RequestCheck-compatible confirmed path (no lead channel)."""
        return self.probe_dos(template, send).context

    def probe_dos(self, template: RequestTemplate, send: Send) -> GraphQLDosResult:
        return self.assess(send(_post_json(template.request, self.build())))


@dataclass(frozen=True)
class GraphQLAliasCheck:
    """ALIAS overloading. POSTs one query aliasing ``__typename`` ``N`` times
    (``a0: __typename ... aN: __typename``) — ``__typename`` is a spec meta-field
    present even when introspection is disabled, so this needs no schema. If all
    ``N`` aliases resolve in one response (an ``N``× amplification actually came
    back) and no alias-count guard rejected it, alias limiting is not enforced —
    routed to the predicate oracle over the observed alias count."""

    id: str = "graphql-alias"
    bug_class: str = "graphql_alias_overloading"
    aliases: int = _ALIAS_PROBE

    def build(self) -> str:
        sel = " ".join(f"a{i}: __typename" for i in range(self.aliases))
        query = "query CrucibleDosAliasProbe { " + sel + " }"
        return json.dumps({"query": query, "operationName": "CrucibleDosAliasProbe"})

    def assess(self, resp: object) -> GraphQLDosResult:
        doc = _parse_body(resp)
        if not _is_graphql_shaped(doc):
            return GraphQLDosResult(reason="not a GraphQL response")
        data = doc.get("data") if isinstance(doc, dict) else None
        errors = _errors_text(doc)
        returned = 0
        if isinstance(data, dict):
            returned = sum(
                1 for i in range(self.aliases)
                if data.get(f"a{i}") is not None
            )
        alias_rejected = _has_token(errors, _ALIAS_GUARD_TOKENS)
        ctx = FindingContext.from_predicate(
            {"sent_aliases": self.aliases, "returned_aliases": returned,
             "alias_rejected": alias_rejected},
            {"all": [
                {"gt": [{"var": "sent_aliases"}, 1]},
                {"eq": [{"var": "returned_aliases"}, {"var": "sent_aliases"}]},
                {"not": {"eq": [{"var": "alias_rejected"}, True]}},
            ]},
            bug_class=self.bug_class)
        if returned == self.aliases and not alias_rejected:
            return GraphQLDosResult(context=ctx, reason=f"{returned} aliases resolved")
        if alias_rejected:
            return GraphQLDosResult(reason="alias guard rejected the probe (protected)")
        return GraphQLDosResult(reason=f"only {returned}/{self.aliases} aliases resolved")

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        return self.probe_dos(template, send).context

    def probe_dos(self, template: RequestTemplate, send: Send) -> GraphQLDosResult:
        return self.assess(send(_post_json(template.request, self.build())))


@dataclass(frozen=True)
class GraphQLBatchingCheck:
    """Request BATCHING. POSTs a JSON ARRAY of ``M`` tiny ``{__typename}``
    operations. A server that returns a JSON array of ``M`` results has array
    batching enabled — a binary capability (``M`` need only exceed 1 to prove it)
    that lets one HTTP request carry many operations, defeating per-request rate
    limits and enabling batched credential/enumeration attacks. Routed to the
    predicate oracle over the returned array length; a non-batching server
    returns a single object/error and does not fire."""

    id: str = "graphql-batching"
    bug_class: str = "graphql_batching"
    batch: int = _BATCH_PROBE

    def build(self) -> str:
        return json.dumps([
            {"query": "{ __typename }", "operationName": None}
            for _ in range(self.batch)
        ])

    def assess(self, resp: object) -> GraphQLDosResult:
        doc = _parse_body(resp)
        if not isinstance(doc, list):
            # Single object / error / non-JSON: batching not honoured (or not GraphQL).
            if _is_graphql_shaped(doc):
                return GraphQLDosResult(reason="batching not honoured (single response)")
            return GraphQLDosResult(reason="not a GraphQL response")
        if not _is_graphql_shaped(doc):
            return GraphQLDosResult(reason="array response is not GraphQL-shaped")
        returned = len(doc)
        all_data = all(isinstance(e, dict) and e.get("data") is not None for e in doc)
        ctx = FindingContext.from_predicate(
            {"sent_batch": self.batch, "returned_len": returned, "all_have_data": all_data},
            {"all": [
                {"gt": [{"var": "sent_batch"}, 1]},
                {"eq": [{"var": "returned_len"}, {"var": "sent_batch"}]},
                {"eq": [{"var": "all_have_data"}, True]},
            ]},
            bug_class=self.bug_class)
        if returned == self.batch and all_data:
            return GraphQLDosResult(context=ctx, reason=f"{returned}-operation batch executed")
        return GraphQLDosResult(reason=f"array of {returned}, all_data={all_data}")

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        return self.probe_dos(template, send).context

    def probe_dos(self, template: RequestTemplate, send: Send) -> GraphQLDosResult:
        return self.assess(send(_post_json(template.request, self.build())))


@dataclass(frozen=True)
class GraphQLCostCheck:
    """Query COST / complexity. POSTs one bounded compound query — a few aliased
    *list-returning* introspection selections (``__Schema.fields`` ×K) — which has
    a high STATIC complexity yet a tiny, bounded execution cost. This is
    deliberately a LEAD, never a confirmed finding: a minimal probe being accepted
    proves only that the cost limit (if any) is ≥ this probe's complexity, NOT that
    none exists — and proving absence would require a genuinely expensive,
    schema-specific query we will not send (doctrine: no flood). If a cost/
    complexity guard rejects the probe the endpoint reads as protected (silent)."""

    id: str = "graphql-cost"
    bug_class: str = "graphql_cost"
    aliases: int = _COST_ALIAS_PROBE

    def build(self) -> str:
        sel = '__type(name: "__Schema") { name fields { name } }'
        body = " ".join(f"c{i}: {sel}" for i in range(self.aliases))
        query = "query CrucibleDosCostProbe { " + body + " }"
        return json.dumps({"query": query, "operationName": "CrucibleDosCostProbe"})

    def assess(self, resp: object) -> GraphQLDosResult:
        doc = _parse_body(resp)
        if not _is_graphql_shaped(doc):
            return GraphQLDosResult(reason="not a GraphQL response")
        data = doc.get("data") if isinstance(doc, dict) else None
        errors = _errors_text(doc)
        executed = isinstance(data, dict) and data.get("c0") is not None
        cost_rejected = _has_token(errors, _COST_GUARD_TOKENS)
        if cost_rejected:
            return GraphQLDosResult(reason="cost/complexity guard rejected the probe (protected)")
        if executed:
            return GraphQLDosResult(
                lead=f"a static-complexity query ({self.aliases}× nested list selections) was "
                     "accepted without a cost/complexity rejection — no query-cost limit observed "
                     "at this complexity; assess a schema-aware cost attack manually",
                reason="compound query accepted")
        return GraphQLDosResult(
            lead="query-cost limiting not assessable (introspection disabled); "
                 "assess complexity against known expensive fields manually",
            reason="introspection unavailable")

    def probe_dos(self, template: RequestTemplate, send: Send) -> GraphQLDosResult:
        return self.assess(send(_post_json(template.request, self.build())))


# The opt-in DoS/abuse arsenal. NOT in the campaign's DEFAULT_REQUEST_CHECKS — a
# scan runs these only via ``enable_graphql_dos`` (see scanner.campaign), so the
# default scan and the regression gate are byte-for-byte unchanged.
GRAPHQL_DOS_CHECKS: tuple[object, ...] = (
    GraphQLDepthCheck(),
    GraphQLAliasCheck(),
    GraphQLBatchingCheck(),
    GraphQLCostCheck(),
)
