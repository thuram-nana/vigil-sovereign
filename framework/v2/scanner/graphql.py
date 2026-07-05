"""
scanner.graphql — GraphQL security checks.

A GraphQL endpoint is its own surface: introspection that hands an attacker the
whole schema, and field "did you mean?" suggestions that leak it even when
introspection is off. Neither is reachable by parameter fuzzing — they need a
GraphQL query POSTed and the JSON response inspected. These request-level checks
do that, confirmed via achieved-state on the actual leak (a returned schema / a
suggestion), not on the mere presence of a ``/graphql`` path.

Stdlib only (json). The checks POST an introspection / typo query to the request's
URL through the injected, gated ``send``.
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


@dataclass(frozen=True)
class GraphQLIntrospectionCheck:
    """Confirm introspection is enabled: POST the introspection query and check
    the response actually returns a schema (``__schema`` / ``queryType`` / a
    ``types`` list under ``data``) — not just a 200."""

    id: str = "graphql-introspection"
    bug_class: str = "graphql_introspection"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        resp = send(_post_json(template.request, _INTROSPECTION))
        enabled = _schema_returned(resp)
        return FindingContext.from_state(
            {"introspection_enabled": True}, {"introspection_enabled": enabled},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class GraphQLSuggestionsCheck:
    """Confirm field suggestions leak the schema: POST a typo'd field and check
    the error offers a 'Did you mean' hint — schema disclosure even when
    introspection is disabled."""

    id: str = "graphql-suggestions"
    bug_class: str = "graphql_suggestions"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        resp = send(_post_json(template.request, _TYPO))
        body = str(resp.get("body", "")) if isinstance(resp, dict) else ""
        leaks = "did you mean" in body.lower()
        return FindingContext.from_state(
            {"suggestions_enabled": True}, {"suggestions_enabled": leaks},
            bug_class=self.bug_class)


def _schema_returned(resp: object) -> bool:
    if not isinstance(resp, dict):
        return False
    body = str(resp.get("body", ""))
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return False
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, dict):
        return False
    schema = data.get("__schema")
    return isinstance(schema, dict) and ("queryType" in schema or "types" in schema)
