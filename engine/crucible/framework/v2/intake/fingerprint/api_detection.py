"""api_detection — identify API patterns (REST / GraphQL / SOAP / RPC)."""

from __future__ import annotations

from typing import Iterable

from ..models import DetectionResult, HTTPExchange
from . import _common as c


SIGNATURES = (
    # REST / generic
    c.path("rest",      c.re_(r"^/api(/|$)|^/v\d+/"),                  0.7,  "/api/ or /vN/ path served"),
    c.path("rest",      c.re_(r"^/api/v\d+(/|$)"),                     0.85, "/api/vN/ path"),
    c.hdr ("rest",      "Content-Type", c.re_(r"application/(json|hal\+json|vnd\..*\+json)"),
                                                                       0.4,  "JSON Content-Type"),

    # OpenAPI / Swagger
    c.path("openapi",   c.re_(r"/(openapi\.json|swagger\.json|api-docs)"), 0.95, "OpenAPI/Swagger doc path"),
    c.body("openapi",   c.re_(r"\"openapi\"\s*:\s*\"[0-9]"),           0.95, "OpenAPI version key in body"),
    c.body("openapi",   c.re_(r"\"swagger\"\s*:\s*\""),                0.95, "Swagger version key in body"),

    # GraphQL
    c.path("graphql",   c.re_(r"^/(graphql|graphiql|graphql-explorer)$"), 0.95, "/graphql endpoint"),
    c.body("graphql",   c.re_(r"\"errors\":\s*\[.*\"locations\""),     0.85, "GraphQL error shape"),
    c.body("graphiql",  c.re_(r"GraphiQL|graphql-playground"),         0.95, "GraphiQL/Playground UI"),

    # gRPC-Web
    c.hdr ("grpc-web",  "Content-Type", c.re_(r"application/grpc-web"), 0.95, "gRPC-Web Content-Type"),
    c.hdr ("grpc-web",  "Grpc-Status",  "",                             0.95, "Grpc-Status header"),

    # JSON-RPC
    c.body("jsonrpc",   c.re_(r"\"jsonrpc\"\s*:\s*\"2\.0\""),          0.95, "JSON-RPC 2.0 envelope"),

    # SOAP / WSDL
    c.path("soap",      c.re_(r"\.asmx(\?WSDL)?$|\?wsdl$"),            0.95, ".asmx or ?wsdl path"),
    c.body("soap",      c.re_(r"<soap:Envelope|<soapenv:Envelope"),    0.95, "SOAP envelope"),
    c.hdr ("soap",      "Content-Type", c.re_(r"text/xml|application/soap"),
                                                                       0.6,  "SOAP/XML Content-Type"),

    # HAL / HATEOAS
    c.body("hal",       c.re_(r"\"_links\":\s*\{"),                    0.7,  "HAL _links key"),
    c.body("hateoas",   c.re_(r"\"_embedded\":\s*\{"),                 0.5,  "HAL _embedded key"),

    # OData
    c.body("odata",     c.re_(r"\"@odata\.context\""),                 0.95, "OData @odata.context"),
    c.path("odata",     c.re_(r"/odata/"),                             0.7,  "/odata/ path"),

    # tRPC
    c.body("trpc",      c.re_(r"\"trpc\"|trpc-id"),                    0.7,  "tRPC marker"),

    # Server-Sent Events / WebSocket signals
    c.hdr ("sse",       "Content-Type", c.re_(r"text/event-stream"),   0.95, "text/event-stream"),
    c.hdr ("websocket", "Upgrade",      c.re_(r"websocket"),           0.95, "Upgrade: websocket"),
)


def detect(exchanges: Iterable[HTTPExchange]) -> DetectionResult:
    return c.run("api_detection", SIGNATURES, exchanges, category="api")
