"""A tiny stdlib router: (method, path) -> handler, with exact and `<param>` segment matching.

Handlers are `(Ctx) -> Response`. Kept deliberately small and dependency-free.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Callable, Optional, Union


@dataclass
class Ctx:
    """One request, plus the range state a handler needs."""

    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: bytes
    client_ip: str
    base_dir: str
    mode: str  # 'vuln' | 'hardened', read fresh per request
    params: dict[str, str] = field(default_factory=dict)

    def q1(self, name: str, default: str = "") -> str:
        """First value of query param `name`."""
        vals = self.query.get(name)
        return vals[0] if vals else default

    def form(self) -> dict[str, list[str]]:
        """Parse a urlencoded POST body."""
        import urllib.parse
        return urllib.parse.parse_qs(self.body.decode("utf-8", "replace"))

    def f1(self, name: str, default: str = "") -> str:
        vals = self.form().get(name)
        return vals[0] if vals else default

    @property
    def hardened(self) -> bool:
        return self.mode == "hardened"

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def html(cls, markup: str, status: int = 200) -> "Response":
        return cls(status=status, body=markup.encode("utf-8", "replace"),
                   content_type="text/html; charset=utf-8")

    @classmethod
    def text(cls, s: str, status: int = 200, content_type: str = "text/plain; charset=utf-8") -> "Response":
        return cls(status=status, body=s.encode("utf-8", "replace"), content_type=content_type)

    @classmethod
    def json(cls, obj: object, status: int = 200, headers: Optional[dict[str, str]] = None) -> "Response":
        return cls(status=status, body=json.dumps(obj).encode("utf-8"),
                   content_type="application/json", headers=headers or {})

    @classmethod
    def redirect(cls, location: str, status: int = 302) -> "Response":
        return cls(status=status, body=b"", headers={"Location": location})


@dataclass
class StreamResponse:
    """A streaming response: the handler writes each chunk as the generator yields it, then closes the
    connection (Connection: close). Used by Range Control to stream a live verb's stdout to the browser."""

    chunks: Iterator[bytes]
    content_type: str = "text/plain; charset=utf-8"
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)


AnyResponse = Union[Response, StreamResponse]
Handler = Callable[[Ctx], AnyResponse]


class Router:
    def __init__(self) -> None:
        self._routes: list[tuple[str, list[str], Handler]] = []

    def add(self, method: str, path: str, handler: Handler) -> None:
        self._routes.append((method.upper(), path.strip("/").split("/") if path != "/" else [""], handler))

    def get(self, path: str) -> Callable[[Handler], Handler]:
        def deco(h: Handler) -> Handler:
            self.add("GET", path, h)
            return h
        return deco

    def post(self, path: str) -> Callable[[Handler], Handler]:
        def deco(h: Handler) -> Handler:
            self.add("POST", path, h)
            return h
        return deco

    @staticmethod
    def _match(pattern: list[str], parts: list[str]) -> Optional[dict[str, str]]:
        if len(pattern) != len(parts):
            return None
        params: dict[str, str] = {}
        for pat, got in zip(pattern, parts, strict=True):  # lengths pre-checked equal above
            if pat.startswith("<") and pat.endswith(">"):
                params[pat[1:-1]] = got
            elif pat != got:
                return None
        return params

    def dispatch(self, ctx: Ctx) -> Optional[AnyResponse]:
        parts = ctx.path.strip("/").split("/") if ctx.path != "/" else [""]
        for method, pattern, handler in self._routes:
            if method != ctx.method:
                continue
            params = self._match(pattern, parts)
            if params is not None:
                ctx.params = params
                return handler(ctx)
        return None
