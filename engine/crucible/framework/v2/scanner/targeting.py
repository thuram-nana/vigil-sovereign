"""
scanner.targeting — surface-driven check selection.

Running every check against every insertion point is correct but wasteful: a
`redirect=` parameter is not SQL, an `id=` parameter is rarely XSS. Burp leans on
a human's intuition here; this is that intuition as code — a fingerprint of the
insertion point (its parameter name, and optionally whether it reflects input)
maps to the bug classes worth trying first, so the autonomous sweep spends its
request budget where a bug is plausible.

It is a *prioritiser*, never a gate: if a point matches no hint it falls back to
the full check set, so nothing is silently skipped — targeting narrows effort, it
does not blind the scan. Pure and deterministic.
"""

from __future__ import annotations

from .checks import Check
from .insertion import InsertionPoint

# Parameter-name signal → the bug classes that name suggests, most-specific first.
# Matched by exact name or as a substring, case-insensitive.
_HINTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("redirect", "returnurl", "return_url", "next", "dest", "destination",
      "continue", "goto", "forward", "out", "view"),
     ("open_redirect", "ssrf")),
    (("url", "uri", "link", "site", "host", "domain", "feed", "proxy", "fetch",
      "load", "callback", "webhook", "target"),
     ("ssrf", "open_redirect")),
    (("file", "filename", "path", "filepath", "template", "page", "include",
      "document", "dir", "folder", "download", "read"),
     ("path_traversal",)),
    (("cmd", "command", "exec", "execute", "run", "ping", "host_cmd"),
     ("command_injection",)),
    (("xml", "soap", "xmldata"),
     ("blind_xxe",)),
    (("id", "uid", "userid", "user_id", "account", "accountid", "pid", "oid",
      "order", "orderid", "record", "recordid", "num", "key", "ref", "object"),
     ("idor", "boolean_sqli")),
    (("q", "query", "search", "keyword", "term", "filter", "name", "title",
      "category", "sort", "order_by", "field", "column", "s"),
     ("boolean_sqli", "xss")),
)

# Classes worth trying on any point that reflects input into the response.
_REFLECTION_CLASSES = ("xss", "ssti", "error_based_sqli", "path_traversal")


def likely_classes(param_name: str) -> list[str]:
    """The bug classes suggested by a parameter name (deduped, priority order).

    A needle matches by exact name always, and as a substring only when it is at
    least 3 chars — so short names like ``s``/``q``/``id`` do not fire on every
    parameter that merely contains those letters."""
    name = (param_name or "").lower()
    classes: list[str] = []
    for needles, cls in _HINTS:
        if any(n == name or (len(n) >= 3 and n in name) for n in needles):
            classes.extend(cls)
    return list(dict.fromkeys(classes))


def select_checks(
    point: InsertionPoint,
    checks: tuple[Check, ...],
    *,
    reflected: bool = False,
) -> list[Check]:
    """The prioritised checks for one insertion point. Falls back to the full set
    when the point matches no hint, so coverage is never silently lost."""
    by_class: dict[str, Check] = {}
    for c in checks:
        by_class.setdefault(c.bug_class, c)

    wanted = likely_classes(point.name)
    if reflected:
        wanted = wanted + list(_REFLECTION_CLASSES)

    selected = [by_class[bc] for bc in dict.fromkeys(wanted) if bc in by_class]
    return selected or list(checks)
