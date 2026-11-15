"""Allowlist re-derivation and path containment for operator-supplied console values.

The console's handlers already validate every request value they act on (a slug, a run id, a finding reference) with
an anchored pattern. A pattern check proves the value is safe but still hands the REQUEST's string to the command or
the path that follows. These helpers return a value rebuilt character by character from a fixed table instead, so
what reaches ``subprocess`` or the file system is the validated content and nothing else — and static analysis
(CodeQL) can see that.

* :func:`token` — a short identifier (slug, run id, finding ref): every character must be in the allowlist, or
  ``ValueError``; the result is rebuilt from the allowlist table.
* :func:`slug_chars` — the console's slug scrub (drop every character outside ``[A-Za-z0-9._-]``).
* :func:`contained` — ``base / rel`` resolved, which must stay inside ``base`` (``ValueError`` otherwise).

stdlib only.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Union

#: The characters an identifier may hold, mapped to themselves: the rebuilt value is read from this table.
_IDENT = {c: c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-:@ "}


def token(value: object, *, maxlen: int = 256, extra: str = "") -> str:
    """``value`` rebuilt from the identifier allowlist (plus ``extra`` characters), or ``ValueError``. Callers keep
    their own stricter pattern check; this only guarantees what is handed on is that checked content."""
    s = str(value if value is not None else "")
    allowed = _IDENT if not extra else {**_IDENT, **{c: c for c in extra}}
    if not s or len(s) > maxlen or any(c not in allowed for c in s):
        raise ValueError("value holds characters outside the allowlist")
    return "".join(allowed[c] for c in s)


#: The characters an engagement slug keeps (letters, digits, ``-``, ``_``, ``.``).
_SLUG_CHARS = {c: c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."}


def slug_chars(value: object, *, maxlen: int = 120) -> str:
    """``value`` (stripped) with every character outside ``[A-Za-z0-9._-]`` dropped, the rest read from the slug
    table, cut to ``maxlen`` — the console's existing slug scrub, in a form the result provably holds only those
    characters. May be empty: the caller refuses an empty slug."""
    text = str(value if value is not None else "").strip()
    return "".join(_SLUG_CHARS[c] for c in text if c in _SLUG_CHARS)[:maxlen]


def contained(base: Union[str, Path], rel: Union[str, Path]) -> Path:
    """``base / rel`` with every symlink resolved, which must be ``base`` itself or lie inside it; else
    ``ValueError``."""
    root = os.path.realpath(str(base))
    real = os.path.realpath(os.path.join(root, str(rel)))
    if real == root:
        return Path(root)
    if not real.startswith(root + os.sep):
        raise ValueError("path escapes its base directory")
    return Path(real)


def resolved_under(base: Union[str, Path], path: Union[str, Path]) -> Path:
    """An absolute or relative ``path`` resolved (``~`` expanded), which must lie inside ``base``; else
    ``ValueError``."""
    root = os.path.realpath(os.path.expanduser(str(base)))
    real = os.path.realpath(os.path.expanduser(str(path)))
    if real == root:
        return Path(root)
    if not real.startswith(root + os.sep):
        raise ValueError("path escapes its base directory")
    return Path(real)
