"""
scanner.nuclei_compile — compile a Nuclei YAML TEMPLATE into a CRUCIBLE library entry (Workstream D.3).

CRUCIBLE already drives the nuclei BINARY as a gated sensor and mints its output as leads
(``sensors.web_scanner``). This module is the other, offline direction: it reads a Nuclei TEMPLATE
DEFINITION (the YAML itself) and COMPILES a supported subset into a native ``scanner.library``
:class:`~scanner.library.LibraryEntry`, so CRUCIBLE can run the template's logic through its OWN
engine and — crucially — re-verify the match with its OWN deterministic oracle. No nuclei binary is
needed to run a compiled entry.

Prove-don't-guess, by construction:
  * The template's own verdict is NEVER trusted. A compiled entry is a PROVENANCE-TAGGED LEAD until
    CRUCIBLE's OWN check re-fires the match over a REAL response and the predicate/ACHIEVED-STATE
    oracle confirms it. A word/status/regex/dsl match compiles to a declarative predicate the
    predicate oracle re-evaluates over the raw ``{status, body}`` a real request returned — the
    external template's classification only ever raises priority; it never mints a fact. The compiled
    entry carries its origin in ``payload_family = "nuclei:<id>"`` and a ``nuclei-template:<id>``
    reference.
  * A template (or a matcher term) outside the supported subset compiles to nothing (``supported=False``
    with a reason) — it degrades cleanly, never guesses.

Supported matcher subset (widened in Wave C, slice C2):
  * ``word`` matchers over the response BODY (the original slice) — case-insensitive substring.
  * ``status`` matchers — the response status is one of the template's codes.
  * ``regex`` matchers over the BODY — reduced to the pattern's distinctive LITERAL CORE (the longest
    literal run that any match MUST contain). CRUCIBLE re-verifies presence of that literal, never
    "the full pattern matched": a SOUND weakening, since a regex match implies the literal is present.
    The template's regex is NEVER compiled or executed here (no ReDoS surface), only statically parsed.
  * ``dsl`` matchers — a conservative subset (``status_code == N``, ``contains(body, "lit")`` /
    ``icontains`` / ``contains(tolower(body), "lit")``, joined by ``&&`` or ``||``). Anything else in
    the expression degrades that term.
  * MULTI-REQUEST templates — the first self-contained, re-verifiable request is compiled (a request
    that chains a value extracted from an earlier one is not self-contained and is skipped).
  * RAW-request templates — a fixed ``GET`` raw request (request line + headers + optional body, no
    interpolation beyond ``BaseURL``/``Hostname``). Non-GET raw requests degrade (a scanner mints only
    over idempotent probes).

Matcher combination is faithful and CONSERVATIVE: the template's ``matchers-condition`` (default
``or``) and each matcher's ``condition`` (default ``or``) map to predicate ``all``/``any``. An
unsupported term is DROPPED only under ``or`` (which makes the compiled match STRICTER — a subset — so
it can never fire where the template would not); under ``and`` a single unsupported/negative term
degrades the WHOLE template, because dropping an ``and`` term would fire MORE broadly than the source.
``negative`` matchers (must-NOT-appear) are never a basis for a mint — absence is not a re-verifiable
fact — so they degrade like any unsupported term.

OFF by default + gate-neutral: the compiler is a pure function that RETURNS entries to the caller. It
writes nothing into the shipped ``library_entries/`` directory, so a compiled entry never enters the
benchmark/scan/engage default path and the regression gate stays byte-identical. An operator opts in
by compiling templates and passing the entries to a campaign explicitly (``library_entries=``).

DETERMINISM: parsing YAML and shaping an entry is a pure, replayable function of the template text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..common.errors import CrucibleError
from .library import LibraryEntry, OracleSpec

# Nuclei severities -> CRUCIBLE finding-template severities.
_SEVERITY_MAP: dict[str, str] = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info", "unknown": "Info", "": "Info",
}

# The bug classes a compiled signature check may claim. A ``signature``/``nuclei_http`` oracle spec
# compiles to a check whose confirmation is the predicate/ACHIEVED-STATE oracle, so the class MUST be
# one that routes to ACHIEVED-STATE (see verify.verifier.BUG_CLASS_ORACLES). A word/status/regex match
# at a path is an exposure detection, so the vocabulary here is deliberately the exposure family.
_EXPOSURE_CLASSES: frozenset[str] = frozenset({"exposure", "sensitive_exposure", "security_misconfiguration"})
_DEFAULT_BUG_CLASS = "exposure"

# A tiny CWE -> class hint (best-effort; anything unmapped falls back to the default exposure class).
_CWE_HINTS: dict[str, str] = {
    "cwe-200": "sensitive_exposure",   # exposure of sensitive information
    "cwe-538": "sensitive_exposure",   # file/dir info exposure
    "cwe-16": "security_misconfiguration",
    "cwe-1004": "security_misconfiguration",
}

# The BaseURL interpolation nuclei uses for the target root; we strip it to a relative probe path.
_BASE_URL_TOKENS: tuple[str, ...] = ("{{BaseURL}}", "{{RootURL}}", "{{Hostname}}")

# A regex matcher is re-verified by its distinctive LITERAL CORE; a core shorter than this is not
# distinctive enough to ground a fact (it would be an FP magnet), so the regex term degrades instead.
_MIN_REGEX_LITERAL = 4

# A defensive cap on the pattern length we will statically parse (single linear pass; no execution).
_MAX_REGEX_PARSE = 8192


class NucleiCompileError(CrucibleError):
    """A template is unreadable/unparseable. A plain recoverable error — this module authors a check,
    it makes no trust decision, so a bad template is a data error, never an ethics crossing."""


@dataclass(frozen=True)
class CompiledTemplate:
    """The outcome of compiling one Nuclei template. ``supported`` is True with a populated ``entry``
    when the template fell in the subset this compiler understands; otherwise ``entry`` is None and
    ``reason`` explains why (the template degrades cleanly rather than being force-fit). ``template_id``
    is the source template's id (provenance)."""

    template_id: str
    supported: bool
    entry: LibraryEntry | None = None
    reason: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _first(value: Any) -> Any:
    """The first element of a list, the value itself if scalar, or None if empty."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _strip_base_url(path: str) -> str | None:
    """Turn a nuclei path (``{{BaseURL}}/actuator/env``) into a relative probe path (``/actuator/env``).
    Returns None when the path carries interpolation OTHER than the leading BaseURL token — the probe
    only fetches a fixed path, so a templated/computed path is unsupported."""
    p = path.strip()
    for tok in _BASE_URL_TOKENS:
        if p.startswith(tok):
            p = p[len(tok):]
            break
    if "{{" in p or "}}" in p:
        return None   # residual interpolation -> not a fixed path
    if not p.startswith("/"):
        p = "/" + p
    return p


def _extract_word_matcher(request: dict) -> tuple[str | None, tuple[str, ...]]:
    """Find a ``word`` matcher over the response BODY and return ``(signature, warnings)``. The first
    word of the first body ``word`` matcher becomes the signature (the simple ``signature`` entry
    confirms a single distinctive substring). Returns ``(None, ...)`` when no usable body word matcher
    exists. This is the ORIGINAL, unchanged simple-case extractor — a plain GET template with a body
    word still compiles to exactly the ``signature`` entry it did before this slice."""
    matchers = request.get("matchers")
    warnings: list[str] = []
    if not isinstance(matchers, list) or not matchers:
        return None, ("template has no matchers",)
    for m in matchers:
        if not isinstance(m, dict):
            continue
        if m.get("type") != "word":
            continue
        if m.get("negative") is True:
            continue
        part = (m.get("part") or "body")
        if part != "body":
            warnings.append(f"skipped a word matcher on part={part!r} (only body is supported)")
            continue
        words = m.get("words")
        if isinstance(words, list) and words and isinstance(words[0], str) and words[0].strip():
            if "{{" in words[0] or "}}" in words[0]:
                continue   # a computed word (interpolation) is not a fixed literal
            if len(words) > 1:
                warnings.append(f"used only the first of {len(words)} words as the signature")
            return words[0], tuple(warnings)
    return None, tuple(warnings) or ("no body 'word' matcher found",)


def _bug_class_from_info(info: dict) -> str:
    """Derive a compiled bug_class from the template's classification CWEs / tags, defaulting to the
    exposure class. Always returns a class that routes to the ACHIEVED-STATE oracle."""
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cwes = classification.get("cwe-id")
    for cwe in (cwes if isinstance(cwes, list) else [cwes]):
        hint = _CWE_HINTS.get(str(cwe).strip().lower())
        if hint in _EXPOSURE_CLASSES:
            return hint
    return _DEFAULT_BUG_CLASS


def _references(template_id: str, info: dict) -> list[str]:
    """Provenance + citations: the CWE ids the template declares, its external references, and a
    ``nuclei-template:<id>`` tag so a compiled finding traces back to its origin."""
    refs: list[str] = []
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cwes = classification.get("cwe-id")
    for cwe in (cwes if isinstance(cwes, list) else [cwes] if cwes else []):
        c = str(cwe).strip().upper()
        if c:
            refs.append(c)
    ext = info.get("reference")
    for r in (ext if isinstance(ext, list) else [ext] if ext else []):
        rs = str(r).strip()
        if rs:
            refs.append(rs)
    refs.append(f"nuclei-template:{template_id}")
    # de-dupe, order-preserving
    seen: set[str] = set()
    return [r for r in refs if not (r in seen or seen.add(r))]


# ---------------------------------------------------------------------------
# regex -> distinctive literal core (static parse only; the pattern is NEVER executed)
# ---------------------------------------------------------------------------


_QUANT_RE = re.compile(r"\{(\d*)(,?)(\d*)\}")


def _quantifier_at(pattern: str, i: int) -> tuple[int, int] | None:
    """If a ``{m}``/``{m,}``/``{,n}``/``{m,n}`` quantifier begins at ``pattern[i]``, return
    ``(end_index, min_count)``; otherwise None (a literal ``{``). ``{}``/``{,}`` are not quantifiers."""
    m = _QUANT_RE.match(pattern, i)
    if not m:
        return None
    lo, _comma, hi = m.group(1), m.group(2), m.group(3)
    if not lo and not hi:
        return None   # {} or {,}: a literal brace, not a quantifier
    return m.end(), (int(lo) if lo else 0)


def _regex_atoms(pattern: str) -> list[tuple[str | None, bool]] | None:
    """Statically tokenise ``pattern`` into ``(literal_char | None, required)`` atoms in a single
    linear pass, or return None when it uses a construct whose "required literal" is not well defined
    (grouping ``(``/``)`` or alternation ``|`` — we bail conservatively).

    ``required`` is False for an atom a ``*``/``?``/``{0,..}`` quantifier can make zero-occurrence; a
    literal char with ``required`` True is guaranteed to appear in every string the pattern matches.
    Character classes, ``.``/anchors, and class escapes (``\\d``/``\\w``/…) are non-literal atoms (char
    None). An escaped NON-alphanumeric (``\\.``/``\\/``/…) is the literal char it escapes. A ``{m,n}``
    quantifier keeps the required literal PREFIX before it (only its own atom's required-ness depends on
    ``m``). No regex engine is invoked — this is pure string scanning, so no attacker-authored pattern
    can execute (no ReDoS)."""
    if not isinstance(pattern, str) or not pattern or len(pattern) > _MAX_REGEX_PARSE:
        return None
    atoms: list[tuple[str | None, bool]] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch in "()|":
            return None   # grouping / alternation: any literal could be optional -> bail
        if ch == "\\":
            if i + 1 >= n:
                return None   # trailing backslash: malformed
            nxt = pattern[i + 1]
            atom_char = None if nxt.isalnum() else nxt   # \d \w \1 -> class/backref; \. \/ -> literal
            i += 2
        elif ch == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":   # a literal ']' as the first class member
                j += 1
            while j < n and pattern[j] != "]":
                if pattern[j] == "\\":
                    j += 1
                j += 1
            if j >= n:
                return None   # unterminated class: malformed
            atom_char = None
            i = j + 1
        elif ch in ".^$":
            atom_char = None
            i += 1
        elif ch in "*+?":
            return None   # a quantifier with no preceding atom: malformed
        else:
            atom_char = ch    # ordinary literal (a bare '{' that is not a quantifier lands here too)
            i += 1
        # Peek for a quantifier that binds to the atom just consumed.
        required = True
        if i < n and pattern[i] in "*?":
            required = False   # zero occurrences allowed
            i += 1
            if i < n and pattern[i] == "?":   # lazy modifier
                i += 1
        elif i < n and pattern[i] == "+":
            required = True    # one-or-more: at least once
            i += 1
            if i < n and pattern[i] == "?":
                i += 1
        elif i < n and pattern[i] == "{":
            q = _quantifier_at(pattern, i)
            if q is not None:
                end, min_count = q
                i = end
                required = min_count >= 1
                if i < n and pattern[i] == "?":   # lazy modifier
                    i += 1
            # else: a literal '{' — leave it for the next iteration to consume as a literal atom.
        atoms.append((atom_char, required))
    return atoms


def _regex_literal_core(pattern: str) -> str | None:
    """The longest run of REQUIRED literal characters in ``pattern`` (a substring any match must
    contain), or None when there is none of length ``_MIN_REGEX_LITERAL`` or when the pattern is
    outside the statically-reasoned subset."""
    atoms = _regex_atoms(pattern)
    if atoms is None:
        return None
    best, cur = "", ""
    for c, required in atoms:
        if c is not None and required:
            cur += c
        else:
            if len(cur) > len(best):
                best = cur
            cur = ""
    if len(cur) > len(best):
        best = cur
    return best if len(best) >= _MIN_REGEX_LITERAL else None


# ---------------------------------------------------------------------------
# matcher -> predicate-oracle AST (over {status, body}); existing ops only
# ---------------------------------------------------------------------------


def _translate_word_matcher(m: dict) -> tuple[dict | None, list[str]]:
    """A body ``word`` matcher -> an ``icontains`` clause (case-insensitive, matching the simple
    ``signature`` path). Multiple words combine per the matcher's ``condition`` (default ``or``)."""
    part = (m.get("part") or "body")
    if part != "body":
        return None, [f"skipped a word matcher on part={part!r} (only body is supported)"]
    words = m.get("words")
    if not (isinstance(words, list) and words):
        return None, ["word matcher has no words"]
    clauses: list[dict] = []
    for w in words:
        if isinstance(w, str) and w and "{{" not in w and "}}" not in w:
            clauses.append({"icontains": [{"var": "body"}, w]})
    if not clauses:
        return None, ["word matcher has no usable fixed string words"]
    if len(clauses) == 1:
        return clauses[0], []
    cond = str(m.get("condition") or "or").strip().lower()
    return ({"all": clauses} if cond == "and" else {"any": clauses}), []


def _translate_status_matcher(m: dict) -> tuple[dict | None, list[str]]:
    """A ``status`` matcher -> ``status in [codes]`` (nuclei ORs its status list)."""
    statuses = m.get("status")
    ints: list[int] = []
    for s in (statuses if isinstance(statuses, list) else [statuses]):
        try:
            ints.append(int(s))
        except (TypeError, ValueError):
            continue
    if not ints:
        return None, ["status matcher has no integer codes"]
    return {"in": [{"var": "status"}, ints]}, []


def _translate_regex_matcher(m: dict) -> tuple[dict | None, list[str]]:
    """A body ``regex`` matcher -> a ``contains`` clause over each pattern's distinctive literal core.
    CRUCIBLE re-verifies the LITERAL, never the full pattern (a sound weakening). Patterns without a
    distinctive core are dropped under ``or``; under ``and`` a drop degrades the matcher (would widen)."""
    part = (m.get("part") or "body")
    if part != "body":
        return None, [f"skipped a regex matcher on part={part!r} (only body is supported)"]
    patterns = m.get("regex")
    if not (isinstance(patterns, list) and patterns):
        return None, ["regex matcher has no patterns"]
    clauses: list[dict] = []
    dropped = 0
    for p in patterns:
        core = _regex_literal_core(p) if isinstance(p, str) else None
        if core is None:
            dropped += 1
            continue
        clauses.append({"contains": [{"var": "body"}, core]})
    if not clauses:
        return None, [f"no regex pattern has a distinctive literal core (>= {_MIN_REGEX_LITERAL} chars)"]
    cond = str(m.get("condition") or "or").strip().lower()
    if cond == "and" and dropped:
        return None, ["a regex AND term has no literal core; won't widen an AND"]
    warnings = ["re-verifies the literal core of the regex pattern(s), not the full pattern"]
    if dropped:
        warnings.append(f"dropped {dropped} regex pattern(s) with no distinctive literal core")
    if len(clauses) == 1:
        return clauses[0], warnings
    return ({"all": clauses} if cond == "and" else {"any": clauses}), warnings


_DSL_STATUS_RE = re.compile(r"^status_code\s*==\s*(\d{1,3})$")
_DSL_CONTAINS_RE = re.compile(
    r"^(contains|icontains)\s*\(\s*(tolower\(\s*body\s*\)|body)\s*,\s*([\"'])(.*)\3\s*\)$",
    re.DOTALL,
)


def _translate_dsl_term(term: str) -> dict | None:
    """One atomic DSL comparison -> a predicate clause, or None if outside the supported subset."""
    s = term.strip()
    mm = _DSL_STATUS_RE.match(s)
    if mm:
        return {"eq": [{"var": "status"}, int(mm.group(1))]}
    mm = _DSL_CONTAINS_RE.match(s)
    if mm:
        lit = mm.group(4)
        if not lit or "{{" in lit or "}}" in lit:
            return None
        case_insensitive = (mm.group(1) == "icontains") or mm.group(2).startswith("tolower")
        op = "icontains" if case_insensitive else "contains"
        return {op: [{"var": "body"}, lit]}
    return None


def _translate_dsl_expr(expr: str) -> dict | None:
    """A DSL expression -> a predicate clause. Supports ``&&`` (all) or ``||`` (any) joins of atomic
    terms; a mix of both (ambiguous precedence) or any unsupported term degrades the whole expression."""
    if not isinstance(expr, str):
        return None
    s = expr.strip()
    has_and, has_or = "&&" in s, "||" in s
    if has_and and has_or:
        return None   # mixed precedence: refuse rather than mis-bind
    if has_and:
        subs = [_translate_dsl_expr(p) for p in s.split("&&")]
        return {"all": subs} if all(x is not None for x in subs) else None
    if has_or:
        subs = [_translate_dsl_expr(p) for p in s.split("||")]
        return {"any": subs} if all(x is not None for x in subs) else None
    return _translate_dsl_term(s)


def _translate_dsl_matcher(m: dict) -> tuple[dict | None, list[str]]:
    """A ``dsl`` matcher -> a predicate clause over its supported expressions."""
    exprs = m.get("dsl")
    if not (isinstance(exprs, list) and exprs):
        return None, ["dsl matcher has no expressions"]
    clauses: list[dict] = []
    dropped = 0
    for e in exprs:
        c = _translate_dsl_expr(e) if isinstance(e, str) else None
        if c is None:
            dropped += 1
            continue
        clauses.append(c)
    if not clauses:
        return None, ['dsl matcher has no supported expression '
                      '(supported: status_code==N, contains/icontains(body,"lit"), &&/||)']
    cond = str(m.get("condition") or "or").strip().lower()
    if cond == "and" and dropped:
        return None, ["a dsl AND expression is unsupported; won't widen an AND"]
    warnings: list[str] = []
    if dropped:
        warnings.append(f"dropped {dropped} unsupported dsl expression(s)")
    if len(clauses) == 1:
        return clauses[0], warnings
    return ({"all": clauses} if cond == "and" else {"any": clauses}), warnings


def _build_match_predicate(request: dict) -> tuple[dict | None, list[str], str]:
    """Translate a request's matcher block into a single predicate-oracle AST over ``{status, body}``,
    honouring ``matchers-condition``. Returns ``(predicate, warnings, reason)`` — ``predicate`` is None
    (with a reason) when nothing re-verifiable remains. Under ``and`` an unsupported/negative term
    degrades the whole template (dropping it would fire more broadly); under ``or`` unsupported terms
    are dropped (making the match a stricter subset — never firing where the template would not)."""
    matchers = request.get("matchers")
    warnings: list[str] = []
    if not isinstance(matchers, list) or not matchers:
        return None, warnings, "template has no matchers"
    condition = str(request.get("matchers-condition") or "or").strip().lower()
    if condition not in ("and", "or"):
        condition = "or"

    clauses: list[dict] = []
    had_unsupported = False
    for m in matchers:
        if not isinstance(m, dict):
            had_unsupported = True
            continue
        if m.get("negative") is True:
            had_unsupported = True
            warnings.append("skipped a negative matcher (absence is not a re-verifiable fact)")
            continue
        mtype = str(m.get("type") or "word").lower()
        if mtype == "word":
            clause, w = _translate_word_matcher(m)
        elif mtype == "status":
            clause, w = _translate_status_matcher(m)
        elif mtype == "regex":
            clause, w = _translate_regex_matcher(m)
        elif mtype == "dsl":
            clause, w = _translate_dsl_matcher(m)
        else:
            clause, w = None, [f"skipped an unsupported matcher type {mtype!r}"]
        warnings.extend(w)
        if clause is None:
            had_unsupported = True
        else:
            clauses.append(clause)

    if not clauses:
        return None, warnings, "no re-verifiable matcher (status/word/regex-literal/dsl) found"
    if condition == "and" and had_unsupported:
        return (None, warnings,
                "an AND matcher term is not re-verifiable; template degraded (won't widen an AND)")
    if len(clauses) == 1:
        return clauses[0], warnings, ""   # a single clause needs no all/any wrapper
    if condition == "and":
        return {"all": clauses}, warnings, ""
    # OR: dropping unsupported branches only makes the compiled match STRICTER (a subset) -> sound.
    return {"any": clauses}, warnings, ""


# ---------------------------------------------------------------------------
# raw request parsing (a fixed GET request line + headers + optional body)
# ---------------------------------------------------------------------------


def _parse_raw_request(raw: Any) -> tuple[str, str, tuple[tuple[str, str], ...], str | None] | str:
    """Parse a nuclei ``raw`` request blob into ``(method, probe_path, headers, body)`` or return a
    reason string when unsupported. Only a fixed ``GET`` with a BaseURL-relative target is accepted
    (a scanner mints only over idempotent probes). The ``Host`` header is dropped (the target's netloc
    wins) and any header/body carrying interpolation is dropped (it cannot be resolved statically —
    omitting it is safe: at worst re-verification does not fire, which mints nothing)."""
    blob = _first(raw)
    if not isinstance(blob, str) or not blob.strip():
        return "raw request block is empty"
    text = blob.replace("\r\n", "\n").replace("\r", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    request_line = lines[0].strip() if lines else ""
    parts = request_line.split()
    if len(parts) < 2:
        return "raw request line is malformed"
    method = parts[0].upper()
    target = parts[1]
    if method != "GET":
        return f"only GET raw requests are supported, got {method}"
    probe_path = _strip_base_url(target)
    if probe_path is None:
        return f"raw request target carries interpolation beyond BaseURL: {target!r}"
    headers: list[tuple[str, str]] = []
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        name, _, value = ln.partition(":")
        name, value = name.strip(), value.strip()
        if not name or name.lower() == "host":
            continue
        if "{{" in name or "}}" in name or "{{" in value or "}}" in value:
            continue
        headers.append((name, value))
    body_val: str | None = body if body.strip() else None
    if body_val is not None and ("{{" in body_val or "}}" in body_val):
        body_val = None
    return method, probe_path, tuple(headers), body_val


# ---------------------------------------------------------------------------
# per-request compilation
# ---------------------------------------------------------------------------


def _compile_request(request: dict) -> tuple[OracleSpec | None, tuple[str, ...], str]:
    """Compile ONE request block into an :class:`~scanner.library.OracleSpec`, or return
    ``(None, warnings, reason)`` when it is outside the subset.

    Back-compat: a plain ``GET`` method+path request with a body ``word`` matcher compiles to exactly
    the ``signature`` spec it did before this slice. Everything wider (status/regex/dsl/raw, multi-word
    and combined matchers) compiles to a ``nuclei_http`` spec carrying a declarative predicate."""
    is_raw = request.get("raw") is not None
    req_headers: tuple[tuple[str, str], ...] = ()
    req_body: str | None = None

    if is_raw:
        parsed = _parse_raw_request(request.get("raw"))
        if isinstance(parsed, str):
            return None, (), parsed
        method, probe_path, req_headers, req_body = parsed
    else:
        method = str(request.get("method") or "GET").upper()
        if method != "GET":
            return None, (), f"only GET templates are supported, got {method}"
        path_val = _first(request.get("path"))
        if not isinstance(path_val, str) or not path_val.strip():
            return None, (), "template has no usable single path"
        probe_path = _strip_base_url(path_val)
        if probe_path is None:
            return None, (), f"path carries interpolation beyond BaseURL: {path_val!r}"
        # Back-compat: the original simple case (a body word) stays a `signature` entry, unchanged.
        signature, sig_warnings = _extract_word_matcher(request)
        if signature:
            spec = OracleSpec(kind="signature", probe_path=probe_path, signature=signature, http_method="GET")
            return spec, tuple(sig_warnings), ""

    predicate, warnings, reason = _build_match_predicate(request)
    if predicate is None:
        return None, tuple(warnings), reason
    spec = OracleSpec(
        kind="nuclei_http",
        probe_path=probe_path,
        http_method=method,
        match_predicate=predicate,
        request_body=req_body,
        request_headers=list(req_headers) or None,
    )
    return spec, tuple(warnings), ""


# ---------------------------------------------------------------------------
# the compiler
# ---------------------------------------------------------------------------


def compile_nuclei_template(source: str | dict) -> CompiledTemplate:
    """Compile one Nuclei template (YAML text or an already-parsed dict) into a
    :class:`CompiledTemplate`.

    Compiles the supported matcher subset (see the module docstring) of an HTTP template (``http:`` or
    legacy ``requests:``) into a native :class:`~scanner.library.LibraryEntry` whose match CRUCIBLE's
    OWN oracle re-verifies over a real response. A multi-request template compiles its first
    self-contained, re-verifiable request. Anything outside the subset is returned as
    ``supported=False`` with a reason — it degrades cleanly, never guesses."""
    if isinstance(source, str):
        try:
            import yaml   # local import: pyyaml is a light dep, keep it off the module load path
            data = yaml.safe_load(source)
        except Exception as e:   # noqa: BLE001 - any YAML error is a clean "unparseable" outcome
            raise NucleiCompileError(f"could not parse nuclei template YAML: {e}") from e
    else:
        data = source
    if not isinstance(data, dict):
        raise NucleiCompileError("nuclei template must be a mapping (id/info/http)")

    template_id = str(data.get("id") or "").strip()
    if not template_id:
        raise NucleiCompileError("nuclei template is missing an 'id'")
    info = data.get("info") if isinstance(data.get("info"), dict) else {}

    def _unsupported(reason: str, warnings: tuple[str, ...] = ()) -> CompiledTemplate:
        return CompiledTemplate(template_id=template_id, supported=False, reason=reason, warnings=warnings)

    http = data.get("http")
    if http is None:
        http = data.get("requests")   # legacy key
    if not isinstance(http, list) or not http:
        return _unsupported("no http/requests block (only HTTP templates are supported)")

    # Multi-request: compile the FIRST self-contained, re-verifiable request. A request that fails to
    # compile (non-GET, computed path, no re-verifiable matcher, chained value) is skipped, not fatal.
    spec: OracleSpec | None = None
    warnings: tuple[str, ...] = ()
    reasons: list[str] = []
    fail_warnings: list[str] = []
    chosen_idx = 0
    for idx, request in enumerate(http):
        if not isinstance(request, dict):
            reasons.append("request is not a mapping")
            continue
        rspec, rwarnings, reason = _compile_request(request)
        if rspec is not None:
            spec, warnings, chosen_idx = rspec, rwarnings, idx
            break
        reasons.append(reason)
        fail_warnings.extend(rwarnings)

    if spec is None:
        # A single-request template reports its own reason (preserves the original messages); a
        # multi-request template reports each request's reason so the degrade is explainable. Any
        # warnings gathered while trying (e.g. "skipped a negative matcher") are retained.
        if len(reasons) == 1:
            return _unsupported(reasons[0], tuple(fail_warnings))
        return _unsupported("; ".join(f"req#{i + 1}: {r}" for i, r in enumerate(reasons)), tuple(fail_warnings))

    if len(http) > 1:
        warnings = warnings + (
            f"multi-request template: compiled request #{chosen_idx + 1} "
            f"(the first self-contained, re-verifiable one of {len(http)})",
        )

    severity = _SEVERITY_MAP.get(str(info.get("severity", "")).strip().lower(), "Info")
    bug_class = _bug_class_from_info(info)
    title = str(info.get("name") or template_id).strip() or template_id

    try:
        entry = LibraryEntry(
            id=f"nuclei-{template_id}",
            bug_class=bug_class,
            title=title,
            severity=severity,
            applies_when={"always": True},
            oracle=spec,
            references=_references(template_id, info),
            remediation=str(info.get("remediation") or ""),
            payload_family=f"nuclei:{template_id}",
        )
    except Exception as e:   # noqa: BLE001 - a schema rejection is a clean unsupported outcome, not a crash
        return _unsupported(f"compiled entry failed schema validation: {e}", warnings)

    return CompiledTemplate(template_id=template_id, supported=True, entry=entry, warnings=warnings)


def compile_nuclei_templates(sources: list[str | dict]) -> list[CompiledTemplate]:
    """Compile many templates, order-preserving. Each element is YAML text or a parsed dict. An
    individual unparseable template is captured as ``supported=False`` (it never sinks the batch)."""
    out: list[CompiledTemplate] = []
    for src in sources:
        try:
            out.append(compile_nuclei_template(src))
        except NucleiCompileError as e:
            out.append(CompiledTemplate(template_id="<unparseable>", supported=False, reason=str(e)))
    return out


def compile_nuclei_dir(directory: str | Path) -> list[CompiledTemplate]:
    """Compile every ``*.yaml`` / ``*.yml`` template under ``directory`` (sorted, deterministic). A
    file that cannot be read/parsed becomes a ``supported=False`` entry naming the file, never a crash.
    The entries are RETURNED, not written into the shipped library — the caller decides whether to run
    them (off by default)."""
    d = Path(directory)
    if not d.is_dir():
        raise NucleiCompileError(f"nuclei template directory not found: {directory}")
    results: list[CompiledTemplate] = []
    for f in sorted([*d.glob("*.yaml"), *d.glob("*.yml")]):
        try:
            results.append(compile_nuclei_template(f.read_text(encoding="utf-8")))
        except (OSError, NucleiCompileError) as e:
            results.append(CompiledTemplate(template_id=f.name, supported=False, reason=str(e)))
    return results


def compiled_entries(results: list[CompiledTemplate]) -> list[LibraryEntry]:
    """The successfully-compiled :class:`~scanner.library.LibraryEntry` objects from a batch — the
    subset an operator would hand to a campaign as ``library_entries``."""
    return [r.entry for r in results if r.supported and r.entry is not None]
