"""js_lex — split JavaScript source into CODE and NON-CODE regions, so a navigation sink found in a comment
or a string is not mistaken for one the engine would execute.

Why this exists: the redirect sink was matched by a regex over raw script text, so
``// location.href="//evil/"`` — a commented-out line that never runs — matched exactly like the real thing.
That is a false-FACT surface, and the branch was quarantined LEAD-only because of it.

Why this is not the "hand-approximated a specification" trap again (CLAIM-DISCIPLINE rule 4): no JavaScript
parser is available offline, so the alternative the rule permits applies — implement the specified lexical
grammar literally. The scope is deliberately tiny: this classifies regions, it does not parse expressions,
build an AST, or evaluate anything.

And the design is **sound by construction rather than by my confidence in it**. The one genuinely ambiguous
lexical decision in JavaScript — whether ``/`` begins a regular-expression literal or is a division operator
— cannot be settled without parsing. So this lexer never guesses in the direction that could mint a false
FACT: where the decision is ambiguous the span is marked ``ambiguous``, and the caller must treat a sink
found there as a LEAD. A sink in a region proven to be code may mint; a sink anywhere else may not.

Regions returned by :func:`regions` tile the input exactly (``"".join(text[s:e]) == text``), which is the
invariant that makes a classification error visible rather than silent.
"""

from __future__ import annotations

from dataclasses import dataclass

CODE = "code"
COMMENT = "comment"
STRING = "string"
TEMPLATE = "template"
AMBIGUOUS = "ambiguous"      # possibly a regex literal — never allowed to mint

# After these tokens a `/` unambiguously starts a REGEX literal (an operand may not follow them), per the
# ECMA-262 lexical-goal rules. After an identifier, number, `)` or `]` a `/` is division — except that
# `)` and `]` are only division when the bracket closed an expression, which needs parsing. Those cases are
# reported AMBIGUOUS rather than guessed.
_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%~^<>")
# After any of these a `/` begins a REGEX literal, never division — either the keyword expects an operand to
# follow (`return`/`typeof`/…/`case`, `extends`, and `default` in `export default <expr>`) or it ends a
# statement so the `/` starts a NEW expression statement (`break`/`continue`/`debugger`). Value-producing
# keywords (`this`, `super`, `true`, `false`, `null`) are DELIBERATELY ABSENT: a `/` after them is division.
# This set must be COMPLETE for every reserved word that can be immediately followed by `/` in valid JS —
# a missing operand keyword lets a sink inside a regex literal lex as executable and mint a false, signed
# js_sink FACT (red-pen FINDING 1: `export default`/`extends`/`debugger` were missing). Reserved words that
# are always followed by `(` or an identifier (if/for/while/switch/catch/function/class/const/var/let/import/
# export/try/finally) can never precede a `/`, so they are omitted rather than listed for show.
_REGEX_KEYWORDS = ("return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
                   "case", "do", "else", "yield", "await",
                   "break", "continue", "debugger", "default", "extends")


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    kind: str

    @property
    def is_code(self) -> bool:
        return self.kind == CODE


def _prev_significant(text: str, i: int) -> str:
    """The last non-whitespace character before ``i``, or '' at the start of input."""
    k = i - 1
    while k >= 0 and text[k] in " \t\r\n":
        k -= 1
    return text[k] if k >= 0 else ""


def _preceded_by_keyword(text: str, i: int) -> bool:
    head = text[:i].rstrip()
    return any(head.endswith(word) and (len(head) == len(word) or not (head[-len(word) - 1].isalnum()
               or head[-len(word) - 1] in "_$")) for word in _REGEX_KEYWORDS)


def _string_end(text: str, i: int, quote: str) -> int:
    """Index just past the closing quote, honouring backslash escapes; unterminated runs to end of input."""
    k = i + 1
    n = len(text)
    while k < n:
        c = text[k]
        if c == "\\":
            k += 2
            continue
        if c == quote:
            return k + 1
        k += 1
    return n


def _template_end(text: str, i: int) -> int:
    """Index just past the closing backtick, skipping over ``${ ... }`` substitutions.

    The substitutions themselves are CODE and are classified separately by :func:`regions` — swallowing them
    into the template span would hide a real sink inside `${...}`, which is a dropped vulnerability, not a
    safe under-claim."""
    k = i + 1
    n = len(text)
    depth = 0
    while k < n:
        c = text[k]
        if c == "\\":
            k += 2
            continue
        if c == "$" and k + 1 < n and text[k + 1] == "{":
            depth += 1
            k += 2
            continue
        if c == "}" and depth:
            depth -= 1
            k += 1
            continue
        if c == "`" and not depth:
            return k + 1
        k += 1
    return n


def _template_regions(text: str, start: int, end: int) -> "list[Region]":
    """Split a template literal into TEMPLATE text and the CODE inside its ``${ ... }`` substitutions."""
    out: "list[Region]" = []
    k = start
    literal_from = start
    while k < end:
        if text[k] == "\\":
            k += 2
            continue
        if text[k] == "$" and k + 1 < end and text[k + 1] == "{":
            depth, j = 1, k + 2
            while j < end and depth:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            if k > literal_from:
                out.append(Region(literal_from, k + 2, TEMPLATE))
            inner_start, inner_end = k + 2, max(k + 2, j - 1)
            # Recurse: a substitution can itself contain strings, comments and nested templates.
            for region in regions(text[inner_start:inner_end]):
                out.append(Region(region.start + inner_start, region.end + inner_start, region.kind))
            out.append(Region(inner_end, min(j, end), TEMPLATE))
            k = literal_from = j
            continue
        k += 1
    if literal_from < end:
        out.append(Region(literal_from, end, TEMPLATE))
    return out


def _regex_end(text: str, i: int) -> int:
    """Index just past a regular-expression literal's closing ``/``, honouring escapes and ``[...]`` classes
    (a ``/`` inside a character class does not terminate the literal). A literal cannot span a newline, so an
    unterminated one ends at the line break — that is what a JS engine does too."""
    k = i + 1
    n = len(text)
    in_class = False
    while k < n:
        c = text[k]
        if c == "\\":
            k += 2
            continue
        if c == "\n":
            return k
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            return k + 1
        k += 1
    return n


# Beyond this, or on input we cannot lex at all, the lexer FAILS CLOSED: the whole text becomes AMBIGUOUS,
# so no sink inside it is ever "provably executable" and no FACT can be minted from it. Incomplete lexing
# must read as "we could not establish the context", never as evidence in either direction.
MAX_LEX_BYTES = 512_000


def regions(text: str) -> "list[Region]":
    """Classify ``text`` into CODE / COMMENT / STRING / TEMPLATE / AMBIGUOUS spans that tile the input.

    Fails closed on input it cannot faithfully lex — oversized script data, or text containing NUL, which a
    real engine rejects outright (nothing in such a script executes, so nothing in it is a sink)."""
    n = len(text)
    if n > MAX_LEX_BYTES or "\x00" in text:
        return [Region(0, n, AMBIGUOUS)] if n else []
    out: "list[Region]" = []
    i = 0
    code_start = 0

    def close_code(upto: int) -> None:
        if upto > code_start:
            out.append(Region(code_start, upto, CODE))

    while i < n:
        c = text[i]
        # Legacy HTML-like comments are SINGLE-LINE comments in script data (Annex B): `<!--` comments to
        # end of line anywhere, and `-->` does so at the start of a line. A sink after either on the SAME
        # line never runs, so counting it was a false-FACT surface.
        if c == "<" and text.startswith("<!--", i):
            close_code(i)
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(Region(i, end, COMMENT))
            i = code_start = end
            continue
        if c == "-" and text.startswith("-->", i) and not text[:i].rsplit("\n", 1)[-1].strip():
            close_code(i)
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(Region(i, end, COMMENT))
            i = code_start = end
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            close_code(i)
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(Region(i, end, COMMENT))
            i = code_start = end
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            close_code(i)
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append(Region(i, end, COMMENT))
            i = code_start = end
            continue
        if c in "'\"":
            close_code(i)
            end = _string_end(text, i, c)
            out.append(Region(i, end, STRING))
            i = code_start = end
            continue
        if c == "`":
            close_code(i)
            end = _template_end(text, i)
            # A template is literal TEXT interleaved with `${...}` CODE. Classify each part for what it is:
            # a sink in the text cannot run, a sink in a substitution can.
            out.extend(_template_regions(text, i, end))
            i = code_start = end
            continue
        if c == "/":
            prev = _prev_significant(text, i)
            if prev in _REGEX_PRECEDERS or prev == "" or _preceded_by_keyword(text, i):
                close_code(i)                      # unambiguously a regex literal
                end = _regex_end(text, i)
                out.append(Region(i, end, STRING))
                i = code_start = end
                continue
            if prev == "]" or prev.isalnum() or prev in "_$":
                # After a VALUE (identifier, number, `]`) a `/` is DIVISION — the standard previous-token
                # rule, and not ambiguous: `]` always ends an array literal or index (a value), never a
                # control head, so there is no `]`-then-regex construct. `)` is DIFFERENT — see below.
                i += 1
                continue
            if prev == ")":
                # `)` alone is genuinely undecidable without parsing: it ends an `if (...)`/`while (...)` head
                # (so `/` starts a regex) OR a grouping/call value (so `/` is division). Mark AMBIGUOUS — a
                # sink in a span VIGIL cannot classify must never mint a FACT; now that js_sink is
                # FACT-capable this resolves away from minting, at the cost of an under-claim on the contrived
                # `(a)/b; location.href=...`-on-one-line shape. (`}` is NOT handled here: it is in
                # _REGEX_PRECEDERS above, so a `/` after it is treated as a regex literal (STRING) — a `/`
                # after a block is a regex, and treating the rare object-literal division `({}/2)` as a regex
                # only ever under-claims, never mints. It never reaches this branch.)
                end = _regex_end(text, i)
                if end > i + 1 and "\n" not in text[i:end]:
                    close_code(i)
                    out.append(Region(i, end, AMBIGUOUS))
                    i = code_start = end
                    continue
        i += 1
    close_code(n)
    return out


def code_spans(text: str) -> "list[tuple[int, int]]":
    """Only the spans proven to be executable code — the sole place a sink may mint a FACT."""
    return [(r.start, r.end) for r in regions(text) if r.is_code]


def offset_kind(text: str, offset: int) -> str:
    """The region kind containing ``offset``.

    This — not blanking — is how a caller decides whether a sink is real, because a navigation sink SPANS
    both kinds by nature: in ``location.href="//evil/"`` the assignment is code and the URL is a string
    literal. Blanking strings would erase the URL and destroy every genuine sink. What distinguishes a real
    sink from a quoted or commented one is where the expression BEGINS, so callers test the match's start
    offset."""
    for region in regions(text):
        if region.start <= offset < region.end:
            return region.kind
    return CODE


def sink_is_executable(text: str, offset: int) -> bool:
    """Whether a sink beginning at ``offset`` is in executable code — the precondition for minting.

    False for a sink inside a comment, a string, a template literal, or an AMBIGUOUS ``/``-span, all of
    which the engine would never execute (or which cannot be shown to execute without parsing)."""
    return offset_kind(text, offset) == CODE
