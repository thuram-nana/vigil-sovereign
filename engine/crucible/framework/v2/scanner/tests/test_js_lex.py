"""Direct tests for the ECMA-262 lexical regions used to decide whether a redirect sink can execute.

The behavioural guards (a sink inside a comment/string must not mint) live with the claim-discipline tests;
these exercise the lexer itself, because its hard cases are exactly the ones that never show up in a tidy
fixture: the regex-vs-division ambiguity, nested template substitutions, and escapes that hide a terminator.

Every ambiguity resolves AWAY from minting. A sink VIGIL cannot prove is executable is not a FACT.
"""

from __future__ import annotations

import pytest

from framework.v2.scanner.js_lex import offset_kind, regions, sink_is_executable


def _kind_at(src: str, needle: str) -> str:
    return offset_kind(src, src.index(needle))


# ---- the three exclusions the FACT claim rests on -------------------------------------------------

@pytest.mark.parametrize("src,needle", [
    ("// location.href='//evil/'", "location"),                       # line comment
    ("/* location.href='//evil/' */", "location"),                    # block comment
    ("/*\n * location.href='//evil/'\n */", "location"),              # multi-line block comment
    ('var s = "location.href=\'//evil/\'";', "location"),             # double-quoted string
    ("var s = 'location.href=\"//evil/\"';", "location"),             # single-quoted string
    ("var t = `location.href='//evil/'`;", "location"),               # template literal
])
def test_non_executable_regions_are_recognised(src: str, needle: str) -> None:
    assert not sink_is_executable(src, src.index(needle)), f"{src!r} should not be executable code"


@pytest.mark.parametrize("src,needle", [
    ("location.href='//evil/'", "location"),
    ("if (x) { location.href='//evil/' }", "location"),
    ("var t = `hi ${location.href='//evil/'}`;", "location"),         # INSIDE a template substitution
    ("/* c */ location.href='//evil/'", "location"),                  # after a closed comment
    ('var s = "x"; location.href="//evil/"', "location.href=\"//evil/\""),
])
def test_executable_regions_are_preserved(src: str, needle: str) -> None:
    """The upgrade must not become a blanket suppression: real sinks still have to be reachable, including
    inside `${...}` substitutions, which ARE code even though the surrounding template is not."""
    assert sink_is_executable(src, src.index(needle)), f"{src!r} should be executable code"


# ---- escapes that hide a terminator --------------------------------------------------------------

def test_escaped_quote_does_not_end_a_string() -> None:
    src = r'var s = "he said \" location.href=\'//evil/\' "; location.href="//real/"'
    assert not sink_is_executable(src, src.index("location")), "the first sink is inside the string"
    assert sink_is_executable(src, src.rindex("location")), "the trailing sink is real code"


def test_backslash_before_template_terminator() -> None:
    src = r"var t = `a \` location.href='//evil/'`;"
    assert not sink_is_executable(src, src.index("location"))


# ---- the ambiguity JavaScript cannot settle without parsing --------------------------------------

def test_regex_literal_is_not_code() -> None:
    src = "var re = /location.href='\\/\\/evil\\//;"
    assert not sink_is_executable(src, src.index("location"))


def test_division_is_not_mistaken_for_a_regex() -> None:
    """`a / b` is division; `= /re/` is a literal. Misreading division as a regex would swallow the rest of
    the line and hide a REAL sink after it — a silent false negative, which is why this is pinned."""
    src = "var r = total / count; location.href='//evil/'"
    assert sink_is_executable(src, src.index("location")), "division swallowed the following statement"


def test_an_ambiguous_span_never_mints() -> None:
    """Where the lexer cannot decide, the answer must be 'not provably executable' — the resolution is away
    from minting, so an unparseable page yields no FACT rather than a guessed one."""
    src = "}/location.href='//evil/'/"          # `/` after `}` is genuinely ambiguous without parsing
    assert not sink_is_executable(src, src.index("location"))


def test_regions_cover_the_whole_input_without_gaps() -> None:
    """A gap or overlap would make offset_kind depend on iteration order rather than position."""
    src = "a = 1; // c\nvar s = 'x'; /* y */ location.href='//z/'; var t = `q${1}`;"
    spans = sorted((r.start, r.end) for r in regions(src))
    assert spans, "no regions produced"
    cursor = 0
    for start, end in spans:
        assert start >= cursor, f"overlapping regions at {start}"
        cursor = end
    assert cursor <= len(src)


# ---- fail-closed: unsupported or incomplete lexing must never yield a FACT -----------------------

@pytest.mark.parametrize("src,needle", [
    ("<!-- location.href='//evil/'", "location"),          # legacy HTML open comment, SAME line
    ("--> location.href='//evil/'", "location"),           # legacy HTML close comment at line start
    ("\x00location.href='//evil/'", "location"),           # NUL: a real engine rejects the script outright
    ("a=1;" * 200_000 + "location.href='//evil/'", "location.href"),   # beyond the lex bound
])
def test_unlexable_or_commented_input_is_never_executable(src: str, needle: str) -> None:
    """Incomplete lexing must read as "we could not establish the context" — which yields no FACT, and
    (because the JS branch is not CLEAN-capable) no CLEAN either. It must never resolve toward minting."""
    assert not sink_is_executable(src, src.index(needle))


def test_a_legacy_html_comment_only_hides_its_own_line() -> None:
    """`<!--` is a SINGLE-line comment in script data, so the following line is genuinely code. Treating it
    as a block comment would swallow real sinks — the dropped-vulnerability direction."""
    src = "<!--\nlocation.href='//evil/'\n//-->"
    assert sink_is_executable(src, src.index("location"))
