"""input_safety — the ONE central input-sanitization pass at the request trust boundary (every customer POST).

Both keyless edges (``custui`` and ``pubui``) read a JSON body once, at a single choke point (``custui._read_body``
/ ``pubui._parse_access_fields``). This module is applied THERE, so EVERY user-input field is tightened the same way
— no field-by-field drift, no field left behind. It does two things, deterministically and with no network:

  * ``sanitize_text`` — NFC-normalise a string, strip the genuinely-dangerous character classes (NUL + all C0/C1
    control characters except ordinary whitespace, the zero-width characters, and the bidirectional controls /
    overrides that drive Trojan-Source / homoglyph-direction attacks), and hard-truncate to a generous char cap. A
    normal email / host / name / question is returned UNCHANGED except for those dangerous characters — its semantics
    are preserved (per-field length / format validation stays in the downstream validators).

  * ``sanitize_body`` — walk a parsed-JSON structure and apply ``sanitize_text`` to every STRING value, with two
    hard guarantees: (1) a dict value whose KEY is in ``passthrough`` is left BYTE-EXACT (never descended into, never
    altered) — this is how credentials / tokens / WebAuthn blobs / base64 payloads survive untouched so authentication
    is never corrupted; (2) a JSON-bomb (deeply nested, or a huge object / array) is rejected with a clean ``ValueError``
    BEFORE it is processed, bounding both recursion depth and total node count — an anti-abuse guard that also keeps
    this module's own recursion within a tiny, fixed budget (it never follows a structure deeper than ``max_depth``).

Non-string scalars (int / float / bool / None) pass through unchanged. Pure stdlib + ``unicodedata`` only — no
framework / strix import (FATAL-2), so the keyless edge can never pull an offense dependency across the boundary.

  * ``sanitize_input`` — the chat-engagement / command-plane variant. It strips the SAME dangerous classes as
    ``sanitize_text`` but carries a DIFFERENT, caller-friendly contract that its own callers (``assistant`` /
    ``assistant_command`` / ``provision``'s flow + advice hops) and tests rely on: it COERCES its argument (``None`` ->
    ``""``, never a ``TypeError``) so a missing box field is simply empty, and it VALIDATES ``max_chars`` (a bad cap —
    negative, ``bool``, non-``int`` — raises a clean ``ValueError`` at the call site rather than mangling the slice).
    It is kept as a dedicated function (not an alias of ``sanitize_text``) precisely because those two contract points
    differ; the character-stripping behaviour is otherwise identical and equally deterministic / network-free.
"""
from __future__ import annotations

import unicodedata
from typing import Any

from ..reuse import assert_no_offense

assert_no_offense()

__all__ = ["sanitize_text", "sanitize_body", "sanitize_input"]

#: Whitespace that is always kept even though it is a C0 control character (``unicodedata`` category ``Cc``): the
#: ordinary tab / newline / carriage-return. A plain space (U+0020) is category ``Zs``, not a control, so it is never
#: a candidate for removal and is not listed here.
_KEEP_WHITESPACE = frozenset("\t\n\r")

#: Code points removed outright regardless of their Unicode category — the invisible / direction-steering classes that
#: carry no legitimate text meaning in a form field but drive obfuscation (homoglyph padding) and Trojan-Source
#: (bidirectional reordering) attacks:
#:   * zero-width:        U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF ZWNBSP / BOM
#:   * bidi embeddings / overrides: U+202A..U+202E (LRE RLE PDF LRO RLO)
#:   * bidi isolates:     U+2066..U+2069 (LRI RLI FSI PDI)
#:   * bidi marks:        U+200E LRM, U+200F RLM
_REMOVE_CODEPOINTS = frozenset(
    {0x200B, 0x200C, 0x200D, 0xFEFF}                      # zero-width
    | set(range(0x202A, 0x202E + 1))                      # LRE RLE PDF LRO RLO
    | set(range(0x2066, 0x2069 + 1))                      # LRI RLI FSI PDI
    | {0x200E, 0x200F}                                    # LRM RLM
)

#: Unicode general categories stripped wholesale (never a legitimate character in a form field):
#:   * ``Cc`` — control characters: NUL, the rest of C0, DEL (U+007F), all of C1 (U+0080..U+009F).
#:   * ``Cf`` — FORMAT characters: the entire invisible-format class, not just the explicit set above. This is what
#:     closes the Trojan-Source / invisible-prompt-injection surface: it also removes the Tag block
#:     (U+E0000..U+E007F, used to smuggle an invisible instruction into free text an LLM later reads), WORD JOINER
#:     (U+2060), the invisible math operators (U+2061..U+2064), SOFT HYPHEN (U+00AD), the interlinear-annotation
#:     anchors (U+FFF9..U+FFFB) and the Arabic/other format controls. The ordinary whitespace in ``_KEEP_WHITESPACE``
#:     is category ``Cc`` but is restored by an explicit earlier check, so it survives this sweep.
_REMOVE_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})   # Cc controls + Cf invisible-format + Cs lone surrogates


def sanitize_text(s: str, *, max_chars: int) -> str:
    """Return ``s`` NFC-normalised, with dangerous characters removed and hard-truncated to ``max_chars``.

    Deterministic and network-free. Removes, in this order of consideration: the explicit invisible / bidirectional
    code points in ``_REMOVE_CODEPOINTS``; then every character whose Unicode general category is in
    ``_REMOVE_CATEGORIES`` (``Cc`` control characters AND the whole ``Cf`` invisible-format class — Tag characters,
    word joiner, soft hyphen, interlinear-annotation anchors, Arabic format controls, ...) EXCEPT the ordinary
    whitespace in ``_KEEP_WHITESPACE`` (``\\t`` ``\\n`` ``\\r``; a plain space is category ``Zs`` and is always kept).
    The result is then NFC-normalised AGAIN: stripping a zero-width separator can leave a base character adjacent to a
    combining mark, and the second pass composes them so the return value genuinely honours the NFC contract (no
    decomposed look-alike of a precomposed value survives). Truncation is applied LAST, on code points (Python ``str``
    holds no surrogate pairs), so the result is never longer than ``max_chars`` and neither NFC pass can re-expand it.

    A non-``str`` argument is a programming error at the call site (``sanitize_body`` only ever passes ``str`` here)
    and raises ``TypeError`` rather than silently coercing.
    """
    if not isinstance(s, str):
        raise TypeError("sanitize_text expects a str")
    s = unicodedata.normalize("NFC", s)
    out: list[str] = []
    for ch in s:
        if ord(ch) in _REMOVE_CODEPOINTS:
            continue
        if ch in _KEEP_WHITESPACE:
            out.append(ch)
            continue
        if unicodedata.category(ch) in _REMOVE_CATEGORIES:   # Cc (controls) + Cf (invisible format incl. Tag chars)
            continue
        out.append(ch)
    # Re-normalise after stripping so a base + combining-mark pair left adjacent by a removed zero-width separator is
    # composed; this is what makes the NFC contract (and the no-decomposed-look-alike guarantee) actually hold.
    result = unicodedata.normalize("NFC", "".join(out))
    if len(result) > max_chars:
        result = result[:max_chars]
    return result


def sanitize_body(obj: Any, *, passthrough: "frozenset[str]", max_chars: int, max_depth: int, max_nodes: int) -> Any:
    """Recursively sanitize every STRING value in a parsed-JSON structure, returning the sanitized structure.

    Rules:
      * A ``dict`` value whose KEY is in ``passthrough`` is left **byte-exact** — not descended into, not altered.
        This is how credential / token / WebAuthn / base64 blobs survive the pass unchanged.
      * Every other ``str`` value is replaced by ``sanitize_text(value, max_chars=max_chars)``.
      * ``dict`` and ``list`` are rebuilt from their sanitized children (dict keys are preserved verbatim).
      * Non-``str`` scalars (``int`` / ``float`` / ``bool`` / ``None``) pass through unchanged.

    Anti-abuse guard (raised BEFORE the offending sub-structure is processed, so a JSON-bomb cannot hang the pass or
    overflow this function's own recursion):
      * nesting deeper than ``max_depth`` raises ``ValueError("request structure too deeply nested")``;
      * more than ``max_nodes`` total container/scalar nodes raises ``ValueError("request structure too large")``.
    A passthrough value is counted as a single node and never walked, so a bomb cannot hide inside a credential key.
    """
    counter = [0]

    def walk(value: Any, depth: int) -> Any:
        if depth > max_depth:
            raise ValueError("request structure too deeply nested")
        counter[0] += 1
        if counter[0] > max_nodes:
            raise ValueError("request structure too large")
        if isinstance(value, dict):
            result: dict[Any, Any] = {}
            for k, v in value.items():
                if isinstance(k, str) and k in passthrough:
                    result[k] = v                        # BYTE-EXACT: never descended into, never altered
                else:
                    result[k] = walk(v, depth + 1)
            return result
        if isinstance(value, list):
            return [walk(item, depth + 1) for item in value]
        if isinstance(value, str):
            return sanitize_text(value, max_chars=max_chars)
        return value                                     # int / float / bool / None — unchanged

    return walk(obj, 0)


# ===================================================================== the chat-engagement / command-plane variant ==
# A customer types or pastes ONE line into the chat engagement box (and, on the advice path, a free-text question; on
# the flow path, a ``host`` / ``text``). ``sanitize_input`` turns any untrusted input into INERT, DISPLAY-SAFE,
# CLASSIFIER-STABLE text BEFORE it is classified, stored, echoed, or handed to the grounded model. It strips the SAME
# dangerous classes as ``sanitize_text`` (zero-width + bidi + the whole Cc control and Cf invisible-format classes,
# bar ordinary whitespace) and re-NFCs + hard-truncates the same way; it is KEPT as a dedicated function (not an alias
# of ``sanitize_text``) because its CALLER CONTRACT differs: it COERCES (``None`` -> ``""``, never ``TypeError``) and
# VALIDATES ``max_chars`` (a bad cap raises ``ValueError``), which ``sanitize_text`` deliberately does not do. Its
# chat-plane callers (``assistant`` / ``assistant_command`` / ``provision``) and tests depend on that contract.

#: Ordinary whitespace that is KEPT: tab, newline, carriage-return, space. Every other C0/C1 control char (NUL
#: included) is removed. These four are the whitespace a human legitimately types or pastes; the rest only serve to
#: smuggle bytes into a stored/echoed field or to break a rendered transcript.
_KEEP_WS = frozenset("\t\n\r ")

#: Zero-width / join-format code points: they render as NOTHING but can split a verb (``ve<zwj>rify``) so the rendered
#: transcript and the classifier disagree on the word. Removed outright, which rejoins the surrounding characters
#: exactly as they already render to a human. Spelled as code points (``chr``) so the module source itself carries no
#: invisible character.
_ZERO_WIDTH = frozenset(chr(c) for c in (
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
))

#: Bidirectional controls, overrides and isolates: they reorder the RENDERED text away from the logical/stored order,
#: so a transcript can read one thing while the stored/classified bytes are another (bidi-override spoofing). Removed
#: outright so the stored order IS the rendered order. Spelled as code points for the same reason as above.
_BIDI = frozenset(chr(c) for c in (
    0x202A,  # LEFT-TO-RIGHT EMBEDDING
    0x202B,  # RIGHT-TO-LEFT EMBEDDING
    0x202C,  # POP DIRECTIONAL FORMATTING
    0x202D,  # LEFT-TO-RIGHT OVERRIDE
    0x202E,  # RIGHT-TO-LEFT OVERRIDE
    0x2066,  # LEFT-TO-RIGHT ISOLATE
    0x2067,  # RIGHT-TO-LEFT ISOLATE
    0x2068,  # FIRST STRONG ISOLATE
    0x2069,  # POP DIRECTIONAL ISOLATE
    0x200E,  # LEFT-TO-RIGHT MARK
    0x200F,  # RIGHT-TO-LEFT MARK
))

#: The union removed regardless of the control-char rule (these are >= U+0020, so the control test would miss them).
_STRIP = _ZERO_WIDTH | _BIDI


def _is_removable_control(ch: str) -> bool:
    """A C0 (U+0000-001F) or C1 (U+007F-009F) control character that is NOT ordinary whitespace - NUL included. The
    four ordinary-whitespace characters (tab/newline/carriage-return/space) are kept; everything else in those two
    ranges is removed."""
    if ch in _KEEP_WS:
        return False
    o = ord(ch)
    return o < 0x20 or 0x7F <= o <= 0x9F


def sanitize_input(s: object, *, max_chars: int) -> str:
    """Coerce ``s`` to INERT, display-safe, classifier-stable text and hard-truncate to ``max_chars``.

    Deterministic, pure-stdlib. In order it:

      1. coerces to ``str`` (``""`` for ``None``);
      2. NFC-normalizes, so a decomposed / compatibility sequence has ONE canonical form and the classifier and the
         rendered transcript agree on the SAME code points;
      3. removes zero-width characters (U+200B/200C/200D/FEFF) and bidi controls / overrides / isolates
         (U+202A-202E, U+2066-2069, U+200E/200F) - the characters that let a paste render one way and classify /
         store another;
      4. removes NUL and C0/C1 control characters EXCEPT ordinary whitespace (tab, newline, carriage-return, space);
      5. removes EVERY remaining Unicode ``Cf`` invisible-format character - the whole class, not just the explicit
         set above: the Tag block (U+E0000-E007F, which can smuggle a fully invisible instruction into text an LLM
         later reads), WORD JOINER (U+2060), SOFT HYPHEN (U+00AD), the invisible math operators and more;
      6. NFC-normalizes AGAIN (stripping a zero-width separator can leave a base + combining-mark pair adjacent, which
         the second pass composes so the NFC guarantee holds on the RESULT, not only the input);
      7. hard-truncates to ``max_chars`` (the resource / model-cost bound) - applied LAST, so neither the obfuscation
         strip nor the re-normalization ever leaves dangling bytes past the cap.

    The result contains no zero-width, bidi, NUL or other control character beyond ordinary whitespace, and is never
    longer than ``max_chars``. ``max_chars`` must be a non-negative ``int``. Surrounding-whitespace trimming is left
    to the caller (the deterministic classifier and ``valid_question`` ``.strip()`` after calling this), so this
    function makes no assumption about how the caller wants the edges treated."""
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars < 0:
        raise ValueError("max_chars must be a non-negative int")
    text = "" if s is None else str(s)
    text = unicodedata.normalize("NFC", text)
    out: "list[str]" = []
    for ch in text:
        if ch in _STRIP:
            continue
        if _is_removable_control(ch):
            continue
        if unicodedata.category(ch) in ("Cf", "Cs"):  # Cf: the whole invisible-format class (Tag chars, word
            # joiner, ...). Cs: lone surrogates (U+D800..U+DFFF) - never valid in well-formed text, pass NFC
            # unchanged, and would raise UnicodeEncodeError on a later ensure_ascii=False UTF-8 encode (a 500).
            continue
        out.append(ch)
    # Re-normalize after stripping: a removed zero-width separator can leave a base character adjacent to a combining
    # mark, and the second NFC pass composes them so the result is the canonical (precomposed) form, not a decomposed
    # look-alike. Truncation is still applied LAST so neither NFC pass can exceed the cap.
    cleaned = unicodedata.normalize("NFC", "".join(out))
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars]
    return cleaned
