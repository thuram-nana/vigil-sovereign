"""input_safety - a shared, deterministic TEXT INPUT sanitizer for the customer assistant / command plane.

A customer types or pastes ONE line into the chat engagement box (and, on the advice path, a free-text question; on
the flow path, a ``host`` / ``text``). A pasted STRING cannot execute - this is NOT about running code - but hostile
text can still:

  * **spoof the rendered transcript and dodge the deterministic classifier** with zero-width joiners inside a verb
    (``ve<zwj>rify``) or bidi overrides that reorder what a human sees away from the logical bytes that are stored
    and classified;
  * **smuggle control characters** (NUL, C0/C1) into fields that are stored, echoed back, or logged (stored /
    reflected injection, broken transcripts);
  * **blow up resource / model cost** with an oversized paste.

:func:`sanitize_input` turns any untrusted input into INERT, DISPLAY-SAFE, CLASSIFIER-STABLE text BEFORE it is
classified, stored, echoed, or handed to the grounded model. It is the server-authoritative input-hardening boundary
for the chat plane - the server never trusts the client to have cleaned the paste.

It is PURE stdlib (``unicodedata`` only), DETERMINISTIC, and makes NO network / model / I/O call: the same input
always yields the same output. For ordinary text (no obfuscation, within the cap) it is a NO-OP, so a normal command
or question still classifies exactly as the raw line did (honest behaviour - the hardening is invisible to a real
customer and only bites on a hostile paste).

It deliberately does NOT fold homoglyphs (a Cyrillic ``а`` is not rewritten to a Latin ``a``): NFC is a lossless
canonicalization, whereas a homoglyph map is lossy and locale-hostile. The deterministic classifier only ever matches
ASCII ``[a-z]`` verbs, so a homoglyph in a verb simply fails to match and FALLS BACK to advice (the read-only path) -
the safe direction - without this module having to guess intent.

FATAL-2: sovereign-only, pure-stdlib, ``assert_no_offense`` at import. No offense import, no mint, no I/O.
"""
from __future__ import annotations

import unicodedata

from ..reuse import assert_no_offense

assert_no_offense()

__all__ = ["sanitize_input"]

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
        if unicodedata.category(ch) == "Cf":          # the whole invisible-format class (Tag chars, word joiner, ...)
            continue
        out.append(ch)
    # Re-normalize after stripping: a removed zero-width separator can leave a base character adjacent to a combining
    # mark, and the second NFC pass composes them so the result is the canonical (precomposed) form, not a decomposed
    # look-alike. Truncation is still applied LAST so neither NFC pass can exceed the cap.
    cleaned = unicodedata.normalize("NFC", "".join(out))
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars]
    return cleaned
