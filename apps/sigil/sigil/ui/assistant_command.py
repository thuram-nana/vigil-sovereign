"""assistant_command - the DETERMINISTIC, model-free command interpreter for the chat engagement box (B2).

One box, one typed customer line. This module turns that line into a structured ``{intent, host?, depth?, text?}``
over a CLOSED allowlist of verbs (verify / launch / status / steer / pause / resume / cancel / advice) WITHOUT a
model. :func:`classify` is the ONLY path from the box to an engagement ACTION, and it is pure text classification:
it calls no mint primitive, launches nothing, reserves nothing and holds no key.

This is the security boundary that makes the box un-prompt-injectable into launching. The MODEL (the grounded,
read-only ``customer_assistant_ask``) is reached ONLY on the ``advice`` intent, which takes no action and mints
nothing; and a line that is not an UNAMBIGUOUS allowlisted command FALLS BACK to advice (read-only). So no amount
of hostile phrasing fed to the model, and no clever wording in the box, can make the deterministic layer emit a
launch / verify / control intent it did not recognise from an explicit LEADING verb. On top of the intent the
provisioner still requires an explicit authorization affirmation before any verify mints an authority and an
explicit spend confirm before any launch reserves credits (``engagement_flow`` / ``customer_flow_step``) - the
classifier only NAMES the intent; it never authorizes or performs the act.

FATAL-2: sovereign-only, pure-stdlib, ``assert_no_offense`` at import. No offense import, no mint, no I/O.
"""
from __future__ import annotations

import re

from ..reuse import assert_no_offense

assert_no_offense()

#: The CLOSED allowlist of intents the box may express. Everything else - and anything ambiguous - is ``advice``.
INTENTS = ("verify", "launch", "status", "steer", "pause", "resume", "cancel", "advice")

#: The longest line the classifier reads (the grounded assistant caps the question separately; this just bounds work).
MAX_LINE_CHARS = 2000

# Lead-verb lexicons. An ACTION intent is recognised ONLY from an explicit LEADING verb (the first meaningful token
# after any polite wrapper), so an ordinary question never classifies as an action. Each set is small and curated.
_VERIFY_VERBS = frozenset({"verify", "prove", "register", "add"})
_LAUNCH_VERBS = frozenset({"launch", "scan", "assess", "pentest", "engage", "run", "start", "test", "attack",
                           "probe"})
_STATUS_VERBS = frozenset({"status", "progress", "activity", "watch", "watching"})
_STEER_VERBS = frozenset({"steer", "focus", "prioritise", "prioritize", "concentrate"})
_PAUSE_VERBS = frozenset({"pause", "hold", "suspend"})
_RESUME_VERBS = frozenset({"resume", "unpause", "continue"})
_CANCEL_VERBS = frozenset({"cancel", "abort", "kill", "stop"})

# Polite filler stripped from the FRONT so the head verb is found (politeness carries no intent).
_FILLER = frozenset({"please", "pls", "hey", "hi", "hello", "yo", "ok", "okay", "vigil", "just", "now", "kindly",
                     "so", "well", "um"})
# A polite command wrapper ("can you ...", "could you ...", "let's ...") is stripped before the head is read.
_WRAP_LEAD = frozenset({"can", "could", "would", "will", "please"})
_WRAP_SUBJECT = frozenset({"you", "we", "u"})

# Depth words → the canonical depth the server's launch products name (a depth, never an amount).
_DEPTH = {
    "quick": "quick", "fast": "quick", "light": "quick", "shallow": "quick",
    "standard": "standard", "normal": "standard", "default": "standard", "medium": "standard",
    "deep": "deep", "thorough": "deep", "full": "deep", "comprehensive": "deep", "complete": "deep",
}

# A conservative dotted-DNS matcher: at least one label + a dot + a 2..63 alpha TLD. "e.g" / "i.e" never match
# (1-char TLD), so prose abbreviations are not mistaken for a host. The label-group repetition is POSSESSIVE
# (``)++``): on untrusted box input like "0.0.0.0...0" (many "label." with no alpha TLD) a backtracking "+" would
# re-try every label when the trailing TLD fails -> polynomial ReDoS; the possessive form matches a valid host
# identically (labels are dot-terminated, the TLD is not) but refuses to backtrack into the labels, so a failing
# match aborts in one linear pass. ``_extract_host`` also caps the token length as defence in depth.
_HOST_RE = re.compile(r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)++[a-z]{2,63})")


def _head_index(words: "list[str]") -> int:
    """The index of the first MEANINGFUL token - past any polite filler and a polite command wrapper
    (``can/could/would/will/please`` + ``you/we/u``, or ``let('s)/let us``). Returns ``len(words)`` when the line
    is only filler."""
    i = 0
    n = len(words)
    while i < n:
        w = words[i]
        if w in _FILLER or w in _DEPTH:        # a leading depth adjective ("quick scan ...") precedes the verb
            i += 1
            continue
        if w in _WRAP_LEAD and i + 1 < n and words[i + 1] in _WRAP_SUBJECT:
            i += 2
            continue
        if w in ("lets", "let"):
            i += 1
            if i < n and words[i] == "us":
                i += 1
            continue
        break
    return i


def _extract_host(text: str) -> str:
    """The first domain-like token in ``text`` (scheme / path / query / userinfo / port stripped), lowercased, or
    ``""``. A pure, conservative match - it never resolves, fetches or validates ownership; it only lifts a host
    the later tenant-scoped reads will check against the org's own proven set."""
    for tok in re.split(r"\s+", text.strip().lower()):
        t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", tok)   # scheme
        t = t.split("/", 1)[0].split("?", 1)[0]          # path / query
        t = t.split("@")[-1]                             # userinfo
        t = t.split(":", 1)[0]                           # port
        t = t.strip(".,;!()[]{}<>\"'`")
        if len(t) > 253:                                 # a hostname is at most 253 chars; skip pathological input
            continue
        m = _HOST_RE.fullmatch(t) or _HOST_RE.search(t)
        if m:
            return m.group(1)
    return ""


def _extract_depth(words: "list[str]") -> str:
    for w in words:
        if w in _DEPTH:
            return _DEPTH[w]
    return ""


def _intent_of(head: str) -> str:
    if head in _VERIFY_VERBS:
        return "verify"
    if head in _LAUNCH_VERBS:
        return "launch"
    if head in _STATUS_VERBS:
        return "status"
    if head in _STEER_VERBS:
        return "steer"
    if head in _PAUSE_VERBS:
        return "pause"
    if head in _RESUME_VERBS:
        return "resume"
    if head in _CANCEL_VERBS:
        return "cancel"
    return "advice"


def _steer_text(text: str) -> str:
    """The advisory instruction for the engine: the line with a pure ``steer`` command marker stripped from the
    front (``steer: focus on auth`` → ``focus on auth``); a natural lead like ``focus on auth`` is kept verbatim.
    The engine bounds and sanitises it (advisory-only); this is only a tidy-up."""
    return re.sub(r"^\s*steer\b[\s:,-]*", "", text.strip(), count=1, flags=re.IGNORECASE).strip() or text.strip()


def classify(line: str) -> dict:
    """Classify ONE typed box line into ``{intent, host?, depth?, text?}`` over the CLOSED verb allowlist
    (:data:`INTENTS`). PURE and model-free. The intent is read from an explicit LEADING verb after any polite
    wrapper; anything unrecognised (and the empty line) is ``advice`` - the read-only path. ``host`` (a domain-like
    token) and ``depth`` (quick / standard / deep) are lifted when present; ``text`` carries the steer instruction
    or, for advice, the whole question to hand to the grounded assistant. It NEVER returns a launch/verify/control
    intent for a line whose head is not an allowlisted action verb, and it NEVER itself acts."""
    text = (line or "").strip()[:MAX_LINE_CHARS]
    if not text:
        return {"intent": "advice", "text": ""}
    words = re.findall(r"[a-z]+", text.lower())
    hi = _head_index(words)
    head = words[hi] if hi < len(words) else ""
    intent = _intent_of(head)

    out: "dict[str, str]" = {"intent": intent}
    if intent == "advice":
        out["text"] = text                       # the whole question → the grounded, read-only assistant
        return out
    host = _extract_host(text)
    if host:
        out["host"] = host
    if intent == "launch":
        depth = _extract_depth(words)
        if depth:
            out["depth"] = depth
    if intent == "steer":
        out["text"] = _steer_text(text)
    return out
