"""The plain-English briefing must explain every agent and named capability the code contains.

WHY THIS TEST EXISTS. The briefing is the document a national agency reads to understand what this
system is. It grew to roughly 250,000 words covering the offensive engine in depth while the entire
sovereign half went undocumented — not by anyone's decision, but because nobody was counting. A
measured census found the web researcher, the sovereign graph, screen reading and point-at-a-URL
learning at ZERO mentions, and four more capabilities at one apiece.

Asserting completeness in prose does not keep it true. The moment someone adds an agent and forgets
the document, the same gap reopens silently — and a silent gap in THIS document is a reader being
told the system is smaller than it is. So the roster is read FROM THE CODE, and an entity nobody
documented fails the build with a message naming the file it was found in.

WHAT THIS TEST DOES NOT CLAIM. It cannot judge whether an explanation is any good. It checks that a
thing is named and discussed more than once, which is a floor, not a standard. A drive-by mention in
a table with no explanation anywhere is precisely the failure this catches, because that is the
failure that actually happened.

This test imports nothing from either trust domain — it only reads files — so it is safe in every
CI leg and cannot pull offensive modules into a sovereign process.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BRIEFING = REPO / "docs" / "plain-english"

# A single passing mention is what the original gap looked like: present in an index, explained
# nowhere. Two independent mentions is the floor for "the document actually covers this".
MIN_MENTIONS = 2


def _briefing_text() -> str:
    """Every authored chapter, concatenated.

    The assembled VIGIL-EXPLAINED.md is a build product of these files, so counting it too would
    double every number and let a single mention masquerade as two. The working directories are
    research scaffolding, not part of the document a reader receives.
    """
    parts = []
    for p in sorted(BRIEFING.glob("*.md")):
        if p.name == "VIGIL-EXPLAINED.md":
            continue
        parts.append(p.read_text(encoding="utf-8", errors="replace"))
    assert parts, f"no briefing chapters found under {BRIEFING}"
    return "\n\n".join(parts).lower()


def _count(haystack: str, phrases: list[str]) -> int:
    return sum(haystack.count(p.lower()) for p in phrases)


# --------------------------------------------------------------------------------------------
# Discovery — the roster comes from the code, never from a list maintained by hand here.
# --------------------------------------------------------------------------------------------

def _sovereign_agents() -> dict[str, Path]:
    """Every sovereign agent, found by its own declaration.

    An agent declares an identity (`name = "X"`) and a permanent ceiling on how dangerous an action
    it may ever take. Requiring BOTH is what makes this discovery honest: it finds the real actors
    and skips helper classes. It also settles a question the document got wrong once — the web
    researcher subclasses the research agent and carries ITS name, so it is that agent's web mode
    and not a separate one. Discovery reflects that automatically; a hand-written list did not.
    """
    found: dict[str, Path] = {}
    for py in sorted((REPO / "apps" / "sigil" / "sigil").rglob("*.py")):
        src = py.read_text(encoding="utf-8", errors="replace")
        if "ceiling = Tier." not in src:
            continue
        for m in re.finditer(r'^\s{4}name\s*=\s*"([A-Z][A-Z0-9_]+)"', src, re.M):
            found.setdefault(m.group(1), py)
    return found


def _offense_agents() -> dict[str, Path]:
    """Every offensive-side agent class, e.g. ReconAgent -> "recon"."""
    found: dict[str, Path] = {}
    d = REPO / "engine" / "crucible" / "framework" / "v2" / "agents"
    for py in sorted(d.glob("*_agent.py")):
        src = py.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"^class (\w+)Agent\(Agent\):", src, re.M):
            found.setdefault(m.group(1), py)
    return found


# Plain English is the whole point of this document, so it does not print code identifiers. Each
# entity therefore maps to the words a reader would actually meet. An entity with NO entry here and
# no mention under its own name fails — which is the trigger that catches a newly added agent.
OFFENSE_ALIASES: dict[str, list[str]] = {
    "Recon": ["reconnaissance agent", "recon agent", "mapping agent"],
    "Hypothesis": ["hypothesis agent", "hypothesis-forming"],
    "Exploit": ["exploitation agent", "exploit agent", "testing agent"],
    "Critique": ["critique agent", "adversarial review", "reviewing agent"],
    "Reporter": ["reporting agent", "reporter agent"],
    "Memory": ["memory agent", "learning store"],
}

# Named capabilities. Each is a thing a reader could reasonably ask "and what about X?" about.
# Phrasings are alternatives — any one of them counts — because the document rightly prefers plain
# words to product names.
CAPABILITIES: list[tuple[str, list[str]]] = [
    ("voice control", ["voice", "spoken"]),
    ("gesture control", ["gesture"]),
    ("the status overlay", ["status overlay", "overlay", "hud"]),
    ("screen and camera perception", ["screen reading", "perception", "captured text", "on-screen text"]),
    # The document introduces the full term once and then uses the hyphenated short form, which is
    # good plain-English practice — so both spellings count. Widening an alias to match the wording
    # the document genuinely uses is not the same as lowering the bar: the substance must still be
    # there, and here it is (the full term, the abbreviation, and its absence on this machine).
    ("optical character recognition",
     ["optical character recognition", "text-recognition", "text recognition", "reads the text on"]),
    ("the sovereign memory graph", ["sovereign memory graph", "sovereign knowledge graph", "memory graph"]),
    ("recall by meaning", ["recall by meaning", "searches by meaning", "similarity of meaning"]),
    ("the memory server for other assistants", ["memory server", "cited recall"]),
    ("the phone companion", ["phone companion", "companion", "from their phone", "paired phone"]),
    ("point-at-a-url learning", ["point-at-a-url", "learn from url", "learn from a web address", "point it at a"]),
    ("deep learning of a weakness", ["deep-learn", "find, detect and prevent", "how to find it"]),
    ("propose-to-learn", ["propose-to-learn", "learn queue", "learning proposal"]),
    ("self-evolve", ["self-evolve", "self evolve", "gaps in its own coverage"]),
    ("the vulnerability intelligence feed", ["intelligence feed", "vulnerability feed", "advisories"]),
    ("the governed terminal", ["governed terminal", "terminal screen"]),
    ("the sandboxed command runner", ["sandbox", "sandboxed"]),
    ("strix, the vendored testing agent", ["strix"]),
    ("the offensive world model", ["world model", "picture of the attack", "attack graph"]),
    ("attack paths and chokepoints", ["chokepoint", "attack path"]),
    ("sessions", ["session"]),
    ("the engagement library", ["engagement library"]),
    ("the case file in the dossier", ["case file", "start here"]),
    ("the record as memory", ["append-only", "the record"]),
    ("machine-checked invariants", ["machine-checked", "formally", "formal model"]),

    # ----------------------------------------------------------------------------------------
    # Added 2026-08-13, and the reason this file could pass while knowing none of it.
    #
    # All of the below was BUILT on the day the briefing was being written. The document says
    # nothing about any of it, and this file reported green anyway — because a capability that
    # is absent from this list cannot be caught, which is the one weakness of a curated list and
    # the reason the agent roster is read from the code instead. Adding the rows is what turns
    # each silence into a failure the writing then has to close.
    #
    # THE PHRASINGS ARE DELIBERATELY NARROW. "negative control", "sandbox image", "capability
    # pack", "attachment" and "offensive side" already appear in the briefing, in quantity, about
    # entirely different things — the oracle's own controls, the vendored agent's container, the
    # scan options, the fail-closed gate wiring, the offence half of the system. A row phrased
    # with any of those bare words would go green without one word being written about the range,
    # the tool image, the packs or the chat. Each row below is worded so that only the new
    # material can satisfy it, and so that the words are still ones a reader would actually meet.
    # ----------------------------------------------------------------------------------------

    # -- the local proving range --------------------------------------------------------------
    ("the local proving range", ["proving range", "practice range"]),
    ("the deliberately-vulnerable applications on the range",
     ["juice shop", "webgoat", "mutillidae", "damn vulnerable web application"]),
    ("the range's targets are pinned to exact published content",
     ["pinned by content digest", "pinned by its content digest", "pinned to an exact published"]),
    ("the range is loopback-bound by construction, not by convention",
     ["loopback by construction", "cannot express a host address", "rather than by convention"]),
    ("a weakness on the range is shown by difference",
     ["verified by difference", "verification by difference", "shown by difference",
      "a benign request beside", "beside an attacking one"]),
    # The honesty row. One of the six is brought up, is asserted to answer, and is NOT claimed to
    # have demonstrated anything — because its weaknesses sit behind per-lesson state no single
    # request reaches. A document that quietly rounded six up to six-out-of-six would be exactly
    # the overclaim the range exists to prevent.
    ("the range target that honestly claims nothing",
     ["not probed", "does not claim to have demonstrated", "did not demonstrate"]),

    # -- how a tool is driven, and what is actually proven -------------------------------------
    ("the four ways a tool can be driven",
     ["four ways a tool", "how each tool is driven", "four kinds of driver"]),
    ("the typed argument builder",
     ["typed argument builder", "argument builder", "builds the command line itself"]),
    # The single most important honesty row on this page. Nine tools have a typed builder; the
    # number PROVEN end to end against a live target is three. "The engine drives nine tools" is
    # the sentence that is natural to write here and is false.
    ("how many typed drivers are proven against a live target",
     ["proven end to end", "driven end to end", "three of the nine"]),
    ("the drivers whose output nothing in the engine could read",
     ["discarded every byte", "no reader existed", "threw every byte away"]),
    ("the drivers that have never been executed",
     ["never been executed", "never been run against a target"]),
    ("tools the screen refused while the engine was already driving them",
     ["refused as undrivable", "already driving", "refused while the engine"]),

    # -- the sandbox tool image ----------------------------------------------------------------
    # The briefing currently states the image is NOT built, in more than one chapter. It is built,
    # and every tool in it was verified by running it. An underclaim is a defect.
    ("the sandbox tool image",
     ["sandbox tool image", "twenty-four tools", "built for the first time"]),
    ("the defects that had made the tool image unbuildable",
     ["build context", "could never have worked", "resolved over the network at build time"]),
    ("every host tool is now present", ["thirteen host tools", "all thirteen"]),

    # -- the chat screen -----------------------------------------------------------------------
    ("handing the chat an archive, a folder or a web address",
     ["upload an archive", "uploaded archive", "upload a codebase", "hand it a folder"]),
    ("what the chat's extractor refuses",
     ["decompression bomb", "path escape", "symlinked parent", "member flood"]),
    # The chat reads a budget-limited selection; the gated scan reads the whole tree. An answer
    # that did not say which one it was would read as complete when it is not.
    ("the chat says how much of the material it read",
     ["how many files it read", "files it read and how many", "read n of m"]),
    ("drawing one chat's history into another",
     ["connected chat", "connect another chat", "another chat's history"]),

    # -- organisation and control ---------------------------------------------------------------
    ("the interface is scoped to one engagement at a time",
     ["active engagement", "one engagement at a time", "scoped to one engagement"]),
    ("starting the offensive side from the screen",
     ["start the offensive side from the screen", "starts the offensive side",
      "start the offensive plane"]),

    # -- the defects that only running the system revealed --------------------------------------
    ("the defects that unit tests could not have found",
     ["invisible to unit tests", "only by running them", "found by running"]),
    ("the false positive minted from a tool's stored session",
     ["stored session", "resumed a stored", "re-reported a confirmed weakness"]),
    ("the scanner that did nothing because a port was busy",
     ["a port that was already in use", "silent no-op", "ten-second"]),
    ("capability selections that were accepted and never applied",
     ["were not applied", "accepted and silently", "accepted and then discarded"]),
]


# --------------------------------------------------------------------------------------------
# The assertions
# --------------------------------------------------------------------------------------------

def test_every_sovereign_agent_is_explained():
    text = _briefing_text()
    missing = []
    for name, path in sorted(_sovereign_agents().items()):
        n = _count(text, [name])
        if n < MIN_MENTIONS:
            missing.append(f"  {name:<12} mentioned {n}x — declared in {path.relative_to(REPO)}")
    assert not missing, (
        "These sovereign agents exist in the code and the briefing does not explain them.\n"
        + "\n".join(missing)
        + "\n\nAdd each to the agent roster in 11-the-agents-and-learning.md with its job, its\n"
          "ceiling, and — the part an agency reads hardest — what it may NEVER do."
    )


def test_every_offense_agent_is_explained():
    text = _briefing_text()
    missing = []
    for name, path in sorted(_offense_agents().items()):
        phrases = OFFENSE_ALIASES.get(name, [])
        n = _count(text, phrases + [f"{name} agent"])
        if n < MIN_MENTIONS:
            missing.append(
                f"  {name}Agent mentioned {n}x (looked for: {phrases or 'no alias registered'})"
                f" — declared in {path.relative_to(REPO)}"
            )
    assert not missing, (
        "These offensive-side agents exist in the code and the briefing does not explain them.\n"
        + "\n".join(missing)
        + "\n\nIf the briefing calls one of these something else in plain English, register that\n"
          "wording in OFFENSE_ALIASES above. If it does not describe it at all, describe it."
    )


def test_every_named_capability_is_explained():
    text = _briefing_text()
    missing = []
    for label, phrases in CAPABILITIES:
        n = _count(text, phrases)
        if n < MIN_MENTIONS:
            missing.append(f"  {label:<38} mentioned {n}x (looked for: {phrases})")
    assert not missing, (
        "The briefing does not explain these capabilities, which the system has.\n"
        + "\n".join(missing)
        + "\n\nA reader who asks 'and what about this?' must find an answer. If a capability was\n"
          "removed from the system, remove its row here in the same change."
    )


def test_the_roster_is_actually_being_discovered():
    """MUTATION CONTROL for the three tests above.

    Every one of them passes trivially if discovery silently returns nothing — a refactor that moves
    or renames the declaration would turn this whole file into a no-op that still reports green,
    which is a worse outcome than never having written it. Pin the floors so that failure is loud.
    """
    sov = _sovereign_agents()
    off = _offense_agents()
    assert len(sov) >= 9, f"sovereign agent discovery found only {sorted(sov)} — the pattern broke"
    assert len(off) >= 5, f"offensive agent discovery found only {sorted(off)} — the pattern broke"
    # The research agent owns the web-research mode; a separate identity for it would be an
    # invented component. If this ever fails, the code changed and CORRECTIONS.md item 1 is stale.
    assert "SCRIBE" not in sov, "SCRIBE now declares its own identity — update the briefing and CORRECTIONS.md"
