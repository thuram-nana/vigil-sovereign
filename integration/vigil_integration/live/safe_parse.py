"""safe_parse — resource-governed, non-raising parse helpers for posture evidence.

Every Track-A/B posture parser turns bytes VIGIL captured (a JSON API body, a YAML manifest, a config file)
into a structure a check reasons over. That parse is an attack surface in its own right: a hostile or merely
huge document can exhaust memory (a decompression- or alias-expansion bomb), blow the interpreter stack
(deep recursion), or — with an unsafe YAML loader — construct arbitrary Python objects. If a parser crashes
or hangs the prober, the enclosing check produces no observation, and an absent observation must NEVER be
laundered into a CLEAN verdict. So the governing rule here is the same conservatism the rest of the sovereign
layer follows:

  * A parse that COMPLETES within budget over well-formed input yields ``outcome="ok"`` with the value.
  * A parse that we can PROVE is out of bounds or malformed — too many bytes, too deep, too many nodes, an
    alias bomb, an unsafe tag, a syntax error — yields ``outcome="error"``. This is a definite negative about
    THE DOCUMENT, not about the target's posture.
  * A parse we cannot perform at all for an environmental reason — PyYAML not importable in this venv — yields
    ``outcome="inconclusive"`` (reason ``"yaml_unavailable"``). Inconclusive is the honest floor; it must never
    be read as "the document was fine" and it must never be read as a posture CLEAN by a caller.

Nothing in this module raises on caller-supplied input: :func:`safe_json` and :func:`safe_yaml` catch every
parse-time and walk-time failure and return a typed :class:`ParseResult`. The only exceptions raised are
``ValueError`` from constructing a nonsensical :class:`ParseBudget` (a programming error, not hostile input).

Defenses, and why each is sound:

  * **Byte cap, enforced BEFORE parsing.** ``len(bytes)`` is measured and rejected over ``max_bytes`` before a
    single parser call, so an oversized document is refused without ever being handed to json/yaml.
  * **YAML is SafeLoader-only.** The loader is a subclass of :class:`yaml.SafeLoader`; ``!!python/*`` and any
    other unregistered tag raise ``ConstructorError`` (→ ``outcome="error"``), never a constructed object. We
    do not hand-roll a YAML parser; if PyYAML is missing we degrade to the inconclusive path, not to a bespoke
    scanner.
  * **Alias / merge-key bomb defense, three independent bounds.** (1) A counting loader aborts once the number
    of alias references resolved during composition exceeds ``max_aliases``. (2) PyYAML shares one object
    across all aliases to an anchor, so the classic pure-alias "billion laughs" is a small DAG that only
    explodes when WALKED; the post-parse structural walk counts every visit (including via shared references)
    and trips ``max_nodes`` long before the expansion is materialised. (3) A YAML ``<<`` MERGE key is REFUSED
    outright (``outcome="error"``, reason ``"merge_key"``): PyYAML expands merges during CONSTRUCTION
    (``flatten_mapping`` materialises a list of length refs**levels), which BOTH (1) — merge alias EVENTS grow
    only linearly — AND (2) — the merged mapping collapses to a tiny dict — miss, so a ~600-byte nested-merge
    bomb would otherwise hang/OOM or silently bypass the node budget. We do not expand merges. Each bound
    alone turns its bomb class into ``outcome="error"``.
  * **Node cap, enforced DURING parse AND by the post-parse walk.** ``max_nodes`` is counted twice over: (1)
    the YAML loader counts each newly-composed node and aborts past ``max_nodes`` WHILE parsing (alias refs
    are O(1) via the anchor cache, so this bounds the RAW parse work) — without this, a large flat/shallow
    document within the byte cap (e.g. 1M scalars, well under ``max_bytes``) would parse for tens of seconds
    or OOM before any post-parse budget applied; and (2) the post-parse structural walk counts every visit
    including via shared references, catching an alias-EXPANDED structure the compose-time count (which sees
    the small DAG) would miss. Parse work is therefore bounded to O(``max_nodes``): at the default ceiling a
    pathological document is REFUSED (``too_many_nodes``) in a few seconds — bounded and deterministic, not an
    unbounded hang or OOM. A latency-sensitive caller over untrusted live bytes (Track B) should pass a
    tighter ``ParseBudget``.
  * **Depth cap + cycle detection, enforced by an iterative walk.** Recursion depth is bounded by
    ``max_depth`` in an explicit-stack walk (no Python recursion, so a deep document cannot blow the
    interpreter stack during the check itself). True reference CYCLES (possible via recursive YAML anchors)
    are detected against the current DFS path and reported as an error rather than looped on.
  * **No network, no file includes.** Neither ``json`` nor ``yaml.SafeLoader`` dereferences URLs or file
    paths; this module adds no such capability.

Pure stdlib, except an OPTIONAL function-local ``import yaml`` inside :func:`safe_yaml` (FATAL-2 safe: no
``framework.*`` / ``vigil_core`` import anywhere, and the one third-party import is function-local).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

Outcome = Literal["ok", "error", "inconclusive"]

# Conservative defaults. Callers may tighten (or, deliberately, loosen) per parser; these are sane bounds for
# posture evidence, which is normally small.
DEFAULT_MAX_BYTES = 5_000_000
DEFAULT_MAX_DEPTH = 100
DEFAULT_MAX_NODES = 200_000
DEFAULT_MAX_ALIASES = 100


class _AliasBudgetExceeded(Exception):
    """Raised inside the counting YAML loader when alias references pass ``max_aliases``. Never escapes."""


class _NodeBudgetExceeded(Exception):
    """Raised inside the counting YAML loader when the number of composed nodes passes ``max_nodes`` — the
    DURING-parse node bound that stops a large flat/shallow document (within the byte cap) from parsing for
    tens of seconds / OOMing before the post-parse walk can run. Never escapes."""


class _MergeKeyRefused(Exception):
    """Raised inside the loader when a YAML ``<<`` merge key is seen. PyYAML expands merges during
    CONSTRUCTION (``flatten_mapping`` materialises a real list of length refs**levels), which BOTH the
    compose-time alias counter (alias EVENTS grow only linearly, refs*levels) AND the post-parse node walk
    (the merged mapping collapses to a tiny dict) miss — so a ~600-byte nested-merge bomb hangs/OOMs or
    silently bypasses the node budget. This safe parser does NOT expand merges: a ``<<``-bearing document is
    refused (outcome="error"/"merge_key") rather than expanded. Never escapes."""


@dataclass(frozen=True)
class ParseBudget:
    """Resource ceilings for a single parse.

    All bounds are inclusive limits: a document AT the bound is accepted; one PAST it is rejected. ``max_bytes``
    is measured on the UTF-8 encoding of the input (or its raw length if already bytes) before parsing.
    ``max_depth`` counts the root as depth 1. ``max_nodes`` counts every scalar and container, and every
    revisit through a shared reference (this is what makes it an anti-bomb bound). ``max_aliases`` caps the
    number of YAML alias references resolved during composition; it is ignored for JSON.
    """

    max_bytes: int = DEFAULT_MAX_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_nodes: int = DEFAULT_MAX_NODES
    max_aliases: int = DEFAULT_MAX_ALIASES

    def __post_init__(self) -> None:
        for name in ("max_bytes", "max_depth", "max_nodes", "max_aliases"):
            v = getattr(self, name)
            if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                raise ValueError(f"ParseBudget.{name} must be a positive int, got {v!r}")


@dataclass(frozen=True)
class ParseResult:
    """Typed outcome of a governed parse. ``ok`` is a convenience mirror of ``outcome == 'ok'``.

    On success ``value`` holds the parsed structure and ``reason`` is empty. On failure ``value`` is ``None``
    and ``reason`` is a short, stable machine token (e.g. ``"oversize"``, ``"too_deep"``, ``"too_many_nodes"``,
    ``"alias_bomb"``, ``"unsafe_tag"``, ``"cycle"``, ``"malformed"``, ``"yaml_unavailable"``).
    """

    ok: bool
    value: Any
    outcome: Outcome
    reason: str = ""


def _ok(value: Any) -> ParseResult:
    return ParseResult(ok=True, value=value, outcome="ok", reason="")


def _error(reason: str) -> ParseResult:
    return ParseResult(ok=False, value=None, outcome="error", reason=reason)


def _inconclusive(reason: str) -> ParseResult:
    return ParseResult(ok=False, value=None, outcome="inconclusive", reason=reason)


def _byte_len(text: str | bytes) -> int:
    if isinstance(text, bytes):
        return len(text)
    # Measure the transport size, not the character count; a multibyte document can be far larger in bytes.
    return len(text.encode("utf-8", "surrogatepass"))


def _walk_within_budget(root: Any, budget: ParseBudget) -> ParseResult | None:
    """Structural walk enforcing depth, node-count, and cycle bounds. Returns an error ``ParseResult`` on a
    violation, or ``None`` if the structure is within budget. Iterative (explicit stack) so a deep document
    cannot exhaust the interpreter recursion limit here.
    """
    nodes = 0
    # ``stack`` holds ("enter", obj, depth) and ("leave", id) frames; ``on_path`` is the set of container ids
    # currently on the DFS path, used ONLY to detect true cycles (a back-edge to an ancestor). Shared but
    # acyclic references (an alias DAG) are intentionally NOT deduplicated, so a bomb is fully re-counted and
    # trips ``max_nodes``.
    stack: list = [("enter", root, 1)]
    on_path: set[int] = set()

    while stack:
        frame = stack.pop()
        if frame[0] == "leave":
            on_path.discard(frame[1])
            continue

        _, obj, depth = frame
        nodes += 1
        if nodes > budget.max_nodes:
            return _error("too_many_nodes")
        if depth > budget.max_depth:
            return _error("too_deep")

        if isinstance(obj, (dict, list, tuple, set, frozenset)):
            oid = id(obj)
            if oid in on_path:
                return _error("cycle")
            on_path.add(oid)
            stack.append(("leave", oid))
            child_depth = depth + 1
            if isinstance(obj, dict):
                # Both keys and values are nodes.
                for k, v in obj.items():
                    stack.append(("enter", v, child_depth))
                    stack.append(("enter", k, child_depth))
            else:
                for item in obj:
                    stack.append(("enter", item, child_depth))

    return None


def safe_json(text: str | bytes, budget: ParseBudget | None = None) -> ParseResult:
    """Parse JSON under ``budget`` without ever raising on ``text``.

    Rejects over-size input before parsing, returns a typed error on malformed input or one that exceeds the
    depth/node bounds, and returns ``outcome="ok"`` with the value otherwise.
    """
    budget = budget or ParseBudget()

    size = _byte_len(text)
    if size > budget.max_bytes:
        return _error("oversize")

    try:
        value = json.loads(text)
    except RecursionError:
        # Deeply nested JSON overflows the C scanner's recursion before our walk runs; treat as too deep.
        return _error("too_deep")
    except (ValueError, UnicodeDecodeError):
        # json raises JSONDecodeError (a ValueError subclass) for syntax errors; bytes with a bad encoding
        # raise UnicodeDecodeError.
        return _error("malformed")
    except Exception:  # noqa: BLE001 - defensive: never propagate a parser fault on hostile input.
        return _error("malformed")

    walk_err = _walk_within_budget(value, budget)
    if walk_err is not None:
        return walk_err
    return _ok(value)


def _counting_safe_loader(max_aliases: int, max_nodes: int):
    """Build a one-shot ``yaml.SafeLoader`` subclass that aborts past ``max_aliases`` alias references OR
    ``max_nodes`` composed nodes.

    The node counter is enforced DURING composition, not only by the post-parse walk: PyYAML's pure-Python
    parser fully materialises the structure before any post-parse budget applies, so a large flat/shallow
    document within the byte cap (e.g. 1M scalars) would otherwise parse for tens of seconds / OOM before the
    walk ever runs. Counting each composed node bounds parse work to O(max_nodes). (Alias references still
    compose in O(1) via the anchor cache, so an alias bomb stays cheap here and is caught by the alias cap +
    the post-parse expanded-node walk.)

    Imported types are function-local (FATAL-2: no module-level third-party import). The loader is created
    fresh per call so the caps are captured without shared mutable class state.
    """
    import yaml  # noqa: PLC0415 - optional third-party dep, imported lazily and function-locally.
    from yaml.events import AliasEvent  # noqa: PLC0415

    class _CountingSafeLoader(yaml.SafeLoader):
        def __init__(self, stream: Any) -> None:
            super().__init__(stream)
            self._alias_seen = 0
            self._nodes_composed = 0

        def compose_node(self, parent, index):  # type: ignore[override]
            if self.check_event(AliasEvent):
                self._alias_seen += 1
                if self._alias_seen > max_aliases:
                    raise _AliasBudgetExceeded(max_aliases)
            else:
                # A genuinely new node (not an O(1) alias ref) is about to be composed — bound the raw parse.
                self._nodes_composed += 1
                if self._nodes_composed > max_nodes:
                    raise _NodeBudgetExceeded(max_nodes)
            return super().compose_node(parent, index)

        def flatten_mapping(self, node):  # type: ignore[override]
            # Refuse a `<<` merge key BEFORE the base class expands it. flatten_mapping runs for every mapping
            # at CONSTRUCTION; the base implementation materialises the merge (exponential for a nested-merge
            # bomb) — the vector the alias counter and node walk both miss. We do not expand merges: raise on
            # the merge tag so the bomb is refused instead of built. Non-merge mappings fall through unchanged.
            for item in getattr(node, "value", ()):
                key_node = item[0] if isinstance(item, tuple) and item else None
                if key_node is not None and getattr(key_node, "tag", "") == "tag:yaml.org,2002:merge":
                    raise _MergeKeyRefused()
            return super().flatten_mapping(node)

    return _CountingSafeLoader


def safe_yaml(text: str | bytes, budget: ParseBudget | None = None) -> ParseResult:
    """Parse a single YAML document under ``budget`` using ``yaml.SafeLoader`` ONLY, without ever raising.

    If PyYAML is not importable in this environment, returns ``outcome="inconclusive"`` with reason
    ``"yaml_unavailable"`` — never a hand-rolled parse and never a CLEAN. Unsafe tags (``!!python/*`` and any
    unregistered tag) are refused as errors, alias bombs and over-budget structures are errors, and syntax
    errors are errors.
    """
    budget = budget or ParseBudget()

    size = _byte_len(text)
    if size > budget.max_bytes:
        return _error("oversize")

    try:
        import yaml  # noqa: PLC0415 - optional; absence is an inconclusive, not a crash.
    except Exception:  # noqa: BLE001 - ImportError or a broken install both mean "cannot parse YAML here".
        return _inconclusive("yaml_unavailable")

    try:
        loader_cls = _counting_safe_loader(budget.max_aliases, budget.max_nodes)
    except Exception:  # noqa: BLE001 - PyYAML present at import but internals unavailable: stay honest.
        return _inconclusive("yaml_unavailable")

    try:
        value = yaml.load(text, Loader=loader_cls)  # SafeLoader subclass: no arbitrary object construction.
    except _AliasBudgetExceeded:
        return _error("alias_bomb")
    except _NodeBudgetExceeded:
        return _error("too_many_nodes")   # bounded DURING parse (large flat/shallow doc within the byte cap)
    except _MergeKeyRefused:
        return _error("merge_key")     # a `<<` merge key — refused, never expanded (nested-merge bomb vector)
    except RecursionError:
        return _error("too_deep")
    except yaml.constructor.ConstructorError:
        # Unregistered/unsafe tag under SafeLoader (e.g. !!python/object) — refused, never constructed.
        return _error("unsafe_tag")
    except yaml.YAMLError:
        return _error("malformed")
    except Exception:  # noqa: BLE001 - defensive: never propagate a loader fault on hostile input.
        return _error("malformed")

    walk_err = _walk_within_budget(value, budget)
    if walk_err is not None:
        return walk_err
    return _ok(value)
