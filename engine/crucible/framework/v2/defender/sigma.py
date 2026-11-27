"""
defender.sigma — a small, deterministic, FAIL-CLOSED Sigma rule runtime + ATT&CK mapping.

Sigma is the community standard for portable detection rules. This module parses a useful,
well-defined SUBSET of Sigma and evaluates it against the normalized ``LogEvent``s produced by
``defender.logsource`` — so the operator can ask two purple-team questions with their OWN rules:

  * "which of my detections fire on my logs?"                 (efficacy over ingested events)
  * "would my ruleset have caught what CRUCIBLE just did?"    (efficacy over the scan's actions)

It is NOT a full Sigma engine and does not pretend to be. The design rule is the load-bearing
one for a DEFENSIVE tool:

  >  FAIL CLOSED. If a rule uses a construct this runtime does not implement (an unknown field
  >  modifier, an unparsable condition, a value-modifier like base64/re/cidr, a numeric range
  >  operator), the rule DOES NOT MATCH. We never fabricate a detection we could not actually
  >  evaluate — a false "detected" is worse than an honest "unsupported → not detected", because
  >  it would tell the blue team they are covered when they are not.

Supported subset (documented and tested):
  * ``logsource`` (informational only — matching keys off ``detection``).
  * selections that are a field->value MAP (all pairs AND), a LIST of such maps (OR), or a LIST
    of strings (keywords / free-text, matched case-insensitively against any field + the raw line).
  * field modifiers ``|contains`` ``|startswith`` ``|endswith`` ``|all`` (and the plain, no-modifier
    equality). A list value is OR by default, AND under ``|all``. Everything else is UNSUPPORTED.
  * ``condition`` over selection identifiers with ``and`` / ``or`` / ``not`` / parentheses, plus the
    aggregations ``1 of them`` / ``all of them`` / ``1 of <prefix>*`` / ``all of <prefix>*``.
    Anything else (``| count() > N`` correlation, ``near`` temporal joins) is UNSUPPORTED.
  * ATT&CK mapping from ``tags: [attack.tXXXX(.YYY), attack.<tactic>]``.

Sigma v2 (AS-17a). Four additions, each strictly additive — the DEFAULT evaluation path is
BYTE-IDENTICAL to v1, so a rule that uses none of them matches exactly as before:

  * **Wildcard fix.** A plain (no-modifier) field value with a LIVE (unescaped) ``*`` (zero-or-more
    chars) or ``?`` (exactly one char) is now a Sigma glob, not a literal (``\\*`` ``\\?`` are
    literals inside such a pattern). Previously ``Image: '*cmd.exe'`` never fired (``a ==
    '*cmd.exe'``); now it matches per the standard. Matching is a hand-rolled LINEAR two-pointer
    glob — no regex is compiled from rule text (DoS-free) — and stays case-insensitive and
    fail-closed. A value with NO live wildcard takes the identical fast ``a == e`` path as v1,
    backslash values (UNC / device / named-pipe paths) included.
  * **author / licence / references.** Parsed from the rule and surfaced (``describe()`` /
    ``provenance``), so a distributed rule can carry its required attribution (plan §4.7).
  * **field maps.** An OPT-IN ``field_map`` (canonical field -> event-field aliases) lets a rule
    written against standard Sigma field names match a differently-named normalized event field.
    A direct field hit always wins; the map is a pure fallback. It is NOT applied to selections used
    under a ``not`` in the condition (exclusion/filter), so enabling a map can only ADD a match at
    the rule level, never silently suppress one. Default ``None`` -> no mapping.
  * **logsource + not_deployable.** ``logsource_channels()`` resolves a rule's
    ``logsource`` to the event channel(s) it applies to; an OPT-IN ``match_logsource`` narrows
    evaluation to those channels (an unresolvable logsource never narrows). ``deployable`` /
    ``deploy_blockers`` flag a rule that must NOT be pushed to a customer — unsupported, or
    missing the author/licence attribution distribution requires — WITHOUT stopping local
    efficacy evaluation.

Determinism: parse + evaluate are PURE (no wallclock, no rng). Untrusted input: ``yaml.safe_load``
only, bounded rule/condition sizes, linear string scans (no regex compiled from rule text), no
``eval``. String matching is case-insensitive (the common Sigma backend default), which only ever
makes a detection MORE likely to fire — it never manufactures a match from an unsupported construct.
"""

from __future__ import annotations

import re as _re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .logsource import LogEvent

# An optional field-name alias map: canonical rule field -> ordered event-field fallbacks.
FieldMap = Mapping[str, Sequence[str]]

# --- untrusted-input bounds -------------------------------------------------
_MAX_RULE_BYTES = 512 * 1024
_MAX_CONDITION = 2_000            # a condition string longer than this is refused (unsupported)
_MAX_SELECTIONS = 128
_MAX_TOKENS = 400


class _Unsupported(Exception):
    """Raised internally when a rule uses a construct we do not implement. Caught at the match
    boundary and turned into a NON-match (fail-closed) — never propagated to the caller."""


# ---------------------------------------------------------------------------
# rule model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigmaRule:
    """A parsed Sigma rule (the supported subset). ``detection`` is the raw selections map
    (minus ``condition``); ``condition`` is the boolean expression over selection names;
    ``attack_techniques`` / ``attack_tactics`` are extracted from ``tags``. ``supported`` is a
    best-effort static verdict — the AUTHORITATIVE guarantee is at evaluation time, where any
    unsupported construct yields NO match."""

    id: str
    title: str
    level: str
    logsource: dict
    detection: dict
    condition: str
    attack_techniques: tuple[str, ...] = ()
    attack_tactics: tuple[str, ...] = ()
    supported: bool = True
    unsupported_reason: str = ""
    # --- provenance (AS-17a): attribution a distributed rule must carry (plan §4.7) ---
    author: str = ""
    license: str = ""
    description: str = ""
    references: tuple[str, ...] = ()
    # --- deployability (AS-17a): may this rule be PUSHED to a customer? ---
    # A non-deployable rule is still evaluated locally for efficacy; it just must not be
    # distributed (unsupported construct, or missing the author/licence attribution).
    deployable: bool = True
    deploy_blockers: tuple[str, ...] = ()

    @property
    def selection_names(self) -> list[str]:
        return [k for k in self.detection.keys() if k != "condition"]

    @property
    def provenance(self) -> dict:
        """The attribution + deployability of this rule, as a plain, serialisable dict —
        the data behind the AS-17a acceptance 'Rule, author and licence shown'."""
        return {
            "id": self.id,
            "title": self.title,
            "author": self.author,
            "license": self.license,
            "references": list(self.references),
            "supported": self.supported,
            "deployable": self.deployable,
            "deploy_blockers": list(self.deploy_blockers),
        }

    def describe(self) -> str:
        """One honest human line: id, title, author, licence, and deployability — so the
        operator SEES who wrote a rule, under what licence, and whether it may be pushed."""
        who = self.author or "<no author>"
        lic = self.license or "<no licence>"
        state = "deployable" if self.deployable else ("NOT deployable: " + "; ".join(self.deploy_blockers))
        return f"{self.id} — {self.title} [author: {who}; licence: {lic}] ({state})"


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

_TECH_RE = _re.compile(r"^t(\d{4})(?:\.(\d{3}))?$")


def _extract_attack(tags: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """From a Sigma ``tags`` list, pull ATT&CK technique ids (``attack.t1190`` -> ``T1190``,
    ``attack.t1059.007`` -> ``T1059.007``) and tactic names (``attack.initial_access`` ->
    ``initial-access``). Total; order-preserving, de-duplicated."""
    techniques: list[str] = []
    tactics: list[str] = []
    if not isinstance(tags, list):
        return (), ()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        t = tag.strip().lower()
        if not t.startswith("attack."):
            continue
        rest = t[len("attack."):]
        m = _TECH_RE.match(rest)
        if m:
            tid = "T" + m.group(1) + ("." + m.group(2) if m.group(2) else "")
            if tid not in techniques:
                techniques.append(tid)
        else:
            tac = rest.replace("_", "-")
            if tac and tac not in tactics:
                tactics.append(tac)
    return tuple(techniques), tuple(tactics)


def _condition_supported(condition: str, selection_names: list[str]) -> tuple[bool, str]:
    """Static check that a condition uses ONLY the supported grammar. Returns (ok, reason).
    Correlation pipes (``|``), comparison operators, and stray tokens are rejected here so a
    rule with an unevaluable condition is honestly flagged unsupported (and also fails closed
    at match time)."""
    if not isinstance(condition, str) or not condition.strip():
        return False, "missing condition"
    if len(condition) > _MAX_CONDITION:
        return False, "condition too long"
    if "|" in condition:
        return False, "aggregation/correlation ('|') is unsupported"
    for bad in ("<", ">", "=", "count(", "near "):
        if bad in condition:
            return False, f"unsupported operator {bad!r}"
    tokens = _tokenize_condition(condition)
    if not tokens:
        return False, "empty/untokenizable condition"
    if len(tokens) > _MAX_TOKENS:
        return False, "condition too complex"
    return True, ""


def _selections_supported(selections: dict) -> tuple[bool, str]:
    """Static check that every selection uses only the supported shape/modifiers, so the
    'unsupported' count in a report is honest (the eval path already fails closed regardless).
    A dict selection's keys may carry only ``contains/startswith/endswith/all`` modifiers over
    scalar/list values; a list selection is OR-of-maps or keywords. Anything else -> unsupported."""
    for name, sel in selections.items():
        maps = sel if isinstance(sel, list) and sel and all(isinstance(x, dict) for x in sel) else \
               ([sel] if isinstance(sel, dict) else [])
        if isinstance(sel, list) and not maps:
            # keyword list (scalars) — supported iff all items are scalars
            if not all(isinstance(x, (str, int, float, bool)) for x in sel):
                return False, f"non-scalar keyword in {name!r}"
            continue
        if not maps and not isinstance(sel, dict):
            return False, f"unsupported selection shape in {name!r}"
        for m in maps:
            for key, val in m.items():
                mods = [p.strip().lower() for p in str(key).split("|")[1:] if p.strip()]
                if any(mod not in _SUPPORTED_MODIFIERS for mod in mods):
                    return False, f"unsupported field modifier in {name!r}.{key!r}"
                if not isinstance(val, (str, int, float, bool, list)):
                    return False, f"non-scalar selection value in {name!r}.{key!r}"
                if isinstance(val, list) and not all(isinstance(x, (str, int, float, bool)) for x in val):
                    return False, f"non-scalar list value in {name!r}.{key!r}"
    return True, ""


def parse_sigma_rule(doc: "str | dict") -> "SigmaRule | None":
    """Parse ONE Sigma rule (YAML text or an already-loaded dict) into a :class:`SigmaRule`, or
    None if it is not a usable rule. ``yaml.safe_load`` only. A rule that parses structurally but
    uses an unsupported construct is returned with ``supported=False`` (and will never match) —
    so the operator can SEE which of their rules this runtime cannot evaluate, rather than having
    them silently dropped. Total: any parse error yields None, never an exception."""
    if isinstance(doc, str):
        if len(doc) > _MAX_RULE_BYTES:
            return None
        try:
            loaded = yaml.safe_load(doc)
        except (yaml.YAMLError, ValueError, RecursionError):
            return None
    else:
        loaded = doc
    if not isinstance(loaded, dict):
        return None

    detection = loaded.get("detection")
    if not isinstance(detection, dict):
        return None
    condition = detection.get("condition")
    # A dict of {name: selection} minus 'condition'. Bound the count.
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections or len(selections) > _MAX_SELECTIONS:
        return None

    rid = str(loaded.get("id") or loaded.get("title") or "sigma-rule")
    title = str(loaded.get("title") or rid)
    level = str(loaded.get("level") or "medium")
    logsource = loaded.get("logsource") if isinstance(loaded.get("logsource"), dict) else {}
    techniques, tactics = _extract_attack(loaded.get("tags"))

    # Provenance (AS-17a): author, licence (both spellings), description, references.
    author = str(loaded.get("author") or "").strip()
    license_ = str(loaded.get("license") or loaded.get("licence") or "").strip()
    desc = str(loaded.get("description") or "").strip()
    refs_raw = loaded.get("references")
    references = tuple(str(r).strip() for r in refs_raw if isinstance(r, (str, int, float))) \
        if isinstance(refs_raw, list) else ()

    cond_str = condition if isinstance(condition, str) else ""
    ok, reason = _condition_supported(cond_str, list(selections.keys()))
    if ok:
        ok, reason = _selections_supported(selections)

    # Deployability (AS-17a `not_deployable`): a rule may be PUSHED to a customer only if it is
    # evaluable here AND carries the attribution distribution requires (plan §4.7). It is still
    # evaluated locally for efficacy regardless — deployability gates DISTRIBUTION, not matching.
    blockers: list[str] = []
    if not ok:
        blockers.append(f"unsupported construct: {reason}")
    if not author:
        blockers.append("missing author attribution")
    if not license_:
        blockers.append("missing licence")

    return SigmaRule(
        id=rid, title=title, level=level, logsource=logsource,
        detection=selections, condition=cond_str,
        attack_techniques=techniques, attack_tactics=tactics,
        supported=ok, unsupported_reason=reason,
        author=author, license=license_, description=desc, references=references,
        deployable=not blockers, deploy_blockers=tuple(blockers),
    )


def load_sigma_dir(path: str) -> list[SigmaRule]:
    """Load every ``*.yml`` / ``*.yaml`` Sigma rule under ``path`` (non-recursive + one level of
    subdirs), in sorted filename order (deterministic). GRACEFUL ABSENCE: a missing dir or an
    unreadable/invalid file is skipped, never raised — an operator who points ``--defender-sigma``
    at nothing gets an empty ruleset, not a crash. A YAML file may hold multiple rules separated
    by ``---`` (safe_load_all)."""
    rules: list[SigmaRule] = []
    p = Path(path).expanduser() if path else None
    if p is None or not p.is_dir():
        return rules
    try:
        candidates = sorted(
            [f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in (".yml", ".yaml")],
            key=lambda f: str(f))
    except OSError:
        return rules
    for f in candidates[:5_000]:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")[:_MAX_RULE_BYTES]
            for chunk in yaml.safe_load_all(text):
                rule = parse_sigma_rule(chunk) if isinstance(chunk, dict) else None
                if rule is not None:
                    rules.append(rule)
        except (OSError, yaml.YAMLError, ValueError, RecursionError):
            continue
    return rules


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------

_SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "all"})


def _as_str(value: object) -> str:
    return value if isinstance(value, str) else str(value)


# ---- Sigma wildcard glob (AS-17a) -----------------------------------------
# A plain field value may contain the Sigma wildcards '*' (zero-or-more) and '?' (exactly one),
# with '\' escaping '*', '?' and '\'. We compile the pattern to a token list ONCE and match with
# a hand-rolled linear two-pointer glob — NO regex is compiled from rule text, so an adversarial
# rule cannot cause catastrophic backtracking (the module's "linear scans only" discipline).

_LIT = 0
_STAR = 1
_ANY = 2


def _glob_tokens(pattern: str) -> tuple[tuple[int, str], ...]:
    """Compile a (already-lowercased) pattern into ('lit'|'star'|'any') tokens. ``\\*`` ``\\?``
    ``\\\\`` are literal escapes; a backslash before any other char stays a literal backslash.
    Consecutive stars collapse (so ``a**b`` costs the same as ``a*b``)."""
    toks: list[tuple[int, str]] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n and pattern[i + 1] in "*?\\":
            toks.append((_LIT, pattern[i + 1]))
            i += 2
            continue
        if c == "*":
            if not toks or toks[-1][0] != _STAR:
                toks.append((_STAR, ""))
            i += 1
            continue
        if c == "?":
            toks.append((_ANY, ""))
            i += 1
            continue
        toks.append((_LIT, c))
        i += 1
    return tuple(toks)


def _glob_match(text: str, toks: tuple[tuple[int, str], ...]) -> bool:
    """Two-pointer glob of a token list against ``text`` (both already lowercased). ``*`` matches
    zero-or-more chars, ``?`` exactly one. Deterministic, iterative (no recursion, no regex); a
    single star-backtrack pointer bounds it to O(len(text)·len(toks)) worst case — polynomial, NOT
    the exponential/catastrophic backtracking a regex compiled from rule text would risk. Both
    inputs are size-bounded upstream (field value ≤ 8 KiB; rule ≤ 512 KiB)."""
    ti = 0
    pi = 0
    star_pi = -1
    star_ti = 0
    n, m = len(text), len(toks)
    while ti < n:
        if pi < m and toks[pi][0] == _LIT and toks[pi][1] == text[ti]:
            ti += 1
            pi += 1
        elif pi < m and toks[pi][0] == _ANY:
            ti += 1
            pi += 1
        elif pi < m and toks[pi][0] == _STAR:
            star_pi = pi
            star_ti = ti
            pi += 1
        elif star_pi != -1:
            pi = star_pi + 1
            star_ti += 1
            ti = star_ti
        else:
            return False
    while pi < m and toks[pi][0] == _STAR:
        pi += 1
    return pi == m


def _has_live_wildcard(s: str) -> bool:
    """Does ``s`` contain a LIVE (unescaped) Sigma wildcard ``*`` or ``?``? Skips ``\\*`` ``\\?``
    ``\\\\`` escape pairs (a backslash before another char is a plain literal backslash, advanced
    singly — matching ``_glob_tokens``). This is the ONLY trigger for the glob path: a value with
    no live wildcard — INCLUDING any value with backslashes such as a UNC path ``\\\\server\\share``
    or ``\\\\.\\PhysicalDrive0`` — takes the exact ``a == e`` fast path, so v1 byte-identity holds
    for every backslash value (the glob-tokeniser would otherwise collapse ``\\\\``->``\\`` and
    silently drop the match)."""
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n and s[i + 1] in "*?\\":
            i += 2
            continue
        if c == "*" or c == "?":
            return True
        i += 1
    return False


def _scalar_match(actual: object, expected: object, modifier: str) -> bool:
    """Match one event field value against one expected value under a single string modifier.
    Case-insensitive (Sigma backend default). Unknown modifier -> _Unsupported (fail-closed).

    AS-17a: the plain (no-modifier) branch treats a LIVE (unescaped) ``*``/``?`` as a Sigma glob
    (``\\*`` ``\\?`` are literals inside such a pattern). A value with NO live wildcard takes the
    identical fast ``a == e`` path as v1 — byte-identical for the whole v1 corpus, backslash values
    (UNC / device / named-pipe paths) included. A value whose ONLY ``*``/``?`` is escaped therefore
    stays an exact literal match on its raw form (v1 behaviour), which is the higher-priority
    guarantee over re-interpreting a lone escaped ``\\*`` as ``*``."""
    a = _as_str(actual).lower()
    e = _as_str(expected).lower()
    if modifier == "" or modifier == "eq":
        if _has_live_wildcard(e):
            return _glob_match(a, _glob_tokens(e))
        return a == e
    if modifier == "contains":
        return e in a
    if modifier == "startswith":
        return a.startswith(e)
    if modifier == "endswith":
        return a.endswith(e)
    raise _Unsupported(f"value modifier {modifier!r}")


_MISSING = object()


def _resolve_field(event: LogEvent, fname: str, field_map: "FieldMap | None") -> object:
    """Return the event's value for ``fname``, or (AS-17a field maps) the first present alias
    from ``field_map[fname]``, or the ``_MISSING`` sentinel. A DIRECT field always wins, so at the
    SELECTION level the map is a pure fallback that can only make a selection match MORE. (The
    rule-level 'never suppress' guarantee is enforced in :func:`rule_matches_event`, which withholds
    the map from negated/exclusion selections.) A sentinel (not a truthiness test) is used so a
    falsy-but-present value (``0``, ``""``) still counts as present."""
    if fname in event.fields:
        return event.fields[fname]
    if field_map:
        for alias in field_map.get(fname, ()):
            if alias in event.fields:
                return event.fields[alias]
    return _MISSING


def _field_matches(event: LogEvent, key: str, expected: object,
                   field_map: "FieldMap | None" = None) -> bool:
    """Evaluate one ``field|modifier: expected`` entry of a selection map against an event.
    A missing field never matches. A list expected value is OR by default, AND under ``|all``.
    An unsupported modifier raises _Unsupported (the whole rule then fails closed)."""
    parts = key.split("|")
    fname = parts[0]
    modifiers = [m.strip().lower() for m in parts[1:] if m.strip()]
    require_all = "all" in modifiers
    str_mods = [m for m in modifiers if m != "all"]
    if any(m not in _SUPPORTED_MODIFIERS for m in modifiers):
        raise _Unsupported(f"field modifier in {key!r}")
    if len(str_mods) > 1:
        raise _Unsupported(f"stacked value modifiers in {key!r}")
    modifier = str_mods[0] if str_mods else ""

    actual = _resolve_field(event, fname, field_map)
    if actual is _MISSING:
        return False

    if isinstance(expected, list):
        results = [_scalar_match(actual, item, modifier) for item in expected]
        return all(results) if require_all else any(results)
    if isinstance(expected, (str, int, float, bool)):
        return _scalar_match(actual, expected, modifier)
    # a dict / nested structure as an expected value is not part of the supported subset
    raise _Unsupported("non-scalar selection value")


def _keywords_match(event: LogEvent, keywords: list) -> bool:
    """A keywords selection (list of strings): match if ANY keyword appears (case-insensitively)
    in ANY field value or the raw line. This is Sigma's free-text search."""
    haystack = (" ".join(_as_str(v) for v in event.fields.values()) + " " + (event.raw or "")).lower()
    for kw in keywords:
        if not isinstance(kw, (str, int, float, bool)):
            raise _Unsupported("non-scalar keyword")
        if _as_str(kw).lower() in haystack:
            return True
    return False


def _selection_matches(event: LogEvent, selection: object,
                       field_map: "FieldMap | None" = None) -> bool:
    """Evaluate one named selection against an event.
      * dict  -> ALL field entries must hold (AND);
      * list of dicts -> ANY sub-map holds (OR);
      * list of scalars -> keywords (free-text ANY).
    Anything else is unsupported (fail-closed)."""
    if isinstance(selection, dict):
        if not selection:
            return False          # an empty selection has no criteria — it must never fire (fail-closed)
        return all(_field_matches(event, str(k), v, field_map) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(x, dict) for x in selection) and selection:
            return any(_selection_matches(event, sub, field_map) for sub in selection)
        return _keywords_match(event, selection)
    raise _Unsupported("unsupported selection shape")


# ---- condition parsing (tiny recursive-descent boolean parser) ----

def _tokenize_condition(condition: str) -> list[str]:
    """Tokenize a condition into words and parens. Lowercases keywords; keeps selection names as-is
    (they are matched case-sensitively against the rule's own selection keys)."""
    spaced = condition.replace("(", " ( ").replace(")", " ) ")
    return [t for t in spaced.split() if t]


def _eval_condition(tokens: list[str], selresults: dict[str, bool], names: list[str]) -> bool:
    """Evaluate the boolean condition token stream. Recursive descent with precedence
    not > and > or, parentheses, and ``1|all of them|<prefix>*`` aggregations. Any unrecognized
    token raises _Unsupported (fail-closed)."""
    pos = 0

    def peek() -> "str | None":
        return tokens[pos] if pos < len(tokens) else None

    def advance() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def resolve_name(name: str) -> bool:
        if name not in selresults:
            raise _Unsupported(f"unknown selection {name!r} in condition")
        return selresults[name]

    def aggregate(quant: str) -> bool:
        # quant is '1' or 'all'; expects: quant 'of' ('them' | prefix*)
        if peek() != "of":
            raise _Unsupported("malformed aggregation")
        advance()  # 'of'
        target = peek()
        if target is None:
            raise _Unsupported("malformed aggregation target")
        advance()
        if target == "them":
            picked = [selresults[n] for n in names]
        elif target.endswith("*"):
            prefix = target[:-1]
            picked = [selresults[n] for n in names if n.startswith(prefix)]
        else:
            picked = [resolve_name(target)]
        if not picked:
            return False
        return any(picked) if quant == "1" else all(picked)

    def atom() -> bool:
        tok = peek()
        if tok is None:
            raise _Unsupported("unexpected end of condition")
        if tok == "(":
            advance()
            val = or_expr()
            if peek() != ")":
                raise _Unsupported("unbalanced parentheses")
            advance()
            return val
        low = tok.lower()
        if low in ("1", "all") and pos + 1 < len(tokens) and tokens[pos + 1] == "of":
            advance()
            return aggregate(low)
        if low in ("and", "or", "not", "of", ")", "them"):
            raise _Unsupported(f"unexpected token {tok!r}")
        advance()
        return resolve_name(tok)

    def not_expr() -> bool:
        if peek() is not None and peek().lower() == "not":
            advance()
            return not not_expr()
        return atom()

    def and_expr() -> bool:
        val = not_expr()
        while peek() is not None and peek().lower() == "and":
            advance()
            val = not_expr() and val
        return val

    def or_expr() -> bool:
        val = and_expr()
        while peek() is not None and peek().lower() == "or":
            advance()
            rhs = and_expr()
            val = val or rhs
        return val

    result = or_expr()
    if pos != len(tokens):
        raise _Unsupported("trailing tokens in condition")
    return result


def _negated_selection_names(condition: str, names: list[str]) -> set[str]:
    """Return the selection names that appear at ODD ``not``-depth in ``condition`` (a true
    negation, e.g. ``filter`` in ``selection and not filter`` or every ``filter_*`` in
    ``not 1 of filter_*``). Field-map alias resolution MUST be withheld from these: aliasing an
    exclusion selection can make it fire where v1 could not, flipping ``not filter`` True->False and
    SILENTLY SUPPRESSING the rule. Walks the same grammar as :func:`_eval_condition`, tracking
    negation parity. Total/fail-safe: on any parse oddity it returns ALL names (disable aliasing
    entirely rather than risk a silent suppression)."""
    tokens = _tokenize_condition(condition)
    out: set[str] = set()
    pos = 0

    def peek() -> "str | None":
        return tokens[pos] if pos < len(tokens) else None

    def advance() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def mark(target: str, neg: bool) -> None:
        if not neg:
            return
        if target == "them":
            out.update(names)
        elif target.endswith("*"):
            prefix = target[:-1]
            out.update(n for n in names if n.startswith(prefix))
        elif target in names:
            out.add(target)

    def aggregate(neg: bool) -> None:
        if peek() != "of":
            raise _Unsupported("malformed aggregation")
        advance()
        target = peek()
        if target is None:
            raise _Unsupported("malformed aggregation target")
        advance()
        mark(target, neg)

    def atom(neg: bool) -> None:
        tok = peek()
        if tok is None:
            raise _Unsupported("unexpected end of condition")
        if tok == "(":
            advance()
            or_expr(neg)
            if peek() != ")":
                raise _Unsupported("unbalanced parentheses")
            advance()
            return
        low = tok.lower()
        if low in ("1", "all") and pos + 1 < len(tokens) and tokens[pos + 1] == "of":
            advance()
            aggregate(neg)
            return
        if low in ("and", "or", "not", "of", ")", "them"):
            raise _Unsupported(f"unexpected token {tok!r}")
        advance()
        if neg and tok in names:
            out.add(tok)

    def not_expr(neg: bool) -> None:
        tok = peek()
        if tok is not None and tok.lower() == "not":
            advance()
            not_expr(not neg)
            return
        atom(neg)

    def and_expr(neg: bool) -> None:
        not_expr(neg)
        tok = peek()
        while tok is not None and tok.lower() == "and":
            advance()
            not_expr(neg)
            tok = peek()

    def or_expr(neg: bool) -> None:
        and_expr(neg)
        tok = peek()
        while tok is not None and tok.lower() == "or":
            advance()
            and_expr(neg)
            tok = peek()

    try:
        or_expr(False)
        if pos != len(tokens):
            raise _Unsupported("trailing tokens in condition")
    except _Unsupported:
        return set(names)          # fail-safe: alias nothing, never risk a silent suppression
    return out


def rule_matches_event(rule: SigmaRule, event: LogEvent, *,
                       field_map: "FieldMap | None" = None) -> bool:
    """Does this Sigma rule fire on this event? FAIL-CLOSED: a statically-unsupported rule, an
    unsupported modifier/selection encountered during evaluation, or an unparsable condition all
    yield ``False`` — never a fabricated detection. Pure and deterministic.

    ``field_map`` (AS-17a, default ``None``) is an optional canonical-field -> event-field alias
    map; with it ``None`` the match path is byte-identical to v1. When a map IS supplied, alias
    resolution is applied only to NON-negated selections — a selection used under a ``not`` in the
    condition (an exclusion/filter) resolves with direct fields only, so enabling a field map can
    only ever ADD a match at the rule level, never silently suppress one via a filter."""
    if not rule.supported:
        return False
    try:
        negated = _negated_selection_names(rule.condition, rule.selection_names) if field_map else frozenset()
        selresults = {
            name: _selection_matches(event, rule.detection[name],
                                     None if name in negated else field_map)
            for name in rule.selection_names
        }
        tokens = _tokenize_condition(rule.condition)
        return _eval_condition(tokens, selresults, rule.selection_names)
    except _Unsupported:
        return False
    except Exception:
        # Defensive: any unexpected shape in an untrusted rule fails closed, never crashes.
        return False


# ---------------------------------------------------------------------------
# ruleset evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigmaMatch:
    """One rule firing on one event (the first event it matched — enough for a coverage signal)."""

    rule_id: str
    rule_title: str
    level: str
    channel: str
    event_index: int
    attack_techniques: tuple[str, ...] = ()


@dataclass
class SigmaEvalResult:
    """The outcome of evaluating a ruleset over a set of events."""

    matches: list[SigmaMatch] = field(default_factory=list)
    rules_evaluated: int = 0
    rules_unsupported: int = 0
    events_evaluated: int = 0
    rules_not_deployable: int = 0      # AS-17a: counted at eval time, does NOT suppress matching

    @property
    def techniques_detected(self) -> list[str]:
        seen: list[str] = []
        for m in self.matches:
            for t in m.attack_techniques:
                if t not in seen:
                    seen.append(t)
        return sorted(seen)

    @property
    def matched_rule_ids(self) -> list[str]:
        return sorted({m.rule_id for m in self.matches})

    def summary(self) -> str:
        return (f"{len(self.matched_rule_ids)}/{self.rules_evaluated} rule(s) fired over "
                f"{self.events_evaluated} event(s); {self.rules_unsupported} unsupported; "
                f"{self.rules_not_deployable} not-deployable; "
                f"ATT&CK techniques detected: {', '.join(self.techniques_detected) or 'none'}")


# ---------------------------------------------------------------------------
# logsource resolution + field maps (AS-17a)
# ---------------------------------------------------------------------------

# Resolve a Sigma ``logsource: {category, product, service}`` to the normalized event channel(s)
# a rule applies to (``defender.logsource`` emits 'syslog'/'cef'/'windows'). The mapping is
# deliberately PERMISSIVE (a union of plausible channels) and returns None when it cannot resolve —
# so an opt-in logsource filter NARROWS only on a confident mapping and never suppresses a real
# detection on an unknown logsource (false "not detected" is still worse the more we over-narrow).
_LOGSOURCE_PRODUCT = {
    "windows": frozenset({"windows"}),
    "linux": frozenset({"syslog"}),
    "unix": frozenset({"syslog"}),
}
_LOGSOURCE_CATEGORY = {
    "process_creation": frozenset({"windows", "syslog"}),
    "proxy": frozenset({"cef", "syslog"}),
    "webserver": frozenset({"cef", "syslog"}),
    "web": frozenset({"cef", "syslog"}),
    "firewall": frozenset({"cef", "syslog"}),
    "dns": frozenset({"syslog", "cef"}),
    "dns_query": frozenset({"windows", "syslog"}),
    "antivirus": frozenset({"cef", "syslog"}),
    "network_connection": frozenset({"windows", "syslog", "cef"}),
}
_LOGSOURCE_SERVICE = {
    "security": frozenset({"windows"}),
    "sysmon": frozenset({"windows"}),
    "powershell": frozenset({"windows"}),
    "system": frozenset({"windows", "syslog"}),
    "auditd": frozenset({"syslog"}),
    "sshd": frozenset({"syslog"}),
}


def logsource_channels(logsource: object) -> "frozenset[str] | None":
    """Resolve a rule's ``logsource`` dict to the event channel(s) it applies to, or None when it
    cannot be resolved. Pure and total: a non-dict / empty / unknown logsource yields None (applies
    everywhere). Product + category + service each contribute; the result is their UNION."""
    if not isinstance(logsource, dict):
        return None
    chans: set[str] = set()
    for keymap, key in ((_LOGSOURCE_PRODUCT, "product"),
                        (_LOGSOURCE_CATEGORY, "category"),
                        (_LOGSOURCE_SERVICE, "service")):
        val = logsource.get(key)
        if isinstance(val, str):
            mapped = keymap.get(val.strip().lower())
            if mapped:
                chans |= set(mapped)
    return frozenset(chans) if chans else None


# A small, well-defined default field-name alias map: standard Sigma field names -> the
# normalized event fields ``defender.logsource`` produces. Opt-in (pass to evaluate_events);
# a DIRECT field hit always wins, so this only ever ADDS a match where names differed.
_DEFAULT_FIELD_MAP: dict[str, tuple[str, ...]] = {
    "CommandLine": ("CommandLine", "cmdline", "command_line", "exe"),
    "Image": ("Image", "image", "process", "proc", "exe"),
    "User": ("User", "user", "username", "suser", "account"),
    "DestinationIp": ("DestinationIp", "dst", "dest_ip", "dst_ip", "dstip"),
    "SourceIp": ("SourceIp", "src", "src_ip", "source_ip", "srcip"),
    "EventID": ("EventID", "event_id", "eventid", "cef_signature_id"),
    "TargetFilename": ("TargetFilename", "filename", "file", "path"),
    # AS-17b — CloudTrail: the normalized ``cloudtrail`` event already keeps AWS' own field names
    # (``eventSource``/``eventName``/…), so a standard CloudTrail Sigma rule matches directly; these
    # rows are the pure, ADDITIVE fallbacks for a rule that spells the SAME datum differently
    # (a direct field hit always wins, so they can only ever ADD a match — never suppress one).
    "SourceIP": ("SourceIP", "sourceIPAddress", "SourceIp", "src_ip"),
    "sourceIPAddress": ("sourceIPAddress", "SourceIp", "src_ip"),
    "UserAgent": ("UserAgent", "userAgent", "http_user_agent"),
    "AccountId": ("AccountId", "recipientAccountId", "userIdentity.accountId"),
}


def default_field_map() -> dict[str, tuple[str, ...]]:
    """A copy of the built-in canonical-field -> event-field alias map (AS-17a field maps).
    Opt-in: pass it to :func:`evaluate_events` / :func:`rule_matches_event`."""
    return dict(_DEFAULT_FIELD_MAP)


def evaluate_events(rules: list[SigmaRule], events: list[LogEvent], *,
                    field_map: "FieldMap | None" = None,
                    match_logsource: bool = False) -> SigmaEvalResult:
    """Evaluate ``rules`` against ``events``. For each rule, record the FIRST event it fires on
    (a per-rule coverage signal, not an every-hit firehose). Deterministic: input order preserved,
    one pass. An unsupported rule is counted but never matches (fail-closed).

    AS-17a options, both defaulting to the v1 (byte-identical) behaviour:
      * ``field_map`` — an opt-in canonical-field -> event-field alias map (see
        :func:`default_field_map`);
      * ``match_logsource`` — when True, a rule whose ``logsource`` resolves (see
        :func:`logsource_channels`) only evaluates events on those channels; an unresolvable
        logsource never narrows. ``rules_not_deployable`` is tallied either way (it never
        suppresses matching)."""
    result = SigmaEvalResult(rules_evaluated=len(rules), events_evaluated=len(events))
    for rule in rules:
        if not rule.deployable:
            result.rules_not_deployable += 1
        if not rule.supported:
            result.rules_unsupported += 1
            continue
        wanted = logsource_channels(rule.logsource) if match_logsource else None
        for i, ev in enumerate(events):
            if wanted is not None and ev.channel not in wanted:
                continue
            if rule_matches_event(rule, ev, field_map=field_map):
                result.matches.append(SigmaMatch(
                    rule_id=rule.id, rule_title=rule.title, level=rule.level,
                    channel=ev.channel, event_index=i,
                    attack_techniques=rule.attack_techniques))
                break
    return result
