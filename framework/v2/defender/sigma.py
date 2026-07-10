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

Determinism: parse + evaluate are PURE (no wallclock, no rng). Untrusted input: ``yaml.safe_load``
only, bounded rule/condition sizes, linear string scans (no regex compiled from rule text), no
``eval``. String matching is case-insensitive (the common Sigma backend default), which only ever
makes a detection MORE likely to fire — it never manufactures a match from an unsupported construct.
"""

from __future__ import annotations

import re as _re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .logsource import LogEvent

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

    @property
    def selection_names(self) -> list[str]:
        return [k for k in self.detection.keys() if k != "condition"]


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

    cond_str = condition if isinstance(condition, str) else ""
    ok, reason = _condition_supported(cond_str, list(selections.keys()))
    if ok:
        ok, reason = _selections_supported(selections)

    return SigmaRule(
        id=rid, title=title, level=level, logsource=logsource,
        detection=selections, condition=cond_str,
        attack_techniques=techniques, attack_tactics=tactics,
        supported=ok, unsupported_reason=reason,
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


def _scalar_match(actual: object, expected: object, modifier: str) -> bool:
    """Match one event field value against one expected value under a single string modifier.
    Case-insensitive (Sigma backend default). Unknown modifier -> _Unsupported (fail-closed)."""
    a = _as_str(actual).lower()
    e = _as_str(expected).lower()
    if modifier == "" or modifier == "eq":
        return a == e
    if modifier == "contains":
        return e in a
    if modifier == "startswith":
        return a.startswith(e)
    if modifier == "endswith":
        return a.endswith(e)
    raise _Unsupported(f"value modifier {modifier!r}")


def _field_matches(event: LogEvent, key: str, expected: object) -> bool:
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

    if fname not in event.fields:
        return False
    actual = event.fields[fname]

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


def _selection_matches(event: LogEvent, selection: object) -> bool:
    """Evaluate one named selection against an event.
      * dict  -> ALL field entries must hold (AND);
      * list of dicts -> ANY sub-map holds (OR);
      * list of scalars -> keywords (free-text ANY).
    Anything else is unsupported (fail-closed)."""
    if isinstance(selection, dict):
        if not selection:
            return False          # an empty selection has no criteria — it must never fire (fail-closed)
        return all(_field_matches(event, str(k), v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(x, dict) for x in selection) and selection:
            return any(_selection_matches(event, sub) for sub in selection)
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


def rule_matches_event(rule: SigmaRule, event: LogEvent) -> bool:
    """Does this Sigma rule fire on this event? FAIL-CLOSED: a statically-unsupported rule, an
    unsupported modifier/selection encountered during evaluation, or an unparsable condition all
    yield ``False`` — never a fabricated detection. Pure and deterministic."""
    if not rule.supported:
        return False
    try:
        selresults = {name: _selection_matches(event, rule.detection[name])
                      for name in rule.selection_names}
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
                f"ATT&CK techniques detected: {', '.join(self.techniques_detected) or 'none'}")


def evaluate_events(rules: list[SigmaRule], events: list[LogEvent]) -> SigmaEvalResult:
    """Evaluate ``rules`` against ``events``. For each rule, record the FIRST event it fires on
    (a per-rule coverage signal, not an every-hit firehose). Deterministic: input order preserved,
    one pass. An unsupported rule is counted but never matches (fail-closed)."""
    result = SigmaEvalResult(rules_evaluated=len(rules), events_evaluated=len(events))
    for rule in rules:
        if not rule.supported:
            result.rules_unsupported += 1
            continue
        for i, ev in enumerate(events):
            if rule_matches_event(rule, ev):
                result.matches.append(SigmaMatch(
                    rule_id=rule.id, rule_title=rule.title, level=rule.level,
                    channel=ev.channel, event_index=i,
                    attack_techniques=rule.attack_techniques))
                break
    return result
