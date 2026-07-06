"""
scanner.library — the declarative check library (Milestone-1 module B).

A check used to be Python code (see ``scanner.checks``: DifferentialCheck,
MarkerReflectionCheck, OOBCheck, TimingCheck). That is the right *engine*, but it
means every new bug class is a code change. This module turns "a check" into
DATA: a :class:`LibraryEntry` carries a payload, an oracle contract (which of the
four concrete check shapes runs it), and an applicability predicate — so coverage
scales to thousands of entries without touching the engine. Adding a class is
authoring one JSON file, not editing Python.

Three moving parts, all pure and deterministic:

  * **schema** — :class:`OracleSpec` (the payload + which concrete check runs it)
    and :class:`LibraryEntry` (id/class/title/severity + applicability +
    references + remediation). Pydantic v2, ``extra="forbid"``: a typo in an
    entry is a load-time error, never a silent no-op.
  * **loader** — :func:`load_library` reads every ``*.json`` under
    ``library_entries/``, validates each into a :class:`LibraryEntry`, and
    returns them sorted by id. A malformed file raises a clear
    :class:`LibraryError` naming the file.
  * **compiler** — :func:`compile_entry` binds an entry to the correct concrete
    :class:`~scanner.checks.Check` (differential -> DifferentialCheck, reflection
    -> MarkerReflectionCheck, oob -> OOBCheck, timing -> TimingCheck), carrying
    the entry's id and bug_class. The engine then runs the compiled check exactly
    as it runs a hand-written one, and the oracle layer — never this module —
    still adjudicates every confirmation.

Applicability is a tiny JSON predicate grammar evaluated against a fingerprint
token set: ``{"always": true}``, ``{"tech": "wordpress"}``, ``{"category":
"php"}``, ``{"any": [...]}``, ``{"all": [...]}``, ``{"not": pred}``. The
fingerprint that produces the tokens lives in a sibling module; this module is
decoupled from it — it evaluates against a plain ``set[str]``, so the two never
import each other.

Boundary: this module shapes and selects checks; it sends nothing. Every payload
here is a verification probe (a differential term, a unique canary marker, an OOB
callback token, a delay clause), rendered into an insertion point and issued only
through the engine's gated ``send``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ..common.errors import CrucibleError
from .checks import Check, DifferentialCheck, MarkerReflectionCheck, OOBCheck, TimingCheck
from .insertion import InsertionKind

# The seed entries ship next to this module so a default load needs no config.
LIBRARY_DIR: Path = Path(__file__).resolve().parent / "library_entries"

# The four concrete check shapes an entry's oracle can name.
ORACLE_KINDS: frozenset[str] = frozenset({"differential", "reflection", "oob", "timing"})

# Severities an entry may claim (aligns with the framework's finding template).
SEVERITIES: frozenset[str] = frozenset({"Critical", "High", "Medium", "Low", "Info"})

# Predicate operators supported by the applicability grammar.
_PREDICATE_OPS: frozenset[str] = frozenset({"always", "tech", "category", "any", "all", "not"})

# Canonical InsertionKind values, plus a name->value map so an entry may spell a
# kind either way ("query_value" or "QUERY_VALUE").
_KIND_VALUES: frozenset[str] = frozenset(k.value for k in InsertionKind)
_KIND_BY_NAME: dict[str, str] = {k.name: k.value for k in InsertionKind}


class LibraryError(CrucibleError):
    """A library entry (or a predicate) is malformed, unloadable, or invalid.

    A plain recoverable :class:`~common.errors.CrucibleError`: the library layer
    authors and selects checks, it makes no trust decision, so a bad entry is a
    data error, never an ethics-boundary crossing."""


# ---------------------------------------------------------------------------
# Applicability predicate grammar (decoupled from the fingerprinter)
# ---------------------------------------------------------------------------


def _validate_predicate(predicate: Any) -> None:
    """Structurally validate an ``applies_when`` predicate, raising
    :class:`LibraryError` if malformed. Walks EVERY branch (unlike the
    short-circuiting evaluator) so a nested error surfaces at load time, not on
    the first token set that happens to reach it.

    Empty (``{}``) and ``None`` are the "always applicable" degenerate cases and
    validate trivially."""
    if predicate is None:
        return
    if not isinstance(predicate, Mapping):
        raise LibraryError(f"predicate must be an object, got {type(predicate).__name__}")
    if len(predicate) == 0:
        return
    if len(predicate) != 1:
        raise LibraryError(
            f"predicate must be a single-operator object, got keys {sorted(predicate)}"
        )
    (op, arg), = predicate.items()
    if op not in _PREDICATE_OPS:
        raise LibraryError(
            f"unknown predicate operator {op!r}; expected one of {sorted(_PREDICATE_OPS)}"
        )
    if op == "always":
        if not isinstance(arg, bool):
            raise LibraryError(f"'always' takes a boolean, got {type(arg).__name__}")
        return
    if op in ("tech", "category"):
        if not isinstance(arg, str) or not arg:
            raise LibraryError(f"{op!r} takes a non-empty string token")
        return
    if op in ("any", "all"):
        if not isinstance(arg, list):
            raise LibraryError(f"{op!r} takes a list of predicates, got {type(arg).__name__}")
        for sub in arg:
            _validate_predicate(sub)
        return
    # op == "not"
    _validate_predicate(arg)


def _token_present(kind: str, value: str, tokens: set[str]) -> bool:
    """A token matches either bare (``wordpress``) or namespaced
    (``tech:wordpress``), so this stays compatible with a flat fingerprint token
    set and a namespaced one alike."""
    v = value.lower()
    return v in tokens or f"{kind}:{v}" in tokens


def _eval_predicate(predicate: Any, tokens: set[str]) -> bool:
    """Evaluate a (pre-validated, normalised-token) predicate. Internal — the
    public entry point is :func:`evaluate_predicate`."""
    if predicate is None or len(predicate) == 0:
        return True
    (op, arg), = predicate.items()
    if op == "always":
        return bool(arg)
    if op == "tech":
        return _token_present("tech", arg, tokens)
    if op == "category":
        return _token_present("category", arg, tokens)
    if op == "any":
        return any(_eval_predicate(p, tokens) for p in arg)
    if op == "all":
        return all(_eval_predicate(p, tokens) for p in arg)
    # op == "not"
    return not _eval_predicate(arg, tokens)


def evaluate_predicate(predicate: Any, tokens: set[str]) -> bool:
    """Evaluate an applicability ``predicate`` against a fingerprint ``tokens``
    set, returning whether the entry applies.

    Grammar (an empty ``{}`` or ``None`` predicate means "always applies"):

      ``{"always": true}``      unconditional (``false`` never applies)
      ``{"tech": "wordpress"}`` applies iff the token is present
      ``{"category": "php"}``   applies iff the token is present
      ``{"any": [p, ...]}``     applies iff ANY sub-predicate applies
      ``{"all": [p, ...]}``     applies iff EVERY sub-predicate applies
      ``{"not": p}``            applies iff the sub-predicate does not

    ``tech`` and ``category`` differ only in intent; both test set membership of
    their value (bare or ``kind:value``-namespaced) so the two decouple cleanly
    from whatever a fingerprinter emits. Raises :class:`LibraryError` on a
    malformed predicate — a validation error, never a silent False."""
    _validate_predicate(predicate)
    norm = {str(t).lower() for t in (tokens or set())}
    return _eval_predicate(predicate, norm)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class OracleSpec(BaseModel):
    """The payload + which of the four concrete check shapes runs it.

    ``kind`` selects the shape and therefore which params are required:

      ``differential`` boolean/logic differential -> DifferentialCheck.
                       Requires ``benign`` and ``probe``.
      ``reflection``   marker-reflection side-effect -> MarkerReflectionCheck.
                       Requires ``payload_template`` containing ``{marker}``.
      ``oob``          blind out-of-band callback -> OOBCheck.
                       Requires ``payload_template`` containing ``{callback}``.
      ``timing``       statistical time-based blind -> TimingCheck.
                       Requires ``benign``, ``sleep_payload`` and ``injected_ms``.

    Params irrelevant to the chosen ``kind`` stay unset. ``extra="forbid"`` means
    a stray param is a load error, and the after-validator enforces that the
    required params for the kind are present (and the ``{marker}``/``{callback}``
    placeholder is where the concrete check expects it)."""

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(description="One of: differential | reflection | oob | timing.")

    # differential + timing
    benign: str | None = Field(default=None, description="Benign control value (differential, timing).")
    # differential
    probe: str | None = Field(default=None, description="Probe payload for the differential.")
    # reflection ({marker}) + oob ({callback})
    payload_template: str | None = Field(
        default=None,
        description="Payload with a '{marker}' (reflection) or '{callback}' (oob) placeholder.",
    )
    # timing
    sleep_payload: str | None = Field(default=None, description="Delay-injecting payload (timing).")
    injected_ms: float | None = Field(default=None, description="Delay the timing payload induces, ms.")

    @model_validator(mode="after")
    def _check_shape(self) -> "OracleSpec":
        k = self.kind
        if k not in ORACLE_KINDS:
            raise ValueError(
                f"unknown oracle kind {k!r}; expected one of {sorted(ORACLE_KINDS)}"
            )
        if k == "differential":
            _require(self, "benign")
            _require(self, "probe")
        elif k == "reflection":
            _require(self, "payload_template")
            if "{marker}" not in self.payload_template:  # type: ignore[operator]
                raise ValueError("reflection payload_template must contain the '{marker}' placeholder")
        elif k == "oob":
            _require(self, "payload_template")
            if "{callback}" not in self.payload_template:  # type: ignore[operator]
                raise ValueError("oob payload_template must contain the '{callback}' placeholder")
        elif k == "timing":
            _require(self, "benign")
            _require(self, "sleep_payload")
            if self.injected_ms is None:
                raise ValueError("timing oracle requires 'injected_ms'")
            if self.injected_ms <= 0:
                raise ValueError("timing 'injected_ms' must be > 0")
        return self


def _require(spec: OracleSpec, field: str) -> None:
    value = getattr(spec, field)
    if value is None or (isinstance(value, str) and value == ""):
        raise ValueError(f"{spec.kind!r} oracle requires a non-empty {field!r}")


class LibraryEntry(BaseModel):
    """One declarative check: a bug class, its payload/oracle contract, and when
    it applies.

    A ready-to-compile entry — :func:`compile_entry` turns it into a runnable
    :class:`~scanner.checks.Check`. ``applies_when`` gates the entry against a
    fingerprint token set (see the predicate grammar); ``insertion_kinds`` scopes
    which positions it should target (empty = all — the engine decides), and is
    metadata the selector reads, not something the compiled check enforces
    itself. ``references`` carries CWE/CVE/CAPEC ids so a finding cites why."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, description="Stable, unique entry id (also the compiled check's id).")
    bug_class: str = Field(min_length=1, description="Canonical/aliased bug class; selects the oracle set.")
    title: str = Field(min_length=1, description="Human-readable name of the check.")
    severity: str = Field(description="One of: Critical | High | Medium | Low | Info.")
    applies_when: dict = Field(
        default_factory=lambda: {"always": True},
        description="Applicability predicate (see the grammar). Default: always.",
    )
    insertion_kinds: list[str] = Field(
        default_factory=list,
        description="InsertionKind values to scope to (empty = all). Metadata for the selector.",
    )
    oracle: OracleSpec = Field(description="The payload + which concrete check runs it.")
    references: list[str] = Field(
        default_factory=list, description="CWE/CVE/CAPEC ids justifying the class."
    )
    remediation: str = Field(default="", description="How to fix the class this check finds.")
    payload_family: str = Field(default="", description="Optional grouping tag for related payloads.")

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: str) -> str:
        if v not in SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(SEVERITIES)}, got {v!r}")
        return v

    @field_validator("insertion_kinds")
    @classmethod
    def _check_kinds(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for k in v:
            kk = str(k)
            if kk in _KIND_VALUES:
                out.append(kk)
            elif kk in _KIND_BY_NAME:
                out.append(_KIND_BY_NAME[kk])
            elif kk.upper() in _KIND_BY_NAME:
                out.append(_KIND_BY_NAME[kk.upper()])
            else:
                raise ValueError(
                    f"unknown insertion kind {kk!r}; valid values: {sorted(_KIND_VALUES)}"
                )
        return out

    @model_validator(mode="after")
    def _check_applies_when(self) -> "LibraryEntry":
        try:
            _validate_predicate(self.applies_when)
        except LibraryError as e:
            raise ValueError(str(e)) from e
        return self

    def applies(self, tokens: set[str]) -> bool:
        """Whether this entry applies to a target with the given fingerprint
        ``tokens``. A thin wrapper over :func:`evaluate_predicate`."""
        return evaluate_predicate(self.applies_when, tokens)


# ---------------------------------------------------------------------------
# Compiler — entry -> runnable Check
# ---------------------------------------------------------------------------


def compile_entry(entry: LibraryEntry) -> Check:
    """Bind ``entry`` to the concrete :class:`~scanner.checks.Check` its oracle
    kind names, carrying the entry's id and bug_class so a finding traces back to
    the entry that produced it. The oracle layer still adjudicates confirmation;
    this only wires the payload into the right runnable shape."""
    spec = entry.oracle
    kind = spec.kind
    if kind == "differential":
        return DifferentialCheck(
            id=entry.id, bug_class=entry.bug_class,
            benign=spec.benign, probe_payload=spec.probe,  # type: ignore[arg-type]
        )
    if kind == "reflection":
        return MarkerReflectionCheck(
            id=entry.id, bug_class=entry.bug_class,
            payload_template=spec.payload_template,  # type: ignore[arg-type]
        )
    if kind == "oob":
        return OOBCheck(
            id=entry.id, bug_class=entry.bug_class,
            payload_template=spec.payload_template,  # type: ignore[arg-type]
        )
    if kind == "timing":
        return TimingCheck(
            id=entry.id, bug_class=entry.bug_class,
            benign=spec.benign, sleep_payload=spec.sleep_payload,  # type: ignore[arg-type]
            injected_ms=spec.injected_ms,  # type: ignore[arg-type]
        )
    # OracleSpec validation makes this unreachable; kept as a defensive guard.
    raise LibraryError(f"unknown oracle kind {kind!r} in entry {entry.id!r}")


def compile_library(entries: Iterable[LibraryEntry]) -> list[Check]:
    """Compile a list of entries into runnable checks, order-preserving."""
    return [compile_entry(e) for e in entries]


# ---------------------------------------------------------------------------
# Loader + selection
# ---------------------------------------------------------------------------


def load_library(directory: str | Path = LIBRARY_DIR) -> list[LibraryEntry]:
    """Load every ``*.json`` entry under ``directory``, validate each into a
    :class:`LibraryEntry`, and return them sorted by id.

    Deterministic: files are read in sorted order and the result is sorted by id,
    so two runs over the same directory yield the same list. A file that is not
    valid JSON, or does not validate against the schema, raises a
    :class:`LibraryError` naming the file — a broken entry fails loudly, it does
    not silently drop. Duplicate ids across files are likewise an error."""
    path = Path(directory)
    if not path.is_dir():
        raise LibraryError(f"library directory not found: {path}")

    entries: list[LibraryEntry] = []
    for f in sorted(path.glob("*.json")):
        try:
            raw = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise LibraryError(f"could not read/parse library entry {f.name}: {e}") from e
        try:
            entries.append(LibraryEntry.model_validate(raw))
        except ValidationError as e:
            raise LibraryError(f"invalid library entry {f.name}: {e}") from e

    entries.sort(key=lambda e: e.id)
    ids = [e.id for e in entries]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise LibraryError(f"duplicate entry ids across the library: {dupes}")
    return entries


def select_entries(entries: Iterable[LibraryEntry], tokens: set[str]) -> list[LibraryEntry]:
    """The subset of ``entries`` whose :meth:`LibraryEntry.applies` is True for
    the fingerprint ``tokens`` — the fingerprint-gated selection the engine runs
    against a specific target. Always-on entries are always included."""
    tok = set(tokens)
    return [e for e in entries if e.applies(tok)]
