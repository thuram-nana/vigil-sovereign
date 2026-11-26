"""langplugins.base — the ``LanguagePlugin`` interface (MULTILANG-P1, plan §2.1).

A ``LanguagePlugin`` is the single object a language supplies so that adding a language LATER is a bounded,
additive unit — ``register()`` a plugin, with ZERO edits to the registry, the oracle, the single FACT mint
site, or the certificate. This module declares the interface (the six components of plan §2.1) plus the one
typed carrier the plan names but the codebase did not already own: :class:`PatternRule`.

The carriers the plan names that ALREADY exist are REUSED, never redefined:

  * ``Symbol``      — ``framework.v2.analysis.index.Symbol`` (the language-agnostic symbol shape).
  * ``BuildPlan``   — ``vigil_integration.remediation.buildsys.BuildPlan`` (the compile-floor + test recipe).
  * ``FetchResult`` — ``vigil_integration.remediation.depfetch.FetchResult`` (the gated host-side fetch result).

Those three are referenced ONLY as string annotations (``from __future__ import annotations`` +
``TYPE_CHECKING``), so importing this module pulls NEITHER ``framework`` NOR the remediation modules at module
scope — the interface is import-clean and offense-plane-lazy (FATAL-2). A plugin's own methods import what they
need function-locally.

Phase boundary (MULTILANG-P1): the FACT-path hooks — ``detect`` / ``extensions`` / ``manifests`` /
``parse`` / ``parse_symbols`` / ``retain_region`` / ``static_tier_predicate`` / ``fact_capable_rule_ids`` —
are FULLY implemented by the Python reference plugin (they back the signed-certificate re-parse). The
build / depfetch / rule / graph hooks are phase-1 thin delegations or documented deferrals; see
``python_plugin`` for the per-hook choice.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # import-clean: these are string annotations only, never imported at module scope
    from pathlib import Path

    from framework.v2.analysis.index import Symbol
    from ..remediation.buildsys import BuildPlan
    from ..remediation.depfetch import FetchResult


@dataclass(frozen=True)
class PatternRule:
    """A per-language DAA regex rule carrier (plan §2.4). Mirrors the SHAPE of the existing
    ``analysis.analyzers.builtin._Rule`` so a plugin can expose the builtin ruleset's per-extension entries
    WITHOUT the builtin analyzer having to change — the merged set stays byte-identical to today's ``_RULES``.
    ``pattern`` is kept as the raw regex SOURCE string (not a compiled ``re.Pattern``) so this carrier is
    hashable/frozen and framework-free; the consumer compiles it. ``extensions`` empty means "all"."""

    rule_id: str
    severity: str
    pattern: str
    message: str
    cwe: str
    extensions: frozenset[str] = frozenset()


class LanguagePlugin(abc.ABC):
    """One language's bounded, additive unit (plan §2.1). The registry is the ONLY new dispatch point; every
    scattered per-language site becomes a thin call into ``registry.for_path`` / ``registry.for_language``.

    A plugin supplies the six components:

      (1) detection — ``id`` / ``extensions`` / ``manifests`` / ``detect(path)``;
      (2) parse     — ``parse(source)`` (the re-parse substrate, the oracle's CST), ``parse_symbols`` (→ the
                      agnostic ``Symbol`` shape), ``retain_region`` (import-provenance + enclosing decl);
      (3) rules     — ``taint_ruleset_dir`` (semgrep YAML dir) / ``pattern_rules`` (DAA regex, per-ext);
      (4) build     — ``build_plan`` / ``offline_install`` / ``depfetch`` (the sandbox recipe);
      (5) oracle    — ``static_tier_predicate(rule_id, cst)`` + ``fact_capable_rule_ids`` (the FACT re-derivation);
      (6) PCR fix   — ``graph_context`` (cross-file neighborhood).

    Determinism: ``parse`` / ``static_tier_predicate`` / ``retain_region`` add NO wallclock or RNG — they are
    pure functions of the retained bytes, so a confirmed FACT re-verifies offline exactly like today's ``ast``
    path. Fail-closed: an unparseable region / an unregistered language → the caller REFUSES → a LEAD, never a
    crash and never a false FACT.
    """

    # (1) detection ---------------------------------------------------------------------------------------
    id: str
    """The canonical language id, e.g. ``"python"``. Used by ``registry.for_language`` and as the signal's
    ``language`` label."""

    extensions: "frozenset[str]"
    """The source-file extensions this language owns (incl. the leading dot), e.g. ``frozenset({".py"})``."""

    manifests: "frozenset[str]"
    """The ecosystem manifest basenames, e.g. ``frozenset({"pyproject.toml", "requirements.txt"})``."""

    @abc.abstractmethod
    def detect(self, path: str) -> bool:
        """True iff ``path`` is a source file this plugin owns (by extension). PURE + TOTAL — a hostile /
        empty path must return ``False``, never raise (mirrors buildsys's hostile-repo totality)."""

    # (2) parse / retain ----------------------------------------------------------------------------------
    @abc.abstractmethod
    def parse(self, source: str, path: str = "") -> Any:
        """Re-parse ``source`` into the language's concrete/abstract syntax tree — the CST the FACT oracle
        re-derives a code property from (Python: stdlib ``ast``; other languages: tree-sitter, a phase-2
        concern). May raise ``SyntaxError`` / ``ValueError`` on unparseable bytes; the caller treats that as a
        REFUSE (a LEAD), never a crash."""

    @abc.abstractmethod
    def parse_symbols(self, source: str, path: str) -> "list[Symbol]":
        """Emit the language-agnostic ``Symbol`` shape (kind ∈ {function,class,import,call}) for ``source``.
        An unparseable region yields ``[]`` (no symbols), never a raise."""

    @abc.abstractmethod
    def retain_region(self, source: str, line: int) -> str:
        """The RETAINED source region the FACT oracle re-parses offline: the module's import statements (the
        provenance the oracle resolves) + the enclosing top-level declaration at ``line``, concatenated so the
        region re-parses standalone. Fail-closed: an unparseable module falls back to the whole source, then a
        one-line snippet — the oracle then REFUSES → a LEAD, never a crash. The retained bytes travel verbatim
        into the cert, so a tamper that removes the property no longer re-fires."""

    # (3) rules -------------------------------------------------------------------------------------------
    @abc.abstractmethod
    def taint_ruleset_dir(self) -> "Path | None":
        """The directory holding this plugin's semgrep taint YAML(s), or ``None`` if the language ships none.
        The semgrep adapter is handed the UNION of registered rulesets (semgrep is already multi-language)."""

    @abc.abstractmethod
    def pattern_rules(self) -> "tuple[PatternRule, ...]":
        """This plugin's DAA regex rules (the grade-(1) pattern analyzer's per-extension entries). The merged
        set across plugins is byte-identical to today's ``builtin._RULES``."""

    # (4) build / sandbox recipe --------------------------------------------------------------------------
    @abc.abstractmethod
    def build_plan(self, repo: str) -> "BuildPlan":
        """The dependency-free compile/syntax floor + the real test command for ``repo`` (the deep-fix build
        gate, Axis A). PURE + TOTAL over a hostile repo (mirrors buildsys totality)."""

    @abc.abstractmethod
    def offline_install(self, plan: "BuildPlan", cache_in_box: str) -> str:
        """The ``/bin/sh -c`` string that installs OFFLINE from the mounted read-only cache then runs the
        suite (mirrors ``compose_offline_test_command``)."""

    @abc.abstractmethod
    def depfetch(self, repo: str, cache_dir: str) -> "FetchResult":
        """The GATED host-side dependency fetch into ``cache_dir`` (``VIGIL_EGRESS_GUARD``, fail-closed).
        TOTAL — a failure is a ``FetchResult(ok=False, …)``, never a raise."""

    # (5) oracle mapping (the FACT re-derivation) ---------------------------------------------------------
    @property
    @abc.abstractmethod
    def fact_capable_rule_ids(self) -> "frozenset[str]":
        """The subset of the CLOSED static-rule vocabulary this language can SOUNDLY re-derive as a
        single-region call-shape + import-provenance property — the ONLY rule_ids that can mint a STATIC_RULE
        FACT for this language. Everything else (inter-procedural taint, provenance-free randomness) stays
        LEAD-only in EVERY language."""

    @abc.abstractmethod
    def static_tier_predicate(self, rule_id: str, cst: Any) -> "tuple[bool, str]":
        """Re-derive the FACT-capable tier property for ``rule_id`` over the re-parsed ``cst`` (from
        :meth:`parse`). Returns ``(fired, detail)``. A ``rule_id`` outside :attr:`fact_capable_rule_ids`
        returns ``(False, "")``. PURE + deterministic, so the same verdict re-verifies offline."""

    # (6) PCR fix support ---------------------------------------------------------------------------------
    @abc.abstractmethod
    def graph_context(self, repo: str, file: str) -> "list[str]":
        """The cross-file neighborhood (import / caller graph) for ``file`` in ``repo`` that feeds the coder.
        Everything else in the PCR fix (``git apply``, the negative cert) is reused agnostically."""


__all__ = ["LanguagePlugin", "PatternRule"]
