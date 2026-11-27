"""langplugins.python_plugin — the Python reference plugin (MULTILANG-P1, plan §3.1).

Python is the FIRST plugin and the refactor safety net: its FACT-path methods REUSE the existing Python
logic VERBATIM (they call the existing functions, they do not reimplement them), so routing the Python FACT
path through this plugin is a BYTE-IDENTICAL refactor of the direct ``ast`` path. It adds NO new dependency —
Python uses the stdlib ``ast``; tree-sitter is a phase-2 concern and is never imported here.

FATAL-2: every ``framework`` import is FUNCTION-LOCAL (offense-plane, lazy). Importing this module pulls
neither ``framework`` nor ``tree_sitter``.

Per-hook phase-1 choice (plan §2.1 — the build/graph/rule hooks are phase-1 thin delegations or documented
deferrals; the FACT-path hooks are fully implemented):

  FACT-path (fully implemented, byte-identical reuse):
    * ``detect`` / ``extensions`` / ``manifests`` — ``.py`` + the Python ecosystem manifests.
    * ``parse``               — stdlib ``ast.parse`` (the oracle's re-parse substrate).
    * ``parse_symbols``       — shares ``analysis.index.symbols_from_source`` (the ``ast`` -> ``Symbol`` walk).
    * ``retain_region``       — shares ``codescan._retain_region_from_text`` (import-provenance + enclosing
                                decl, with the same fail-closed whole-source fallback).
    * ``static_tier_predicate`` — calls ``verify.oracles._static_tier_hit`` (the two FACT-capable tiers).
    * ``fact_capable_rule_ids`` — IS ``verify.oracles._FACT_RULE_IDS`` (never re-listed here).

  Non-FACT hooks (phase-1 thin delegation to the existing per-language function — NO logic migrated):
    * ``build_plan``     -> ``remediation.buildsys.detect_build_plan``.
    * ``offline_install``-> ``remediation.buildsys.compose_offline_test_command``.
    * ``depfetch``       -> ``remediation.depfetch.fetch_deps`` (gated host-side fetch).
    * ``graph_context``  -> ``remediation.graph_context.graph_context_paths``.
    * ``taint_ruleset_dir`` -> the shipped ``framework/v2/analysis/rules`` dir (holds ``taint-python.yaml``).
    * ``pattern_rules``  -> a READ-ONLY view over ``analysis.analyzers.builtin._RULES`` (python-applicable).
      The per-plugin migration of ``_RULES`` is a LATER phase; phase-1 exposes a view so the merged set stays
      byte-identical to today's ``_RULES``.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Any

from .base import LanguagePlugin, PatternRule

if TYPE_CHECKING:
    from pathlib import Path

    from framework.v2.analysis.index import Symbol
    from ..remediation.buildsys import BuildPlan
    from ..remediation.depfetch import FetchResult


class PythonPlugin(LanguagePlugin):
    """The Python reference plugin. FACT-path methods reuse the existing Python logic; non-FACT hooks are
    thin delegations to the existing per-language functions (see the module docstring)."""

    id = "python"
    extensions = frozenset({".py"})
    manifests = frozenset({
        "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
        "Pipfile", "poetry.lock", "Pipfile.lock",
    })

    # (1) detection ---------------------------------------------------------------------------------------
    def detect(self, path: str) -> bool:
        return str(path or "").lower().endswith(".py")

    # (2) parse / retain (FACT path — byte-identical reuse) -----------------------------------------------
    def parse(self, source: str, path: str = "") -> Any:
        # The oracle's re-parse substrate: the IDENTICAL call the direct path makes (``ast.parse``). Raises
        # SyntaxError / ValueError on unparseable bytes, which the oracle treats as a REFUSE (a LEAD).
        return ast.parse(source)

    def parse_symbols(self, source: str, path: str) -> "list[Symbol]":
        # Share the existing ``ast`` -> ``Symbol`` walk (framework.v2.analysis.index) — do NOT reimplement it.
        from framework.v2.analysis.index import symbols_from_source  # noqa: PLC0415 (FATAL-2: framework-free offense plugin)
        symbols, _err = symbols_from_source(source, path)
        return symbols

    def retain_region(self, source: str, line: int) -> str:
        # Share the existing import-provenance + enclosing-decl retention (codescan._retain_region_from_text),
        # including its fail-closed whole-source fallback — do NOT reimplement it.
        from ..codescan import _retain_region_from_text  # noqa: PLC0415 (FATAL-2: framework-free offense plugin, offense-plane sibling)
        return _retain_region_from_text(source, line)

    # (5) oracle mapping (FACT re-derivation — byte-identical reuse) --------------------------------------
    @property
    def fact_capable_rule_ids(self) -> "frozenset[str]":
        # IS the oracle's own FACT-capable set — lazy so the attribute never pulls ``framework`` at import.
        from framework.v2.verify.oracles import _FACT_RULE_IDS  # noqa: PLC0415 (FATAL-2: framework-free offense plugin)
        return _FACT_RULE_IDS

    def static_tier_predicate(self, rule_id: str, cst: Any) -> "tuple[bool, str]":
        # Call the EXISTING tier dispatch — do NOT copy the predicate bodies.
        from framework.v2.verify.oracles import _static_tier_hit  # noqa: PLC0415 (FATAL-2: framework-free offense plugin)
        return _static_tier_hit(rule_id, cst)

    # (3) rules (phase-1 thin delegation / view) ----------------------------------------------------------
    def taint_ruleset_dir(self) -> "Path | None":
        # The shipped semgrep rules dir (holds ``taint-python.yaml``); thin, no logic. ``rules/`` is a plain
        # data dir (no ``__init__``), so locate it from the ``analysis`` PACKAGE's ``__file__``.
        from pathlib import Path  # noqa: PLC0415 — stdlib, lazy to keep the module import-clean
        try:
            from framework.v2 import analysis as _analysis  # noqa: PLC0415 (FATAL-2: framework-free offense plugin)
            base = Path(_analysis.__file__).resolve().parent / "rules"
        except Exception:  # noqa: BLE001 — layout differs / framework absent ⇒ no ruleset to point at
            return None
        yaml = base / "taint-python.yaml"
        return base if yaml.is_file() else None

    def pattern_rules(self) -> "tuple[PatternRule, ...]":
        # A READ-ONLY VIEW over the builtin DAA ruleset, filtered to the entries that apply to Python (empty
        # extensions == all-languages). Phase-1 does NOT migrate ``_RULES`` into the plugin — the builtin
        # analyzer still OWNS it; this view exists so a later phase can consolidate without a behavior change.
        from framework.v2.analysis.analyzers.builtin import _RULES  # noqa: PLC0415 (FATAL-2: framework-free offense plugin)
        out: list[PatternRule] = []
        for r in _RULES:
            exts = frozenset(r.extensions)
            if exts and ".py" not in exts:
                continue
            out.append(PatternRule(
                rule_id=r.rule_id, severity=r.severity, pattern=r.pattern.pattern,
                message=r.message, cwe=r.cwe, extensions=exts,
            ))
        return tuple(out)

    # (4) build / sandbox recipe (phase-1 thin delegation) ------------------------------------------------
    def build_plan(self, repo: str) -> "BuildPlan":
        from ..remediation.buildsys import detect_build_plan  # noqa: PLC0415 — offense-plane sibling, lazy
        return detect_build_plan(repo)

    def offline_install(self, plan: "BuildPlan", cache_in_box: str) -> str:
        from ..remediation.buildsys import compose_offline_test_command  # noqa: PLC0415 — offense-plane sibling, lazy
        return compose_offline_test_command(plan, cache_dir_in_box=cache_in_box)

    def depfetch(self, repo: str, cache_dir: str) -> "FetchResult":
        from ..remediation.buildsys import detect_build_plan  # noqa: PLC0415 — offense-plane sibling, lazy
        from ..remediation.depfetch import fetch_deps  # noqa: PLC0415 — offense-plane sibling, lazy
        plan = detect_build_plan(repo)
        return fetch_deps(repo, cache_dir, install_specs=plan.install_specs)

    # (6) PCR fix support (phase-1 thin delegation) -------------------------------------------------------
    def graph_context(self, repo: str, file: str) -> "list[str]":
        from ..remediation.graph_context import graph_context_paths  # noqa: PLC0415 — offense-plane sibling, lazy
        paths = graph_context_paths(repo, file)
        return list(paths) if paths else []


__all__ = ["PythonPlugin"]
