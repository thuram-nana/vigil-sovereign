#!/usr/bin/env python3
"""Generate DATA-GROUND-TRUTH.md from one code-grounded source of truth, and verify it never rots.

WHY THIS EXISTS. ``DATA-GROUND-TRUTH.md`` is the data-at-rest / egress declaration a reviewer reads
first: where sensitive data lands on disk, in what form, and what can be done to it. Nothing kept it
true of the code, and it had already been contradicted once by a moved key path (W0-4 #399). A map a
reader carries to a national agency cannot be maintained by hand and hoped to stay equal to the code.

THE DESIGN (mirrors ``docs/capability-matrix/gen_coverage_tiers.py``). The map lives once, in
``docs/data-ground-truth/data-stores.json``. This module renders the two tables of
``DATA-GROUND-TRUTH.md`` from that file, between HTML-comment markers, and — crucially — GROUNDS the
source of truth against the code that actually performs each egress:

  * Every on-disk STORE names the ``paths.py`` / ``blackboard.py`` sink it writes to, plus the code
    symbols (path resolvers, the redactor, the crypto-shred keyring, the payload excerpt fields) its
    prose cites. Each symbol must be DEFINED (pure AST, no import); each cited env override / SQL
    trigger / ``.dek`` literal must be PRESENT in its file; each named CLI verb must be a real verb.
  * COMPLETENESS is the teeth. The set of credential/state sinks is DISCOVERED from the code by AST
    (every ``<root>() / ".<hidden>"`` and every ``.../"evidence"`` under a per-engagement root). Each
    discovered sink must be EITHER a documented store OR carried in the ``out_of_scope`` ledger with a
    stated reason. A NEW sink that code grows and the declaration omits is UNACCOUNTED -> the guard
    goes red. That is acceptance criterion "CI fails when a new egress site exists that the
    declaration does not describe", and its negative control.

GROUNDING READS SOURCE TEXT (``--check`` / :func:`validate`). ``models.py`` / ``paths.py`` etc. are
parsed by AST over their SOURCE TEXT; this module imports NEITHER trust domain and uses only the
standard library, so it is safe in the reads-only ``the briefing explains every agent and capability``
CI leg (which installs only pytest) and cannot pull an offensive module into a sovereign process.

    python3 docs/data-ground-truth/gen_data_ground_truth.py            # write the blocks into the doc
    python3 docs/data-ground-truth/gen_data_ground_truth.py --check    # fail on any drift (no writes)
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent            # docs/data-ground-truth
_REPO = _HERE.parents[1]                            # repo root
_SOURCE = _HERE / "data-stores.json"
_DOC = _REPO / "DATA-GROUND-TRUTH.md"

# The path-building calls whose string operand names a real on-disk sink. A per-engagement root
# (``target_dir`` / ``_write_target_dir``) or the framework state root (``v2_root``); ``crucible_root``
# is included so a future top-level store is not missed.
_ROOT_PRODUCERS = {"v2_root", "_write_target_dir", "target_dir", "crucible_root"}

# Main store table.
BEGIN = ("<!-- BEGIN GENERATED data-ground-truth (source: docs/data-ground-truth/data-stores.json; "
         "regenerate: python3 docs/data-ground-truth/gen_data_ground_truth.py) -->")
END = "<!-- END GENERATED data-ground-truth -->"
# Out-of-scope accounting table (every discovered sink deliberately NOT in the credential map).
BEGIN_OOS = ("<!-- BEGIN GENERATED data-ground-truth-oos (source: "
             "docs/data-ground-truth/data-stores.json) -->")
END_OOS = "<!-- END GENERATED data-ground-truth-oos -->"


class DriftError(Exception):
    """The source of truth or the document is out of step with the code."""


# ---------------------------------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------------------------------
def load_source() -> dict:
    return json.loads(_SOURCE.read_text(encoding="utf-8"))


def _engine(source: dict) -> Path:
    return _REPO / source["engine_root"]


# ---------------------------------------------------------------------------------------------------
# Sink DISCOVERY — the credential/state sinks the code actually writes to, by AST over source text.
# A sink is the string operand of a ``<root_producer>() / "<name>"`` division where ``name`` begins
# with "." (a hidden state dir/file) or equals "evidence" (the raw-HTTP credential archive).
# ---------------------------------------------------------------------------------------------------
def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            return f.attr
    return None


def _left_spine_has_root(binop: ast.BinOp) -> bool:
    for sub in ast.walk(binop):
        if _call_name(sub) in _ROOT_PRODUCERS:
            return True
    return False


def sinks_in_text(text: str) -> set[str]:
    """The set of sink names a source file declares. Pure AST; usable on synthetic text in tests."""
    tree = ast.parse(text)
    found: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)):
            lit = node.right.value
            if (lit.startswith(".") or lit == "evidence") and _left_spine_has_root(node):
                found.add(lit)
    return found


def discover_sinks(source: dict | None = None) -> set[str]:
    source = source if source is not None else load_source()
    eng = _engine(source)
    out: set[str] = set()
    for rel in source["sink_sources"]:
        p = eng / rel
        if not p.is_file():
            raise DriftError(f"sink source {rel} not found under {source['engine_root']}")
        out |= sinks_in_text(p.read_text(encoding="utf-8"))
    if not out:
        raise DriftError("no on-disk sinks discovered — the AST rule or the source files changed shape")
    return out


# ---------------------------------------------------------------------------------------------------
# Symbol resolution — top-level function/class/assign, descending only through classes. Pure AST.
# ---------------------------------------------------------------------------------------------------
def _find_symbol(body: list, parts: list[str]) -> bool:
    head, rest = parts[0], parts[1:]
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == head:
            if not rest:
                return True
            return isinstance(node, ast.ClassDef) and _find_symbol(node.body, rest)
        if not rest and isinstance(node, ast.Assign):
            for tgt in node.targets:
                names = [tgt] if isinstance(tgt, ast.Name) else (
                    list(tgt.elts) if isinstance(tgt, (ast.Tuple, ast.List)) else [])
                if any(isinstance(n, ast.Name) and n.id == head for n in names):
                    return True
        if (not rest and isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name) and node.target.id == head):
            return True
    return False


def symbol_defined(engine: Path, file_rel: str, dotted: str) -> bool:
    p = engine / file_rel
    if not p.is_file():
        return False
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError:
        return False
    return _find_symbol(tree.body, dotted.split("."))


def _text_contains(engine: Path, file_rel: str, needle: str) -> bool:
    p = engine / file_rel
    return p.is_file() and needle in p.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------------------------------
# The load-bearing grounding check. Raises DriftError on any mismatch; returns the discovered sinks.
# ---------------------------------------------------------------------------------------------------
def validate(source: dict | None = None, *, discovered: set[str] | None = None) -> set[str]:
    source = source if source is not None else load_source()
    eng = _engine(source)
    discovered = discovered if discovered is not None else discover_sinks(source)

    stores = source["stores"]
    ids = [s["id"] for s in stores]
    if len(ids) != len(set(ids)):
        raise DriftError("data-stores.json lists a store id twice")

    # Every store's cited symbols / env overrides / literals / CLI verbs must be real.
    for s in stores:
        for sym in s.get("symbols", []):
            if not symbol_defined(eng, sym["file"], sym["symbol"]):
                raise DriftError(f"store {s['id']!r}: symbol {sym['symbol']!r} not defined in {sym['file']}")
        for env in s.get("env_overrides", []):
            if not _text_contains(eng, env["file"], env["name"]):
                raise DriftError(f"store {s['id']!r}: env override {env['name']!r} not read in {env['file']}")
        for lit in s.get("literals", []):
            if not _text_contains(eng, lit["file"], lit["text"]):
                raise DriftError(f"store {s['id']!r}: literal {lit['text']!r} not present in {lit['file']}")
        for verb in s.get("cli_verbs", []):
            if not _text_contains(eng, source["cli_source"], f'"{verb}"'):
                raise DriftError(f"store {s['id']!r}: CLI verb {verb!r} is not a dispatch verb in "
                                 f"{source['cli_source']}")

    # The out-of-scope ledger must name real sinks with real symbols and a stated reason.
    for oos in source["out_of_scope"]:
        if not oos.get("reason", "").strip():
            raise DriftError(f"out-of-scope sink {oos['sink']!r} has no stated reason")
        if not symbol_defined(eng, oos["file"], oos["symbol"]):
            raise DriftError(f"out-of-scope sink {oos['sink']!r}: symbol {oos['symbol']!r} not defined "
                             f"in {oos['file']}")

    # COMPLETENESS (the teeth): discovered sinks == documented sinks + out-of-scope sinks, exactly.
    documented = {sk for s in stores for sk in s["sinks"]}
    excluded = {oos["sink"] for oos in source["out_of_scope"]}
    accounted = documented | excluded
    if len(documented) + len(excluded) != len(accounted):
        raise DriftError(f"a sink is both documented and out-of-scope: {sorted(documented & excluded)}")
    unaccounted = discovered - accounted
    if unaccounted:
        raise DriftError(
            "on-disk sink(s) the declaration does not describe (document them in a store row, or list "
            f"them in out_of_scope with a reason): {sorted(unaccounted)}")
    phantom = accounted - discovered
    if phantom:
        raise DriftError(f"data-stores.json accounts for sink(s) no code declares any more: {sorted(phantom)}")

    # The cross-check test the doc names must exist.
    if not (_REPO / source["cross_check_test"]).is_file():
        raise DriftError(f"cross-check test missing: {source['cross_check_test']}")
    return discovered


# ---------------------------------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------------------------------
def render_main(source: dict | None = None) -> str:
    source = source if source is not None else load_source()
    lines = [
        BEGIN,
        "| Data | Location | Contains credentials? | At-rest form | Mutable? | Erasure |",
        "|------|----------|-----------------------|--------------|----------|---------|",
    ]
    for s in source["stores"]:
        lines.append(f"| {s['data']} | {s['location']} | {s['credentials']} | {s['at_rest']} | "
                     f"{s['mutable']} | {s['erasure']} |")
    lines.append(END)
    return "\n".join(lines)


def render_oos(source: dict | None = None) -> str:
    source = source if source is not None else load_source()
    lines = [
        BEGIN_OOS,
        "| On-disk store | Resolver | Why it is not in the credential map above |",
        "|---------------|----------|-------------------------------------------|",
    ]
    for oos in sorted(source["out_of_scope"], key=lambda o: o["sink"]):
        loc = f"`{oos['sink']}`"
        sym = f"`{oos['symbol']}`"
        lines.append(f"| {loc} | {sym} | {oos['reason']} |")
    lines.append(END_OOS)
    return "\n".join(lines)


def _extract_region(text: str, begin: str, end: str, path: Path) -> str:
    i = text.find(begin)
    j = text.find(end)
    if i == -1 or j == -1 or j < i:
        raise DriftError(f"{path}: markers {begin[:40]}… not found — cannot locate the generated block")
    return text[i:j + len(end)]


def _replace_region(text: str, block: str, begin: str, end: str, path: Path) -> str:
    return text.replace(_extract_region(text, begin, end, path), block)


# ---------------------------------------------------------------------------------------------------
# check() / write() / main()
# ---------------------------------------------------------------------------------------------------
def check() -> list[str]:
    """Return a list of drift messages; empty means the source is grounded AND the doc is in sync."""
    problems: list[str] = []
    try:
        source = load_source()
        validate(source)                       # grounding: raises DriftError on any mismatch
        main_block = render_main(source)
        oos_block = render_oos(source)
    except DriftError as exc:
        return [str(exc)]
    try:
        text = _DOC.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{_DOC}: {exc}"]
    for block, begin, end in ((main_block, BEGIN, END), (oos_block, BEGIN_OOS, END_OOS)):
        try:
            region = _extract_region(text, begin, end, _DOC)
        except DriftError as exc:
            problems.append(str(exc))
            continue
        if region != block:
            problems.append(f"{_DOC.name}: a generated block has drifted from the source of truth — "
                            "run gen_data_ground_truth.py")
    return problems


def write() -> None:
    source = load_source()
    validate(source)
    text = _DOC.read_text(encoding="utf-8")
    text = _replace_region(text, render_main(source), BEGIN, END, _DOC)
    text = _replace_region(text, render_oos(source), BEGIN_OOS, END_OOS, _DOC)
    _DOC.write_text(text, encoding="utf-8")
    print(f"updated {_DOC.relative_to(_REPO)}")


def main(argv: list[str]) -> int:
    if "--check" in argv:
        problems = check()
        if problems:
            print("data-ground-truth DRIFT:", file=sys.stderr)
            for p in problems:
                print("  - " + p, file=sys.stderr)
            return 1
        print("data-ground-truth: source of truth is grounded in code and the document is in sync.")
        return 0
    write()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
