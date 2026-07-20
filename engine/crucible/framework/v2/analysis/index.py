"""
analysis.index — a queryable Python symbol index over AST.

Where the pattern analyzer finds suspicious *lines*, the symbol index
gives the reasoning kernel *structure*: where functions and classes are
defined, what is imported, and where a given callee is invoked. That is
what lets a hypothesis like "user input reaches a subprocess call" be
grounded in real call sites rather than guessed.

Python-only (uses the stdlib `ast`). Other languages would need their
own parser; the `Symbol` shape is language-agnostic so they can be added
behind the same index.
"""

from __future__ import annotations

import ast
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .models import AnalysisTarget


class Symbol(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(description="function | class | import | call")
    name: str
    path: str
    line: int = Field(ge=0)
    detail: str = ""


class SymbolIndex(BaseModel):
    """An immutable index of symbols with lookup helpers."""

    model_config = ConfigDict(extra="forbid")

    symbols: list[Symbol] = Field(default_factory=list)
    files_indexed: int = 0
    parse_errors: list[str] = Field(default_factory=list)

    def of_kind(self, kind: str) -> list[Symbol]:
        return [s for s in self.symbols if s.kind == kind]

    def find_function(self, name: str) -> list[Symbol]:
        return [s for s in self.symbols if s.kind == "function" and s.name == name]

    def find_callsites(self, callee: str) -> list[Symbol]:
        return [s for s in self.symbols if s.kind == "call" and s.name == callee]

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for s in self.symbols:
            out[s.kind] = out.get(s.kind, 0) + 1
        return out


def _callee_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _index_file(path: Path, rel: str) -> tuple[list[Symbol], str | None]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [], f"{rel}: read error {e}"
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [], f"{rel}: syntax error line {e.lineno}"

    symbols: list[Symbol] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append(Symbol(
                kind="function", name=node.name, path=rel, line=node.lineno,
                detail=f"{len(node.args.args)} positional arg(s)",
            ))
        elif isinstance(node, ast.ClassDef):
            methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            symbols.append(Symbol(
                kind="class", name=node.name, path=rel, line=node.lineno,
                detail=f"{len(methods)} method(s)",
            ))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                symbols.append(Symbol(kind="import", name=alias.name, path=rel, line=node.lineno))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                symbols.append(Symbol(
                    kind="import", name=f"{mod}.{alias.name}" if mod else alias.name,
                    path=rel, line=node.lineno,
                ))
        elif isinstance(node, ast.Call):
            name = _callee_name(node)
            if name:
                symbols.append(Symbol(kind="call", name=name, path=rel, line=node.lineno))
    return symbols, None


def build_symbol_index(target: AnalysisTarget) -> SymbolIndex:
    """Index every Python file under the target."""
    root = Path(target.root).expanduser()
    all_symbols: list[Symbol] = []
    errors: list[str] = []
    indexed = 0
    for path in target.iter_files():
        if path.suffix != ".py":
            continue
        try:
            rel = str(path.relative_to(root)) if root.is_dir() else path.name
        except ValueError:
            rel = str(path)
        symbols, err = _index_file(path, rel)
        if err is not None:
            errors.append(err)
            continue
        all_symbols.extend(symbols)
        indexed += 1
    all_symbols.sort(key=lambda s: (s.path, s.line, s.kind, s.name))
    return SymbolIndex(symbols=all_symbols, files_indexed=indexed, parse_errors=errors)
