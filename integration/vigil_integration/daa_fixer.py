"""daa_fixer — DETERMINISTIC, key-free fixes for DAA static findings.

For the mechanical DAA rules (weak hash, yaml.load, eval, subprocess shell=True, TLS verify=False,
debug=True, DOM innerHTML, and a hard-coded secret assignment) the canonical fix is a one-line source
transform. This module produces that fix as a minimal unified diff WITHOUT any LLM — so a codebase fix
needs no API key AND is free of the model-diff apply fragility (wrong / bare ``@@`` hunk headers, drifting
context) that makes a proposed patch fail ``git apply``. The diff is generated with
:func:`difflib.unified_diff` over the real file content, so it always applies cleanly.

Rules with no safe mechanical fix return ``None`` (``pickle``/``exec`` need a redesign) — the caller then
falls back to the inline LLM coder, unchanged.

SAFETY: this only PROPOSES a diff. It is still parsed fail-closed (``parse_unified_diff``), applied only to
a DISPOSABLE clone through the SAME gated ladder, and verified by re-running the DAA rule. It changes what
gets proposed, never the gate/clone/verify envelope. Deterministic and pure: no wallclock, no RNG, no net.
"""
from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any, Callable, Optional

# One transform per rule_id. Each takes the matched source LINE (without newline) and returns the fixed
# line, or None when this particular line does not actually carry the pattern (so we never emit a no-op).
_LINE_FIX: dict[str, Callable[[str], Optional[str]]] = {}


def _sub_if_changed(pattern: str, repl: str, *, flags: int = 0) -> Callable[[str], Optional[str]]:
    rx = re.compile(pattern, flags)

    def _fix(line: str) -> Optional[str]:
        new = rx.sub(repl, line)
        return new if new != line else None

    return _fix


# NAME = "literal"  ->  NAME = os.environ.get("NAME")   (keeps indentation + any trailing comment)
_SECRET_ASSIGN = re.compile(r'^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*[:=]\s*)(["\']).*?\4\s*(#.*)?$')


def _secret_fix(line: str) -> Optional[str]:
    m = _SECRET_ASSIGN.match(line)
    if not m:
        return None
    indent, name, assign, _q, comment = m.groups()
    out = f'{indent}{name}{assign}os.environ.get("{name}")'
    if comment:
        out += "  " + comment
    return out if out != line else None


_LINE_FIX["DAA-WEAK-HASH"] = _sub_if_changed(r"\b(md5|sha1)\b", "sha256")
_LINE_FIX["DAA-YAML-LOAD"] = _sub_if_changed(r"\byaml\.load\s*\(", "yaml.safe_load(")
_LINE_FIX["DAA-SHELL-TRUE"] = _sub_if_changed(r"shell\s*=\s*True", "shell=False")
_LINE_FIX["DAA-TLS-VERIFY-OFF"] = _sub_if_changed(r"verify\s*=\s*False", "verify=True")
_LINE_FIX["DAA-DEBUG-TRUE"] = _sub_if_changed(r"(?i)(\bdebug\s*=\s*)True", r"\1False")
_LINE_FIX["DAA-MD-INNERHTML"] = _sub_if_changed(r"\.innerHTML(\s*=)", r".textContent\1")
_LINE_FIX["DAA-EVAL"] = _sub_if_changed(r"\beval\s*\(", "ast.literal_eval(")
_LINE_FIX["DAA-SECRET"] = _secret_fix

# stdlib import a fix introduces, keyed by a marker the fixed line now contains.
_IMPORT_FOR = (("ast", "ast.literal_eval"), ("os", "os.environ"))


def _is_secret_rule(rule_id: str, bug_class: str) -> bool:
    """An external (gitleaks-style) secret rule id, or a secret bug class, gets the env-var transform too."""
    r = rule_id.lower()
    b = str(bug_class or "").lower()
    return ("secret" in r or "token" in r or "apikey" in r or "api-key" in r or "-key" in r
            or "credential" in r or "password" in r or "secret" in b or "798" in b)


def _decode_ref(finding: Any) -> tuple[Optional[str], Optional[str], Optional[int]]:
    """Recover (rule_id, rel_path, line) from the finding's DAA ref, robust to how the finding is shaped."""
    ref = str(getattr(finding, "ref", "") or "")
    if not ref:
        ref = str(getattr(finding, "finding_ref", "") or getattr(finding, "check_id", "") or "")
    if not ref:
        return (None, None, None)
    try:
        from .codescan import parse_ref
        return parse_ref(ref)
    except Exception:  # noqa: BLE001 — an unparseable ref simply means no deterministic fix
        return (None, None, None)


def deterministic_daa_diff(finding: Any, target_repo: str) -> Optional[str]:
    """A minimal, clean unified diff that fixes a DAA static finding mechanically, or None when the rule has
    no safe mechanical fix (fall back to the LLM). Never raises."""
    try:
        rule_id, rel_path, line = _decode_ref(finding)
        if not rule_id or rel_path is None or line is None:
            return None
        fixer = _LINE_FIX.get(rule_id)
        if fixer is None:
            # external secret rule (gitleaks-style, e.g. stripe-access-token) → the env-var transform
            if _is_secret_rule(rule_id, getattr(finding, "bug_class", "")):
                fixer = _secret_fix
            else:
                return None                    # pickle / exec / unknown → the LLM coder handles it
        root = Path(str(target_repo or "")).resolve()
        src = (root / rel_path).resolve()
        if root not in src.parents and src != root:   # path-escape guard (defence in depth)
            return None
        if not src.is_file():
            return None
        old = src.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        idx = int(line) - 1
        if idx < 0 or idx >= len(old):
            return None
        raw = old[idx]
        nl = "\n" if raw.endswith("\n") else ""
        fixed = fixer(raw.rstrip("\n"))
        if fixed is None:
            return None                        # the pattern was not on the recorded line — no no-op patch
        new = list(old)
        new[idx] = fixed + nl
        # add any stdlib import the fix introduced, once, at the top
        for mod, marker in _IMPORT_FOR:
            if marker in new[idx] and not any(re.match(rf"\s*import\s+.*\b{mod}\b", ln) for ln in new):
                new.insert(0, f"import {mod}\n")
        if new == old:
            return None
        diff = "".join(difflib.unified_diff(
            old, new, fromfile=f"a/{rel_path}", tofile=f"b/{rel_path}", lineterm="\n"))
        return diff or None
    except Exception:  # noqa: BLE001 — a deterministic-fix miss must NEVER break the ladder; fall back to LLM
        return None
