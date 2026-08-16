"""General DEV-MODE codebase edits (Phase D2) — the chat's "change this code" leg.

The operator points the chat at an attached/cloned codebase and asks for a change; the model proposes it
as a MINIMAL unified diff; the operator reviews the diff and approves-to-apply. This is GENERAL software
editing, NOT security remediation, so — unlike the remediation pipeline (``remediation.codefix.run_codefix``
/ ``autopatch.loop.autopatch``, which refuse anything not spawned from an oracle-confirmed FACT) — it does
NOT require a fired oracle. It reuses the SAME hardened primitives the remediation path uses, minus the
FACT gate, so every other control still holds:

  * model egress is sovereignty-gated (``llm_egress_refusal``) — a refusal degrades to "no proposal";
  * the diff is parsed fail-closed and PATH-CONFINED (``parse_unified_diff`` — repo-relative, no ``..``,
    capped), so an edit can never touch a file outside the clone;
  * apply is ``git apply --check`` then ``git apply`` into the DISPOSABLE clone workdir only, never the
    source repo (``CodefixSession.build``);
  * every edit passes the WARDEN gate at tier A2 (``code_edit``) — auto-runs never; it opens only when the
    operator is PRESENT (they reviewed the diff and clicked approve) and the kill-switch is clear
    (``CodefixSession.gate``);
  * the destructive open-PR leg stays OFF (``pr_enabled=False``).

Offense-plane, import-clean of ``framework``/``strix``/``sigil`` (only sibling live/remediation/autopatch
seams + vigil_core), matching the modules it reuses.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from ..autopatch.loop import parse_unified_diff
from ..remediation.codefix import is_safe_repo_path
from .codefix_runner import CodefixConfig, CodefixSession
from .think_claude import _build_live_client, _extract_text, _resolve_key, llm_egress_refusal

_MAX_FILE_BYTES = 20000        # per-file context handed to the model
_MAX_CONTEXT_FILES = 8


def _read_context(workdir: str, files) -> list:
    """Bounded current content of the named repo-relative files under ``workdir`` (so the model diffs
    against real content). Each path is confinement-checked (``is_safe_repo_path``) and read under the
    workdir only — never an absolute path, never ``..``."""
    out: list = []
    for rel in (files or [])[:_MAX_CONTEXT_FILES]:
        r = str(rel or "").strip()
        ok, _ = is_safe_repo_path(r)
        if not ok:
            continue
        p = os.path.join(workdir, r)
        try:
            # confinement: the resolved file must sit under the workdir
            if os.path.commonpath([os.path.abspath(workdir), os.path.abspath(p)]) != os.path.abspath(workdir):
                continue
            if os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as fh:
                    out.append((r, fh.read(_MAX_FILE_BYTES)))
        except (OSError, ValueError):
            continue
    return out


def propose_dev_edit(workdir: str, instruction: str, files=None, *, client: Any = None,
                     model: str = "claude-opus-5", max_tokens: int = 4000) -> str:
    """Propose the requested change to the code in ``workdir`` as a unified diff. GENERAL dev editing (no
    security-fix framing, no ``finding``, no oracle-FACT gate). Returns the diff string, or ``""`` on a
    sovereignty refusal / no key / model failure (fail-closed — the caller then applies nothing)."""
    instruction = str(instruction or "").strip()
    if not instruction or not workdir:
        return ""
    ctx = _read_context(workdir, files)
    ctx_block = "\n\n".join(f"### {rel}\n```\n{body}\n```" for rel, body in ctx)
    prompt = (
        "You are a senior software engineer working in a cloned repository. Make the change described "
        "below as a MINIMAL unified diff against the current files. Change only what the request needs.\n\n"
        f"CHANGE REQUESTED:\n{instruction}\n\n"
        + (f"CURRENT FILE CONTENT (edit against exactly this):\n{ctx_block}\n\n" if ctx_block else "")
        + "Return ONLY a unified diff. Each file MUST start with consecutive lines "
          "`--- a/<repo-relative-path>` then `+++ b/<repo-relative-path>` (repo-relative paths only; no "
          "absolute paths, no `..`). No prose, no code fences."
    )
    # SOVEREIGNTY GATE — a model egress carrying the operator's source; the same ladder every egress passes.
    if llm_egress_refusal(None) is not None:
        return ""
    client = client or _build_live_client(_resolve_key(None) or "")
    if client is None:
        return ""
    try:
        from vigil_core import token_budget as _tb
    except Exception:  # noqa: BLE001
        _tb = None
    _mx = max_tokens
    if _tb is not None:
        try:
            _tb.throttle("devedit")
            _mx = _tb.clamp_output("devedit", max_tokens)
        except Exception:  # noqa: BLE001
            _tb = None
    try:
        resp = client.messages.create(model=model, max_tokens=_mx,
                                      messages=[{"role": "user", "content": prompt}])
    except Exception:  # noqa: BLE001 — a coder failure degrades to no-patch
        return ""
    if _tb is not None:
        try:
            _tb.record_usage("devedit", getattr(resp, "usage", None))
        except Exception:  # noqa: BLE001
            pass
    return _extract_text(resp) or ""


def apply_dev_edit(workdir: str, diff_text: str, *, operator_present: bool = False,
                   killswitch: Any = None, git_bin: str = "git") -> dict:
    """Parse + APPLY a unified diff into the cloned ``workdir`` (``git apply``, clone-only). Gated as an A2
    ``code_edit``: it opens ONLY when the operator is present (they reviewed the diff and approved) and the
    kill-switch is clear; a background/unattended caller is refused. Returns ``{ok, applied:[paths]}`` or
    ``{ok: False, error}``. Fail-closed: an empty/malformed/unconfined diff applies nothing."""
    if not workdir or not os.path.isdir(workdir):
        return {"ok": False, "error": "no clone workdir to edit"}
    patches = parse_unified_diff(diff_text)          # confined repo-relative paths, capped, fail-closed
    if not patches:
        return {"ok": False, "error": "no applicable, path-confined changes in the diff"}
    cfg = CodefixConfig(target_repo=workdir, base_dir=os.path.dirname(os.path.abspath(workdir)) or ".",
                        git_bin=git_bin, pr_enabled=False)
    sess = CodefixSession(cfg, killswitch=killswitch, operator_present=operator_present)
    sess.workdir = workdir
    v = sess.gate("code_edit", workdir, destructive=False)   # A2; operator-present opens; kill-switch fail-closed
    if not getattr(v, "allowed", False):
        return {"ok": False, "error": "edit refused by the gate: " + (getattr(v, "reason", "") or ""),
                "outcome": getattr(v, "outcome", "deny")}
    r = sess.build(None, patches)                    # build ignores its request arg; applies into workdir only
    if not getattr(r, "ok", False):
        return {"ok": False, "error": getattr(r, "reason", "the diff did not apply cleanly")}
    return {"ok": True, "applied": [p.path for p in patches]}
