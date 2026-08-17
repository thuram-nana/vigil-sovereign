"""General DEV-MODE codebase edits (Phase D2) — the chat's "change this code" leg.

The operator points the chat at an attached/cloned codebase and asks for a change; the model proposes it
as a MINIMAL unified diff; the operator reviews the diff and approves-to-apply. This is GENERAL software
editing, NOT security remediation, so — unlike the remediation pipeline (``remediation.codefix.run_codefix``
/ ``autopatch.loop.autopatch``, which refuse anything not spawned from an oracle-confirmed FACT) — it does
NOT require a fired oracle. It reuses the SAME hardened primitives the remediation path uses, minus the
FACT gate, so every other control still holds:

  * model egress is sovereignty-gated (``llm_egress_refusal``) — a refusal degrades to "no proposal";
  * the diff's ``+++`` target paths are parsed fail-closed + confined (``parse_unified_diff`` — repo-relative,
    no ``..``, capped); ``apply_dev_edit`` additionally refuses a diff whose git-extended headers
    (``rename to`` / ``copy to``) name an unconfined path (defense-in-depth), and **git apply itself**
    (run ``-C workdir``, no ``--unsafe-paths``) is the backstop that rejects any remaining out-of-tree /
    rename / through-symlink escape — the three layers together keep an edit inside the clone;
  * apply is ``git apply --check`` then ``git apply`` into the DISPOSABLE clone workdir only, never the
    source repo (``CodefixSession.build``);
  * every edit passes the WARDEN gate at tier A2 (``code_edit``) — auto-runs never; it opens only when the
    operator is PRESENT (they reviewed the diff and clicked approve); the ENGAGEMENT kill-switch (emergency
    stop) is enforced by the console wrapper (``actions.propose/apply_codebase_edit`` →
    ``_chat_killswitch_tripped``), and ``CodefixSession.gate`` also honors a ``killswitch`` when one is
    injected here;
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
from .think_claude import (
    _build_live_client,
    _extract_text,
    _resolve_key,
    is_local_backend,
    llm_egress_refusal,
    local_backend_or_refusal,
)

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


def _propose_dev_edit_local(backend_name: str, instruction: str, ctx: list, *, max_tokens: int) -> str:
    """GAP-1 — propose the diff on a LOOPBACK-enforced LOCAL backend (a per-session local pick), with NO
    cloud failover. Uses ``local_backend_or_refusal`` (loopback check + reachability + sovereignty assert);
    on ANY refusal it returns ``""`` (no proposal) — it NEVER constructs or calls a cloud client, so the
    operator's source never egresses to a cloud model. The kernel provider layer is structured-output only,
    so the diff rides a single ``diff`` field, mirroring the console chat's local schema."""
    backend, refusal = local_backend_or_refusal(backend_name)
    if refusal is not None:
        return ""                                  # fail-closed: no proposal, NEVER a cloud egress
    try:
        from pydantic import BaseModel, Field

        from framework.v2.kernel.llm import Prompt
    except Exception:  # noqa: BLE001 — provider/prompt layer unavailable ⇒ no proposal, never cloud
        return ""

    class DiffReply(BaseModel):
        diff: str = Field(default="", description=(
            "the requested change as a MINIMAL unified diff; each file starts with `--- a/<repo-relative>` "
            "then `+++ b/<repo-relative>` (repo-relative paths only; no absolute paths, no `..`)"))

    ctx_block = "\n\n".join(f"### {rel}\n```\n{body}\n```" for rel, body in ctx)
    system = ("You are a senior software engineer working in a cloned repository. Make the requested change "
              "as a MINIMAL unified diff against the current files. Change only what the request needs.")
    user = (
        f"CHANGE REQUESTED:\n{instruction}\n\n"
        + (f"CURRENT FILE CONTENT (edit against exactly this):\n{ctx_block}\n\n" if ctx_block else "")
        + "Return the change as a unified diff in the `diff` field. Each file MUST start with consecutive "
          "lines `--- a/<repo-relative-path>` then `+++ b/<repo-relative-path>` (repo-relative paths only; "
          "no absolute paths, no `..`)."
    )
    try:
        prompt = Prompt(system=system, user=user, schema=DiffReply, schema_name="DiffReply",
                        cognitive_doc="", max_tokens=max_tokens, temperature=0.2)
        result = backend.complete(prompt)          # ONE backend, NO failover
    except Exception:  # noqa: BLE001 — a local failure yields no proposal; it never reaches for a cloud model
        return ""
    return str(getattr(getattr(result, "parsed", None), "diff", "") or "")


def propose_dev_edit(workdir: str, instruction: str, files=None, *, client: Any = None,
                     model: str = "claude-opus-5", backend: str = "", max_tokens: int = 4000) -> str:
    """Propose the requested change to the code in ``workdir`` as a unified diff. GENERAL dev editing (no
    security-fix framing, no ``finding``, no oracle-FACT gate). Returns the diff string, or ``""`` on a
    sovereignty refusal / no key / model failure (fail-closed — the caller then applies nothing).

    GAP-1 model sovereignty: ``backend`` is the per-session LOCAL pick (ollama / self-hosted / …). When set
    (and no ``client`` is injected) the diff is proposed on that loopback-enforced local backend with NO
    cloud failover — the source never egresses to a cloud model, and an unreachable local backend yields no
    proposal rather than a cloud call. ``model`` is the CLOUD model string used on the direct-SDK path."""
    instruction = str(instruction or "").strip()
    if not instruction or not workdir:
        return ""
    ctx = _read_context(workdir, files)
    # GAP-1 — a LOCAL per-session pick routes through the loopback-enforced provider FIRST, before the cloud
    # key/SDK path, so a LOCAL pick with an ANTHROPIC_API_KEY in the env can never egress source to a cloud
    # model. Only when no client is injected (the console path injects none); an injected client is the
    # explicit cloud-test seam and keeps precedence.
    if client is None and is_local_backend(backend):
        return _propose_dev_edit_local(str(backend), instruction, ctx, max_tokens=max_tokens)
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
    patches = parse_unified_diff(diff_text)          # confines the +++ target paths (capped, fail-closed)
    if not patches:
        return {"ok": False, "error": "no applicable, path-confined changes in the diff"}
    # Defense-in-depth (red-pen MEDIUM-1): parse_unified_diff validates only the +++/--- target, not the
    # git-extended headers. Refuse a patch whose `rename to`/`copy to`/`rename from`/`copy from` names an
    # UNCONFINED path — so we do not lean solely on git apply's own out-of-tree rejection.
    for pf in patches:
        for ln in str(getattr(pf, "diff_text", "") or "").split("\n"):
            for pfx in ("rename to ", "rename from ", "copy to ", "copy from "):
                if ln.startswith(pfx):
                    cand = ln[len(pfx):].strip()
                    ok, _ = is_safe_repo_path(cand)
                    if not ok:
                        return {"ok": False, "error": "refused: the diff renames/copies to a path outside "
                                                      "the repository"}
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
