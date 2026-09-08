"""strix_fix — the AGENTIC deep-fix front-end (Phase E.2).

Drives the vendored Strix agent (a Claude-Code-class edit+shell+test loop, in the gated Docker sandbox) to
PRODUCE a fix for a confirmed finding, then hands its diff to the SAME gated, oracle-verified deep-fix ladder
(``autopatch_live(proposed_diff=…)``, Phase E.1). Strix's self-reported "fixed" is NEVER trusted: the diff
earns ``verified-no-pr`` only if VIGIL's own ladder (apply → build/test gate in a disposable clone → re-run
the finding's deterministic oracle) confirms it. So the breadth of a real agent is gated behind VIGIL's proof.

Seams are injectable (``produce_diff``) so the orchestrator is unit-testable with a fake agent — no Docker,
no LLM. The real ``run_strix_fix`` goes through ``strix_runtime`` (sovereignty + sandbox-net gate + Docker
preflight), so it inherits every Strix safety layer. Total: any failure degrades to "no agent diff" (a
fail-closed non-verified result), never a crash.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional

# a ```diff … ``` fenced block (Strix renders fixes as fenced diff blocks in its reports).
_DIFF_FENCE = re.compile(r"```(?:diff|patch)\s*\n(.*?)```", re.DOTALL)
# a block is a usable UNIFIED diff only if it carries real file headers we can git-apply.
_UNIFIED_HDR = re.compile(r"(?m)^(?:diff --git |--- (?:a/|/dev/null)|\+\+\+ (?:b/|/dev/null))")
_MAX_REPORT_FILES = 200          # bound the walk over the untrusted agent-written tree
_MAX_REPORT_BYTES = 2_000_000    # per-file read cap (a huge/pathological .md can't pressure host memory)


def extract_unified_diff(*search_dirs: str, cap: int = 200_000) -> str:
    """Pull git-appliable unified diffs out of Strix's markdown reports (``penetration_test_report.md``,
    ``vulnerabilities/*.md``) under any of ``search_dirs``. Keeps ONLY fenced ```diff blocks that carry real
    ``--- a/`` / ``+++ b/`` (or ``diff --git``) headers — a display-only or headerless block is dropped, so an
    un-appliable agent output fails closed downstream rather than corrupting the clone. Deduplicated, bounded,
    total (never raises)."""
    seen: set[str] = set()
    out: list[str] = []
    total = 0
    for d in search_dirs:
        if not d:
            continue
        try:
            root = Path(d)
            files = [root] if root.is_file() else (sorted(root.rglob("*.md"))[:_MAX_REPORT_FILES] if root.is_dir() else [])
        except OSError:
            continue
        for f in files:
            try:
                with f.open(encoding="utf-8", errors="replace") as _fh:
                    text = _fh.read(_MAX_REPORT_BYTES)   # bounded read of an untrusted report file
            except OSError:
                continue
            for m in _DIFF_FENCE.finditer(text):
                block = m.group(1).strip("\n")
                if not block.strip() or not _UNIFIED_HDR.search(block):
                    continue
                key = block.strip()
                if key in seen:
                    continue
                seen.add(key)
                chunk = block if block.endswith("\n") else block + "\n"
                if total + len(chunk) > cap:
                    return "".join(out)
                out.append(chunk)
                total += len(chunk)
    return "".join(out)


def default_fix_instruction(finding: Any, *, test_cmd: str = "") -> str:
    """A fix-oriented Strix instruction for one confirmed finding (white-box). Asks it to fix the ROOT cause,
    keep the change minimal, run the tests, and include the unified diff in its report (which is how the fix
    reaches the host — the container is ephemeral).

    The codebase is bind-mounted READ-ONLY (``--mount``; W4 — this avoids the SDK's file-by-file ``--target``
    copy that OOM-killed the workspace-materialization child, exit 137). Only the mount subdir is read-only;
    the rest of ``/workspace`` is a writable overlay, so the instruction tells the agent to copy the source to
    a writable dir before editing + testing. VIGIL never uses the in-container edits — it re-applies the
    reported repo-relative diff to its OWN disposable clone and re-verifies with its own oracle + suite."""
    ref = str(getattr(finding, "ref", "") or "")
    bug = str(getattr(finding, "bug_class", "") or "")
    tgt = str(getattr(finding, "target", "") or "")
    tnote = f" Run `{test_cmd}` and iterate until it passes." if test_cmd else ""
    return (f"White-box FIX task. A deterministic oracle CONFIRMED a {bug or 'vulnerability'} "
            f"({ref}) at {tgt}. The target codebase is bind-mounted READ-ONLY under `/workspace`; BEFORE "
            f"editing, copy it to a writable working directory (e.g. `cp -a /workspace/<dir> /workspace/fix && "
            f"cd /workspace/fix`) and make ALL changes there. Fix the ROOT cause with the MINIMAL change; do "
            f"not weaken tests or hide the pattern.{tnote} In your final report, INCLUDE the complete fix as a "
            f"fenced ```diff block with `--- a/<path>` / `+++ b/<path>` headers (repo-relative paths, NOT the "
            f"/workspace/fix prefix) — this is how the fix is returned to the host.")


def run_strix_fix(root: str, instruction: str, *, base_dir: str, timeout: float = 1800.0,
                  scan_mode: str = "standard", launch: Optional[Callable[..., int]] = None) -> tuple[str, str]:
    """LIVE: run Strix headless (``--non-interactive --mount <root> --instruction <fix>``) through the gated
    ``strix_runtime`` (Docker + sandbox-net + sovereignty), then extract the produced unified diff from its
    run report. Returns ``(diff, note)``; ``diff`` is "" when Strix produced no git-appliable diff (the run
    then fails closed to a non-verified result upstream). Total — a Docker/agent failure yields ("", reason)."""
    from . import strix_runtime
    _launch = launch or strix_runtime.launch
    work = tempfile.mkdtemp(prefix="vigil-strixfix-")   # Strix writes strix_runs/<name> under its CWD
    # W4: bind-mount the clone READ-ONLY (--mount) rather than stream it in file-by-file (--target), which
    # OOM-killed the SDK's workspace-copy child (exit 137) on non-trivial repos. VIGIL extracts the diff from
    # the report and re-verifies on its own clone, so a read-only source is fine (the instruction has the agent
    # copy it to a writable overlay dir to edit + test).
    argv = ["--non-interactive", "--mount", str(root), "--scan-mode", scan_mode, "--instruction", instruction]

    def _runner(cmd: list, env: dict) -> int:
        import subprocess
        try:
            return subprocess.run(cmd, env=env, cwd=work, timeout=timeout).returncode  # noqa: S603
        except subprocess.TimeoutExpired:
            return 124
        except OSError:
            return 127

    try:
        rc = _launch(argv, base_dir=base_dir, runner=_runner)
    except Exception as exc:  # noqa: BLE001 — never let the agent front-end crash the fix
        return "", f"strix launch errored: {type(exc).__name__}: {exc}"
    # extract from the run dirs Strix wrote (strix_runs under the work cwd + any proof-run dir)
    diff = extract_unified_diff(os.path.join(work, "strix_runs"), work)
    if not diff.strip():
        return "", (f"strix produced no git-appliable diff (rc={rc}) — nothing to re-verify" if rc == 0
                    else f"strix exited rc={rc} with no usable diff")
    return diff, f"strix produced a {len(diff)} B diff (rc={rc}); re-verifying through the gated ladder"


def agentic_deepfix(finding: Any, *, config: Any, verify_oracle: Any,
                    instruction: str = "", test_cmd: str = "",
                    produce_diff: Callable[[str, str], tuple[str, str]] = run_strix_fix) -> Any:
    """Run the agentic front-end for ONE confirmed finding, then RE-VERIFY its diff through the gated ladder.

    ``produce_diff(root, instruction) -> (diff, note)`` is the injectable agent seam (default: live Strix).
    Whatever it returns is UNTRUSTED: an empty/un-appliable diff yields a clean non-verified ``no-agent-diff``
    result; a diff is driven through ``autopatch_live(proposed_diff=…, verify_before_pr=True)`` and earns
    ``verified-no-pr`` ONLY if VIGIL's build/test gate + oracle confirm it. Never mints the signed ``remediated``."""
    from .autopatch.loop import PatchResult
    from .live.codefix_runner import autopatch_live

    instr = instruction or default_fix_instruction(finding, test_cmd=test_cmd)
    try:
        diff, note = produce_diff(str(getattr(config, "target_repo", "") or ""), instr)
    except Exception as exc:  # noqa: BLE001
        diff, note = "", f"agent front-end errored: {type(exc).__name__}: {exc}"
    if not str(diff or "").strip():
        return PatchResult(remediation_id="", status="no-agent-diff", opened_pr=False, remediated=False,
                           reason=note or "the agent produced no git-appliable diff")
    return autopatch_live(finding, config=config, client=None, verify_oracle=verify_oracle,
                          verify_before_pr=True, proposed_diff=diff)
