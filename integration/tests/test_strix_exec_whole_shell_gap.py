"""S4 item 4 — the Strix whole-shell approval gap, pinned as an executable, negative-controlled contract.

CONTEXT. S4's other three items are already landed on ``main`` (unknown-tool fail-closed, every shipped tool
explicitly classified, and network approvals bound to their real destination — see
``test_strix_unknown_tool_fail_closed.py`` and ``test_strix_approval_target.py``). This module covers the one
remaining item: "prefer typed argv builders over whole-shell approval where feasible — at minimum document
the gap if you don't close it."

THE GAP, STATED HONESTLY. An approved ``exec_command`` runs the WHOLE command string — pipes, subshells,
arbitrary binaries — with NO argv allowlist and NO per-binary re-check. The CRUCIBLE executor does the
opposite: it DENIES a tool that has no typed argv ``_BUILDERS`` entry, and confines ``terminal.run`` to the
read-only ``_TERMINAL_ALLOWLIST``. That asymmetry is DELIBERATE and cannot be closed the CRUCIBLE way for
Strix: Strix is a general offensive agent whose tool surface is unbounded by design (it MUST run
nmap/ffuf/curl/python3/msf/…), so a fixed argv allowlist would defeat its purpose and a denylist of dangerous
spellings is unsound. Strix's exec is contained by THREE other controls instead:

  1. this per-action, single-use, owner-signed WARDEN approval — the owner reviews the EXACT command string
     before it runs (the command is bound via ``_strix_args``, not summarised away);
  2. the S2/S3 scope-enforcing egress gateway (governs where its traffic may go); and
  3. the S5 container hardening (bounds what a compromised exec can reach).

These tests pin that disposition so it cannot silently regress into either (a) an UNGATED exec, or (b) a
false claim that Strix gained an argv allowlist it did not, or (c) the CRUCIBLE fail-closed markers being
removed. They import the import-clean ``warden_gate`` and read the executor SOURCE as text (no gateway
import), so they run in the sovereign-env test leg.
"""
from __future__ import annotations

import ast
from pathlib import Path

from vigil_integration.warden_gate import (
    _STRIX_EXEC_TOOLS,
    _strix_args,
    _strix_shell_classifier,
    _strix_target,
    decide_tool,
)

_REPO = Path(__file__).resolve().parents[2]
_EXECUTOR_REL = "integration/vigil_integration/live/executor.py"


def _fn_code(module_rel: str, func_name: str) -> str:
    """A function's body source with its docstring stripped — so a structural probe never matches prose."""
    src = (_REPO / module_rel).read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            body = list(node.body)
            if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]
            return "\n".join(ast.get_source_segment(src, stmt) or "" for stmt in body)
    raise AssertionError(f"{func_name} not found in {module_rel} — the probe is anchored to a moved seam")


# --------------------------------------------------------------------------------------------------------
# The exec chokepoint is GATED (queued) even though it has no argv allowlist — approval is the containment.
# --------------------------------------------------------------------------------------------------------

def test_exec_tools_are_gated_despite_having_no_argv_allowlist():
    assert _STRIX_EXEC_TOOLS == {"exec_command", "write_stdin"}, (
        "the exec chokepoint set changed — re-check that every arbitrary-execution name is gated"
    )
    for name in _STRIX_EXEC_TOOLS:
        assert _strix_shell_classifier(name) == "A3", f"exec tool {name!r} does not classify A3"
        d = decide_tool(name, classify=_strix_shell_classifier, floor="A0", ceiling="A1")
        assert d.outcome == "queue", f"exec tool {name!r} decided {d.outcome!r} (expected queue for approval)"


def test_negative_control_an_ungated_exec_would_be_the_defect():
    """Proves the gate is what contains exec (there is no argv allowlist doing it): had the classifier rated
    ``exec_command`` A0, the whole command string would AUTO-RUN with no owner in the loop."""
    def ungated(name: str) -> str:
        return "A0" if name == "exec_command" else _strix_shell_classifier(name)

    d = decide_tool("exec_command", classify=ungated, floor="A0", ceiling="A1")
    assert d.outcome == "auto" and d.tier == "A0", (
        "the ungated-exec negative control no longer auto-runs — the probe is stale"
    )


# --------------------------------------------------------------------------------------------------------
# The WHOLE command string is what the owner reviews and what the token binds — that IS the containment.
# --------------------------------------------------------------------------------------------------------

def test_the_exact_command_string_is_bound_not_summarised_away():
    # a non-JSON command string binds VERBATIM (nothing is dropped) …
    assert _strix_args("nmap -sV --script=vuln 10.0.0.5") == "nmap -sV --script=vuln 10.0.0.5"
    # … and a JSON-object command is parsed so the command field survives for the owner to read.
    assert _strix_args('{"command": "curl http://x/ | tee /etc/passwd"}') == {
        "command": "curl http://x/ | tee /etc/passwd"
    }


def test_distinct_commands_bind_distinctly_so_an_owner_cannot_approve_a_stale_command():
    a = _strix_args("nmap 10.0.0.1")
    b = _strix_args("rm -rf /var/www")
    assert a != b, "two different commands normalised to the same bound value — the owner could be misled"


# --------------------------------------------------------------------------------------------------------
# The exec approval target stays an HONEST local sentinel — never a spoofable network-style label.
# --------------------------------------------------------------------------------------------------------

def test_exec_target_is_the_honest_local_sentinel_not_a_network_label():
    for name in ("exec_command", "write_stdin"):
        t = _strix_target(name, {"command": "id"})
        assert t == "strix:exec", f"{name} target is {t!r} (expected the local sentinel)"
        # it must not be dressed up as a network destination it does not have
        assert not t.startswith("strix:repeat_request") and "://" not in t


# --------------------------------------------------------------------------------------------------------
# The accepted asymmetry: CRUCIBLE has typed argv builders + a terminal allowlist; Strix (by design) does not.
# Pinned structurally so it cannot be silently removed OR silently mis-claimed as closed.
# --------------------------------------------------------------------------------------------------------

def test_crucible_path_is_fail_closed_on_argv_the_asymmetry_this_gap_accepts():
    execute = _fn_code(_EXECUTOR_REL, "_execute")
    assert "_BUILDERS" in execute and "no argv builder" in execute, (
        "the CRUCIBLE executor no longer denies a tool that has no typed argv builder — the asymmetry this "
        "gap documents (CRUCIBLE fail-closed on argv, Strix whole-shell) is gone; re-verify item 4"
    )
    executor_src = (_REPO / _EXECUTOR_REL).read_text(encoding="utf-8", errors="replace")
    assert "_TERMINAL_ALLOWLIST" in executor_src, (
        "the CRUCIBLE terminal.run allowlist is gone — the read-only-argv confinement item 4 contrasts "
        "against no longer exists"
    )


def test_strix_side_does_not_pretend_to_have_an_argv_allowlist():
    """The honest half of the asymmetry: the Strix classifier gates the whole TOOL by name; it does not — and
    must not silently claim to — inspect or allowlist the argv of ``exec_command``. If a real per-argv control
    is ever added for Strix, this contract (and the ACCEPTED GAP comment in warden_gate.py) must be rewritten
    deliberately, not drifted past."""
    warden_src = (_REPO / "integration/vigil_integration/warden_gate.py").read_text(encoding="utf-8")
    # the accepted-gap disposition is documented at the definition site (item 4: "at minimum document the gap")
    assert "ACCEPTED GAP" in warden_src and "argv allowlist" in warden_src, (
        "the accepted whole-shell gap is no longer documented at the code site — restore it or, if the gap "
        "was genuinely closed, replace it with the real control and update this test"
    )
