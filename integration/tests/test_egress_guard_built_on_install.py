"""The egress guard is BUILT on the install path — not only in CI.

WHY THIS EXISTS. ``tools/egress-guard/egress_guard`` is the syscall-level no-egress supervisor the live
executor wraps a tool spawn in when ``VIGIL_EGRESS_GUARD`` is set. Its source + Makefile ship in-repo and
``live/executor.py`` wires it, but the build (``make -C tools/egress-guard``) used to run ONLY in
``.github/workflows/ci.yml`` and ``livefire.yml`` — never in ``bootstrap.sh``, the root ``Makefile`` or
``envs/build_envs.sh``. So a normal install produced NO binary, and:

  * ``VIGIL_EGRESS_GUARD=1``  + absent binary → spawns proceed UNGUARDED at the syscall level (the argv
    allowlist and loopback pin still apply, but the connect/sendto/sendmsg supervisor does not). That
    degradation used to be SILENT — the operator got no signal the control they opted into did not exist.
  * ``VIGIL_EGRESS_GUARD=require`` + absent binary → every spawn refuses.

Two guards, both file-truth (no framework import — this runs in the sovereign CI leg):

  1. the install path (``bootstrap.sh`` and ``envs/build_envs.sh``) contains a REAL build INVOCATION of
     ``make -C tools/egress-guard`` — not merely a mention inside a comment or a quoted warning string; and
  2. plain-enabled mode with an absent binary now emits ONE loud stderr warning (was silent) and still
     proceeds, while ``require`` is unaffected and OFF stays byte-identical.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_BOOTSTRAP = _REPO / "bootstrap.sh"
_BUILD_ENVS = _REPO / "envs" / "build_envs.sh"

# `make -C tools/egress-guard` or `$(MAKE) -C tools/egress-guard`, with any whitespace between tokens.
_INVOKE = re.compile(r"(?:make|\$\(MAKE\))\s+-C\s+tools/egress-guard\b")
_QUOTED = re.compile(r'"[^"]*"|' + r"'[^']*'")


def _build_invocation_lines(text: str) -> list[str]:
    """Lines that actually RUN the guard build, excluding comments and quoted mentions.

    A shell ``#`` comment or a ``warn "... make -C tools/egress-guard ..."`` message string mentions the
    command without running it; counting those would let the real invocation be deleted while the test
    still passed. So: skip ``#``-comment lines, strip every quoted substring, THEN look for the token."""
    hits = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        unquoted = _QUOTED.sub("", raw)
        if _INVOKE.search(unquoted):
            hits.append(raw)
    return hits


# --- negative + positive control for the detector itself ---------------------------------------------

def test_detector_ignores_comments_and_quoted_mentions_but_sees_a_real_call():
    """NEGATIVE CONTROL: a comment or a quoted-in-a-message occurrence must NOT count as a build; only a
    bare command invocation does. Without this, the install-path assertions below would be satisfied by a
    leftover warning string even after the real build was removed."""
    only_mentions = (
        "# build it with make -C tools/egress-guard someday\n"
        "warn \"NOT built — run 'make -C tools/egress-guard' yourself\"\n"
        "echo '>>> make -C tools/egress-guard'\n"
    )
    assert _build_invocation_lines(only_mentions) == [], "a mention was miscounted as a real build"

    real_call = (
        "# comment\n"
        "elif have make && make -C tools/egress-guard >/dev/null 2>&1; then\n"
        "\t$(MAKE) -C tools/egress-guard\n"
    )
    assert len(_build_invocation_lines(real_call)) == 2, "a real invocation was missed"


# --- guard 1: the install path builds the binary -----------------------------------------------------

def test_bootstrap_builds_the_egress_guard():
    hits = _build_invocation_lines(_BOOTSTRAP.read_text(encoding="utf-8"))
    assert hits, (
        "bootstrap.sh must actually BUILD the egress guard (a real `make -C tools/egress-guard` "
        "invocation, not just a comment/warning mention) — otherwise a normal install produces no binary "
        "and VIGIL_EGRESS_GUARD=1 falls open silently."
    )


def test_build_envs_builds_the_egress_guard():
    hits = _build_invocation_lines(_BUILD_ENVS.read_text(encoding="utf-8"))
    assert hits, (
        "envs/build_envs.sh must BUILD the egress guard so `make envs` / a direct build (and bootstrap's "
        "step 2, which calls it) produce the binary — not only CI."
    )


# --- guard 2: plain-enabled + absent binary WARNS LOUDLY (was silent) and still proceeds -------------

eg = pytest.importorskip("vigil_integration.live.egress_guard")


def test_enabled_with_missing_binary_warns_once_and_proceeds(monkeypatch, capsys):
    """The silent fail-open is now loud. Enabled (not require) + a binary that resolves to None must emit
    exactly ONE stderr warning per process and STILL return the argv unchanged (the documented, byte-
    identical degradation — the argv allowlist stays in force)."""
    monkeypatch.setenv("VIGIL_EGRESS_GUARD", "1")
    monkeypatch.setenv("VIGIL_EGRESS_GUARD_BIN", "/nonexistent/egress_guard")  # resolves to None
    monkeypatch.setattr(eg, "_warned_unavailable", False, raising=False)  # fresh-process state

    argv = ["nuclei", "-u", "http://127.0.0.1:8080/"]
    out = eg.wrap_argv(argv)
    assert out == argv, "enabled+absent must degrade to argv-unchanged, not wrap/raise"

    err = capsys.readouterr().err
    assert "egress-guard" in err.lower() and "unguarded" in err.lower(), (
        f"expected a loud UNGUARDED warning on stderr, got: {err!r}"
    )

    # warn-once: a scan spawns many tools; a per-spawn line would drown the run.
    eg.wrap_argv(argv)
    assert capsys.readouterr().err == "", "the unavailable warning must fire ONCE per process, not per spawn"


def test_disabled_is_silent_and_require_still_raises(monkeypatch, capsys):
    """CONTROL for the warning: it fires ONLY on enabled+absent. OFF must stay byte-identical (no warn,
    argv unchanged); `require` must still FAIL CLOSED (raise), never warn-and-proceed."""
    monkeypatch.setattr(eg, "_warned_unavailable", False, raising=False)
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)
    argv = ["nuclei", "-u", "http://127.0.0.1:8080/"]
    assert eg.wrap_argv(argv) == argv
    assert capsys.readouterr().err == "", "OFF must not warn — it is not a degradation, it is disabled"

    monkeypatch.setattr(eg, "_warned_unavailable", False, raising=False)
    monkeypatch.setenv("VIGIL_EGRESS_GUARD", "require")
    monkeypatch.setenv("VIGIL_EGRESS_GUARD_BIN", "/nonexistent/egress_guard")
    with pytest.raises(eg.EgressGuardUnavailable):
        eg.wrap_argv(argv)
