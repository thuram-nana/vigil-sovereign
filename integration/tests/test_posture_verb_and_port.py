"""W17-12 (#546) — `vigil posture` is a real dispatch verb, and its read-only endpoint no longer defaults
onto the offense console's port.

These tests are FRAMEWORK-FREE by construction (they never trigger the live `attest` scan, only the pure
argparse dispatch + the pure server bind), so they run in the framework-free integration leg. The signed-
artifact half of #546 (the endpoint emits the SIGNED bundle, tamper -> NOT SOUND) lives in
`test_posture_endpoint.py`, which mints a real bundle and therefore runs in the offense leg.
"""
from __future__ import annotations

import argparse
import contextlib
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from vigil_integration import cli
from vigil_integration.posture.endpoint import DEFAULT_ENDPOINT_PORT, PostureEndpointError, serve_posture
from vigil_integration.uiproxy import CONSOLE_PORT


def _posture_choices() -> dict:
    parser = cli.build_parser()
    sub = [a for a in parser._subparsers._group_actions
           if isinstance(a, argparse._SubParsersAction)][0]
    return sub.choices


def test_posture_is_a_registered_dispatch_verb():
    # Structural: before the fix `posture` is NOT a subcommand at all (argparse would say "invalid
    # choice"); after it, the verb exists and routes to the posture sub-CLI.
    assert "posture" in _posture_choices()


def test_vigil_posture_verify_dispatches_to_the_posture_subcli(tmp_path: Path):
    # Behavioural fail-before/pass-after: `vigil posture verify …` must reach `posture.cli._cmd_verify`,
    # which returns 3 for a directory that is not a bundle. WITHOUT the verb, `cli.main(["posture",…])`
    # raises SystemExit(2) (argparse "invalid choice") — so this both proves dispatch AND is the negative
    # control: a non-bundle path is REJECTED (rc 3), never silently accepted.
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        rc = cli.main(["posture", "verify", "--bundle", str(tmp_path / "not-a-bundle")])
    assert rc == 3, buf.getvalue()


def test_vigil_posture_endpoint_help_advertises_the_non_colliding_default():
    # The endpoint sub-verb's own --port default is the off-8787 port, surfaced in its help.
    out = io.StringIO()
    with contextlib.suppress(SystemExit), contextlib.redirect_stdout(out):
        cli.main(["posture", "endpoint", "-h"])
    text = out.getvalue()
    # The advertised default IS the off-8787 port (8787 still appears only as prose naming the console).
    assert f"default {DEFAULT_ENDPOINT_PORT}" in text


class _Noop(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_a):  # quiet
        return


def _bind_fixed(port: int):
    """Bind a throwaway server at a FIXED port; skip (never red-fail) if a dev box already holds it."""
    try:
        return ThreadingHTTPServer(("127.0.0.1", port), _Noop)
    except OSError as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"fixed port {port} busy in this environment ({e}); the constant-inequality assertion "
                    f"below is the deterministic regression guard")


def test_posture_endpoint_default_port_does_not_collide_with_console(tmp_path: Path):
    # Deterministic core (this is the fail-before/pass-after guard): the posture endpoint default was 8787,
    # byte-identical to the offense console's port. It must not be.
    assert DEFAULT_ENDPOINT_PORT != CONSOLE_PORT

    # Functional: START BOTH at their REAL fixed ports at the same time -> they coexist (no collision).
    console = _bind_fixed(CONSOLE_PORT)          # stands in for the crucible console on 8787
    try:
        posture = serve_posture("127.0.0.1", DEFAULT_ENDPOINT_PORT, tmp_path)  # the posture endpoint default
        try:
            assert console.server_address[1] == CONSOLE_PORT
            assert posture.server_address[1] == DEFAULT_ENDPOINT_PORT

            # NEGATIVE CONTROL: the OLD default (== the console's port) is REFUSED while the console holds
            # it — proving the collision was real and that binding is not a no-op.
            with pytest.raises(OSError):
                serve_posture("127.0.0.1", CONSOLE_PORT, tmp_path)
        finally:
            posture.server_close()
    finally:
        console.server_close()


def test_posture_endpoint_still_refuses_a_public_bind():
    # Guard against a new fail-open: moving the port must not relax the loopback-only bind refusal.
    with pytest.raises(PostureEndpointError):
        serve_posture("0.0.0.0", DEFAULT_ENDPOINT_PORT, ".")


def test_posture_doc_states_the_real_default_port():
    # Doc-truth (derived from the code constant so it cannot drift): docs/POSTURE.md must advertise the
    # actual default endpoint port, and must NOT tell the operator to bind the posture endpoint on 8787.
    repo = Path(__file__).resolve().parents[2]
    doc = (repo / "docs" / "POSTURE.md").read_text(encoding="utf-8")
    assert f"default port {DEFAULT_ENDPOINT_PORT}" in doc
    assert "posture endpoint --bundle ./run/bundle --host 127.0.0.1 --port 8787" not in doc
