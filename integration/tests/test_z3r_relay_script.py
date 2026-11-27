"""AS-26 (OPS-1) — the Z3R relay SHELL WRAPPER, exercised by actually invoking it (red-pen finding 1).

The pure Python guard was already sound; the HOLE was in tools/z3r/z3r-relay.sh's transport classifier,
which matched only `user@host:...` / `host:/abs` / `host:NNN` and so misread a bare `host:relpath` rsync-ssh
remote (`report-host:reports/`, `1.2.3.4:reports`, `unit:authority/x`) as a LOCAL path — skipping the
transport guard AND the pinned `-e ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=... -i ...`
options, i.e. silently defeating guard 3 (unauthenticated-transport-refused) by falling back to the relay
user's ambient ssh config (TOFU). No test ran the shell script at all. These do: they drive it in dry-run
and assert each bare-host spec is classified REMOTE (refused without the pin; the pinned `-e ssh` applied
with it), and that a genuine local path is NOT treated as remote.

Skips if bash is unavailable. Pure stdlib + pytest."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "z3r" / "z3r-relay.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None or not SCRIPT.is_file(), reason="bash or the relay script missing")


def _run(args: list[str], *, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["Z3R_DRY_RUN"] = "1"
    env["Z3R_LANDING_DIR"] = "/tmp/z3r-land-test"
    env.pop("Z3R_KNOWN_HOSTS", None)
    env.pop("Z3R_IDENTITY", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([BASH, str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=60)


# ==================================================================================================
# finding 1 — a bare `host:relpath` ssh remote must be classified REMOTE (and so refused without the pin).
# ==================================================================================================
@pytest.mark.parametrize("spec", ["report-host:reports/", "1.2.3.4:reports", "unit:authority/tenant-a"])
def test_bare_host_relpath_is_remote_and_refused_without_pin(spec: str) -> None:
    """Without Z3R_KNOWN_HOSTS/Z3R_IDENTITY, a remote spec must be REFUSED (exit 2, 'set Z3R_KNOWN_HOSTS') —
    proving it was NOT misclassified as a local path (which would silently skip the ssh pin)."""
    cp = _run(["pull", spec])
    assert cp.returncode == 2, f"expected refusal (remote, no pin) for {spec!r}, got {cp.returncode}: {cp.stderr}"
    assert "Z3R_KNOWN_HOSTS" in cp.stderr, cp.stderr


def test_bare_host_relpath_applies_pinned_ssh_when_authenticated() -> None:
    """With the pin present, the SAME bare-host spec validates and the dry-run argv carries the pinned
    `-e ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=... -i ...` — the pin is actually applied."""
    cp = _run(["pull", "report-host:reports/"],
              env_extra={"Z3R_KNOWN_HOSTS": "/etc/vigil/known_hosts", "Z3R_IDENTITY": "/etc/vigil/relay_id"})
    assert cp.returncode == 0, f"expected ok, got {cp.returncode}: {cp.stderr}"
    out = cp.stdout + cp.stderr
    assert "transport-ok" in out
    assert "-e ssh -o StrictHostKeyChecking=yes" in out and "UserKnownHostsFile=/etc/vigil/known_hosts" in out
    assert "-i /etc/vigil/relay_id" in out


def test_local_path_is_not_remote_and_omits_ssh_pin() -> None:
    """A genuine local absolute path is NOT treated as remote: it validates with no pin and the argv carries
    no `-e ssh` (no false positive the other way)."""
    cp = _run(["pull", "/srv/aegis/outbound/reports/"])
    assert cp.returncode == 0, f"{cp.returncode}: {cp.stderr}"
    out = cp.stdout + cp.stderr
    assert "DRY-RUN rsync argv" in out
    assert "-e ssh" not in out


def test_local_relative_with_colon_after_slash_is_local() -> None:
    """`a/b:c` (colon AFTER the first slash) is a local path per rsync's own rule — not remote."""
    cp = _run(["pull", "reports/a:b"])
    # local source -> no transport refusal; it reaches the dry-run argv.
    assert cp.returncode == 0, f"{cp.returncode}: {cp.stderr}"
    assert "-e ssh" not in (cp.stdout + cp.stderr)


def test_push_local_src_remote_dst_applies_pin() -> None:
    """A push (local source -> remote per-tenant dir) must pin the ssh transport for the REMOTE dst — the
    run_rsync remote check was fixed to test each side, not the concatenation."""
    cp = _run(["push", "/srv/aegis/stage/grants/tenant-a", "unit:authority/tenant-a"],
              env_extra={"Z3R_KNOWN_HOSTS": "/kh", "Z3R_IDENTITY": "/id"})
    assert cp.returncode == 0, f"{cp.returncode}: {cp.stderr}"
    assert "-e ssh -o StrictHostKeyChecking=yes" in (cp.stdout + cp.stderr)


def test_daemon_transport_refused() -> None:
    cp = _run(["pull", "rsync://host/module"])
    assert cp.returncode != 0
    assert "unauthenticated_daemon" in (cp.stdout + cp.stderr)
