"""apt-retry.sh must bound a HUNG apt operation with `timeout`, not let it burn the whole job timeout.

Root cause of the recurring P5/P6 cancellations: `apt-get update` HUNG on a stuck mirror connection for the
job's entire timeout (~30m) and the job was CANCELLED. `apt-retry.sh` retried on *failure* but a hang never
returns, so the retry never fired. The fix wraps each apt op in `timeout`, converting a hang into a
retryable non-zero exit. This test proves it: a stub apt-get that HANGS must be killed and the script must
EXIT (non-zero) quickly — without the `timeout` wrapper it would run forever (this test would hit its own
subprocess timeout, i.e. fail).
"""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "apt-retry.sh"


def _write_exe(p: Path, body: str) -> None:
    p.write_text(body, encoding="utf-8")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_script_wraps_both_apt_ops_in_timeout():
    """Static guard: a future edit cannot silently drop the hang protection."""
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "timeout" in src, "apt-retry.sh must use `timeout` to bound a hung apt op"
    # both the update and the install must be under a timeout
    assert "timeout" in src and "apt-get update" in src and "apt-get install" in src
    # the ceilings must be present and overridable
    assert "APT_RETRY_UPDATE_TIMEOUT" in src and "APT_RETRY_INSTALL_TIMEOUT" in src


def test_a_hung_apt_get_is_killed_and_the_script_exits_quickly(tmp_path: Path):
    """Behavioural: a stub apt-get that HANGS on `update` is killed by `timeout`; the script exits (non-zero)
    within a small bound instead of hanging forever. Fail-before: remove the `timeout` wrappers and this
    subprocess would run past its own timeout (the fake apt-get sleeps 3600s)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    # `sudo` -> just exec the rest (no privilege needed in the test)
    _write_exe(bindir / "sudo", '#!/usr/bin/env bash\nexec "$@"\n')
    # `apt-get` -> hang for an hour (simulates the stuck-mirror update)
    _write_exe(bindir / "apt-get", '#!/usr/bin/env bash\nsleep 3600\n')
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["APT_RETRY_UPDATE_TIMEOUT"] = "1"   # kill the hang after 1s per attempt
    env["APT_RETRY_INSTALL_TIMEOUT"] = "1"
    # 4 attempts * ~1s + backoffs(5+15+45=65s) ~= 70s worst case; give a safe outer bound.
    proc = subprocess.run(["bash", str(_SCRIPT), "nftables"], env=env,
                          capture_output=True, text=True, timeout=120)
    # It must FAIL (persistent hang) but must NOT have hung past the outer timeout — reaching here proves it
    # returned. Non-zero because every attempt was killed.
    assert proc.returncode != 0, "a persistently-hanging apt-get should fail the step, not pass"
    assert "hang-timeout" in (proc.stderr or "") or "124" in (proc.stderr or ""), \
        f"expected the hang to be reported as a timeout; stderr:\n{proc.stderr}"
