"""The edge swap (tools/deploy/edge-swap.sh) and the units it drives (deploy/systemd/sigil-{customer,public}@.service).

The script runs here against stand-in `systemctl`, `curl` and `sleep` (a state directory records which units run
and which loopback ports answer /healthz), so the ORDER is checked exactly:
  start the new instance on the free port -> its /healthz answers -> settle -> enable new -> stop old -> disable old;
a new edge that never answers (or dies) is stopped and the old one is never touched; nothing running, a busy
port or a wrong argument changes nothing. The template units are pinned to the plain units' lifecycle, env file
and hardening, and the release runbook's stop list covers their instances.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "tools" / "deploy" / "edge-swap.sh"
UNITS = REPO / "apps" / "sigil" / "deploy" / "systemd"

_SYSTEMCTL = r"""#!/usr/bin/env bash
# stand-in: systemctl --user <verb> <unit>; state in $FAKE_STATE/{active,listening}; every call logged
[ "$1" = "--user" ] && shift
verb="$1"; shift
[ "$verb" = "is-active" ] && [ "$1" = "--quiet" ] && shift
unit="$1"
echo "$verb $unit" >> "$FAKE_STATE/log"
port_of() { case "$1" in *@*.service) p="${1##*@}"; echo "${p%.service}";; sigil-customer.service) echo 8734;;
            sigil-public.service) echo 8735;; esac; }
case "$verb" in
  is-active) [ -e "$FAKE_STATE/active/$unit" ];;
  start) touch "$FAKE_STATE/active/$unit"
         if ! grep -qx "$unit" "$FAKE_STATE/broken" 2>/dev/null; then touch "$FAKE_STATE/listening/$(port_of "$unit")"; fi
         if grep -qx "$unit" "$FAKE_STATE/dies" 2>/dev/null; then rm -f "$FAKE_STATE/active/$unit"; fi;;
  stop) rm -f "$FAKE_STATE/active/$unit" "$FAKE_STATE/listening/$(port_of "$unit")";;
  enable|disable) :;;
  *) exit 1;;
esac
"""
_CURL = r"""#!/usr/bin/env bash
url="${@: -1}"; port="${url#http://127.0.0.1:}"; port="${port%%/*}"
echo "curl $port" >> "$FAKE_STATE/log"
[ -e "$FAKE_STATE/listening/$port" ]
"""
_SLEEP = """#!/usr/bin/env bash
echo "sleep $1" >> "$FAKE_STATE/log"
"""


def _swap(tmp_path, edge, *, active=(), listening=(), broken=(), dies=(), env=None):
    state, bin_ = tmp_path / "state", tmp_path / "bin"
    for d in (state / "active", state / "listening", bin_):
        d.mkdir(parents=True, exist_ok=True)
    for u in active:
        (state / "active" / u).touch()
    for p in listening:
        (state / "listening" / str(p)).touch()
    (state / "broken").write_text("".join(f"{u}\n" for u in broken))
    (state / "dies").write_text("".join(f"{u}\n" for u in dies))
    for name, body in (("systemctl", _SYSTEMCTL), ("curl", _CURL), ("sleep", _SLEEP)):
        (bin_ / name).write_text(body)
        (bin_ / name).chmod(0o755)
    e = {"PATH": f"{bin_}:{os.environ['PATH']}", "FAKE_STATE": str(state), "VIGIL_EDGE_SWAP_HEALTH_S": "5"}
    e.update(env or {})
    r = subprocess.run(["bash", str(SCRIPT), edge], capture_output=True, text=True, timeout=30, env=e)
    log = (state / "log").read_text().splitlines() if (state / "log").exists() else []
    acts = [ln for ln in log if not ln.startswith(("is-active", "curl"))]
    return r, acts, sorted(p.name for p in (state / "active").iterdir())


@pytest.mark.parametrize("edge,old,new,new_port", [
    ("customer", "sigil-customer.service", "sigil-customer@8744.service", 8744),       # the first swap
    ("customer", "sigil-customer@8744.service", "sigil-customer@8734.service", 8734),
    ("customer", "sigil-customer@8734.service", "sigil-customer@8744.service", 8744),
    ("public", "sigil-public.service", "sigil-public@8745.service", 8745),
    ("public", "sigil-public@8745.service", "sigil-public@8735.service", 8735),
])
def test_a_swap_starts_proves_settles_then_replaces(tmp_path, edge, old, new, new_port):
    old_port = {"sigil-customer.service": 8734, "sigil-public.service": 8735}.get(old) or int(old.split("@")[1][:4])
    r, acts, running = _swap(tmp_path, edge, active=[old], listening=[old_port])
    assert r.returncode == 0, r.stderr
    assert acts == [f"start {new}", "sleep 3", f"enable {new}", f"stop {old}", f"disable {old}"]
    assert running == [new]
    assert f"{old} -> {new}" in r.stdout


def test_the_settle_wait_is_configurable(tmp_path):
    r, acts, _ = _swap(tmp_path, "customer", active=["sigil-customer@8734.service"], listening=[8734],
                       env={"VIGIL_EDGE_SWAP_SETTLE_S": "7"})
    assert r.returncode == 0 and "sleep 7" in acts
    assert acts.index("sleep 7") < acts.index("stop sigil-customer@8734.service")


def test_a_new_edge_that_never_answers_is_stopped_and_the_old_one_keeps_serving(tmp_path):
    r, acts, running = _swap(tmp_path, "customer", active=["sigil-customer@8734.service"], listening=[8734],
                             broken=["sigil-customer@8744.service"])
    assert r.returncode == 1 and "keeps serving" in r.stderr
    assert acts[0] == "start sigil-customer@8744.service" and acts[-1] == "stop sigil-customer@8744.service"
    assert acts.count("sleep 1") == 5                            # VIGIL_EDGE_SWAP_HEALTH_S=5 one-second waits
    assert not any("8734" in a for a in acts) and running == ["sigil-customer@8734.service"]


def test_a_new_edge_whose_unit_dies_is_given_up_at_once(tmp_path):
    r, acts, running = _swap(tmp_path, "public", active=["sigil-public@8745.service"], listening=[8745],
                             broken=["sigil-public@8735.service"], dies=["sigil-public@8735.service"])
    assert r.returncode == 1
    assert acts == ["start sigil-public@8735.service", "stop sigil-public@8735.service"]
    assert running == ["sigil-public@8745.service"]


def test_nothing_running_a_busy_port_or_a_wrong_argument_changes_nothing(tmp_path):
    r, acts, _ = _swap(tmp_path / "a", "customer")
    assert r.returncode == 1 and acts == [] and "no customer edge is running" in r.stderr
    r, acts, _ = _swap(tmp_path / "b", "customer", active=["sigil-customer@8734.service"], listening=[8734, 8744])
    assert r.returncode == 1 and acts == [] and "already answers on port 8744" in r.stderr
    r, acts, _ = _swap(tmp_path / "c", "cockpit")
    assert r.returncode == 2 and acts == []


# ---- the template units ---------------------------------------------------------------------------------------
def _directives(path: Path) -> dict:
    out: dict = {}
    for ln in path.read_text(encoding="utf-8").splitlines():
        if ln and not ln.startswith(("#", "[")) and "=" in ln:
            k, v = ln.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


@pytest.mark.parametrize("edge,cmd", [("customer", "serve-customer --host ${VIGIL_CUSTOMER_BIND}"),
                                      ("public", "serve-public --host ${VIGIL_PUBLIC_BIND}")])
def test_the_template_runs_the_same_edge_on_the_instance_port(edge, cmd):
    plain, tmpl = _directives(UNITS / f"sigil-{edge}.service"), _directives(UNITS / f"sigil-{edge}@.service")
    assert tmpl["ExecStart"] == [f"%h/.sigil/venv/bin/sigil {cmd} --port %i"]
    for key in ("EnvironmentFile", "WorkingDirectory", "Restart", "RestartSec", "KillSignal", "TimeoutStopSec",
                "NoNewPrivileges", "ProtectSystem", "ReadWritePaths", "PrivateTmp", "ProtectKernelTunables",
                "ProtectKernelModules", "ProtectControlGroups", "RestrictSUIDSGID", "LockPersonality", "WantedBy"):
        assert tmpl.get(key) == plain.get(key), key


def test_the_release_runbook_stops_the_template_instances_too():
    text = (REPO / "docs" / "runbooks" / "RELEASE-UPGRADE-ROLLBACK.md").read_text(encoding="utf-8")
    joined = text.replace("\\\n", " ")                        # one line per shell command
    stop = next(ln for ln in joined.splitlines() if ln.startswith("systemctl --user stop sigil-customer.service"))
    assert "'sigil-customer@*.service'" in stop and "'sigil-public@*.service'" in stop


def test_the_swap_names_the_vhost_ports():
    # the script's default ports are the two servers of each shipped nginx upstream
    script = SCRIPT.read_text(encoding="utf-8")
    rp = REPO / "apps" / "sigil" / "deploy" / "reverse-proxy"
    for vhost, a, b in (("vigil-customer.nginx.conf", 8734, 8744), ("vigil-public.nginx.conf", 8735, 8745)):
        conf = (rp / vhost).read_text(encoding="utf-8")
        assert re.search(rf"server 127\.0\.0\.1:{a} max_fails=1 fail_timeout=2s;", conf)
        assert f"server 127.0.0.1:{b} backup;" in conf
        assert f":-{a}}}" in script and f":-{b}}}" in script
    assert 'settle_s="${VIGIL_EDGE_SWAP_SETTLE_S:-3}"' in script     # longer than fail_timeout=2s
