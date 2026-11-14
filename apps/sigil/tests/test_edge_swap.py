"""The edge swap (tools/deploy/edge-swap.sh) and the units it drives (deploy/systemd/sigil-{customer,public}@.service).

The script runs here against stand-in `systemctl`, `curl` and `sleep` (a state directory records which units run,
which loopback ports answer and with which build, and which ports the stand-in reverse proxy names), so the ORDER
is checked exactly. Each hop:
  start the new instance on the free port -> its /healthz answers -> settle -> it still answers -> enable new ->
  stop old -> disable old -> the reverse proxy answers with the new edge's build;
and the swap always ENDS ON THE FIRST PORT (out to the second and back), where nginx's first try succeeds.
A new edge that never answers, dies, or stops answering during the settle is stopped and the old one is never
touched; a proxy that does not reach the new port gets the edge moved back to the port it reached and the swap
fails; a wrong or missing proxy URL, nothing running, a busy port or a wrong argument changes nothing. The template
units are pinned to the plain units' lifecycle, env file and hardening, and the release runbook's stop list covers
their instances.
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
         # a started edge serves the build now on disk
         if ! grep -qx "$unit" "$FAKE_STATE/broken" 2>/dev/null; then
           cp "$FAKE_STATE/build_on_disk" "$FAKE_STATE/listening/$(port_of "$unit")"; fi
         if grep -qx "$unit" "$FAKE_STATE/dies" 2>/dev/null; then rm -f "$FAKE_STATE/active/$unit"; fi;;
  stop) rm -f "$FAKE_STATE/active/$unit" "$FAKE_STATE/listening/$(port_of "$unit")";;
  enable|disable) :;;
  *) exit 1;;
esac
"""
_CURL = r"""#!/usr/bin/env bash
# stand-in: an edge on a loopback port answers /healthz and /version.json (its build); any other URL is the
# reverse proxy, which tries the ports in $FAKE_STATE/proxy in order and answers from the first that listens
url="${@: -1}"; path="/${url#*://*/}"
if [ "${url#http://127.0.0.1:}" != "$url" ]; then
  port="${url#http://127.0.0.1:}"; port="${port%%/*}"; via=""
else
  port=""; via="proxy->"
  for p in $(cat "$FAKE_STATE/proxy"); do [ -e "$FAKE_STATE/listening/$p" ] && { port="$p"; break; }; done
fi
echo "curl $via${port:-none} $path" >> "$FAKE_STATE/log"
[ -n "$port" ] && [ -e "$FAKE_STATE/listening/$port" ] || exit 22
if [ "$path" = /version.json ]; then printf '{"build": "%s"}' "$(cat "$FAKE_STATE/listening/$port")"; fi
"""
_SLEEP = """#!/usr/bin/env bash
echo "sleep $1" >> "$FAKE_STATE/log"
# the settle (any wait but the 1 s health polls): the new edge may fail now
if [ "$1" != 1 ]; then
  for u in $(cat "$FAKE_STATE/settle_exits"); do rm -f "$FAKE_STATE/active/$u"; done
  for p in $(cat "$FAKE_STATE/settle_mute"); do rm -f "$FAKE_STATE/listening/$p"; done
fi
"""


_PROXY = {"customer": (8734, 8744), "public": (8735, 8745)}      # the shipped vhosts' upstreams, first port first
_URL = {"VIGIL_EDGE_SWAP_CUSTOMER_URL": "https://app.example.test", "VIGIL_EDGE_SWAP_PUBLIC_URL": "https://example.test"}


def _swap(tmp_path, edge, *, active=(), listening=(), broken=(), dies=(), settle_exits=(), settle_mute=(),
          env=None, proxy=None, builds=None, disk_build="feed"):
    state, bin_ = tmp_path / "state", tmp_path / "bin"
    for d in (state / "active", state / "listening", bin_):
        d.mkdir(parents=True, exist_ok=True)
    for u in active:
        (state / "active" / u).touch()
    for p in listening:
        (state / "listening" / str(p)).write_text((builds or {}).get(p, "01d0"))   # the running build
    (state / "build_on_disk").write_text(disk_build)                               # what a new edge serves
    (state / "proxy").write_text(" ".join(str(p) for p in (_PROXY.get(edge, ()) if proxy is None else proxy)))
    (state / "broken").write_text("".join(f"{u}\n" for u in broken))
    (state / "dies").write_text("".join(f"{u}\n" for u in dies))
    (state / "settle_exits").write_text("".join(f"{u}\n" for u in settle_exits))
    (state / "settle_mute").write_text("".join(f"{p}\n" for p in settle_mute))
    for name, body in (("systemctl", _SYSTEMCTL), ("curl", _CURL), ("sleep", _SLEEP)):
        (bin_ / name).write_text(body)
        (bin_ / name).chmod(0o755)
    e = {"PATH": f"{bin_}:{os.environ['PATH']}", "FAKE_STATE": str(state), "VIGIL_EDGE_SWAP_HEALTH_S": "5", **_URL}
    e.update(env or {})
    r = subprocess.run(["bash", str(SCRIPT), edge], capture_output=True, text=True, timeout=30, env=e)
    log = (state / "log").read_text().splitlines() if (state / "log").exists() else []
    acts = [ln for ln in log if not ln.startswith(("is-active", "curl"))]
    return r, acts, sorted(p.name for p in (state / "active").iterdir())


def _hop(old: str, new: str) -> list:
    return [f"start {new}", "sleep 3", f"enable {new}", f"stop {old}", f"disable {old}"]


@pytest.mark.parametrize("edge,old,first,second", [
    ("customer", "sigil-customer.service", "sigil-customer@8734.service", "sigil-customer@8744.service"),
    ("customer", "sigil-customer@8734.service", "sigil-customer@8734.service", "sigil-customer@8744.service"),
    ("public", "sigil-public.service", "sigil-public@8735.service", "sigil-public@8745.service"),
    ("public", "sigil-public@8735.service", "sigil-public@8735.service", "sigil-public@8745.service"),
])
def test_a_swap_goes_out_to_the_second_port_and_back_to_the_first(tmp_path, edge, old, first, second):
    # each hop: start, prove, settle, replace — and the edge always comes to rest on the first port, where nginx's
    # first try succeeds (on the second port alone every request first meets the refused first port)
    r, acts, running = _swap(tmp_path, edge, active=[old], listening=[_PROXY[edge][0]])
    assert r.returncode == 0, r.stderr
    assert acts == _hop(old, second) + _hop(second, first)
    assert running == [first]
    assert f"{old} -> {second}" in r.stdout and f"{second} -> {first}" in r.stdout
    assert f"serves on port {_PROXY[edge][0]}" in r.stdout


@pytest.mark.parametrize("edge,on_second,first", [
    ("customer", "sigil-customer@8744.service", "sigil-customer@8734.service"),
    ("public", "sigil-public@8745.service", "sigil-public@8735.service"),
])
def test_from_the_second_port_one_hop_brings_it_to_the_first(tmp_path, edge, on_second, first):
    r, acts, running = _swap(tmp_path, edge, active=[on_second], listening=[_PROXY[edge][1]])
    assert r.returncode == 0, r.stderr
    assert acts == _hop(on_second, first) and running == [first]


def _log(tmp_path) -> list:
    return (tmp_path / "state" / "log").read_text().splitlines()


def test_each_hop_is_proven_through_the_reverse_proxy(tmp_path):
    r, _acts, _running = _swap(tmp_path, "customer", active=["sigil-customer@8734.service"], listening=[8734])
    assert r.returncode == 0, r.stderr
    log = _log(tmp_path)
    marks = [ln for ln in log if ln.startswith(("curl proxy->", "start ", "disable "))]
    # before anything, the proxy reaches the running edge; after each hop, the new one
    assert marks == ["curl proxy->8734 /version.json", "start sigil-customer@8744.service",
                     "disable sigil-customer@8734.service", "curl proxy->8744 /version.json",
                     "start sigil-customer@8734.service", "disable sigil-customer@8744.service",
                     "curl proxy->8734 /version.json"]


def test_a_proxy_answering_from_another_edge_does_not_count_as_reaching_the_new_one(tmp_path):
    # after the first hop the proxy still answers — but from a stray edge serving the old build, not the new edge
    r, acts, running = _swap(tmp_path, "customer", active=["sigil-customer@8734.service"], listening=[8734, 9999],
                             proxy=[8734, 9999])
    assert r.returncode == 1 and "does not reach the edge on port 8744" in r.stderr
    assert running == ["sigil-customer@8734.service"]
    assert acts == (_hop("sigil-customer@8734.service", "sigil-customer@8744.service") + ["sleep 1", "sleep 1"]
                    + _hop("sigil-customer@8744.service", "sigil-customer@8734.service"))


@pytest.mark.parametrize("edge,start", [("customer", "sigil-customer.service"),
                                        ("customer", "sigil-customer@8734.service"),
                                        ("public", "sigil-public@8735.service")])
def test_a_proxy_naming_the_first_port_only_gets_the_edge_back_and_the_swap_fails(tmp_path, edge, start):
    # e.g. a host still on a one-port vhost (`proxy_pass http://127.0.0.1:8734;`) or behind the Caddy examples: the
    # swap must not leave the edge where the proxy cannot reach it, nor report success
    first, second = (f"{edge.join(['sigil-', ''])}@{p}.service" for p in _PROXY[edge])
    r, acts, running = _swap(tmp_path, edge, active=[start], listening=[_PROXY[edge][0]], proxy=[_PROXY[edge][0]])
    assert r.returncode == 1
    assert f"does not reach the edge on port {_PROXY[edge][1]}" in r.stderr and "two-port upstream" in r.stderr
    assert acts == _hop(start, second) + ["sleep 1", "sleep 1"] + _hop(second, first)
    assert running == [first]                                    # where the proxy reaches it
    assert "done" not in r.stdout


def test_a_proxy_that_does_not_reach_the_first_port_gets_the_edge_back_on_the_second(tmp_path):
    r, acts, running = _swap(tmp_path, "customer", active=["sigil-customer@8744.service"], listening=[8744],
                             proxy=[8744])
    assert r.returncode == 1 and "does not reach the edge on port 8734" in r.stderr
    assert acts == (_hop("sigil-customer@8744.service", "sigil-customer@8734.service") + ["sleep 1", "sleep 1"]
                    + _hop("sigil-customer@8734.service", "sigil-customer@8744.service"))
    assert running == ["sigil-customer@8744.service"]


def test_a_new_edge_that_cannot_name_its_build_is_stopped_and_the_old_one_keeps_serving(tmp_path):
    # its build is what the proxy check compares against: an empty one would match a proxy that answers nothing
    r, acts, running = _swap(tmp_path, "customer", active=["sigil-customer@8734.service"], listening=[8734],
                             proxy=[8734], disk_build="")
    assert r.returncode == 1 and "keeps serving" in r.stderr
    assert acts == ["start sigil-customer@8744.service", "sleep 3", "stop sigil-customer@8744.service"]
    assert running == ["sigil-customer@8734.service"]


def test_a_wrong_or_missing_proxy_url_changes_nothing(tmp_path):
    # the URL answers, but with another edge's build (e.g. the public site's URL given for the customer edge)
    r, acts, running = _swap(tmp_path / "a", "customer", active=["sigil-customer@8734.service"],
                             listening=[8734, 8735], builds={8735: "0be1"}, proxy=[8735])
    assert r.returncode == 1 and "does not name the build" in r.stderr and "nothing was changed" in r.stderr
    assert not [a for a in acts if not a.startswith("sleep")] and running == ["sigil-customer@8734.service"]
    # nothing answers there
    r, acts, _ = _swap(tmp_path / "b", "public", active=["sigil-public@8735.service"], listening=[8735], proxy=[])
    assert r.returncode == 1 and not [a for a in acts if not a.startswith("sleep")]
    # no URL at all
    e = {k: "" for k in _URL}
    r, acts, _ = _swap(tmp_path / "c", "customer", active=["sigil-customer@8734.service"], listening=[8734], env=e)
    assert r.returncode == 2 and acts == [] and "VIGIL_EDGE_SWAP_CUSTOMER_URL" in r.stderr
    # a running edge that cannot say which build it serves (an edge from before /version.json)
    r, acts, _ = _swap(tmp_path / "d", "customer", active=["sigil-customer@8734.service"], listening=[8734],
                       builds={8734: ""})
    assert r.returncode == 1 and acts == [] and "does not answer /version.json" in r.stderr


def test_the_settle_wait_is_configurable(tmp_path):
    r, acts, _ = _swap(tmp_path, "customer", active=["sigil-customer@8744.service"], listening=[8744],
                       env={"VIGIL_EDGE_SWAP_SETTLE_S": "7"})
    assert r.returncode == 0 and "sleep 7" in acts
    assert acts.index("sleep 7") < acts.index("stop sigil-customer@8744.service")


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


@pytest.mark.parametrize("how", ["exits", "stops answering"])
def test_a_new_edge_that_fails_during_the_settle_is_stopped_and_the_old_one_keeps_serving(tmp_path, how):
    # the old edge is only stopped once the new one has stayed up for the whole settle
    fail = ({"settle_exits": ["sigil-customer@8734.service"], "settle_mute": [8734]} if how == "exits"
            else {"settle_mute": [8734]})
    r, acts, running = _swap(tmp_path, "customer", active=["sigil-customer@8744.service"], listening=[8744], **fail)
    assert r.returncode == 1 and "during the 3s settle" in r.stderr and "keeps serving" in r.stderr
    assert acts == ["start sigil-customer@8734.service", "sleep 3", "stop sigil-customer@8734.service"]
    assert running == ["sigil-customer@8744.service"]


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
        assert f"server 127.0.0.1:{a} max_fails=0;" in conf
        assert f"server 127.0.0.1:{b} backup max_fails=0;" in conf
        assert f":-{a}}}" in script and f":-{b}}}" in script
    assert 'settle_s="${VIGIL_EDGE_SWAP_SETTLE_S:-3}"' in script
