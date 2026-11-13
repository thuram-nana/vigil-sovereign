"""E3a — the SHIPPED units meet in ONE money seam: real processes, real files, the units' own environment.

Before E3a nothing on the GO-LIVE path set VIGIL_BASE_DIR. The cockpit (sigil-cockpit.service,
WorkingDirectory=%h/.sigil) published the credit lease under a CWD-relative ``.vigil-live`` — ~/.sigil/.vigil-live
— while the settle drain (vigil-settle-drain.service) was handed ``--base-dir %h/.sigil/credit-lease`` and the
offense backup (backup.env ``VIGIL_BASE_DIR=.vigil-live`` under WorkingDirectory=%h/vigil) captured
~/vigil/.vigil-live. Three trees: the drain found no lease, archived every completion as a no-op (a cancel never
refunded, credits held), and the backup missed the tree the cockpit wrote.

These tests install the shipped env examples exactly as the runbooks say (``cp …env.example …``, set only the
delegation), build each process's environment and working directory FROM THE SHIPPED UNIT FILE (Environment=
with %h expanded, EnvironmentFile values literal and overriding, WorkingDirectory, the ExecStart argv), and run:
  1. the cockpit's reserve + publish (the real LaunchGate default, as provision.launch_start does) + a signed
     CANCELED completion onto the drain's spool;
  2. the real ``sigil settle-drain drain`` CLI with the drain unit's argv/env/cwd.
The drain must settle (full refund), and the offense backup's --base-dir must contain the published lease.
A settle-drain.env still carrying a contradictory legacy VIGIL_SETTLE_BASE_DIR must make the drain REFUSE
before it claims or archives anything.

Sovereign leg (no framework): PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_UNITS = {"cockpit": _REPO / "apps/sigil/deploy/systemd/sigil-cockpit.service",
          "settle": _REPO / "infra/systemd/vigil-settle-drain.service",
          "backup": _REPO / "infra/systemd/vigil-backup.service"}
_PYPATH = os.pathsep.join(str(_REPO / p) for p in ("apps/sigil", "integration", "packages/core/vigil_core"))

_COCKPIT_STEP = r'''
import itertools, json, sys
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import _customer_slug, add_customer_target
from vigil_core import AuthorizerKey, generate_keypair
from vigil_integration.jobs.completion_signal import emit_completion_signal
spool, deleg_path = sys.argv[1], sys.argv[2]
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
it = itertools.count(1)
store = SpineStore()
owner = ensure_owner_keypair()
orgs = OrgRegistry(store)
orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(it)))
orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(it)))
WalletRegistry(store).grant(ORG, 100, "trial", entry_id="trial:" + ORG, issued_at=float(next(it)))
reg = AssetOwnershipRegistry(store)
ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(it)))
reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
g = LaunchGate(store)                                   # NO base_dir: exactly as provision.launch_start builds it
r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=30, now=NOW)
assert r["ok"], r
assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
gov = generate_keypair()
slug = _customer_slug(ORG, HOST)
deleg = delegate_offense_governance(
    owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
    threshold=1, scope=slug, not_after=9_000_000_000)
open(deleg_path, "w", encoding="utf-8").write(deleg.model_dump_json())
emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                       signers=[("gov", gov.private_key_b64)], spool_dir=spool)
print(json.dumps({"slug": slug, "nonce": r["nonce"], "available": WalletRegistry(store).available(ORG)}))
'''

_STATE_STEP = r'''
import json, sys
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from vigil_integration.live.credit_lease_broker import is_lease_settled
slug, nonce, seam = sys.argv[1:]
print(json.dumps({"available": WalletRegistry(SpineStore()).available("org_a"),
                  "settled": is_lease_settled(seam, slug, nonce)}))
'''


def _env_file(path: Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _unit(name: str, home: Path) -> "tuple[dict, str, list]":
    """(env, cwd, ExecStart argv) the way systemd builds them for this USER unit: Environment= (%h expanded),
    then every present EnvironmentFile= (values literal) overriding it; WorkingDirectory; ExecStart ${VAR}s."""
    env: dict = {}
    files, cwd, exec_start = [], str(home), ""
    for raw in _UNITS[name].read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line[0] in "#;[" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "Environment":
            for tok in shlex.split(value):
                k, v = tok.split("=", 1)
                env[k] = v.replace("%h", str(home))
        elif key == "EnvironmentFile":
            files.append(Path(value.lstrip("-").replace("%h", str(home))))
        elif key == "WorkingDirectory":
            cwd = value.replace("%h", str(home))
        elif key == "ExecStart":
            exec_start = value
    for f in files:
        if f.is_file():
            env.update(_env_file(f))
    argv = []
    for w in shlex.split(exec_start.replace("%h", str(home))):
        if w.startswith("${") and w.endswith("}"):
            w = env.get(w[2:-1], "")
        argv.append(w)
    return env, cwd, argv


def _run(argv, *, env_extra, cwd, home, check=True):
    env = {k: v for k, v in os.environ.items()
           if k not in ("VIGIL_BASE_DIR", "VIGIL_SETTLE_BASE_DIR", "SIGIL_SPINE_DIR")}
    env.update({"HOME": str(home), "SIGIL_HOME": str(home / ".sigil"), "PYTHONPATH": _PYPATH})
    env.update(env_extra)
    Path(cwd).mkdir(parents=True, exist_ok=True)
    p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
    if check:
        assert p.returncode == 0, (argv, p.stdout, p.stderr)
    return p


def _install(home: Path, *, settle_extra: str = "") -> Path:
    """The runbooks' install steps: copy the shipped env examples, set ONLY the delegation (ABSOLUTE)."""
    (home / ".sigil").mkdir(parents=True)
    cfg = home / ".config" / "vigil"
    cfg.mkdir(parents=True)
    (home / ".sigil" / "cockpit.env").write_text(
        (_REPO / "apps/sigil/deploy/cockpit.env.example").read_text(encoding="utf-8"), encoding="utf-8")
    deleg = cfg / "offense-governance-delegation.json"
    settle = (_REPO / "infra/systemd/vigil-settle-drain.env.example").read_text(encoding="utf-8")
    settle = settle.replace("VIGIL_SETTLE_DELEGATION=/home/USER/.config/vigil/offense-governance-delegation.json",
                            f"VIGIL_SETTLE_DELEGATION={deleg}")
    from sigil.ui.target_authorization import _customer_slug        # the drain's scope = the delegated cust_ slug
    settle += f"VIGIL_SETTLE_SCOPE={_customer_slug('org_a', 'apme.cm')}\n"
    (cfg / "settle-drain.env").write_text(settle + settle_extra, encoding="utf-8")
    (cfg / "backup.env").write_text(
        (_REPO / "infra/systemd/vigil-backup.env.example").read_text(encoding="utf-8"), encoding="utf-8")
    return deleg


def _publish_and_complete(home: Path, deleg: Path) -> "tuple[dict, dict, str, list]":
    c_env, c_cwd, _ = _unit("cockpit", home)
    s_env, s_cwd, s_argv = _unit("settle", home)
    _run([sys.executable, "-m", "sigil", "upgrade"], env_extra=c_env, cwd=c_cwd, home=home)   # install flow
    step = home / "cockpit_step.py"
    step.write_text(_COCKPIT_STEP, encoding="utf-8")
    out = _run([sys.executable, str(step), s_env["VIGIL_SETTLE_SPOOL"], str(deleg)],
               env_extra=c_env, cwd=c_cwd, home=home)
    pub = json.loads(out.stdout.strip().splitlines()[-1])
    assert pub["available"] == 70                                     # 30 of 100 held by the reservation
    assert s_argv[0].endswith("/bin/sigil") and s_argv[1:3] == ["settle-drain", "drain"]
    return pub, s_env, s_cwd, [sys.executable, "-m", "sigil", *s_argv[1:]]


def _state(home, pub, seam, env_extra, cwd):
    step = home / "state_step.py"
    step.write_text(_STATE_STEP, encoding="utf-8")
    p = _run([sys.executable, str(step), pub["slug"], pub["nonce"], seam], env_extra=env_extra, cwd=cwd, home=home)
    return json.loads(p.stdout.strip().splitlines()[-1])


def test_shipped_units_settle_a_published_lease_and_back_up_its_tree(tmp_path):
    home = tmp_path / "home"
    deleg = _install(home)
    pub, s_env, s_cwd, drain = _publish_and_complete(home, deleg)
    leases = sorted(home.rglob("credit-launch-leases/*.json"))
    assert len(leases) == 1, leases
    seam = leases[0].parent.parent                                    # where the cockpit actually published

    p = _run(drain, env_extra=s_env, cwd=s_cwd, home=home)
    assert "1 settled, 0 noop" in p.stdout, (p.stdout, p.stderr)      # the drain read THE cockpit's lease
    st = _state(home, pub, str(seam), s_env, s_cwd)
    assert st == {"available": 100, "settled": True}                  # canceled ⇒ full refund, marker in the seam

    b_env, b_cwd, b_argv = _unit("backup", home)                      # the offense backup's --base-dir
    base = Path(b_argv[b_argv.index("--base-dir") + 1])
    base = base if base.is_absolute() else Path(b_cwd) / base
    assert os.path.normpath(base) == os.path.normpath(seam), (base, seam)


def test_a_contradictory_legacy_settle_base_refuses_before_archiving(tmp_path):
    home = tmp_path / "home"
    deleg = _install(home, settle_extra=f"VIGIL_SETTLE_BASE_DIR={home / 'elsewhere'}\n")
    pub, s_env, s_cwd, drain = _publish_and_complete(home, deleg)
    p = _run(drain, env_extra=s_env, cwd=s_cwd, home=home, check=False)
    assert p.returncode == 2 and "contradictory seam base settings" in p.stderr, (p.stdout, p.stderr)
    spool = Path(s_env["VIGIL_SETTLE_SPOOL"])
    assert len(list((spool / "incoming").iterdir())) == 1             # nothing claimed ...
    assert not (spool / "processed").exists() or not any((spool / "processed").iterdir())   # ... or archived
    assert _state(home, pub, s_env["VIGIL_BASE_DIR"], s_env, s_cwd)["available"] == 70   # still held, not lost


@pytest.mark.parametrize("unit", sorted(_UNITS))
def test_every_shipped_seam_unit_sets_the_same_vigil_base_dir(unit):
    """Explicit and identical: each shipped unit on the launch path carries the one seam base in a unit directive
    (where %h expands) — not left to a CWD-relative default or an env-file value systemd never expands."""
    lines = [ln.strip() for ln in _UNITS[unit].read_text(encoding="utf-8").splitlines()]
    assert "Environment=VIGIL_BASE_DIR=%h/.sigil/credit-lease" in lines
    assert not any(ln.startswith("Environment=VIGIL_SETTLE_BASE_DIR") for ln in lines)
