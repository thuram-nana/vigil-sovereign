"""Red-Pen R4 — the sovereign System-review producer (``ui/redpen_scheduler.py``) and ``sigil redpen-schedule``.

Invariants pinned here (each guard has a named test the mutation table reds):
  * on demand: ONE review is reserved through the W2 path (``reserve_redpen_review``) and ONE owner-signed
    ``profile="full"`` ticket is written; a repeat the same day is idempotent (no second hold, no second ticket),
    and end-to-end the integration drain enqueues exactly ONE job;
  * refused with nothing held and no ticket: an unconnected repo, a repo at its monthly spending limit, Red-Pen off;
  * the scheduler tick enqueues each DUE schedule once per period (weekly + monthly), advances the period on a
    terminal refusal (no per-tick spin), and DEFERS — period kept due — on a transient refusal (billing busy) or
    while the owner's kill switch halts new reservations;
  * cross-tenant: each org's review is reserved against that org's own wallet and carries that org's ticket;
  * it only ENQUEUES: nothing here (producer, ticket, drain) runs a job;
  * ``sigil redpen-schedule``: refuses with Red-Pen off, refuses an implicit / relative / foreign SIGIL_HOME, writes
    its tickets to the seam ``_writer_seam_base(money=True)`` names, and set/status/tick round-trip;
  * BYTE-IDENTICAL when off: no spine record, no ticket, no reservation, from either entry point or the CLI.
"""
from __future__ import annotations

import itertools
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigil import cli, config
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.killswitch import KillSwitch
from sigil.governor.orgs import OrgRegistry
from sigil.governor.redpen_schedule import RedPenScheduleRegistry, period_key
from sigil.governor.redpen_spend import RedPenSpendLedger
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.redpen_scheduler import RedPenScheduler
from sigil.ui.target_authorization import _customer_slug
from vigil_core import AuthorizerKey, TrustRoot, model_metering as mm, verify_credit_launch_lease
from vigil_core.rate_card import RATE_CARD_ENV
from vigil_integration.jobs.queue import SecurityJobQueue
from vigil_integration.jobs.redpen_system_trigger import RedPenSystemDrain
from vigil_integration.live.redpen_system_seam import list_system_tickets, read_system_ticket, tickets_root

_iss = itertools.count(1)
ORG, ORG2 = "org_a", "org_b"
REPO, REPO2, REPO_B = "github.com/acme/widgets", "github.com/acme/gadgets", "github.com/beta/tools"


def _ts(y: int, mo: int, d: int, h: int = 12) -> float:
    return datetime(y, mo, d, h, tzinfo=timezone.utc).timestamp()


MON_W47 = _ts(2026, 11, 16)
WED_W47 = _ts(2026, 11, 18)
MON_W48 = _ts(2026, 11, 23)


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("HOME", str(tmp_path / "home"))           # no host unit/env file can leak into a verdict
    # `cli.main()` runs its store-operability gate (assert_operable) against config.SPINE_PATH — bound at import
    # and shared across the process — BEFORE reaching `cmd_redpen_schedule`. Point it at this test's fresh home so
    # a legacy single-file spine another test left at the import-time default can't refuse the verb with exit 3
    # before it reaches its own fail-closed refusals (exit 2). Mirrors test_cli_billing_drain's convention.
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine" / "spine.jsonl")
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, "0.5")
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES", "VIGIL_MODEL_GATEWAY_ENABLED",
              mm.ALLOWANCE_CHUNK_ENV, RATE_CARD_ENV, "VIGIL_TIERED_PRODUCTS", "VIGIL_SETTLE_BASE_DIR",
              *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _org(store, org, *, credits=100_000, repos=(), limit=0):
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}:{next(_iss)}",
                                    issued_at=float(next(_iss)))
    for repo in repos:
        ConnectedRepoRegistry(store).connect(org, 42, repo, monthly_limit_credits=limit, issued_at=float(next(_iss)))


def _setup(store, *, credits=100_000, limit=0, connect=True):
    ensure_owner_keypair()
    _org(store, ORG, credits=credits, repos=(REPO,) if connect else (), limit=limit)
    return RedPenScheduler(store, base_dir=_seam())


def _seam() -> str:
    import os
    return os.environ["VIGIL_BASE_DIR"]


def _avail(store, org=ORG):
    return WalletRegistry(store).available(org)


def _owner_root():
    return TrustRoot(threshold=1, authorizers=[AuthorizerKey(
        key_id="owner", name="owner", public_key_b64=ensure_owner_keypair().public_key_b64)])


class _FakeScheduler:
    """The durable FIFO under SecurityJobQueue, faked so no framework is needed: the queue's OWN delivery and
    fingerprint markers (the exactly-once machinery under test) stay real."""

    def __init__(self):
        self.rows: list = []

    def enqueue(self, slug, *, params):
        self.rows.append((slug, params))
        return SimpleNamespace(job_id=f"j{len(self.rows)}", seq=len(self.rows))


def _drain(tmp_path, sched, *, now):
    queue = SecurityJobQueue(tmp_path / "queue", scheduler=sched)
    return RedPenSystemDrain(base_dir=_seam(), queue=queue, now=now).drain()


# ---- on demand ------------------------------------------------------------------------------------------------
def test_on_demand_reserves_one_review_and_writes_one_full_profile_ticket():
    s = _store()
    rp = _setup(s)
    before = _avail(s)
    r = rp.enqueue_system_review(ORG, REPO, now=MON_W47)
    assert r["ok"] and r["slug"] == _customer_slug(ORG, REPO) and r["nonce"] == "od-2026-11-16"
    ticket = read_system_ticket(_seam(), r["slug"])
    assert ticket is not None and ticket.profile == "full" and ticket.repo == REPO and ticket.org_id == ORG
    assert verify_credit_launch_lease(ticket.signed_lease, _owner_root())[0]      # an owner-signed lease rides along
    assert ticket.signed_lease.document.scope_host == REPO and ticket.signed_lease.document.nonce == r["nonce"]
    assert _avail(s) == before - ticket.signed_lease.document.units_reserved      # held through the W2 path


def test_on_demand_is_idempotent_the_same_day():
    s = _store()
    rp = _setup(s)
    first = rp.enqueue_system_review(ORG, REPO, now=MON_W47)
    held = _avail(s)
    again = rp.enqueue_system_review(ORG, REPO, now=MON_W47 + 3600)
    assert again["ok"] and again.get("already") is True and again["nonce"] == first["nonce"]
    assert _avail(s) == held                                                     # no second hold
    assert len(list_system_tickets(_seam())) == 1


def test_on_demand_enqueues_exactly_one_job_end_to_end(tmp_path):
    s = _store()
    rp = _setup(s)
    sched = _FakeScheduler()
    rp.enqueue_system_review(ORG, REPO, now=MON_W47)
    assert _drain(tmp_path, sched, now=MON_W47 + 60) == {"enqueued": 1, "duplicate": 0, "deferred": 0}
    rp.enqueue_system_review(ORG, REPO, now=MON_W47 + 120)                      # a double-click, the same day
    assert _drain(tmp_path, sched, now=MON_W47 + 180) == {"enqueued": 0, "duplicate": 1, "deferred": 0}
    assert len(sched.rows) == 1
    slug, params = sched.rows[0]
    assert slug == _customer_slug(ORG, REPO)
    assert params["profile"] == "full" and params["source"] == "scheduled" and params["repo"] == REPO
    assert params["tenant_id"] == ORG and params["extra"]["lease"]["document"]["nonce"] == "od-2026-11-16"


def test_on_demand_refuses_an_unconnected_repo_with_nothing_held_and_no_ticket():
    s = _store()
    rp = _setup(s, connect=False)
    before = _avail(s)
    r = rp.enqueue_system_review(ORG, REPO, now=MON_W47)
    assert r["ok"] is False and "not connected" in r["error"]
    assert _avail(s) == before and list_system_tickets(_seam()) == []


def test_on_demand_refuses_at_the_monthly_spending_limit():
    s = _store()
    rp = _setup(s, limit=50)
    RedPenSpendLedger(s).record_charge(ORG, REPO, 50, nonce="prev", now=MON_W47)
    before = _avail(s)
    r = rp.enqueue_system_review(ORG, REPO, now=MON_W47)
    assert r["ok"] is False and "monthly" in r["error"]
    assert _avail(s) == before and list_system_tickets(_seam()) == []


# ---- the scheduled tick -----------------------------------------------------------------------------------------
def _schedule(store, org, repo, cadence):
    RedPenScheduleRegistry(store).set_schedule(org, repo, cadence=cadence, issued_at=float(next(_iss)))


def test_the_tick_enqueues_each_due_schedule_once_per_period():
    s = _store()
    ensure_owner_keypair()
    _org(s, ORG, repos=(REPO, REPO2))
    _schedule(s, ORG, REPO, "weekly")
    _schedule(s, ORG, REPO2, "monthly")
    rp = RedPenScheduler(s, base_dir=_seam())
    out = rp.tick(MON_W47)
    assert out["enqueued"] == 2 and out["refused"] == 0 and out["deferred"] == 0
    nonces = {t.repo: t.signed_lease.document.nonce for t in list_system_tickets(_seam())}
    assert nonces == {REPO: f"sch-{period_key('weekly', MON_W47)}", REPO2: f"sch-{period_key('monthly', MON_W47)}"}
    assert rp.tick(WED_W47)["enqueued"] == 0                                    # same week, same month: nothing due
    third = rp.tick(MON_W48)                                                     # next ISO week: the weekly one only
    assert third["enqueued"] == 1 and [d["repo"] for d in third["details"]] == [REPO]


def test_the_tick_records_the_period_on_a_terminal_refusal():
    s = _store()
    rp = _setup(s, limit=50)
    _schedule(s, ORG, REPO, "weekly")
    RedPenSpendLedger(s).record_charge(ORG, REPO, 50, nonce="prev", now=MON_W47)
    before = _avail(s)
    out = rp.tick(MON_W47)
    assert out["refused"] == 1 and out["enqueued"] == 0 and "monthly" in out["details"][0]["reason"]
    assert RedPenScheduleRegistry(s, owner_key=None).due(MON_W47) == []         # attempted once: no per-tick spin
    assert _avail(s) == before and list_system_tickets(_seam()) == []


def test_the_tick_defers_while_the_owner_kill_switch_halts_new_reviews():
    s = _store()
    rp = _setup(s)
    _schedule(s, ORG, REPO, "weekly")
    KillSwitch(s).engage(reason="test halt")
    before = _avail(s)
    out = rp.tick(MON_W47)
    assert out["deferred"] == 1 and out["enqueued"] == 0 and out["refused"] == 0
    assert RedPenScheduleRegistry(s, owner_key=None).due(MON_W47) == [(ORG, REPO, "weekly")]   # period kept due
    assert _avail(s) == before and list_system_tickets(_seam()) == []
    KillSwitch(s).release(issued_at=float(next(_iss)) + 1e6)
    assert rp.tick(MON_W47 + 60)["enqueued"] == 1                               # released: the same period runs


class _BusyGate:
    """A gate whose reserve reports the TRANSIENT 'billing busy' refusal (the settle lock held elsewhere)."""

    def __init__(self):
        self.calls = 0

    def reserve_redpen_review(self, **_kw):
        self.calls += 1
        return {"ok": False, "retry": True, "error": "billing is busy right now; please retry in a moment"}

    def _new_launch_refusal(self):
        return None


def test_the_tick_defers_a_transient_billing_busy_refusal():
    s = _store()
    ensure_owner_keypair()
    _org(s, ORG, repos=(REPO,))
    _schedule(s, ORG, REPO, "weekly")
    gate = _BusyGate()
    rp = RedPenScheduler(s, gate=gate, base_dir=_seam())
    assert rp.tick(MON_W47)["deferred"] == 1
    assert RedPenScheduleRegistry(s, owner_key=None).due(MON_W47) == [(ORG, REPO, "weekly")]   # retried next tick
    assert rp.tick(MON_W47 + 60)["deferred"] == 1 and gate.calls == 2


def test_each_org_review_is_reserved_against_its_own_wallet():
    s = _store()
    ensure_owner_keypair()
    _org(s, ORG, credits=100_000, repos=(REPO,))
    _org(s, ORG2, credits=100_000, repos=(REPO_B,))
    _schedule(s, ORG, REPO, "weekly")
    _schedule(s, ORG2, REPO_B, "monthly")
    a0, b0 = _avail(s, ORG), _avail(s, ORG2)
    assert RedPenScheduler(s, base_dir=_seam()).tick(MON_W47)["enqueued"] == 2
    by_repo = {t.repo: t for t in list_system_tickets(_seam())}
    assert by_repo[REPO].org_id == ORG and by_repo[REPO].signed_lease.document.org_id == ORG
    assert by_repo[REPO_B].org_id == ORG2 and by_repo[REPO_B].signed_lease.document.org_id == ORG2
    assert _avail(s, ORG) == a0 - by_repo[REPO].signed_lease.document.units_reserved
    assert _avail(s, ORG2) == b0 - by_repo[REPO_B].signed_lease.document.units_reserved


def test_the_scheduler_only_enqueues_it_never_runs_a_job(tmp_path):
    # the producer writes a ticket and the drain enqueues it — the queue's claim (the runner's first step) is never
    # reached: nothing on the scheduler path executes a review
    s = _store()
    rp = _setup(s)
    _schedule(s, ORG, REPO, "weekly")
    rp.tick(MON_W47)
    queue = SecurityJobQueue(tmp_path / "queue", scheduler=_FakeScheduler())
    claimed: list = []
    queue.claim_next = lambda: claimed.append(1)                                 # type: ignore[method-assign]
    RedPenSystemDrain(base_dir=_seam(), queue=queue, now=MON_W47 + 60).drain()
    assert claimed == []


def test_a_seam_migration_carries_a_pending_ticket_so_no_held_review_is_stranded(monkeypatch, tmp_path):
    from sigil import seam_migrate
    legacy, new = tmp_path / "legacy-seam", tmp_path / "credit-lease"
    legacy.mkdir()
    new.mkdir()
    monkeypatch.setenv("VIGIL_BASE_DIR", str(legacy))
    s = _store()
    ensure_owner_keypair()
    _org(s, ORG, repos=(REPO,))
    r = RedPenScheduler(s, base_dir=str(legacy)).enqueue_system_review(ORG, REPO, now=MON_W47)
    assert r["ok"] and read_system_ticket(str(legacy), r["slug"]) is not None
    monkeypatch.setenv("VIGIL_BASE_DIR", str(new))                     # the processes now use the units' seam
    code, rep = seam_migrate.run(s, ensure_owner_keypair(), seam=new, sources=[str(legacy)], apply=True,
                                 now=MON_W47 + 60)
    assert code == 0, rep
    carried = read_system_ticket(str(new), r["slug"])
    assert carried is not None and carried.signed_lease.document.nonce == r["nonce"]
    sched = _FakeScheduler()
    out = RedPenSystemDrain(base_dir=str(new), queue=SecurityJobQueue(tmp_path / "q", scheduler=sched),
                            now=MON_W47 + 120).drain()
    assert out["enqueued"] == 1                                       # the drain on the new seam still enqueues it


# ---- byte-identical when off ------------------------------------------------------------------------------------
def test_with_red_pen_off_nothing_is_read_written_or_reserved(monkeypatch, capsys):
    s = _store()
    rp = _setup(s)
    _schedule(s, ORG, REPO, "weekly")
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED")
    n0, before = sum(1 for _ in s.iter_records()), _avail(s)
    assert rp.tick(MON_W47) == {"enqueued": 0, "refused": 0, "deferred": 0, "details": [], "skipped": True}
    r = rp.enqueue_system_review(ORG, REPO, now=MON_W47)
    assert r["ok"] is False and "Red-Pen is off" in r["error"]
    monkeypatch.setattr(cli, "SpineStore", lambda: s)
    for argv in (["redpen-schedule"], ["redpen-schedule", "enqueue", ORG, REPO],
                 ["redpen-schedule", "set", ORG, REPO, "--cadence", "monthly"]):
        with pytest.raises(SystemExit) as e:
            cli.main(argv)
        assert e.value.code == 2
    assert "Red-Pen is off" in capsys.readouterr().err
    assert sum(1 for _ in s.iter_records()) == n0 and _avail(s) == before
    assert not tickets_root(_seam()).exists()


# ---- `sigil redpen-schedule` ------------------------------------------------------------------------------------
def test_cli_set_status_tick_round_trip(monkeypatch, capsys):
    import json
    s = _store()
    _setup(s)
    monkeypatch.setattr(cli, "SpineStore", lambda: s)
    cli.main(["redpen-schedule", "set", ORG, REPO, "--cadence", "weekly", "--now", str(MON_W47)])
    assert "weekly System review scheduled" in capsys.readouterr().out
    cli.main(["redpen-schedule", "status", "--now", str(MON_W47)])
    (row,) = json.loads(capsys.readouterr().out)
    assert row["repo"] == REPO and row["cadence"] == "weekly" and row["due"] is True
    cli.main(["redpen-schedule", "tick", "--now", str(MON_W47)])
    assert json.loads(capsys.readouterr().out)["enqueued"] == 1
    cli.main(["redpen-schedule", "status", "--now", str(WED_W47)])
    assert json.loads(capsys.readouterr().out)[0]["due"] is False
    cli.main(["redpen-schedule", "clear", ORG, REPO])
    cli.main(["redpen-schedule", "status", "--now", str(MON_W48)])
    assert json.loads(capsys.readouterr().out.split("\n", 1)[1]) == []


def test_cli_writes_tickets_to_the_seam_the_money_units_use(monkeypatch, tmp_path):
    s = _store()
    _setup(s)
    monkeypatch.setattr(cli, "SpineStore", lambda: s)
    units_seam = tmp_path / "units-seam"
    asked: list = []

    def _writer(verb, *, money=False):
        asked.append((verb, money))
        return str(units_seam)
    monkeypatch.setattr(cli, "_writer_seam_base", _writer)
    cli.main(["redpen-schedule", "enqueue", ORG, REPO, "--now", str(MON_W47)])
    assert asked == [("redpen-schedule enqueue", True)]
    assert len(list_system_tickets(units_seam)) == 1 and list_system_tickets(_seam()) == []


def test_cli_refuses_a_seam_the_configured_money_units_do_not_use(monkeypatch, tmp_path, capsys):
    # a real disagreement: the installed cockpit names one seam, this shell resolves another -> refused before any
    # reservation (a held review whose ticket the drain would never read)
    s = _store()
    _setup(s)
    monkeypatch.setattr(cli, "SpineStore", lambda: s)
    home = Path(tmp_path / "home")
    unit = Path(__file__).resolve().parents[1] / "deploy" / "systemd" / "sigil-cockpit.service"
    udir = home / ".config" / "systemd" / "user"
    udir.mkdir(parents=True)
    (udir / "sigil-cockpit.service").write_text(unit.read_text(encoding="utf-8"), encoding="utf-8")
    before = _avail(s)
    with pytest.raises(SystemExit) as e:
        cli.main(["redpen-schedule", "enqueue", ORG, REPO, "--now", str(MON_W47)])
    assert e.value.code == 2 and "refusing" in capsys.readouterr().err
    assert _avail(s) == before and list_system_tickets(_seam()) == []


@pytest.mark.parametrize("home_value", ["", "relative/home", "%h/.sigil"])
def test_cli_refuses_an_implicit_or_unexpanded_sigil_home(monkeypatch, capsys, home_value):
    s = _store()
    _setup(s)
    monkeypatch.setattr(cli, "SpineStore", lambda: s)
    monkeypatch.setenv("SIGIL_HOME", home_value)
    with pytest.raises(SystemExit) as e:
        cli.main(["redpen-schedule", "tick", "--now", str(MON_W47)])
    assert e.value.code == 2 and "SIGIL_HOME" in capsys.readouterr().err
    assert list_system_tickets(_seam()) == []


def test_cli_refuses_a_sigil_home_the_cockpit_does_not_use(monkeypatch, tmp_path, capsys):
    s = _store()
    _setup(s)
    monkeypatch.setattr(cli, "SpineStore", lambda: s)
    cockpit_env = tmp_path / "home" / ".sigil" / "cockpit.env"
    cockpit_env.parent.mkdir(parents=True)
    cockpit_env.write_text(f"SIGIL_HOME={tmp_path / 'the-cockpits-home'}\n", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cli.main(["redpen-schedule", "tick", "--now", str(MON_W47)])
    assert e.value.code == 2 and "not the cockpit's" in capsys.readouterr().err


def test_cli_refuses_a_home_with_no_owner_identity(monkeypatch, capsys):
    s = _store()
    _setup(s)
    monkeypatch.setattr(cli, "SpineStore", lambda: s)
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: None)
    with pytest.raises(SystemExit) as e:
        cli.main(["redpen-schedule", "tick", "--now", str(MON_W47)])
    assert e.value.code == 2 and "no owner identity" in capsys.readouterr().err
