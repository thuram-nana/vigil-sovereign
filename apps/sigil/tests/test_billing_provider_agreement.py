"""Checkout and the money-IN drain agree on ONE payment processor, by construction.

`config.billing_provider()` is the one resolver of VIGIL_BILLING_PROVIDER (unset/blank -> stripe, the default;
stripe / flutterwave name themselves; anything else -> refuse). Checkout (`provision._checkout_provider`), a bare
`sigil billing-drain` and a bare `sigil ops-sweep tx-refs` (argparse default None -> `cli._billing_lane`) all
resolve through it, so the processor checkout takes payments on is the one whose spool a bare drain credits and a
bare sweep reconciles. Two sources of truth would let checkout take Stripe payments while a bare drain reconciled the
Flutterwave spool: paid, never credited. An explicit `--provider` still names its own lane (each drain unit pins its
processor's spool). Every probe runs the REAL code: the provisioner's selector, and `cli.main` argv parsing.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sigil import cli
from sigil.governor.billing import FlutterwaveBillingProvider, StripeBillingProvider
from test_customer_checkout import _iso, _provisioner  # noqa: F401  (_iso: autouse isolation)
from test_customer_checkout_stripe import _stripe_on, _with_fake_stripe


@pytest.fixture()
def home(monkeypatch):
    """A hermetic SIGIL_HOME for `cli.main` (its store-operability gate reads config.SPINE_PATH), with both drain
    lanes' enable flags unset so each lane refuses at its FIRST check, naming itself."""
    from sigil import config
    from sigil.governor.identity import ensure_owner_keypair
    d = tempfile.mkdtemp()
    monkeypatch.setenv("SIGIL_HOME", d)
    monkeypatch.setenv("HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "SPINE_PATH", Path(d) / "spine" / "spine.jsonl")
    for k in ("VIGIL_BILLING_DRAIN_ENABLED", "VIGIL_STRIPE_BILLING_DRAIN_ENABLED"):
        monkeypatch.delenv(k, raising=False)
    ensure_owner_keypair()
    return Path(d)


def _both_processors_provisioned(monkeypatch):
    """Stripe and Flutterwave both fully provisioned, so only the selector decides (it is set afterwards)."""
    _stripe_on(monkeypatch)
    _with_fake_stripe(monkeypatch)
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "flw-" + "x")
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", "flw-" + "key")


def _select(monkeypatch, selector):
    if selector is None:
        monkeypatch.delenv("VIGIL_BILLING_PROVIDER", raising=False)
    else:
        monkeypatch.setenv("VIGIL_BILLING_PROVIDER", selector)


def _checkout_kind():
    p, *_rest = _provisioner()
    provider = p._checkout_provider()
    if isinstance(provider, StripeBillingProvider):
        return "stripe"
    if isinstance(provider, FlutterwaveBillingProvider):
        return "flutterwave"
    assert provider is None, provider
    return None


# Each drain lane's FIRST refusal (its own enable flag unset) names that lane; the resolver's refusal names none.
_LANE_SIGNATURES = {"billing-drain --provider stripe is disabled": "stripe",
                    "billing-drain is disabled (set VIGIL_BILLING_DRAIN_ENABLED=1": "flutterwave",
                    "names no known payment processor": None}


def _drain_lane(capsys, *flag):
    """The lane `sigil billing-drain drain [flag]` runs, read off the refusal it exits 2 with."""
    with pytest.raises(SystemExit) as ei:
        cli.main(["billing-drain", "drain", *flag])
    err = capsys.readouterr().err
    assert ei.value.code == 2, err
    hits = [lane for signature, lane in _LANE_SIGNATURES.items() if signature in err]
    assert len(hits) == 1, err
    return hits[0]


def _sweep_provider(monkeypatch, capsys, tmp_path, *flag):
    """The processor `sigil ops-sweep tx-refs [flag]` reads its spool as (None: it refused, before any work)."""
    from sigil import ops_sweeps
    seen: list = []
    monkeypatch.setattr(ops_sweeps, "sweep_dangling_tx_refs",
                        lambda checkouts, **kw: seen.append(kw["provider"]) or {"applied": False, "items": []})
    checkouts, spool = tmp_path / "checkouts.jsonl", tmp_path / "spool"
    checkouts.write_text("")
    spool.mkdir(exist_ok=True)
    try:
        cli.main(["ops-sweep", "tx-refs", "--checkouts", str(checkouts), "--spool", str(spool), *flag])
    except SystemExit as exc:
        assert exc.code == 2 and "names no known payment processor" in capsys.readouterr().err
        assert seen == []
        return None
    assert len(seen) == 1, seen
    return seen[0]


@pytest.mark.parametrize("selector, expected", [
    (None, "stripe"), ("", "stripe"), ("stripe", "stripe"), (" Stripe ", "stripe"),
    ("flutterwave", "flutterwave"), ("FLUTTERWAVE", "flutterwave"), ("strpe", None), ("paypal", None)])
def test_checkout_the_bare_drain_and_the_bare_sweep_resolve_one_processor(home, monkeypatch, capsys, tmp_path,
                                                                          selector, expected):
    """For every VIGIL_BILLING_PROVIDER value, the processor checkout builds, the lane a bare `billing-drain` runs
    and the processor a bare `ops-sweep tx-refs` reads are ONE processor — Stripe when the selector is unset — or all
    three refuse: checkout can never take a payment on one processor while a bare drain credits the other's spool."""
    _both_processors_provisioned(monkeypatch)
    _select(monkeypatch, selector)
    resolved = (_checkout_kind(), _drain_lane(capsys), _sweep_provider(monkeypatch, capsys, tmp_path))
    assert resolved == (expected, expected, expected)


@pytest.mark.parametrize("selector, flag", [(None, "flutterwave"), ("stripe", "flutterwave"),
                                            ("flutterwave", "stripe"), ("paypal", "flutterwave"),
                                            ("paypal", "stripe")])
def test_an_explicit_provider_names_its_own_lane_whatever_checkout_uses(home, monkeypatch, capsys, tmp_path,
                                                                        selector, flag):
    """An explicit `--provider` names its lane whatever the selector says: the Flutterwave unit pins
    `--provider flutterwave` and must keep draining its spool after checkout moves to Stripe (a renewal of a plan sold
    through Flutterwave is still paid there) — even while a mistyped selector has checkout refusing."""
    _both_processors_provisioned(monkeypatch)
    _select(monkeypatch, selector)
    assert _drain_lane(capsys, "--provider", flag) == flag
    assert _sweep_provider(monkeypatch, capsys, tmp_path, "--provider", flag) == flag
