"""PRICING G1 — the pure capacity mechanism (``sigil.gateway_capacity``): the rate-limit header parser, the
capacity lane (never exceed the provider's remaining; honour retry-after; fail closed on a malformed header), the
per-tenant fair share (a deterministic N-tenants-one-greedy simulation), and the provider-account pool with health
and failover selection.
"""
from __future__ import annotations

import datetime as dt

from sigil import gateway_capacity as gc

NOW = 1_000_000.0


def _reset(offset: float) -> str:
    return dt.datetime.fromtimestamp(NOW + offset, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _headers(**over) -> dict:
    h = {
        "anthropic-ratelimit-requests-limit": "1000",
        "anthropic-ratelimit-requests-remaining": "400",
        "anthropic-ratelimit-requests-reset": _reset(30),
        "anthropic-ratelimit-tokens-limit": "80000",
        "anthropic-ratelimit-tokens-remaining": "50000",
        "anthropic-ratelimit-tokens-reset": _reset(30),
        "anthropic-ratelimit-input-tokens-limit": "60000",
        "anthropic-ratelimit-input-tokens-remaining": "40000",
        "anthropic-ratelimit-input-tokens-reset": _reset(30),
        "anthropic-ratelimit-output-tokens-limit": "20000",
        "anthropic-ratelimit-output-tokens-remaining": "12000",
        "anthropic-ratelimit-output-tokens-reset": _reset(30),
        "anthropic-workspace-id": "wrk_main",
        "retry-after": "7",
    }
    h.update(over)
    return {k: v for k, v in h.items() if v is not None}    # a None override DROPS that header


# --------------------------------------------------------------------------- header parsing
def test_every_rate_limit_header_is_read():
    snap = gc.parse_rate_limit_headers(_headers(), NOW)
    assert snap.trusted and snap.present and snap.workspace_id == "wrk_main" and snap.retry_after == 7
    assert snap.dim("requests") == gc._Dim(limit=1000, remaining=400, reset=NOW + 30)
    # token remaining is rounded to the nearest thousand by the provider: taken half-a-rounding below it
    assert snap.dim("tokens").remaining == 50_000 - 500
    assert snap.dim("input_tokens").remaining == 40_000 - 500
    assert snap.dim("output_tokens").remaining == 12_000 - 500


def test_header_case_is_ignored():
    snap = gc.parse_rate_limit_headers(
        {"Anthropic-RateLimit-Requests-Limit": "10", "ANTHROPIC-RATELIMIT-REQUESTS-REMAINING": "4",
         "anthropic-ratelimit-requests-reset": _reset(5)}, NOW)
    assert snap.trusted and snap.dim("requests").remaining == 4


def test_a_malformed_header_fails_closed_to_untrusted():
    # remaining greater than the limit, an unparseable reset, a reset far in the past, a non-digit, a partial triple
    for bad in (
        {"anthropic-ratelimit-requests-remaining": "9999"},                 # remaining > limit
        {"anthropic-ratelimit-requests-reset": "not-a-date"},               # bad reset
        {"anthropic-ratelimit-requests-reset": _reset(-10_000)},            # far in the past
        {"anthropic-ratelimit-requests-limit": "1_000"},                    # non-digit (underscore)
        {"anthropic-ratelimit-requests-limit": "-5"},                       # negative
    ):
        snap = gc.parse_rate_limit_headers(_headers(**bad), NOW)
        assert not snap.trusted and snap.dims == {}


def test_a_half_read_dimension_is_untrusted():
    h = {"anthropic-ratelimit-requests-limit": "10", "anthropic-ratelimit-requests-remaining": "4"}  # no reset
    snap = gc.parse_rate_limit_headers(h, NOW)
    assert not snap.trusted and snap.dims == {}


def test_two_conflicting_values_for_one_header_are_untrusted():
    # a full, otherwise-valid header set PLUS a conflicting duplicate of one header: without the duplicate guard the
    # last value would win and the snapshot would be trusted, so this isolates the guard
    base = list(_headers(**_NO_RETRY).items())

    class _Multi(dict):
        def items(self):
            return base + [("anthropic-ratelimit-requests-limit", "2000")]   # conflicts with the "1000" above
    assert gc.parse_rate_limit_headers(dict(base), NOW).trusted               # the base alone IS trusted
    snap = gc.parse_rate_limit_headers(_Multi(), NOW)
    assert not snap.trusted                                                   # the duplicate makes it untrusted


def test_no_rate_headers_is_trusted_but_empty():
    snap = gc.parse_rate_limit_headers({"content-type": "application/json"}, NOW)
    assert snap.trusted and snap.dims == {} and not snap.present and snap.retry_after is None


def test_retry_after_is_seconds_only_and_clamped():
    assert gc.parse_retry_after("12") == 12
    assert gc.parse_retry_after("0") is None                       # below one second: treated as absent
    assert gc.parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT") is None   # an HTTP-date is not a seconds value
    assert gc.parse_retry_after("soon") is None
    assert gc.parse_retry_after(None) is None
    assert gc.parse_retry_after("99999") == gc._MAX_RETRY_AFTER_S          # clamped


def test_the_spend_cap_429_carries_no_retry_after():
    # the provider's spend-cap 429 rate_limit_error has no retry-after: the snapshot shows None, the gateway
    # backs off on its own
    h = {"anthropic-ratelimit-requests-limit": "1000", "anthropic-ratelimit-requests-remaining": "1000",
         "anthropic-ratelimit-requests-reset": _reset(1)}
    snap = gc.parse_rate_limit_headers(h, NOW)
    assert snap.retry_after is None and snap.trusted


# --------------------------------------------------------------------------- capacity lane
_NO_RETRY = {"retry-after": None}


def test_a_lane_never_reserves_past_the_providers_remaining():
    lane = gc.CapacityLane()
    lane.observe(gc.parse_rate_limit_headers(_headers(**_NO_RETRY), NOW), NOW)
    # requests remaining 400: 400 reservations fit, the 401st does not (within the same instant, no refill)
    for _ in range(400):
        assert lane.reserve(1, 1, NOW)
    assert not lane.reserve(1, 1, NOW)


def test_a_reservation_bigger_than_the_output_remaining_is_refused():
    lane = gc.CapacityLane()
    lane.observe(gc.parse_rate_limit_headers(_headers(**_NO_RETRY), NOW), NOW)
    # output remaining is 12000-500 = 11500; a request wanting 20000 output tokens cannot fit
    assert not lane.reserve(1, 20_000, NOW)
    assert lane.reserve(1, 10_000, NOW)         # one that fits does


def test_a_lane_refills_at_the_per_minute_rate_between_snapshots():
    lane = gc.CapacityLane()
    # requests: limit 600 (=> 10/s), remaining 10
    h = {"anthropic-ratelimit-requests-limit": "600", "anthropic-ratelimit-requests-remaining": "10",
         "anthropic-ratelimit-requests-reset": _reset(60)}
    lane.observe(gc.parse_rate_limit_headers(h, NOW), NOW)
    for _ in range(10):
        assert lane.reserve(1, 0, NOW)
    assert not lane.reserve(1, 0, NOW)          # emptied
    assert lane.reserve(1, 0, NOW + 1.0)        # one second later, ~10 refilled


def test_retry_after_pauses_the_lane():
    lane = gc.CapacityLane()
    lane.observe(gc.parse_rate_limit_headers(_headers(), NOW), NOW)   # retry-after 7
    assert lane.paused(NOW)
    assert not lane.reserve(1, 1, NOW)
    assert not lane.reserve(1, 1, NOW + 6.9)
    assert lane.reserve(1, 1, NOW + 7.1)        # the pause has elapsed


def test_a_malformed_snapshot_is_ignored_keeping_the_last_good_limits():
    lane = gc.CapacityLane()
    lane.observe(gc.parse_rate_limit_headers(_headers(**_NO_RETRY), NOW), NOW)
    before = lane.limits()
    lane.observe(gc.parse_rate_limit_headers(_headers(**{"anthropic-ratelimit-requests-remaining": "999999"}), NOW),
                 NOW)
    assert lane.limits() == before             # the untrusted snapshot did not change the lane


def test_an_untrusted_snapshot_does_not_pause_the_lane():
    # a malformed snapshot that nonetheless carries a retry-after must NOT pause the lane (it is not trusted)
    lane = gc.CapacityLane()
    bad = gc.parse_rate_limit_headers(_headers(**{"anthropic-ratelimit-requests-remaining": "999999"}), NOW)
    assert not bad.trusted and bad.retry_after == 7
    lane.observe(bad, NOW)
    assert not lane.paused(NOW)                 # the untrusted snapshot was ignored whole, pause and all


def test_an_unsized_lane_never_blocks_so_the_stand_ins_bound():
    lane = gc.CapacityLane()                     # no snapshot yet
    assert not lane.known()
    for _ in range(10_000):
        assert lane.reserve(10 ** 9, 10 ** 9, NOW)   # fail closed to the stand-in semaphores (unbounded here)


def test_settle_returns_the_unused_part_of_a_reservation():
    lane = gc.CapacityLane()
    h = {"anthropic-ratelimit-output-tokens-limit": "100000", "anthropic-ratelimit-output-tokens-remaining": "10000",
         "anthropic-ratelimit-output-tokens-reset": _reset(60),
         "anthropic-ratelimit-tokens-limit": "1000000", "anthropic-ratelimit-tokens-remaining": "1000000",
         "anthropic-ratelimit-tokens-reset": _reset(60),
         "anthropic-ratelimit-input-tokens-limit": "1000000", "anthropic-ratelimit-input-tokens-remaining": "1000000",
         "anthropic-ratelimit-requests-limit": "1000", "anthropic-ratelimit-requests-remaining": "1000",
         "anthropic-ratelimit-requests-reset": _reset(60),
         "anthropic-ratelimit-input-tokens-reset": _reset(60)}
    lane.observe(gc.parse_rate_limit_headers(h, NOW), NOW)
    assert lane.reserve(1000, 9000, NOW)         # output remaining 10000-500=9500 -> reserve 9000 fits
    assert not lane.reserve(0, 1000, NOW)        # only 500 output left
    lane.settle(1000, 9000, actual_input=1000, actual_output=100)   # it really used 100 output
    assert lane.reserve(0, 1000, NOW)            # the 8900 output given back now fits a 1000-token request


# --------------------------------------------------------------------------- the fair share (the simulation)
def test_within_the_fair_share_every_tenant_is_served():
    sched = gc.FairShareScheduler(capacity_rpm=100.0, capacity_tpm=10 ** 9)
    # four tenants each demanding exactly their fair share (25) are all admitted
    for t in ("a", "b", "c", "d"):
        for _ in range(25):
            assert sched.admit(t, 1.0, 1.0, NOW)


def test_one_greedy_tenant_cannot_starve_the_others():
    """The deterministic simulation the spec asks for: N tenants, one greedy. Under steady contention (every tenant
    offers work each tick) the greedy tenant is capped at its fair share while every modest tenant is fully served."""
    sched = gc.FairShareScheduler(capacity_rpm=100.0, capacity_tpm=10 ** 9)
    want = {"greedy": 100, "m1": 25, "m2": 25, "m3": 25}
    admitted = {t: 0 for t in want}
    # round-robin ticks at a FIXED instant (one minute window): each tenant that still wants to send tries once
    for _ in range(max(want.values())):
        for t in want:
            if admitted[t] < want[t] and sched.admit(t, 1.0, 1.0, NOW):
                admitted[t] += 1
    assert admitted["m1"] == 25 and admitted["m2"] == 25 and admitted["m3"] == 25   # modest tenants fully served
    assert admitted["greedy"] == 25                                                 # greedy capped at its fair share
    assert sum(admitted.values()) == 100                                            # and the capacity is not exceeded


def test_a_greedy_tenant_may_use_slack_no_one_else_needs():
    # one tenant alone may use the whole capacity (work-conserving), since no one else is active
    sched = gc.FairShareScheduler(capacity_rpm=10.0, capacity_tpm=10 ** 9)
    admitted = sum(1 for _ in range(100) if sched.admit("solo", 1.0, 1.0, NOW))
    assert admitted == 10          # the whole per-minute capacity, not just a 1/N share


def test_fairness_is_inactive_without_a_known_capacity():
    sched = gc.FairShareScheduler(capacity_rpm=None, capacity_tpm=None)
    for _ in range(10_000):
        assert sched.admit("anyone", 1.0, 10 ** 9, NOW)      # the stand-in semaphores bound the account instead


def test_the_token_dimension_is_bounded_too():
    sched = gc.FairShareScheduler(capacity_rpm=10 ** 9, capacity_tpm=1000.0)
    # two tenants: each fair share is 500 tokens; a greedy one is capped there under contention
    want = {"greedy": 4000, "modest": 500}
    got = {t: 0 for t in want}
    for _ in range(8):
        for t, step in (("greedy", 500), ("modest", 500)):
            if got[t] < want[t] and sched.admit(t, 1.0, float(step), NOW):
                got[t] += step
    assert got["modest"] == 500 and got["greedy"] == 500


# --------------------------------------------------------------------------- the account pool
def _pool(n=2):
    return gc.AccountPool([gc.ProviderAccount(account_id=f"ws{i}", api_key=f"sk-{i}", workspace_id=f"w{i}")
                           for i in range(n)], down_s=30.0)


def test_the_pool_refuses_a_second_cloud_at_the_interface():
    import pytest
    with pytest.raises(ValueError) as exc:
        gc.AccountPool([gc.ProviderAccount(account_id="bedrock", api_key="k", kind="bedrock")])
    assert "overflow" in str(exc.value) or "not wired" in str(exc.value)


def test_a_pool_needs_distinct_account_ids_and_at_least_one():
    import pytest
    with pytest.raises(ValueError):
        gc.AccountPool([])
    with pytest.raises(ValueError):
        gc.AccountPool([gc.ProviderAccount("x", "k"), gc.ProviderAccount("x", "k2")])


def test_choose_skips_a_down_account_and_health_restores_it():
    pool = _pool(2)
    assert set(pool.healthy_ids(NOW)) == {"ws0", "ws1"}
    pool.mark_down("ws0", NOW, "http 500")
    # a down account is NEVER chosen (round-robin would otherwise return it on some calls)
    assert all(pool.choose("cls", 1, 1, NOW) == "ws1" for _ in range(6))
    assert pool.down_ids(NOW) == ["ws0"]
    assert pool.down_ids(NOW + 31) == []               # the down window elapsed
    pool.mark_up("ws0", NOW + 31)
    assert set(pool.healthy_ids(NOW + 31)) == {"ws0", "ws1"}


def test_choose_prefers_an_account_with_capacity():
    pool = _pool(2)
    # size ws0 small, ws1 large; a request that fits only ws1 picks ws1
    small = {"anthropic-ratelimit-requests-limit": "1", "anthropic-ratelimit-requests-remaining": "0",
             "anthropic-ratelimit-requests-reset": _reset(60)}
    pool.observe("ws0", "cls", gc.parse_rate_limit_headers(small, NOW), NOW)
    assert pool.choose("cls", 1, 1, NOW) == "ws1"      # ws0 has no request capacity


def test_capacity_aggregates_only_healthy_accounts_with_a_known_limit():
    pool = _pool(2)
    assert pool.capacity("cls", NOW) == (None, None)   # no snapshot yet: unknown
    h = {"anthropic-ratelimit-requests-limit": "100", "anthropic-ratelimit-requests-remaining": "100",
         "anthropic-ratelimit-requests-reset": _reset(60),
         "anthropic-ratelimit-tokens-limit": "1000", "anthropic-ratelimit-tokens-remaining": "1000",
         "anthropic-ratelimit-tokens-reset": _reset(60)}
    pool.observe("ws0", "cls", gc.parse_rate_limit_headers(h, NOW), NOW)
    pool.observe("ws1", "cls", gc.parse_rate_limit_headers(h, NOW), NOW)
    assert pool.capacity("cls", NOW) == (200.0, 2000.0)    # summed over both healthy accounts
    pool.mark_down("ws1", NOW, "err")
    assert pool.capacity("cls", NOW) == (100.0, 1000.0)    # only the healthy one counts
