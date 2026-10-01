# Egress-floor engine residuals (deferred, tracked)

Status: OPEN — deferred to dedicated slices. Tracked by the egress-floor completeness guard
`engine/crucible/framework/v2/verify/tests/test_egress_floor_complete.py` (the `DEFERRED` set), which
fails the build if either site below loses the referenced tracking (this file) or changes shape.

## What this records

The completeness guard classifies every egress primitive under `framework/v2` as a floor primitive,
floored (routed through `resolve_and_pin` / `pin_egress` and dialing the pinned IP), or covered-elsewhere
(its own gate + a covering test). Three residuals remain: two genuine engagement-egress-to-a-target sites
are **not yet floored** at all (R1, R2) because flooring them soundly needs its own slice — each must
thread an engagement **slug** into the floor (so the charter can lift loopback/RFC1918 for an authorized
literal), and neither is on a live, gated, FACT-minting path today; and one **validate-only** site (R3)
where the floor *does* run and refuse metadata/RFC1918 on every hop but the HTTP client re-resolves at
connect, leaving a narrow connect-time-rebind TOCTOU. They are recorded here rather than rush-floored (a
sloppy mass change) or falsely allowlisted (an allowlist entry is a claim that *another gate* covers the
site — R1/R2 have none; R3 is honestly labeled `covered` validate-only, not `floored`).

### R1 — `scanner/quantum_era.py::pqc_scan` (socket.create_connection, TLS)

`pqc_scan(host, port)` opens a real TLS handshake to `(host, port)` with no egress floor. It is a library
scanner (exported from `scanner/__init__.py`) with **no live FACT-minting caller** — only the module
exports and its own tests invoke it, always against `127.0.0.1`. Flooring it means threading an
engagement slug from a gated campaign driver and either pinning the dial IP (mirroring `verify/tls.py`'s
`dial_ip` + `server_hostname=host`) or refusing a non-floored call. The loopback-only test corpus must be
migrated to a scoped charter at the same time, so this is a slice, not a one-liner.

**Scope of the gap:** dormant until a gated driver wires `pqc_scan` to a target host; today it cannot be
reached with a non-loopback host from any live engagement path.

### R2 — `scanner/csp_bypass.py::_gated_fetch_headers` (urllib build_opener/open)

`_gated_fetch_headers(url)` is the loopback/dev **fallback** fetch for the CSP-bypass confirmation. The
live product supplies **retained** response headers from the gated, egress-floored `web_redrive` channel
(`integration/.../live/web_redrive.py`, which calls `pin_egress`), so the live path does not use this
helper. The fallback can still reach a target if a caller passes `response_headers=None` with a target
URL. Flooring the fallback (resolve-and-refuse / pin) needs a slug threaded through `confirm_csp_bypass`.

**Scope of the gap:** the live confirmation path is floored (via `web_redrive`); this is the unfloored
fallback, reachable only when a caller omits the retained headers.

### R3 — `agents/http_executor.py` httpx path (validate-only, connect-time rebind TOCTOU)

`_assert_egress_floor` runs `resolve_and_pin` on the host before **every** `client.request` hop, so a
metadata / link-local / RFC1918 destination (direct, or the DNS answer at check time) is refused and the
request never leaves. But the actual socket is opened by `httpx` / `httpcore`, which **re-resolves** the
name at connect — so a name that rebinds in the narrow window *between* the floor check and the connect
could still be dialled. This is the same validate-only posture as `intake/http.py` (classified `covered`,
not `floored`) and the same TOCTOU class that Wave 2 closed for `verify/reachability_cloud.py` via an
SNI-preserving dial-the-pinned-IP. Closing it here means a custom httpx transport (or resolver) that
connects to the floor-validated IP while preserving `Host` / SNI — a dedicated hardening slice, because
httpcore manages connection reuse and resolution internally.

**Scope of the gap:** metadata/RFC1918/link-local are refused on every hop by the validate step; the
residual is only a precisely-timed rebind in the check→connect window on the httpx path. The census labels
this site `covered` (validate-only), never `floored`, so the completeness guard does not overclaim it.

## Invariants held while deferring

- `_ALL_ORACLES` stays 15 (no oracle touched); no FACT minted on either path.
- FATAL-2 holds: the engine imports no `vigil_integration`.
- Fail-closed throughout the floor primitives these slices will reuse.
