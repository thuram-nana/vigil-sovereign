# Egress posture — one page

How VIGIL controls outbound traffic. There are four independent layers, and each one only ever **narrows**
what can be reached.

| Layer | What it enforces | Where |
|---|---|---|
| **Egress floor** (never liftable) | Before connecting, resolve the name and refuse metadata / link-local / private addresses, even if a charter lists them. Then connect to the exact IP that was checked, so DNS rebinding cannot swap the target. | Integration: [`egress_floor.py`](../../integration/vigil_integration/live/egress_floor.py) (`pin_egress`, `EgressPin`). Engine connectors: [`egress_pin.py`](../../engine/crucible/framework/v2/common/egress_pin.py). Shared denylist: [`gateway/vigil_gateway/denylist.py`](../../gateway/vigil_gateway/denylist.py) |
| **Gateway** | L7 forward proxy plus scope matching. Deny-default nftables at L3/L4: from the sandbox subnet, only the proxy and the gateway DNS can be reached, so unsetting proxy env vars gains nothing. | [`proxy.py`](../../gateway/vigil_gateway/proxy.py), [`scope_match.py`](../../gateway/vigil_gateway/scope_match.py), [`nftables.py`](../../gateway/vigil_gateway/nftables.py) |
| **In-process allowlist** | A sovereign-mode httpx transport. A request to a host outside the allowlist raises `SovereigntyViolation` before any bytes are sent. | [`agents/egress_guard.py`](../../engine/crucible/framework/v2/agents/egress_guard.py) |
| **Seccomp egress guard** (tool subprocesses) | A seccomp user-notify supervisor wrapped around external tools, covering forked children too. It is opt-in through `VIGIL_EGRESS_GUARD`, and the production posture forces it to `require` (fail closed). It refuses to wrap privileged binaries it would silently break. | [`live/egress_guard.py`](../../integration/vigil_integration/live/egress_guard.py) |
| **Kill-switch** | A persistent file-on-disk hard stop. While it is tripped, the authority gate refuses every action, and the trip survives crashes and restarts. Only an explicit, logged operator act clears it. | [`authority/killswitch.py`](../../engine/crucible/framework/v2/authority/killswitch.py). Fleet-wide: `vigil panic` / `vigil emergency-stop` |

## Composition

- A request must pass **every** layer. No layer can re-enable what another one denies. In particular, a
  charter can never lift the floor/denylist.
- Fail closed: if the floor cannot classify an address, it refuses. If the guard is unavailable under
  `require`, the tool does not start. A tripped kill-switch blocks everything.
- Honest bounds are documented in the module docstrings. Examples: the urllib anonymous-GET path in
  `reachability_cloud.py` is check-only, and the seccomp guard strips privilege. Read those docstrings
  before claiming more coverage than the code provides.

See also [PANIC-AND-CONTAINMENT.md](PANIC-AND-CONTAINMENT.md) and [`gateway/README.md`](../../gateway/README.md).
