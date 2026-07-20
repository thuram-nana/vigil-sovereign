# VIGIL environments — two isolated locks (FATAL-2)

VIGIL is **not** one environment. The offense-free guarantee requires two that never share an
interpreter:

| Env | Members | Rule |
|-----|---------|------|
| **env-sovereign** (`.venv-sovereign`) | `vigil_core` + `apps/sigil` + `integration` | MUST NOT contain `framework.*` (CRUCIBLE) or `strix.*`. That absence makes `assert_no_offense()` hold by construction. |
| **env-offense** (`.venv-offense`) | `vigil_core` + `engine/crucible` + `vendor/strix` + `gateway` + `integration` | Runs the offense engine as a **keyless** process (no owner key). |

Build both (prefers `uv`, falls back to venv+pip):

```bash
bash envs/build_envs.sh        # creates .venv-sovereign and .venv-offense, then verifies the boundary
```

The member sets are `envs/sovereign.txt` and `envs/offense.txt` (editable installs). The uv
workspace root (`/pyproject.toml`) lists all members for discovery; the two **isolated** locks are
these two sets, because a single uv workspace resolves to one shared environment — which is exactly
what the boundary forbids.

**The boundary is proven, not promised:** `integration/tests/test_two_env_boundary.py` demonstrates
that in a sovereign-only interpreter the offense namespaces are unimportable and the guard passes,
with a negative control that the guard fires when an offense module is loaded. `build_envs.sh` runs
the same check against the freshly built `.venv-sovereign`.
