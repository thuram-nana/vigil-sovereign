# W1-7 — The AEGIS runtime is aligned to the Python minor the locks target

Issue: milestone W1 — CI ENFORCEMENT, item **W1-7** (#416) ·
Registered in the claims registry ([W0-3] #398, id `W1-7`).

## The defect

`engine/crucible/framework/v2/aegis/Dockerfile` pinned `python:3.11-slim` while the committed hash-locks
— and every CI job, and the sibling `gateway/Dockerfile` data-plane image — target **3.13**. So the
interpreter that SHIPS in the public-facing AEGIS gateway image was the one minor CI never exercised, and
nothing asserted the two agreed. A base-image bump on either side could silently drift them apart again.

## The fix

1. **Align the image.** The AEGIS Dockerfile now pins `python:3.13-slim` at the SAME content digest the
   gateway image already uses (`@sha256:ffb752e1…`, resolved 2026-08-12) — a real, content-addressed pin,
   not a mutable tag, and the same base the locks were resolved against.
2. **Assert it, with a negative control.** `integration/tests/test_aegis_dockerfile_wired.py` derives the
   image's Python minor from the Dockerfile and the locked minor from `envs/build_envs.sh` (the script
   that builds the two hash-locked environments and pins `python3.13`) and asserts they are equal, so the
   alignment cannot silently rot. Changing the Dockerfile's pin without updating the locks turns the
   assertion red; a paired negative control proves the predicate fires on a mismatch and passes on a
   match (it is neither a no-op nor always-red).
3. **Matrix.** A cross-version `python-compat` CI job runs the version-sensitive guard suite under Python
   3.12 AND 3.13, so the alignment invariant is proven on more than the single minor CI used to exercise.

## The claim (registered in the claims registry — [W0-3] #398, id `W1-7`)

<!-- CLAIM:W1-7 -->
> **Registered claim (W0-3 #398):** The AEGIS gateway Dockerfile pins the same Python minor the committed locks target, and a required CI test asserts the two are equal and turns red if either the Dockerfile pin or the locked target drifts.

## Why this is TRUE of the code

- **Enforced by** `aegis_python_pin_drift` in `integration/tests/test_aegis_dockerfile_wired.py`: it
  returns a drift description unless the AEGIS Dockerfile's `FROM python:X.Y` base equals the minor
  `envs/build_envs.sh` pins, and `test_aegis_runtime_python_is_aligned_to_the_locked_target` asserts it is
  `None`. This runs in the **required** `integration two-env boundary (P5)` job (pure stdlib file reads —
  no Docker daemon, no network — so it belongs in the sovereign leg alongside `test_supply_chain.py`).
- **Residual (honest).** The committed hash-locks target 3.13, so the FULL test suites still run only on
  3.13; the `python-compat` matrix broadens the *version-sensitive guards* to 3.12, not the whole tree.
  Running the full runtime suite on 3.12 would need a second 3.12 hash-lock — tracked separately, not
  claimed here.
