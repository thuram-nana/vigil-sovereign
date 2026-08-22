# W16-STD-3a — `authorize-destruction` writes its single-use token with `O_EXCL`

Issue: [#529](https://github.com/thuram-nana/vigil-sovereign/issues/529) ·
Milestone: W16 — DECLARED-LIMITATION BURNDOWN.

## The claim (registered in the claims registry — [W0-3] #398, id `W16-STD-3a`)

<!-- CLAIM:W16-STD-3a -->
> **Registered claim (W0-3 #398):** `vigil authorize-destruction` writes the single-use signed authorization with `O_EXCL`, so a second authorize-destruction to the same path fails rather than overwriting the still-unspent token.

## Why it is TRUE of the code

The signed-authorization file is a single-use token (one authorization → one destructive PR; durably
enforced at spend time by the `O_EXCL` nonce ledger). The writer previously used `O_WRONLY | O_CREAT |
O_TRUNC`, which silently clobbered an existing token in place — a TOCTOU/reuse hole of the exact class the
LAP nonce-ledger fix closed. `destruction_provision.write_single_use_authorization` now opens the file with
`O_WRONLY | O_CREAT | O_EXCL` (0600); a second write raises `AuthorizationExistsError` and the CLI reports
it and exits non-zero, leaving the original token intact. The operator must remove/rename a spent token to
mint a fresh one, which is what keeps the single-use property sound.

Enforced by `integration/vigil_integration/live/destruction_provision.py::write_single_use_authorization`
(called from `authorize-destruction` in `cli.py`); proved by
`integration/tests/test_destruction_provision.py` (a first legit write succeeds — the negative control — and
a second write to the same path is refused).
