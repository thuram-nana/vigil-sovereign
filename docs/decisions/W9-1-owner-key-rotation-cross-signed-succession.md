# W9-1 — Owner-key rotation as a signed key history with cross-signed succession

Issue: [#434](https://github.com/thuram-nana/vigil-sovereign/issues/434) ·
Milestone: W9 — KEY LIFECYCLE & PRODUCTION POSTURE.

## The claim (register in the claims registry, [W0-3] #398)

> The sovereign owner key can be ROTATED. `sigil key rotate` mints a successor and CROSS-SIGNS it into
> an append-only owner-key history — `sig_prev` (the incumbent authorizes the successor) plus `sig_new`
> (the successor proves possession) over one canonical statement. Verification WALKS that succession
> chain from a **pinned genesis root** and authenticates every spine record under the owner key valid
> **at that record's seq**. So after a rotation **every pre-rotation head and grant still verifies**
> (nothing is orphaned), while a NEW record forged with a retired key at a later seq is **refused**. A
> broken or **forked** succession is **fail-closed** (DENY). For an actual key compromise, `sigil key
> re-genesis` re-pins a fresh root and **deliberately abandons** verifiable continuity of all prior
> history.

This claim is TRUE of the code as of W9-1.

## Why rotation used to orphan everything

Every governance fold and the head anchor verified against a **single** owner pubkey at threshold 1
(`accounts.py`, `promotion.py`, `killswitch.py`, `capability.py`, `offense_gate.py`,
`mesh/registry.py`, and `spine/checkpoint.py::verify_head`/`classify_head`). A naive key swap left every
historical head/grant signed by the retired key, and none of them verified under the new one — the
single largest missing security capability.

## The design

- **The record** — a dedicated, W5-1-versioned spine kind `owner_key_history`
  (`apps/sigil/sigil/spine/models.py::KINDS`). Its payload (`apps/sigil/sigil/governor/key_history.py`)
  carries `{signal, mode, epoch, prev_pubkey, new_pubkey, issued_at}` plus `sig_prev` + `sig_new`. Both
  signatures are over the identical canonical core, so the record binds `prev → new` atomically:
  mutating `new_pubkey` breaks `sig_prev` (only the incumbent private-key holder can authorize a
  successor), and `sig_new` proves the successor key is real and controlled.
- **The walk** (`build_succession`) — starts at the pinned genesis and extends only on a validly
  cross-signed record that chains from the current tip at the strictly-next epoch. A record that is not
  validly cross-signed, or does not chain from the tip, is **ignored** (injecting garbage cannot advance
  or brick the chain). A genuine FORK — the incumbent cross-signing two different successors at one epoch
  — raises `SuccessionError`; every consumer treats that as DENY-all until a re-genesis. A fork can only
  be produced by the owner private-key holder, so it is not a DoS vector for a non-holder.
- **Time-windowed validity** — each epoch key is authoritative for records in its seq window
  `[start, end)` (`KeyResolver.at(seq)`). A grant appended under the key valid at its time still
  verifies (not orphaned); a forged grant minted with a retired key lands at a seq outside that key's
  window and is refused. This is also *why routine rotation is protective*: it bounds the seq window in
  which a since-retired key is honored. It assumes the retired key was not adversary-held while current
  — for that case, see re-genesis.
- **The pinned root** — `KEYS_DIR/owner.genesis.pub` (`identity.genesis_owner_pubkey` /
  `pin_genesis`), written once at the first rotation and thereafter the anchor a verifier walks from.
  Absent a pin (an un-rotated install), current *is* genesis, so every fold is **byte-identical** to the
  pre-W9-1 single-key behaviour.
- **The head** — `trust_root()` anchors on the succession-validated current tip; `sigil key rotate`
  re-signs the head + durable floor under the new key. An `owner.pub` swapped in without a valid
  cross-signed succession record does not become the trusted head signer.

## Re-genesis — what continuity is deliberately abandoned

`sigil key re-genesis` (requires `--yes --i-understand-continuity-is-abandoned`) mints a fresh genesis
key, appends a self-signed re-genesis marker, swaps the at-rest key material, and **repins** the genesis
root to the fresh key. The succession walk then starts from the new root, so **every** pre-re-genesis
owner key falls out of every window and **every pre-re-genesis head, grant and succession record stops
being authenticated** by the new root. That is the point: a compromised key must no longer be able to
forge anything the new system trusts. The stated cost is that verifiable continuity of pre-compromise
history is lost — an out-of-band verifier pinned to the OLD genesis will no longer chain to the new key
and must re-pin to the fresh key the command prints.

## Live-only residual

The new private key is written through the owner vault (`identity.set_owner_key` →
`vigil_core.vault`), which TPM-seals it at rest once a KEK is provisioned. The seal-to-real-hardware
step is exercised only on a host with a TPM; the succession/rotation LOGIC is fully tested with
generated keypairs and a temp home under plaintext-fallback.

## Tests

`apps/sigil/tests/test_key_rotation.py` runs in the required `SIGIL governor gates (P7 …)` CI job (which
executes the whole `apps/sigil/tests/` directory). It covers:

- rotation with pre-existing account + promotion grants, asserting **none is orphaned** and the head
  still verifies;
- the succession walk + seq-windowed validity;
- the "**fails without the fix**" delta, asserted in the same run: a pre-rotation grant verified under
  the naive single (current) key is refused, while the succession resolver accepts it under the key
  valid at its seq; and a retired-key forgery at a later seq is refused end-to-end;
- **negative controls**: an uncrossed successor, a missing successor PoP, a swapped `new_pubkey`, and a
  forked succession (DENY-all) — each asserted rejected;
- re-genesis abandoning continuity; and rotation refusing a tampered (non-tip) on-disk key state.
