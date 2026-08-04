# F1 — model ↔ code correspondence (and the honest scope)

`formal/` machine-checks the **four core invariants** of VIGIL with TLC (the TLA⁺ model
checker). For each invariant there is a **faithful** spec (TLC proves the invariant holds over a
bounded, exhaustive state space) and a **mutant** with the one load-bearing guard removed (TLC
must produce a counterexample). `check.sh` fails closed if any faithful spec regresses **or** any
mutant stops being caught.

## What this IS — and what it is NOT

**IS:** the four invariants hold in a **machine-checked model that faithfully abstracts the
enforcing code**, and each guard is demonstrably **load-bearing** (its mutant is caught). This is
real, exhaustive, reproducible assurance about the *design* — stronger than tests, which only
sample.

**IS NOT:** a code-extraction proof. TLC checks the **model**, not the Python/Rust bytes. The
model↔code link below is a **human-argued abstraction**. We do **not** claim "the code is formally
verified." We claim: *the soundness invariant holds in a machine-checked model that faithfully
abstracts the enforcing code at the cited `file:line`.* Keeping that distinction is itself part of
the TRUTHENOVATION discipline — a system built to refuse the AI's word must not overclaim its own
proofs.

The model is deliberately **small and finite** (2–3 element constant sets, bounded counters) so TLC
terminates in seconds and the state space is exhausted, not sampled.

## The four invariants

### 1. Conjunctive gate — `gate/VigilGate.tla` (invariant `GateSound`)
A target-touching action auto-runs (**allow**) only if, first-failure-wins and fail-closed:
CRUCIBLE authority is in-envelope (kill-switch clear ∧ in-window ∧ in-scope ∧ under-budget) ∧ the
WARDEN tier is exactly `auto` ∧ (destructive ⇒ an owner-inclusive m-of-n threshold quorum is
present and `authorized is True`) ∧ no conjunct raised.
- **Code:** `packages/core/vigil_core/vigil_core/gate.py` `conjunctive_decide` (the gate-of-record
  since S6); `engine/crucible/framework/v2/authority/gate.py` `authorize_action`;
  `integration/vigil_integration/warden_gate.py` `decide_tool`;
  `integration/vigil_integration/conjunctive_gate.py` (now re-exports the core decision).
- **Mutant:** deletes the `destructive ∧ ¬quorum → deny` clause → a destructive action auto-runs
  with no owner quorum → `GateSound` violated.

### 2. Oracle-as-sole-authority — `oracle-mint/OracleMint.tla` (invariant `OracleOnlyMints`)
A claim's status becomes `FACT` **only** because a deterministic oracle fired over real target
bytes. LLM proposals, critic endorsements, and RL re-ranking may set/keep a `LEAD` (and the
re-execution firewall may **demote**), but none may mint a `FACT`.
- **Code:** `integration/vigil_integration/oracle_adapter.py` `confirm_and_certify` (the sole mint
  path), reached only after `framework/v2/verify/confirmation.py` `confirm_finding` returns
  non-None, which requires `framework/v2/verify/verifier.py` — a signal with `fired` at ≥
  high-confidence. `veracity/firewall.py` is demote-only.
- **Mutant:** lets a non-oracle actor set `status = FACT` without an oracle fire → `OracleOnlyMints`
  violated.

### 3. FATAL-2 two-env boundary — `boundary/Boundary.tla` (invariants `BoundaryHolds`, `InertSeam`)
No process ever co-loads offense (`framework`/`strix`) and sovereign (`sigil`/`vigil_core`) code,
and an offense process never holds the owner signing key; a confirmed finding crosses the seam as
inert signed DATA (no capability).
- **Code:** `apps/sigil/.../reuse` `assert_no_offense` (the co-load refusal);
  `integration/vigil_integration/offense_worker.py` (keyless-by-construction);
  `integration/vigil_integration/inert_finding.py` (`json.loads`-only, size-bounded, m-of-n
  re-verified); the dependency-graph boundary asserted by `integration/tests/test_two_env_boundary.py`.
- **Mutant:** removes the co-load refusal (and/or lets the owner key into an offense process) →
  `BoundaryHolds` violated.

### 4. Anti-rollback floor — `antirollback/MonotoneFloor.tla` (invariant `MonotoneFloor`)
The durable accepted high-water never decreases: a signed head is accepted only if its
`entry_count ≥ floor.entry_count` (primary) **and** `last_seq ≥ floor.last_seq` (secondary); a
below-floor head is refused and nothing is written. The model captures the 0-indexed `last_seq`
degeneracy (both an empty and a 1-record chain read `last_seq = 0`), which is exactly why
`entry_count` — not `last_seq` — is the sound guard.
- **Code:** `packages/core/vigil_core/vigil_core/highwater.py` `check_highwater` / `_advance_locked`;
  `packages/core/vigil_core/vigil_core/chain.py` `verify_head` / `sign_head`.
- **Mutant:** removes the `entry_count ≥ floor` guard → a rolled-back/truncated head is accepted and
  the high-water drops → `MonotoneFloor` violated.

## Reproduce

```bash
bash formal/check.sh                 # downloads a pinned, sha256-verified tla2tools.jar
TLA2TOOLS_JAR=/path/to/tla2tools.jar bash formal/check.sh   # offline / air-gapped
```

Exit 0 iff all four faithful specs model-check clean **and** all four mutants are caught. The CI
job `formal-verification` runs exactly this.
