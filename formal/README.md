# `formal/` — machine-checked core invariants (F1)

VIGIL's safety rests on four invariants. They are exercised by tests throughout the tree; this
directory **proves them over an exhaustive, bounded model** with TLC (the TLA⁺ model checker), and
proves each guard is **load-bearing** by checking a mutant that must fail.

| invariant | spec | proves |
|---|---|---|
| Conjunctive gate | `gate/VigilGate.tla` | an action auto-runs only if authority ∧ tier=auto ∧ (destructive⇒quorum) ∧ no error |
| Oracle sole-authority | `oracle-mint/OracleMint.tla` | a claim is `FACT` only if a deterministic oracle fired; the firewall is demote-only |
| FATAL-2 two-env boundary | `boundary/Boundary.tla` | offense and sovereign code never co-load; offense never holds the owner key; the seam is inert |
| Anti-rollback floor | `antirollback/MonotoneFloor.tla` | the durable high-water never decreases; a rolled-back head is refused |

Each `X.tla` has a companion `X_broken.tla` — identical except the one load-bearing guard is
removed — which TLC must report as **violating** the invariant. So `check.sh` is red both when an
invariant regresses *and* when a mutant stops being caught (a vacuous check).

```bash
bash formal/check.sh
```

See [`CORRESPONDENCE.md`](CORRESPONDENCE.md) for the model↔code mapping (`file:line`) and the honest
scope: **this is model-level assurance that faithfully abstracts the enforcing code — not a
code-extraction proof.** CI runs it as the `formal-verification` job.
