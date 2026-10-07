# VIGIL assurance mapping (Lane C / C4)

`assurance-mapping.json` maps VIGIL's machine-checked evidence onto a structure a reviewer from an
accredited body (Common Criteria, FedRAMP) recognises:

```
security objective  ->  claim(s)  ->  evidence / verifier  ->  residual limitation(s)
```

It is **generated**, never hand-maintained: `gen_assurance_mapping.py` reads the authoritative sources and
writes the JSON, so the mapping can never drift from the evidence it cites.

## Sources (all machine-checked already)

- `docs/claims/registry.json` — every product claim, its enforcing symbol, and its proving test in a
  required CI job (checked by `docs/tests/test_claims_registry.py`).
- `docs/limitations/inventory.json` — the code-grounded, honestly-worded limitation inventory (checked by
  `docs/tests/test_limitation_inventory.py`).
- `docs/capability-matrix/evidence-branches.json` — the per-branch FACT-capability contract, with the
  `oracle_version` (OracleKind) that adjudicates each FACT.

## What the mapping contains

- **`security_objectives`** — nine Common-Criteria / FedRAMP-shaped control families (access control,
  non-repudiation, finding soundness, isolation, supply chain, configuration, cryptography, resilience,
  assurance governance). Each lists the claims that realise it and the residual limitations that bound it.
- **`claims`** — every registry claim, routed to exactly one objective, carrying its enforcing symbol and
  its proving-test verifier (file + tests + CI job). Routing is a transparent, priority-ordered keyword
  rule a reviewer can re-run.
- **`fact_class_assurance`** — every FACT-capable oracle class mapped to the verifier that re-checks it:
  - the universal **framework reproduction** verifier (`python3 -m framework.v2 evidence verify`), which
    re-executes the `oracle_version`-bound procedure over the retained `oracle_context`;
  - and, for the subset whose oracle body is a pure stdlib port, the stronger **zero-dependency standalone**
    verifier (`docs/proof-carrying-finding/verify_vf.py`). The standalone set is *derived* from ground truth
    (the C1 ports + the posture-tier ports + the ACHIEVED_STATE predicate kernel), never asserted.
  - Where an oracle cannot be re-executed with zero dependencies, its **reproduction boundary** is named:
    *irreducible-by-dependency* (needs `packaging` / an external OOB collector), *mixed* (the live TLS
    handshake path), or *pure-but-deferred* (portable, but today re-fired only inside the framework over a
    live-capture / browser / subprocess / cloud-API context — the boundary is live I/O, not a missing
    verifier).
- **`adversarial_review`** — the RED-PEN + adversarial-sweep cadence recorded as an **auditable control**
  (`AR-REDPEN`) with a **sign-off slot**: a reviewer fills one entry per audited release; the slots are
  intentionally empty until signed, so an unsigned review is recorded as *pending*, never fabricated. This
  turns the near-zero-false-positive discipline from tribal knowledge into a documented control.
- **`irreducible_boundaries`** — named honestly, each linked to the limitation that records it.

## Honest boundary

This is an **audit-ready input** to an assessment, **not** an accreditation:

- `IRR-external-body` — an external, accredited assessment body is required for an actual Common-Criteria /
  FedRAMP accreditation (`LIMIT-external-audit-team`).
- `IRR-hardware-root` — origin is anchored to out-of-band-pinned Ed25519 roots, not a hardware root of trust
  (`LIMIT-attest-tee-hardware`).
- `IRR-liveness-bound` — re-execution proves a verdict is the correct function of the retained evidence, not
  that the evidence was live (`LIMIT-audit-package-reproduction`).

## Regenerate / verify

```
python3 docs/assurance/gen_assurance_mapping.py     # rewrite assurance-mapping.json from the sources
```

`docs/tests/test_assurance_mapping.py` is the completeness + drift guard (stdlib-only, runs in the briefing
job): the committed JSON must equal a fresh generation, every registry claim must be mapped to a real
objective, every FACT-capable class must map to a verifier, the standalone set must equal the independent
ground-truth derivation, and every residual-limitation reference must resolve in the inventory.
