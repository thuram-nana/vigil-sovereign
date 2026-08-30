<!-- CLAIM:W16-STD-7-docs-index -->
# VIGIL documentation index

The map of the whole `docs/` tree. This page is kept complete by
[`docs/tests/test_w16_std7_docs_completeness.py`](tests/test_w16_std7_docs_completeness.py), a **required**
CI check (`the briefing explains every agent and capability`): every top-level `docs/*.md` must be linked
here, and every top-level `*.md` this page links to must exist — so a new document cannot be added without
appearing on the map, and the map cannot point at a document that was removed.

New here? Start with the [plain-English briefing](plain-english/00-index.md) (what the system is, in words),
then the [CLI & subsystem reference](CLI-REFERENCE.md) (what you can run), then this index for the rest.

## Start here

| Document | What it is |
|---|---|
| [MANIFESTO.md](MANIFESTO.md) | *The Provable Adversary* — the why, in plain language. |
| [VISION.md](VISION.md) | Where the system is going. |
| [GLOSSARY.md](GLOSSARY.md) | Plain-language dictionary of every term used across these docs. |
| [plain-English briefing](plain-english/00-index.md) | The ~250k-word narrative an agency reads to understand the whole system. |

## Run it / operate it

| Document | What it is |
|---|---|
| [CLI-REFERENCE.md](CLI-REFERENCE.md) | Every `vigil` verb, passthrough verb, and CRUCIBLE subcommand + subsystem, code-grounded. |
| [MERIDIAN.md](MERIDIAN.md) | The bundled deliberately-vulnerable test app (`target up`) — what it is, all the commands, the 17 weaknesses it tests, and the OWASP/NIST/ISO/CIS/ATT&CK mapping. |
| [HTTP-API.md](HTTP-API.md) | The loopback gated HTTP API (`crucible api`) and the product's other web surfaces. |
| [DEPLOY.md](DEPLOY.md) | Deployment guide. |
| [OBSERVABILITY.md](OBSERVABILITY.md) | Metrics, telemetry, and the assurance collector. |
| [DEFERRED-INFRA.md](DEFERRED-INFRA.md) | The deferred infrastructure pieces and their activation runbooks. |
| [H3-FIELD-RECORD-RUNBOOK.md](H3-FIELD-RECORD-RUNBOOK.md) | The H3 field-record runbook. |
| [OIDC-RP.md](OIDC-RP.md) | The OIDC relying-party integration (off by default). |
| [BRAIN-SLOT-INTEGRATION.md](BRAIN-SLOT-INTEGRATION.md) | The hexstrike "brain slot" integration. |

## What is built, and how honestly it is claimed

| Document | What it is |
|---|---|
| [AS-BUILT.md](AS-BUILT.md) | The as-built architecture — what exists, wired, at this HEAD. |
| [AS-BUILT-LIVE.md](AS-BUILT-LIVE.md) | The live-validated as-built record (real gate + oracle runs). |
| [FEATURES.md](FEATURES.md) | The full feature catalogue with honest wiring status per feature. |
| [POSTURE.md](POSTURE.md) | The security posture of the system. |
| [ENFORCEMENT-COVERAGE-MATRIX.md](ENFORCEMENT-COVERAGE-MATRIX.md) | Which claims are enforced by which required check. |
| [CLAIM-DISCIPLINE.md](CLAIM-DISCIPLINE.md) | The rule: an audited overclaim is built up, never softened. |
| [claim-audit.md](claim-audit.md) | The claim-vs-enforcement audit — every enforcement-flavoured claim graded TRUE / SCOPED / FALSE / UNVERIFIABLE against the code. |
| [DELIBERATE-REFUSALS.md](DELIBERATE-REFUSALS.md) | The seven deliberate refusals, stated as strengths, each paired with the code that enforces it. |
| [TRUTHENOVATION.md](TRUTHENOVATION.md) | The programme that turns every overclaim into a verified fact. |
| [CLAIM-6-RBAC.md](CLAIM-6-RBAC.md) | The Claim-6 multi-user RBAC design. |
| [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) | The supply-chain integrity controls. |
| [supply-chain-scheduled-scan.md](supply-chain-scheduled-scan.md) | The daily supply-chain scan (scheduled counterpart to the required gate). |
| [PLAN.md](PLAN.md) | The build plan / roadmap. |
| [CONTINUATION.md](CONTINUATION.md) | Session continuation notes. |

## Deeper reference (subdirectories)

- [`architecture/`](architecture/) — architecture decision records and diagrams.
- [`assessments/`](assessments/) — assessments and audits.
- [`audit/`](audit/) — audit dossiers (e.g. the Claim-6 RBAC dossier).
- [`capability-matrix/`](capability-matrix/) — the capability matrix.
- [`claims/`](claims/) — the machine-checked claims registry (`registry.json`) and its README.
- [`data-ground-truth/`](data-ground-truth/) — the ground-truth data corpus.
- [`decisions/`](decisions/) — decision records (including the W16-STD-7 doc-drift record).
- [`features/`](features/) — per-feature notes.
- [`knowledge/`](knowledge/) — the knowledge-base docs.
- [`limitations/`](limitations/) — the limitations inventory (the source of the §16/§17 drift work).
- [`pilot/`](pilot/) — operator-facing pilot runbooks (buyer-facing).
- [`plain-english/`](plain-english/) — the plain-English briefing chapters.
- [`proof-carrying-finding/`](proof-carrying-finding/) — the proof-carrying-finding standard.
- [`research/`](research/) — research notes.
- [`runbooks/`](runbooks/) — operational runbooks.
- [`screenshots/`](screenshots/) — the UI screenshot walkthrough.
- [`strix-patches/`](strix-patches/) — the vendored-Strix patch set.
- [`tests/`](tests/) — the docs-truth tests (this index's guard lives here).

## Licensing (read before you deploy)

VIGIL is dual-licensed and **government / public-sector use is EXCLUDED from the free grant** — see
[LICENSING.md](../LICENSING.md), [`LICENSE`](../LICENSE), and [LICENSE-COMMERCIAL.md](../LICENSE-COMMERCIAL.md).
