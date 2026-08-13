# The Case File — ground truth

**Question asked.** *"Every engagement produces findings, evidence, signed certificates, and a report. I
expect those STORED per engagement; a SCREEN where findings live and I can click into evidence; a LIBRARY of
past engagements I can return to months later; and a DOWNLOAD that gives me the whole package — report +
evidence + certificates — as one thing I can hand to an auditor who can verify it themselves without my
system. All driven from the FRONT END."*

**Verdict: PARTLY — and the part that is missing is the part a national agency buys.**

The whole chain works, clicking only, for **one** kind of run: a **loopback `scan` of your own machine**.
For a **remote engagement** — the only mode allowed against a real customer target — the Findings screen, the
Evidence screen, the certificates and the download are all **structurally empty**, because the process that
performs a remote engagement writes **no files at all** into the run directory. And even on the loopback path
the downloaded package contains **no certificates, no evidence and no human report**, while its own
`index.html` asserts that it does.

Repo state: `/home/kali/vigil` @ `02b65ea5`, read-only. Everything below is either a file:line I read or a
command I ran against copies in a scratch directory. Nothing in the repo was modified.

---

## 1. WHAT ALREADY WORKS

These I confirmed by reading the code path end to end and, where marked **[ran it]**, by executing it.

**A findings screen that reads real stored data.** `Findings` is a real nav entry
(`packages/vigil-ui/app.js:25`). It picks a run from `GET /api/runs` (`console/api.py:153`, which enumerates
`<v2_root>/.console/runs/` newest-first) and loads `GET /api/report/<run>` (`console/api.py:346`, reading
`<run_dir>/report.json`). **[ran it]** `api.list_runs()` on this host returns 3 runs, each `findings: 13`,
`has_report: true`. Clicking a row opens a drawer with verdict, CVSS, oracle kind, rationale, how-to-verify
and remediation (`app.js:2331`).

**A per-finding evidence view that re-proves itself live.** The Evidence tab calls `GET /api/evidence/<run>`
(`console/api.py:502`), which **re-executes each retained oracle certificate offline** — no traffic — and
returns per finding: `reproduced`, `matches_claim`, `sound`, and a real content-addressed `cert_id`
(sha256 over the canonical `oracle_context`, `api.py:527-531`). **[ran it]** on run `20260729-100817-523`:
`2 / 2` sound, `boolean_sqli` and `xss`, both `reproduced=True matches_claim=True`. That is genuine: the
screen is not displaying a stored boolean, it is re-firing the proof each time you load it.

**A library of past runs.** `GET /api/runs` is unfiltered, uncapped and never pruned; runs live at
`<v2_root>/.console/runs/<id>/` with 0700/0600 permissions, gitignored. Findings, Report, Compliance,
Assurance and Proof Studio each render it as a run `<select>`, and picking one rewrites the URL hash. A run
from months ago opens fine — **[ran it]** I built a dossier today from a run dated 2026-07-29.

**A one-click download that is genuinely tamper-evident.** Report screen → `⤓ Download dossier`
(`app.js:5424`) → `POST /api/dossier/<run>/build` (`server.py:437` → `actions.build_dossier:1850`, which
shells the exec-only `vigil dossier`) → an `<a download>` on `GET /api/dossier/<run>.zip` (`server.py:268`,
`_download_dossier:292`). **[ran it]** The ZIP is deterministic (sorted entries, fixed epoch), carries a
`MANIFEST.json` of sha256s, an m-of-n Ed25519 `MANIFEST.sig.json` over the exact manifest bytes
(`dossier.py:698-730`), and a `TRUST-ROOT-FINGERPRINT.txt` for out-of-band pinning.

**Offline third-party verification is real — where a proof bundle is present.** The one complete dossier on
this host (`.console/runs/20260729-112009-041/dossier.zip`) contains `proof-bundle/` with 3 signed
certificates, a hash chain, a signed head, a trust root and raw evidence bytes
(`proof-bundle/evidence/poc-*/req`). The crypto layer is honest and well-built: the certificate binds the
`oracle_context`, and verification requires the oracle to actually **re-fire**, not merely a signature to
check out.

**The remote engagement's reasoning IS durably stored — just not as a case file.** `engage` mirrors every
finding onto an append-only SQLite event spine with `oracle_context` retained
(`engage.py:_spine_finding_payload:327-352`; schema `agents/schema.sql:24-53`, UPDATE/DELETE refused by
trigger). `GET /api/blackboard?slug=<slug>` replays the entire stream from event 1 (`server.py:240`). The
honesty grading there is correct: `critique_status="confirmed"` only when the finding re-grounds as a fact.

**The download path is safe.** `_download_dossier` is confined to the fixed filename `<run_dir>/dossier.zip`;
the run id passes `_safe_run_id` (`actions.py:281`, regex + explicit `..` rejection); a bad id raises
`ValueError` → clean 404 (`server.py:283`). I found no file-disclosure hole.

---

## 2. WHAT IS MISSING

### (a) Exists but is not wired to the UI — hours, not days

| Thing that exists | Where | Why the operator cannot reach it |
|---|---|---|
| **Raw HTTP evidence per engagement** — `request.http`, `response.http`, `response.body` | written by `agents/http_executor.py:744-752, 865-869` into `targets/<slug>/evidence/<action_id>/` | **No API route, no UI screen and no dossier reads it.** I grepped `request.http` / `response.body` across `console/`, `packages/vigil-ui/` and `integration/`: zero non-writer hits. This is the richest evidence the system produces and it is invisible. |
| **The three human reports + SARIF** — `executive.md`, `technical.md`, `remediation-roadmap.md` | renderers `report/generate.py:453`, `report/export.py:286,292`; the dossier calls them at `dossier.py:338-388` | They render only from a `findings.json` in the run dir. **Nothing in production writes that file** (grep across `engine/` + `integration/`: only the dossier reader, the `report --from-json` CLI help text, and tests). |
| **Certificates for a normal scan run** | `proof/bundle.py:131` `export_bundle` | It sources findings from `proof/run.py:124` `read_reverifiable`, which reads **only** `<run_dir>/proofs/reverifiable.json`. The console's scan writes the **top-level** `<run_dir>/reverifiable.json` (`actions.py:607`). The two conventions never meet. `proofs/` is written only by the Strix sink, enabled only for `mode == "codebase"` (`actions.py:556-558`). |
| **A whole-session/engagement handoff package** | `vigil dossier --session <id>` (`integration/vigil_integration/cli.py:1143`) | No HTTP route, no button. The Sessions screen's run chips link only to `#/live?run=…` (`app.js:4629`) — never to Findings, Report or a download. |
| **The Certificate of Non-Exploitability (posture bundle)** with its own bundled `verify_offline.py` | `integration/vigil_integration/posture/bundle.py:74` | **No `vigil posture` verb exists** (grep of `cli.py`: no hits) and no POST route. The UI's "Download certificate (JSON)" (`app.js:672`) dumps the read-view *summary* from `/api/posture` — claims and pubkeys, **not the signed bytes**. Unverifiable by a third party. The screen literally instructs the operator to run a `python -m` module (`app.js:709`). **[ran it]** `/api/posture` → `{"posture": []}`. |
| **The external-audit package** — the best artefact in the repo (evidence + contexts + trust root + a standalone `verify_offline.py` + SCOPE/CHARTER/RUNBOOK) | `evidence/audit_package.py:284` | **No CLI verb, no route.** Every caller is a test or the `__init__` re-export. Unreachable by any operator. |
| **The proof bundle from Proof Studio** | `POST /api/proof/export` → `actions.proof_export:1198` | Writes a **directory on the server** (`out = rd / "proof-bundle"`) and toasts the path. Not a browser download. |
| **The gated action API plane** `/api/v1/*` on :8799 | `framework/v2/api/server.py:41-58` | **[ran it]** `grep -c "api/v1" packages/vigil-ui/app.js` → **0**. Nothing in the UI calls it. It is also the only surface `CRUCIBLE_API_KEY` protects (`uiproxy.py:786-795`). |
| **AuditFinding → FindingPayload coercion** (the fix for the Compliance bug below) | `dossier.py:139-166` `_auditfinding_to_payload` | `report/standards.py` does not use it. |

### (b) Does not exist at all — days, not hours

**1. A remote engagement produces no case file. This is the decisive finding.**
`launch_assessment` routes any non-loopback target to `framework.v2 engage <slug> <target> --spine` with
`capture_report=False` and **no `--reverifiable-out`** (`actions.py:623-638`). That flag exists **only on
`scan`** (`scanner/cli.py:136`; grep confirms `engage.py` has no `reverifiable` anything). And **`engage.py`
contains zero file writes** — I grepped `write_text|write_bytes|open(...,'w')`: no hits. It renders to stdout.
`_spawn_background` only saves `report.json` when `capture_report` is true (`actions.py:426-429`), so a remote
run's directory holds `meta.json`, an empty `progress.jsonl`, and `stdout.txt`.

Consequence, confirmed by execution. **[ran it]** I built a dossier from a run dir with exactly that shape:

```
entries:      5  (facts=0)
verify facts: (no offline proof bundle — this run produced no oracle-confirmed FACT)
  note: no report/proof/log/spine/drift artifact was found under the run dir
```

Five files: `MANIFEST.json`, `MANIFEST.sig.json`, `README.md`, `TRUST-ROOT-FINGERPRINT.txt`, `index.html`.
That is the entire deliverable for the engagement type an agency would actually run. The Findings screen for
such a run correctly says *"This run reports on the reasoning spine… Open in Live"* (`app.js:2218-2228`) —
honest, but there is nothing to click into and nothing to hand over.

**2. The downloaded package contradicts itself, in the signed bytes.**
**[ran it]** I built a dossier from a copy of a real UI-created loopback scan run (13 findings in
`report.json`, 2 oracle-confirmed in `reverifiable.json`):

```
entries: 6  (facts=2)
NAMES: MANIFEST.json MANIFEST.sig.json README.md TRUST-ROOT-FINGERPRINT.txt index.html reports/report.json
```

`index.html` banner: *"**2 oracle-confirmed FACT(s) — each re-verifiable OFFLINE from the embedded proof
bundle.** Plus leads (see reports) (leads not enumerated — no structured report.json in this run)."*

`README.md`, same ZIP: *"**No proof bundle is included**: no proven findings to export… A run with only leads
has nothing to re-prove — this is the honest outcome, not an omission."*

Three separate defects in that one output:
- The banner is gated **only on `n_facts > 0`** (`dossier.py:526-530`), never on `proof.get("ok")`. It asserts
  an embedded bundle that is not there.
- The two halves read different sources: `dossier._read_reverifiable` tries **both** path conventions
  (`dossier.py:189-214`) so it sees 2 facts; `export_bundle`'s `read_reverifiable` tries **only** `proofs/`
  (`proof/run.py:124`) so it exports nothing.
- *"leads not enumerated — no structured report.json in this run"* while `reports/report.json` is in the ZIP.
  The lead counter expects `summary.leads` (`dossier.py:511-516`); the real summary carries
  `confirmed`/`passive` (**[ran it]** — verified against the on-disk report).

A regulator opening a **signed** archive and finding it contradict itself is worse than an archive that
claims less.

**3. There is no engagement library — only a run library.**
`GET /api/engagements` (`api.py:118`) lists **directories under `targets/`**, not the spine. **[ran it]** on
the bootstrap-canonical root (`bootstrap.sh:35` sets `CRUCIBLE_ROOT="$REPO/engine/crucible"`) it returns
`{"engagements": []}` — while that same root's spine holds a real `testasp` engagement. The `Blackboard`
class has **no `list_engagements` method at all** (`agents/blackboard.py:186-430`). And `bb_engagements.slug`
is `UNIQUE` (`schema.sql:26`), so every run against one target accumulates into a **single** engagement id
with no per-run partition — two engagements a month apart on the same host are one interleaved event stream.
Nothing joins a run id to a slug's spine events.

**4. Signed certificates are never stored.** They are re-minted at download time. `mint_proof` builds and
signs in memory (`proof/engine.py:209-227`), but the only thing persisted is `_persist_record`
(`proof/run.py:95-117`) — a ~12-field summary with **no signature and no certificate body**; `res.signed` is
dropped. The per-run certificates the Trust Center reads (`coverage-certificate.json`,
`plan-integrity.json`, `api.py:1249-1252`) have **no production writer**.

**5. The download's signature does not anchor an operator identity.** `actions.build_dossier` shells
`vigil dossier` with **no `--base-dir`** (`actions.py:1870`), so `_sign_manifest` falls back to
`base_dir or str(run_dir)` (`dossier.py:717`) and `provision_authority` mints a **fresh Ed25519 key inside
the run directory**. **[ran it]** — two builds from two different run dirs produced two different trust roots
(`sha256:b1dc689c…` and `sha256:8ef7b72f…`), and I watched `offense-governance.key` appear inside the run dir.
The README instructs the auditor to *"pin it OUT-OF-BAND to anchor authenticity"* — there is no stable pin to
hold across engagements, so the signature proves **integrity only**, not origin.

**6. The regulator-facing standards mapping can never assert coverage.** `standards._record`
(`standards.py:444-478`) calls `grade_finding` on the raw dict; a `reverifiable.json` finding is
AuditFinding-shaped and fails `FindingPayload` validation, so it drops to the *"could not validate → treat as
LEAD"* branch. **[ran it]** on the run whose evidence is **2/2 sound**:

```
{"finding_ref": "?", "bug_class": "boolean_sqli", "graded": "lead", "is_fact": false,
 "status": "advisory", "coverage_asserted": false, "controls": null}
{"finding_ref": "?", "bug_class": "xss",          "graded": "lead", "is_fact": false, ...}
```

It errs toward under-claiming, which is the safe direction — but the OWASP/PCI/SOC2/ISO mapping the owner
would show a regulator is structurally unreachable. `dossier.py` already carries the exact coercion that
fixes it.

**7. Two independent storage roots that drift.** Sessions live at
`Path(os.environ.get("VIGIL_LIVE_DIR") or ".vigil-live")` — **a relative path, resolved against the console's
CWD** (`console/sessions.py:57-59`) — while runs live under `CRUCIBLE_ROOT`. `link_run` validates a run id's
*shape* but never its *existence* (`sessions.py:249-262`). The result is a session listing runs that are not
there. Separately, `crucible_root()` (`common/paths.py:40-68`) falls back to a `CLAUDE.md` sentinel walk-up
when `$CRUCIBLE_ROOT` is unset — changing an env var silently relocates the entire case-file archive.

**8. The home tiles and top-bar counters are dead.** `api.status_data` returns **only** `{paths, backends}`
(`api.py:35-58`); the UI reads `active_runs`, `findings_confirmed`, `agents`, `tools` (`app.js:171-176`) —
none exist. **[ran it]**: `STATUS keys: ['paths', 'backends']`. Every screen's header permanently reads
0 agents · 0 tools · 0 findings.

**9. The console has no credential of any kind.** `console/cli.py` exposes only `--port`, `--host`, `--open`,
`--allow-host`, `--allow-origin`. There is no token, key or session anywhere in `console/server.py`. The only
guards are a loopback bind and a Host/Origin anti-rebinding check. `vigil up --domain …` starts it with an
allow-host and the proxy forwards verbatim without authenticating (`uiproxy.py:263-330`). In any deployment
where the origin is reachable — the whole point of hosting it — **anyone who can reach it can download every
engagement's evidence package.** Contrast the sovereign cockpit, which HMAC-checks a bearer token on every
`/api/` request (`apps/sigil/sigil/ui/server.py:107-110`).

### Corrections to earlier review notes

- **`started` is not universally lost.** `launch_scan`'s completion handler rewrites `meta.json` without it
  (`actions.py:337-345`), so legacy scan runs show `started: null` — **[ran it]**, all 3 runs on this host do.
  But `_spawn_background` writes `{**meta, …}` (`actions.py:430`) and `meta` carries `started` from `base`
  (`actions.py:522`), so **wizard-launched runs keep it**. Only `launch_scan` drops it.
- **`api.reports_data` is not "orphaned by accident".** Its removal from the route table is deliberate and
  documented (`server.py:86-91`).
- I did **not** verify claims about a second CRUCIBLE tree at `/home/kali/Music/PENTEST/crucible`. The
  root-resolution fragility above is a code fact (`paths.py:40-68`); the contents of any other tree are not.

---

## 3. THE MINIMUM BUILD

Four things, in this order. Every one reuses machinery the repo already has.

### Step 1 — Make a remote engagement produce a case file *(the only true blocker)*

Nothing downstream can work until `engage` leaves artefacts on disk. Two options; **do the first**.

**1a. Give `engage` a `--reverifiable-out` and a `--report-out`, and have the console pass them.**
- `engine/crucible/framework/v2/engage.py` — add the two arguments to its parser and, at the point where the
  scan report object exists (the same object `_spine_finding_payload` at `:327` reads its findings from),
  write `model_dump_json` to `--reverifiable-out`. Mirror `scanner/cli.py:188-198` exactly — that is 12 lines
  and it produces the byte-shape `verify` already re-fires.
- `console/actions.py:623-638` — append `--reverifiable-out <rd>/reverifiable.json`,
  `--report-out <rd>/report.json` to the engage argv. **Do not** flip `capture_report=True`: engage's stdout
  is a human render, not JSON.

**1b. Fallback if 1a is refused (engage's report object is not reachable there):** add a console-side
harvester that, on run completion, reads the spine for that slug **bounded to the run's `started`..`finished`
window** and materialises `report.json` + `reverifiable.json` into the run dir. Reuse
`Blackboard.read(kind="finding")` (`blackboard.py:328`). This is strictly worse — it depends on wallclock
windowing because the spine carries no run id — but it unblocks without touching the engine.

Either way, **also record the run id on the spine**: add `run_id` to the payload in
`engage._spine_finding_payload` (`engage.py:327`). Without it, per-engagement retrieval is forever a
timestamp guess.

### Step 2 — Make the download contain what it claims

Three small, independent fixes; each is worth doing even alone.

- **`integration/vigil_integration/proof/run.py:124`** — make `read_reverifiable` try
  `proofs/reverifiable.json` **then** `reverifiable.json`, exactly the loop
  `report/dossier.py:189` already uses. **This one function is why every scan dossier ships zero
  certificates.** One change restores certificates + raw evidence bytes to every loopback dossier.
- **`report/dossier.py:526-530`** — gate the "re-verifiable OFFLINE from the embedded proof bundle" clause on
  `proof.get("ok")`. When there are facts but no bundle, say so and give the reason. Same for the
  `reports/technical.md` / `reports/remediation-roadmap.md` pointers at `dossier.py:578-580` — gate them on
  membership in `included`. And fix the lead count to fall back to
  `summary.passive` when `summary.leads` is absent (`dossier.py:511-516`).
- **Write a `findings.json` into the run dir at completion** so `_gather_reports` (`dossier.py:338`) renders
  the three human reports + SARIF with the **existing** renderers (`report/generate.py:453`,
  `report/export.py:286,292`). Build it by mapping `reverifiable.json`'s `active_findings` through the
  coercion that already exists — `dossier._auditfinding_to_payload` (`dossier.py:139-166`) — and folding in
  the passive/lead rows from `report.json`. Do **not** write a new renderer.

### Step 3 — A per-finding evidence view with the actual bytes, and an engagement library

- **New route `GET /api/evidence/<run>/<finding_ref>/artifacts`** in `console/server.py` (`_PREFIX_ROUTES`
  cannot express two segments — add it as an explicit branch near `_download_dossier`). It returns the
  captured `request.http` / `response.http` / `response.body` for that finding's `action_id`, from
  `paths.evidence_dir(slug, action_id)` (`common/paths.py:358`). **Serve it as a downloadable attachment,
  never inline** (see risks). Wire it into the existing evidence card (`app.js:2625` `p3EvidenceCard`) as a
  "Download raw exchange" link — the card and its Sound / Tampered state already exist.
- **Make `/api/engagements` read the spine, not the filesystem.** Add `Blackboard.list_engagements()` to
  `agents/blackboard.py` (the query already exists, hard-coded, at
  `integration/vigil_integration/telemetry.py:95-101` — lift it) and rewrite `api.list_engagements`
  (`api.py:118`) to return, per slug: started/closed, finding + fact counts, and the run ids that carry that
  slug in `meta.json`. Add an `Engagements` nav entry (`app.js:19-52`) whose rows link to
  `#/findings?run=…` — reuse `drawSessions`' card layout (`app.js:4636`), and fix the session chips at
  `app.js:4629` to point at `#/findings?run=…` instead of `#/live?run=…`.
- **Fix the root split**: `console/sessions.py:57-59` must resolve `.vigil-live` against a stable base
  (`paths.crucible_root()`), not the CWD, and `link_run` (`sessions.py:249`) should record existence at link
  time so the library never lists phantom runs.

### Step 4 — One stable operator identity, and a package that verifies itself

- **`console/actions.py:1870`** — pass `--base-dir <stable operator base>` to `vigil dossier` (the same base
  `vigil engage --base-dir` uses, per `dossier.py:717`'s contract). One trust root then signs every case file
  and the out-of-band pin becomes publishable **once**. This is the difference between "integrity only" and
  "provably from this operator".
- **Ship the verifier inside the box.** `docs/proof-carrying-finding/verify_pcf.py` already exists and
  already self-proves it is VIGIL-free. Copy it into `proof-bundle/` in `proof/bundle.py:131` alongside the
  existing `README.md` + `HOW-TO-VERIFY.md`, and reference it from `index.html`. Today the auditor is told to
  install VIGIL's own engine — defensible, but not "verify without my system".
- **`report/standards.py:444`** — route the finding through `dossier._auditfinding_to_payload` before
  `grade_finding`, so the Compliance screen and the Report screen's Standards row stop grading proven facts
  as advisory leads. (Move that helper somewhere both modules import; do not copy it.)
- **Two buttons, no new backend**: a Sessions-screen "Download engagement package" calling a new
  `POST /api/dossier/session/<id>/build` that shells the **existing** `vigil dossier --session`
  (`integration/vigil_integration/cli.py:1143`); and a Posture-screen "Mint signed certificate" calling the
  **existing** `posture/bundle.py:74`, returning the signed bytes rather than the read-view summary.

**Order matters.** Step 1 before Step 2 (a fixed packager over an empty run dir still packages nothing).
Step 2 before any demo — the self-contradicting `index.html` is the single most damaging artefact here,
because it is *signed*. Steps 3 and 4 are independent of each other.

---

## 4. SECURITY — what is dangerous to get wrong

1. **Put a credential on the console before Step 3 ships.** Today `GET /api/dossier/<run>.zip` and
   `GET /api/evidence/<run>` need **no credential** — only a Host header match. Adding a raw-bytes evidence
   route to an unauthenticated server turns a missing feature into a data-exfiltration surface: captured
   request/response bodies contain session cookies, tokens and whatever the target returned. The pattern to
   copy already exists in-repo: the sovereign cockpit's per-request bearer HMAC
   (`apps/sigil/sigil/ui/server.py:107-110, 154`). Note also that `ui.js:64-67, 89` already sends the
   sovereign token to offense routes and puts it in the **query string** for SSE — do not build new auth on
   query-string tokens.
2. **The new evidence route is a path-traversal target.** `action_id` comes from a **file on disk**, i.e. it
   is untrusted input. Confine it to a single path segment before touching the filesystem — `export_bundle`
   already does exactly this and the comment explains why (`proof/bundle.py:161-165`): reject absolute paths,
   reject `..`, require `Path(aid) == Path(aid.name)`. Reuse `actions._safe_run_id` (`actions.py:281`) for the
   run id. Never `os.path.join` a caller-supplied slug.
3. **Serve evidence as `Content-Disposition: attachment` with `Content-Type: application/octet-stream` and a
   restrictive CSP.** `response.body` is attacker-controlled HTML/JS captured from the target. Rendering it
   inline on the console origin is stored XSS against the operator's own console — which has no auth and can
   launch engagements.
4. **Never let a slug or run id from one engagement reach another's data.** With Step 3, `/api/engagements`
   starts keying by slug. Resolve the slug from the run's `meta.json` server-side; do not accept a
   caller-supplied slug for an evidence read.
5. **Redact before packaging, as the dossier already does.** `_scrub_log` (`dossier.py:216`) runs the same
   secret masker the live logger uses and drops unparseable lines rather than shipping them. Raw evidence
   bytes are deliberately **not** scrubbed (`common/redact.py:18-20` explains: byte fidelity matters for
   re-verification, so the protection is owner-only file permissions). If those bytes now leave the host over
   HTTP, that trade changes — decide it explicitly, and keep the 0600/0700 posture
   (`paths.secure_dir`, `http_executor.py:674`).
6. **`build_dossier` writes as a side effect of a "download" click** — `provision_authority` persists a signed
   authority and a private key into the run dir. Once a stable `--base-dir` is used (Step 4), that key is a
   long-lived operator signing key: it must live outside the run store, 0600, and ideally under the existing
   `Vault` seal (`cli.py:62` shows the pattern).
7. **`_download_dossier` reads the whole ZIP into memory** (`server.py:301`). Fine at 12 KB; with evidence
   bundles included, stream it.

---

## Bottom line

**No — not today, not for the engagement that matters.** For a **loopback scan of your own machine**, an
operator can click through Findings → Evidence → Report → Download and hand an auditor a signed,
hash-manifested, tamper-evident ZIP — but that ZIP contains a raw `report.json` and an HTML summary, **no
certificates, no evidence bytes and none of the three human reports**, and its `index.html` tells the auditor
it contains a proof bundle that is not in the file. For a **remote engagement** — the only mode that can run
against a real customer — the run directory is empty, the Findings and Evidence screens honestly say there is
nothing there, and the download produces a five-file ZIP with no findings at all; the proofs exist, in the
spine, with response bodies and oracle predicates intact, but no code path packages them. The cryptographic
foundation is genuinely strong and the honesty discipline in the grading code is real; what is missing is the
plumbing between the engine that proves things and the archive that hands them on. Step 1 plus Step 2 above —
roughly a day of work, most of it in three functions — converts this from "a proof nobody can retrieve" into
the deliverable the owner described.
