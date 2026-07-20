---
name: sigil-phase5-perception-bastion
description: "SIGIL Phase 5 — Perception (grounded screen/camera) + BASTION (own-infra defensive posture)"
metadata:
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
---

**SIGIL Phase 5 (Perception + BASTION) — BUILT + RED-PEN REVIEWED + MERGED-READY** at **`/home/kali/sigil/sigil/perception/`** + **`/home/kali/sigil/sigil/agents/bastion.py`** (extends the [[sigil-phase3-agent-mesh]] framework + reuses the [[sigil-phase4-artificer-scholar]] serve-the-quote discipline). SIGIL §4.3/§4.8/§8. Acceptance MET end-to-end: "screen/vision queries work; cert/CVE findings surface in briefs."

**PERCEPTION (`perception/{capture,vision,perceive}.py`, ceiling A0/A1):** on-demand screen/camera capture → a GROUNDED answer. `Frame{kind,sha256,text,image_path}`; real backends (`grab_screen` scrot/gnome-screenshot/spectacle/import + tesseract OCR; `grab_camera` ffmpeg v4l2) return None on failure (honest, like read_source); `StaticFrame` is the test double. **THE DISCIPLINE = serve-the-quote (same as SCHOLAR):** the captured TEXT (OCR/a11y) is AUTHORITATIVE; the VLM reading is ADVISORY-only, never presented as screen content. `VisionModel` seam pluggable; `ClaudeVision` documented-but-inert offline (returns '' — an unconfigured VLM must not fabricate). Ambient C6 = opt-in, indicator-lit, escalates only on a byte-identity frame CHANGE (baseline no-escalate), nothing persists beyond event records. CLI `sigil agents perceive [--screen|--camera|--image]`.

**BASTION (`bastion.py`, ceiling A1):** defensive posture over an allowlisted own-infra INVENTORY only. Scanners (observational, no exploit): TLS cert-expiry (real PEM `notAfter` parse), dependency-CVE (manifest pins vs a LOCAL advisory feed, offline), uptime (HEAD). **OWN-INFRA-ONLY IS STRUCTURAL:** any ref not in `_allow` → `refusal` record, never scanned (`probe_target` guard + `_assess` defense-in-depth). Every finding GROUNDED in its verbatim observed fact (real notAfter / verbatim manifest line / probe status). A CVE fires ONLY on a PROVABLY-affected version; unparseable = non-assessment, never a fabricated vuln. CLI `sigil agents bastion` (+ `_load_bastion` reads `~/.sigil/bastion-assets.json` + `bastion-cve-feed.json`, auto-run in `morning()` → findings surface in the STEWARD brief). New KIND reused: `finding`/`refusal`/`event`.

**RED-PEN REVIEW (4-lens Workflow, 16 agents, attack→verify-with-real-repro): 12 objections → 10 CONFIRMED (all fixed), 2 refuted.** The review caught 3 HIGH honesty bugs self-review missed:
- **RP-1/RP-5 (HIGH) stale finding shown as current:** findings are append-only + a fixed asset is SILENT → the brief kept showing a resolved warning. FIX: `Bastion.run()` emits a `resolved` supersession (via new `Proposal.supersedes_id`, threaded through `_dispatch`) for any prior (asset,check,cve) now clean; `compose_brief` drops resolved. + negative-control test (fire→renew→assert absent).
- **RP-2 (HIGH) N CVEs collapse to one:** brief dedup keyed on (asset,check). FIX: key on **(asset,check,cve)** identity.
- **RP-3 (HIGH) all-or-nothing config:** one typo'd asset dropped the whole inventory silently. FIX: per-asset try/except in `_load_bastion`, loud stderr, valid assets survive.
- **RP-BASTION-01 (MED) SSRF-shaped scope leak:** the uptime probe FOLLOWED 30x redirects → an allowlisted host could bounce the HEAD to a third party / `169.254.169.254`, silent + unaudited. FIX: `_NoRedirect` opener (never follows; 3xx = the status). Regression test drives the REAL `UrllibUptimeSource` against live redirecting local servers.
- **REDPEN-P5-2 (MED) forgeable advisory boundary:** the perception text boundary was a substring in attacker-controlled screen text. FIX: guard-prefix (`  │ `) every captured line so it can never occupy column-0 → the header is an unforgeable EXACT-LINE boundary; machine consumers key off structured `captured_text`/`vision_reading_advisory` fields.
- **RP-PERCEPT-01 (MED) summary laundering:** image-only `summary` served the bare VLM reading unlabelled. FIX: prefix `(unverified VLM reading)` / neutral placeholder when no captured text.
- **REDPEN-BASTION-VER-1 (LOW):** `_ver_tuple` used `str.isdigit()` (accepts Unicode digits `int()` mishandles). FIX: `p.isascii() and p.isdigit()` — truly fail-closed.
- **RP-4 (MED) greenwashed offense test:** name-substring blocklist. FIX: positive FROZEN public-API allowlist (`{run,probe_target,name,mandate,ceiling}`) — any new public method fails until reviewed.

**ADVERSARIAL RE-CHECK on the fixed code (the recurring lesson — the fix introduces the next defect): CLEAN.** 3-run resolution idempotence (no churn), resolved→regressed reappears, SSRF-to-metadata redirect refused (0 hits), spine integrity holds across supersessions.

**Tests: 20/20 (`tests/test_perception_bastion.py`). Full system 93/93 (68 Python + 25 Rust).** Doctrine: `assert_no_offense` holds; no `framework.*` import.

**RECURRING LESSONS reinforced:** (1) serve-the-quote AGAIN — a VLM reading is a paraphrase; serve the captured span, label the reading advisory (4th time across consolidation/SCHOLAR/here). (2) "own-infra by construction" must survive the REAL capture path, not just injected doubles — the redirect leak lived in `UrllibUptimeSource`, which the doubles never exercised. (3) append-only findings need an explicit RESOLUTION path or the brief lies. (4) dedup on IDENTITY not CATEGORY. (5) positive allowlists > negative name-blocklists for capability-drift tests.

**NEXT:** Phase 6 (hardening: budgets, kill switch, promotion policy, mobile bridge, dashboard, + SCHOLAR/`read_source` scope-gate + BASTION real-remediation stays A3). Wire perception/BASTION actions through the Rust WARDEN signed log. Roadmap SIGIL.md §11.
