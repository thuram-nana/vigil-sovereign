# SIGIL

**A local-first, sovereign personal AI orchestrator.** SIGIL runs on hardware you own, remembers your
entire working history in a tamper-evident record, reasons over it, and — only ever with a provable
proof of authorization — acts on your files, your terminal, your screen, the web, and (with per-action
consent) your own online accounts. It answers by voice, from a hotkey palette, in a local web cockpit,
through any Claude session (via an MCP memory server), and from your **phone over WireGuard**.

It is built around a Rust authorization kernel (WARDEN), an append-only hash-chained memory spine, and a
mesh of gated agents, with a cheap-local → frontier cognition cascade.

> **Five laws.** ① Every action carries a proof of authorization. ② Memory is append-only. ③ Local-first.
> ④ Cascade, not monolith. ⑤ Prove, don't guess. **Non-negotiable: SIGIL has no offensive capability** —
> `assert_no_offense()` runs at import in every process; it imports zero offensive modules.

---

## Table of contents

- [What it is](#what-it-is)
- [Architecture](#architecture)
- [Capabilities](#capabilities)
- [Setup](#setup)
- [Usage](#usage)
- [The phone companion](#the-phone-companion)
- [Security model](#security-model)
- [Development & testing](#development--testing)
- [Status](#status)
- [Disclaimer](#disclaimer)

---

## What it is

Most "AI assistants" are a chat box wrapped around a remote model that forgets you between sessions and
can't safely touch anything you own. SIGIL is the opposite:

- **It remembers everything, provably.** Every message, decision, commitment, tool call, git commit, and
  agent transcript lands on an **append-only, hash-chained, Ed25519-signed spine**. Nothing is edited —
  only superseded. Any answer it gives cites the exact spine record it came from; an ungrounded claim is
  labelled as commentary, never asserted as fact.
- **It is local-first and sovereign.** The spine, keys, vectors, and graph live under `~/.sigil/` (0700)
  on your machine. Embeddings run on-CPU with no API. Frontier models are used through a **cascade** —
  cheap/local first, escalate only when needed — and any data leaving the box for a frontier model is a
  WARDEN-gated, owner-approved event.
- **It acts only with proof of authorization.** Every action an agent wants to take is a `Proposal`
  carrying an autonomy tier (A0–A3). The Rust WARDEN kernel classifies the *real* action (by an honest
  tool name), fail-closed: read-only auto-runs; anything reversible-internal auto-runs; anything
  external-visible or destructive **queues for an explicit, owner-signed approval** and never auto-runs.

The result is an assistant you can hand real capability — "fix the failing test and open a PR", "what did
I decide about X in March", "approve this from my phone", "log into my own account and do Y" — without
handing it a blank cheque.

---

## Architecture

```
  voice · hotkey palette · local web cockpit · Claude Code/Desktop (MCP) · phone (WireGuard)
        │            │              │                    │                       │
        └────────────┴──────────────┴─── T0 router ──────┴───────────────────────┘
                                           │
                    ┌──────────────────────┴───────────────────────┐
                    │   WARDEN  (Rust kernel: token-based, danger-  │   every action → a tier A0–A3
                    │   first tier classifier, fail-closed to A3,   │   → AUTO / QUEUE-for-approval / DENY
                    │   Ed25519-signed action log)                  │
                    └──────────────────────┬───────────────────────┘
                                           │
     agent mesh  ──────────────────────────┼──────────────────────────  perception
     ARCHIVIST · SENTINEL · STEWARD ·       │        vision (local VLM + egress-gated frontier),
     ENVOY(drafts-only) · ARTIFICER ·       │        screen/camera capture, gesture (hand landmarks),
     SCHOLAR · BASTION · OPERATOR ·         │        recall ("where did I last see X?")
     DELEGATE · WebResearcher(SCRIBE)       │
                                           │
        ┌──────────────────────────────────┴──────────────────────────────────┐
        │   append-only, hash-chained, Ed25519-signed SPINE (source of truth)  │
        └───────┬───────────────────────┬───────────────────────────┬─────────┘
         rebuild│                  embed │                    consume │
        Kùzu graph (entities)   Qdrant vectors            8 read-only, cited MCP tools
        (deterministic mirror)  (on-CPU, no API)          (Claude Code + Claude Desktop)
```

**Trust flow:** the spine is the sole authority. Graph and vectors are *deterministic projections* of it
(double-rebuild → identical). The MCP server, the cockpit, and the phone are read/act *surfaces* over it —
none of them is a second source of truth, and every mutating action they trigger passes WARDEN.

---

## Capabilities

Everything below is built and tested. Where something is a documented seam or off-by-default, it says so.

### Memory & recall
- **Episodic spine** (`sigil/spine/`) — append-only hash-chained JSONL; two-layer integrity (payload
  binding + chain linkage) plus an Ed25519-**signed head** that distinguishes benign growth from
  truncation/rewrite. 43k+ records.
- **Ingestion** (`sigil/ingest/`) — your Claude Code history, git commits (live post-commit/post-merge
  hooks), subagent transcripts (each a titled session), and curated docs. Incremental, idempotent.
- **Vectors** (`sigil/vectors/`) — on-device embeddings (`fastembed` / bge-small, CPU, no API, no cost)
  in a local Qdrant. An absent topic returns *"no grounded match"* — never a fabrication.
- **Graph** (`sigil/graph/`) — a deterministic Kùzu entity mirror of the spine, rebuilt by replay with an
  atomic swap; every node cites its spine anchor.
- **Consolidation / ARCHIVIST** (`sigil/consolidate/`) — a nightly agent-driven pass that extracts
  decisions/commitments/entities behind a **demote-only veracity gate**: a fact is promoted only if its
  quote is byte-verbatim in a cited spine record; everything else is recorded as an honest refusal.
- **MCP memory server** (`sigil/mcp/`) — **8 gated, read-only, cited tools** (`memory_search`,
  `episodic_range`, `ingest_status`, `graph_entity`, `graph_query`, `threads_open`, `commitments_due`,
  `contradictions_pending`) registered in **Claude Code and Claude Desktop**, so any Claude session gains
  cited recall of your own history.

### Authorization kernel (WARDEN) & governance
- **Rust KERNEL + WARDEN** (`kernel/`) — a token-based, danger-first tier classifier (fail-closed to A3),
  a T0 request router, and a hash-chained **Ed25519-signed action log**. Sub-commands: `ask`, `do`,
  `classify`, `verify`, `audit`, `checkpoint`, `pubkey`.
- **Governor** (`sigil/governor/`) — the Python enforcement layer: an asymmetric **kill switch** (any
  engage halts fail-safe; only an owner-signed release un-halts), fail-closed **budgets**, and a
  per-(agent, record-kind) **promotion policy** — all owner-Ed25519-signed and verified against the
  persisted owner key, so a forged grant grants nothing.
- **Owner-signed approval queue** (`sigil/agents/approvals.py`) — A2/A3 proposals queue and resolve only
  on a verified owner (or owner-authorized device) signature bound to the exact target.

### Agents
- **ARCHIVIST / SENTINEL / STEWARD** — memory consolidation, salience/budget triage, and an unprompted
  morning brief.
- **ENVOY** — communications drafting; **drafts-only by construction** (no send path exists) and
  no-promotion forever.
- **ARTIFICER** — background coding via headless `claude -p`: writes tests before a PR, opens PRs (never
  pushes), git-worktree isolated.
- **SCHOLAR / WebResearcher (SCRIBE)** — sourced research and a grounded web-research engine
  (`sigil/scrape/`): a value-of-information crawl frontier, **robots.txt respected**, per-host rate
  limiting, and every claim served as a byte-verbatim quote citing a real spine record.
- **BASTION** — defensive posture scanning of **your own infrastructure only** (allowlist → refusal):
  cert-expiry, dependency-CVE, uptime; findings surface in the brief.
- **OPERATOR** (`sigil/agents/operator.py`) — opens folders/files and runs terminal commands **on
  request**, each step WARDEN-tiered, in a transaction: plan → preview (dry-run diffs, zero mutation) →
  hash-bound approval → execute → verify by re-reading the world → transactional rollback / signed undo.
- **DELEGATE** (`sigil/agents/actor.py`) — an owner-consented **identity/account manager + web actor**:
  manages your *own* email/username/password (in the OS keyring, never on the spine) and, with per-action
  A3 owner approval, creates accounts / logs in / fills forms. Offense-free by construction — no
  impersonation code path, a CAPTCHA/403 STOPS and is surfaced (never defeated), per-service creation cap,
  HTTP-only.

### Perception, voice & gesture
- **Voice** (`sigil/voice/`) — a full-duplex wake → VAD → streaming ASR → KERNEL → TTS pipeline with
  barge-in.
- **Vision** (`sigil/perception/`) — on-device VLM (Moondream via Ollama, A0) by default; a **frontier**
  hop is a WARDEN-classified, owner-approved **data-egress** event (nothing leaves the box unapproved).
  Captured OCR text is authoritative; the VLM is advisory (serve-the-quote). **Recall:** "where did I
  last see X?" answered from grounded on-screen history.
- **Gesture / SIGIL-HAND** (`sigil/gesture/`) — control the cursor with your hand through a camera: a warm
  camera stream → landmark model → invariant-feature classifier → debounced fail-safe FSM →
  owner-**armed** session. A gesture is bounded by WARDEN to an A1 pointer move/click/scroll inside a live
  session; `type`/`launch` **always queue** for approval — a gesture can never type a password or launch
  an app.

### Interfaces
- **Web cockpit** (`sigil/ui/`) — a provenance-first "glass cockpit" (loopback by default; private-bind +
  reverse proxy to reach it by a domain, **never** a public listener — see
  [`deploy/REMOTE-HOSTING.md`](deploy/REMOTE-HOSTING.md)): every on-screen atom click-throughs to a
  **live-re-verified** spine hash; a live SSE feed; a knowledge-graph map; a ⌘K palette showing the
  predicted WARDEN tier before acting; and a CSRF-proof, owner-signed action plane (the private key never
  enters the browser).
- **Cross-platform + mobile** (`sigil/platform/`, `sigil/mesh/`, `sigil/bridge/`) — per-OS backends
  (Linux real; macOS/Windows/Android honest-degrading), OS-keyring secrets, an owner-signed
  device-authorization ledger, and the **phone companion** below.

---

## Setup

**Prerequisites:** Linux (primary), Python 3.13, Rust (for the kernel), Docker (for Qdrant), and
optionally Ollama (local VLM), a WireGuard/Tailscale tunnel (phone companion), and `ydotool`/`xdotool`
(gesture input on Linux).

```bash
# 1. Python environment + dependencies
python3 -m venv ~/.sigil/venv
~/.sigil/venv/bin/pip install -r requirements.txt
#    (cryptography, fastembed, kuzu, mcp, onnxruntime, pydantic, qdrant-client)

# 2. Local vector store (Qdrant on loopback)
docker run -d --name sigil-qdrant --restart unless-stopped -p 127.0.0.1:6333:6333 \
    -v ~/.sigil/vectors:/qdrant/storage qdrant/qdrant

# 3. Build the Rust authorization kernel
cd kernel && cargo build --release && cd ..     # → kernel/target/release/sigil-kernel

# 4. Build the memory loop
V=~/.sigil/venv/bin/python
$V -m sigil.cli ingest      # your Claude history + subagents (+ --git, --docs) → spine
$V -m sigil.cli index       # spine → vectors (incremental)
$V -m sigil.cli graph       # rebuild the deterministic entity graph
$V -m sigil.cli sign        # anchor the spine (Ed25519 signed head)

# 5. Register the MCP memory server (Claude Code + Claude Desktop)
#    add to ~/.claude.json and ~/.config/Claude/claude_desktop_config.json under "mcpServers":
#    "sigil-memory": { "command": "/home/<you>/.sigil/venv/bin/python",
#                      "args": ["-m","sigil.mcp.server"],
#                      "env": {"SIGIL_HOME": "/home/<you>/.sigil"} }
```

Runtime data lives under `~/.sigil/` (spine, keys, vectors, graph — private, 0700). Code lives in this
repo. The Qdrant server URL is persisted in `~/.sigil/sigil.env`.

---

## Usage

```bash
V=~/.sigil/venv/bin/python
S="$V -m sigil.cli"

# ── memory ───────────────────────────────────────────────
$S search "the veracity firewall"      # cited recall from the spine
$S consolidate --provider heuristic    # offline extraction (default, no frontier spend)
$S consolidate --provider claude       # agent-driven (headless claude -p on Max)
$S status                              # counts + live integrity
$S verify <report.json>                # re-verify a report's citations offline

# ── the WARDEN authorization kernel ──────────────────────
$S warden status                       # kill-switch / promotion state
$S warden kill        /  $S warden release
$S warden promote <agent> / revoke <agent>
$S audit                               # the signed action log

# ── agents ───────────────────────────────────────────────
$S agents brief                        # the unprompted morning brief (STEWARD)
$S agents triage                       # inbox triage (ENVOY drafts-only)
$S agents sentinel                     # salience / budget pass
$S agents research "<question>"        # sourced research (SCHOLAR / SCRIBE)
$S agents artifice                     # background coding (ARTIFICER → PR)
$S agents bastion                      # defensive posture scan (own infra only)
$S agents perceive --image <path>      # vision (OCR authoritative + local VLM advisory)
$S agents perceive --recall "<X>"      # "where did I last see X?"

# ── voice & scraping ─────────────────────────────────────
$S voice --mic                         # full-duplex voice (--asr/--tts/--wake options)
$S scrape <seed-url>                   # grounded web research (robots-respected, cited)

# ── the local cockpit ────────────────────────────────────
$S serve                               # loopback provenance-first web UI (prints a token)
$S dashboard                           # read-only TUI dashboard
$S host                                # this host's capability descriptor
```

Any registered Claude session (Code or Desktop) can also just *ask* — e.g. *"what did I decide about the
kill-switch"* — and gets a cited answer via the MCP tools.

---

## The phone companion

Your phone becomes a **signed remote-control + approval + gesture surface over WireGuard**. The engine
stays on your PC; the phone holds only its own Ed25519 device key — your owner trust-root never leaves the
desktop, and the desktop **verifies** every request (it never signs on the phone's behalf).

**Try it now, no phone or tunnel needed** — a runnable end-to-end demo against the real server on loopback:

```bash
~/.sigil/venv/bin/python demo/companion_demo.py    # pair → approve → relay → recall → arm → panic
```

**Real WireGuard / Tailscale** (full guide in [`demo/README.md`](demo/README.md)):

```bash
sigil bridge serve --addr 10.13.13.1      # bind to the tunnel IP (refuses 0.0.0.0/public);
                                          # mints owner-pinned self-signed TLS + prints its fingerprint
sigil mesh authorize phone-1 <pubkey>     # pair the phone, confirming the fingerprint it shows
sigil mesh list-devices  /  sigil mesh revoke phone-1 <pubkey>
```

Then, from the installable PWA the desktop serves, the phone can: **approve/deny** queued A2·A3 actions,
**panic-halt** (fail-safe; release stays owner-only), **relay** a command to the WARDEN-gated KERNEL,
browse a **read-only cockpit** + live push feed, **recall** grounded on-screen history, and (opt-in) **arm
a gesture session** and act as a **remote trackpad** — with every guarantee (A1 pointer only; type/launch
always queue; owner disarm/panic/revoke always wins) intact over the wire.

---

## Security model

- **Proof-of-authorization on every action.** Actions are tiered by the fail-closed Rust WARDEN oracle,
  not self-declared; A0/A1 auto-run, A2/A3 queue for an owner-signed approval and never auto-run.
- **Tamper-evident memory.** The spine is append-only + hash-chained; the Ed25519-signed head catches
  truncation/rewrite; concurrent writers are serialized so the chain can't fork.
- **Secrets off the spine.** Credentials and keys live in the OS keyring / 0700 files, never in the
  append-only log, a network payload, or a UA/Referer header.
- **Local-first & sovereign.** Data leaving the box for a frontier model is a WARDEN-gated, owner-approved
  egress event. The cockpit binds loopback by default and **never** a public interface (a public bind
  fails closed; reach it by a domain via a private bind + TLS reverse proxy — `deploy/REMOTE-HOSTING.md`);
  the phone bridge binds a WireGuard-private address only
  (never `0.0.0.0`/public), authenticates by per-request Ed25519 signature (no wire bearer secret), and
  the owner trust-root never leaves the PC.
- **Offense-free by construction.** `assert_no_offense()` at import; no impersonation, no CAPTCHA/bot
  evasion, no attacking third parties, no mass account creation — enforced by the *absence* of the code
  paths, not just a check.
- **Prove, don't guess.** Every served fact is a byte-verbatim quote citing a real spine record; an
  ungrounded model claim is labelled commentary, never asserted; the veracity gate can only demote.

Every security-relevant change in this repo went through an adversarial review (red-pen + an independent
sweep) and an adversarial re-check on the fixed code before merge — the review history is in the commit
log and the per-finding negative-control tests.

---

## Development & testing

```bash
# the full Python suite (deterministic, offline; temp stores + generated keypairs)
for t in tests/test_*.py; do ~/.sigil/venv/bin/python "$t"; done
# the Rust kernel suite
cd kernel && cargo test --release
```

25 Python suites (**319 tests**) + **26 Rust tests**, all green. Tests use temp `SpineStore`s and
generated keypairs — they never touch your real `~/.sigil`. Each historical finding has a negative
control that fails before its fix and passes after.

---

## Status

Phases 0–9 are complete and merged: **memory loop** → **KERNEL + WARDEN** → **voice** → **agent mesh** →
**ARTIFICER/SCHOLAR** → **perception + BASTION** → **hardening** → **embodiment** (vision, operator, web
cockpit, cross-platform/mobile) → **frontier** (grounded scraper, gesture control, web-actor) →
**companion** (phone bridge + PWA + gesture trackpad + device-signed remote arm). macOS/Windows/Android
backends and the browser-fallback web engine are honest, documented seams (Linux is the proven path).

---

## Disclaimer

**SIGIL is a personal, single-owner, defensive/local-first tool — not a product, not a service, and not
security-audited software.** By using it you accept the following:

- **Operate only on systems, accounts, data, and networks you own or are explicitly authorized to use.**
  The DELEGATE web-actor manages **your own** identity only and acts only on origins you allowlist; the
  BASTION scanner touches **your own** infrastructure only. Do not point any part of this at third
  parties.
- **It takes real, powerful actions on your machine** — reading/writing files, running terminal commands,
  injecting input, driving the cursor, creating/logging into accounts, and controlling the machine from a
  phone. Approvals are the safety boundary; grant them deliberately. Some capabilities (the phone bridge,
  the device-signed remote gesture arm) are **trust-widening** — review them before enabling.
- **No warranty.** This software is provided "as is", without warranty of any kind. The authors are not
  liable for any damage, data loss, cost (including frontier-model API spend), account lockout, or other
  consequence of its use. You are responsible for your keys, your backups, and your scope.
- **Offense-free by design, but not a security guarantee for you.** SIGIL contains no offensive
  capability and is built to fail closed, but it has **not** been independently audited; run it on
  hardware you control, keep the runtime data (`~/.sigil/`, keys) private, and rotate any secret you ever
  place in it.
- **AI-assisted and probabilistic.** Agent output and model reasoning can be wrong. SIGIL is built to
  serve grounded, cited facts and to label ungrounded output as commentary — but you remain the final
  authority on every consequential decision.

Use it as what it is: a sovereign assistant for your own life and work, on your own machines, under your
own key.
