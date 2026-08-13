# Inventory D — Tools, keys, credentials, authorization, signing, and network safety

**Status: raw technical inventory for downstream writers. Not lay-reader prose.**

Every statement below was read out of the repository at `/home/kali/vigil` on 2026-08-12
(`main` @ `1487e03a`). Each entry cites the file it came from. Where a capability is **built but not
yet exercised against a live third-party system**, that is stated explicitly — per
`docs/CLAIM-DISCIPLINE.md`, an audited overclaim is closed by building the capability up, never by
softening the claim.

> **Revision note.** An earlier pass of this inventory was taken at `main` @ `0afb6e9a`. Two things
> have moved since, and both are reflected below:
>
> 1. **The E-series of cloud and Kubernetes exploitation confirmations is now COMPLETE and merged**
>    (PRs #286, #288–#293). All six are wired end to end and proven with fixture evidence offline.
>    New **§6** inventories them. The honesty ledger in **§9** is updated accordingly — the deferral
>    is now precisely *real-world live fire against third-party cloud accounts*, nothing more.
> 2. **Supply-chain hardening is being delivered today** (dependency hash-locking, container
>    base-image pinning, SBOM, and a vulnerability gate that blocks on CRITICAL). New **§7** records
>    exactly what was observed in flight, and what was not yet present at the time of this pass.

Notation used throughout:

| Tag | Meaning |
|---|---|
| **WORKING** | Code exists, is wired into a live path, and the repo documents it as exercised. |
| **BUILT — NOT LIVE-FIRED** | Code exists and is tested offline, but its real-world execution is deliberately deferred (usually waiting on operator-supplied credentials, hardware, or a tool binary). |
| **SCAFFOLD / STUB** | Interface exists; the implementation raises. Never claimed as active. |
| **NOT VERIFIED** | I could not confirm it from code in this pass. |

---

## 1. External tools the system can drive

There are **four distinct tool surfaces**, and they must not be conflated. Writers should treat
these as separate lists.

### 1.1 The host tool roster — tools the offense engine actually spawns

Source of truth: `engine/crucible/framework/v2/tools/registry.py` → `HOST_TOOLS`.
This roster is deliberately restricted "to what the code ACTUALLY spawns as a subprocess — not an
aspirational arsenal; every entry is traceable to a call site" (module docstring).

`bootstrap.sh` reads this same roster via `python -m framework.v2.tools.registry --emit-shell`, so
the installer and the UI's Tools screen cannot drift apart.

**Required (`optional=False`) — the offense core, spawned by the live executor:**

| Tool | Plain terms | Install hint in code |
|---|---|---|
| `nmap` | Port and service discovery. | `apt: nmap` |
| `httpx` (ProjectDiscovery) | Fast HTTP probing / technology fingerprint. | `apt: httpx-toolkit` |
| `nuclei` | Template-based vulnerability scanning. | `apt: nuclei` |
| `ffuf` | Content / parameter fuzzing and discovery. | `apt: ffuf` |
| `sqlmap` | SQL-injection confirmation. | `apt/pip: sqlmap` |
| `hydra` | Credential brute-force. Registry comment: "destructive — floors at A3 + m-of-n quorum". | `apt: hydra` |

**Optional (`optional=True`) — the engine uses them when present and degrades cleanly:**

| Tool | Plain terms |
|---|---|
| `semgrep` | Static analysis (SAST) over source code. |
| `joern` | Code-property-graph inter-procedural dataflow (deep source review). Installed out of band. |
| `tshark` | Packet-capture flow analysis (sensor). |
| `chromium` (or `chromium-browser` / `google-chrome*`) | Headless DOM render for DOM-XSS confirmation. |
| `nikto` | Web-server misconfiguration scan (report parsed by an adapter). |
| `wapiti` | Web-application vulnerability scan (JSON report parsed). |
| `zaproxy` (OWASP ZAP) | DAST; JSON report parsed. Version probe deliberately disabled (GUI/daemon wrapper — the code will not launch it just to read a version). |

**Deliberately excluded from the probed roster (honesty over completeness, per the docstring):**
Burp Suite. The engine talks to Burp's REST API via `CRUCIBLE_BURP_URL`; it never spawns a
`burpsuite` binary, so probing for one "would be a fabricated status."

Notable integrity detail: `ToolSpec.wrong_markers` catches the common case where the Python `httpx`
HTTP-client CLI shadows ProjectDiscovery's `httpx` on `PATH`. A shadowed hit reports `shadowed`, not
`installed`, so "a required tool that is effectively absent never shows a false green."

Installation behaviour (`bootstrap.sh` → `provision_host_tools`): OS-detects, probes each tool,
installs missing ones **only with consent** (`--yes`, or an interactive prompt; a non-TTY run without
`--yes` answers **no**, fail-closed). Failures are recorded with the exact manual command and
bootstrap continues — "a tool never aborts bootstrap." On non-Linux hosts every tool is reported
`unsupported`, never a faked install. If a required tool is missing, the warning is explicit: "live
engagements needing them will refuse until you install them."

Runtime on-demand install: `engine/crucible/framework/v2/tools/install.py`. Only a roster-admitted
tool may be installed, only via its **declared** install hint (never a caller-supplied package),
always as a list argv (no shell), and **operator consent is required** — without `consent=True` the
call returns a `needs_consent` ask, so "autonomous code therefore never mutates the host."

### 1.2 The Strix sandbox roster — tools inside the agent container, not on the host

Source: `registry.py` → `SANDBOX_TOOLS`, `SANDBOX_IMAGE = "vigil/strix-sandbox:local"`, drawn from
`vendor/strix/containers/Dockerfile`. These are **informational only — never probed on the host and
never installed by bootstrap**:

`nmap`, `ncat`, `sqlmap`, `nuclei`, `httpx`, `subfinder`, `naabu`, `ffuf`, `katana`, `gospider`,
`arjun`, `dirsearch`, `wafw00f`, `interactsh-client`, `wapiti`, `zaproxy`, `semgrep`, `bandit`,
`trufflehog`, `gitleaks`, `trivy`, `chromium`, `caido-cli`, `jwt_tool`.

Using this surface **requires Docker** (`docs/DEPLOY.md` prerequisites table: Docker is "optional for
the core… **required for strix**"), plus a built image (`docker compose --profile strix build
strix-sandbox`) and `STRIX_IMAGE` set in `.env`.

### 1.3 The capability matrix — which tools can produce a *proven fact*

Source: `docs/capability-matrix/hexstrike.json` (schema `vigil-capability-matrix/1`), validated by
`integration/vigil_integration/live/tool_manifest.py`.

Upstream note recorded in the file: `hexstrike-ai (0x4m4), pinned d689933 — vendored NON-runnable;
79 distinct external tools`. The matrix currently carries **33 rows**.

This is the single most important honesty structure in the tool inventory. Three states:

- **`fact_capable: true`** — a VIGIL-owned oracle re-drive exists **and** the tool's ToolSpec passed
  the conformance battery. **Only 2 of 33 rows qualify: `nmap` (oracle family
  `SERVICE_REACHABILITY`) and `sslscan` (oracle family `TLS_WEAKNESS`).**
- **LEAD-only** — the tool is allowed to *propose* where to look; its say-so never mints a fact.
  This covers `httpx`, `katana`, `subfinder`, `nuclei`, `gobuster`, `trivy`, `grype`, `checkov`,
  `prowler`, `kube-bench`, `gdb`, `scout-suite`, `terrascan`, `kube-hunter`.
- **`excluded: true`** — offense/credential/persistence/destructive tools that are never proposable
  and never a fact source: `sqlmap`, `xsser`, `metasploit`, `pacu`, `pwntools`, `angr`, `ropgadget`,
  `ropper`, `one-gadget`, `libc-database`, `pwninit`, `hashpump`, `hydra`, `netexec`, `responder`,
  `john`, `hashcat`. (`john` and `hashcat` are annotated "EXCLUDED — exceptional authorization only".)

**Note for writers — an apparent contradiction that is real and must be explained, not hidden:**
`sqlmap` and `hydra` appear in the *required host roster* (§1.1) and in the live executor's argv
builders (§1.4), yet are `excluded` in the capability matrix. These are two different claims. The
executor *can* be asked to drive them (they are classified destructive and gated hardest — see §3);
the capability matrix says their **output can never become a proven fact** — VIGIL confirms SQL
injection with its own gated payload re-drive plus its own oracle, "never sqlmap"
(`hexstrike.json` note on the `sqlmap` row).

The matrix's own note records that **two fact families are VIGIL-DIRECT — no tool is the authority**:
`VERSION_RANGE` via `live/sbom.py` (VIGIL parses the manifest/lockfile against a pinned OSV snapshot
itself) and `ACHIEVED_STATE` via `live/web_redrive.py` (VIGIL issues its own gated, no-redirect
capture). Their proposer tools (`trivy`/`grype`, `httpx`) keep `fact_capable: false` **by design**.

Structural invariants enforced by `tool_manifest.validate_manifest`:
`excluded ⇒ not fact_capable`; `fact_capable ⇒ a non-empty oracle_family`; a tool with no oracle
family is LEAD-only by construction; and a **name backstop** (`_KNOWN_OFFENSE_BINARIES`) forces
exclusion for known offense/credential binaries "regardless of the self-declared category, so a row
cannot relabel e.g. sqlmap as 'recon' to escape the category rule."
The module states its own honest bound: the validator checks **structure only** — it does not verify
that `oracle_family` names a real oracle. That is enforced by the conformance battery
(`live/conformance.py`) and a pinned `fact_capable` set test (`integration/tests/test_tool_manifest.py`).

### 1.4 The live executor's six network tool builders

Source: `integration/vigil_integration/live/executor.py` → `_BUILDERS`.
Exactly six tools can be driven by the live engagement loop, each via a hand-written argv builder
(no shell, no free-form command): **`nmap`, `nuclei`, `httpx`, `ffuf`, `sqlmap`, `hydra`.**
`hydra`'s inline `-p <password>` position is explicitly masked in the signed execution record.

Plus two non-network execution tiers registered with the same gate: `terminal.run` (local read/inspect
allowlist) and `sandbox.exec` (bubblewrap-isolated arbitrary command) — see §3 and §5.

### 1.5 The tool-agnostic external-tool runner

Source: `integration/vigil_integration/live/external_tool.py`; runbook `docs/DEFERRED-INFRA.md` §R4.

`run_external_tool(spec, target, …)` is the bridge from "a tool ran" to "a machine-verified fact." Its
order is fail-closed at every step: pre-flight gate (kill-switch + charter + entitlement) → scope gate
(no traffic leaves for an out-of-scope target; the tool is never launched) → backend availability
(`BackendUnavailable` rather than a silent un-gated fallback) → run → **oracle adjudication** of each
proposal via an independent gated handshake.

Two exec backends:
- `DockerTopologyBackend` — runs the tool inside a container pinned to the internal `vigil_sandbox`
  network, whose only exit is the filtering gateway behind the nftables egress gate.
- `LocalSubprocessBackend` — runs on the host, used only for loopback proofs (the isolation backends
  unshare the network namespace and therefore cannot reach a host loopback service).

**Honest status (from the module docstring and `DEFERRED-INFRA.md` §R4):**
- **WORKING** — a real `nmap -oG -` run against a stood-up loopback listener producing exactly one
  oracle-confirmed, signed fact; a closed / non-reproducing port becomes a lead, never a fact.
- **BUILT — NOT LIVE-FIRED** — the LLM-red-team tools **garak / PyRIT / promptfoo** are *absent from
  this environment* (no network to install them). "This module does NOT mint a garak/PyRIT FACT."
- **BUILT — NOT LIVE-FIRED** — `DockerTopologyBackend` builds the real pinned-network argv, but its
  live container run is gated on Docker + the sandbox network + a tool image being present.

`live/conformance.py` is the acceptance battery a ToolSpec must pass *through the real runner, never
a mock* before `fact_capable` may be set: POSITIVE (mints a fact that re-verifies offline), DECEPTIVE
(a proposal the re-drive cannot reproduce mints nothing), TOOL-ERROR, KILL-SWITCH (refuses before any
traffic), OUT-OF-SCOPE (refuses before any traffic). A report is conformant only if **every** required
property is present and true — a missing property is non-conformant, never vacuously satisfied.

### 1.6 The vendored "brain" and the vendored agent

- `vendor/hexstrike-ai/` is vendored **NON-RUNNABLE and quarantined**. A CI tripwire
  (`integration/tests/test_vendor_hexstrike_quarantine.py`) fails the build if any VIGIL source tree
  imports it. The only reuse is `integration/vigil_integration/brains/hexstrike_brain.py`, a
  clean-room, propose-only reimplementation with **zero network side effects, zero evasion, zero fact
  authority**; the upstream's evasion/stealth, credential-poisoning (Responder LLMNR/WPAD), WAF-tamper,
  and live-exploit/persistence stages are "REMOVED by construction, not stripped after the fact."
  Reached with `vigil engage --brain hexstrike` (`cli.py`, `--brain` choices are `""` or `"hexstrike"`).
- `vendor/strix/` is a vendored third-party agentic pentest tool (Apache-licensed upstream; see
  `NOTICE`). Its arbitrary shell is governed — see §3.5.

### 1.7 MCP (Model Context Protocol) tool servers

- `engine/crucible/framework/v2/mcp/` — CRUCIBLE can **expose** its gated capabilities as an MCP
  server, or **consume** external MCP servers (`__main__.py` subcommand `mcp`).
- `integration/vigil_integration/tools/mcp_registry.py` — the pluggable MCP-server manifest layer
  (adapted from redamon, MIT; see `NOTICE`). Servers carry phase and destructive flags so MCP tools
  route through the same conjunctive gate. **Honest bound in the docstring:** "The live client that
  actually speaks to an MCP server … is the one real seam and is [pending]" — the manifest/validation/
  config-conversion layer is built; binding a live MCP client is described as a later slice.
  Status: **BUILT — NOT LIVE-FIRED** for the live client leg. Reserved server IDs cannot be claimed by
  a user-supplied server.

---

## 2. External APIs, accounts, and credentials

### 2.1 The canonical credential list

Source of truth: `apps/sigil/sigil/ui/settings.py` → `SECRET_META`. This is a **closed allowlist** —
"an unknown name is refused by `set_secret`, so the UI can never seal an arbitrary env var." Secrets
are sealed on the machine and never returned to the browser. `probe: True` means a **live** health
check exists (`apps/sigil/sigil/platform/secret_probes.py`) so a bad or expired key shows as
**failing**, not green; the count drives a top-bar "N keys failing" badge.

| Env var | Category | Required? | What it buys |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | LLM | **Effectively required for AI reasoning** (see §2.2) | Lets the AI reason over the target: engagements, scans, fix proposals. |
| `MISTRAL_API_KEY` | LLM | Optional | Bring-your-own-model via Mistral. |
| `OPENAI_API_KEY` | LLM | Optional | Bring-your-own-model for the Strix agent body. |
| `PERPLEXITY_API_KEY` | LLM | Optional | Live web research during a codebase engagement (Strix). |
| `AZURE_OPENAI_API_KEY` | LLM | Optional | Bring-your-own-model via Azure OpenAI (also needs the endpoint). |
| `AWS_ACCESS_KEY_ID` | Cloud | Optional | Read-only AWS posture testing (S3/IAM) and Bedrock models. Validated via STS `get-caller-identity`. |
| `AWS_SECRET_ACCESS_KEY` | Cloud | Optional (paired) | Secret half of the AWS pair. |
| `AWS_SESSION_TOKEN` | Cloud | Optional | Only for temporary/STS credentials. |
| `AZURE_CLIENT_SECRET` | Cloud | Optional | Service-principal secret for read-only Azure posture. Validated with an AAD token. |
| `GOOGLE_APPLICATION_CREDENTIALS_JSON` | Cloud | Optional | Read-only GCP service-account key (pasted whole JSON). Validated by minting an access token. |
| `KUBECONFIG_CONTENT` | Cloud | Optional | Kubeconfig for the cluster to test. Validated with a read-only `/version` call. **`exec` / `cmd-path` credential plugins are refused** (they run a local command). |
| `GITHUB_TOKEN` | Integration | Optional until live auto-patch | Lets the auto-patch engine push a fix branch and open a gated PR. Needs `repo` + `pull-request` scope. |
| `ELEVENLABS_API_KEY` | Integration | Optional | Voice output (TTS). Explicitly never bridged to the offense side. |
| `CRUCIBLE_API_KEY` | Integration | Conditionally required | Shared secret protecting the gated offense API when the cockpit is hosted behind a domain. An internal secret you choose — no external service. |
| `CRUCIBLE_OOB_RELAY_SECRET` | Integration | Optional | Authenticates out-of-band (OAST) callbacks. Internal secret. |
| `NEO4J_PASSWORD` | Graph | Optional until you connect a graph | Cloud/remote Neo4j (e.g. Aura) for the per-session knowledge graph. Validated live with a bolt `RETURN 1`. |
| `VIGIL_DESTRUCTION_OWNER_KEY` | Auto-patch signing | Optional until you open PRs | The owner key that authorizes an auto-patch pull request (the m-of-n destruction quorum). |

Non-secret companion config (`CLOUD_CONFIG_META`, shown not masked): `AWS_REGION`, `AWS_ROLE_ARN`,
`CRUCIBLE_AWS_ENDPOINT_URL`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_SUBSCRIPTION_ID`,
`GOOGLE_CLOUD_PROJECT`, `KUBE_CONTEXT`, `NEO4J_URI`, `NEO4J_USERNAME`.

Two additional owner keys are read from the environment, never argv, and are **not** in `SECRET_META`
delivery paths to offense children:
- `VIGIL_APPROVAL_OWNER_KEY` — signs per-action approval tokens (`vigil approve sign`).
- `VIGIL_DESTRUCTION_OWNER_KEY` — signs one destructive action (`vigil authorize-destruction`).

### 2.2 Model providers — bring-your-own-model

Source: `apps/sigil/sigil/ui/settings.py` → `PROVIDERS` (9 entries), and
`engine/crucible/framework/v2/kernel/backends/` (11 backend modules).

| Provider id | Label | Keyless? | Keys needed |
|---|---|---|---|
| `anthropic` | Claude (Anthropic API) | no | `ANTHROPIC_API_KEY` |
| `anthropic-zdr` | Claude (zero-data-retention API) | no | `ANTHROPIC_API_KEY` |
| `bedrock` | Claude on AWS Bedrock | no | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ region) |
| `vertex` | Claude on Google Vertex | no | GCP service-account JSON path (+ project, region) |
| `mistral` | Mistral (EU) | no | `MISTRAL_API_KEY` |
| `azure_openai` | Azure OpenAI | no | `AZURE_OPENAI_API_KEY` + endpoint |
| `self-hosted` | Self-hosted (OpenAI-compatible) | **yes** | base URL only |
| `ollama` | Ollama (local) | **yes** | host only |
| `claude-code` | Claude Code (local session) | **yes** | none |

There is also a `DryRunBackend` (`kernel/backends/dryrun.py`) — the default fallback when no live LLM
is reachable. It writes the rendered prompt to disk and returns deterministic fixture output; its
docstring is explicit that this is "not 'realistic LLM output'" and that reasoning quality is bounded.

**Sovereignty ladder** (`kernel/sovereignty.py`, env `CRUCIBLE_SOVEREIGNTY_TIER`), which constrains
which providers may be selected at all: `AIR_GAPPED` (local backends only; cloud refused at
construction) → `SOVEREIGN_CLOUD` (local + jurisdictional cloud: Bedrock/Vertex with regional
restriction, Mistral; direct consumer Anthropic API and Claude Code OAuth refused) → `TRUSTED_CLOUD`
(adds Anthropic Enterprise/ZDR; requires explicit operator attestation that the key is ZDR-enabled) →
`PERMISSIVE` (default for development; no policy enforcement). This is directly relevant to a
government reader.

### 2.3 Is any credential strictly required to run?

No. Several distinct fallbacks exist, and each is honest about what it gives up:

- **No LLM key at all.** `vigil engage` still runs: "it still attests first, then completes proposing
  NOTHING — it never fabricates activity" (`cli.py` module docstring). A scripted `--replay` file, or
  a keyless provider (`ollama` / `self-hosted` / `claude-code`), also drives the loop.
- **`.env.example` states plainly:** "NO secrets are required to bring the stack up; the commented
  lines are optional overrides."
- **Deterministic layers need no key at all.** Oracles, signing, verification, the gate chain, and the
  offline verifiers are pure code — the model only ever proposes.

### 2.4 Services (not credentials, but external dependencies)

`docker-compose.yml` + `integration/vigil_integration/services.py` → `ROOT_SERVICES`.
**Every host port is published on `127.0.0.1` only — never `0.0.0.0`.**

| Service | Compose profile | Port | Purpose | Required? |
|---|---|---|---|---|
| Qdrant | (default) | 6333 | Vector memory (SIGIL) | Optional — SIGIL has an embedded fallback (`bootstrap.sh --no-services`) |
| Neo4j | `graph` | 7687 | Knowledge graph | Optional |
| OTel collector | `observability` | 4318 | Telemetry / OTLP export | Optional |
| `strix-sandbox` | `strix` | — | **Build-only** Kali image the agent runs targets in | Required for Strix |

Host prerequisites (`docs/DEPLOY.md`): Python 3.12/3.13 (**hard stop**), Rust/rustup (builds the
WARDEN kernel; bootstrap offers a user-level install), Docker + compose (optional for core, required
for Strix), TPM + `tpm2-tools` (optional; see §4.6).

### 2.5 How credentials reach the offense engine

`integration/vigil_integration/uiproxy.py`. The **sovereign** side holds the owner key; the
**offense** side is keyless. `vigil up` resolves runtime env from the sovereign venv
(`sigil settings export-runtime-env --include-secrets`) and passes it to offense children through a
**consumer allowlist** (`_OFFENSE_ENV_ALLOWLIST`).

Hard rules encoded there:
- **`VIGIL_DESTRUCTION_OWNER_KEY` is the one hard exclusion** — absent from the allowlist *and*
  stripped from the ambient parent environment (`_CHILD_ENV_HARD_EXCLUDE`), "so a keyless offense
  process must never receive the auto-patch signing key" and cannot self-authorize a destructive PR.
- `ELEVENLABS_API_KEY` is never bridged ("voice = sovereign").
- `PYTHONPATH` / `PYTHONHOME` are stripped from every cross-venv child so a parent-injected path can
  never inject the other trust domain's modules (`dispatch.py`, `uiproxy.py`).
- **File-content credentials** (`GOOGLE_APPLICATION_CREDENTIALS_JSON`, `KUBECONFIG_CONTENT`) are
  base64-sealed, then materialised to **fixed-name `0600` files** under a `0700` dir using
  `os.unlink`-then-`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` with an `st_nlink==1` check (symlink/hardlink
  safe). The child receives **only the path**; the raw content var is always dropped from the child
  env, even on failure.

---

## 3. Security and authorization — the gate chain

### 3.1 The charter — the binding authorization document

`engine/crucible/framework/v2/authority/charter.py` + `common/ethics.py:parse_scope`.
The charter is a Markdown file at `targets/<slug>/charter.md`. Scope is parsed from a **numbered
in-scope host table**; `authority_from_charter` builds an `EngagementAuthority` from it.
`authority_from_scope` **fails closed on an empty scope** ("an authority that authorises nothing is
not useful, and an empty scope usually means a parse problem upstream").

Defaults are deliberately conservative: destructive actions **off**, a bounded validity window
(default 8 hours), a finite action budget (default 1000 actions in `vigil provision`; the model's
own default is 10,000). Live examples on disk: `targets/loopback/charter.md`,
`targets/testphp/charter.md`, `targets/testasp/charter.md`. A charter carries: in-scope host table,
operator attestation, hard limits, soft limits, stop conditions, and objectives.

A separate, additive charter section authorizes **cloud/Kubernetes** targets:
`## 2b. Cloud scope (Track B — cloud / Kubernetes)` — see `live/cloud_scope.py`. Track B authorizes by
**cloud-native identity, not URL host**, because "authorising the API endpoint `ec2.amazonaws.com`
must NOT authorise every AWS account that shares that endpoint." The tenant id must be named
**exactly**; "a wildcard / blank / `*` / `any` here authorises NOTHING."

### 3.2 The kill switch

`engine/crucible/framework/v2/authority/killswitch.py`. A file on disk, per engagement. Tripping it
writes the file; the gate refuses every action while it exists, so **a tripped switch survives a
process crash or restart**. Clearing is a separate, explicit, logged operator act.

Fail-closed detail worth quoting: `is_tripped()` returns **True (halted) unless the switch file can be
positively determined to be absent**. `Path.is_file()` swallows every `OSError` and would report
`False` — "the opposite of what a fail-closed hard stop must do" — so only `ENOENT`/`ENOTDIR`/
`ENAMETOOLONG` count as genuinely absent; permission denied, symlink loop, or I/O error all read as
**tripped**.

### 3.3 The authority gate (CRUCIBLE half)

`engine/crucible/framework/v2/authority/gate.py`. First failure wins, fail-closed throughout:

1. kill-switch tripped → HALTED (checked first, the absolute stop)
2. outside the time window → EXPIRED
3. target out of scope → denied (`out_of_scope`)
4. destructive and not permitted → denied (`destructive`)
5. destructive on a LIVE target without a second acknowledgement → denied (`live_destructive`)
6. action budget exhausted → denied (`budget`)
7. otherwise → allowed

### 3.4 WARDEN permission tiers A0–A3

`packages/core/vigil_core/vigil_core/warden_tiers.py` — "the ONE classifier of record," a
**byte-faithful Python port of the Rust WARDEN kernel classifier** (`apps/sigil/kernel/src/tiers.rs`).
Both sides are pinned to a shared golden vector set (`warden_golden.json`) loaded by *both* the Python
tests and the Rust unit test, "so they cannot silently drift."

| Tier | Meaning | Gate decision (`gate()`) |
|---|---|---|
| **A0** | Known-safe observe/answer verbs only, via a **positive allowlist** (`read`, `search`, `query`, `get`, `list`, `status`, `view`, `inspect`, …) | auto |
| **A1** | Reversible internal writes (draft, note, report, commit, branch, tag, …) | auto |
| **A2** | External-visible / semi-reversible: communication, publishing, bulk data egress (`send`, `email`, `publish`, `post`, `upload`, `export`, `dump`, `download`, `sync`, …) | queued |
| **A3** | Destructive verbs, financial ops, crypto/restore ops, **and dangerous targets** — secret/credential/token/key/iam/policy/firewall/role/grant/prod/root/admin/vault material is A3 *regardless of the verb* | explicit-required |

Mechanics: **token-based, never substring** (split on `.`/`_`/`-`/`/`/whitespace, so "overwrite" is not
"write" and "forget" is not "get"). **Danger is checked first.** Anything not positively classified —
unknown, empty, or dangerous-target — is **A3**. The tokenizer also splits on the C0 information
separators so a hidden control character cannot smuggle a danger token past classification
(`read.log\x1cdelete` → A3); the docstring notes danger exposure is **monotone**.

Offense-side application (`integration/vigil_integration/live/wiring.py`):
- `default_classify` derives danger from the shared classifier. A curated, danger-free recon name
  (`nmap`, `httpx`, `nuclei`, `ffuf`, `curl`, `subfinder`, `gau`, `katana`) stays auto-eligible **A1**;
  everything else is **A2**; anything carrying a danger token is **A3**.
- `EngineConfig.offense_ceiling` defaults to **`"A1"`**. Because the ceiling is A1, anything classified
  A2 or A3 **queues for owner approval and can never auto-run**.
- `DEFAULT_TOOL_VIEW` is a **tool→phase manifest**: an unlisted tool is DENIED in a phase.
  (`nmap`/`httpx`/`nuclei`/`ffuf`/`curl` → informational + exploitation; `sqlmap`/`hydra` →
  exploitation + post_exploitation; `terminal.run` and `sandbox.exec` → all three.)
- `DEFAULT_DESTRUCTIVE_VIEW = {"sqlmap": True, "hydra": True, "metasploit": True}` — the operator
  manifest that is authoritative for the m-of-n threshold-destruction leg.

`integration/vigil_integration/warden_gate.py` additionally imposes a **raise-only floor** (default A2)
— it can only ever raise a tool's tier, never lower it — because read-shaped offense names such as
`http.get` would otherwise classify A0 and auto-run.

### 3.5 The conjunctive gate of record

`packages/core/vigil_core/vigil_core/gate.py` → `conjunctive_decide`. Lives in the shared neutral core
so both processes import the *same* primitive. An action runs only if **all** conjuncts hold:

1. the domain (CRUCIBLE) authority is in-envelope — its kill-switch step is the absolute stop;
2. the WARDEN tool tier returns exactly `"auto"`;
3. **for a destructive action only** — an owner-inclusive m-of-n threshold authorization is present.

Fail-closed invariants pinned by `tests/test_gate.py`: a raised conjunct → DENY; **a strict
`authorized is True` identity check** on the destructive conjunct, so "a truthy-but-not-`True` value
must NOT open an irreversible action"; an unrecognised WARDEN outcome → DENY; a missing destruction
gate on a destructive action → DENY. Only an explicit `"auto"` may open the gate.

Verdicts are `allow` / `queue` / `deny`. Offense wiring: `integration/vigil_integration/conjunctive_gate.py`
→ `build_offense_gate`, which cross-binds `(slug, target_url)` to the quorum-signed action's
target/engagement, else DENY (`docs/AS-BUILT.md` §3).

### 3.6 The approval queue

Two modes, both real:

- **Standing approval (lower assurance):** `--approve-offense` / `--approve`. One boolean that
  blanket-approves every queued action for the run. The code says so explicitly.
- **Per-action, single-use, owner-signed token (the default for offense tools):**
  `live/approval_token.py` + `live/approval_broker.py`. Properties, all fail-closed:
  1. **Action binding** — the token names the exact `(tool_name, target, action_digest)`; it cannot be
     replayed to authorize a different action.
  2. **Pinned owner key** — verified against the owner public key in the immutable, deployment-time
     `ApprovalAuthority`; the token's `key_id` must equal the authority's. Deliberately *not* a
     per-call string, because "a per-call `key_id` could be renamed to a compromised worker's own
     registered id."
  3. **Dead-man's-switch** — bounded window, policy-capped lifetime. A pre-signed long-lived "sleeper"
     token is void.
  4. **Single-use** — atomic check-and-burn via `nonce_ledger.NonceLedger`, whose `O_EXCL` create is
     the serialization point: of N concurrent callers of the same token, exactly one wins. The burn
     happens **only after** signature + binding + window all pass, so an invalid token cannot
     grief-burn a victim's nonce.

Transport (`approval_broker.py`): the offense worker publishes a **public-safe, redacted** pending
request to `<base>/approvals/pending/<id>.json`; the sovereign signer (the only holder of the owner
private key) writes the signed token to `<base>/approvals/signed/<id>.json`. Critically: **a token
never widens scope** — it only satisfies the WARDEN human leg for an action the CRUCIBLE gate already
put in-envelope (`queue`). A CRUCIBLE `deny` stays `deny`, untouched.

CLI: `vigil approve provision-authority` (prints the owner private key **once**, never stores it),
`vigil approve list`, `vigil approve sign --request-id <id>` (key read from `VIGIL_APPROVAL_OWNER_KEY`,
never argv).

**Strix shell gating — note a doc/code discrepancy.** `warden_gate.attach_from_env` is documented and
implemented as **ON BY DEFAULT** ("the gate is default-ON, not opt-in", `vendor/strix/strix/core/runner.py`);
the explicit opt-*out* is `VIGIL_WARDEN_STRIX_GATE ∈ {0,off,false,no}`. Strix's arbitrary
`exec_command` / `write_stdin` shell is the queued chokepoint (floor A0, ceiling A1), routed to the
per-action approval broker; every other sandbox-contained Strix tool auto-runs. **`docs/AS-BUILT.md`
§2.1 row T3 is stale** — it says "*gateable*, **not** gated by default." The code and the
`AS-BUILT.md` §"What's assured now" bullet (#178) agree it is default-on. Writers should follow the
code.

### 3.7 The threshold-destruction gate (m-of-n)

`integration/vigil_integration/destruction_gate.py`. "The highest-consequence gate in the system."
Five properties, all fail-closed:

1. **m-of-n threshold** via `vigil_core.verify_threshold` over distinct trusted authorizers. The
   docstring is precise about scope: this delivers the RFC-9591 *m-of-n authorization* property; true
   FROST single-signature aggregation is a size/verification refinement, deferred, and does **not**
   change the security property.
2. **Mandatory owner** — the mandatory signer set is bound into the immutable deployment-time
   `DestructionAuthority`, not a per-call string, because the worker is itself a registered authorizer
   and a free `owner_key_id` would let it self-authorize. A worker+policy quorum without the owner
   authorizes nothing.
3. **Action binding** — `(engagement, target, blast_class, action_id)`. Stated honest limit:
   `action_id` is opaque to the gate; binding it to the real command depends on the signer computing
   `action_id = digest(command)` and the executor re-deriving it. "The gate never sees the command and
   cannot enforce that."
4. **Dead-man's-switch** — policy-capped window; a long-lived pre-signed sleeper is void.
5. **Single-use** — `consume_authorization` is the atomic check-and-burn (`O_EXCL` marker is the single
   serialization point); `authorize_destruction` is the pure check that requires a caller-supplied
   `is_consumed` (no permissive default).

CLI: `vigil provision-destruction` (mints the quorum; prints each signer's private key once and
explicitly does not store it; warns that with threshold=1 whoever holds the owner key can authorize),
then `vigil authorize-destruction` (signs one action; owner key from `VIGIL_DESTRUCTION_OWNER_KEY` env,
never argv; total window capped at a 900 s dead-man's-switch; output written `0600`).

**Honest note recorded in `docs/FEATURES.md`:** `vigil authorize-destruction` writes with
`O_CREAT|O_TRUNC`, **not** `O_EXCL` — it overwrites any prior file at that path. Single-use is enforced
downstream by the nonce ledger the PR leg checks, not by this open. (This correction was caught by the
repo's own adversarial honesty pass.)

### 3.8 The destructive path in practice: `vigil patch`

The only destructive leg wired today is opening a pull request. Every leg is an explicit opt-in; with
all off, the run is a **non-destructive propose-only dry run**.

- The finding source must be **provenance-grounded**: exactly one of a signed inert envelope
  (m-of-n verified under an owner-signed delegation) **or** a fact rebuilt from the signed spine after
  a fail-closed integrity audit. "**A raw-JSON finding is never accepted.**"
- `--apply-edits` applies the fix into a **disposable clone** and sandbox-builds it; the source tree is
  never touched.
- `--open-pr` is **OFF by default** and requires all of: a signed authorization, an authority trust
  root, ≥1 mandatory signer including the owner, the durable single-use nonce ledger, and a
  `GITHUB_TOKEN` in the environment.

**Status: BUILT — NOT LIVE-FIRED.** Per project memory and the code's own framing, live fire of the
destructive PR leg requires the operator to provision m-of-n keys.

---

## 4. Signing, keys, and offline third-party verification

### 4.1 Primitives

`packages/core/vigil_core/vigil_core/crypto.py`. Ed25519 via pyca `cryptography` — "We do not roll our
own crypto." Signing helpers are **provisioning-only; the runtime only ever verifies.**
`load_public_key` **rejects non-canonical (`y ≥ p`) and low-order Ed25519 public keys**, which closes a
keyless forgery (`R=identity, S=0` verifies for any message) against *every* threshold check
(`docs/AS-BUILT.md` §2). That fix came out of a four-level-deep adversarial review.

Canonical JSON + **domain-separated** signing bytes (`vigil_core/canonical.py`,
`evidence/canonical.py`; e.g. `crucible-evidence-v1\0`, `vigil-transparency-checkpoint-v1\0`) so a
signature cannot be lifted across contexts.

### 4.2 What holds which key

- **Sovereign side (SIGIL, `apps/sigil`)** holds the **owner key**. It is the only party that signs
  approvals and owner delegations.
- **Offense side is keyless with respect to owner authority.** It holds its own *stable* identities:
  a spine signing key (`live/spine_identity.py`, `SPINE_KEY_ID`) and a governance key
  (`live/governance_identity.py`, `DEFAULT_KEY_ID = "root0"`), both persisted `0600` and sealed at rest
  when a vault is provisioned (`vigil_core/keystore.py` — one shared load-or-create implementation,
  weak-key rejection, priv/pub round-trip validation, and **fail-closed on a sealed-but-unopenable
  file: it never silently mints a new divergent identity**).
- `vigil identity` exports **only public keys** ("never a private key crosses") for the owner to bless
  via the sovereign `sigil delegate-offense` ceremony. The command warns that the file must move over
  an **authenticated channel**, because a swapped file would get an attacker's key owner-blessed.

### 4.3 What gets signed

- Every **evidence certificate** over an oracle-confirmed finding (`evidence/certify.py`).
- The **hash chain** and a **signed chain head** binding the whole certificate set.
- The **usage-attestation ledger** (`attestation/ledger.py`) — who/when/what, replayed by
  `vigil ledger who|when`, verified by `vigil verify-ledger`.
- **Execution records** (`ExecRecord`) from the governed terminal and sandbox tiers — signed and
  redacted.
- **Transparency checkpoints** (`transparency.py`), **witness co-signatures** (`witness_service.py`),
  **remediation / posture / authority-envelope certificates**, **dossier manifests**, and
  **SCITT/OpenVEX DSSE statements** (`scitt.py`).

### 4.4 The four things `verify_certificate` checks

`evidence/certify.py` — "a certificate is sound only if all hold":

1. **Authenticity** — an m-of-n governance signature over the certificate's canonical bytes.
2. **Binding** — `oracle_context_digest` matches the sha256 of the oracle context presented, "so the
   signature cannot be lifted onto different evidence."
3. **Artifact integrity** — every raw file in the manifest still hashes to its recorded digest.
4. **Reproduction** — the pure oracle **re-fires** over the oracle context and matches the claimed
   verdict.

`trust_root_fingerprint()` is the out-of-band anchor: "the verifier compares this against a value the
operator publishes OUT-OF-BAND — that comparison, **not** the copy of `trust-root.json` shipped
alongside a bundle, is what anchors authenticity."

### 4.5 Offline third-party verification (no VIGIL installed)

Three artefacts, in increasing scope:

- **`vigil proof-export`** → a client-verifiable proof bundle. Only the **public** trust root is
  written. The command prints a trust-root fingerprint to publish out of band; the client pins it with
  `--trust-root-fingerprint` so a bundle re-signed under another key is refused.
- **`vigil dossier`** → one self-contained, tamper-evident `.zip`: three human reports, JSON/SARIF
  exports, the offline proof bundle, the secret-scrubbed engagement log, the governance-signed spine
  chain, any drift record, an `index.html`, and a `MANIFEST.json` of sha256s. Deterministic (omit
  `--timestamp` for byte reproducibility) and path-safe (every entry confined, symlinks never
  followed). Output is honestly labelled **SIGNED** or **UNSIGNED**.
- **Standalone verifiers under `docs/proof-carrying-finding/`** — these are the strongest claim in the
  system and their limits are stated in their own docstrings:
  - `verify_pcf.py` — imports **no** VIGIL code (not `framework`, not `vigil_core`, not
    `vigil_integration`, not `strix`); stdlib + one Ed25519 library, re-implemented from the published
    wire spec (`SPEC.md` + `schemas/`). Proves offline, with no target and no network: fingerprint
    (out-of-band pin), authenticity (m-of-n Ed25519), binding, artifact integrity, and chain
    (hash chain + signed head + anti-rollback high-water). **What it does NOT do: re-run the oracle.**
    Reproduction is framework-specific and needs `python -m framework.v2 evidence verify`. Exit 0 iff
    SOUND, 2 if NOT SOUND, 3 on usage/IO error. "Verification only — this file contains no offensive
    capability."
  - `verify_vf.py` — the negative/continuous counterpart: re-derives the whole remediation lifecycle
    (`vulnerable → proven-fixed → still-proven`, witnessed no-later-than *T*) with zero VIGIL code. A
    differential test (`integration/tests/test_vf_differential.py`) proves it agrees byte-for-byte with
    the in-tree verifiers on real artifacts and on a battery of tampers.

### 4.6 Keys at rest

`vigil_core/vault.py` + `vigil_core/kek.py`. A 32-byte KEK wraps every at-rest secret and private key,
and its custody is **TPM-sealed** (owner hierarchy) so the sealed blob is useless on another machine.
Explicitly opt-in and non-bricking: until `Vault.provision` is run, the vault is **disabled** and reads
and writes are exactly the prior plaintext behaviour, with a loud "unsealed" status surfaced. Once
provisioned, a legacy plaintext file **migrates non-destructively** — the sealed copy is verified to
round-trip *before* the plaintext is replaced. If the TPM later cannot unseal, sealed reads fail
**closed** (`VaultLocked`) — "never a silent plaintext fallback." There is no silent plaintext fallback
in `kek.py` either.

`docs/DEPLOY.md` is honest about the no-TPM case: "keys are **plaintext at rest**. That is acceptable
on a trusted single-user box. On a shared or web-hosted host, install `tpm2-tools` (or use a vTPM)…
Bootstrap prints a loud warning; it never silently degrades confidentiality without telling you."

Status: **WORKING** with a real TPM (the live path activates once `tpm2-tools` is installed and the
user can reach `/dev/tpmrm0`); the TPM is reached through an injectable runner seam, so the whole vault
is unit-tested deterministically with a fake TPM.

### 4.7 Anti-rollback

`vigil_core/highwater.py` — a durable, file-backed monotonic floor storing
`{entry_count, last_seq}`. `entry_count` is the **primary** guard because `last_seq` is 0-indexed and
reads 0 for both an empty chain and a one-record chain, so a 1→0 truncation would slip past a
`last_seq`-only check. A present-but-malformed floor **raises** rather than being read as absent,
because reading it as "no floor" would fail-open the whole guarantee.

**Its own stated honest limit, verbatim in intent:** this is a **local** floor — an unsigned `0600`
file. "A SAME-HOST attacker with the owner's UID (or root) defeats the local verify path by rewriting
the log AND this floor together." The real anti-rollback guarantee holds against (i) an attacker who
can overwrite the log but not the floor, and (ii) an out-of-band verifier that retained a newer floor.
"A fully-dishonest producer that rewrites everything is closed only by the out-of-band witness, not by
this file." What it gives unconditionally: last-writer-monotonic, downgrade-refusing, crash-safe
advance under a cross-process lock.

### 4.8 The transparency log and witnesses

`integration/vigil_integration/transparency.py` + `witness_service.py` +
`docs/proof-carrying-finding/WITNESS-TRUST.md`.

A **witness** independently checks that a new checkpoint consistently *extends* the prior one
(append-only: record count and `last_seq` only grow, and the checkpoint meta-chain links back), then
countersigns. An honest, stateful witness never equivocates.

**Split-view resistance is CONDITIONAL, and the repo insists on saying so.** It holds only for a
**strict majority** quorum (`2·threshold > n`) over `n` **distinct, canonical, non-low-order** keys
(`is_split_view_resistant`). Below strict majority — in particular `threshold == 1`, which the trust
model blesses — two disjoint quorums can each countersign a different fork **with no witness
equivocating**; only per-witness non-equivocation and *detection* remain. `verify_witnessed` proves *a*
quorum signed; `verify_split_view_resistant` proves the set is strict-majority.

`WITNESS-TRUST.md` is marked **"DRAFT — design, not a guarantee"** and states the assumption code
cannot enforce: "Distinct keys ≠ distinct operators. If the producer P holds all the witness keys, the
quorum is **theater**." It also states plainly that a witness does **not** attest that any finding is
true, that a remediation holds, or that an oracle fired — only **log-state continuity** plus a **time
bound**. "Conflating 'witnessed' with 'true' would be an overclaim."

`witness_service.py` is a deployable loopback witness co-sign **service** (A3): N independently-keyed
witness processes co-sign a real checkpoint series over the wire, and a third party can run one.
`bind_ok` refuses a public/unspecified bind. Every `POST /cosign` is fail-closed on three counts before
the tip is touched: a bounded, timed body read (413 on oversize, unread); an anti-CSRF/anti-DNS-rebind
guard (Host/Origin/`X-Requested-With`/Content-Type); and a **producer-pin gate** so an
unsigned/wrong-signed submission is rejected at the door and can never poison the tip.

**Honest status:** the transport and protocol are **WORKING**; genuine *independence* of witnesses is a
**deployment trust assumption**, not something the code can prove. Per project memory, third-party
independence for the witness/time-anchor legs remains an honestly-marked irreducible.

Deferred by name: OpenTimestamps Bitcoin anchoring of a checkpoint hash (needs a live calendar server);
full COSE_Sign1/CBOR encoding for SCITT.

An external **RFC 3161 time anchor** (A1) is implemented via the system `openssl ts`
(`integration/vigil_integration/time_anchor.py`); when a bundle carries one and a pinned TSA cert is
supplied (`--tsa-cert-pin`), its genTime **supersedes** the witness median, giving a
witness-honesty-independent "existed no later than T."

### 4.9 The Proof-of-Posture certificate (the sound negative)

`docs/POSTURE.md` + `integration/vigil_integration/posture/`. A `PostureCertificate` states, per
`(surface, parameter, vuln-class)`: **CLOSED** (an applicable deterministic oracle had a live channel
to the real target and did not fire), **OPEN** (an oracle fired), or **UNPROVEN**.

Two verification tiers, both shipped: `binding` (re-check the m-of-n signature, the out-of-band
fingerprint pin, the coverage-projection binding, and the owner target-binding — offline, no VIGIL) and
`re-executable` (the certificate embeds each clean probe's JSON-AST predicate and the observed evidence;
the standalone verifier re-derives the verdict without trusting the producer's asserted verdict).

**The honest boundary is stated as a feature, not a footnote:** CLOSED means non-exploitability *by the
oracle family, over the reached surface, as of the freshness bound* — never "secure against everything."
Undiscovered endpoints are out of the denominator. And for **both** tiers: "the retained values are
still **producer-supplied** — re-execution proves the verdict↔evidence binding, NOT that the evidence
reflects the live target."

---

## 5. Network safety: egress, TLS, sandboxing

### 5.1 The egress denylist — the single source of truth

`gateway/vigil_gateway/denylist.py`, described as "the L3/L4 conscience of the gateway." Two tiers:

- **HARD DENY (charter-independent, never liftable).** `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`
  (**includes `169.254.169.254`, cloud instance metadata**), `192.0.0.0/24`, the three TEST-NET blocks,
  `198.18.0.0/15`, `192.88.99.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, and the IPv6 equivalents. The
  rationale is explicit: "A charter can NOT re-enable these; they are denied even if an operator lists
  them, because a listing is far more likely to be an injection or a mistake than a real intent to let
  the agent read the host's cloud credentials."
- **PRIVATE (conditional).** RFC1918 / CGNAT / IPv6 ULA — denied **unless** the exact resolved IP is in
  the charter-authorized allowlist.

Embedded-IPv4 forms are unwrapped and re-checked under the v4 rules (IPv4-mapped `::ffff:a.b.c.d`,
6to4 `2002::/16`, NAT64 `64:ff9b::/96`) "otherwise `::ffff:169.254.169.254` would slip past a naive
v6-only check." The module is pure and deterministic — no DNS, no I/O, no clock — and is imported by
*both* the nftables renderer and the forward proxy.

### 5.2 Two enforcement layers

- **L3/L4 — nftables** (`gateway/vigil_gateway/nftables.py`): "the layer a prompt-injected agent cannot
  argue with." From the sandbox subnet, DROP everything except two destinations: the gateway's forward
  proxy and the gateway's DNS resolver. "There is no direct route to the internet, so unsetting the
  in-sandbox proxy env (which the agent can do) buys nothing: the packets are dropped at the host." The
  metadata/link-local/reserved ranges are hard-denied explicitly, including on the gateway's own OUTPUT
  path, "so even a bug in the proxy cannot reach 169.254.169.254." The forward hook uses `policy accept`
  and only *jumps* sandbox-sourced traffic into the deny-default chain, so co-tenant containers are
  untouched. The container's `NET_ADMIN` capability is dropped so it cannot rewrite even its own rules.
- **L7 — the filtering forward proxy** (`gateway/vigil_gateway/proxy.py`): runs **outside the sandbox's
  control**, unlike Strix's in-sandbox Caido proxy "which the agent can reconfigure or bypass." The
  security decision is the pure, unit-testable `authorize()`: (1) destination host must be in charter
  scope; (2) the host is resolved **once** and if **any** resolved address is on the denylist the whole
  connection is refused — "refusing on *any* bad answer defeats a DNS-rebinding response that mixes a
  public and an internal address"; (3) the connection is pinned to the exact validated IP and never
  re-resolved, closing the resolve-then-connect TOCTOU. Fail-closed everywhere. Refusals are logged "so
  the operator can correlate them (OBSIDIAN opsec: the agent is correlatable, not stealthy)."

Gateway configuration (`gateway/vigil_gateway/config.py`, all env-driven): proxy binds `127.0.0.1:48081`
by default; destination port allowlist defaults to `80,443,8080,8443`; 10 s header timeout (slow-loris
cap); 256 concurrent connection cap (503 beyond); sandbox subnet `172.31.240.0/24`.

### 5.3 The app-layer egress guard in the live executor

`live/executor.py` → `_resolve_scoped_target`. Total and fail-closed — any parse/resolve failure,
malformed port, or unresolvable host returns a refusal. Two modes:

- **Default (`scope is None`)** — legacy loopback-only: refuse unless every resolved address is IPv4
  loopback `127.0.0.0/8`. IPv6 `::1` is refused. "The fail-closed default stays loopback, never wider."
- **Scoped (production, threaded from the signed authority)** — the host must be in the
  **signature-verified** authority scope **and** every resolved IP must clear the egress floor; then the
  **exact resolved IP is pinned** (resolve-once-pin-exact-IP = TOCTOU/DNS-rebind defence). "Loopback is
  reachable ONLY when the signed scope authorises it; the metadata/link-local/reserved floor is never
  liftable by any scope."

Note: `--scope` accepts comma-separated literal hosts and `*.wildcards`, **no CIDR**.

### 5.4 TLS handling

`engine/crucible/framework/v2/verify/tls.py`. VIGIL negotiates its **own** bounded TLS handshake (one
attempt, hard timeout) through the same audited active-connect gate as reachability, and judges the
retained `(protocol, cipher)` with the pure `tls_weakness_oracle`. Because the evidence is JSON-safe, a
confirmed weakness **re-verifies offline** from its certificate with no network.

**Certificate validation is intentionally disabled** (`check_hostname = False`, `verify_mode =
CERT_NONE`) — and the reason is documented: "this is a crypto-POSTURE probe of what a standard client
negotiates, not a trust check, so it must work against self-signed / internal endpoints." Under
`CERT_NONE` the presented leaf DER is still retrieved and judged by the weak-crypto oracle (e.g. a
broken-hash signature). `tls_spki_sha256()` gives a stable observed-key fingerprint that survives
reissuance and changes the moment the key changes — "a sound *observed-key* identity for a target
(stronger than a producer-asserted host string)."

Elsewhere TLS verification is required rather than disabled: the IMDS runner's transport must report
"TLS verification on", proxies disabled, redirects disabled, and the oracle *requires* a validated TLS
peer with no proxy/redirect before it will confirm.

### 5.5 Sandboxing — bubblewrap

`integration/vigil_integration/live/sandbox_exec.py`. Two safety floors enforced by **kernel isolation,
not an allowlist**:

- **No egress** — the network namespace is unshared, so DNS fails and every connect fails.
- **No write outside the workspace** — only a minimal set of program/library/config dirs is mounted
  read-only; the only writable paths are the bound workspace dir and an ephemeral `/tmp`.

The docstring records a merge-blocking red-pen finding and why the obvious approach was rejected:
**not** `--ro-bind / /`, because a wholesale root bind carries the host `/run` — and every host daemon
socket in it (`/run/docker.sock` = host-root-equivalent, system/session D-Bus) — into the box. "Unix-
domain sockets live in the MOUNT namespace, so `--unshare-net` does NOT isolate them." So only specific
read paths are bound: no `/run`, no `/home`, no `/var`.

Two residuals are documented as reviewed and **not** escapes: (1) `--ro-bind /etc /etc` exposes host
`/etc` read-only (glibc/NSS needs it) — minor config disclosure, `/etc/shadow` is mode-640 and
unreadable to the box user, and there is no egress to exfiltrate it; (2) a host-side attacker racing
the workspace path (classic TOCTOU) is out of the in-sandbox threat model.

Also: `--die-with-parent` (no orphan), `--new-session` (no TIOCSTI terminal injection), time-boxed and
output-capped. **Fail-closed: a missing or unusable `bwrap` REFUSES to run — there is deliberately no
fallback to an un-sandboxed exec.** Reached by `vigil sandbox`, classified **A3** → queues under the A1
ceiling.

### 5.6 The governed local terminal (the un-sandboxed tier)

`live/executor.py` → `execute_terminal`, reached by `vigil terminal`. Safe by **construction** rather
than isolation: no shell (argv list, `shell=False`; any shell metacharacter refuses the whole command),
allowlist-validated to local read/print binaries only (`ls cat head tail wc stat pwd whoami id uname
echo df du ps uptime grep cut tr`; `find` only via a read-only *predicate* allowlist; `date`/`hostname`
bare-only). It "can **neither egress, write files, nor spawn an interpreter — by construction**." The
test suite includes a hostile battery covering network binaries, interpreters, writers, metacharacters,
unsafe `find` predicates, and coreutils option-abbreviation bypasses (`sort --compress=curl`, `--out=`).
Classified **A2** → queues under the A1 ceiling; a successful run writes a signed, redacted `ExecRecord`.

### 5.7 Binding and UI network posture

- The offense console **binds loopback only** — `serve()` raises `ValueError` on any non-loopback host
  (`console/server.py`). CSRF/anti-rebind guard via a required `X-Requested-With` header.
- The gated offense API (`api/authn.py`) opts in to a shared-secret gate via `CRUCIBLE_API_KEY`
  (`Authorization: Bearer <key>` or `X-Relay-Key`), **stacked on top of** the loopback bind.
- `vigil up` refuses a public bind up front (`uiproxy.bind_ok`): loopback, IPv4 RFC1918 or
  Tailscale-CGNAT `100.64.0.0/10`, or IPv6 ULA `fc00::/7` / link-local `fe80::/10` only — never
  `0.0.0.0`, `::`, or a globally-routable address. IPv6 uses a **positive allowlist** "because Python
  mislabels Teredo/6to4 as private."
- A `--domain` deployment with `CRUCIBLE_API_KEY` unset and no `--insecure-no-api-key` is **REFUSED**,
  so the gated offense API is never internet-exposed unauthenticated.
- The reverse proxy is the only human-facing listener: strict same-origin CSP, `X-Content-Type-Options:
  nosniff`, `Referrer-Policy: no-referrer`, 16 MiB request-body cap (413 beyond), no traversal out of
  the serve dir, and `?token=` redacted from access logs. Serve dir is `0700`; the token-bearing
  `index.html` is `0600`.
- `docs/DEPLOY.md`: "VIGIL never binds a public interface." Remote access is a tunnel + reverse proxy
  (WireGuard/Tailscale + Caddy/nginx templates), with the domain added to an anti-rebind allowlist.

### 5.8 The two-process boundary (relevant to every item above)

`docs/AS-BUILT.md` §1: one monorepo, one CLI, one signed spine, **two isolated process/trust domains**
joined only by an inert, signed, no-code data seam. `packages/core/vigil_core` imports neither
`framework.*` nor `strix.*`. **env-sovereign** = `vigil_core` + SIGIL (offense-free by construction);
**env-offense** = `vigil_core` + CRUCIBLE + Strix + the gateway. Subsystem routing
(`integration/vigil_integration/dispatch.py`) is a hardcoded verb→environment table — `sigil` →
`.venv-sovereign/bin/sigil`; `crucible`, `aegis`, `strix`, `gateway` → `.venv-offense/bin/…` — so
"an offense verb can never resolve into the sovereign venv or vice-versa. This is the FATAL-2 boundary:
routing is by construction, not inspection."

---

## 6. Cloud and Kubernetes exploit confirmations — the E-series

**Status: COMPLETE and merged.** All six confirmations are wired end to end and proven with fixture
evidence **offline**. What remains deferred is *real-world live fire against third-party cloud
accounts*, which waits on the customer supplying their own cloud credentials. The detection logic,
the evidence handling, the certificates and the safety gates are all built and proven; only the act
of pointing them at a live third-party account is pending, **by design**.

Merge trail on `main`: #286 (E1 wiring), #288/#289 (E5 oracle + wiring), #290 (E4 Tier-1 wiring),
#291 (E3), #292 (E2), #293 (E4 Tier-2).

| # | Capability, in plain terms | Producer module | Evidence branch |
|---|---|---|---|
| **E1** | A machine's cloud metadata service handed out a credential, and that credential really worked. | `live/imds_runner.py` (the live capture) + `live/imds_verify.py` | `imds_credential_capture` |
| **E5** | A secret found lying exposed is a *valid, currently working* credential — not just a string that looks like one. | `live/secret_verify.py` | `cloud_exploit.secret.credential_validity` |
| **E3** | One Google Cloud service account can impersonate another — i.e. borrow its identity. | `live/gcp_impersonation_verify.py` | `cloud_exploit.gcp.sa_impersonation` |
| **E2** | An identity's permissions let it grant itself *more* permission than it started with (privilege escalation). | `live/iam_escalation_verify.py` | `cloud_exploit.iam.privilege_escalation` |
| **E4 Tier 1** | An **anonymous**, unauthenticated caller is bound to a dangerous built-in Kubernetes role (`cluster-admin` / `admin` / `edit`). | `live/k8s_rbac_verify.py` | `k8s_exploit.rbac.anonymous_privileged_binding` |
| **E4 Tier 2** | A Kubernetes role actually *grants* dangerous verbs, or a default service account holds them — proven by reading the role object's rules, not just its name. | `live/k8s_rbac_grant_verify.py` | `k8s_exploit.rbac.dangerous_verb_grant` |

### 6.1 The five properties every one of them shares

Verified across all six module docstrings — these are the safety and honesty invariants a national
agency reader should be told about:

1. **Inert on scan and engage.** None of these oracles is in the frozen `_ALL_ORACLES` fallback, so
   nothing on the scan / engage / benchmark path can mint one. The capability fires **only** when its
   producer is called explicitly over a runner capture. This is the no-auto-fire gate: an autonomous
   loop cannot wander into using a cloud credential.
2. **Exactly one sanctioned mint path.** Each routes the capture through its deterministic oracle,
   then through `verdict.admit(...)` against a *registered* evidence branch (a fired oracle over a
   fact-capable, precondition-holding branch is a FACT; anything else is a LEAD), and only then
   through `oracle_adapter.certify_admitted`. The rule is stated in every file: a sovereign `live/*`
   module must **never** call `build_certificate` / `confirm_and_certify` directly. Admission
   decides; minting merely executes.
3. **Secret-safe captures.** The plaintext credential is validated and fingerprinted (a
   domain-separated sha256) *in memory* and then **discarded**. Only a redacted structural record,
   the fingerprint, and non-secret provenance (resolved peer IPs, TLS-verified flags,
   no-proxy/no-redirect, a bounded response digest) are retained. **No live secret ever enters a
   capture or a certificate** — and yet the certificate still re-verifies offline. For the
   Kubernetes tiers the retained capture is secret-safe *by construction*: it carries only RBAC
   metadata (subject names, roleRef, rules/verbs/resources), never the bearer token or client
   certificate used to read the cluster.
4. **Gated and scoped before any network I/O.** Every live capture is authorized first (the WARDEN
   A2 floor + the kill-switch) and scoped to the signed charter's cloud scope (§3.1, Track B). An
   unauthorized or out-of-scope call **refuses before a single packet leaves**.
5. **Trusted transport, verified TLS.** The network reach is via an *injected* transport that must
   report the resolved peer, whether TLS was verified, and whether a proxy or redirect occurred. The
   oracle then *requires* that the metadata GET hit a metadata peer and the confirming call hit an
   allow-listed HTTPS endpoint with a validated TLS peer and no proxy or redirect. A hand-supplied
   record can never become a FACT, because the live proof of "where both calls went, and that the
   same credential authenticated both" originates only in the runner.

Both automatic downstream guarantees apply unchanged, because they are generic over any finding
carrying a retained `oracle_context`: a confirmed FACT **re-verifies offline** from its certificate
(the oracle re-fires — §4.4 item 4), and the retained context **re-executes under the veracity
firewall**.

### 6.2 The claim boundaries these capabilities state about themselves

Worth carrying into prose verbatim in spirit, because they are the difference between an honest
product and an impressive one:

- **E2 (IAM privilege escalation)** is a **capability over the retained configuration**: the identity
  policy, the permissions boundary, and the service-control policy together *permit* the escalation
  primitive. A resource-based policy not present in the capture — a KMS key policy, an S3 bucket
  policy, the target role's trust `Deny` — could still nullify it. The oracle's verdict and the
  branch limitation say exactly this. It is deliberately the **achieved strict-gain** claim, on its
  own evidence branch, distinct from the weaker "policy path reachability" half.
- **E4 Tier 1 vs Tier 2** are different strengths and are tracked separately. Tier 1 matches a
  dangerous built-in ClusterRole **by name**. Tier 2 is stronger: it reads the binding *and*,
  separately, the Role/ClusterRole the `roleRef` names — because "a `roleRef` is only a NAME; the
  rules live in a distinct object" — and adjudicates the actual verbs granted.

### 6.3 What "live fire" would add, and why it is deferred

The transport in each producer is **injected**, which is what makes the module unit-testable with a
mock and makes the offline proof real. Each module states the remaining step in its own words — for
example: *"Real-transport LIVE-FIRE (running the impersonation runner against real GCP endpoints) is
deferred on an operator-provisioned credential"*, and the E1 runner: *"its live-fire is a thin
real-transport binding (httpx with proxies disabled + redirects disabled + TLS verification on),
deferred until an authorized lab credential is available."*

So the honest sentence for any audience is: **the logic, the evidence handling, the certificates and
the safety gates are built and proven offline; pointing them at a live third-party cloud account
awaits that customer's own credentials.** Nothing about the mechanism is unfinished — a credential
is a thing only the account owner can supply, and the system is designed not to acquire one any
other way.

Related but distinct, and already covered elsewhere in this document: the cloud **posture**
collectors (§2.1, §9) and the cloud **scope** gate (§3.1) — the gate is what makes a live-fire run
authorizable at all, because it authorizes by cloud-native identity (provider + exact account /
project / subscription) rather than by API-endpoint hostname.

---

## 7. Build and release safeguards — the supply chain

**Status: IN FLIGHT — being delivered today (2026-08-12).** At the time of this pass the work lives
on branch `a14-supply-chain` in worktree `/home/kali/vigil-wt-a14` as uncommitted working-tree
changes. Writers must describe this as *being delivered*, not as long-merged. Everything below is
what I observed directly; two of the four components were not yet present and are marked so.

### 7.1 Why it is needed — the honest starting position on `main`

Three facts, read off `main`, that this work exists to close:

- `engine/crucible/framework/v2/requirements.lock.txt` is an explicitly self-labelled **skeleton, not
  a real lock**: *"This skeleton is intentionally NOT a real lock."* Generating one needs PyPI's JSON
  API, which sovereign-deployment hosts may legitimately firewall, so generation was left as a
  deliberate operator step on a network-permitted host.
- `engine/crucible/framework/v2/sbom.json` is marked `SCAFFOLD — operator regenerates with
  cyclonedx-bom`, with a placeholder timestamp.
- `.github/workflows/ci.yml` carries **no** dependency-vulnerability gate.

This is a good example of the project's own claim discipline working: the gaps were labelled in the
artifacts themselves rather than papered over, and the fix is to build the capability up.

### 7.2 Dependency hash-locking

`infra/supply-chain/sovereign.in` — a new source spec for the **sovereign** environment, compiled to
a hash-pinned `sovereign.lock.txt` and installed with `pip install --require-hashes`. The
regeneration command is recorded in the file itself (`pip-tools==7.6.1`, `pip-compile
--generate-hashes --no-header --strip-extras`, Python 3.13 — the lock is Python-minor specific, and
`--no-header` keeps the output byte-comparable so CI can detect drift).

Two design points worth carrying:
- **The scope comment encodes the offense-free invariant**: nothing in this lock may drag in
  `framework.*` (CRUCIBLE) or `strix.*`, and "that absence is what makes
  `sigil.reuse.assert_no_offense()` hold by construction." The three first-party members are
  installed from the tree with `-e` and carry no registry hash.
- **Deliberate non-scope, stated rather than hidden**: SIGIL's optional extras (voice, secrets,
  capture, dev) are *not* locked, because they are lazy-imported, degrade gracefully, and are not
  part of the default deployed surface — locking them would pin a large optional tree no default
  install pulls. Dev extras are CI tooling, pinned in the workflow itself.

`engine/crucible/framework/v2/requirements.in` gains `packaging>=23` — a genuine runtime dependency
(used by the `VERSION_RANGE` fact family for version comparison) that both `pyproject.toml` files
declared and every CI job installed, but which was absent from the spec, so it was the one runtime
dependency the lock could never pin.

### 7.3 Container base-image pinning

`infra/supply-chain/image_pins.py` — the single source of truth for one rule, stated plainly in its
docstring: **a container tag is a mutable pointer.** `FROM python:3.13-slim` means "whatever the
registry serves at pull time", so a retag — benign or hostile — silently changes what ships, "with
no diff, no review and no signal." A digest (`@sha256:…`) is content-addressed: the daemon verifies
it or the pull fails. The module is **stdlib-only**, "so it runs in any job without adding a
dependency to the thing it is auditing."

Three consumers, by design:
1. an offline test (`integration/tests/test_supply_chain.py`) asserting every base image in the repo
   is digest-pinned;
2. `python3 infra/supply-chain/image_pins.py --check` — the same assertion as a CLI, for the CI gate;
3. `--drift` — the **only** networked mode, which re-resolves each pinned tag against the registry
   and reports where upstream has moved on. It is **advisory by design and exits 0**, because
   "upstream retagging is not the fault of the PR being tested, so it must not turn a contributor's
   build red." That is a thoughtful distinction between *a gate* and *a report*.

Exemptions are written as rules, not holes: `FROM scratch` has no content to pin (it is the empty
base), and first-party images built from this repo (`vigil-gateway`, `vigil/*`) have no upstream
digest because their provenance is the tree itself.

Pins applied so far (observed in the worktree diff):
- `gateway/Dockerfile` → `python:3.13-slim@sha256:ffb752e1…` as the **default** build-arg. The
  comment is careful: overriding `--build-arg PYTHON_BASE=<unpinned>` remains possible and is the
  operator's call; "the committed default is what CI and `vigil services up` actually build, and
  that is pinned."
- `engine/crucible/framework/v2/aegis/Dockerfile`, two eval-corpus Dockerfiles, and
  `vendor/strix/containers/Dockerfile`.
- `docker-compose.yml` → `qdrant/qdrant:v1.19.0@sha256:…`, `neo4j:5-community@sha256:…`,
  `otel/opentelemetry-collector:0.158.0@sha256:…`. Notably the previous
  `${QDRANT_VERSION:-latest}` / `${OTEL_VERSION:-latest}` indirections are **deliberately removed**:
  a floating `latest` behind an env var "is the exact drift this pinning exists to stop — it made
  `docker compose up` non-reproducible, and nothing in the repo ever set those vars." The pinned
  versions are recorded as byte-identical to what `:latest` resolved to on 2026-08-12, so it is a
  no-op for behaviour and a strict gain in reproducibility.
- `infra/supply-chain/resolve-image-digests.sh` re-pins them all.

### 7.4 Software bill of materials — **NOT VERIFIED at the time of this pass**

In scope for today's delivery, replacing the scaffold SBOM described in §7.1. I did **not** observe a
generated SBOM artifact in the worktree. Do not describe it as complete without re-checking.

### 7.5 Vulnerability gate blocking on CRITICAL — **NOT VERIFIED at the time of this pass**

In scope for today's delivery. The gate is *named* in the new file comments — the "A14 supply-chain
gate" CI job at `.github/workflows/supply-chain.yml`, plus a `docs/SUPPLY-CHAIN.md` — but neither
file existed in the worktree when I read it. Do not describe it as running without re-checking.

### 7.6 The existing CI, for context

`.github/workflows/ci.yml` on `main`, every job on Python 3.13, with required status checks enforced
on protected `main`: `vigil_core` migration safety (byte-identical v1 signing, threshold, tamper);
CRUCIBLE core (evidence, entitlement, verify, scanner predicates, authority, console/API federation,
AEGIS gate invariants, report, graph, attest, knowledge engine); the **gateway egress gate**,
including a real network-namespace nftables ruleset load; the two-environment boundary (inert
receiver, keyless worker, oracle adapter); the Strix Claude runtime; the SIGIL governor gates; **TLA+
formal model-checking** of four core invariants plus a caught mutant for each; and 30 `cargo test`s
over the Rust WARDEN kernel as its own required check.

Note the related but distinct capability, so writers do not conflate them: `live/sbom.py` is
VIGIL's **product** feature that reads a *target's* manifest against a pinned OSV snapshot to mint a
`VERSION_RANGE` fact (§1.3). Sections 7.2–7.5 are about securing **VIGIL's own** build. Same
subject matter, opposite direction.

---

## 8. Operator-facing command surface (for cross-reference)

Native `vigil` verbs (`integration/vigil_integration/cli.py`): `engage`, `engage-instruct`, `ledger`,
`verify-ledger`, `verify`, `provision`, `identity`, `patch`, `remediate`, `provision-destruction`,
`authorize-destruction`, `approve` (`provision-authority` | `list` | `sign`), `proof-export`, `dossier`,
`detect`, `up`, `services` (`up` | `status` | `down` | `render`), `doctor`, `telemetry`, `down`,
`knowledge` (`sync` | `push` | `status`), `learn-drain`, `terminal`, `sandbox`.

Passthrough verbs: `vigil sigil`, `vigil crucible`, `vigil aegis`, `vigil strix`, `vigil gateway`.

`vigil doctor` is a read-only, pure-stdlib preflight: prerequisites present, both venvs built, runtime
dirs writable, UI ports free (proxy 8770, cockpit 8733, console 8787, api 8799), and which Docker
services are up.

The CRUCIBLE arsenal behind `vigil crucible` exposes **28 subcommands** registered in an explicit
`_DISPATCH` table (`engine/crucible/framework/v2/__main__.py`) — including `verify`, `evidence`,
`drift`, `report`, `imports`, `mcp`, `api`, `console`, `capabilities`, and `status`. `main()` latches an
owner-only umask before anything writes to disk.

---

## 9. Consolidated honesty ledger — what is NOT yet live-fired

For downstream writers: these must never be presented as completed field deployments.

**Read the first two rows carefully — they changed with this revision.** The cloud and Kubernetes
*confirmations* are no longer "in progress"; all six are complete, merged, and proven offline (§6).
What is deferred is narrower and more precise than before: **the act of pointing them at a live
third-party cloud account, which requires that customer's own credentials.** Framing this as "the
capability is unfinished" would understate the system; framing it as "field-proven in customer
clouds" would overstate it. The accurate framing is: *built, gated, and proven offline — live fire
awaits operator-supplied credentials, by design.*

| Item | Status | Blocking dependency (as stated in-repo) |
|---|---|---|
| LLM red-team tools (garak / PyRIT / promptfoo) as fact sources | BUILT — NOT LIVE-FIRED | Tools absent from this environment; no network to install them. `DEFERRED-INFRA.md` §R4. |
| `DockerTopologyBackend` live container run | BUILT — NOT LIVE-FIRED | Docker + the `vigil_sandbox` network + a tool image present. |
| Live MCP client (speaking to an external MCP server) | BUILT (manifest/validation) — client seam pending | `tools/mcp_registry.py` docstring. |
| Destructive auto-patch PR leg (`vigil patch --open-pr`) | BUILT — NOT LIVE-FIRED | Operator must provision m-of-n quorum keys + `GITHUB_TOKEN`. |
| **The six E-series cloud / Kubernetes exploit confirmations** (metadata-credential capture, exposed-secret validity, GCP service-account impersonation, IAM privilege escalation, and both tiers of Kubernetes RBAC) | **COMPLETE and merged; wired end to end and proven with fixture evidence OFFLINE.** Real-world **live fire** is deferred. | The customer supplying their own cloud credentials. Every module says so in its own words, e.g. "Real-transport LIVE-FIRE … is deferred on an operator-provisioned credential." Detection logic, evidence handling, certificates and safety gates are all built and proven — see §6. |
| Cloud posture (AWS / Azure / GCP / K8s) live collectors | BUILT — awaiting operator credentials | Requires operator-supplied read-only credentials; all validated by live probes when present. |
| Supply-chain hardening: SBOM generation, and the CRITICAL-blocking vulnerability gate | **IN FLIGHT — being delivered today.** Dependency hash-locking and container base-image digest pinning were observed in the working tree; the SBOM artifact and the gate CI job were **not yet present** at the time of this pass. | Nothing external — this is in-flight engineering, not a blocked dependency. Re-check before publishing. See §7. |
| Running external Neo4j / OTLP service | Client body BUILT; deployment deferred | `DEFERRED-INFRA.md` G1 / `AS-BUILT.md` §8. The embedded file-backed graph store *is* built. |
| Hardware TEE attestation (SEV-SNP / TDX) | SCAFFOLD — stubs raise | Confidential-computing silicon. `SoftwareAttestationProvider` works today with `hardware_backed=False`; the auto-detect selector activates hardware only if detected **and** implemented. |
| General binary patch synthesis (a cyber-reasoning system) | SCAFFOLD — `synthesize_patch` raises | Research-gated. A narrow ASan-grounded crash-confirm + fix-by-silence path *is* built. |
| Next-gen agent body (Claude Agent SDK + in-process MCP) | SCAFFOLD — interface only | Needs `claude-agent-sdk` + a live Kali container. |
| OpenTimestamps Bitcoin anchoring of a checkpoint | Deferred | Needs a live calendar server. |
| Full COSE_Sign1 / CBOR SCITT encoding | Deferred | Current implementation uses the governance root + witnesses, described in-repo as stronger. |
| Independently-operated witness quorum | Protocol + deployable service WORKING; independence is a deployment assumption | "Distinct keys ≠ distinct operators" — `WITNESS-TRUST.md`, marked DRAFT. |
| Field record on diverse real targets (H3) | Mechanism BUILT; the record itself is not | Social/access-gated. `DEFERRED-INFRA.md` H3. |

### Known documentation drift found during this pass

1. **`docs/AS-BUILT.md` §2.1 row T3** says the Strix shell gate is "*gateable*, **not** gated by
   default." The code (`warden_gate.attach_from_env`, `vendor/strix/strix/core/runner.py`) and
   `AS-BUILT.md`'s own "What's assured now" bullet both say it is **default-ON with an explicit
   opt-out**. Follow the code.
2. **`docs/FEATURES.md`** declares "Coverage: 260+ features" and immediately labels it "a pre-2026-08
   lower bound." Do not cite it as a current count.
3. **`docs/capability-matrix/hexstrike.json`** says the upstream carries 79 distinct tools; the matrix
   itself carries 33 rows. The number that matters for any claim is **`fact_capable`, which is 2**.
4. **Two supply-chain artifacts on `main` are self-labelled placeholders** and must never be cited as
   evidence of a locked build: `engine/crucible/framework/v2/requirements.lock.txt` says of itself
   "This skeleton is intentionally NOT a real lock", and `engine/crucible/framework/v2/sbom.json`
   carries `crucible:sbom-status = SCAFFOLD` with a `0000-00-00` timestamp. The in-flight A14 work
   (§7) is what replaces them. Both files are honest about their own state — the drift would be a
   *reader* treating their presence as completion.
5. **`README.md` §"What's live vs. what's still deferred"** still describes the cloud-exploit work at
   the E1-only stage ("E1-Slice3 (#286)… Deferred: real-transport IMDS live-fire"). Since that text
   was written, E2, E3, E5 and both E4 tiers have merged (#288–#293). §6 above is current; the
   README row is stale in *scope* while remaining correct about the *nature* of the deferral.
