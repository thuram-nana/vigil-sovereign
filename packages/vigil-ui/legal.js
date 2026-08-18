"use strict";
/* ==========================================================================
   VIGIL COMMAND — legal.js : the in-product LEGAL pages (real documentation).
   Registered exactly like manual.js: a static data module (no runtime/target
   data, no fetch) that app.js renders on the `legal` screen.

   DOCTRINE: these pages SUMMARISE; the repository documents GOVERN. Every
   factual statement about behaviour below is true of the code on this branch
   and names the file it comes from, so it can be checked. Where a capability
   is designed but NOT shipped, that is said plainly rather than implied.
   Nothing here is legal advice.
   ========================================================================== */
window.VIGIL_LEGAL = {
  /* Shown once at the top of the screen, above every section. */
  preamble: "These four pages are a plain-language summary for the operator sitting at the console. "
    + "They are not legal advice, not a contract, and not a compliance claim. The governing texts are the "
    + "documents in the source tree, named at the end of each section; where a summary and a document "
    + "differ, the document controls.",

  sections: [
    /* ====================================================================== */
    {
      id: "acceptable-use", title: "Acceptable Use",
      lede: "One rule, and it is not negotiable.",
      blocks: [
        { rule: "Point VIGIL only at systems you own, or hold current, written authorization to test. "
          + "Authorization must exist BEFORE the first packet. “Just checking” is not authorization." },
        { p: "VIGIL is dual-use offensive tooling. Directing it at a system without authorization is a "
          + "criminal act in most jurisdictions — among others under the U.S. Computer Fraud and Abuse "
          + "Act, the U.K. Computer Misuse Act 1990, and EU Directive 2013/40/EU. You are responsible for "
          + "knowing the law that applies to you AND the law that applies where your target sits. Those are "
          + "often not the same law." },

        { h: "What the software actually enforces" },
        { p: "These are gates in the code, not promises in a document — but they constrain the tool, "
          + "not you. They cannot make an unauthorized test lawful." },
        { list: [
          ["Signed scope", "An engagement runs against a signed charter scope of exact hosts or *.wildcards. Anything outside it is refused. Scope is never widened silently."],
          ["Conjunctive gate", "Every target-touching action must clear authority (in scope, not halted, within budget) AND its WARDEN risk tier AND, if destructive, an m-of-n threshold sign-off. First failure wins; any error at all denies (integration/vigil_integration/conjunctive_gate.py)."],
          ["Approve-then-run", "Externally visible (A2) and destructive (A3) actions queue for your explicit approval, and auto-reject on a timeout. Silence is safe."],
          ["Usage ledger", "Every run is written to an append-only, hash-chained, Ed25519-signed attestation ledger that binds WHO to WHAT and WHEN. It refuses a record with no human handle, so the supported path cannot be run pseudonymously (integration/vigil_integration/attestation/)."],
        ] },

        { h: "What the software does NOT do" },
        { list: [
          ["It cannot validate your authorization", "The charter records your attestation that you are authorized. It does not verify it. A false attestation produces a signed record of a false attestation."],
          ["It cannot keep third-party data out of your evidence", "A captured response body is stored raw (see Privacy). Testing someone's production system means handling that system's users' personal data."],
          ["It does not make you anonymous", "The opposite: it is built to make you identifiable and correlatable to your own logs."],
        ] },

        { h: "Out of scope by default" },
        { p: "Third-party services your target depends on — payment processors, identity and email "
          + "providers, hosting, CDNs, upstream APIs — are not yours to test. You may test your client's "
          + "INTEGRATION with them (webhook handlers, callback URLs, key handling); you may not attack the "
          + "provider. If an in-scope bug can pivot to an out-of-scope system, document it and stop." },

        { note: "Governing law and forum are deliberately not settled here. They belong in TERMS.md and in "
          + "each client-signed instrument, completed by qualified counsel in the relevant jurisdictions. "
          + "Your jurisdiction and your client's may differ, and EU / UK / US law can reach an operator "
          + "located outside those territories." },

        { docs: [
          ["ACCEPTABLE-USE.md", "the authorized-use policy in full"],
          ["engine/crucible/DISCLAIMER.md", "the engine's own authorized-use policy, prohibited use, and limitation of liability"],
          ["TERMS.md", "terms of use, including the governing-law placeholder"],
        ] },
      ],
    },

    /* ====================================================================== */
    {
      id: "privacy", title: "Privacy",
      lede: "What this machine holds, and what can leave it.",
      blocks: [
        { rule: "Model egress is PERMISSIVE by default. Unless you set a sovereignty tier, prompt content "
          + "— which can include target data and findings, and therefore other people's personal data "
          + "— may be sent to a cloud model provider." },
        { p: "This is verifiable, not a caveat: with CRUCIBLE_SOVEREIGNTY_TIER unset, the policy resolves to "
          + "PERMISSIVE (“anything” — engine/crucible/framework/v2/kernel/sovereignty.py, "
          + "_resolve_tier_from_env), and bootstrap.sh writes ~/.sigil/sigil.env with every tier line "
          + "COMMENTED OUT. Any statement that VIGIL keeps everything local by default would be false." },
        { h: "How to set it — and which processes each mechanism actually reaches" },
        { p: "The tier is read from the process environment and from nowhere else (_resolve_tier_from_env, "
          + "engine/crucible/framework/v2/kernel/sovereignty.py). The three mechanisms below do NOT have the "
          + "same reach, and the third one fails OPEN." },
        { list: [
          ["(a) In the environment — always effective, highest precedence", "Export CRUCIBLE_SOVEREIGNTY_TIER in the shell, systemd unit or container that launches the process. AIR_GAPPED = local backends only (Ollama / vLLM / llama-cpp / TGI). SOVEREIGN_CLOUD adds jurisdictional cloud (Bedrock / Vertex / Mistral). TRUSTED_CLOUD adds an Anthropic zero-data-retention key you attest to. PERMISSIVE is the explicit form of the default. A value already present in the real environment always wins over a stored one — the settings loader merges with setdefault (apps/sigil/sigil/config.py, _load_env_file)."],
          ["(b) In the UI or in ~/.sigil/sigil.env — reaches only what `vigil up` launched", "Settings → “Sovereignty tier (what may leave this machine)” writes that same 0600 file. No offense-plane module reads it. `vigil up` closes the gap by asking the sovereign venv for the resolved runtime environment and injecting the allowlisted variables — CRUCIBLE_SOVEREIGNTY_TIER is on that allowlist (integration/vigil_integration/uiproxy.py) — into the offense children it spawns. So a tier stored here governs an offense process when, and only when, `vigil up` started it — and only as of that start: the runtime env is resolved once at bring-up (integration/vigil_integration/uiproxy.py, _resolve_offense_llm_env, line 2104), so a tier changed in Settings while the UI is already running reaches only the offense children of a SUBSEQUENT `vigil up`. A run you launch from the UI in the meantime keeps the tier the UI started with; restart `vigil up` (or the vigil-command service) for the change to take effect, and note the Governance pill disagrees with the Settings screen until then."],
          ["(c) Anything else — FAIL-OPEN, and silent", "An offense process started any other way — `vigil engage` from a shell, `python3 -m framework.v2 …` run in engine/crucible/, a systemd unit or container that does not export the variable — sees only its own environment. A tier that exists ONLY in sigil.env or on the Settings screen is not read by it, the policy falls back to PERMISSIVE, nothing warns, and the run proceeds with cloud model egress permitted."],
          ["Latch it", "CRUCIBLE_SOVEREIGNTY_SEALED=1 latches the tier for the process lifetime, so a later environment change cannot relax it mid-run. Without it the tier is re-read on every call."],
        ] },
        { code: "export CRUCIBLE_SOVEREIGNTY_TIER=AIR_GAPPED\nexport CRUCIBLE_SOVEREIGNTY_SEALED=1" },
        { rule: "If the tier must hold for EVERY run on this host, export it in the environment those "
          + "processes inherit — a shell profile, the systemd unit, or the container — not only in "
          + "sigil.env or on the Settings screen. Setting it in both places is the safe combination; the "
          + "exported value wins where they differ." },
        { note: "To check what is actually in force, open Governance & Gate Audit (#/governance): the tier "
          + "pill there is read from the live policy IN the offense process that serves this UI, so it is "
          + "authoritative for THAT process and says nothing about a separate offense process launched from "
          + "a shell. Because that process took its environment at `vigil up` start, the pill DISAGREES with "
          + "the Settings screen after you change the tier there, until the next `vigil up` — the pill is what "
          + "is in force, not the Settings value. A refused backend is refused BEFORE the SDK is imported or a client is constructed, so "
          + "nothing leaves the host. An unrecognised tier name fails closed to AIR_GAPPED. If the policy "
          + "module cannot be evaluated while a tier is configured, the call is refused rather than sent." },

        { h: "What this machine stores" },
        { p: "Condensed inventory. “Sealed” means AEAD-encrypted under a TPM-sealed key, which "
          + "exists only after `sigil vault provision` has run against a real TPM; unprovisioned, those "
          + "items are plaintext at rest behind 0600 file permissions." },
        { table: {
          cols: ["Data", "Where", "Protection"],
          rows: [
            ["Account username and role", "Owner-signed grant on the hash-chained spine, ~/.sigil/spine/spine.jsonl",
             "PLAINTEXT in the record. Never covered by field-level encryption. File permissions only."],
            ["Account bearer token", "Same grant",
             "Never stored. Only sha256(per-account salt || bearer) is kept; comparison is constant-time."],
            ["Enrolled Ed25519 public key", "Same grant",
             "Plaintext — it is a public key. Only the owner can bind one; malformed, non-canonical and low-order keys are refused."],
            ["TOTP second-factor secret", "Same grant",
             "SEALED, never plaintext. Without a provisioned vault, TOTP enrolment REFUSES rather than falling back."],
            ["Password hash (optional weaker login)", "Same grant",
             "scrypt, n=2^15, fresh 16-byte salt per password. The plaintext password never reaches the spine."],
            ["OIDC identity", "Not persisted",
             "The RP is off unless enabled. Only a single-use state/nonce marker is written. A role is never taken from a claim."],
            ["Operator identity: OS login, git name and email, hostname, key fingerprint", "EVERY record of .vigil-live/usage-ledger.jsonl",
             "None beyond 0600 — this is signed plaintext by design. A human handle is structurally required."],
            ["Owner private key, spine data key, vault KEK", "~/.sigil/spine/keys/, ~/.sigil/vault/",
             "Sealed to this machine's TPM once provisioned; useless on another machine. UNPROVISIONED = plaintext at 0600."],
            ["API keys and service passwords", "OS keyring if available; else sealed ~/.sigil/secrets.sealed; else PLAINTEXT ~/.sigil/sigil.env (0600)",
             "Never written to the spine, a log, or a network payload. Redacted by key name in config output."],
            ["Target response bodies — your client's data", "targets/<slug>/evidence/<action_id>/response.body",
             "NOT REDACTED. Only credential HEADERS are masked; the raw body is deliberately untouched so the proof survives. Owner-only 0600 in a 0700 dir."],
            ["Findings and evidence certificates", "Offense spine and agent blackboard under .vigil-live/",
             "Signed and hash-chained. A certificate is a documented PLAINTEXT boundary — sealing it would break offline re-verification."],
            ["Chat transcripts, uploads, session registry", ".vigil-live/chats/, .vigil-live/sessions/",
             "0700 dirs, 0600 files. May contain whatever you pasted or uploaded."],
            ["Ingested assistant transcripts and git history (if you run SIGIL ingestion)", "Appended to the spine as events",
             "Content fields sealed under the spine key when the vault is provisioned; plaintext otherwise. A client discussion held with an AI assistant can land in the ledger."],
          ],
        } },

        { h: "Append-only audit versus erasure" },
        { p: "The spine is hash-chained and Ed25519-signed precisely so it cannot be quietly edited. That "
          + "same property is in tension with erasing personal data, and the system now stores per-user "
          + "identity data. Read this before you put a third party's data on it." },
        { list: [
          ["Revoking an account does not erase it", "Revocation appends a new owner-signed record. The earlier grant — and the username in it — remains readable in the chain."],
          ["Deleting a record in place is detectable, not supported", "It breaks the chain and fails verification. There is no secret-edit path, by design."],
          ["A hard-prune design exists; the destructive step is NOT shipped here", "Whole sealed segments [0..K) can be archived and replaced by an owner-signed snapshot that folds the security state forward, guarded by referential floors. On this branch only the NON-destructive machinery plus a dry run (`sigil spine prune-plan -K`) and an archive verifier are wired; apps/sigil/sigil/spine/prune.py states it deletes no live record. Treat in-product erasure of a spine record as NOT AVAILABLE today."],
          ["Even a completed prune leaves residue", "The owner-signed Merkle commitment over the pruned prefix survives, and the snapshot deliberately CARRIES active account records forward — otherwise a prune would silently vanish a user and reset their anti-replay floor."],
          ["Ordinary files are ordinary files", "targets/<slug>/evidence/, chats and reports are files you can delete. Deleting them does not rewrite the spine, which keeps its metadata and hashes of what happened."],
        ] },
        { note: "This is an operator decision, not a setting: tamper-evidence and erasure genuinely conflict. "
          + "Decide what personal data may enter the ledger BEFORE an engagement, because afterwards is too "
          + "late. If a data subject's erasure request is foreseeable, keep that data out of the spine." },

        { h: "Reducing what is kept and what leaves" },
        { list: [
          ["Set a tier", "AIR_GAPPED refuses every cloud model call, including the engage think step."],
          ["Provision the vault", "`sigil vault provision` is what turns “sealed at rest” from a description into a fact. Until then the owner key and the secrets store are plaintext behind file permissions."],
          ["Run ephemeral — CRUCIBLE engine CLI only", "`python3 -m framework.v2 engage … --ephemeral`, run from engine/crucible/, re-roots evidence and the audit log onto an in-memory tmpfs dir that is purged and VERIFIED absent on exit, suppresses persistent writers, and forces a zero-data-retention or local tier. The flag is declared on that parser alone (engine/crucible/framework/v2/engage.py). It is NOT an option of `vigil engage`, and no control in this UI sets it — so a run started from here, or from the super-CLI, persists to disk."],
          ["Keep intel offline", "The live intelligence collectors make no network call without an explicit --live opt-in."],
        ] },

        { h: "What leaves this machine" },
        { list: [
          ["Model calls", "As above — PERMISSIVE unless you say otherwise."],
          ["Traffic to your target", "The point of the tool. It carries a recognisable User-Agent so you can find it in your own logs."],
          ["Nothing from this interface", "The UI is served locally under a strict same-origin CSP (default-src 'self'), with no CDN, no external fonts, no analytics, and no third-party assets. These legal pages are static data compiled into the bundle; opening them fetches nothing."],
          ["Only what you arm", "Live intel pulls (--live), and opening a pull request (a GitHub token plus a single-use, minutes-long, m-of-n authorization you sign) are off unless you turn them on."],
          ["Vendored Strix telemetry is removed", "Upstream's phone-home modules are deleted, not disabled, and replaced by a local-only sink (see NOTICE)."],
        ] },

        { docs: [
          ["PRIVACY.md", "the full data inventory, retention and egress statement"],
          ["docs/OIDC-RP.md", "the optional OIDC relying party, off by default"],
        ] },
      ],
    },

    /* ====================================================================== */
    {
      id: "licenses", title: "Licenses & Attribution",
      lede: "How VIGIL is licensed, and whose work it is built on.",
      blocks: [
        { h: "VIGIL's own code is dual-licensed" },
        { p: "Copyright © 2026 Junior Thuram Nana. You may use VIGIL's first-party code under EITHER "
          + "the PolyForm Noncommercial License 1.0.0, free of charge, OR a Commercial License from the "
          + "copyright holder. If you have not signed a commercial agreement, the noncommercial terms apply." },
        { list: [
          ["Noncommercial — free", "Personal use, research, study, experimentation, hobby projects, and use by charitable, educational or public-research organizations (NON-GOVERNMENT), under PolyForm Noncommercial 1.0.0. Many schools and public-research institutes are state-owned; those fall under the Government-Use term below, not here."],
          ["Commercial — requires a licence", "Any commercial or production use, and anything the noncommercial licence does not permit."],
          ["Government and public sector — EXCLUDED from the free tier", "VIGIL adds a Government-Use Supplemental Term that overrides stock PolyForm-NC: use by, for, on behalf of, or funded by any government, agency, ministry, military, law-enforcement, public authority or state-owned entity requires a Commercial License."],
        ] },
        { note: "Whichever licence you use it under, you alone are responsible for how you use it. The "
          + "software is supplied AS IS, without warranty. Third-party components below keep their OWN "
          + "licences and are unaffected by VIGIL's dual licence." },

        { h: "Third-party components" },
        { table: {
          cols: ["Component", "Licence", "How it is used"],
          rows: [
            ["Strix", "Apache-2.0", "Vendored under vendor/strix/ and MODIFIED: upstream telemetry modules deleted and replaced by a local-only sink (default off), OpenRouter attribution headers removed, default model changed. LICENSE and NOTICE retained verbatim in that directory."],
            ["redamon", "MIT", "Source portions adapted into the fusion program, re-inverted to deny-by-default and subordinated to VIGIL's oracle, gates and signed spine. Full MIT text reproduced in NOTICE."],
            ["hexstrike-ai", "MIT", "Its decision model is reimplemented clean-room; the upstream server and MCP entry points are vendored ONLY as non-runnable “.reference” blobs — never imported, never executed, never on PYTHONPATH. LICENSE retained in vendor/hexstrike-ai/."],
            ["pentagi", "MIT plus an upstream EULA", "DESIGN REFERENCE ONLY. Its ideas are reimplemented in Python; its Go source, configuration and documentation prose are not vendored."],
            ["garak, PyRIT, Giskard, promptfoo", "Their own upstream licences (garak Apache-2.0, PyRIT MIT)", "Invoked as subprocesses, never imported, so their dependencies and licences stay outside VIGIL's process."],
          ],
        } },

        { h: "Export control" },
        { p: "VIGIL is dual-use intrusion software. Several jurisdictions regulate the export, re-export, "
          + "transfer or provision of such software and of related technology — including regimes "
          + "derived from the Wassenaar Arrangement, the EU dual-use Regulation and the U.S. Export "
          + "Administration Regulations. Whether any of them applies depends on the software, the recipient, "
          + "the destination and the end use." },
        { note: "No export classification has been performed for VIGIL and none is asserted here. Before you "
          + "distribute it, take it across a border, provide access to a person outside your jurisdiction, "
          + "or deploy it for a government end user, determine your own obligations with qualified counsel. "
          + "Sanctions and end-user restrictions apply independently of the licence you hold." },

        { docs: [
          ["LICENSE", "the binding noncommercial terms plus the Government-Use Supplemental Term"],
          ["LICENSE-COMMERCIAL.md", "the commercial model in plain language, and how to obtain a licence"],
          ["LICENSING.md", "which licence applies to your situation"],
          ["NOTICE", "every third-party attribution and the full reproduced licence texts"],
          ["vendor/strix/LICENSE, vendor/strix/NOTICE, vendor/hexstrike-ai/LICENSE", "the vendored components' own licences, retained verbatim"],
          ["EXPORT.md", "the export-control note in full"],
        ] },
      ],
    },

    /* ====================================================================== */
    {
      id: "security", title: "Security & Disclosure",
      lede: "How to report a vulnerability in VIGIL itself.",
      blocks: [
        { rule: "Report privately first. Do not open a public issue, and do not test anyone else's "
          + "deployment — VIGIL is self-hosted, so every running instance belongs to someone." },
        { p: "This page is about bugs in VIGIL. A vulnerability you found in a client's system using VIGIL "
          + "is a finding for that client under your engagement — see Acceptable Use." },

        { h: "Where to send it" },
        { p: "SECURITY.md is the governing document; use the channel it names. It publishes "
          + "security@thuramnana.com as the security address — marked there as a placeholder pending "
          + "confirmation that the mailbox is monitored — with the maintainer address "
          + "thuram@thuramnana.com as the fallback, subject line “VIGIL security report”. No PGP key is "
          + "published yet, so treat email as unencrypted: send enough to triage and hold the full proof "
          + "of concept until keys can be exchanged." },
        { note: "SECURITY.md states a 90-day coordinated-disclosure window and offers safe harbour for "
          + "good-faith research. Its response times are stated as targets, not a contractual SLA, and "
          + "the repository publishes no bug-bounty program or reward. This is a single-maintainer "
          + "project; treat it accordingly." },

        { h: "What to include" },
        { list: [
          ["Version", "The commit or release you tested, and how you installed it."],
          ["Reproduction", "Exact steps, and the smallest input that triggers it. A working proof of concept is worth more than a description."],
          ["Impact", "What an attacker gains — in particular whether it crosses one of the boundaries below."],
          ["Environment", "OS, whether the TPM vault is provisioned, whether you run behind the vigil up proxy or a plane server directly."],
        ] },

        { h: "The boundaries worth attacking" },
        { p: "A break in any of these is more serious than a routine bug, because the system's honesty "
          + "claims rest on them:" },
        { list: [
          ["Oracle authority", "Anything that lets an unproven LEAD be reported as a confirmed FACT."],
          ["Evidence integrity", "Forging, replaying or tampering with a signed certificate, ledger record or spine entry so it still verifies."],
          ["The gate", "Reaching a target-touching or destructive action without clearing scope, the WARDEN tier, the kill-switch, or the m-of-n threshold."],
          ["The two-plane split", "Anything that lets the keyless offense engine reach owner key material, or that co-mingles the two processes."],
          ["Egress", "Any path that sends data off the host when the configured sovereignty tier forbids it."],
          ["The console origin", "Script injection into the UI origin, CSRF or DNS-rebinding past the console's guards, or a token leak into a served asset."],
        ] },

        { h: "Please do not" },
        { list: [
          ["Test infrastructure that is not yours", "There is no VIGIL-operated service to test. Do not attack the maintainer's hosts, mailbox, or accounts."],
          ["Publish before contact", "Reach the maintainer first, even if the reply is slow."],
          ["Include real third-party data", "Redact. A report should prove the bug, not hand over someone's personal data."],
        ] },

        { docs: [
          ["SECURITY.md", "the reporting policy in full — governing"],
          ["docs/SUPPLY-CHAIN.md", "how dependencies are pinned and scanned"],
        ] },
      ],
    },
  ],
};
