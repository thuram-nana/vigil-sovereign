"use strict";
/* ==========================================================================
   VIGIL COMMAND — manual.js : the in-app manual (real documentation content).
   This is DOCUMENTATION, not runtime data — it explains each part of the system
   in plain language so a newcomer can operate it. window.VIGIL_MANUAL is an
   array of sections; app.js renders it. No runtime/target data lives here.
   ========================================================================== */
window.VIGIL_MANUAL = [
  {
    id: "overview", title: "What VIGIL COMMAND is",
    blocks: [
      { p: "VIGIL is one security system with two jobs: it can attack a target you own to find real bugs (OFFENSE), and it can defend an app you run against AI attacks (DEFENSE). This screen — COMMAND — is the single place to run, watch, and govern all of it." },
      { p: "Under the hood it runs as two isolated processes that never mix: a SOVEREIGN core that holds your keys and grants approvals, and a keyless OFFENSE engine that does the work. You never see that split as two apps — the interface shows it as two colours." },
      { note: "Gold means it involves YOU — your approval, your keys, your kill-switch. The cool default colour is the work itself. If something is gold, it is waiting for a human decision." },
    ],
  },
  {
    id: "safety", title: "The safety model (read this first)",
    blocks: [
      { h: "Approve-then-run" },
      { p: "Nothing offensive fires on its own. Any action that touches a target, or is destructive, is QUEUED and waits for your explicit approval. You approve from the top-bar safety pill, the Approvals screen, or your paired phone. If you do nothing, a queued action auto-rejects on a timer — silence is safe." },
      { h: "Only an oracle confirms" },
      { p: "A finding is only marked CONFIRMED (a FACT) when a deterministic checker — an ORACLE — re-runs and fires on data the real target produced. The AI's opinion, a critic's endorsement, or a plausible story never make something a fact; they stay LEADS. Evidence can be re-verified offline at any time." },
      { h: "Kill-switch" },
      { p: "The kill-switch is always one click away in the top bar. Tripping it halts everything immediately; only releasing it (which requires your signature) resumes work." },
      { h: "Never public" },
      { p: "No part of VIGIL ever opens itself to the open internet. It binds only to your machine or a private tunnel; to reach it by a domain you put a reverse proxy in front (see Deploying)." },
    ],
  },
  {
    id: "assess", title: "Running an assessment",
    blocks: [
      { p: "Start from New Assessment. Step 1 asks what you want to check — pick one of five:" },
      { list: [
        ["A codebase", "Point the AI at a folder on this machine or a git repo. It reads and reasons over the source. You can also ask it to propose fixes for anything it proves."],
        ["A website / URL", "Give a web address. VIGIL crawls it and safely probes it, within the scope you set."],
        ["One specific tool", "You already know what you want to run — e.g. a single SSO or injection check."],
        ["Full autonomous suite", "Let the AI decide and run everything, step by step, pausing for your approvals."],
        ["Defend my app (AEGIS)", "Not an attack — put VIGIL in front of your own app to catch AI attacks against it."],
      ] },
      { p: "The remaining steps ask WHERE the target is, HOW FAR VIGIL may go (the scope — the exact hosts it is allowed to touch), HOW it should work (quick/standard/deep, and whether to apply fixes), and WHICH AI model to think with. A running summary on the right shows exactly what will happen before you launch." },
      { note: "Scope uses exact hosts or *.wildcards — never IP ranges (CIDR). Anything outside your scope is hard-denied, always." },
    ],
  },
  {
    id: "live", title: "Watching it live",
    blocks: [
      { p: "The Live screen shows every action as it happens — as a node graph (the flow of reasoning) and as a plain-language timeline. Each entry is one of these kinds:" },
      { list: [
        ["Observation", "Something VIGIL saw about the target."],
        ["Hypothesis", "An idea to test (e.g. “this field might be injectable”), with an ID like H-014."],
        ["Plan / Action / Result", "What it intends to do, does, and what came back."],
        ["Tool call", "A tool being run, tagged with its risk tier (T1–T3)."],
        ["Finding", "A possible or PROVEN bug. Green shield = proven by an oracle (a FACT)."],
        ["Critique / Decision", "The system reviewing its own work — advisory only."],
        ["Refusal", "A safety gate blocked an action, with the reason. Shown openly, never hidden."],
        ["Reward / Reflection", "How it learns and re-prioritises — advisory only, never a confirmation."],
      ] },
      { note: "A LEAD is a suspicion. A FACT is proven by a fired oracle. The filter at the top of the timeline lets you see only proven facts when you want certainty." },
    ],
  },
  {
    id: "findings", title: "Findings & evidence",
    blocks: [
      { p: "Findings collects every result. Each shows a severity, the bug class, where it was found, which oracle confirmed it, and a status: CONFIRMED (a fact) or LEAD (unproven, and never reported as a fact)." },
      { p: "Every confirmed finding carries an evidence certificate you can re-verify offline — it re-checks the stored proof and reports one of three honest states: Sound (re-proven), Tampered (evidence changed), or Claim-mismatch (the evidence does not support the claim). The Attack Graph shows how findings chain toward real impact." },
    ],
  },
  {
    id: "fixes", title: "Fixes",
    blocks: [
      { p: "The Fixes screen shows what to fix after a run — its oracle-confirmed findings (only PROVEN bugs are eligible; unproven leads are never auto-fixed), each with its own remediation guidance, plus the highest-impact fix points (the single choke-points that sever the most attack paths)." },
      { h: "The gated ladder" },
      { p: "An auto-fix follows a ladder of gated steps, each at its own risk tier: clone the repo (A1), apply the AI's proposed edits (A2 — each file needs your explicit approval; a timeout auto-rejects), build in a sandbox (A3), and open a pull request (A3 — a distinct multi-signer approval). Only explicit, path-validated files are ever staged — never a bulk change." },
      { p: "A fix is marked FIXED only when the ORIGINAL exploit oracle is re-run on the patched build and goes SILENT — i.e. the bug can no longer be proven. If it still fires, the pull request still opens but is flagged as a proposal, not a fix. Nothing is merged for you." },
      { note: "Live auto-application (actually cloning, editing, sandbox-building, and opening a PR against your repo) runs from the command line as `vigil patch`, and only over a PROVEN finding — never a raw file you hand it. The default is a dry run that touches nothing but a throwaway clone; opening a real PR is off by default and needs the signing key set up below." },
    ],
  },
  {
    id: "arming-autofix", title: "Arming live auto-patch (opening real PRs)",
    blocks: [
      { p: "By default `vigil patch` proposes a fix and applies it inside a throwaway copy of your repo — your real repo is never touched and no pull request is opened. Turning on real PRs (`--open-pr`) is a deliberate, one-time setup because it is the one step that changes something outside VIGIL." },
      { h: "Why a signing key" },
      { p: "Opening a PR is gated by an m-of-n signature — “m of n approved keys must sign, and the owner must be one of them.” This is what stops the engine from ever opening a PR on its own: it can only act on an authorization YOU signed, for THAT one repo and finding, that is single-use and expires in minutes." },
      { h: "One-time setup" },
      { list: [
        ["1. Generate the keys", "Run `vigil provision-destruction`. It prints your signing key(s) ONCE and writes a public trust file. Paste the owner key into Settings → “Auto-patch signing key (owner)”."],
        ["2. (optional) Share duties", "For a team, run `vigil provision-destruction --signers 2 --threshold 2` and give each co-signer their own key, kept on their own machine — then no single machine can authorize a PR alone."],
      ] },
      { h: "Per fix" },
      { list: [
        ["3. Dry run", "`vigil patch --finding-envelope … --target-repo R` prints the exact action to authorize (an id, the engagement, the repo)."],
        ["4. Authorize", "`vigil authorize-destruction --action-id … --slug … --target R` signs that one action with your owner key (read from Settings), producing a single-use, minutes-long authorization."],
        ["5. Open the PR", "`vigil patch … --target-repo R --open-pr` finds that authorization automatically and opens the gated pull request. It still needs a GitHub token (Settings) and never merges anything for you."],
      ] },
      { note: "Solo setup (the default, one key at threshold 1): whoever holds the owner key can authorize a PR — it is still single-use, time-boxed, bound to one repo+finding, and off by default. For real separation of duties use more signers and keep their keys on separate machines." },
    ],
  },
  {
    id: "defense", title: "Defense — AEGIS",
    blocks: [
      { p: "AEGIS sits in front of an app you run (as a reverse proxy) and watches real traffic for AI attacks. From the Defense screen you point it at your app's URL, choose a mode, optionally seed honeypot paths (decoy URLs no real user would touch — a fetch proves automated access), and give it a deployment secret. Start it, and it protects your app while streaming what it sees." },
      { note: "The deployment secret keys PRIVACY pseudonymisation of who's who (IP/session) — it is not a request password. Canary / prompt-injection detection for an LLM app is a separate in-process path (the Aegis SDK / `aegis detect`), not this reverse proxy — the screen says so where it matters." },
      { h: "Observe vs Enforce" },
      { p: "Observe (the default) watches and proves attacks but blocks nothing. Enforce blocks PROVEN attacks — and only proven ones — but needs a specific entitlement; without it, it safely downgrades to observe and the screen tells you so. Everything fails open: if inspection ever errors, your traffic still flows." },
      { h: "Reading the verdicts" },
      { p: "The live feed streams verdicts as they happen. Here a CONFIRMED verdict is a PROVEN attack on your app (an oracle fired, with an offline-re-verifiable certificate) — shown in red, the opposite of the offense side where proven is good. A Lead is a suspicion, not proof. Clear means nothing was proven — which is NOT the same as safe. An actor view shows how likely each source is hostile (a belief that rises with corroboration), and the graduated response it warrants." },
      { p: "The screen also gives you the exact command to run the same gateway on your own edge for production — VIGIL's loopback console is for watching and configuring, not for being your public edge." },
    ],
  },
  {
    id: "safety-screen", title: "Approvals & Safety",
    blocks: [
      { p: "This is your human-in-the-loop cockpit. Actions are ranked by risk tier:" },
      { list: [
        ["A0", "Observe / answer — no target impact."],
        ["A1", "Reversible, internal — applied automatically."],
        ["A2", "Externally visible — needs your one-tap approval."],
        ["A3", "Destructive / security-sensitive — explicit approval, sometimes several signers."],
      ] },
      { p: "The approval queue lists everything waiting, with what it will do, why, and a countdown. You also control the kill-switch here, review the who/when usage ledger (nothing runs without a record), and toggle capabilities. The same approvals appear on your paired phone." },
    ],
  },
  {
    id: "settings", title: "Settings — keys & model",
    blocks: [
      { p: "Add the secrets the system uses here — your AI provider API key; a GitHub token (for live auto-patch) that lets the fix engine push a branch and open a gated pull request; and the auto-patch signing key that AUTHORIZES a PR (generate it with `vigil provision-destruction` — see “Arming live auto-patch”). Each is sealed into your machine's keyring or TPM-backed vault, shown to you only as a redacted fingerprint afterwards, and is NEVER written to the audit log or sent to your browser again. All three are optional — you can run keyless (deterministic checks only, no AI reasoning), and you only need the GitHub token and signing key if you open PRs." },
      { p: "Choose which AI model VIGIL thinks with — the model you pick here is the one the engine actually reasons with (it flows to both engagements and fix proposals). Every secret is sealed and delivered to the engine on your machine only." },
    ],
  },
  {
    id: "brain", title: "Brain — memory, benchmark & catalog",
    blocks: [
      { p: "The Brain screen is a window into what the system knows and how well it performs. It has tabs:" },
      { list: [
        ["Memory", "Cross-engagement priors it has learned — a per-archetype / bug-class success rate (how often a class of attack actually pans out). Empty until you run assessments; it never fabricates a score."],
        ["Benchmark", "How the engine scores on a fixed corpus of planted bugs AND safe controls: true positives (bugs found), false positives (safe things wrongly flagged), and misses. Honest calibration."],
        ["Catalog", "The searchable list of capabilities the AI can bring to bear, each mapped to an already-gated action and risk tier."],
        ["Intel / Planner", "Per-engagement reconnaissance and the plan tree for a chosen run."],
      ] },
      { note: "Reasoning — the critics, learning, and reflection the system runs on itself — is ADVISORY only. It re-ranks and defers work, but it never promotes a finding to a fact. Only a fired oracle can do that." },
    ],
  },
  {
    id: "deploy", title: "Deploying — local & hosted",
    blocks: [
      { p: "One command, vigil up, brings the whole system up on your machine and opens this interface in your browser (loopback only — never exposed)." },
      { p: "To reach it from elsewhere, host it on a server you own behind your own domain: VIGIL still binds privately and you put a TLS reverse proxy (Caddy or nginx templates are included) in front. The tunnel/proxy is the boundary — VIGIL itself never listens on a public address." },
    ],
  },
  {
    id: "glossary", title: "Glossary",
    blocks: [
      { list: [
        ["Oracle", "A deterministic checker that PROVES a bug by re-running against real target data. The only thing that can confirm a finding."],
        ["FACT vs LEAD", "FACT = proven by an oracle. LEAD = a suspicion, never reported as proven."],
        ["Scope", "The exact hosts VIGIL is allowed to touch. Signed, enforced, and never widened silently."],
        ["WARDEN tier (A0–A3)", "The risk level of an action; higher tiers need your approval."],
        ["Spine", "The tamper-evident, signed log of everything that happened. Every item can be re-verified."],
        ["Provenance", "For any item on screen, the proof of where it came from and that it is untampered."],
        ["Sovereign / Offense", "The two isolated processes — your key-holding core, and the keyless engine that does the work."],
      ] },
    ],
  },
];
