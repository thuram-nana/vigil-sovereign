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
      { p: "If you ask VIGIL to fix what it finds, it only ever acts on a PROVEN bug. The fix runs as a ladder of gated steps you can watch: clone the code, edit it, build in a sandbox, and open a pull request — each step at its own risk tier, and the pull-request step needs your explicit approval." },
      { p: "A fix is only accepted when the ORIGINAL exploit oracle is re-run and goes silent — i.e. the bug can no longer be proven. Nothing is merged for you." },
    ],
  },
  {
    id: "defense", title: "Defense — AEGIS",
    blocks: [
      { p: "AEGIS sits in front of an app you run and watches for AI attacks. You set up two kinds of bait: canaries (secret sentinel text — if it ever leaks, a prompt-leak is proven) and honeypots (resources no real user would touch)." },
      { p: "The dashboard streams verdicts as they happen — Confirmed attack (oracle-proven, with a certificate), Lead (suspicious, not proven), or Clear (with the honest note that clear is not the same as safe). An actor view shows how likely each source is hostile, based on what it has actually done." },
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
      { p: "Add your AI provider API key here. It is sealed into your machine's keyring or TPM-backed vault, shown to you only as a redacted fingerprint afterwards, and is NEVER written to the audit log or sent to your browser again. You can also run keyless (deterministic checks only, no AI reasoning)." },
      { p: "Choose which AI model VIGIL thinks with, manage the scope/authority it is allowed to act under, and pair devices (like your phone for remote approvals)." },
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
