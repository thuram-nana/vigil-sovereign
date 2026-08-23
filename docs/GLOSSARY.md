<!-- CLAIM:W16-STD-7-glossary -->
# Glossary

The plain-language dictionary for the whole documentation set. Where the [README glossary](../README.md#glossary)
and the [briefing glossary](plain-english/00-glossary.md) define a shorter working subset for their own
readers, this is the canonical, consolidated list. A floor set of the core terms is pinned by
[`docs/tests/test_w16_std7_docs_completeness.py`](tests/test_w16_std7_docs_completeness.py) so this page
cannot silently lose a term the rest of the docs rely on.

## The three planes and their control plane

- **VIGIL** — the whole system: an autonomous offensive engine, a defensive dual, and a sovereign personal
  AI, fused under one control plane over two isolated processes.
- **CRUCIBLE** — the offensive engine (the "arsenal"): recon, scanning, engagement, verification. Keyless.
- **AEGIS** — the embeddable defensive dual of CRUCIBLE: runtime-defence oracles and the Detection Mirror.
- **SIGIL** — the sovereign personal core; it holds the owner key and is offense-free.
- **`vigil` super-CLI** — the single command surface that routes each verb to its own isolated environment.
- **Two-environment boundary** — the hard separation between the keyless offense side and the offense-free
  sovereign core, so no single interpreter ever holds the owner key *and* can import the offense engine.

## Truth, proof, and evidence

- **Oracle** — a small, deterministic (non-AI) program that independently re-proves a suspected weakness
  over the target's own bytes. It is the **only** thing that can mint a fact.
- **FACT vs LEAD** — a FACT is oracle-proven and signed; a LEAD is an unproven, honestly-labelled proposal.
  Imported third-party findings are LEADs until an oracle re-verifies them.
- **Veracity firewall** — the anti-hallucination layer that re-executes rather than trusting a string; it
  can only *demote* a claim, never promote one.
- **Challenge oracle** — a proof that uses a fresh one-time challenge, so a replay or a hallucination cannot
  fake a finding.
- **Spine / record** — the one append-only, hash-chained, Ed25519-signed log of everything; entries are
  added, never quietly changed.
- **Evidence bundle** — the signed, offline-re-verifiable package of a run's facts; `crucible verify`
  re-fires each oracle over the retained material with no VIGIL and no vendor required.
- **Proof-carrying finding** — a finding shipped with everything a third party needs to re-prove it offline.
- **Certificate of Non-Exploitability** — a signed, coverage-bounded *negative* proof (`vigil posture`):
  provably-tested-clean, separated from merely-untested.
- **Transparency log** — the record re-expressed so outsiders can audit it without trusting the operator.
- **SCITT / OpenVEX** — standards-based, offline-verifiable formats for signed statements about
  vulnerabilities.

## Authorization and safety

- **Charter** — the binding engagement document: the target hosts, scope, rules of engagement, and the
  operator attestation. No target-touching action runs without one.
- **Attestation (usage record)** — the always-on "who / when / what" entry minted *before* anything runs,
  tied to a never-decreasing (hardware-anchored where available) counter.
- **WARDEN** — the classifier-of-record that assigns every action a danger **tier**.
- **WARDEN tier (A0–A3)** — the danger level of an action; A0 is harmless, A3 is destructive; anything
  unknown is treated as A3 (fail-closed).
- **Conjunctive gate** — the checkpoint requiring authority *and* tier approval *and* (for destructive
  actions) multi-person sign-off, all at once, before an action runs.
- **Egress gate** — the deny-by-default network firewall + proxy that is the sandbox's only route out.
- **m-of-n threshold** — destructive actions require a quorum of independent signers, not one key.
- **Kill-switch** — a persistent, gate-level DENY that stops an engagement's actions immediately.
- **Entitlement** — the licence/capability system that decides what a copied or stolen build may do.
- **Capability** — a named permission a tool declares; the gate checks it against the entitlement.

## Attack reasoning and output

- **World model** — the picture of the attack: assets, findings, and their relationships, projected from
  the signed spine.
- **Attack path / chokepoint** — a route an attacker could take, and the node that, if fixed, closes many
  paths at once.
- **Detection Mirror** — the defensive twin that proves an attack from the target's *own* logs, with a
  benign-twin control.
- **Session / engagement** — one scoped body of work against one authorized target.

## Technical terms a reader meets

- **LLM** — "large language model," the AI's underlying text-prediction engine (here, Claude).
- **MCP** — the Model Context Protocol, the emerging standard plug-in interface that lets AI assistants use
  external tools.
- **SSRF** — "server-side request forgery," tricking a server into fetching a forbidden internal address.
- **Loopback (`127.0.0.1`)** — your own computer talking to itself, so no outside system is contacted.
- **Ed25519** — the signature scheme used for the spine, governance, and evidence signing.
- **Sandbox (bwrap)** — a network-isolated, workspace-confined container (`--unshare-all`) an arbitrary
  command runs inside.
- **Sidecar** — an optional companion service (e.g. the graph database or the telemetry collector).
- **Non-repudiable** — provable in a way the actor cannot later deny.
- **CI** — "continuous integration," the automated system that builds and tests every change.
