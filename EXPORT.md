# EXPORT CONTROL — dual-use notice

**This is an informational notice, not a legal opinion, not a classification, and not
advice.** It exists because tooling of this kind can fall under export-control law, and
because both the person who *distributes* VIGIL and the person who *downloads* it can carry
obligations. It tells you what to look at. It does not tell you the answer, and nobody on
this project is qualified to.

**No classification is asserted here.** This document does not state an ECCN, an EU Annex I
entry, a national control-list entry, or that VIGIL is or is not controlled anywhere.
Determining that is the responsibility of whoever distributes or receives the software, in
their own jurisdiction, with qualified counsel.

---

## 1. Why this document exists

VIGIL is dual-use security software. It performs authorised intrusion testing: it probes
systems, it exploits vulnerabilities to prove them, and it captures and retains the evidence
of doing so.

Since the 2013 Wassenaar Arrangement amendments, several regimes have maintained controls
touching "intrusion software" and related technology, along with IP-network surveillance
systems. Those controls are implemented differently in each participating state, they have
been repeatedly revised, and they interact with cyber-specific and general dual-use rules
that vary by country. Instruments an analysis commonly starts from include:

| Regime | What it is |
|---|---|
| **Wassenaar Arrangement** dual-use lists | The multilateral source most national lists derive from. Not itself law anywhere — each participating state implements it |
| **EU Regulation (EU) 2021/821** (the recast dual-use regulation) | The EU's dual-use framework, including its cyber-surveillance provisions and Annex I control lists |
| **US Export Administration Regulations (EAR)**, 15 CFR Parts 730-774 | Including the Commerce Control List and its cybersecurity-items entries, plus licence-exception and "published" concepts |
| **UK, and other national regimes** | Each participating state maintains its own list and its own licensing authority |
| **Sanctions and restricted-party regimes** | UN, EU restrictive measures, US OFAC (SDN and other lists), UK and other national regimes. These operate *independently* of dual-use classification — an uncontrolled item can still be unlawful to supply to a listed party or embargoed destination |

Which of these reach you depends on where you are, where the recipient is, your nationality
and residence, where the code is hosted, and sometimes the origin of components in the
software. Export law also reaches conduct that does not feel like "export": publishing a
download link, granting repository access, emailing a copy, carrying a laptop across a
border, or providing technical assistance to a person in another country.

## 2. Obligations run in both directions

**If you distribute VIGIL** — mirror it, fork it publicly, bundle it into a product, host it
for others, ship it to a client, or hand it to a colleague abroad — you may be an exporter
or re-exporter under one or more of the regimes above, with your own classification,
screening, licensing, and record-keeping duties.

**If you download or receive VIGIL** — you may be an importer or end user with your own
duties: import restrictions in some countries, end-use restrictions, prohibitions on
re-export or on transfer to certain parties, and in some places domestic restrictions on
possessing or supplying intrusion tooling that are separate from export law entirely.

Neither party can rely on the other to have done this analysis. The maintainer has not
performed a classification and does not represent that any transfer is authorised.

## 3. The licence does not exempt anyone

VIGIL's noncommercial branch is a **source-available licence**
([`LICENSING.md`](LICENSING.md)), not a waiver of anyone's legal obligations.

- **A licence is not an export authorisation.** Being permitted to use the software under
  PolyForm Noncommercial 1.0.0, or under a commercial licence, says nothing about whether
  you may lawfully transfer it to a particular country or person.
- **"Noncommercial" is not a control-law category.** Research, education, evaluation, and
  charitable use are licence concepts. Export and sanctions law generally does not turn on
  whether money changed hands.
- **"Publicly available" / "published" is a real concept in some regimes — and a question of
  fact and law, not a self-declaration.** Several frameworks treat published or publicly
  available software and technology differently from controlled transfers, and some carry
  carve-outs relevant to vulnerability disclosure and incident response. Whether any of that
  applies to a specific transfer of this specific software is exactly the question for
  counsel. Do not assume it, and do not treat this paragraph as saying it does.
- **Sanctions apply regardless.** Even where an item is uncontrolled, supplying it to a
  designated person or an embargoed destination can be prohibited.

## 4. What a classification analysis would need to look at

Offered as factual description of the software, **not** as an argument for or against any
classification. An analyst will want the facts; here are the ones this repository can
state truthfully.

VIGIL **does** include:

- autonomous discovery, probing, and exploitation of vulnerabilities against a target
  identified in a signed charter;
- capture and retention of raw target responses as evidence
  (`engine/crucible/framework/v2/agents/http_executor.py`);
- cryptographic signing, hash-chained audit ledgers, and evidence certificates;
- integration with third-party security tooling invoked as subprocesses, and vendored
  third-party components under their own licences (see [`NOTICE`](NOTICE)).

VIGIL also includes post-exploitation, persistence, and data-exfiltration-impact material,
run per an engagement's rules of engagement
(`engine/crucible/framework/playbooks/21-post-exploitation.md`,
`22-data-exfiltration-impact.md`), bounded by the charter's hard limits.

What VIGIL, as a matter of project doctrine, **does not** build is **evasion** capability —
detector or WAF bypass, stealth, IP rotation. The vendored brain carries a runtime guard
that rejects any such knob (`docs/BRAIN-SLOT-INTEGRATION.md:19, 34`), the defensive build
stream refuses diffs that add evasion, payload, or C2 capability
(`engine/crucible/FORGE.md:27, 177`), and the default HTTP posture is deliberately
identifiable and throttled (`engine/crucible/framework/v2/agents/http_executor.py:75-92`).

None of this is an argument about classification. It is the factual description an analyst
would ask for; the conclusion is theirs.

Note that vendored and subprocess-invoked third-party components are governed by their own
licences and may carry their own control considerations; a classification of "VIGIL" that
ignores what it bundles or invokes is incomplete.

## 5. What you should do

1. **Determine your own jurisdiction's rules** — as the distributor, the downloader, or
   both. The maintainer's primary jurisdiction is understood to be Cameroon (confirm before
   publication); users and clients are elsewhere, and EU, UK, and US rules can reach a
   person or transaction outside those territories.
2. **Get a classification from qualified counsel or your national licensing authority**
   before distributing, mirroring, re-exporting, or shipping VIGIL as part of an offering.
   Do not self-classify from this document.
3. **Screen destinations and parties** against the sanctions and restricted-party lists
   that apply to you, before any transfer, repository access grant, or engagement.
4. **Keep records** of what you transferred, to whom, when, and on what basis.
5. **Remember non-export restrictions.** Some countries restrict possession, supply, or use
   of intrusion tooling under domestic criminal law, independently of export control. See
   [`ACCEPTABLE-USE.md`](ACCEPTABLE-USE.md).

## 6. No representation

The maintainer makes **no representation** that VIGIL is or is not subject to export
control in any jurisdiction, that any particular transfer is lawful, or that any licence
exception, exemption, or general authorisation applies. The maintainer does not screen
downloaders and has no ability to do so. Responsibility for compliance rests with the party
making or receiving the transfer.

---

*Related:* [`LICENSING.md`](LICENSING.md) · [`ACCEPTABLE-USE.md`](ACCEPTABLE-USE.md) ·
[`TERMS.md`](TERMS.md) · [`engine/crucible/DISCLAIMER.md`](engine/crucible/DISCLAIMER.md).

*Contact for licensing questions:* `thuram@thuramnana.com`. The maintainer cannot answer
export-control questions and will not attempt to.
