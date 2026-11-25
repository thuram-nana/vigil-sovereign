# AEGIS Threat Model — Public Register (slice AS-0)

This is the **public** AEGIS threat register: the companion to
[`aegis-threat-model.json`](./aegis-threat-model.json). It is published under the VIGIL
plan's §4.7 publication split, which this repository (vigil-sovereign) is public under.

It carries **fixed-state governance only** — decided architecture and mitigated threats.
Open, un-mitigated, or sensitive entries are **not** here; they live in the private handoff
register (vigil-handoff) per plan §4.7. The guiding rule for every row below: describe the
**decision** and the **mitigation**, never a live weakness.

Grounding: VIGIL plan `parsed-popping-lemur.md` §4.1 (zones and boundaries), §4.2 (threat
register), §4.3 (what stays trustworthy), §4.4 (origin and edge-chain declarations),
§4.7 (publication). Sibling docs: [`AEGIS-DESIGN-RESEARCH.md`](./AEGIS-DESIGN-RESEARCH.md),
[`AEGIS-DOCTRINE-CRITIQUE.md`](./AEGIS-DOCTRINE-CRITIQUE.md),
[`AEGIS-SIGNAL-CATALOG.md`](./AEGIS-SIGNAL-CATALOG.md),
[`AEGIS-CRUCIBLE-REUSE-MAP.md`](./AEGIS-CRUCIBLE-REUSE-MAP.md), and
[`DEPLOYMENT.md`](./DEPLOYMENT.md).

---

## 1. Zones and attackers (reference)

Public entries name zones and attackers from plan §4.1.

**Zones:** Z1 AWS edge · **Z2E** enforcement (unit = front + gateway, egress broker, origin
prover) · Z2W workers · Z2X actuation · Z3 control plane · Z3R keyless relay ·
Z4 offensive sandbox · Z5/Z6 customer / operators.

**Attackers:** A1 internet · A2 hostile tenant · A3 RCE in a unit · A4 operator ·
A5 supply chain · A6 provider/connector · A7 customer sensor · A8 AI-aimed content ·
A9 compromised shared SIGIL component. AWS is a stated dependency, not an attacker.

---

## 2. Public mitigated threats

Every row below has `status = mitigated` and a non-empty `record_ref` — the §4.7 invariant
that the public register is fixed state only (see §4). The JSON is authoritative; this table
mirrors it.

| Id | Title | Zone | Attacker | Status | Record |
|---|---|---|---|---|---|
| `AEGIS-T-BG-KILLSWITCH` | Break-glass kill-switch unreadable must not keep the gateway blocking | Z2E | A4 / A3 + fault | mitigated | AS-27a / PR#1228 |
| `AEGIS-T-BG-MODEFILE` | Break-glass mode-file glitch must not silently escalate to enforce | Z2E | A4 + fault | mitigated | AS-27a / PR#1228 |

Only threats closed by a **shipped** control (code on `main` with an engineering record) appear here.
Decided-but-not-yet-shipped mitigations (e.g. edge routing AS-2d, origin binding AS-2g, unit isolation
AS-2j) remain in the **private** register until their slice ships and earns its record, at which point the
corresponding threat moves into this file described as the decision and the mitigation.

### Mitigations in detail

- **`AEGIS-T-BG-KILLSWITCH` — shipped (AS-27a / PR#1228).** The enforce gate consults the
  kill-switch (break-glass) subsystem. AS-27a makes the gateway wrapper treat an *unreadable*
  kill-switch subsystem (`is_tripped` raising, or `KillSwitch` construction failing) as
  **TRIPPED**, so enforcement drops to pass-through rather than continuing to block on a switch
  it cannot read. The downgrade is honest — `enforcement_status()` reports `enforcing=false`,
  `kill_switch_tripped=true`, `downgraded=true`, and names the kill-switch as the reason.
  Covered by `framework/v2/aegis/tests/test_gateway_breakglass.py`
  (TT-STG negative: "unreadable kill switch → no block"; plan §4.2 T-BG/T-FO, §3 B10).

- **`AEGIS-T-BG-MODEFILE` — shipped (AS-27a / PR#1228).** A present-but-unreadable mode-override
  file is a *glitch*, not "no override": AS-27a falls back to the last cleanly-read override, and
  if none to **OBSERVE** — it never silently escalates to the startup `--mode` (which may be
  enforce). A cleared or invalidated override is not resurrected by a later glitch
  (cache-invalidation guard). `ENOENT`/`ENOTDIR` are treated as "absent" (startup mode, cache
  cleared); `EACCES` and a path-subsystem failure are glitches. Covered by the same test module.

The decided architecture for edge routing, cross-tenant origin binding and unit isolation is documented in
the ADRs ([`adr/`](./adr/)) as design decisions; the corresponding **threat** entries are published here
only once the mitigating slice (AS-2d / AS-2g / AS-2j) ships with its record, so this register never claims
a threat is closed before the control exists.

---

## 3. What stays trustworthy (plan §4.3)

The public entries rest on the decided trust invariants: a compromised unit cannot choose egress
or reach other units; an edge misroute fails closed; a compromised broker sees ciphertext only
while locked origins hold; and host root does not reach the owner or release roots. These are the
fixed-state properties the mitigations above preserve.

---

## 4. §4.7 publication policy

This register exists because plan §4.7 splits AEGIS threat documentation into a **public** half
and a **private** half, and this repository is the public one.

- **Public (here):** `aegis-threat-model.json` and `aegis-threat-model.md` — **fixed state only**.
  A row is published only when its mitigation is a decided, committed architecture decision or a
  shipped control. Each row is written as the *decision* and the *mitigation*.
- **Private:** open / un-mitigated entries, held in the private handoff register (vigil-handoff),
  per plan §4.7 (HANDOFF:83). They are intentionally absent here. The JSON records this in its
  top-level `private_register_note`.
- **Drift test:** plan §4.7 requires a drift test asserting every threat id exists in exactly one
  of the two registers (public or private), so nothing is silently dropped.
- **`mitigated` needs a record (line 639):** plan §4.7 states an entry may be marked `mitigated`
  only with a *current record*. This AS-0 publication is strict about it: a threat appears here only
  when its control is **shipped on `main`** and carries an engineering record (`record_ref`). The
  two published entries carry **`AS-27a / PR#1228`** — the break-glass fixes (first gateway PR),
  covered by `test_gateway_breakglass.py`; their signed AS-25 demonstration **drill** is scheduled
  for AS-29 / TB5. A threat whose mitigation is only *decided* (an ADR) but not yet shipped is **not
  published here** — it stays in the private register until its slice ships, so the public register
  never implies a threat is closed before the control exists.

No open weakness is disclosed: every public row is a shipped, recorded control.

---

## 5. Validation

`framework/v2/aegis/tests/test_aegis_threat_model.py` loads the JSON and asserts: it parses;
every entry carries the required fields (`id`, `title`, `zone`, `attacker`, `vector`, `status`,
`mitigation`, `record_ref`); **every public entry has `status == "mitigated"` and a non-empty
`record_ref`** (the §4.7 fixed-state invariant); ids are unique; the top-level
`private_register_note` is present; and this Markdown names every JSON id.

Run it from the engine root:

```
cd engine/crucible
python3 -m pytest framework/v2/aegis/tests/test_aegis_threat_model.py -q
```
