export const meta = {
  name: 'adversarial-sweep',
  description: 'Independent multi-lens adversarial re-attack of a defensive-oracle domain — the FORGE stage-9 companion to RED-PEN. Attack from disjoint lenses, refute each objection with a real repro, report only what survives.',
  whenToUse: 'Before merging any AEGIS/FORGE domain stream, alongside (not instead of) the red-pen agent. Pass the domain spec via args. On the email-auth stream it caught 3 CRITICAL/LOW defects PAST a RED-PEN PASS — near-zero-FP cannot be self-certified by one reviewer.',
  phases: [
    { title: 'Attack', detail: 'independent lenses hunt the reviewed SHA' },
    { title: 'Verify', detail: 'refute each objection with a real, executed repro' },
  ],
}

// ---------------------------------------------------------------------------
// args (all optional except sha + claim + cardinal_rule + benign_twin):
//   {
//     sha:            "<git sha under review>",              // REQUIRED — the exact commit
//     root:           "/home/kali/Pictures/PENTEST-main",     // repo root (default)
//     domain:         "Domain N — <name>",                    // human label
//     oracle_paths:   "verify/oracles.py::x_oracle, verify/x.py (seam), sensors/x.py (sensor)",
//     claim:          "what a FIRED FACT asserts",            // REQUIRED
//     cardinal_rule:  "the benign/hardened input that must NEVER fire",  // REQUIRED
//     benign_twin:    "the concrete correctly-configured input the oracle must stay silent on", // REQUIRED
//     producer_path:  "parse_x -> ingest_x -> confirm_x",     // the REAL end-to-end path to drive
//     test_command:   "python3 -m pytest framework/v2/verify/tests/test_x.py -q",
//     fault_line:     "prior defects on this domain's fault line, if any (helps the hunt)",
//     has_fusion:     true,                                    // run the fusion-promotion lens
//     extra_lenses:   [{key,prompt}]                           // domain-specific lenses to add
//   }
// ---------------------------------------------------------------------------

const A = (args && typeof args === 'object') ? args : {}
const ROOT = A.root || '/home/kali/Pictures/PENTEST-main'
const SHA = A.sha || 'HEAD'
const DOMAIN = A.domain || 'the domain under review'
const CLAIM = A.claim || 'a defensive fact the oracle proves from retained evidence'
const CARDINAL = A.cardinal_rule || 'a genuinely benign/hardened/compliant input must NEVER produce a FACT'
const TWIN = A.benign_twin || 'a correctly-configured input the oracle must stay silent on'
const PRODUCER = A.producer_path || 'the sensor -> ingest -> oracle path'
const TESTCMD = A.test_command || 'python3 -m pytest -q'
const FAULT = A.fault_line || 'none recorded — assume the classic fault line: asserting from a transform not verified lossless (reading a failed/ambiguous parse as absence, a lossy normalize as a clean value, or a producer that drops the evidence a guard needs).'
const HAS_FUSION = A.has_fusion === true

const CONTEXT = [
  'You are an INDEPENDENT adversarial reviewer of CRUCIBLE/AEGIS, an authorized owner-testing security engine, at ' + ROOT + '.',
  'You run ALONGSIDE the red-pen agent, from a DISJOINT attack model — a single reviewer has been empirically insufficient on near-zero-FP oracles (one such oracle took 8 defects across two reviewers, 3 caught by THIS harness past a red-pen PASS).',
  '',
  'UNDER REVIEW: ' + DOMAIN + ' @ commit ' + SHA + '.',
  A.oracle_paths ? ('CODE: ' + A.oracle_paths) : '',
  'Run the suite: cd ' + ROOT + ' && ' + TESTCMD,
  'Probe EMPIRICALLY — a claim without a reproduced input+output is worthless. Drive the REAL end-to-end path (' + PRODUCER + '), never a hand-built control (a guard is only as real as its reachability from the producer).',
  '',
  'WHAT A FIRED FACT CLAIMS: ' + CLAIM,
  '',
  'CARDINAL RULE — NEAR-ZERO FALSE POSITIVES. ' + CARDINAL + '. A FACT a benign/hardened input can trigger is CRITICAL and always real. Refusing to adjudicate is ALWAYS sound; asserting from an ambiguity never is. False negatives are acceptable UNLESS a rule goes inert on common real input. PROVE, DON\'T GUESS.',
  'THE BENIGN TWIN: ' + TWIN,
  'FAULT-LINE HISTORY: ' + FAULT,
].filter(Boolean).join('\n')

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    findings: { type: 'array', items: { type: 'object', properties: {
      title: { type: 'string' }, severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] },
      repro: { type: 'string' }, why_it_matters: { type: 'string' },
    }, required: ['title', 'severity', 'repro', 'why_it_matters'] } },
    attacked_and_held: { type: 'array', items: { type: 'string' } },
  }, required: ['findings', 'attacked_and_held'],
}
const VERDICT_SCHEMA = {
  type: 'object',
  properties: { is_real: { type: 'boolean' }, reasoning: { type: 'string' }, confirmed_repro_output: { type: 'string' } },
  required: ['is_real', 'reasoning'],
}

const BASE_LENSES = [
  { key: 'benign-twin-fp', prompt: 'THE CARDINAL LENS (highest priority). Your ONLY goal: make a GENUINELY BENIGN / HARDENED / COMPLIANT input FIRE a FACT. Enumerate the input GRAMMAR — every encoding, whitespace/case/unicode form, presentation vs wire form, escape/quoting, multiplicity/ordering, boundary and mid-token split — and drive each end-to-end through the real path. The benign twin (' + TWIN + ') and every faithful re-encoding of it must produce NO fact. Report EVERY benign fire as CRITICAL. Build the twin from the input GRAMMAR, not from the axes the author already thought of — that is where every prior defect hid.' },
  { key: 'producer-transforms', prompt: 'THE TRANSFORM LENS. Attack EVERY transform between raw evidence and the oracle verdict — parse, normalize, decode, split, select, dedup, coerce. Route through the REAL producer (' + PRODUCER + '). (1) Can any lossy/ambiguous transform HIDE a protective signal or FABRICATE a permissive one so a benign input asserts? (2) Does the producer DROP evidence a downstream guard consumes (making a correct guard unreachable — test the guard THROUGH the producer, not hand-fed)? (3) Does a strict attestation/identity check get widened by an upstream coercion (e.g. bool("false")==True)? (4) Is any "absence"/negative asserted from a FAILED parse rather than an observed nothing? Every transform must be verified lossless or must REFUSE.' },
  { key: 'evidence-truth-roundtrip', prompt: 'THE EVIDENCE-TRUTH + ROUND-TRIP LENS. Every fired signal produces an evidence sentence + a retained context that get SIGNED and re-verified offline (a PCF certificate). (1) Is each fired sentence LITERALLY TRUE of the input that produced it — does it name a policy/state not actually in effect, or the WRONG subject? (2) ROUND-TRIP: does every grounded FACT re-derive from ITS OWN retained evidence (re-run the oracle over the exact retained context / world-model node it grounds onto)? Find any FACT that grounds onto a node whose retained evidence contradicts it, or that names/lands-on the wrong subject. (3) Does confidence match what was actually proven?' },
  { key: 'greenwash-and-next', prompt: 'THE GREEN-WASH + NEXT-INSTANCE LENS. (1) Read the domain\'s tests CRITICALLY. Are they real or vacuous — would each FAIL if the guard it targets regressed? Do they route through the REAL producer or hand-feed the oracle? Use `python3 -m coverage run --branch` + mutation testing (revert each load-bearing guard) and confirm the suite CATCHES each mutation; report any guard whose removal leaves the suite green. (2) THE NEXT INSTANCE: name the NEXT untested transform in the chain (JSON/parse, id/key construction, canonicalization/lowercasing collisions, projection, the PCF export) and attack it for a false or MIS-ATTRIBUTED FACT.' },
  { key: 'refuse-determinism-gate', prompt: 'THE TOTALITY / DETERMINISM / GATE LENS. (1) Is the oracle TOTAL — sweep pathological inputs (empty, huge, deeply-nested, every codepoint, malformed) and confirm it NEVER raises (a malformed input is a non-fact, not a crash). (2) DETERMINISM — run the oracle over a fixed corpus many times; the verdict/evidence digest must be identical (no wall-clock, no RNG, no IO in the proof path). (3) GATE — confirm `python3 -m framework.v2 benchmark --gate --no-incumbents` is byte-identical (9|0|0|1.000, 853 reqs, PASS) and the new kind is OUT of the frozen _ALL_ORACLES. (4) OFFENSIVE DRIFT — confirm the diff adds no network/mail/exec/offense; the sensor stays gated (Tier, capability, egress).' },
]
const FUSION_LENS = { key: 'fusion-promotion', prompt: 'THE FUSION LENS. If the domain promotes LEAD->FACT in the autonomous fusion loop, drive it via fuse_sensors. (a) can a benign/hardened input promote to a grounded FACT? (b) node keying — does the FACT land on the SAME node as its lead, carrying the record it was derived from (no orphan/duplicate/mis-attribution, incl. case/unicode/duplicate collisions)? (c) double-fuse idempotent? (d) grounded ONLY on a real oracle fire? (e) does the retained control round-trip the SAME fields the oracle judged? A benign promotion or a FACT on the wrong node is CRITICAL.' }

const EXTRA = Array.isArray(A.extra_lenses) ? A.extra_lenses.filter((l) => l && l.key && l.prompt) : []
const LENSES = BASE_LENSES.concat(HAS_FUSION ? [FUSION_LENS] : []).concat(EXTRA)

phase('Attack')
const rounds = await pipeline(
  LENSES,
  (lens) => agent(
    CONTEXT + '\n\n=== YOUR LENS: ' + lens.key + ' ===\n' + lens.prompt + '\n\n' +
    'Work EMPIRICALLY; paste inputs+outputs. Report ONLY reproduced defects; do not pad. An empty findings ' +
    'list PLUS a precise attacked_and_held list (name the exact property and the input that tested it) is the ' +
    'RIGHT answer when the code holds.',
    { label: 'attack:' + lens.key, phase: 'Attack', schema: FINDINGS_SCHEMA, effort: 'high' }
  ),
  (result, lens) => {
    if (!result || !result.findings?.length) return { lens: lens.key, verified: [], held: result?.attacked_and_held || [] }
    return parallel(result.findings.map((f) => () =>
      agent(
        CONTEXT + '\n\n=== REFUTE THIS OBJECTION ===\nTITLE: ' + f.title + '\nSEVERITY: ' + f.severity + '\n' +
        'REPRO: ' + f.repro + '\nWHY: ' + f.why_it_matters + '\n\nREFUTE it — RUN the claimed repro against the ' +
        'real code. Default is_real=false unless it reproduces EXACTLY as claimed AND is a real defect. Reject ' +
        'if: the input is garbage a real producer cannot emit; the behaviour is a safe REFUSAL not a false ' +
        'FACT; the verdict does not reproduce; or it is an acceptable false negative (not inert on common ' +
        'input). A false or MIS-ATTRIBUTED FACT on a benign/hardened input is always real and always CRITICAL. ' +
        'Paste the actual command output.',
        { label: 'verify:' + f.title.slice(0, 32), phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'high' }
      ).then((v) => ({ ...f, verdict: v }))
    )).then((verified) => ({ lens: lens.key, verified: verified.filter(Boolean).filter((f) => f.verdict?.is_real), held: result.attacked_and_held || [] }))
  }
)

const confirmed = rounds.filter(Boolean).flatMap((r) => r.verified || [])
const lensesRun = rounds.filter(Boolean).map((r) => r.lens)
const missing = LENSES.map((l) => l.key).filter((k) => !lensesRun.includes(k))
log(confirmed.length + ' confirmed defect(s); completed lenses: ' + lensesRun.join(', ') + '; MISSING (re-run these): ' + (missing.join(', ') || 'none'))

return {
  reviewed_sha: SHA,
  domain: DOMAIN,
  lenses_completed: lensesRun,
  lenses_missing: missing,          // a non-empty list means API failure — RE-RUN before trusting the verdict
  confirmed_defects: confirmed.map((f) => ({ lens: f.lens, title: f.title, severity: f.severity, repro: f.repro, reasoning: f.verdict?.reasoning })),
  properties_attacked_and_held: rounds.filter(Boolean).flatMap((r) => r.held || []),
  verdict: missing.length
    ? 'INCOMPLETE — ' + missing.length + ' lens(es) did not return (API failure); RE-RUN them, do NOT read this as ATTEST'
    : (confirmed.length === 0 ? 'ATTEST — no defect survived any lens' : 'BLOCK — ' + confirmed.length + ' defect(s) survived refutation'),
}
