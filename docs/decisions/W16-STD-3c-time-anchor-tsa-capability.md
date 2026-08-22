# W16-STD-3c — the RFC3161 time anchor is a CAPABILITY; independence needs an external TSA

Issue: [#529](https://github.com/thuram-nana/vigil-sovereign/issues/529) ·
Milestone: W16 — DECLARED-LIMITATION BURNDOWN.

## The claim (registered in the claims registry — [W0-3] #398, id `W16-STD-3c`)

<!-- CLAIM:W16-STD-3c -->
> **Registered claim (W0-3 #398):** The RFC3161 time-anchor mechanism is built and tested, but the default `LocalTSA` is a self-signed local authority that establishes the MECHANISM only — a CAPABILITY, NOT time-anchor independence (the same host mints and pins). Genuine "existed no-later-than T" independence requires the operator-configured external `RemoteTSA` (a third-party RFC3161 URL) or a public calendar; a fully-independent external TSA is not wired by default, so this is a capability, not an independence FACT.

## Why it is honestly stated (capability, not independence)

The W16 acceptance-box-4 honesty review found no registered claim for the time anchor even though the code
already carries the honest residual in prose. This registers it so the machine-checked registry pins the
distinction the module's own `HONEST VERDICT` docstring makes (TRUTHENOVATION Rule 1/3):

- `time_anchor.LocalTSA` is the DEFAULT and the CI test authority. It mints a REAL RFC3161 token over
  `transparency.checkpoint_hash`, is offline-verifiable, and (when present and verifiable against its pin)
  supersedes the quorum-median bound. But it is a *self-signed local* authority: the same host mints the
  token and pins the cert, so it proves the MECHANISM only and establishes NO independence.
- `time_anchor.RemoteTSA` is the supported external path — an operator-configured third-party RFC3161 URL
  with an out-of-band-PINNED cert. It is the INDEPENDENCE path and is present so the mechanism is
  production-ready, but its genuine independence cannot be exercised in an offline test, so no test (and no
  claim) pretends a local TSA establishes third-party independence.

Because a fully-independent external TSA is not wired by default, the claim states this plainly: the anchor
is a CAPABILITY, not a verified FACT of independence. Do NOT flip TRUTHENOVATION A1 to VERIFIED FACT for an
independence property a local TSA cannot establish.

Enforced by `integration/vigil_integration/time_anchor.py::LocalTSA` (with `RemoteTSA` as the independence
path); proved by `integration/tests/test_time_anchor.py` — the LocalTSA roundtrip mints a real, superseding,
signed-genTime token (the capability), and `test_remote_tsa_is_the_independence_path_and_is_present_but_offline`
asserts the third-party path is present and fails closed offline, so no offline test claims independence.
