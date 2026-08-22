# W8-4 — mirror-sync.sh is integration-tested (torn-sync + stale-mirror)

Status: accepted
Milestone: W8 — HIGH AVAILABILITY
Issue: #470

## Context

`tools/ha/mirror-sync.sh` MOVES live sovereign state (`~/.sigil`) from an active writer to a
read-only PASSIVE standby so an active-passive failover has a fresh, promotable copy. Until W8-4
only the guard's *decision core* (`tools/ha/spine_failover_guard.py`) was unit-tested; the script
that actually copies the state was untested. Two hazards the HA profile names were therefore
unexercised end-to-end: a copy interrupted mid-transfer (torn-sync), and a mirror whose off-box
witnessed anchor has aged past the freshness bound (stale-mirror).

## Decision

`apps/sigil/tests/test_ha_mirror_sync.py` runs a REAL `mirror-sync.sh delta` between two directories
(the two "hosts") and asserts three distinct properties, each with a negative control:

1. a clean delta transfers every file byte-for-byte, honours `--delete`, and stamps the read-only
   completion sentinel;
2. an interrupted copy (an injected mid-transfer `rsync` failure) leaves the mirror DETECTABLY
   incomplete — the script exits non-zero and never stamps the completion sentinel — never a
   silently-partial mirror marked ready; and
3. the stale-mirror safety property below.

## The registered claim

A passive whose off-box witnessed anchor is older than the freshness bound is refused promotion by the failover guard (STALE ANCHOR, exit 2) rather than silently promoted. <!-- CLAIM:W8-4 -->

This is enforced by `spine_failover_guard.evaluate_promotion` (its `freshness_verdict` gate) and proved
by the integration test, which feeds the guard the witnessed anchor that `mirror-sync.sh` actually
transported into the mirror: a stale clock is refused, a fresh clock on the same transported anchor
promotes.
