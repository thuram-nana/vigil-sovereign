# W16-STD-4 (#530) — close the spine gaps

Four gaps observed on the reference host, each closed with a real fail-without-fix test + negative control.
The load-bearing logic lives in `apps/sigil/sigil/spine/health.py` (pure, backend-free), the cutover in
`apps/sigil/sigil/spine/prune.py` (`commit_prune`), and the surfaces in `cli.py` (`sigil doctor`,
`sigil spine prune`) and `mcp/server.py` (`memory_search`, `ingest_status`).

## Registered claims

<!-- CLAIM:W16-STD-4-A --> A SIGIL host that holds spine records but has no valid owner-signed head fails the health check.

The `signed_head` check in `sigil doctor` is REQUIRED: `_signed_head_doctor` runs `signed_head_health`,
which returns unhealthy when the spine holds records but `verify_checkpoint` finds no valid signed head. An
empty, never-signed box is advisory-OK (a pristine install, nothing to anchor yet), so a fresh checkout's
doctor stays green.

<!-- CLAIM:W16-STD-4-B --> A memory retrieval hit that does not resolve to a live signed spine record is refused at read time and never rendered.

`memory_search` resolves every vector hit back to a live signed record (the seq is present AND its
`entry_hash` matches) via `grounded_after_refusal`; an unresolvable hit — a projection point that outlived a
spine reset/prune, or a rebuilt point at a live seq with a mismatched hash — is dropped before rendering, and
grounding is judged only on the resolved set so a drifted high-score hit cannot masquerade as grounded.

<!-- CLAIM:W16-STD-4-C --> The vector projection is compared against the signed chain and reported as drift when it references a seq beyond the tip or holds more points than the chain has projectable records.

`projection_drift` compares the projection's point count and highest referenced seq against the signed
chain's projectable-record count and tip (`ingest_status` supplies them from the live index + spine). The
13,667-points-over-a-16-record-chain shape trips both signals; a projection that merely trails the chain
(stale-but-honest) is not falsely flagged.

<!-- CLAIM:W16-STD-4-D --> Opt-in content de-duplication on append returns an existing record's seq for byte-identical content without writing a new record, leaving the hash chain unchanged.

`SpineStore.append(dedup=True)` uses `_find_dedup` to look back a bounded window for a record with identical
PLAINTEXT content (keyed on the plaintext, not the seq-bound sealed `cert_digest`) and, on a hit, returns
that record's seq without writing. A dedup hit writes nothing, so the chain is byte-identical to a store
where the caller simply did not re-append. Default off — the append path is otherwise unchanged.

<!-- CLAIM:W16-STD-4-E --> The hard-prune cutover deletes the pruned prefix from the live spine crash-safely: a crash at any point recovers to the un-pruned or the pruned state, never a torn or lost chain, with the pruned prefix preserved in the owner-anchored archive.

`commit_prune` (Slice E) orders the cutover archive-copy+verify → append snapshot → SIGN THE PRUNED HEAD
(the durable commit) → rebase the manifest → delete the orphaned files. A crash before the head sign rolls
back to the un-pruned spine; a crash after it leaves a validly-signed pruned head that `verify()` /
`verify_checkpoint` honour whether or not the manifest+file GC has finished, and `finish_prune` completes the
GC idempotently. Proven by a kill-9-during-cutover fuzz (deterministic per-barrier crashes + random SIGKILL)
with a negative control that the recovery oracle detects a deleted retained record. It is behind three owner
gates: a valid owner-signed head (the cutover re-signs with the owner key), explicit `--yes` confirmation,
and the §7 referential-safety floors.
