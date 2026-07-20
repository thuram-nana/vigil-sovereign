{
  "summary": "Map the SIGIL spine invariants, consumer read-surface, tamper-model conflict, and durability contract before designing snapshot/compaction",
  "agentCount": 10,
  "logs": [],
  "result": {
    "invariants": [
      {
        "name": "chain-anchored-from-genesis",
        "statement": "The FIRST entry of whatever set verify_chain / verify_head receives must have prev_hash == _GENESIS_PREV ('0'*64). verify_chain seeds prev=_GENESIS_PREV and rejects entries[0] if e.prev_hash != prev. Note the subtlety: verify_chain does NOT require entries[0].seq == 0 — only prev_hash==genesis + contiguity — so a rebased chain starting at seq k is chain-valid IF k's prev_hash is rewritten to genesis and hashes recomputed.",
        "enforced_at": "sigil/reuse/chain.py:38-41 (verify_chain, i=0 branch); depended on by sigil/reuse/chain.py:66-71 (verify_head), sigil/spine/checkpoint.py:96 (verify_head over entries[:signed_n]), sigil/spine/store.py:284-303 (verify)",
        "violation_failure_mode": "If a compaction drops records [0..k] and keeps the tail with its ORIGINAL prev_hash values, the first retained entry's prev_hash is the entry_hash of record k, not genesis → verify_chain returns False 'chain break at seq k: prev_hash mismatch (entry deleted/reordered)'. Every verify()/verify_checkpoint/SpineTailer.check_anchor then reports a false TAMPERING verdict permanently, and check_anchor fails closed.",
        "snapshot_impact": "The physical read-front after compaction must be genesis-anchored: either prepend a synthetic SNAPSHOT record whose prev_hash == _GENESIS_PREV (and whose cert_digest commits the pruned prefix's final entry_hash so history is bound by hash), or rewrite the earliest retained record's prev_hash to genesis and recompute its entry_hash. entries()/iter_records must present this genesis-anchored front to verify_chain."
      },
      {
        "name": "strict-seq-contiguity-no-gaps",
        "statement": "For every adjacent pair, seq[i] == seq[i-1] + 1. No gaps, no duplicates, no reordering.",
        "enforced_at": "sigil/reuse/chain.py:44-45 (verify_chain seq-gap check); reads skip malformed lines so a torn MIDDLE line becomes a gap surfaced here — sigil/spine/store.py:212-218 (iter_records skip), 372-378 (_scan_from skip)",
        "violation_failure_mode": "A compaction that removes an INTERIOR record (e.g. a superseded one) while keeping records on both sides leaves seq N-1 followed by seq N+1 → verify_chain returns False 'chain break: seq gap at N+1'. Manifests as a hard false TAMPERING on every verify; also the offset index and get(seq) will have a hole that routes to the fallback scan.",
        "snapshot_impact": "Compaction may only remove a CONTIGUOUS PREFIX [start..k] (segment/prefix truncation), never punch interior holes. If interior records must be reclaimed (e.g. superseded bodies), the seq must remain present as a tombstone/summary entry so contiguity holds, or the whole design must re-map to a snapshot that itself is contiguous from its new front."
      },
      {
        "name": "seq-is-immutable-primary-key (no renumbering)",
        "statement": "A record's seq is its permanent identity. entry_hash binds seq; parent_id/supersedes_id are seq references; all external cursors (SpineTailer.cursor, since_seq, get(seq), MCP episodic_range, graph node anchors, audit rows) address records by seq. Records must never be renumbered.",
        "enforced_at": "entry_hash derivation binds seq — sigil/reuse/chain.py:15-16, sigil/spine/verify.py:34; seq references — sigil/spine/models.py:35-36 (parent_id/supersedes_id), sigil/spine/store.py:220-242 (get), 270-272 (next_seq), sigil/spine/tail.py:56-57,78 (cursor); graph anchors — sigil/graph/rebuild.py:174, sigil/graph/query.py:87",
        "violation_failure_mode": "If compaction renumbers retained records to restart at 0, every entry_hash must be recomputed (invalidating every prior signed head), every parent_id/supersedes_id/graph-node/cursor reference dangles or points at the wrong record, and next_seq/get() return silently wrong records. A live SpineTailer cursor set to an old seq would re-emit or skip. Silent corruption, not a crash.",
        "snapshot_impact": "Preserve original seq numbers across compaction. verify_chain tolerates a first seq != 0, so a rebased front can keep its true high seq (e.g. 40000) with prev_hash rewritten to genesis. Never compact by re-basing seq to 0."
      },
      {
        "name": "signed-head-entry_count-is-the-anti-truncation-gate",
        "statement": "The owner-signed head records entry_count and last_seq over the exact prefix it signed. classify_head treats len(entries) < head.entry_count as TAMPERING; verify_head requires head.entry_count == len(entries), head.last_seq == entries[-1].seq, head.head_hash == entries[-1].entry_hash. This is THE central conflict: legitimate pruning reduces len(entries) below a stale head's entry_count and is indistinguishable from a rollback/truncation attack.",
        "enforced_at": "sigil/spine/checkpoint.py:93-94 (n < signed_n → TAMPERING), 96 (verify_head over entries[:signed_n]); sigil/reuse/chain.py:73-74 (head-vs-chain equality)",
        "violation_failure_mode": "Compaction prunes the prefix but the on-disk signed head still anchors the old (larger) entry_count → verify_checkpoint/classify_head/SpineTailer.check_anchor all report 'TAMPERING: chain has N records but the signed head anchors M (truncated/rolled back)'. The UI/mobile mark the spine tamper-broken; the fresh tail shows anchored=False forever.",
        "snapshot_impact": "Compaction MUST be an owner-key operation that IMMEDIATELY re-signs a fresh head whose entry_count == the new physical entry set (snapshot record + retained tail) and whose head_hash == the new tip's entry_hash, written atomically. The head model / classify_head must be extended to understand a snapshot base so a legitimately compacted chain (fewer physical records, same last_seq) is accepted rather than flagged. Until re-signed, the old head correctly makes any prune look like tampering — that property is a feature (it blocks a keyless attacker) and must be retained."
      },
      {
        "name": "monotonic-last_seq-anti-rollback (durable via head, process-local via high-water)",
        "statement": "last_seq / the chain tip seq must never decrease. verify_head rejects head.last_seq < prev_highwater; SpineTailer flags on-disk head_seq < in-memory monotonic high-water. The DURABLE anti-rollback across restarts is the head's last_seq/entry_count vs the on-disk chain (the SpineTailer high-water resets to -1 each process).",
        "enforced_at": "sigil/reuse/chain.py:78-79 (prev_highwater gate); sigil/spine/tail.py:60,90-93 (process-local _high_water); sigil/spine/checkpoint.py:93 (entry_count as durable water mark)",
        "violation_failure_mode": "A compaction that removes TAIL (high-seq) records, or that re-signs a head with a lowered last_seq, is a rollback: check_anchor returns rollback set / verify_head 'rollback rejected'. If instead compaction silently lowers last_seq without tripping any gate (e.g. resets the seq counter), an attacker's tail rollback becomes indistinguishable from compaction and slips through — records acked to consumers vanish.",
        "snapshot_impact": "Compaction must reclaim only OLD/low-seq records and MUST preserve the maximum seq (last_seq) exactly; a re-signed head's last_seq must equal the true current tip, never regress. Prefix pruning reduces entry_count but must hold last_seq constant. Consider persisting the high-water so restart-time rollback detection survives a crash-during-compaction."
      },
      {
        "name": "append-only / offsets-never-move / no-in-place-rewrite",
        "statement": "Committed bytes never move or change; append() only adds at EOF; the seq→offset index only EXTENDS on growth and REBUILDS only on shrink. classify_head relies on 'append-only ⇒ the prefix is byte-identical' to reuse entries[:signed_n]. Lock-free readers open their own fd and stream forward, tolerating a concurrent append precisely because existing bytes are immutable.",
        "enforced_at": "sigil/spine/store.py:157-194 (append at EOF), 330-351 (_ensure_index: grew→extend, shrank→rebuild), 353-382 (_scan_from); readers 197-218, 244-268; checkpoint.py:95 comment (byte-identical prefix)",
        "violation_failure_mode": "A compaction that rewrites the spine file IN PLACE while a lock-free reader is mid-stream gives that reader a torn view (old head + new tail) → parse errors skipped, seq gaps, false verify() failure, or wrong get() results. Worse, _ensure_index detects change only by file SIZE: an in-place rewrite that leaves the byte size unchanged (or grows it) is UNDETECTED — the index extends from a stale _scan_pos over relocated content, so get(seq) seeks to a wrong offset and silently returns the wrong record or None.",
        "snapshot_impact": "Never rewrite the spine in place. Build the compacted file/new segment fully, fsync it, then atomically os.replace() it into position (as checkpoint._atomic_write_text does for the head) so a lock-free reader sees either the whole old or whole new file. Any store instance whose backing file changed must invalidate/rebuild its in-memory index (size-only change detection is insufficient — force a rebuild signal, e.g. via an epoch/generation counter)."
      },
      {
        "name": "torn-tail-truncation-before-append (BLOCK-1)",
        "statement": "Bytes past the last VALID newline-terminated record are never-committed garbage from an interrupted write; append() locates the last valid boundary and truncates the dead tail BEFORE writing, so a new record cannot merge with torn bytes into one unparseable line and be silently lost. Committed records are never touched by this truncate.",
        "enforced_at": "sigil/spine/store.py:83-121 (_last_valid_boundary), 168-173 (truncate to clean_end before write), 50-80 (_last_nonempty_line skips torn tail on read); MEMORY: BLOCK-1 was a real acked-record loss (incl. a missed panic)",
        "violation_failure_mode": "If a segment/snapshot scheme appends to the wrong file, or computes the clean boundary against a stale/other segment, the truncate either (a) fails to remove a torn tail → the new record merges with garbage and is silently lost while verify() stays green (a lost kill-switch panic never halts the mesh), or (b) truncates against a wrong boundary and deletes COMMITTED records.",
        "snapshot_impact": "Preserve truncate-before-append on whatever segment is the ACTIVE (head) append target; _last_valid_boundary must be evaluated on that exact file under the append lock. Compaction must reliably distinguish a torn tail (removable, un-newline-terminated / fails _REQUIRED_KEYS) from committed records (must survive) — never treat a committed record as torn."
      },
      {
        "name": "fsync durability of acked appends and head swap",
        "statement": "An acknowledged append is durable across a crash (fsync the data fd); the signed head is replaced durably+atomically (write temp, fsync temp, os.replace, fsync the directory) so a crash never leaves a torn head and a reader sees old-or-new, never partial.",
        "enforced_at": "sigil/spine/store.py:182-183 (flush+fsync after write); sigil/spine/checkpoint.py:33-60 (_atomic_write_text: fsync file + dir), 83 (atomic head write)",
        "violation_failure_mode": "A snapshot swap or segment rotation that renames/creates files without fsync'ing the new file AND its directory can, after a crash, present a spine whose data is durable but whose head rename was lost — or a half-materialized compacted file. On restart the head/chain mismatch reads as truncation → false TAMPERING, or an acked record that was mid-migration is lost silently.",
        "snapshot_impact": "Every compaction output (new segment, snapshot record, rewritten front, new head) must be fsync'd and swapped in via an atomic, directory-fsync'd rename, ordered so that at no crash point can the chain be non-verifiable: write+fsync new data, then atomically publish the new head last (head is the commit point)."
      },
      {
        "name": "seq→offset index extend/rebuild correctness under external mutation",
        "statement": "The index is built lazily, kept O(1)-current on our own appends, EXTENDED forward when a stat shows the file grew (another process appended — offsets never move), and fully REBUILT when the file shrank/was rewritten smaller. Full scans (verify/count/entries/iter_records(-1)) never consult the index and stay a single byte-identical pass.",
        "enforced_at": "sigil/spine/store.py:130-138, 187-192 (own-append fast path), 315-352 (_start_offset_for / _ensure_index grew|shrank), 353-382 (_scan_from)",
        "violation_failure_mode": "Detection is size-only. A compaction in another process that shrinks the file triggers a correct rebuild — fine. But a same-size or larger in-place mutation is read as 'grew' and _scan_from extends from a stale _scan_pos over content that moved, poisoning every offset it records → get(seq)/iter_records(since_seq>=0) return wrong records or None with no error. Also the own-append fast path (line 188 `_scan_pos == offset`) assumes no external mutation between reads; a compaction mid-session breaks that assumption.",
        "snapshot_impact": "Prefer append-only segment rotation over any in-place rewrite. When the backing file/segment set changes, force index invalidation on all live store instances (e.g. an mtime+size+generation epoch, not size alone). If segments are introduced, the index must key (segment, offset) and the extend/rebuild logic must span the active segment only while treating sealed segments as immutable."
      },
      {
        "name": "replay-stable content digest (ts excluded)",
        "statement": "cert_digest = sha256(canonical_json(content)) over scope/kind/source/actor/payload/parent_id/supersedes_id ONLY — the wallclock ts is excluded, so the chain is replay-stable. Two records with identical content but different ts share a cert_digest but differ in entry_hash (which binds seq+prev).",
        "enforced_at": "sigil/spine/store.py:146-150 (content excludes ts), sigil/spine/models.py:20-22,27-28 (ts informational), sigil/reuse/canonical.py:17-30 (canonical_json/digest_payload), sigil/spine/verify.py:28-33 (binding uses same content)",
        "violation_failure_mode": "If a snapshot/summary record computes its cert_digest over content that includes ts (or in a non-canonical form), its binding check (digest_payload(content) == cert_digest) fails → verify() 'binding break' false TAMPERING. If a compaction 'manifest' is stored off-chain rather than as a properly-digested spine record, the removed history is not bound by the chain at all.",
        "snapshot_impact": "Any snapshot/tombstone/manifest record must be created via the same append() content shape (ts-excluded, canonical_json) so it binds and chains. The snapshot's payload should commit the pruned prefix by hash (e.g. the final pruned entry_hash + count) so removed history remains bound and reconstructible, using only wallclock-free, canonical bytes."
      },
      {
        "name": "two-layer unkeyed integrity vs the keyed signed head (compactor is a recompute-capable writer)",
        "statement": "verify()/verify_record enforce UNKEYED consistency (binding: payload→cert_digest; chain: entry_hash derivation + linkage). These catch corruption and naive tamper but CANNOT resist a writer who recomputes cert_digest+entry_hash (a tip tamper or forward-cascaded fork stays self-consistent). Only the owner-Ed25519-SIGNED head provides tamper-EVIDENCE. A compaction agent is exactly such a recompute-capable writer.",
        "enforced_at": "sigil/spine/store.py:284-303 (verify two-layer + honesty note), sigil/spine/verify.py:14-19 (scope honesty), sigil/spine/tail.py:1-22 (integrity_ok vs anchored), sigil/spine/checkpoint.py:87-101 (classify_head keyed)",
        "violation_failure_mode": "A compaction can produce a chain that passes verify() (self-consistent) while having silently dropped or altered records — verify() alone would NOT flag it. If the design relies on verify()/verify_record to certify a compaction, an unauthorized or buggy prune goes undetected until (and unless) the signed head catches the entry_count/last_seq mismatch.",
        "snapshot_impact": "Compaction must be gated by the owner key: it re-anchors with a fresh owner-signed head, and the pruned prefix must be committed by a signed snapshot so 'records removed' is provable and authorized, never indistinguishable from tampering. Do not let the unkeyed layer be the sole certifier of a compaction; the keyed head is the authority (mirrors the existing doctrine)."
      },
      {
        "name": "read-path abstraction must present ONE contiguous chain from genesis (entries/iter_records span all data)",
        "statement": "entries(), verify(), count(), iter_records(-1) iterate the full log from byte 0 and hand verify_chain a single contiguous, genesis-anchored, seq-ordered sequence.",
        "enforced_at": "sigil/spine/store.py:197-218 (iter_records from 0), 274-282 (count/entries), 284-303 (verify feeds verify_chain); consumers sigil/bridge/envelope.py:88-104 (full-scan high-water), sigil/graph/rebuild.py, sigil/audit.py:17-33",
        "violation_failure_mode": "In a segment-rotation design, if entries()/iter_records read only the active segment (or read segments out of seq order, or with a boundary gap/overlap), verify_chain sees a chain that doesn't start at genesis or has a seq gap at a segment seam → false TAMPERING; count() undercounts; full-scan consumers (device_nonce_highwater, graph rebuild) miss records.",
        "snapshot_impact": "The store's read API must transparently concatenate the snapshot front + all sealed segments + the active segment in seq order, seamlessly across boundaries (no gap, no dup at a seam), so every existing full-scan caller keeps seeing one contiguous genesis-anchored chain without change."
      },
      {
        "name": "durable tip determines next_seq across restart (no seq reuse)",
        "statement": "On construction the store reads the last valid line to seed self._last; next_seq = self._last.seq + 1. This must reflect the true global maximum seq ever appended so seq numbers are never reused.",
        "enforced_at": "sigil/spine/store.py:138 (_read_last_entry at init), 305-312 (_read_last_entry), 270-272 (next_seq)",
        "violation_failure_mode": "If a segment/snapshot scheme leaves the tip in a file _read_last_entry doesn't consult (it reads only self.path), next_seq regresses; the next append reuses a live seq → duplicate seq, entry_hash fork, verify_chain contiguity/linkage break, and a replay/nonce high-water (derived from receipts) that can be defeated. A forked chain.",
        "snapshot_impact": "_read_last_entry / next_seq must resolve the tip from the ACTIVE segment (the true global max seq), never a sealed/snapshot file. The append lock's tip re-read (store.py:168-174) must likewise target the active segment so concurrent writers can't fork from a stale tip."
      },
      {
        "name": "cross-writer serialization (spine_lock + flock) must cover the compactor",
        "statement": "The whole read-tip→truncate→write is serialized by a process-wide re-entrant spine_lock plus a cross-process advisory flock, so concurrent writers can't fork the chain off a stale tip. Compaction mutates the same file and is itself a writer.",
        "enforced_at": "sigil/spine/store.py:37-47 (spine_lock), 154-160 (lock + flock around append); re-entrancy relied on by sigil/bridge/envelope.py:127-133 (atomic check-then-receipt)",
        "violation_failure_mode": "If compaction rewrites/rotates segments WITHOUT holding spine_lock+flock, an append running concurrently reads a tip that compaction is about to relocate or truncate → two divergent chains / a lost or duplicated record. Also the re-entrant nonce replay gate (check highwater + receipt) could interleave with a prune of the very receipts it reads, reopening a replay window.",
        "snapshot_impact": "Compaction must acquire the same spine_lock and flock as append for the duration of any tip-affecting mutation and swap, and must be atomic w.r.t. lock-free readers (build-then-os.replace). Pruning of state-bearing records (receipts) must be serialized against the consumers that scan them."
      },
      {
        "name": "monotonic-state derived by full scan must survive pruning (replay high-water, graph cursor)",
        "statement": "Several security-relevant monotonic values are reconstructed by scanning ALL spine records at read time, not stored separately: the per-device nonce replay high-water (max receipted nonce) and the graph/replay rebuilt_seq high-water. Pruning the records these scans read silently lowers the reconstructed value.",
        "enforced_at": "sigil/bridge/envelope.py:88-104 (device_nonce_highwater full scan), 107-133 (consume uses it to reject replay); sigil/graph/rebuild.py:174 (manifest replay high-water); sigil/audit.py:17-33 (audit trail by scan)",
        "violation_failure_mode": "If compaction prunes old RECEIPT_SIGNAL records, device_nonce_highwater drops (or returns -1) → a previously-consumed effectful envelope with a lower nonce is accepted again: a replay of a captured device command (approve/arm/panic) succeeds. This is a silent SECURITY regression that no integrity check flags — the chain still verifies.",
        "snapshot_impact": "Compaction must not lose the monotonic state carried by pruned records. Fold each device's max nonce (and rebuilt_seq, and any similar high-water) into the signed snapshot record so the reconstruction floor is preserved, and make device_nonce_highwater seed from the snapshot's carried high-water rather than from -1. Audit-trail continuity likewise must survive (or be summarized in) the snapshot."
      },
      {
        "name": "referential integrity of parent_id / supersedes_id across a prune",
        "statement": "parent_id and supersedes_id are seq references into the spine; supersession is the natural signal that an older record is a compaction candidate. Retained records must not dangle to pruned targets, and the supersession relationship must remain resolvable.",
        "enforced_at": "sigil/spine/models.py:35-36 (fields), sigil/spine/store.py:141-149,177 (set at append, digested into cert_digest), sigil/agents/base.py:85-98 (agents set parent_id/supersedes_id), sigil/mcp/server.py:96 (surfaced)",
        "violation_failure_mode": "If compaction prunes a record still referenced by a retained record's parent_id/supersedes_id, the reference dangles — get() returns None mid-graph-rebuild, episodic_range around an anchor loses context, and a superseded-by chain can't be walked. Because parent_id/supersedes_id are part of the digested content, they cannot be edited to re-point without breaking that record's binding (false TAMPERING).",
        "snapshot_impact": "Only prune records whose supersession/parent relationships are fully closed within the pruned prefix, or record the resolution (final superseding seq) in the snapshot manifest so references remain answerable. Never mutate a retained record's parent_id/supersedes_id (it would break its cert_digest binding)."
      },
      {
        "name": "canonical/domain primitives are frozen (no digest or signing-form drift)",
        "statement": "canonical_json (sorted keys, compact separators, UTF-8) and the _EVIDENCE_DOMAIN tag are frozen; changing them invalidates every existing signature and digest. entry_hash inputs are exactly {cert_digest, prev_hash, seq}. verify_record/verify reuse the same _entry_hash and digest_payload as the enforced write path — never a re-implementation.",
        "enforced_at": "sigil/reuse/canonical.py:14 (domain tag 'never change without a schema bump + migration'), 17-35; sigil/reuse/chain.py:15-16 (_entry_hash inputs); sigil/spine/verify.py:22-23,34 (reuse verbatim)",
        "violation_failure_mode": "If a snapshot introduces a new record type or head format that digests/signs over a different canonical form or domain, its binding/signature won't verify against the existing verify_record/verify_head path → false TAMPERING or an unverifiable head; or, if verify logic is re-implemented for snapshots, it can drift from the enforced path and accept what the real path would reject.",
        "snapshot_impact": "Snapshot records, manifests, and any new head must digest/sign using the identical canonical_json + _EVIDENCE_DOMAIN + _entry_hash primitives, computed by the same reuse functions. Any head/schema extension needs a schema_version bump with an explicit migration, not a silent format change."
      },
      {
        "name": "single verifiable signed head is the commit point",
        "statement": "There is exactly one signed head at HEAD_PATH; verify_checkpoint/classify_head/SpineTailer load that one head and judge the whole chain against its entry_count/last_seq/head_hash. It is written atomically as the last, committing step.",
        "enforced_at": "sigil/config.py:54 (HEAD_PATH single file); sigil/spine/checkpoint.py:79-84 (checkpoint writes one head), 104-109 (verify_checkpoint loads one), sigil/spine/tail.py:110-119 (_resolve_head loads one)",
        "violation_failure_mode": "A snapshot design that needs to attest BOTH the pruned prefix and the current tip but still emits a single flat head cannot express 'records [0..k] are covered by a signed snapshot, [k+1..N] by the live tail' — classify_head's n-vs-entry_count logic will either flag the compacted chain as truncated or, if entry_count is naively lowered, lose the ability to prove the pruned prefix ever existed.",
        "snapshot_impact": "Extend the head/anchor model coherently: a single signed head must carry a snapshot base (base_seq, snapshot_hash committing the pruned prefix) alongside entry_count/last_seq of the retained physical set, and classify_head must be taught to accept 'physical entries == retained set, logical coverage == base..last_seq'. Keep it ONE atomically-published head so there is a single commit point and a single fail-closed verdict."
      },
      {
        "name": "genesis-vs-empty and count semantics for a compacted store",
        "statement": "verify_head/sign_head treat an empty chain specially (head_hash = _GENESIS_PREV, last_seq/entry_count = 0), and next_seq is 0 for an empty store. count() and entry_count reflect PHYSICAL records present.",
        "enforced_at": "sigil/reuse/chain.py:31-32,57-58,71-72 (empty-chain genesis defaults), sigil/spine/store.py:271-272 (next_seq 0 when no _last), 274-275 (count)",
        "violation_failure_mode": "If compaction empties the physical file down to just a snapshot record, naive code paths that special-case len==0 (genesis) could misread a snapshot-only front as an empty/new spine (last_seq→0), silently resetting next_seq to 0 and enabling seq reuse and rollback. Or count() (physical) vs the logical record total diverge and mislead consumers/dashboards.",
        "snapshot_impact": "A compacted store is never 'empty' — its snapshot record defines a non-zero logical base. next_seq, last_seq, and the empty-vs-genesis branches must derive from the snapshot base, not from physical len==0. Decide and document count() semantics (physical vs logical) and update every consumer (mcp ingest_status spine_records, dashboards) accordingly."
      }
    ],
    "consumers": [
      {
        "file": "sigil/graph/rebuild.py",
        "spine_calls": "SpineStore() constructed L120; store.iter_records() FULL scan with no since_seq in _accumulate L55; store.next_seq read L171 (spine_head_seq). Reads r.seq/r.entry_hash/r.kind/r.payload/r.ts/r.actor only. Does NOT call get(). Writes a kuzu db + STAGING/manifest.json (L177) and atomically swaps CURRENT — none of that is the spine.",
        "reads_raw_file": false,
        "assumes_seq_is_line_or_zero_based": false,
        "does_full_scan": true,
        "appends": false,
        "depends_on_old_seq_resolving": true,
        "risk_note": "CENTRAL CONFLICT for prune. rebuild() fully replays the entire spine (iter_records with no cursor) to reconstruct the whole graph; it holds no assumption of contiguity or 0-start (max_seq=r.seq is a value, first_seq/last_seq/anchor_seq are recorded values, no range(count)/positional indexing), so a seq GAP does not crash it. But it NEEDS every historical record present in the live file to mint the corresponding Session/Document/Commit node: a prune of old records silently SHRINKS the graph (old sessions/commits/documents vanish) with no error. Every node also stores anchor_seq+anchor_hash of its minting record; after a prune those seqs no longer resolve, so the graph's own citations dangle. in_sync (rebuilt_seq==next_seq-1) still holds after a prune (head seq unchanged), so mirror-health would falsely read GREEN while the view lost history. A snapshot/segment design MUST let rebuild replay from a compaction snapshot + live segments, or the graph loses everything below the prune point. Not segment-transparent: SpineStore.iter_records must be made to span all segments for this full replay."
      },
      {
        "file": "sigil/graph/query.py",
        "spine_calls": "Reads the kuzu current/ db (read-only), NOT the spine, for query()/entity()/most of health(). Only spine touch: health() constructs SpineStore() and reads .next_seq L117 (spine_head_seq). Reads CURRENT/manifest.json via read_text L116 (sidecar, not the spine). Does NOT call iter_records/get/tail/count.",
        "reads_raw_file": false,
        "assumes_seq_is_line_or_zero_based": false,
        "does_full_scan": false,
        "appends": false,
        "depends_on_old_seq_resolving": false,
        "risk_note": "Segment-transparent for its own operation: it queries the rebuilt kuzu graph and only ever asks the spine for next_seq (a head value, prune-safe). No contiguity/0-start assumption. HOWEVER its OUTPUT is a citation contract: entity() returns anchor_seq, first_seq, last_seq (e.g. Session L84) and the Session branch's hint explicitly tells the caller to `episodic_range(start_seq=first_seq, end_seq=last_seq)`. A prune that removes those old seqs from the live file makes every such returned citation unresolvable downstream even though query.py itself never crashes. So query is safe to run but propagates dangling seq references that a prune creates."
      },
      {
        "file": "sigil/vectors/index.py",
        "spine_calls": "index_spine(store, since_seq) calls store.iter_records(since_seq=since_seq) L148 — INCREMENTAL, driven by an external cursor. Uses r.seq (as the Qdrant point id, id=r.seq L136), r.kind, r.source, r.actor, r.payload, r.ts, r.entry_hash, r.text(). Does NOT call get(). last_indexed_seq()/count()/search() talk to Qdrant, not the spine. The durable cursor lives in Qdrant (max seq via OrderBy), not in the spine.",
        "reads_raw_file": false,
        "assumes_seq_is_line_or_zero_based": false,
        "does_full_scan": true,
        "appends": false,
        "depends_on_old_seq_resolving": false,
        "risk_note": "Mostly prune-robust. Steady state is incremental (since_seq = highest-indexed seq from Qdrant); a full scan (iter_records since_seq=-1) happens only on cold-start or after reset(). id=r.seq is used as an idempotent upsert key (a VALUE), NOT a positional/array index, and only EMBEDDABLE_KINDS are indexed so the indexed-seq set is ALREADY sparse/gappy — proving no contiguity assumption. Because embeddings persist independently in Qdrant, a prune of old spine records does NOT break the index and does NOT lower the cursor, so incremental indexing keeps working. TWO caveats for a prune/segment design: (1) search payloads carry seq+entry_hash as citations, so hits pointing at pruned records become unresolvable in the spine (same dangling-citation issue as query.py); (2) reset() (used when the embed policy changes) drops the collection and re-embeds via iter_records — after a prune it can NEVER rebuild vectors for pruned records, so a policy change would permanently lose recall over pruned history. A snapshot must retain re-embeddable text if reset()-after-prune is to stay lossless."
      },
      {
        "file": "sigil/consolidate/pipeline.py",
        "spine_calls": "SpineStore() L69; store.next_seq L70 (head_before, to avoid feeding its own promotions); store.iter_records(since_seq=since) L73 — INCREMENTAL, cursor-driven. Passes store (+ window_seqs, a set of RECENT batch seqs) into admit() L80 (gate re-executes over those recent seqs). promote_all(store, admitted) L90 and write_brief(store) L94 APPEND records via store. checkpoint(store) L97 re-signs the owner head. Own cursor is CACHE_DIR/consolidate_cursor.json (read_text L48), a sidecar, not the spine.",
        "reads_raw_file": false,
        "assumes_seq_is_line_or_zero_based": false,
        "does_full_scan": true,
        "appends": true,
        "depends_on_old_seq_resolving": false,
        "risk_note": "Incremental forward WRITER. window is bounded to seq>cursor AND seq<=head_before, so it never needs old/pruned seqs (cursor -1 forces a one-time full scan only on first run); window_from/window_to are seq VALUES, head_before=next_seq-1, no positional/contiguity assumption. A prune of records BELOW the cursor does not affect the window it reads. The prune-relevant interaction is checkpoint(store) at L97: it re-signs the head under the current model where classify_head treats len(entries) < head.entry_count as TAMPERING — i.e. exactly the invariant that makes a legitimate prune indistinguishable from a rollback. The compaction work must teach checkpoint/classify_head about the snapshot boundary before this call can coexist with pruning, or every consolidation run after a prune will re-sign a head that the truncation-tamper check then rejects. Also promote_all/write_brief append (offsets never move, fine); gate re-execution uses only recent window seqs, so it is prune-safe."
      },
      {
        "file": "sigil/consolidate/revise.py",
        "spine_calls": "consolidation_records() calls store.iter_records() FULL scan with no since_seq L16, filtering source==archivist (CONSOLIDATE_SOURCE). iter_current() and promotion_ledgers() both consume that full scan. Uses r.source, r.kind, r.seq, r.supersedes_id, r.payload. Does NOT call get(). Read-only (no append).",
        "reads_raw_file": false,
        "assumes_seq_is_line_or_zero_based": false,
        "does_full_scan": true,
        "appends": false,
        "depends_on_old_seq_resolving": true,
        "risk_note": "Full-scan reader that NEEDS the complete archivist history in the live file. supersedes_id is treated as a seq value (superseded={r.supersedes_id}; filter `r.seq not in superseded` L25) — no positional/0-start assumption — but the supersession semantics assume ALL archivist records persist. A prune is doubly destructive here: (1) promotion_ledgers() rebuilds the grounded/refused idempotency ledgers by scanning every archivist record's promotion_key; pruning old promotions drops those keys, so a previously-promoted fact can be RE-PROMOTED as a duplicate (idempotency broken). (2) iter_current() derives the live view by subtracting superseded seqs; if a SUPERSEDING record is pruned while its now-stale predecessor survives, the stale (superseded) fact RESURRECTS into the current view, and pruning live records simply drops facts the MCP tools serve. So any compaction must preserve the full archivist supersession chain + promotion-key ledger (e.g. via a snapshot that folds supersessions and carries forward promotion keys) rather than raw-prune archivist records. Not segment-transparent for prune; segment-transparent only w.r.t. rotation IF iter_records spans all segments."
      },
      {
        "file": "sigil/cli.py",
        "spine_calls": "Constructs SpineStore in nearly every cmd_*. store.count() (L61 cmd_ingest, L467 cmd_status); store.next_seq (L467 cmd_status); store.append(kind=\"warden_checkpoint\",...) (L260 cmd_warden_anchor_set); store.verify() (L274 warden_anchor_get, L456 cmd_verify, L465 cmd_status); store.iter_records() full scan (L283 warden_anchor_get); store.get(seq) (L159 research, L185 bastion, L213 perceive, L354 scrape); checkpoint()/checkpoint(store) (L73 cmd_sign, L262 warden_anchor_set); verify_checkpoint()/verify_checkpoint(store) (L278/L458/L466). Governor/approvals/agents/mesh subcommands append indirectly (KillSwitch.engage, PromotionPolicy.grant, ApprovalQueue, authorize_device).",
        "reads_raw_file": true,
        "assumes_seq_is_line_or_zero_based": false,
        "does_full_scan": true,
        "appends": true,
        "depends_on_old_seq_resolving": false,
        "risk_note": "NOT segment-transparent. (1) Imports SPINE_PATH (L7) and does SPINE_PATH.unlink(missing_ok=True) on --reset (L22) — a raw single-file delete a segment design must generalize to clearing ALL segment files, else --reset leaves stale rotated segments. (2) cmd_warden_anchor_get (L283-287) FULL-scans iter_records() for the highest-count warden_checkpoint per pubkey — the anti-rollback high-water. A prune dropping the max-count anchor would silently LOWER the high-water and let a rolled-back WARDEN log pass verify: a real security regression, not just completeness loss. Compaction MUST retain the newest warden_checkpoint per pubkey. (3) count()/verify() (L456/465/467) and that scan must span segments after rotation. store.get() targets are freshly-appended res.applied seqs (recent), so no dependence on old-seq resolution. No seq==line / gap assumption anywhere."
