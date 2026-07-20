{
  "summary": "Holistic dual adversarial review of hard-prune Slice C (SnapshotState + 12 bearer folds) + verify",
  "agentCount": 4,
  "logs": [
    "raised 3 (2 BLOCK/HIGH/MED)"
  ],
  "result": {
    "confirmed": [
      {
        "severity": "HIGH",
        "file": "sigil/spine/snapshot.py",
        "line": 140,
        "title": "load()/_head_prune_boundary trust the head's prune fields + the named snapshot's folded_state WITHOUT verifying the head signature — a forged snapshot injects governance state with no owner key, bypassing the per-record signature checks the genesis scan enforced",
        "scenario": "_head_prune_boundary() does SignedChainHead.model_validate_json(HEAD_PATH.read_text()) and returns head.base_seq/head.snapshot_seq WITHOUT ever calling verify_head/classify_head; load() then trusts store.get(snapshot_seq)'s folded_state, checking only structural fields (kind=='snapshot', folded_state is a dict, st.base_seq/st.snapshot_seq echo the head) — all attacker-controlled. Repro (reachable in Slice C; load honors snapshot_seq>=0 regardless of whether pruning is 'enabled'): an attacker with write access to ~/.sigil appends a kind=\"snapshot\" record at seq S with payload.folded_state={\"killswitch_engaged\":false,\"mesh_dev_state\":[[attacker_dev,\"authorized\"]],\"trusted_pubkey\":<owner pubkey, a public string>,\"base_seq\":B,\"snapshot_seq\":S} and edits HEAD_PATH to {schema_version:2, base_seq:B, snapshot_seq:S}. KillSwitch._scan_engaged seeds engaged=st.killswitch_engaged(False) and scans only [B..T], so a genuine owner engage in the pruned prefix is silently dropped -> kill-switch reads released; authorized_devices/capability_map/promotion seed the attacker's forged rows because tp==st.trusted_pubkey passes on a forged (public) pubkey string. Pre-slice these paths did a genesis scan that required verify_signed(...owner...) on EVERY governance record, so an FS-write attacker without the owner key could not forge a release/authorization; the snapshot path accepts the folded governance state with no signature over it. The head signature DOES cover base_seq/snapshot_seq (they are in _HEAD_V2_FIELDS / _head_payload), so the tamper is authenticable — it is simply never checked here. Precondition: local FS write to the spine+head (exactly the tamper the signed-head anchor exists to make DETECTABLE); this slice makes it undetected on the governor/mesh/envelope hot paths, which run verify nowhere before load() (SpineStore.__init__ does not verify; consumers call load() directly).",
        "fix": "In _head_prune_boundary() verify the on-disk head via classify_head/verify_head against trust_root() BEFORE returning base_seq/snapshot_seq; on an unverifiable head fail closed (raise), never return a boundary. In load(), after store.get(snapshot_seq), confirm the snapshot record's actual chain position/entry_hash against the verified head rather than trusting the record's self-declared base_seq/snapshot_seq. Do not let a public trusted_pubkey string be the only gate on folded governance state.",
        "verdict": "CONFIRMED",
        "reasoning": "Verified against the real code on branch spine-hardprune-C. (1) snapshot.py:131-143 _head_prune_boundary() parses HEAD via SignedChainHead.model_validate_json (structural only; signatures default to an empty list so an unsigned/forged head parses) and returns head.base_seq/head.snapshot_seq with NO verify_head/classify_head call. (2) load() (104-124) trusts store.get(snapshot_seq).payload['folded_state'], checking only structural echoes (kind=='snapshot', folded is dict, st.base_seq/st.snapshot_seq equal the head) — all attacker-controlled; store.get/iter_records do not verify (manifest.py:56 confirms). (3) Reachable in Slice C despite 'no prune': load() gates only on snapshot_seq<0, there is no pruning-enabled flag, so any head with snapshot_seq>=0 drives the prune path. (4) Consumers seed governance state behind a PUBLIC-string gate self.trusted_pubkey==st.trusted_pubkey: KillSwitch._scan_engaged (killswitch.py:81-87 seeds engaged=st.killswitch_engaged, window base_seq-1), authorized_devices/capability_map (mesh/registry.py:46-95 seed dict(st.mesh_dev_state)/dict(st.capability_map)), promotion.py:48-57, budget.py:190. owner_pubkey() reads owner.pub — a public value — so the attacker sets st.trusted_pubkey to it and the gate passes. (5) Pre-slice these paths ran a genesis scan applying verify_signed(...owner...) (real Ed25519, needs the private key) on every governance record; the seed path carries no signature over the folded rows, a genuine regression. The head signature DOES cover base_seq/snapshot_seq (_HEAD_V2_FIELDS/_head_payload, chain.py:37) so the tamper is authenticable but never checked here; the verifying machinery (checkpoint.classify_head, whose own comment insists the signature check is the 'whole tamper-evidence point') is not wired onto the governor/mesh/envelope hot paths. Net: an FS-write attacker WITHOUT the owner private key can un-halt a kill-switched mesh (breaks the documented 'a forged release can never revive a halted mesh'), authorize a rogue device (breaks 'a rogue device cannot self-authorize'), and grant capability/promotion. Could not construct any reaching input that is blocked before load(); default-REFUTED does not apply. Severity HIGH: it breaks two explicitly-documented governance security guarantees and the program's own invariant #3 (load must fail CLOSED on a mismatched snapshot — it does not fail closed on an unverified/forged head), which arguably rises to BLOCK; I keep HIGH because the precondition is local FS write to ~/.sigil (owner.priv is 0600, so the realistic actor is a lower-priv/other-user/backup-restore attacker — exactly this subsystem's threat model) and because Slice C ships no legitimate prune, so a fleet-level 'reject snapshot_seq>=0 in Slice C' would also neutralize it.",
        "corrected_severity": "HIGH",
        "minimal_fix": "Make the snapshot-load path enforce the head signature and fail closed, reusing the existing verifier. In _head_prune_boundary()/load(), when the parsed head declares a prune (snapshot_seq >= 0), verify the on-disk head with checkpoint.classify_head(head, store.entries(), trust_root(), floor=load_floor()) (equivalently call verify_checkpoint(store)) BEFORE returning/using base_seq/snapshot_seq; on any non-clean/unverifiable result raise SnapshotError (never return a boundary, never scan a truncated window). This requires threading the store into _head_prune_boundary() (load() already holds it). Then bind the named snapshot record to the VERIFIED chain: confirm store.get(snapshot_seq) is the genuine chain entry at snapshot_seq (its cert_digest == the verified ChainEntry.cert_digest at that seq) rather than trusting the record's self-declared base_seq/snapshot_seq echoes — since the head signature covers head_hash+base_seq+snapshot_seq and each ChainEntry.cert_digest = digest(record), this authenticates folded_state end-to-end. Do not let a public trusted_pubkey string be the sole gate on folded governance state. Keep the current no-head / snapshot_seq<0 branch returning the empty identity so the Slice-C byte-identical genesis-scan behavior is preserved."
      },
      {
        "severity": "MED",
        "file": "sigil/spine/snapshot.py",
        "line": 142,
        "title": "_head_prune_boundary fails OPEN on a present-but-unparseable head (except -> return 0,-1,\"\") — under a D/E prune this makes every consumer scan a TRUNCATED window with EMPTY seeds, silently resetting every monotonic security bearer (the exact reset the slice exists to prevent)",
        "scenario": "The bare `except Exception: return 0, -1, \"\"` cannot distinguish 'no head file yet' (HEAD_PATH.exists() False, legitimately no prune) from 'head file PRESENT but corrupt' (truncated write / disk error / an attacker who can only corrupt, not sign). Under a future D/E prune the head legitimately says base_seq=K>0, snapshot_seq=K and records [0..K) are PHYSICALLY deleted. If that head is later corrupted, _head_prune_boundary swallows the parse error and returns (0,-1). load() sees snapshot_seq<0 and returns empty() (base_seq=0) — it NEVER reaches its own SnapshotError fail-closed path (that path only fires when snapshot_seq>=0). Consumers then do iter_records(since_seq=-1) which on a pruned spine starts at the earliest LIVE record seq K with EMPTY seeds: device_nonce_highwater -> -1 (pre-prune nonces replayable = envelope replay defeated), killswitch latch -> False (an engaged halt silently releases), gesture arm_set() -> {} (pruned (device,nonce) arms replayable), creation cap -> 0 (pruned account-create count lost, cap exceedable). This is the 'no replay guard/cap/auth/latch silently resets under prune' invariant, broken by a mere head corruption. Not reachable in Slice C (no prune exists, so the full genesis scan is correct), but the fail-open logic ships now as the D/E foundation.",
        "fix": "Split the cases: if HEAD_PATH.exists() is False, (0,-1,\"\") is correct (genesis, nothing pruned); if the head file is PRESENT but unparseable/unverifiable, raise SnapshotError so consumers fail closed rather than scan a truncated post-prune window with empty seeds. Never catch-all to no-prune when a head is present.",
        "verdict": "CONFIRMED",
        "reasoning": "The code behaves exactly as the finding describes, verified line-by-line in /home/kali/sigil/sigil/spine/snapshot.py. (1) `_head_prune_boundary` (lines 137-143) wraps BOTH the `HEAD_PATH.exists()` check and `SignedChainHead.model_validate_json(...)` in one `try`; its terminal `except Exception: return 0, -1, \"\"` (line 142) cannot distinguish an absent head from a PRESENT-but-unparseable one — a truncated/corrupt/attacker-mangled head raises ValidationError/JSONDecodeError and is swallowed to the no-prune identity `(0,-1,\"\")`. (2) `load()` guards `if snapshot_seq < 0: return cls.empty()` at line 112 BEFORE any SnapshotError raise (all of which — lines 116/120/123 — require snapshot_seq>=0), so a corrupt head returning -1 can never reach the fail-closed path; it returns the empty identity (base_seq=0). (3) Consumers window at `since_seq = st.base_seq - 1` = -1 and seed from the empty sub-states — confirmed in bridge/envelope.py:98-100 (`hi = st.nonce_highwater.get(dev,-1)` resets the replay floor to -1), governor/killswitch.py:81-88 (`engaged = st.killswitch_engaged` resets the latch to False), plus gesture/session.py, governor/budget.py+promotion.py, mesh/registry.py, agents/actor_scope.py+approvals.py, consolidate/revise.py, cli.py. Under a future D/E prune that physically deletes records [0..K), this empty-seed genesis scan of a truncated live window silently resets every monotonic security bearer — the exact reset invariant 3 exists to prevent. The finding is also honest and correct that this is NOT reachable in Slice C (no prune ships, so all records are present and the full genesis scan is correct). Two independent checks reinforce rather than refute: (a) head.json is written atomically (_atomic_write_text, checkpoint.py:90), which lowers the crash-torn likelihood but does NOT eliminate the disk-corruption / write-but-cannot-sign-attacker vector the finding also cites — and that adversary is exactly whom fail-closed defends against; (b) the function's own docstring claim that \"the verify path already fails closed on a too-new head\" is misleading — `load()`/`_head_prune_boundary` never call verify_head; they read base_seq/snapshot_seq from an UNVERIFIED parse — so the asserted protection does not cover this path. All substantive technical claims of the finding hold; only the severity label warrants adjustment.",
        "corrected_severity": "LOW",
        "minimal_fix": "Split the absent-head case from the corrupt-head case so a PRESENT head that fails to parse fails CLOSED instead of masquerading as no-prune:\n\ndef _head_prune_boundary() -> tuple[int, int, str]:\n    if not HEAD_PATH.exists():\n        return 0, -1, \"\"                       # genuinely no head -> genesis, nothing pruned\n    try:\n        head = SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding=\"utf-8\"))\n    except Exception as e:                      # present but corrupt/unparseable/future-schema\n        raise SnapshotError(\n            \"head present but unparseable -- refusing to treat as no-prune \"\n            \"(would scan a truncated post-prune window with empty seeds)\"\n        ) from e\n    return head.base_seq, head.snapshot_seq, \"\"\n\nThis lets SnapshotError propagate out of load() (which catches nothing) so consumers fail closed, honoring invariant 3 at the head-corruption boundary. Also correct the now-false docstring line claiming \"the verify path already fails closed\" -- load() never invokes verify_head. Separately (adjacent, before D/E ships prune, out of scope of this finding): _head_prune_boundary trusts base_seq/snapshot_seq from an UNVERIFIED parse, so the owner signature on the head should be verified here too, else a well-formed forged head can set an attacker-chosen prune boundary. Severity adjusted MED->LOW because the defect has zero reachability in the shipped Slice C (no prune exists), but it is a genuine fail-open in the exact foundation function Slice C exists to make fail-closed and MUST be fixed before D/E enables prune emission; MED is defensible given the fail-open logic ships now as the declared D/E base."
      }
    ],
    "refuted": [],
    "nits": [
      {
        "t": "build() relies on strictly-ascending-seq input for its order-DEPENDENT folds but neither sorts its input nor documents the contract",
        "fix": "Either sort `records` by r.seq at the top of build() (cheap, defensive, and matches archivist_view's emit-sort), or document 'records MUST be strictly ascending by seq' in the signature and have the D/E prune caller assert it before folding."
      }
    ]
  },
  "workflowProgress": [
    {
      "type": "workflow_phase",
      "index": 1,
      "title": "Review"
    },
    {
      "type": "workflow_phase",
      "index": 2,
      "title": "Verify"
    },
    {
      "type": "workflow_agent",
      "index": 1,
      "label": "redpen:fold-soundness",
      "phaseIndex": 1,
      "phaseTitle": "Review",
      "agentId": "ad7fb3c5195dc5437",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784502620824,
      "queuedAt": 1784502616067,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "promptPreview": "RED-PEN lens A (fold soundness / associativity / fail-closed) — Slice C. SIGIL hard-prune Slice C. A prune (later, Slice D/E) deletes records [0..K) but keeps a signed snapshot\ncommitting a FOLDED summary. Slice C wires every monotonic-security-bearer consumer to seed from SnapshotState.load(store)\n+ fold the LIVE window (iter_records(since_seq=base_seq-1)), and adds build() (the prefix folder) + …",
      "lastProgressAt": 1784503451916,
      "tokens": 115828,
      "toolCalls": 28,
      "durationMs": 831091,
      "resultPreview": "{\"findings\":[{\"severity\":\"HIGH\",\"file\":\"sigil/spine/snapshot.py\",\"line\":140,\"title\":\"load()/_head_prune_boundary trust the head's prune fields + the named snapshot's folded_state WITHOUT verifying the head signature — a forged snapshot injects governance state with no owner key, bypassing the per-record signature checks the genesis scan enforced\",\"scenario\":\"_head_prune_boundary() does SignedChain…"
    },
    {
      "type": "workflow_agent",
      "index": 2,
      "label": "redpen:byte-identity",
      "phaseIndex": 1,
      "phaseTitle": "Review",
      "agentId": "ac09429395a64ac7a",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784502620916,
      "queuedAt": 1784502616067,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "promptPreview": "RED-PEN lens B (byte-identity + missed bearer + the 3 fixes) — Slice C. SIGIL hard-prune Slice C. A prune (later, Slice D/E) deletes records [0..K) but keeps a signed snapshot\ncommitting a FOLDED summary. Slice C wires every monotonic-security-bearer consumer to seed from SnapshotState.load(store)\n+ fold the LIVE window (iter_records(since_seq=base_seq-1)), and adds build() (the prefix folder) + f…",
      "lastProgressAt": 1784503446384,
      "tokens": 145043,
      "toolCalls": 42,
      "durationMs": 825468,
      "resultPreview": "{\"findings\":[]}"
    },
    {
      "type": "workflow_agent",
      "index": 3,
      "label": "verify:load()/_head_prune_boundary trust th",
      "phaseIndex": 2,
      "phaseTitle": "Verify",
      "agentId": "ace43733739eccb57",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784503459910,
      "queuedAt": 1784503456610,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "CONFIRMED",
      "promptPreview": "Independently VERIFY against the REAL code in /home/kali/sigil (read the exact lines; try to REFUTE — default REFUTED if you cannot construct a reaching input). SIGIL hard-prune Slice C. A prune (later, Slice D/E) deletes records [0..K) but keeps a signed snapshot\ncommitting a FOLDED summary. Slice C wires every monotonic-security-bearer consumer to seed from SnapshotState.load(store)\n+ fold the L…",
      "lastProgressAt": 1784503788941,
      "tokens": 73958,
      "toolCalls": 19,
      "durationMs": 329031,
      "resultPreview": "{\"verdict\":\"CONFIRMED\",\"reasoning\":\"Verified against the real code on branch spine-hardprune-C. (1) snapshot.py:131-143 _head_prune_boundary() parses HEAD via SignedChainHead.model_validate_json (structural only; signatures default to an empty list so an unsigned/forged head parses) and returns head.base_seq/head.snapshot_seq with NO verify_head/classify_head call. (2) load() (104-124) trusts stor…"
    },
    {
      "type": "workflow_agent",
      "index": 4,
      "label": "verify:_head_prune_boundary fails OPEN on a",
      "phaseIndex": 2,
      "phaseTitle": "Verify",
      "agentId": "a1d872d4104eb4806",
      "model": "claude-opus-4-8[1m]",
      "state": "done",
      "startedAt": 1784503459927,
      "queuedAt": 1784503456610,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "CONFIRMED",
      "promptPreview": "Independently VERIFY against the REAL code in /home/kali/sigil (read the exact lines; try to REFUTE — default REFUTED if you cannot construct a reaching input). SIGIL hard-prune Slice C. A prune (later, Slice D/E) deletes records [0..K) but keeps a signed snapshot\ncommitting a FOLDED summary. Slice C wires every monotonic-security-bearer consumer to seed from SnapshotState.load(store)\n+ fold the L…",
      "lastProgressAt": 1784503692980,
      "tokens": 58381,
      "toolCalls": 11,
      "durationMs": 233052,
      "resultPreview": "{\"verdict\":\"CONFIRMED\",\"reasoning\":\"The code behaves exactly as the finding describes, verified line-by-line in /home/kali/sigil/sigil/spine/snapshot.py. (1) `_head_prune_boundary` (lines 137-143) wraps BOTH the `HEAD_PATH.exists()` check and `SignedChainHead.model_validate_json(...)` in one `try`; its terminal `except Exception: return 0, -1, \\\"\\\"` (line 142) cannot distinguish an absent head fro…"
    }
  ],
  "totalTokens": 393210,
  "totalToolCalls": 100
}