"""SIGIL memory-loop CLI: ingest → index → sign → search → verify → status."""
from __future__ import annotations

import argparse
import sys

from .config import ensure_dirs
from .ingest import cursor as cur
from .ingest.corpus import real_projects, session_files
from .ingest.docs import ingest_docs
from .ingest.transcript import ingest_transcript
from .mesh import authorize_device, authorized_devices, revoke_device
from .reuse import sha256_hex
from .spine.checkpoint import checkpoint, verify_checkpoint
from .spine.store import SpineStore
from .vectors.index import VectorIndex


def cmd_ingest(a) -> None:
    ensure_dirs()
    if a.reset:
        SpineStore().reset()                 # clears the legacy file, manifest, segments, trash, lockfile
        cur.clear()
        VectorIndex().reset()
        print("  reset: spine + cursor + vectors cleared")
        # The durable anti-rollback floor lives OUTSIDE spine/ and is intentionally NOT cleared here — a
        # reset must not be able to silently lower it. Re-signing an emptied spine will flag ROLLBACK until
        # the floor is deliberately re-seeded.
        from .config import FLOOR_PATH
        if FLOOR_PATH.exists():
            print("  note: durable anti-rollback floor preserved — run `sigil floor reset --yes` to re-seed "
                  "it to the fresh spine (else `sigil verify` will report ROLLBACK)")
    store = SpineStore()
    cursor = cur.load()
    total_events = 0
    git_only = getattr(a, "git_only", False)  # hook fast-path: record the commit, skip the corpus walk
    for proj in ([] if git_only else real_projects()):
        for sf in session_files(proj):
            key = str(sf)
            skip = cursor.get(key, 0)
            assert isinstance(skip, int)  # transcript keys hold an int record count (git keys hold a str hash)
            events, seen = ingest_transcript(store, sf, proj.name, skip_records=skip, max_events=a.max_events)
            cursor[key] = seen
            if events:
                print(f"  +{events:>5} events  {proj.name}/{sf.name[:18]}  (resumed@{skip})")
                total_events += events
            if getattr(a, "subagents", True):
                from .ingest.subagents import ingest_subagents
                sub = ingest_subagents(store, cursor, proj.name, sf.stem, sf.with_suffix(""),
                                       max_events=a.max_events)
                if sub:
                    print(f"  +{sub:>5} subagent events  {proj.name}/{sf.stem[:12]}…/subagents")
                    total_events += sub
            if a.max_events and total_events >= a.max_events:
                break
        if a.max_events and total_events >= a.max_events:
            break
    if a.docs:
        d = ingest_docs(store)
        print(f"  +{d} document chunks (curated memory/*.md)")
        total_events += d
    if a.git or git_only:
        from .ingest.git import ingest_git
        g = ingest_git(store, cursor=cursor)  # same cursor dict → saved once below (no clobber)
        print(f"  +{g} commit events (git history)")
        total_events += g
    cur.save(cursor)
    print(f"ingested {total_events} new events; spine now holds {store.count()} records")


def cmd_index(a) -> None:
    store, vi = SpineStore(), VectorIndex()
    since = vi.last_indexed_seq()
    print(f"  indexing spine records above seq {since} ...")
    n = vi.index_spine(store, since_seq=since)
    print(f"indexed {n} new records; vector collection now {vi.count()} points")


def cmd_sign(a) -> None:
    store = SpineStore()
    head = checkpoint(store)
    tip = store.next_seq - 1
    if store.count() and head.last_seq != tip:
        # The monotonic head guard deferred: head.json already anchors a LONGER head than this spine's
        # tip (a concurrent sign, or a planted head). We did NOT re-sign — report honestly, never a
        # misleading success line echoing the on-disk head.
        print(f"NOT re-signed: head.json already anchors last_seq={head.last_seq} > this spine's tip "
              f"{tip}. Run `sigil floor reset --yes` after a legitimate truncation/restore, or remove a "
              f"planted head.json.", file=sys.stderr)
        sys.exit(2)
    print(f"signed spine head: last_seq={head.last_seq} entries={head.entry_count} head_hash={head.head_hash[:16]}…")


def cmd_search(a) -> None:
    for r in VectorIndex().search(a.query, k=a.k):
        txt = (r.get("text") or "").replace("\n", " ")
        print(f"  [{r['score']:.3f}] seq={r['seq']} {r['kind']:<9} {str(r.get('ts',''))[:10]}  {txt[:140]}")


def cmd_graph(a) -> None:
    import json

    from .graph import entity, health, query, rebuild
    if a.entity:
        print(json.dumps(entity(a.entity), indent=2, default=str)); return
    if a.query:
        print(json.dumps(query(a.query), indent=2, default=str)); return
    if a.status:
        print(json.dumps(health(), indent=2)); return
    mh = rebuild()
    print(f"rebuilt graph from spine: {mh.projects} projects · {mh.sessions} sessions · "
          f"{mh.documents} docs · {mh.commits} commits · {mh.edges} edges")
    print(f"  in_sync={mh.in_sync} (replayed through seq {mh.rebuilt_seq}, spine head {mh.spine_head_seq})")


def cmd_consolidate(a) -> None:
    import json

    from .consolidate import PROVIDERS, run_consolidation
    cls = PROVIDERS[a.provider]
    if a.provider == "replay":
        provider = cls(a.fixture)
    elif a.provider in ("claude", "api") and a.model:
        provider = cls(model=a.model)       # optional model override for the LLM providers
    else:
        provider = cls()
    rep = run_consolidation(provider, since_seq=a.since, dry_run=a.dry_run, sign=not a.no_sign)
    print(json.dumps(rep.as_dict(), indent=2))


def _warden_anchor_msg(count: int, head_hash: str, pubkey: str) -> bytes:
    return f"{count}:{head_hash}:{pubkey}".encode("utf-8")


def _verify_ed25519(msg: bytes, sig_hex: str, pub_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def cmd_agents(a) -> None:
    from .agents.runner import morning, run_all, triage
    if a.action == "brief":
        out = morning(date_label=a.date or "today")
        print(out["brief"])
        print(f"\n[SENTINEL: {'; '.join(out['sentinel'].notes)}] [brief seq {out['steward'].applied}]")
    elif a.action == "triage":
        r = triage(inbox_path=a.inbox)["envoy"]
        print(f"  {'; '.join(r.notes)}")
        print(f"  drafts queued (awaiting approval, never auto-sent): {len(r.queued)}")
        for q in r.queued:
            print(f"    [{q['tier']} {q['kind']}] → {q.get('subject')}  (seq {q['seq']})")
    elif a.action == "sentinel":
        from .agents.runner import _sentinel_scan
        from .spine.store import SpineStore
        r = _sentinel_scan(SpineStore())
        print(f"  {'; '.join(r.notes)}; alerted seqs {r.applied}")
    elif a.action == "run":
        out = run_all(inbox_path=a.inbox, consolidate=a.consolidate)
        print("  ran ARCHIVIST→SENTINEL→STEWARD→ENVOY")
        for name, res in out.items():
            if hasattr(res, "notes"):
                print(f"    {name}: {'; '.join(res.notes)}")
    elif a.action == "research":
        from .agents.scholar import Scholar
        from .spine.store import SpineStore
        store = SpineStore()
        res = Scholar(store).run(a.question or "", a.source or [])
        print(f"  {'; '.join(res.notes)}")
        for seq in res.applied:
            rec = store.get(seq)
            if rec:
                print("\n" + rec.payload.get("text", ""))
    elif a.action == "artifice":
        from .agents.artificer import Artificer
        from .spine.store import SpineStore
        import shlex
        res = Artificer(SpineStore()).run(a.task or "", repo=a.repo,
                                          test_cmd=shlex.split(a.test) if a.test else None)
        print(f"  {'; '.join(res.notes)}")
        for q in res.queued:
            print(f"    [{q['tier']} {q['kind']}] {q.get('subject')}  (seq {q['seq']}, awaiting approval)")
    elif a.action == "bastion":
        from .agents.runner import _load_bastion
        from .spine.store import SpineStore
        store = SpineStore()
        b = _load_bastion(store)
        if b is None:
            print("  no own-infra inventory configured — create ~/.sigil/bastion-assets.json")
            print('  e.g. {"assets":[{"name":"site","kind":"tls","ref":"example.com:443"},'
                  '{"name":"deps","kind":"deps","ref":"/path/requirements.txt"}]}')
            print("  (defensive posture over YOUR infrastructure only; third-party targets are refused)")
            return
        res = b.run(now_iso=a.now)
        print(f"  {'; '.join(res.notes)}")
        for seq in res.applied:
            rec = store.get(seq)
            if rec:
                p = rec.payload
                print(f"    [{p.get('severity')}] {p.get('summary')}  ({p.get('quote')}, seq {seq})")
    elif a.action == "perceive":
        from .perception import (Frame, MoondreamVision, Perceptor, grab_camera,
                                 grab_screen, recall)
        from .spine.store import SpineStore
        store = SpineStore()
        if a.recall:   # "where did I last see X?" — grounded, on-box, no capture needed
            hit = recall(store, a.recall)
            if not hit:
                print(f"  no grounded sighting of {a.recall!r} in perception memory.")
            else:
                print(f"  last seen at seq {hit['seq']} ({hit['when']}): \"{hit['quote']}\"  "
                      f"[frame {str(hit['frame_sha256'])[:12]}, entry {hit['entry_hash'][:12]}]")
            return
        frame = Frame.from_image("screen", a.image) if a.image else (grab_camera() if a.camera else grab_screen())
        if frame is None:
            print("  no capture — need a screenshot tool (scrot/…) or a camera, or pass --image <path>")
            return
        perceptor = Perceptor(store)
        if a.frontier or a.approved is not None:
            from .perception.vision import ClaudeVision
            res = perceptor.frontier(a.question or "", frame, vision=ClaudeVision(), approved_seq=a.approved)
        else:
            res = perceptor.perceive(a.question or "", frame, vision=MoondreamVision())
        print(f"  {'; '.join(res.notes)}" if res.notes else "")
        for seq in res.applied:
            rec = store.get(seq)
            if rec and rec.payload.get("signal") == "perception":
                print(rec.payload.get("text", ""))
        for q in res.queued:
            print(f"    [{q['tier']} {q['kind']}] {q.get('subject')}  (seq {q['seq']}, awaiting approval)")


def cmd_voice(a) -> None:
    from .voice.backends import find_voices, set_voice
    from .voice.run import run_file, run_mic
    if a.find_voice:
        try:
            voices = find_voices(a.find_voice)
        except Exception as e:  # noqa: BLE001
            print(f"  cannot search the ElevenLabs library ({e}); set ELEVENLABS_API_KEY first")
            return
        print(f"  ElevenLabs voices matching {a.find_voice!r} — pin one with `sigil voice --set-voice <id>`:")
        for v in voices:
            print(f"    {v['voice_id']}  {str(v['name'])[:22]:<22} [{v.get('accent','')}/{v.get('category','')}]  {v.get('description','')}")
        return
    if a.set_voice:
        set_voice(a.set_voice)
        print(f"  pinned TTS voice → {a.set_voice} (SIGIL_TTS_VOICE_ID)")
        return
    if a.mic:
        run_mic(asr=a.asr, wake=a.wake, tts=a.tts, tts_voice=a.tts_voice)
        return
    if not a.file:
        print("  need --file <wav> (file mode), --mic (live), --find-voice <q>, or --set-voice <id>")
        return
    p = run_file(a.file, a.out, asr=a.asr, tts=a.tts, tts_voice=a.tts_voice)
    print(f"  transcript: {p.transcript!r}")
    print(f"  response:   {p.response!r}")
    print(f"  spoke →     {a.out}")
    print(f"  events:     {p.events}")


def cmd_warden_anchor_set(a) -> None:
    """Cross-anchor the WARDEN action-log head into the append-only spine (anti-rollback).
    AUTHENTICATED: the (count, head_hash, pubkey) tuple must carry a valid Ed25519 signature by
    the WARDEN key `pubkey`, so a rogue local caller cannot POISON the high-water (e.g. set a
    huge count to make every future verify fail). Only the KERNEL, which holds the WARDEN private
    key, can anchor."""
    if not _verify_ed25519(_warden_anchor_msg(int(a.count), a.head_hash, a.pubkey), a.sig, a.pubkey):
        print("REJECTED: warden-anchor-set signature invalid (only the WARDEN key may anchor)", file=sys.stderr)
        sys.exit(2)
    store = SpineStore()
    store.append(kind="warden_checkpoint", source="warden", actor="warden",
                 payload={"count": int(a.count), "head_hash": a.head_hash, "pubkey": a.pubkey})
    checkpoint(store)  # re-sign the spine head so the anchor sits under the spine's signature (anti-truncation)
    print(f"anchored WARDEN head into spine: count={a.count} head={a.head_hash[:16]}")


def cmd_warden_anchor_get(a) -> None:
    """Print the highest WARDEN head ever anchored FOR THIS KEY, as JSON {count, head_hash}.
    FAILS CLOSED (exit 2) if the spine's own integrity does not hold — otherwise a surgical edit
    to a warden_checkpoint line, or a spine tail-truncation removing recent anchors, would silently
    lower the high-water and let a rolled-back WARDEN log pass verify. Scoped by pubkey so a key
    rotation starts a fresh lineage."""
    import json as _json
    store = SpineStore()
    ok, msg = store.verify()                       # chain: catches a tampered/deleted anchor record
    if not ok:
        print(f"REJECTED: spine integrity failed — {msg}", file=sys.stderr)
        sys.exit(2)
    hok, hmsg = verify_checkpoint(store)           # signed head: catches spine tail-truncation
    if not hok and "TAMPER" in hmsg.upper():
        print(f"REJECTED: spine head tampered — {hmsg}", file=sys.stderr)
        sys.exit(2)
    # Hard-prune fold: seed the warden high-water from the folded prefix snapshot [0..base_seq), then fold
    # ONLY the live window [base_seq..T]. warden_best is a max-count / LWW-head_hash-on-tie semilattice, and
    # both build() and this loop process records in ascending seq, so fold(prefix)+fold(live) == full scan.
    # warden_best is filtered by the WARDEN pubkey (payload.pubkey), NOT the trust anchor, so it is not a
    # pubkey-dependent fold — no trusted_pubkey bypass is needed. Under the empty Slice-C snapshot
    # base_seq==0 => since_seq=-1 (the current full genesis scan) and warden_best_of()==(0,"",-1) (empty
    # seed) => BYTE-IDENTICAL to the old scan. Local import keeps this edit off the shared top import block.
    from .spine.snapshot import SnapshotState
    st = SnapshotState.load(store)
    best_count, best_hash, _ = st.warden_best_of(a.pubkey)   # scalars — nothing to copy; cache is never mutated
    for r in store.iter_records(since_seq=st.base_seq - 1):
        if r.kind == "warden_checkpoint" and r.payload.get("pubkey") == a.pubkey:
            c = int(r.payload.get("count", 0))
            if c >= best_count:
                best_count, best_hash = c, r.payload.get("head_hash", "")
    print(_json.dumps({"count": best_count, "head_hash": best_hash}))


def cmd_warden(a) -> None:
    """Phase 6 governor controls (SIGIL §5): kill switch + per-kind promotion policy. Governance
    mutations are signed by the persisted OWNER key (auto-created once if absent)."""
    from .governor import KillSwitch, PromotionPolicy
    from .governor.identity import ensure_owner_keypair
    store = SpineStore()
    if a.action == "status":
        print(f"  kill switch: {'ENGAGED (mesh halted)' if KillSwitch(store).is_engaged() else 'released (mesh live)'}")
        return
    ok = ensure_owner_keypair()   # owner signing key (the trust anchor)
    if a.action == "kill":
        seq = KillSwitch(store, owner_key=ok).engage(reason=a.reason or "")
        print(f"  KILL SWITCH ENGAGED (seq {seq}) — agent mesh halted; perception + memory read stay alive")
    elif a.action == "release":
        seq = KillSwitch(store, owner_key=ok).release(reason=a.reason or "")
        print(f"  kill switch released (seq {seq}, owner-signed) — agent mesh live again")
    elif a.action == "promote":
        seq = PromotionPolicy(store, owner_key=ok).grant(a.agent, a.scope or "*")
        print(f"  refused: {a.agent} has no promotion path (SIGIL §4.6)" if seq is None
              else f"  promoted {a.agent}/{a.scope or '*'} → A2 auto-approve, owner-signed (seq {seq})")
    elif a.action == "revoke":
        seq = PromotionPolicy(store, owner_key=ok).revoke(a.agent, a.scope or "*")
        print(f"  revoked promotion for {a.agent}/{a.scope or '*'} (seq {seq})")


def cmd_audit(a) -> None:
    from .audit import render_audit, self_audit
    store = SpineStore()
    rows = self_audit(store, agent=a.agent)
    print(render_audit(rows, agent=a.agent))


def cmd_approve(a) -> None:
    from .agents.approvals import ApprovalQueue
    from .governor.identity import ensure_owner_keypair
    owner_key = ensure_owner_keypair()   # the persisted owner key IS the trusted signer
    q = ApprovalQueue(SpineStore(), owner_key=owner_key)
    try:
        fn = q.approve if a.decision == "approve" else q.deny
        seq = fn(a.seq, approver=a.approver or "owner", reason=a.reason or "")
        print(f"  {a.decision}d queued seq {a.seq} → recorded at seq {seq}  (Ed25519 owner-signed)")
    except Exception as e:  # noqa: BLE001
        print(f"  cannot {a.decision} seq {a.seq}: {e}")


def cmd_dashboard(a) -> None:
    from .dashboard import render_dashboard, snapshot
    print(render_dashboard(snapshot(SpineStore())))


def cmd_scrape(a) -> None:
    """SCRIBE grounded web research — crawl PUBLIC, scope-gated, robots-respecting, serve-the-quote."""
    from .scrape import ScrapeScope
    from .scrape.researcher import WebResearcher
    from .spine.store import SpineStore
    if not a.scope_domain:
        print("  --scope-domain is required (deny-all by default): e.g. --scope-domain example.com")
        return
    scope = ScrapeScope(a.scope_domain, include_subdomains=a.subdomains)
    store = SpineStore()
    res = WebResearcher(store).research_web(a.question or "", a.seed or [], scope)
    print(f"  {'; '.join(res.notes)}")
    for seq in res.applied:
        rec = store.get(seq)
        if rec and rec.payload.get("signal") == "web.research":
            print("\n" + rec.payload.get("text", ""))


def cmd_host(a) -> None:
    """Show this host's capability descriptor (WS-D) — what the mesh routes on."""
    from .platform import host
    d = host().capabilities()
    print(f"  host {d.host_id} · {d.os}")
    print(f"    screen={d.has_screen} camera={d.has_camera} gpu_vlm={d.has_gpu_vlm} always_on={d.always_on}")


def _device_fingerprint(pubkey: str) -> str:
    """A short, human-verifiable fingerprint of a device pubkey — first 8 bytes of its SHA-256 as
    `xxxx-xxxx-xxxx-xxxx`. The PC and the future phone client MUST compute this identically so the
    operator can eyeball-match the code the phone shows before authorizing (defeats a key swap)."""
    short = sha256_hex(pubkey.encode())[:16]
    return "-".join(short[i:i + 4] for i in range(0, 16, 4))


def _mesh_authorize(store, device_id, pubkey, owner_key, *, assume_yes=False, confirm=input):
    """Authorize a phone device key (owner-signed). Prints the fingerprint and, unless `assume_yes`,
    makes the operator confirm it matches what the phone displays before writing the ledger record.
    Returns the record seq, or None if the operator did not confirm."""
    fp = _device_fingerprint(pubkey)
    print(f"  device {device_id!r} fingerprint: {fp}")
    if not assume_yes:
        ans = confirm(f"  confirm this fingerprint matches what phone {device_id!r} shows? [yes/no] ")
        if (ans or "").strip().lower() != "yes":
            print("  aborted — fingerprint not confirmed; device NOT authorized")
            return None
    seq = authorize_device(store, device_id, pubkey, owner_key)
    print(f"  authorized device {device_id!r} (owner-signed, seq {seq}); fingerprint {fp}")
    return seq


def _mesh_revoke(store, device_id, pubkey, owner_key):
    """Revoke a phone device key (owner-signed). Returns the record seq."""
    seq = revoke_device(store, device_id, pubkey, owner_key)
    print(f"  revoked device {device_id!r} (owner-signed, seq {seq}); fingerprint {_device_fingerprint(pubkey)}")
    return seq


def _mesh_list(store, owner_pubkey):
    """Print the currently-authorized device keys (owner-signed authorize minus later revoke).
    Returns the set for callers/tests."""
    devices = authorized_devices(store, owner_pubkey)
    if not devices:
        print("  no authorized devices")
    else:
        print(f"  {len(devices)} authorized device key(s):")
        for pub in sorted(devices):
            print(f"    {pub}  [{_device_fingerprint(pub)}]")
    return devices


def cmd_mesh(a) -> None:
    """Phase 9 W1-E — the PC-side mesh pairing back-end: authorize / revoke / list phone device keys.
    Authorizations are owner-signed via the PERSISTED owner identity (never a supplied key); a thin
    wrapper over the tested mesh ledger. `list-devices` needs no signing (a fail-closed read)."""
    from .governor.identity import ensure_owner_keypair, owner_pubkey
    store = SpineStore()
    if a.action == "list-devices":
        _mesh_list(store, owner_pubkey())
        return
    if not a.device_id or not a.pubkey:
        print(f"  usage: sigil mesh {a.action} <device-id> <pubkey>", file=sys.stderr)
        sys.exit(2)
    owner = ensure_owner_keypair()   # the persisted owner key IS the trusted signer (doctrine)
    if a.action == "authorize":
        _mesh_authorize(store, a.device_id, a.pubkey, owner, assume_yes=a.yes)
    elif a.action == "revoke":
        _mesh_revoke(store, a.device_id, a.pubkey, owner)


def cmd_serve(a) -> None:
    """Start the loopback glass-cockpit UI. Mints a fresh session token (printed here); every
    request needs it and no web page can read it. Read plane is GET-only; the owner-signed action
    plane is CSRF/Host/Origin-gated."""
    import secrets

    from .ui.server import serve
    serve(token=secrets.token_urlsafe(24), port=a.port)


def cmd_bridge_serve(a) -> None:
    """Phase 9 W1-D — start the WireGuard-bound phone bridge transport. Binds a `bind_ok` address
    (loopback or a PRIVATE WireGuard IP) — FAIL-CLOSED (exit 2) on a public/unspecified addr, minting
    no cert — and, unless --no-tls, wraps it in an owner-pinned self-signed TLS cert so the phone gets
    the secure context a PWA needs to install + register a service worker (pin the printed fingerprint
    once). Mirrors `cmd_mesh` / `cmd_serve`."""
    from .bridge.daemon import bind_ok
    if not bind_ok(a.addr):
        print(f"  refusing to bind {a.addr!r}: the bridge binds loopback or a PRIVATE (WireGuard) "
              f"address only — never 0.0.0.0 / an unspecified / a public address", file=sys.stderr)
        sys.exit(2)
    from .bridge.server import serve
    serve(addr=a.addr, port=a.port, tls=not a.no_tls)


def cmd_verify(a) -> None:
    ok, msg = SpineStore().verify()
    print(("chain OK: " if ok else "chain FAIL: ") + msg)
    hok, hmsg = verify_checkpoint()
    print(("head  OK: " if hok else "head  --: ") + hmsg)
    sys.exit(0 if ok else 2)


def cmd_status(a) -> None:
    store, vi = SpineStore(), VectorIndex()
    ok, msg = store.verify()
    hok, hmsg = verify_checkpoint()
    print(f"spine:     {store.count()} records | next_seq {store.next_seq}")
    print(f"vectors:   {vi.count()} points | last_indexed_seq {vi.last_indexed_seq()}")
    print(f"chain:     {'OK' if ok else 'FAIL'} — {msg}")
    print(f"head:      {'OK' if hok else '(' + hmsg + ')'}")


def cmd_spine(a) -> None:
    """Segment-rotation ops. `migrate` moves the legacy single file into the segment layout (O(1), one-way,
    idempotent). `status` lists the segment set. Retain-all: no records are ever deleted."""
    store = SpineStore()
    if a.action == "migrate":
        if store.migrate():
            print("  migrated: spine.jsonl → segments/seg-00000000.jsonl + manifest published")
        else:
            print("  already migrated (manifest present) — no change")
    elif a.action == "rotate":
        print("  sealed the active segment + started a new one" if store.rotate()
              else "  nothing to rotate (legacy or empty active)")
    elif a.action == "compact":
        n = store.compact()
        print(f"  compacted {n} sealed segment(s) to gzip (disk reclaimed)" if n else "  nothing to compact")
    elif a.action == "convert":
        from .spine.migrate_runner import backup_migrate_compact
        rep = backup_migrate_compact(store)
        print(f"  verify before: OK ({rep['count_before']} records)")
        print(f"  backup:        {rep.get('backup', '(skipped)')}")
        print(f"  migrated:      {rep['migrated']} | compacted {rep['compacted']} segment(s)")
        print(f"  verify after:  OK ({rep['count_after']} records — every record preserved)")
    elif a.action == "prune-plan":
        # DRY-RUN: validate a prune boundary K against the §7 referential guards + show what WOULD archive.
        # Archives nothing, drops nothing. (The cutover is Slice E.)
        from .spine.prune import PruneUnsafe, check_prune_safe, open_workflow_floor, snapshot_payload
        if a.boundary is None:
            print("prune-plan needs -K <segment-aligned boundary>; open-workflow referential floor is "
                  f"{open_workflow_floor(store)} (K must be <= this)", file=sys.stderr)
            sys.exit(2)
        try:
            arch_segs = check_prune_safe(store, a.boundary)
            pay = snapshot_payload(store, a.boundary)
        except PruneUnsafe as e:
            print(f"prune UNSAFE at K={a.boundary}: {e}", file=sys.stderr)
            sys.exit(2)
        print(f"prune-plan K={a.boundary}: would archive {len(arch_segs)} whole sealed segment(s) "
              f"[0..{a.boundary}) | base_count={pay['base_count']} | delta_merkle={pay['delta_merkle_root'][:16]}… "
              f"| cumulative={pay['cumulative_merkle_root'][:16]}… (DRY-RUN — nothing archived or dropped)")
        return
    elif a.action == "verify-archive":
        from pathlib import Path as _P
        from .spine.prune import verify_with_archive
        adir = _P(a.archive) if a.archive else None
        ok, msg = verify_with_archive(store, adir=adir)
        print(("OK: " if ok else "FAILED: ") + msg)
        sys.exit(0 if ok else 2)
    elif a.action == "status":
        segs = store.segment_info()
        if not segs:
            print(f"spine: LEGACY single file (not migrated) | {store.count()} records | next_seq {store.next_seq}")
            return
        print(f"spine: {len(segs)} segment(s) | generation {store.generation()} | "
              f"{store.count()} records | next_seq {store.next_seq}")
        for s in segs:
            where = "active" if not s["sealed"] else f"sealed[{s['first_seq']}..{s['last_seq']}]"
            print(f"  seg-{s['id']:08d} {s['codec']:4} {where:24} {s['bytes']:>13,} bytes  {s['file']}")


def cmd_floor(a) -> None:
    """The durable external anti-rollback floor (hard-prune C1). `status` prints it (read-only). `reset`
    DELIBERATELY re-seeds it downward to the current spine — the only path that may lower it — for a
    legitimate reset/restore; owner-key-gated (re-signs the spine) + requires --yes."""
    from .spine.floor import load_floor, reset_floor
    if a.action == "status":
        try:
            fl = load_floor()
        except Exception as e:  # noqa: BLE001 — a corrupt floor is surfaced, never treated as absent/clean
            print(f"durable floor UNREADABLE (possible tamper): {e}", file=sys.stderr)
            sys.exit(2)
        if fl is None:
            print("durable floor: none yet (pre-floor or never signed) — `sigil sign` seeds it")
            return
        print(f"durable floor: last_seq={fl.last_seq} base_seq={fl.base_seq} base_count={fl.base_count} "
              f"head_sig={fl.head_sig_hash[:16]}… scope={fl.scope} updated={fl.updated_ts}")
    elif a.action == "reset":
        if not a.yes:
            print("refusing: `sigil floor reset` DELIBERATELY LOWERS the durable anti-rollback floor to the "
                  "current spine — only run this after a legitimate reset/restore, never routinely. Re-run "
                  "with --yes to confirm.", file=sys.stderr)
            sys.exit(2)
        store = SpineStore()
        head = checkpoint(store, force=True)  # owner-key-gated: re-sign the current spine (force: allow a
        fl = reset_floor(head)                # SHORTER head), then force the floor down to that fresh head.
        print(f"durable floor RE-SEEDED to current head: last_seq={fl.last_seq} base_seq={fl.base_seq} "
              f"base_count={fl.base_count}")


def cmd_budget(a) -> None:
    """Read-only per-agent budget usage (actions / interrupts / provider tokens / USD cost) for a UTC day,
    derived from the spine (zero-impact). Caps (opt-in, from ~/.sigil/budgets.json) are shown for context."""
    from datetime import datetime, timezone

    from .governor import Governor
    day = a.day or datetime.now(timezone.utc).date().isoformat()
    led = Governor(SpineStore()).budget
    c = led.caps
    print(f"# SIGIL budget — {day}")
    print(f"caps: actions={c.daily_actions} interrupts={c.daily_interrupts} "
          f"tokens={c.daily_tokens} cost_usd={c.daily_cost_usd}")
    rep = led.report(day)
    for agent in sorted(rep):
        u = rep[agent]
        print(f"  {agent}: {u['actions']} action(s), {u['interrupts']} interrupt(s), "
              f"{u['tokens']} token(s), ${u['cost_usd']:.4f}")
    if not rep:
        print("  (no agent activity)")


def cmd_doctor(a) -> None:
    """Whole-install self-check: SIGIL_HOME writable, kernel present, Qdrant reachable, keyring, claude."""
    import sys as _sys

    from .config import doctor, effective_config
    print("SIGIL doctor — install self-check\n")
    ok_all = True
    for name, ok, detail in doctor():
        ok_all = ok_all and ok
        print(f"  [{'OK' if ok else '!!'}] {name:16} {detail}")
    print("\neffective config (secrets redacted):")
    for k, v in effective_config().items():
        print(f"  {k:18} {v}")
    _sys.exit(0 if ok_all else 1)


def main(argv=None) -> None:
    from .obs import configure_logging
    configure_logging()                      # one structured-logging setup at startup (level from SIGIL_LOG_LEVEL)
    p = argparse.ArgumentParser(prog="sigil")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="self-check the install (SIGIL_HOME, kernel, Qdrant, keyring, claude)").set_defaults(fn=cmd_doctor)
    pi = sub.add_parser("ingest")
    pi.add_argument("--reset", action="store_true", help="clear spine+cursor+vectors and rebuild")
    pi.add_argument("--docs", action="store_true", help="also ingest curated memory/*.md")
    pi.add_argument("--git", action="store_true", help="also ingest git commit history")
    pi.add_argument("--git-only", dest="git_only", action="store_true",
                    help="only ingest git commits, skip the transcript walk (git-hook fast path)")
    pi.add_argument("--no-subagents", dest="subagents", action="store_false",
                    help="skip subagent sidecar transcripts (default: ingest them)")
    pi.set_defaults(subagents=True)
    pi.add_argument("--max-events", type=int, default=None)
    pi.set_defaults(fn=cmd_ingest)
    sub.add_parser("index").set_defaults(fn=cmd_index)
    sub.add_parser("sign").set_defaults(fn=cmd_sign)
    ps = sub.add_parser("search"); ps.add_argument("query"); ps.add_argument("-k", type=int, default=8); ps.set_defaults(fn=cmd_search)
    pg = sub.add_parser("graph")
    pg.add_argument("--status", action="store_true", help="show graph health without rebuilding")
    pg.add_argument("--entity", help="look up a Project/Session/Commit/Document")
    pg.add_argument("--query", help="run a read-only Cypher query")
    pg.set_defaults(fn=cmd_graph)
    pcon = sub.add_parser("consolidate")
    pcon.add_argument("--provider", choices=["claude", "api", "local", "heuristic", "replay"],
                      default="heuristic",
                      help="claude=Max plan (claude -p); api=Anthropic API key; local=Ollama; "
                           "heuristic=offline no-LLM (default); replay=fixture")
    pcon.add_argument("--model", help="model override for claude/api providers (default: fast Haiku)")
    pcon.add_argument("--fixture", help="candidate fixture path (for --provider replay)")
    pcon.add_argument("--since", type=int, default=None, help="override the run cursor (start after this seq)")
    pcon.add_argument("--dry-run", action="store_true", help="extract+gate but write nothing")
    pcon.add_argument("--no-sign", action="store_true", help="skip re-signing the head after promotion")
    pcon.set_defaults(fn=cmd_consolidate)
    pwas = sub.add_parser("warden-anchor-set")
    pwas.add_argument("count", type=int)
    pwas.add_argument("head_hash")
    pwas.add_argument("pubkey")
    pwas.add_argument("sig", help="Ed25519 signature (hex) over 'count:head_hash:pubkey' by the WARDEN key")
    pwas.set_defaults(fn=cmd_warden_anchor_set)
    pwag = sub.add_parser("warden-anchor-get")
    pwag.add_argument("pubkey")
    pwag.set_defaults(fn=cmd_warden_anchor_get)
    pa = sub.add_parser("agents")
    pa.add_argument("action", choices=["brief", "triage", "sentinel", "run", "research",
                                       "artifice", "bastion", "perceive"])
    pa.add_argument("--inbox", default=None, help="ENVOY inbox JSON (default ~/.sigil/inbox.json)")
    pa.add_argument("--date", default=None, help="date label for the brief")
    pa.add_argument("--consolidate", action="store_true", help="run ARCHIVIST consolidation first (in `run`)")
    pa.add_argument("--question", default=None, help="SCHOLAR research question / PERCEIVE query")
    pa.add_argument("--source", action="append", help="SCHOLAR source URL or path (repeatable)")
    pa.add_argument("--repo", default=None, help="ARTIFICER target repo path")
    pa.add_argument("--task", default=None, help="ARTIFICER coding task")
    pa.add_argument("--test", default=None, help="ARTIFICER test command (e.g. 'python -m pytest')")
    pa.add_argument("--screen", action="store_true", help="PERCEIVE: capture the screen (default)")
    pa.add_argument("--camera", action="store_true", help="PERCEIVE: capture a camera frame")
    pa.add_argument("--image", default=None, help="PERCEIVE: describe a saved image path instead of capturing")
    pa.add_argument("--frontier", action="store_true",
                    help="PERCEIVE: use the frontier VLM — QUEUES the image egress for approval (uploads nothing)")
    pa.add_argument("--approved", type=int, default=None,
                    help="PERCEIVE: run an approved frontier egress by its queued seq (uploads only if verified)")
    pa.add_argument("--recall", default=None, help="PERCEIVE: where did I last see <subject>? (grounded, on-box)")
    pa.add_argument("--now", default=None, help="BASTION: assessment 'now' (ISO) for cert-expiry math")
    pa.set_defaults(fn=cmd_agents)
    pv = sub.add_parser("voice")
    pv.add_argument("--file", help="input WAV (file mode)")
    pv.add_argument("--out", default="/tmp/sigil-voice-out.wav", help="output WAV (file mode)")
    pv.add_argument("--mic", action="store_true", help="live full-duplex (needs mic + speaker)")
    pv.add_argument("--asr", choices=["auto", "stub", "elevenlabs"], default="auto",
                    help="auto=local Whisper; elevenlabs=Scribe cloud STT; stub=placeholder")
    pv.add_argument("--tts", choices=["silence", "elevenlabs", "piper"], default="elevenlabs",
                    help="elevenlabs=cloud TTS (JARVIS voice); piper=local; silence=fallback")
    pv.add_argument("--wake", choices=["energy", "oww"], default="energy")
    pv.add_argument("--tts-voice", dest="tts_voice", default=None,
                    help="voice_id (ElevenLabs) or .onnx (Piper); default = pinned SIGIL_TTS_VOICE_ID")
    pv.add_argument("--find-voice", dest="find_voice", metavar="QUERY",
                    help="search the ElevenLabs library (e.g. 'jarvis') and list voice_ids")
    pv.add_argument("--set-voice", dest="set_voice", metavar="VOICE_ID",
                    help="pin a TTS voice_id as the default (SIGIL_TTS_VOICE_ID)")
    pv.set_defaults(fn=cmd_voice)
    pwd = sub.add_parser("warden", help="governor controls (kill switch, promotion policy)")
    pwd.add_argument("action", choices=["kill", "release", "promote", "revoke", "status"])
    pwd.add_argument("agent", nargs="?", default=None, help="agent for promote/revoke")
    pwd.add_argument("--scope", default=None, help="promotion scope (default '*' = all scopes)")
    pwd.add_argument("--reason", default=None, help="reason recorded on the spine")
    pwd.set_defaults(fn=cmd_warden)
    pau = sub.add_parser("audit", help="self-audit (C18): what the mesh did and why, from the log")
    pau.add_argument("--agent", default=None, help="filter to one agent")
    pau.set_defaults(fn=cmd_audit)
    for name in ("approve", "deny"):
        pap = sub.add_parser(name, help=f"{name} a queued A2/A3 proposal by seq (owner-signed)")
        pap.add_argument("seq", type=int)
        pap.add_argument("--approver", default=None, help="approver id (default 'owner')")
        pap.add_argument("--reason", default=None)
        pap.set_defaults(fn=cmd_approve, decision=name)
    sub.add_parser("dashboard", help="read-only operator status over the spine").set_defaults(fn=cmd_dashboard)
    pbud = sub.add_parser("budget", help="per-agent action/interrupt/token/cost budget usage for a UTC day (read-only)")
    pbud.add_argument("--day", help="UTC date YYYY-MM-DD (default: today)")
    pbud.set_defaults(fn=cmd_budget)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    pfl = sub.add_parser("floor", help="durable external anti-rollback floor: status; reset (deliberate downward re-seed)")
    pfl.add_argument("action", choices=["status", "reset"])
    pfl.add_argument("--yes", action="store_true", help="confirm `reset` deliberately lowers the floor")
    pfl.set_defaults(fn=cmd_floor)
    psp = sub.add_parser("spine", help="segment rotation: migrate; rotate; compact; convert; status; prune-plan; verify-archive")
    psp.add_argument("action", choices=["migrate", "rotate", "compact", "convert", "status",
                                        "prune-plan", "verify-archive"])
    psp.add_argument("-K", "--boundary", type=int, default=None,
                     help="prune-plan: the segment-aligned boundary K (dry-run — checks §7 guards, archives NOTHING)")
    psp.add_argument("--archive", default=None, help="verify-archive: the archive dir (default SIGIL_HOME/spine/archive)")
    psp.set_defaults(fn=cmd_spine)
    psv = sub.add_parser("serve", help="start the loopback glass-cockpit UI")
    psv.add_argument("--port", type=int, default=8733)
    psv.set_defaults(fn=cmd_serve)
    ph = sub.add_parser("host", help="this host's mesh capability descriptor")
    ph.add_argument("action", nargs="?", default="caps", choices=["caps"])
    ph.set_defaults(fn=cmd_host)
    pm = sub.add_parser("mesh", help="authorize/revoke/list phone device keys (mesh pairing back-end)")
    pm.add_argument("action", choices=["authorize", "revoke", "list-devices"])
    pm.add_argument("device_id", nargs="?", default=None, help="device id (authorize/revoke)")
    pm.add_argument("pubkey", nargs="?", default=None, help="device Ed25519 public key b64 (authorize/revoke)")
    pm.add_argument("--yes", action="store_true",
                    help="skip the interactive fingerprint confirmation (authorize)")
    pm.set_defaults(fn=cmd_mesh)
    pb = sub.add_parser("bridge", help="the WireGuard-bound phone bridge transport (owner-pinned self-signed TLS)")
    pb.add_argument("action", choices=["serve"])
    pb.add_argument("--addr", required=True, help="bind address — loopback or a PRIVATE WireGuard IP (bind_ok)")
    pb.add_argument("--port", type=int, default=8734, help="TCP port (default 8734)")
    pb.add_argument("--no-tls", dest="no_tls", action="store_true",
                    help="plain HTTP (degraded: no PWA install / no service worker) — TLS is the default")
    pb.set_defaults(fn=cmd_bridge_serve)
    psc = sub.add_parser("scrape", help="SCRIBE grounded web research (public, scope-gated, robots-respecting)")
    psc.add_argument("--question", default=None)
    psc.add_argument("--seed", action="append", help="seed URL (repeatable)")
    psc.add_argument("--scope-domain", dest="scope_domain", action="append", help="allowed domain (repeatable; deny-all if none)")
    psc.add_argument("--subdomains", action="store_true", help="include subdomains of allowed domains")
    psc.set_defaults(fn=cmd_scrape)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
