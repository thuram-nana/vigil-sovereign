"""SIGIL memory-loop CLI: ingest → index → sign → search → verify → status."""
from __future__ import annotations

import argparse
import json
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
                print("\n" + store.decrypted_or_raw(rec).payload.get("text", ""))
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
                p = store.decrypted_or_raw(rec).payload
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
                print(store.decrypted_or_raw(rec).payload.get("text", ""))
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
    mutations are signed by the persisted OWNER key (auto-created once if absent).

    The CLI supplies `issued_at` for every dangerous-direction mutation. The governance modules read no
    clock by design (a module-supplied timestamp is one an attacker replaying the module's own output
    could rely on); the authority over "when" sits with the caller holding the owner key, which here is
    the operator at this terminal."""
    import time as _time

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
        seq = KillSwitch(store, owner_key=ok).release(issued_at=_time.time(), reason=a.reason or "")
        print(f"  kill switch released (seq {seq}, owner-signed) — agent mesh live again")
    elif a.action == "promote":
        seq = PromotionPolicy(store, owner_key=ok).grant(a.agent, a.scope or "*", issued_at=_time.time())
        print(f"  refused: {a.agent} has no promotion path (SIGIL §4.6)" if seq is None
              else f"  promoted {a.agent}/{a.scope or '*'} → A2 auto-approve, owner-signed (seq {seq})")
    elif a.action == "revoke":
        seq = PromotionPolicy(store, owner_key=ok).revoke(a.agent, a.scope or "*")
        print(f"  revoked promotion for {a.agent}/{a.scope or '*'} (seq {seq})")


def cmd_capability(a) -> None:
    """Enable/disable gesture control, voice control, or autolearn (the Knowledge-Engine propose loop)
    via the owner-signed, tamper-evident capability latch (audit W0 / K2). `status` needs no key; toggling
    is owner-signed. Any disable is fail-safe (takes effect regardless of signature); only an owner-signed
    enable re-enables. `both` is the physical-input pair (gesture+voice); `autolearn` is toggled explicitly.

    The CLI stamps `issued_at` on each enable (the anti-replay high-water); the gate reads no clock."""
    import time as _time

    from .governor import CAPABILITIES, CapabilityGate
    from .governor.identity import ensure_owner_keypair
    store = SpineStore()
    if a.target == "status":
        st = CapabilityGate(store).state_all()
        for c in sorted(CAPABILITIES):
            print(f"  {c}: {st.get(c, 'enabled')}")
        return
    if a.state not in ("on", "off"):
        print("  usage: sigil capability <gesture|voice|autolearn|both> <on|off> [--reason ...]",
              file=sys.stderr)
        sys.exit(2)
    # "both" is the historical gesture+voice pair — autolearn is NOT swept in (matches the UI action plane).
    caps = ["gesture", "voice"] if a.target == "both" else [a.target]
    cg = CapabilityGate(store, owner_key=ensure_owner_keypair())
    # ONE `issued_at` for the whole invocation is correct: the high-water is PER CAPABILITY, so the same
    # value applied to `gesture` and `voice` lands on two independent keys and neither refuses the other.
    now = _time.time()
    for c in caps:
        seq = cg.disable(c, reason=a.reason) if a.state == "off" else cg.enable(c, issued_at=now,
                                                                                reason=a.reason)
        print(f"  {c} {'DISABLED' if a.state == 'off' else 'ENABLED (owner-signed)'} (seq {seq})")


def cmd_accounts(a) -> None:
    """Bootstrap + manage per-user RBAC accounts (Claim 6). Accounts are OWNER-SIGNED spine grants; the
    owner key (auto-created once) is the sole signer. `create` mints a per-user bearer token and prints it
    ONCE (only its salted hash is stored). `assign` changes a role; `revoke` disables an account (the safe
    direction). `enroll-pubkey` owner-binds the account's Ed25519 PUBLIC key — the S3 stronger
    challenge/response (proof-of-possession) login identity; the key comes from `--pubkey`/`--pubkey-file`
    and is validated fail-closed. `enroll-totp` owner-binds a TOTP second factor (S4) — the plaintext secret
    is shown once as an otpauth:// URI and sealed at rest, never stored. `set-password` owner-sets the
    OPTIONAL weaker scrypt password login (prompted, never on argv; only its salted hash reaches the spine).
    `disable-totp` removes the TOTP factor (the documented RECOVERY path for a lost authenticator — W17-1).
    `list` needs no key. This is the CLI half of the W17-3 enrolment fix set; the Users & Roles screen wires
    the same three enrolment actions (enroll_pubkey / enroll_totp / set_password) so a fresh operator can
    enrol from either surface and then log in through the gate (bearer / password+TOTP / SSO).

        sigil accounts create <username> <viewer|analyst|operator>
        sigil accounts assign <username> <viewer|analyst|operator>
        sigil accounts revoke <username>
        sigil accounts enroll-pubkey <username> --pubkey <b64> | --pubkey-file <path>
        sigil accounts enroll-totp <username>
        sigil accounts set-password <username>          # prompts for the password (never on argv)
        sigil accounts disable-totp <username>
        sigil accounts list
    """
    import time as _time
    from pathlib import Path

    from .governor.accounts import ROLES, AccountsRegistry
    from .governor.identity import ensure_owner_keypair
    store = SpineStore()
    if a.accounts_cmd == "list":
        accts = AccountsRegistry(store).accounts()
        if not accts:
            print("  (no accounts — `sigil accounts create <username> <role>` to add one)")
            return
        for ac in accts:
            print(f"  {ac.username:<24} {ac.role:<10} {ac.state}")
        return
    if not a.username:
        print("  usage: sigil accounts <create|assign|revoke|enroll-pubkey|enroll-totp|set-password|"
              "disable-totp> <username> [role]", file=sys.stderr)
        sys.exit(2)
    if a.accounts_cmd in ("create", "assign") and not a.role:
        print(f"  usage: sigil accounts {a.accounts_cmd} <username> <viewer|analyst|operator>",
              file=sys.stderr)
        sys.exit(2)
    reg = AccountsRegistry(store, owner_key=ensure_owner_keypair())
    if a.accounts_cmd == "create":
        import secrets as _secrets
        bearer = _secrets.token_urlsafe(32)
        seq = reg.create(a.username, a.role, bearer_token=bearer, issued_at=_time.time())
        print(f"  account CREATED: {a.username} → {a.role} (owner-signed, seq {seq})")
        print(f"  bearer token (shown ONCE — copy it now; only its salted hash is stored):\n    {bearer}")
    elif a.accounts_cmd == "assign":
        seq = reg.assign_role(a.username, a.role, issued_at=_time.time())
        print(f"  role ASSIGNED: {a.username} → {a.role} (owner-signed, seq {seq})")
    elif a.accounts_cmd == "revoke":
        seq = reg.revoke(a.username)
        print(f"  account REVOKED: {a.username} (seq {seq}) — its bearer token no longer authenticates")
    elif a.accounts_cmd == "enroll-pubkey":
        # S3 — owner-bind the account's Ed25519 PUBLIC key (challenge/response proof-of-possession login,
        # the stronger path). The key is read from --pubkey or --pubkey-file (never generated here — the
        # PRIVATE half stays with the user, never on the host). enroll_pubkey validates it fail-closed
        # (load_public_key rejects malformed / non-canonical / low-order keys), so binding garbage is a
        # clean refusal now rather than a silently-always-failing login later.
        pubkey = (getattr(a, "pubkey", None) or "").strip()
        pubkey_file = (getattr(a, "pubkey_file", None) or "").strip()
        if pubkey and pubkey_file:
            print("  give EITHER --pubkey OR --pubkey-file, not both.", file=sys.stderr)
            sys.exit(2)
        if pubkey_file:
            try:
                pubkey = Path(pubkey_file).read_text(encoding="utf-8").strip()
            except OSError as e:
                print(f"  cannot read --pubkey-file {pubkey_file!r}: {e}", file=sys.stderr)
                sys.exit(1)
        if not pubkey:
            print("  usage: sigil accounts enroll-pubkey <username> --pubkey <b64> | --pubkey-file <path>",
                  file=sys.stderr)
            sys.exit(2)
        try:
            seq = reg.enroll_pubkey(a.username, pubkey, issued_at=_time.time())
        except ValueError as e:  # invalid key / unknown-or-revoked account → an actionable refusal
            print(f"  cannot enroll pubkey: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"  PUBKEY ENROLLED for {a.username} (owner-signed, seq {seq}) — the account can now log in by "
              f"proving possession of the matching PRIVATE key (challenge/response). Keypairs are the "
              f"strongest login path; the private key never touches the host.")
    elif a.accounts_cmd == "set-password":
        # S4 — owner-set the OPTIONAL weaker scrypt password login. The plaintext is PROMPTED (never on
        # argv, where it would land in shell history / the process table) and hashed inside set_password;
        # only the salted-scrypt hash reaches the spine (mirrors the bearer, which is stored only as a hash).
        import getpass as _getpass
        pw = _getpass.getpass(f"  new password for {a.username} (input hidden): ")
        pw2 = _getpass.getpass("  confirm password: ")
        if pw != pw2:
            print("  passwords do not match — nothing changed.", file=sys.stderr)
            sys.exit(1)
        if len(pw) < 8:
            print("  refusing to set a password shorter than 8 characters (keypair login is the stronger "
                  "path anyway — see `enroll-pubkey`).", file=sys.stderr)
            sys.exit(1)
        try:
            seq = reg.set_password(a.username, pw, issued_at=_time.time())
        except ValueError as e:  # unknown-or-revoked account → an actionable refusal
            print(f"  cannot set password: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"  PASSWORD SET for {a.username} (owner-signed, seq {seq}; salted scrypt, the plaintext never "
              f"reached the spine). If TOTP is enrolled, the password login still requires the current code.")
    elif a.accounts_cmd == "enroll-totp":
        # S4 — owner-bind a TOTP second factor. The plaintext secret is generated HERE, shown ONCE in the
        # provisioning URI, and SEALED via the owner vault before it lands on the spine (only the sealed blob
        # is signed into the grant). Sealing needs a provisioned vault — surface the one-time setup cleanly.
        import base64 as _b64

        from .governor import totp as _totp
        from .governor.accounts import TOTP_SEAL_CONTEXT
        from .platform.vault import owner_vault
        secret = _totp.generate_secret()
        uri = _totp.provisioning_uri(secret, account_name=a.username, issuer="VIGIL")
        try:
            sealed = owner_vault().seal_secret(secret.encode("utf-8"), context=TOTP_SEAL_CONTEXT)
        except Exception as e:  # noqa: BLE001 — VaultLocked etc. → an actionable refusal, not a traceback
            print(f"  cannot enroll TOTP: the owner vault must be provisioned to seal the secret at rest "
                  f"({e}). Run `sigil vault provision` first.", file=sys.stderr)
            sys.exit(1)
        seq = reg.enroll_totp(a.username, _b64.b64encode(sealed).decode("ascii"), issued_at=_time.time())
        print(f"  TOTP ENROLLED for {a.username} (owner-signed, seq {seq})")
        print("  scan this into your authenticator NOW — shown ONCE; the secret is sealed at rest and never "
              f"recoverable from the spine:\n    {uri}")
        print("  the bearer login gate is NOT gated by this factor; PoP / password logins now require a code.")
    elif a.accounts_cmd == "disable-totp":
        seq = reg.disable_totp(a.username, issued_at=_time.time())
        print(f"  TOTP DISABLED for {a.username} (owner-signed, seq {seq}) — the account no longer requires a "
              f"second factor (recovery path for a lost authenticator).")
    _ = ROLES  # (choices are enforced by argparse below)


def cmd_gesture_nav(a) -> None:
    """Toggle gesture NAV-MODE (S3). Off by default (opt-in). While ON, a live owner-armed gesture
    session's swipes/pinch NAVIGATE the UI (an A1 `sigil.nav` signal that injects NOTHING) instead of
    scroll/click; every per-frame gesture gate is unchanged. `status` needs no key."""
    from .gesture.navmode import nav_mode_on, set_nav_mode
    store = SpineStore()
    if a.state == "status":
        print("  gesture nav-mode: " + ("ON" if nav_mode_on(store) else "OFF"))
        return
    seq = set_nav_mode(store, a.state == "on")
    print(f"  gesture nav-mode {'ON' if a.state == 'on' else 'OFF'} (seq {seq})")


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


def cmd_delegate_offense(a) -> None:
    """S7b — the OWNER mints + publishes owner-signed delegations over the offense side's stable identity
    (exported by `vigil identity` as offense-identity.json). This is the sovereign half of the owner-tie
    ceremony: it reads only the offense PUBLIC keys, signs an offense-spine and an offense-governance
    DelegationCert with the persisted owner key, and writes them as inert JSON the offense side consumes
    (`vigil verify --delegation …` and the finding receiver). The owner private key never leaves here.

    TRUST ASSUMPTION (read this): this command signs over WHATEVER public keys are in the identity file — it
    has no way to authenticate the file's provenance. The identity file must reach you over an authenticated
    channel, OR you must confirm the printed pubkey fingerprints out-of-band against the offense host BEFORE
    trusting the delegation. A file swapped in transit would get an attacker's key owner-blessed. The command
    ECHOES exactly the keys it is about to sign so you can catch a swap in-band."""
    import json
    import time
    from pathlib import Path
    from .governor.identity import (
        delegate_offense_governance,
        delegate_offense_spine,
        ensure_owner_keypair,
        owner_pubkey,
    )
    from .reuse import AuthorizerKey
    identity = json.loads(Path(a.offense_identity).read_text(encoding="utf-8"))
    if identity.get("schema") != 1:
        print(f"refusing: unsupported offense-identity schema {identity.get('schema')!r} (expected 1)")
        return
    try:
        hours = float(a.hours)
    except (TypeError, ValueError):
        print(f"refusing: --hours {a.hours!r} is not a number")
        return
    if not (0 < hours <= 24 * 365 * 10) or hours != hours or hours in (float("inf"), float("-inf")):
        print(f"refusing: --hours must be a finite value in (0, {24 * 365 * 10}] (got {a.hours!r})")
        return
    owner = ensure_owner_keypair()
    not_after = int(time.time()) + int(hours * 3600)
    sp, gv = identity["spine"], identity["governance"]
    # ECHO the exact keys being blessed so the owner can catch a swapped/tampered identity file in-band.
    print("about to owner-sign delegations over these offense keys (verify out-of-band before trusting):")
    print(f"  spine      key_id={sp['key_id']!r}  pubkey={sp['public_key_b64']}")
    print(f"  governance key_id={gv['key_id']!r}  pubkey={gv['public_key_b64']}")
    spine_cert = delegate_offense_spine(
        owner, scope=a.scope, not_after=not_after,
        authorizers=[AuthorizerKey(key_id=sp["key_id"], name=sp["key_id"],
                                   public_key_b64=sp["public_key_b64"])])
    gov_cert = delegate_offense_governance(
        owner, scope=a.scope, not_after=not_after, threshold=1,
        authorizers=[AuthorizerKey(key_id=gv["key_id"], name=gv["key_id"],
                                   public_key_b64=gv["public_key_b64"])])
    out_dir = Path(a.out_dir) if a.out_dir else Path(a.offense_identity).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "offense-spine.deleg.json").write_text(spine_cert.model_dump_json(), encoding="utf-8")
    (out_dir / "offense-governance.deleg.json").write_text(gov_cert.model_dump_json(), encoding="utf-8")
    print(f"owner-signed offense delegations written → {out_dir}")
    print(f"  scope={a.scope!r}  not_after={not_after} (unix)")
    print("  offense-spine.deleg.json       (role offense-spine)")
    print("  offense-governance.deleg.json  (role offense-governance)")
    print(f"  PIN this owner pubkey at verify: {owner_pubkey()}")
    print("verify (offense side): vigil verify --base-dir <home> "
          f"--owner-pubkey {owner_pubkey()} --delegation <home>/offense-spine.deleg.json --scope {a.scope}")


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
    Returns the record seq, or None if the operator did not confirm.

    Stamps `issued_at` from THIS process's clock (the anti-replay high-water). The mesh module reads no
    clock — the authority over "when" belongs to the caller holding the owner key, which here is the
    operator at this terminal. Stamped AFTER the fingerprint confirmation, so an abandoned pairing
    consumes no high-water."""
    import time as _time

    fp = _device_fingerprint(pubkey)
    print(f"  device {device_id!r} fingerprint: {fp}")
    if not assume_yes:
        ans = confirm(f"  confirm this fingerprint matches what phone {device_id!r} shows? [yes/no] ")
        if (ans or "").strip().lower() != "yes":
            print("  aborted — fingerprint not confirmed; device NOT authorized")
            return None
    seq = authorize_device(store, device_id, pubkey, owner_key, issued_at=_time.time())
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
    """Start the glass-cockpit UI. Mints a fresh session token (printed here); every request needs it
    and no web page can read it. Read plane is GET-only; the owner-signed action plane is
    CSRF/Host/Origin-gated. Binds loopback by default; `--host`/`$SIGIL_UI_BIND` may bind a PRIVATE
    (WireGuard/Tailscale) address to sit behind a reverse proxy — FAIL-CLOSED (exit 2) on a public/
    unspecified bind, minting no token. To serve a real domain add its Host/Origin to the anti-rebind
    allowlist via `--allow-host`/`--allow-origin` (or `$SIGIL_UI_ALLOWED_HOSTS`/`$SIGIL_UI_ALLOWED_ORIGINS`)
    and terminate TLS at the proxy (see apps/sigil/deploy/REMOTE-HOSTING.md). Mirrors `cmd_bridge_serve`."""
    import os as _os
    import secrets

    from .bridge.daemon import bind_ok

    def _multi(flag_vals, env_name):
        # union of a repeatable flag and a comma-separated env var; blanks dropped
        out: list[str] = list(flag_vals or [])
        out += [s.strip() for s in _os.environ.get(env_name, "").split(",") if s.strip()]
        return tuple(dict.fromkeys(out))   # de-dup, order-preserving

    host = a.host or _os.environ.get("SIGIL_UI_BIND", "127.0.0.1")
    if not bind_ok(host):
        print(f"  refusing to bind {host!r}: the cockpit binds loopback or a PRIVATE (WireGuard/Tailscale) "
              f"address only — never 0.0.0.0 / an unspecified / a public address. Put a reverse proxy in "
              f"front to serve a real domain (deploy/REMOTE-HOSTING.md).", file=sys.stderr)
        sys.exit(2)
    allowed_hosts = _multi(a.allow_host, "SIGIL_UI_ALLOWED_HOSTS")
    allowed_origins = _multi(a.allow_origin, "SIGIL_UI_ALLOWED_ORIGINS")

    from .ui.server import serve
    serve(token=secrets.token_urlsafe(24), host=host, port=a.port,
          allowed_hosts=allowed_hosts, allowed_origins=allowed_origins)


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
    from . import config
    ok, msg = SpineStore().verify()
    print(("chain OK: " if ok else "chain FAIL: ") + msg)
    hok, hmsg = verify_checkpoint()
    # A head that EXISTS but does NOT authenticate (absent/bad owner signature, rewritten, or stale) is a
    # HARD, fail-closed failure: `sigil verify` is the composition point that ENFORCES head authentication
    # for the HA failover interlock (docs/architecture/HA-PROFILE.md §3.3) — even if the promotion guard is
    # bypassed, a passive whose head is not authentically owner-signed fails `sigil verify`. A spine with NO
    # head yet (never `sigil sign`ed) stays tolerated: only its chain integrity is asserted (byte-identical
    # to the pre-hardening behavior), so bootstrap/ingest flows are unaffected.
    head_present = config.HEAD_PATH.exists()
    print((("head  OK: " if hok else ("head  FAIL: " if head_present else "head  --: ")) + hmsg))
    sys.exit(0 if (ok and (hok or not head_present)) else 2)


def cmd_status(a) -> None:
    store, vi = SpineStore(), VectorIndex()
    ok, msg = store.verify()
    hok, hmsg = verify_checkpoint()
    print(f"spine:     {store.count()} records | next_seq {store.next_seq}")
    print(f"vectors:   {vi.count()} points | last_indexed_seq {vi.last_indexed_seq()}")
    print(f"chain:     {'OK' if ok else 'FAIL'} — {msg}")
    print(f"head:      {'OK' if hok else '(' + hmsg + ')'}")


def cmd_settings(a) -> None:
    """Settings inspection + the launcher's cross-plane env bridge.

    `status` prints the REDACTED settings view (no secret value).
    `export-runtime-env` prints, as JSON on stdout, the runtime LLM env the keyless offense engine needs
    — the model vars always, and (only with `--include-secrets`) the resolved API key. `vigil up` calls
    this in the SOVEREIGN venv and injects the result into the offense children's env, so the offense
    plane never imports sigil yet still honors the key/model set in the UI. This resolves secrets from the
    keyring/TPM-sealed store the launcher cannot itself decrypt. MACHINE USE ONLY: with --include-secrets
    it writes a secret to stdout — never redirect it to a file or a shared log."""
    from .ui import settings as _settings
    sub = getattr(a, "settings_cmd", "status")
    if sub == "export-runtime-env":
        print(json.dumps(_settings.export_runtime_env(getattr(a, "include_secrets", False))))
        return
    if sub == "check":
        # run ONE secret's live probe and print only the REDACTED verdict (status + reason, never the
        # value). Used by bootstrap to "test + connect" a cloud/remote credential (e.g. Neo4j) on deploy.
        # Always exits 0 — a failing/unknown check is informational, never fatal to a deploy.
        from .platform.secret_probes import check_secret_health   # noqa: PLC0415
        name = str(getattr(a, "secret_name", "") or "").strip()
        if name not in _settings.SECRET_NAMES:
            print(f"unknown secret {name!r}", file=sys.stderr)
            return
        rec = check_secret_health(name)
        print(f"{rec.get('status', 'unknown')}: {rec.get('reason', '')}")
        return
    # default: redacted status (safe to print anywhere)
    st = _settings.settings_status()
    print(f"secret backend: {st['secret_backend']}")
    for s in st["secrets"]:
        state = f"set ({s['fingerprint']})" if s["set"] else "not set"
        print(f"  {s['name']}: {state}")
    print(f"selected model: {st['selected_model'] or '(none — using defaults)'}")
    print(f"  offense reasoning: {st['offense_model']}")
    print(f"  sovereign reasoning: {st['sovereign_model'] or '(default)'}")
    if st["keyless"]:
        print("mode: KEYLESS — " + st["keyless_note"])


def cmd_inbound(a) -> None:
    """Drain / watch the offense→sovereign inert-finding spool onto the owner-signed spine (P5b).

    Owner-tied + fail-closed: a FINDING verifies under an OFFENSE_GOVERNANCE delegation, a DETECTION FACT
    under an OFFENSE_SPINE one — both owner-signed; a rejected envelope is quarantined in ``rejected/``,
    never appended. Verification is vigil_core only (this path imports no offense engine). There is NO
    network ingest endpoint — the seam is a directory drained by this local command."""
    from pathlib import Path

    from .governor.identity import owner_pubkey as _owner_pubkey
    from .inbound import SpoolWatcher

    owner = _owner_pubkey()
    if not owner:
        print("no owner identity on this machine — provision it first (`sigil sign`)", file=sys.stderr)
        sys.exit(2)

    def _load(path):
        if not path:
            return None
        from vigil_core.delegation import DelegationCert
        return DelegationCert.model_validate_json(Path(path).read_text(encoding="utf-8"))

    try:
        gov = _load(a.governance_delegation)
        spine = _load(a.spine_delegation)
    except (OSError, ValueError) as e:
        print(f"could not load a delegation: {e}", file=sys.stderr)
        sys.exit(2)
    if gov is None and spine is None:
        print("provide at least one owner-signed delegation: --governance-delegation (findings) and/or "
              "--spine-delegation (detections). The watcher is owner-tied + fail-closed.", file=sys.stderr)
        sys.exit(2)

    watcher = SpoolWatcher(SpineStore(), spool_dir=a.spool, owner_pubkey=owner, scope=a.scope,
                           governance_delegation=gov, spine_delegation=spine)
    if getattr(a, "inbound_cmd", "drain") == "watch":
        print(f"  watching {a.spool}/incoming → spine (scope={a.scope}); Ctrl-C to stop")
        try:
            watcher.watch(interval=a.interval)
        except KeyboardInterrupt:
            pass
    else:
        r = watcher.drain()
        print(f"  drained: {r['ingested']} ingested, {r['rejected']} rejected → spine seqs {r['seqs']}")


def cmd_knowledge(a) -> None:
    """Sovereign knowledge ops. ``export-learn-grants`` writes a signed inert ``learn_grant`` for each
    owner-APPROVED learn-proposal into a spool the OFFENSE side drains (``vigil learn-drain``) to run K3
    deep-learn (the A2 keystone). Fail-closed + gated on the kill-switch AND the ``autolearn`` latch;
    idempotent. Only signed bytes cross — the offense side re-derives the lead from its own intel."""
    from .knowledge import export_approved_grants

    if a.knowledge_cmd != "export-learn-grants":
        print(f"unknown knowledge command: {a.knowledge_cmd}", file=sys.stderr)
        sys.exit(2)
    if getattr(a, "watch", False):
        import time
        print(f"  exporting owner-approved learn-grants → {a.spool} "
              f"(gated on autolearn + kill-switch); Ctrl-C to stop")
        try:
            while True:
                out = export_approved_grants(SpineStore(), spool_dir=a.spool)
                if out.get("exported"):
                    print(f"  exported {out['exported']} learn-grant(s)")
                time.sleep(a.interval)
        except KeyboardInterrupt:
            pass
    else:
        print(f"  {export_approved_grants(SpineStore(), spool_dir=a.spool)}")


def cmd_owner_pubkey(a) -> None:
    """Print the base64 owner PUBLIC key (nothing if no owner identity exists). Read-only — the private key
    never leaves the sovereign store. Used by `vigil up` to hand the offense `learn-drain` its verify pin."""
    from .governor.identity import owner_pubkey
    pk = owner_pubkey()
    if pk:
        print(pk)


def cmd_key(a) -> None:
    """Owner-key ROTATION as a signed, cross-signed key HISTORY (W9-1).

      status     — print the succession chain: pinned genesis root → each epoch's key + seq window → tip,
                   and whether the on-disk owner key matches the validated tip.
      rotate     — cross-sign a fresh successor into the append-only key history, swap the at-rest key
                   material to it, and re-anchor the head. Every pre-rotation head/grant keeps verifying.
      re-genesis — the COMPROMISE fallback: mint a fresh genesis, REPIN the root, ABANDON continuity of all
                   pre-re-genesis history. Requires an explicit acknowledgement flag.
    """
    import time

    from .governor import key_history as kh
    from .governor.identity import genesis_owner_pubkey, owner_pubkey
    store = SpineStore()
    sub = getattr(a, "key_cmd", "status")
    if sub == "status":
        genesis = genesis_owner_pubkey()
        cur = owner_pubkey()
        if not genesis:
            print("owner key: none yet (run `sigil sign` to mint the owner identity)")
            return
        try:
            succ = kh.succession_from_store(store, genesis_pubkey=genesis)
        except kh.SuccessionError as e:
            print(f"owner-key succession: FORKED / AMBIGUOUS — fail-closed DENY until re-genesis: {e}",
                  file=sys.stderr)
            sys.exit(2)
        print(f"pinned genesis root : {succ.genesis}")
        for e in succ.epochs:
            end = "current" if e.end == float("inf") else f"< seq {int(e.end)}"
            print(f"  epoch {e.epoch:>3}  seq [{e.start}, {end})  {e.pubkey}")
        print(f"validated current   : {succ.current}")
        if cur and cur != succ.current:
            print(f"!! on-disk owner.pub ({cur}) is NOT the validated succession tip — tampered/inconsistent "
                  f"key state (recover with `sigil key re-genesis`)", file=sys.stderr)
            sys.exit(2)
        print(f"epochs: {len(succ.epochs)}  (rotations so far: {len(succ.epochs) - 1})")
        return
    if sub == "rotate":
        if not a.yes:
            print("refusing: `sigil key rotate` mints a NEW owner key, cross-signs it into the key history, "
                  "and re-anchors the head. Pre-rotation heads/grants keep verifying. Re-run with --yes.",
                  file=sys.stderr)
            sys.exit(2)
        try:
            new_kp, seq = kh.rotate(store, issued_at=time.time())
        except (ValueError, kh.SuccessionError) as e:
            print(f"!! rotation refused (fail-closed): {e}", file=sys.stderr)
            sys.exit(2)
        checkpoint(store)                                   # re-sign the head+floor under the NEW owner key
        print(f"owner key ROTATED. succession record @ seq {seq}.")
        print(f"new owner pubkey: {new_kp.public_key_b64}")
        print("every pre-rotation head and grant still verifies (walked from the pinned genesis root).")
        print("re-pin this new pubkey on any OUT-OF-BAND verifier that pins the CURRENT key, if it does not "
              "walk the succession chain.")
        return
    if sub == "re-genesis":
        if not (a.yes and a.i_understand):
            print("refusing: `sigil key re-genesis` mints a FRESH genesis and DELIBERATELY ABANDONS "
                  "verifiable continuity of ALL pre-re-genesis history (every prior head, grant and "
                  "succession record stops being authenticated by the new root). Use ONLY for an actual key "
                  "COMPROMISE. Re-run with --yes --i-understand-continuity-is-abandoned.", file=sys.stderr)
            sys.exit(2)
        new_kp, seq = kh.re_genesis(store, issued_at=time.time())
        checkpoint(store)
        print(f"owner key RE-GENESIS complete. marker record @ seq {seq}.")
        print(f"new genesis owner pubkey: {new_kp.public_key_b64}")
        print("ABANDONED: every pre-re-genesis head, grant and succession record is no longer authenticated "
              "by the new root. Out-of-band verifiers MUST re-pin to this new genesis key.")
        return
    print(f"unknown key subcommand {sub!r}", file=sys.stderr)
    sys.exit(2)


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


def cmd_upgrade(a) -> None:
    """`sigil upgrade` — the automated, crash-safe data-migration verb (W5-5, #449):
    verify(before) -> backup -> verify(backup) -> migrate -> verify(after) -> report, ROLLING BACK to the
    verified backup on ANY failure. Fail-closed: never leaves a half-migrated store. `--check` only reports
    whether a migration is needed (exit 3 if it is), touching nothing."""
    from .spine.store import SpineError
    from .spine.upgrade import UpgradeFailed, migration_needed, upgrade

    store = SpineStore()
    if getattr(a, "check", False):
        needed, reason = migration_needed(store)
        if needed:
            print(f"upgrade REQUIRED: {reason}")
            sys.exit(3)
        print("up to date: the spine is migrated (or fresh) — no upgrade needed")
        return

    try:
        rep = upgrade(store, backup=not getattr(a, "no_backup", False))
    except UpgradeFailed as e:
        print(f"upgrade FAILED: {e}", file=sys.stderr)
        r = e.report
        if r.get("rolled_back"):
            verified = r.get("rollback_verified")
            print(f"  ROLLED BACK to the verified backup: {r.get('backup')} "
                  f"(restored store verifies: {verified})", file=sys.stderr)
        else:
            print("  no state was mutated (nothing to roll back)", file=sys.stderr)
        sys.exit(2)
    except SpineError as e:
        # verify-before / backup-not-restorable: refused BEFORE any mutation (fail-closed).
        print(f"upgrade REFUSED (no state changed): {e}", file=sys.stderr)
        sys.exit(2)

    print(f"  verify before : OK ({rep['count_before']} records)")
    print(f"  backup        : {rep.get('backup', '(skipped)')}")
    if rep.get("verify_backup"):
        print(f"  backup verify : OK ({rep['verify_backup']['count']} records — restorable)")
    print(f"  migrated      : {rep.get('migrated')} | sealed {rep.get('sealed')} | "
          f"compacted {rep.get('compacted')} segment(s)")
    print(f"  verify after  : OK ({rep['count_after']} records — every record preserved)")
    print("  upgrade complete. Rollback (if ever needed): "
          "`sigil restore` / re-extract the backup tar.gz over the spine dir.")


def _load_failover_guard():
    """Load tools/ha/spine_failover_guard.py (sovereign-side) from the repo, so `sigil floor
    promote-passive` and the standalone guard share ONE implementation and cannot diverge. Loaded by
    file path (the tools/ dir is not an installed package) — FATAL-2-clean: it imports only sigil +
    vigil_core/vigil_integration, all already importable here on the sovereign side."""
    import importlib.util
    from pathlib import Path
    repo = Path(__file__).resolve().parents[3]           # apps/sigil/sigil/cli.py -> repo root
    guard_path = repo / "tools" / "ha" / "spine_failover_guard.py"
    if not guard_path.exists():
        print(f"!! failover guard not found at {guard_path}", file=sys.stderr)
        sys.exit(2)
    spec = importlib.util.spec_from_file_location("spine_failover_guard", guard_path)
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec: the module's @dataclass resolves its own annotations via
    # sys.modules[__module__], which is None for an unregistered spec-loaded module (TypeError at import).
    sys.modules.setdefault("spine_failover_guard", mod)
    spec.loader.exec_module(mod)
    return mod


def cmd_floor(a) -> None:
    """The durable external anti-rollback floor (hard-prune C1). `status` prints it (read-only). `reset`
    DELIBERATELY re-seeds it downward to the current spine — the only path that may lower it — for a
    legitimate reset/restore; owner-key-gated (re-signs the spine) + requires --yes."""
    from .governor.identity import owner_keypair
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
        # SHORTER head), then force the floor down to that fresh head — OWNER-signed (audit G2) so the
        # re-seeded floor is not left unsigned. owner_keypair() is None only if the vault is locked → the
        # floor is written unsigned (non-bricking), re-signed on the next checkpoint.
        fl = reset_floor(head, owner_key=owner_keypair())
        print(f"durable floor RE-SEEDED to current head: last_seq={fl.last_seq} base_seq={fl.base_seq} "
              f"base_count={fl.base_count}")
    elif a.action == "witness":
        # C-S4 emit-on-advance: witness the just-advanced floor's head + PERSIST it off-box. The retained
        # copy is the anchor that catches a same-host head+floor co-rewrite the LOCAL floor cannot.
        from pathlib import Path
        from vigil_integration.transparency import Witness
        from .spine import floor_witness as FW
        from .spine.checkpoint import _read_head_on_disk
        if not a.retain:
            print("!! `sigil floor witness` needs --retain <path> (the OFF-BOX path a verifier keeps)",
                  file=sys.stderr)
            sys.exit(2)
        head = _read_head_on_disk()
        if head is None:
            print("!! no signed spine head — run `sigil sign` first", file=sys.stderr)
            sys.exit(1)
        kp = owner_keypair()
        if kp is None:
            print("!! no owner key to co-sign with — run `sigil sign` first", file=sys.stderr)
            sys.exit(1)
        fl = load_floor()
        W, config, roster_path, _tip, owner_pub = _witness_ctx()
        import time as _time
        try:
            wc = FW.emit_floor_witness(head, fl, [Witness(config.OWNER_KEY_ID, kp.private_key_b64)],
                                       retain_path=Path(a.retain), scope=config.SCOPE, now=int(_time.time()))
        except (FW.FloorWitnessError, Exception) as e:  # noqa: BLE001 — surface any emit failure, never fake
            print(f"!! floor witness failed: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"floor witnessed + retained: {a.retain} (count {wc.checkpoint.entry_count}, "
              f"last_seq {wc.checkpoint.last_seq}, {len(wc.witness_signatures)} witness sig(s))")
        print("RETAIN THIS OFF-BOX — a copy kept only here is rolled back WITH the spine and is NOT an anchor.")
        _r, tr = _witness_trust_root(W, config, roster_path, owner_pub)
        print(f"guarantee: {FW.WA.guarantee_label(tr)}")
    elif a.action == "verify-witnessed":
        # C-S4 anchor-on-verify: REQUIRE the local head+floor to be consistent with the HIGHEST retained
        # witnessed checkpoint. Catches a head+floor co-rewrite / a floor stripped below a witnessed height.
        from pathlib import Path
        from .spine import floor_witness as FW
        from .spine.checkpoint import _read_head_on_disk
        if not a.external:
            print("!! `sigil floor verify-witnessed` needs --external <path> (repeatable) — the OFF-BOX "
                  "retained witnessed checkpoint(s)", file=sys.stderr)
            sys.exit(2)
        head = _read_head_on_disk()
        if head is None:
            print("!! no local head to verify — run `sigil sign` first", file=sys.stderr)
            sys.exit(1)
        sources = [sys.stdin.read() if x == "-" else Path(x).read_text() for x in a.external]
        fl = load_floor()
        W, config, roster_path, _tip, owner_pub = _witness_ctx()
        _r, tr = _witness_trust_root(W, config, roster_path, owner_pub)
        import time as _time
        ok, msg, _label = FW.verify_floor_against_witnessed(head, fl, sources, scope=config.SCOPE,
                                                            trust_root=tr, now=_time.time())
        print(("floor anti-rollback OK: " if ok else "floor anti-rollback FAIL: ") + msg)
        if ok:
            # HONEST NUDGE: this is the LIGHT height/fork-at-height anchor. It proves no rollback below the
            # witnessed height and no fork AT it, but NOT that the pruned PREFIX is byte-identical — a history
            # forked below the witnessed height and then RE-GROWN above it passes here. For full prefix
            # byte-identity, ALSO run the heavy `sigil checkpoint verify --external <path>` (ADR 0007).
            print("   note: for full pruned-PREFIX byte-identity (catches a fork-then-extend above this "
                  "height), also run `sigil checkpoint verify --external <path>`.")
        sys.exit(0 if ok else 2)
    elif a.action == "promote-passive":
        # HA active-passive FAILOVER INTERLOCK (Claim 6 Piece B). Refuse to promote this passive to ACTIVE
        # if its local synced head is BELOW an off-box witnessed checkpoint — a stale mirror must never roll
        # the durable floor back. Shares the exact logic of tools/ha/spine_failover_guard.py (loaded from the
        # repo) so the standalone tool and this verb cannot diverge. See docs/architecture/HA-PROFILE.md §3.
        from pathlib import Path

        from .spine.checkpoint import _read_head_on_disk
        if not a.witnessed:
            print("!! promote-passive needs --witnessed <path|-> (the OFF-BOX retained witnessed checkpoint "
                  "the passive must not roll back below)", file=sys.stderr)
            sys.exit(2)
        guard = _load_failover_guard()
        W, config, roster_path, tip_path, owner_pub = _witness_ctx()
        try:
            _roster, tr = _witness_trust_root(W, config, roster_path, owner_pub)
        except W.WitnessError as e:
            print(f"!! promote-passive refused (witness roster error): {e}", file=sys.stderr)
            sys.exit(2)
        data = sys.stdin.read() if a.witnessed == "-" else Path(a.witnessed).read_text(encoding="utf-8")
        head = _read_head_on_disk()
        # The guard AUTHENTICATES the local head (owner signature) against the owner-only trust root and
        # binds/extension-proves it against the witnessed checkpoint, so it needs the passive's live chain
        # AND the owner trust root (distinct from the witness quorum `tr`). See HA-PROFILE.md §3.
        owner_tr = W.witness_trust_root(None, owner_pub=owner_pub, owner_key_id=config.OWNER_KEY_ID)
        import time as _time
        verdict = guard.evaluate_promotion(head, data, scope=config.SCOPE, trust_root=tr,
                                           owner_trust_root=owner_tr, entries=SpineStore().entries(),
                                           now=_time.time())
        for line in verdict.lines():
            print(line, file=(sys.stdout if verdict.activate else sys.stderr))
        sys.exit(verdict.exit_code)


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
    # at-rest sealing status (audit G1). UNSEALED is a prominent WARNING, not a hard doctor failure —
    # the box works either way; provisioning is the operator's one-time choice.
    from .platform.vault import owner_vault
    _v = owner_vault()
    print(f"  [{'OK' if _v.enabled() else '**'}] {'vault':16} {_v.status()}")
    # kernel-binary integrity pin (audit G2). '**' unpinned is a WARNING (opt-in), '!!' is fail-closed
    # (a swapped binary / forged manifest — the kernel will NOT run). Any config drift is advisory.
    from .governor.integrity import config_drift, kernel_pin_status
    _mark, _detail = kernel_pin_status()
    print(f"  [{_mark}] {'kernel_pin':16} {_detail}")
    ok_all = ok_all and _mark != "!!"          # an active kernel tamper (!!) fails doctor; '**' (unpinned) does not
    for _warn in config_drift():
        print(f"  [**] {'config_drift':16} {_warn}")
    print("\neffective config (secrets redacted):")
    for k, v in effective_config().items():
        print(f"  {k:18} {v}")
    _sys.exit(0 if ok_all else 1)


def cmd_vault(a) -> None:
    """At-rest sealing of the trust root under a TPM-sealed KEK (audit G1): `status` | `provision`."""
    import sys as _sys

    from vigil_core.kek import KekError

    from .platform.vault import owner_vault
    v = owner_vault()
    if getattr(a, "vault_cmd", "status") == "provision":
        if v.enabled():
            print("vault already provisioned (a TPM-sealed KEK is present) — nothing to do.")
            return
        try:
            v.provision()
        except KekError as e:
            print(f"!! could not provision the TPM-sealed KEK: {e}")
            print("   one-time setup on this machine:")
            print("     sudo apt install tpm2-tools && sudo usermod -aG tss $USER   (then log out/in)")
            _sys.exit(1)
        print("vault provisioned — a fresh KEK is now TPM-sealed to this machine.")
        print("Trust-root keys + secrets seal at rest transparently on their next read/write.")
    else:
        print(f"vault: {v.status()}")


def cmd_key(a) -> None:
    """Key lifecycle (audit W9-2): rotate the spine DEK, the WARDEN kernel key and the TPM KEK; seal the
    WARDEN key. `status` reports the per-key sealing + succession state; the rotate verbs are
    verify-then-swap and FAIL-CLOSED — a leg that cannot be proven leaves every key untouched."""
    import sys as _sys
    from pathlib import Path

    from vigil_core.rotation import RotationError

    from . import config
    from .platform.vault import OWNER_PRIV_CONTEXT, owner_vault
    from .spine import envelope as _env
    from .spine.dek_rotation import DekRotationError, rotate_spine_dek
    from .warden_key import (
        WARDEN_KEY_CONTEXT, WardenKeyError, rotate_warden_key, seal_warden_key, verify_warden_succession,
    )
    from .warden_key import reconcile_warden_rotation
    v = owner_vault()
    verb = getattr(a, "key_cmd", "status")

    if verb == "status":
        from vigil_core import is_sealed
        print(f"vault: {v.status()}")
        for label, path, _ctx in _kek_sealed_files(config, OWNER_PRIV_CONTEXT, _env, WARDEN_KEY_CONTEXT):
            try:
                raw = Path(path).read_bytes()
                state = "SEALED" if is_sealed(raw) else "PLAINTEXT" if raw else "EMPTY"
            except OSError:
                state = "ABSENT"
            print(f"  {label:<12} {state:<9} {path}")
        try:
            emb = _spine_embedded_secrets(config)
            print(f"  embedded KEK-direct secrets (NOT KEK-rotatable in place): {len(emb)}"
                  + (f" [{', '.join(lbl for lbl, _b, _c in emb)}]" if emb else ""))
        except RotationError as e:
            print(f"  embedded KEK-direct secrets: UNKNOWN — {e}")
        if v.rotation_incomplete():
            print("  !! KEK rotation INCOMPLETE (.prev present) — run `sigil key reconcile`")
        ok, why = verify_warden_succession(config.SIGIL_HOME)
        print(f"  warden succession: {'OK' if ok else 'BROKEN'} — {why}")
        return

    if verb == "seal-warden":
        status = seal_warden_key(config.SIGIL_HOME, v)
        print(f"warden key seal: {status}")
        if status == "disabled":
            print("  (vault not provisioned — run `sigil vault provision` first)")
        return

    try:
        if verb == "reconcile":
            files = [(p, c) for (_l, p, c) in _kek_sealed_files(config, OWNER_PRIV_CONTEXT, _env, WARDEN_KEY_CONTEXT)]
            emb = _spine_embedded_secrets(config)
            kres = v.reconcile_kek_rotation(files, embedded_secrets=emb)
            print(f"KEK rotation reconcile: {kres['status']} ({kres['reconciled']} file(s) re-wrapped)")
            from .spine.dek_rotation import reconcile_spine_dek
            dres = reconcile_spine_dek(config.SPINE_PATH, v)
            print(f"spine DEK reconcile: {dres['status']} ({dres['rotated']} record(s))")
            wres = reconcile_warden_rotation(config.SIGIL_HOME, v)
            print(f"WARDEN rotation reconcile: {wres['status']}")
            return
        if verb == "rotate-warden":
            res = rotate_warden_key(config.SIGIL_HOME, v)
            print(f"WARDEN key rotated (succession seq {res['seq']}); new pub {res['new_pub'][:16]}…")
        elif verb == "rotate-dek":
            res = rotate_spine_dek(config.SPINE_PATH, v)
            print(f"spine DEK rotated: {res['rotated']} record(s) re-encrypted under a fresh DEK")
        elif verb == "rotate-kek":
            files = [(p, c) for (_l, p, c) in _kek_sealed_files(config, OWNER_PRIV_CONTEXT, _env, WARDEN_KEY_CONTEXT)]
            emb = _spine_embedded_secrets(config)  # enumerate KEK-direct spine-embedded secrets (TOTP, …)
            res = v.rotate_kek(files, embedded_secrets=emb)  # fail-closed if any embedded secret would orphan
            print(f"TPM KEK rotated: {res['rotated']} sealed file(s) re-wrapped under a fresh KEK")
    except (RotationError, DekRotationError, WardenKeyError) as e:
        print(f"!! rotation refused (fail-closed, nothing swapped): {e}", file=_sys.stderr)
        _sys.exit(1)


def _kek_sealed_files(config, owner_ctx, envmod, warden_ctx):
    """The vault-sealed FILES that rest under the TPM KEK, as (label, path, aead_context). Only files that
    exist are meaningful to rotate; callers filter. Excludes secrets embedded in the signed spine."""
    from .warden_key import warden_home
    return [
        ("owner.priv", config.KEYS_DIR / "owner.priv", owner_ctx),
        ("spine.dek", config.SPINE_DEK_PATH, envmod._DEK_CONTEXT),
        ("warden.key", warden_home(config.SIGIL_HOME) / "warden.key", warden_ctx),
        ("secrets.kv", config.SIGIL_HOME / "secrets.sealed", b"sigil/secrets.kv"),
    ]


def _spine_embedded_secrets(config):
    """Every KEK-direct secret sealed via ``Vault.seal_secret`` and embedded in the immutable owner-signed
    spine, as ``[(label, blob, context), …]`` — currently account TOTP second factors (S4). ``rotate_kek``
    consumes this to FAIL CLOSED (red-pen BLOCK): such a blob's ciphertext is signed into the append-only
    chain, so it cannot be re-wrapped in place, and rotating the KEK out from under it would permanently
    orphan it.

    FAIL-CLOSED: if the account feature is wired but the spine cannot be enumerated (a locked / tampered /
    unverifiable head), this RAISES :class:`RotationError` so the rotation REFUSES rather than proceed blind
    and orphan an unseen secret. Only a genuinely-absent account module (a minimal build with no such feature)
    yields ``[]``. A malformed base64 blob is skipped (it is not a live openable secret)."""
    import base64 as _b64

    from vigil_core.rotation import RotationError
    try:
        from .governor.accounts import TOTP_SEAL_CONTEXT, AccountsRegistry
    except ImportError:
        return []  # account feature not present in this build → no embedded secrets exist
    try:
        accts = AccountsRegistry(SpineStore()).accounts()
    except Exception as e:  # noqa: BLE001 — cannot prove absence → refuse the rotation (fail-closed)
        raise RotationError(f"cannot enumerate spine-embedded secrets to prove none would be orphaned "
                            f"({e}) — refusing the KEK rotation (fail-closed)") from e
    out = []
    for acct in accts:
        if getattr(acct, "totp_secret", None):
            try:
                blob = _b64.b64decode(acct.totp_secret)
            except (ValueError, TypeError):
                continue
            out.append((f"totp:{acct.username}", blob, TOTP_SEAL_CONTEXT))
    return out


def cmd_kernel(a) -> None:
    """WARDEN kernel-binary integrity pin (audit G2): `pin` owner-signs the resolved binary's content
    hash (+ scope / owner_key_id) into the security manifest; `status` reports the current verdict."""
    import sys as _sys

    from . import config
    from .governor.identity import ensure_owner_keypair, owner_keypair, owner_pubkey
    from .governor.integrity import build_manifest, config_drift, kernel_pin_status, write_manifest

    sub = getattr(a, "kernel_cmd", "status")
    if sub == "pin":
        kb = config.kernel_bin()
        if not kb:
            print("!! no kernel binary resolved — set SIGIL_KERNEL_BIN, add sigil-kernel to PATH, or "
                  "build kernel/target/release/sigil-kernel, then re-run `sigil kernel pin`.")
            _sys.exit(1)
        kp = owner_keypair()
        if kp is None:
            # An existing pubkey with no usable private half = a locked vault → fail-closed, do NOT mint
            # a new owner identity over the old one. Only a genuine first run (no pubkey) generates one.
            if owner_pubkey() is not None:
                print("!! the owner key is present but its private half is unavailable (locked vault) — "
                      "run `sigil vault provision`/unlock first; refusing to mint a new owner identity.")
                _sys.exit(1)
            kp = ensure_owner_keypair()
        manifest = build_manifest(kb, kp, scope=config.SCOPE, owner_key_id=config.OWNER_KEY_ID)
        write_manifest(manifest)
        print(f"pinned kernel binary {kb}")
        print(f"  sha256      {manifest['kernel_sha256']}")
        print(f"  scope       {manifest['scope']}")
        print(f"  owner_key_id {manifest['owner_key_id']}")
        print("The kernel now fails CLOSED (WARDEN classify → A3) if the binary or manifest is tampered.")
        return
    # status
    mark, detail = kernel_pin_status()
    print(f"kernel binary : {config.kernel_bin() or '(unresolved)'}")
    print(f"pin status    : [{mark}] {detail}")
    for warn in config_drift():
        print(f"config drift  : {warn}")


def _backup_passphrase(*, confirm: bool = False) -> str:
    """The backup passphrase: from env SIGIL_BACKUP_PASSPHRASE (unattended) or an interactive prompt.
    NEVER echoed, never stored — it is the only key to an off-box backup."""
    import getpass
    import os as _os
    pw = _os.environ.get("SIGIL_BACKUP_PASSPHRASE")
    if pw:
        return pw
    pw = getpass.getpass("backup passphrase: ")
    if confirm and pw != getpass.getpass("confirm passphrase: "):
        raise SystemExit("passphrases do not match")
    return pw


def cmd_backup(a) -> None:
    """Write a portable, passphrase-encrypted OFF-BOX backup of the trust root + spine (audit G3) — the
    ONLY disaster-recovery path for a TPM-sealed spine (the TPM binds the keys to this box)."""
    from . import config
    from .backup import BackupError, create_backup
    from .governor.identity import ensure_owner_keypair
    from .platform.vault import owner_vault
    try:
        res = create_backup(a.dest, _backup_passphrase(confirm=True), home=config.SIGIL_HOME,
                            vault=owner_vault(), owner_key=ensure_owner_keypair())
    except BackupError as e:
        print(f"!! backup failed: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"backup written: {res['dest']} ({res['files']} files; owner_key={res['owner_key']}, dek={res['dek']})")
    print("KEEP THE PASSPHRASE SAFE — it is the ONLY key to this backup (never stored; lose it → unrecoverable).")


def cmd_restore(a) -> None:
    """Restore a `sigil backup` onto a fresh SIGIL_HOME. VERIFIES the manifest owner-signature + every file
    hash BEFORE writing, and re-verifies the restored spine's chain/binding after; fail-closed on a wrong
    passphrase or any tamper. (The owner-signed HEAD is confirmed by a follow-up `sigil verify`.)"""
    from pathlib import Path

    from vigil_core.vault import Vault

    from .backup import BackupError, restore_backup
    home = Path(a.home)
    try:
        res = restore_backup(a.src, home, _backup_passphrase(), vault=Vault(home / "vault"),
                             force=getattr(a, "force", False))
    except BackupError as e:
        print(f"!! restore failed (nothing trusted): {e}", file=sys.stderr)
        sys.exit(1)
    print(f"restored to {res['home']} ({res['files']} files; chain verified={res['verified']}).")
    print(f"next:  SIGIL_HOME={res['home']} sigil verify   # confirms the owner-signed head against the restored key")
    print(f"then:  SIGIL_HOME={res['home']} sigil vault provision   # re-seals the keys to THIS box's TPM")


def _witness_ctx():
    """Resolve the config-bound witness inputs (the CLI is the sole config boundary; witness.py is
    config-free). Returns (W, config, roster_path, tip_path, owner_pub)."""
    from . import config
    from .governor.identity import owner_pubkey
    from .spine import witness as W
    pub = owner_pubkey()
    if not pub:
        # ADVISORY-1: exit 2 (fail-closed), CONSISTENT with the standalone guard's no-owner-key refusal
        # (tools/ha/spine_failover_guard.py _trust_root_from_config). A missing trust anchor is a refusal,
        # not a generic error — the promote-passive interlock and every witness verb must fail closed alike.
        print("!! no owner key yet — run `sigil sign` first to establish the trust root", file=sys.stderr)
        sys.exit(2)
    roster_path = config.SIGIL_HOME / "witness.trust.json"
    tip_path = config.HEAD_PATH.parent / "witness-tip.json"
    return W, config, roster_path, tip_path, pub


def _witness_trust_root(W, config, roster_path, owner_pub):
    roster = W.load_roster(roster_path, owner_pub=owner_pub, scope=config.SCOPE)
    return roster, W.witness_trust_root(roster, owner_pub=owner_pub, owner_key_id=config.OWNER_KEY_ID)


def cmd_checkpoint(a) -> None:
    """Witnessed anti-rollback checkpoints (audit G3(b)). `emit` produces a portable, witness-co-signed
    checkpoint of the current head to RETAIN OFF-BOX; `verify --external` proves the current head is an
    append-only extension of a retained checkpoint (the anti-rollback the local floor cannot give); `cosign`
    lets an INDEPENDENT witness add its signature on its own box; `witness` manages the trusted set."""
    from pathlib import Path

    from vigil_integration.transparency import Witness

    from .spine.checkpoint import _read_head_on_disk
    try:
        W, config, roster_path, tip_path, owner_pub = _witness_ctx()
    except SystemExit:
        raise

    if a.action == "emit":
        from .governor.identity import owner_keypair
        head = _read_head_on_disk()
        if head is None:
            print("!! no signed spine head — run `sigil sign` first", file=sys.stderr)
            sys.exit(1)
        kp = owner_keypair()
        if kp is None:
            print("!! no owner key to co-sign with — run `sigil sign` first", file=sys.stderr)
            sys.exit(1)
        import time as _time
        _now = int(_time.time())            # W7-5: stamp the anchor's emission timestamp (fail-closed staleness)
        try:
            wc = W.emit_checkpoint(head, [Witness(config.OWNER_KEY_ID, kp.private_key_b64)],
                                   tip_path=tip_path, scope=config.SCOPE, now=_now)
        except W.WitnessError as e:
            print(f"!! emit failed: {e}", file=sys.stderr)
            sys.exit(1)
        env = W.dump_witnessed(wc, scope=config.SCOPE, emitted_at=_now)
        if a.out == "-":
            print(env)
        else:
            out = Path(a.out) if a.out else (config.HEAD_PATH.parent / "checkpoint.witnessed.json")
            out.write_text(env + "\n")
            print(f"witnessed checkpoint written: {out} "
                  f"(count {wc.checkpoint.entry_count}, {len(wc.witness_signatures)} witness sig(s))")
            print("RETAIN THIS OFF-BOX — a USB stick, another machine, a remote commit, or the paired device.")
            print("A copy kept only here is rolled back WITH the spine; only an off-box copy is a real anchor.")
        try:
            _roster, tr = _witness_trust_root(W, config, roster_path, owner_pub)
            print(f"guarantee: {W.guarantee_label(tr)}")
        except W.WitnessError as e:
            print(f"guarantee: (witness roster error: {e})", file=sys.stderr)
    elif a.action == "verify":
        if not a.external:
            print("!! checkpoint verify needs --external <path|-> (the OFF-BOX retained checkpoint)", file=sys.stderr)
            sys.exit(2)
        head = _read_head_on_disk()
        if head is None:
            print("!! no local head to verify — run `sigil sign` first", file=sys.stderr)
            sys.exit(1)
        data = sys.stdin.read() if a.external == "-" else Path(a.external).read_text()
        store = SpineStore()
        cok, cmsg = store.verify()
        print(("chain OK: " if cok else "chain FAIL: ") + cmsg)
        hok, hmsg = verify_checkpoint()                       # the CURRENT head must be authentically owner-signed
        print(("head  OK: " if hok else "head  FAIL: ") + hmsg)
        try:
            _roster, tr = _witness_trust_root(W, config, roster_path, owner_pub)
            ok, msg = W.verify_against_external(data, head=head, entries=store.entries(),
                                                scope=config.SCOPE, trust_root=tr)
        except W.WitnessError as e:
            print(f"anti-rollback FAIL: {e}")
            sys.exit(2)
        print(("anti-rollback OK: " if ok else "anti-rollback FAIL: ") + msg)
        sys.exit(0 if (ok and cok and hok) else 2)
    elif a.action == "cosign":
        import os as _os
        kid = a.cosign_key_id or _os.environ.get("SIGIL_WITNESS_KEY_ID")
        priv = _os.environ.get("SIGIL_WITNESS_PRIV_B64")
        if not kid or not priv:
            print("!! cosign needs an INDEPENDENT witness key: --key-id <id> and $SIGIL_WITNESS_PRIV_B64",
                  file=sys.stderr)
            sys.exit(2)
        if not a.infile:
            print("!! cosign needs --in <path|-> (the checkpoint envelope to co-sign)", file=sys.stderr)
            sys.exit(2)
        data = sys.stdin.read() if a.infile == "-" else Path(a.infile).read_text()
        try:
            out_env = W.cosign_envelope(data, witness_key_id=kid, witness_priv_b64=priv)
        except W.WitnessError as e:
            print(f"!! cosign failed: {e}", file=sys.stderr)
            sys.exit(1)
        if not a.out or a.out == "-":
            print(out_env)
        else:
            Path(a.out).write_text(out_env + "\n")
            print(f"cosigned envelope written: {a.out}")
    elif a.action == "witness":
        _checkpoint_witness(a, W, config, roster_path, owner_pub)


def _checkpoint_witness(a, W, config, roster_path, owner_pub) -> None:
    from .governor.identity import ensure_owner_keypair
    sub = a.wsub or "list"
    try:
        roster = W.load_roster(roster_path, owner_pub=owner_pub, scope=config.SCOPE)
    except W.WitnessError as e:
        print(f"!! witness roster error: {e}", file=sys.stderr)
        sys.exit(1)

    def current_auths() -> list:
        if roster:
            return list(roster["authorizers"])
        return [{"key_id": config.OWNER_KEY_ID, "public_key_b64": owner_pub}]

    def _set(auths, threshold):
        return W.set_roster(auths, threshold, path=roster_path, owner_key=ensure_owner_keypair(),
                            scope=config.SCOPE)

    if sub == "list":
        tr = W.witness_trust_root(roster, owner_pub=owner_pub, owner_key_id=config.OWNER_KEY_ID)
        print(f"witness roster (scope {config.SCOPE}): threshold {tr.threshold} of {len(tr.authorizers)} witness(es)")
        for ak in tr.authorizers:
            print(f"  - {ak.key_id}: {ak.public_key_b64}")
        print(f"guarantee: {W.guarantee_label(tr)}")
        if roster is None:
            print("(default owner-only roster — no witness.trust.json configured yet)")
    elif sub == "add":
        if not a.key_id or not a.pubkey:
            print("!! witness add needs <key_id> <pubkey>", file=sys.stderr)
            sys.exit(2)
        auths = [x for x in current_auths() if x["key_id"] != a.key_id]
        auths.append({"key_id": a.key_id, "public_key_b64": a.pubkey})
        threshold = a.threshold if a.threshold else (roster["threshold"] if roster else 1)
        try:
            core = _set(auths, threshold)
        except W.WitnessError as e:
            print(f"!! witness add failed: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"witness added: {a.key_id}; roster now threshold {core['threshold']} of {len(core['authorizers'])}")
        tr = W.witness_trust_root(core, owner_pub=owner_pub, owner_key_id=config.OWNER_KEY_ID)
        print(f"guarantee: {W.guarantee_label(tr)}")
    elif sub == "remove":
        if not a.key_id:
            print("!! witness remove needs <key_id>", file=sys.stderr)
            sys.exit(2)
        auths = [x for x in current_auths() if x["key_id"] != a.key_id]
        if not auths:
            print("!! refusing to remove the last witness (a roster needs at least one)", file=sys.stderr)
            sys.exit(2)
        threshold = min(a.threshold or (roster["threshold"] if roster else 1), len(auths))
        core = _set(auths, threshold)
        print(f"witness removed: {a.key_id}; roster now threshold {core['threshold']} of {len(core['authorizers'])}")
    else:
        print(f"!! unknown witness sub-action {sub!r} (list|add|remove)", file=sys.stderr)
        sys.exit(2)


def main(argv=None) -> None:
    from .obs import configure_logging
    configure_logging()                      # one structured-logging setup at startup (level from SIGIL_LOG_LEVEL)
    p = argparse.ArgumentParser(prog="sigil")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="self-check the install (SIGIL_HOME, kernel, Qdrant, keyring, claude)").set_defaults(fn=cmd_doctor)
    pvault = sub.add_parser("vault", help="at-rest sealing of the trust root (TPM-sealed KEK): status | provision")
    pvault.add_argument("vault_cmd", choices=["status", "provision"], nargs="?", default="status")
    pvault.set_defaults(fn=cmd_vault)
    pkern = sub.add_parser("kernel", help="WARDEN kernel-binary integrity pin (audit G2): status | pin")
    pkern.add_argument("kernel_cmd", choices=["status", "pin"], nargs="?", default="status")
    pkern.set_defaults(fn=cmd_kernel)
    pkey = sub.add_parser("key", help="key lifecycle (audit W9-2): rotate the spine DEK / WARDEN key / TPM KEK; seal the WARDEN key")
    pkey.add_argument("key_cmd", nargs="?", default="status",
                      choices=["status", "seal-warden", "rotate-warden", "rotate-dek", "rotate-kek", "reconcile"])
    pkey.set_defaults(fn=cmd_key)
    pbak = sub.add_parser("backup", help="portable, passphrase-encrypted off-box backup of the trust root + spine (audit G3)")
    pbak.add_argument("dest", help="destination file for the encrypted backup")
    pbak.set_defaults(fn=cmd_backup)
    pres = sub.add_parser("restore", help="restore a `sigil backup` onto a fresh SIGIL_HOME (verifies before writing)")
    pres.add_argument("src", help="the encrypted backup file")
    pres.add_argument("home", help="a FRESH SIGIL_HOME dir to restore into")
    pres.add_argument("--force", action="store_true",
                      help="REPLACE a non-empty SIGIL_HOME. Without it, restore refuses a non-empty target "
                           "rather than overlay stale state. The replacement is staged + verified first and "
                           "swapped in atomically (crash-safe).")
    pres.set_defaults(fn=cmd_restore)
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
    pcap = sub.add_parser("capability",
                          help="enable/disable gesture, voice, or autolearn (owner-signed latch, audit W0/K2)")
    pcap.add_argument("target", choices=["status", "gesture", "voice", "autolearn", "both"])
    pcap.add_argument("state", nargs="?", choices=["on", "off"], help="on|off (omit for `status`)")
    pcap.add_argument("--reason", default="", help="reason recorded on the spine")
    pcap.set_defaults(fn=cmd_capability)
    pacc = sub.add_parser("accounts",
                          help="per-user RBAC accounts (Claim 6): create|assign|revoke|enroll-pubkey|"
                               "enroll-totp|set-password|disable-totp|list (owner-signed grants)")
    pacc.add_argument("accounts_cmd",
                      choices=["create", "assign", "revoke", "enroll-pubkey", "enroll-totp",
                               "set-password", "disable-totp", "list"])
    pacc.add_argument("username", nargs="?", default=None, help="the account username")
    pacc.add_argument("role", nargs="?", default=None, choices=[None, "viewer", "analyst", "operator"],
                      help="role for create/assign (viewer|analyst|operator; 'owner' is not grantable)")
    pacc.add_argument("--pubkey", default=None,
                      help="enroll-pubkey: the account's base64 Ed25519 PUBLIC key (challenge/response PoP "
                           "login); the private half never touches the host")
    pacc.add_argument("--pubkey-file", default=None,
                      help="enroll-pubkey: read the base64 public key from this file instead of --pubkey")
    pacc.set_defaults(fn=cmd_accounts)
    pgn = sub.add_parser("gesture-nav",
                         help="toggle gesture NAV-MODE (S3): in nav-mode a live armed session's swipes/pinch "
                              "NAVIGATE the UI (an A1 signal that injects nothing) instead of scroll/click")
    pgn.add_argument("state", nargs="?", choices=["status", "on", "off"], default="status")
    pgn.set_defaults(fn=cmd_gesture_nav)
    pdo = sub.add_parser("delegate-offense",
                         help="owner-sign delegations over the offense identity (S7b owner-tie ceremony)")
    pdo.add_argument("--offense-identity", required=True,
                     help="the offense-identity.json exported by `vigil identity`")
    pdo.add_argument("--scope", required=True, help="the engagement scope/slug the delegation is valid for")
    pdo.add_argument("--hours", default="24", help="validity window in hours from now (not_after)")
    pdo.add_argument("--out-dir", default="", help="where to write the .deleg.json (default: beside the identity)")
    pdo.set_defaults(fn=cmd_delegate_offense)

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
    pset = sub.add_parser("settings", help="show settings (redacted) | export the runtime LLM env for the launcher")
    pset.add_argument("settings_cmd", choices=["status", "export-runtime-env", "check"], nargs="?", default="status")
    pset.add_argument("secret_name", nargs="?", default="",
                      help="(check) the secret to live-probe, e.g. NEO4J_PASSWORD — prints only status + reason")
    pset.add_argument("--include-secrets", action="store_true",
                      help="(export-runtime-env) also emit the resolved API key — MACHINE USE ONLY, "
                           "never redirect to a file/log; used by `vigil up` to feed the offense engine")
    pset.set_defaults(fn=cmd_settings)
    pinb = sub.add_parser("inbound", help="drain/watch the offense→sovereign inert-finding spool onto the "
                                          "spine (owner-tied, fail-closed; no network endpoint)")
    pinb.add_argument("inbound_cmd", choices=["drain", "watch"], nargs="?", default="drain")
    pinb.add_argument("--spool", required=True, help="the spool directory (its incoming/ is drained)")
    pinb.add_argument("--governance-delegation", default=None,
                      help="owner-signed OFFENSE_GOVERNANCE delegation JSON (authorizes FINDINGS)")
    pinb.add_argument("--spine-delegation", default=None,
                      help="owner-signed OFFENSE_SPINE delegation JSON (authorizes DETECTION FACTs)")
    pinb.add_argument("--scope", default="*", help="engagement scope to confine ingest to (default: * = any)")
    pinb.add_argument("--interval", type=float, default=2.0, help="(watch) seconds between drains")
    pinb.set_defaults(fn=cmd_inbound)
    pkn = sub.add_parser("knowledge", help="sovereign knowledge ops: export owner-approved learn-grants to "
                                           "the offense spool (the K2b→K3 bridge; gated + fail-closed)")
    pkn.add_argument("knowledge_cmd", choices=["export-learn-grants"])
    pkn.add_argument("--spool", required=True,
                     help="the learn-grant spool dir the offense `vigil learn-drain` consumes")
    pkn.add_argument("--watch", action="store_true", help="keep exporting as new approvals land; Ctrl-C to stop")
    pkn.add_argument("--interval", type=float, default=2.0, help="(watch) seconds between export rounds")
    pkn.set_defaults(fn=cmd_knowledge)
    pop = sub.add_parser("owner-pubkey",
                         help="print the base64 owner PUBLIC key (read-only; for pinning the offense learn-drain)")
    pop.set_defaults(fn=cmd_owner_pubkey)
    pkey = sub.add_parser("key", help="owner-key rotation via a signed cross-signed key history (W9-1): "
                                      "status | rotate | re-genesis")
    pkey.add_argument("key_cmd", choices=["status", "rotate", "re-genesis"], nargs="?", default="status")
    pkey.add_argument("--yes", action="store_true", help="confirm a rotate / re-genesis")
    pkey.add_argument("--i-understand-continuity-is-abandoned", dest="i_understand", action="store_true",
                      help="re-genesis only: acknowledge that ALL pre-re-genesis history stops being "
                           "authenticated by the new root")
    pkey.set_defaults(fn=cmd_key)
    pfl = sub.add_parser("floor", help="durable external anti-rollback floor: status; reset (deliberate "
                                       "downward re-seed); witness (emit+retain off-box); verify-witnessed "
                                       "(anchor); promote-passive (HA failover interlock)")
    pfl.add_argument("action", choices=["status", "reset", "witness", "verify-witnessed", "promote-passive"])
    pfl.add_argument("--yes", action="store_true", help="confirm `reset` deliberately lowers the floor")
    pfl.add_argument("--retain", default="",
                     help="(witness) OFF-BOX path to persist the witnessed checkpoint the verifier retains")
    pfl.add_argument("--external", action="append", default=[],
                     help="(verify-witnessed) an OFF-BOX retained witnessed checkpoint (path or '-'); "
                          "repeatable — the HIGHEST valid one anchors")
    pfl.add_argument("--witnessed", dest="witnessed", default=None,
                     help="(promote-passive) the OFF-BOX retained witnessed checkpoint the passive must not "
                          "roll back below (- for stdin)")
    pfl.set_defaults(fn=cmd_floor)
    pup = sub.add_parser("upgrade",
                         help="automated crash-safe data migration: backup -> verify -> migrate -> verify "
                              "-> report, with ROLLBACK on any failure (W5-5)")
    pup.add_argument("--check", action="store_true",
                     help="only report whether a migration is needed (exit 3 if it is); mutate nothing")
    pup.add_argument("--no-backup", dest="no_backup", action="store_true",
                     help="skip the backup+rollback frame (disposable store only; still refuses a "
                          "non-verifying spine)")
    pup.set_defaults(fn=cmd_upgrade)
    psp = sub.add_parser("spine", help="segment rotation: migrate; rotate; compact; convert; status; prune-plan; verify-archive")
    psp.add_argument("action", choices=["migrate", "rotate", "compact", "convert", "status",
                                        "prune-plan", "verify-archive"])
    psp.add_argument("-K", "--boundary", type=int, default=None,
                     help="prune-plan: the segment-aligned boundary K (dry-run — checks §7 guards, archives NOTHING)")
    psp.add_argument("--archive", default=None, help="verify-archive: the archive dir (default SIGIL_HOME/spine/archive)")
    psp.set_defaults(fn=cmd_spine)
    pck = sub.add_parser("checkpoint",
                         help="witnessed anti-rollback checkpoints (audit G3(b)): emit | verify | cosign | witness")
    pck.add_argument("action", choices=["emit", "verify", "cosign", "witness"])
    pck.add_argument("wsub", nargs="?", default=None, help="witness sub-action: list | add | remove")
    pck.add_argument("key_id", nargs="?", default=None, help="witness key id (witness add/remove)")
    pck.add_argument("pubkey", nargs="?", default=None, help="witness Ed25519 public key b64 (witness add)")
    pck.add_argument("--out", default=None, help="emit/cosign output path (- for stdout; emit default: spine/checkpoint.witnessed.json)")
    pck.add_argument("--external", default=None, help="verify: the OFF-BOX retained witnessed checkpoint (- for stdin)")
    pck.add_argument("--in", dest="infile", default=None, help="cosign: the checkpoint envelope to co-sign (- for stdin)")
    pck.add_argument("--key-id", dest="cosign_key_id", default=None, help="cosign: this witness's key id (or $SIGIL_WITNESS_KEY_ID)")
    pck.add_argument("--threshold", type=int, default=None, help="witness add/remove: the m-of-n witness threshold")
    pck.set_defaults(fn=cmd_checkpoint)
    psv = sub.add_parser("serve", help="start the glass-cockpit UI (loopback default; private bind + "
                                       "reverse proxy for a domain)")
    psv.add_argument("--port", type=int, default=8733)
    psv.add_argument("--host", default=None,
                     help="bind address ($SIGIL_UI_BIND; default 127.0.0.1). Loopback or a PRIVATE "
                          "(WireGuard/Tailscale) IP only — never 0.0.0.0/public (fail-closed exit 2)")
    psv.add_argument("--allow-host", action="append", default=[],
                     help="reverse-proxy Host to accept, e.g. cockpit.example.com (repeatable; also "
                          "$SIGIL_UI_ALLOWED_HOSTS, comma-separated). Anti-DNS-rebinding allowlist")
    psv.add_argument("--allow-origin", action="append", default=[],
                     help="reverse-proxy Origin to accept, e.g. https://cockpit.example.com (repeatable; "
                          "also $SIGIL_UI_ALLOWED_ORIGINS, comma-separated)")
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
    _assert_store_operable_or_exit(a.cmd)
    a.fn(a)


# Commands that DIAGNOSE or FIX a degraded store must run even when a migration is needed — otherwise the
# gate would lock the operator out of the very tools that clear it. Everything else refuses to operate on an
# un-migrated (legacy, pre-segment) store and names `sigil upgrade`.
_MIGRATION_GATE_EXEMPT = frozenset({"upgrade", "spine", "doctor", "restore", "backup", "vault", "kernel"})


def _assert_store_operable_or_exit(cmd: str) -> None:
    """Fail-closed startup gate (W5-5, #449): refuse to run a normal command against a legacy (pre-segment)
    spine that already holds data, naming the command that fixes it. Exempts the recovery/diagnostic
    commands so the operator can always reach the fix. Never raises out of `main()` — prints and exits 3."""
    if cmd in _MIGRATION_GATE_EXEMPT:
        return
    from .spine.upgrade import MigrationRequired, assert_operable
    try:
        assert_operable()
    except MigrationRequired as e:
        print(f"sigil: refusing to run `{cmd}` — {e}", file=sys.stderr)
        sys.exit(3)
    except Exception:  # noqa: BLE001 — a transient store-open error is the COMMAND's to surface, not the gate's
        return


if __name__ == "__main__":
    main()
