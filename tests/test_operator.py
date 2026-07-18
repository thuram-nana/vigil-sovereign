"""SIGIL Phase 7 WS-B — OPERATOR: scope sandbox, grounded reads, and the plan → preview → approve →
execute → verify → rollback/undo transaction. Run: ~/.sigil/venv/bin/python tests/test_operator.py"""
import json
import os
import sys
import tempfile
from pathlib import Path

from sigil.agents.approvals import ApprovalQueue
from sigil.agents.base import Tier
from sigil.agents.operator import Operator, Step
from sigil.agents.operator_scope import OperatorScope
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class FakeClassifier:
    """Deterministic stand-in for the Rust oracle (fs.read=A0, fs.write=A1, fs.delete/shell=A3)."""
    def classify(self, tool):
        if tool == "fs.read":
            return Tier.A0
        if tool == "fs.write":
            return Tier.A1
        return Tier.A3          # fs.delete, shell.exec.*, unknown → fail-closed A3


def _root():
    return Path(tempfile.mkdtemp(prefix="op-root-"))


def _op(store, root, *, auto_write=True):
    scope = OperatorScope(read_roots=[str(root)], auto_write_roots=[str(root)] if auto_write else [])
    return Operator(store, scope=scope, classifier=FakeClassifier(), trusted_pubkey=OP)


# ---- B2 scope sandbox ----------------------------------------------------------------------------
def test_scope_refuses_outside_and_traversal():
    root = _root()
    sc = OperatorScope(read_roots=[str(root)])
    (root / "ok.txt").write_text("hi")
    assert sc.resolve(str(root / "ok.txt"), "read") is not None, "a path inside the root resolves"
    assert sc.resolve(str(root / ".." / "etc" / "passwd"), "read") is None, "traversal out is refused"
    assert sc.resolve("/etc/passwd", "read") is None, "an absolute path outside is refused"


def test_scope_symlink_escape_refused():
    root = _root()
    outside = _root()
    (outside / "secret").write_text("SECRET")
    (root / "link").symlink_to(outside / "secret")     # a symlink escaping the root
    sc = OperatorScope(read_roots=[str(root)])
    assert sc.resolve(str(root / "link"), "read") is None, "a symlink resolving outside the root is refused"


def test_empty_scope_is_deny_all():
    assert OperatorScope().resolve("/anything", "read") is None, "no roots ⇒ deny all (fail-closed)"


def test_operator_read_grounded_and_refuses_out_of_scope():
    root = _root()
    (root / "f.txt").write_text("the answer is 42")
    s = _store()
    op = _op(s, root)
    res = op.read(str(root / "f.txt"))
    rec = s.get(res.applied[0])
    assert rec.payload["content"] == "the answer is 42" and rec.payload["grounded"] is True
    r2 = op.read("/etc/passwd")
    assert not r2.applied and any("REFUSED" in n for n in r2.notes), "out-of-scope read is refused, not read"


# ---- B4 preview mutates nothing ------------------------------------------------------------------
def test_preview_does_not_mutate_and_diffs_a_write():
    root = _root()
    (root / "a.txt").write_text("old line\n")
    s = _store()
    rep, _ = _op(s, root).preview([Step("write", path=str(root / "a.txt"), content="new line\n")], subject="edit")
    assert rep.valid and (root / "a.txt").read_text() == "old line\n", "preview writes NOTHING to disk"
    assert "new line" in rep.steps[0].detail and "old line" in rep.steps[0].detail, "the diff is previewed"
    assert rep.steps[0].tier == "A1"


def test_preview_refuses_out_of_scope_plan():
    root = _root()
    s = _store()
    rep, res = _op(s, root).preview([Step("read", path="/etc/passwd")])
    assert not rep.valid and any("REFUSED" in n for n in res.notes)


# ---- B5 execute: auto (A1), approval-gated (A3), verify, rollback, undo, TOCTOU -------------------
def test_execute_auto_applies_a_reversible_write_and_undo_restores():
    root = _root()
    f = root / "a.txt"
    f.write_text("v1\n")
    s = _store()
    op = _op(s, root)
    rep, pres = op.preview([Step("write", path=str(f), content="v2\n")])
    assert rep.plan_tier == "A1", "an in-auto-write-ring reversible write is A1 (auto)"
    ex = op.execute(rep.plan_seq)
    assert ex.applied and f.read_text() == "v2\n", "the write is applied + post-image verified"
    undo = op.undo(ex.applied[0])
    assert f.read_text() == "v1\n" and undo.applied, "undo restores the pre-image byte-for-byte"


def test_delete_needs_approval_and_transaction_rolls_back_on_failure():
    root = _root()
    a, b = root / "a.txt", root / "b.txt"
    a.write_text("AAA"); b.write_text("BBB")
    s = _store()
    op = _op(s, root)
    # plan: write a.txt (ok), then delete b.txt (A3). Plan tier = A3 → needs approval.
    rep, pres = op.preview([Step("write", path=str(a), content="A2"), Step("delete", path=str(b))])
    plan_seq = rep.plan_seq
    assert rep.plan_tier == "A3"
    assert not op.execute(plan_seq).applied or "not executed" in op.execute(plan_seq).notes[0]  # unapproved → refused
    assert a.read_text() == "AAA", "nothing ran without approval"
    # approve → executes both, verified
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(plan_seq)
    ex = op.execute(plan_seq)
    assert ex.applied and a.read_text() == "A2" and not b.exists(), "approved plan applies + verifies"


def test_execute_rolls_back_all_on_a_mid_transaction_failure():
    root = _root()
    a = root / "a.txt"
    a.write_text("orig\n")
    s = _store()
    op = _op(s, root)
    # step 0: reversible write (applies). step 1: a shell that FAILS → rollback step 0 byte-identical.
    rep, pres = op.preview([Step("write", path=str(a), content="changed\n"),
                            Step("shell", argv=[sys.executable, "-c", "import sys; sys.exit(3)"])])
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(rep.plan_seq)
    ex = op.execute(rep.plan_seq)
    assert a.read_text() == "orig\n", "a mid-transaction failure rolls the applied write back byte-identical"
    assert any("rolled back" in n.lower() for n in ex.notes)


def test_rollback_is_honest_about_an_irreversible_shell():
    root = _root()
    a = root / "a.txt"
    a.write_text("orig\n")
    s = _store()
    op = _op(s, root)
    # shell (succeeds, IRREVERSIBLE) then a write that fails verification is hard to force; instead:
    # shell ok, then a delete of a MISSING-after we remove it out from under — simpler: shell ok then
    # a write to a path we make unwritable. Use: shell ok, then a second failing shell.
    rep, pres = op.preview([Step("shell", argv=[sys.executable, "-c", "print('ran')"]),
                            Step("shell", argv=[sys.executable, "-c", "import sys; sys.exit(1)"])])
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(rep.plan_seq)
    ex = op.execute(rep.plan_seq)
    assert any("IRREVERSIBLE" in n or "irreversible" in n.lower() for n in ex.notes), \
        "a rollback past a shell that already ran must honestly report it cannot fully undo"


def test_toctou_plan_hash_binding_aborts_on_external_change():
    root = _root()
    f = root / "a.txt"
    f.write_text("v1\n")
    s = _store()
    op = _op(s, root)
    rep, pres = op.preview([Step("write", path=str(f), content="v2\n")])
    f.write_text("CHANGED EXTERNALLY\n")               # the world changed after preview
    ex = op.execute(rep.plan_seq)
    assert not ex.applied or any("ABORT" in n.upper() for n in ex.notes), "a changed file aborts execute (hash binding)"
    assert f.read_text() == "CHANGED EXTERNALLY\n", "the aborted execute mutated nothing"


def test_shell_is_a3_never_auto():
    root = _root()
    s = _store()
    rep, _ = _op(s, root).preview([Step("shell", argv=["echo", "hi"])])
    assert rep.plan_tier == "A3", "any shell.exec is A3 (explicit) — never auto"


# ---- red-pen negative controls (BLOCK-1..8) ------------------------------------------------------
def _tamper_field(path, seq, key, val):
    lines = Path(path).read_text().splitlines()
    for i, ln in enumerate(lines):
        d = json.loads(ln)
        if d["seq"] == seq:
            d["payload"][key] = val
            lines[i] = json.dumps(d)
    Path(path).write_text("\n".join(lines) + "\n")


def test_hardlink_read_is_refused():                               # BLOCK-1
    root = _root(); outside = _root()
    (outside / "secret").write_text("OUT-OF-SCOPE-SECRET")
    try:
        os.link(outside / "secret", root / "innocent.txt")        # hardlink inside root → outside inode
    except OSError:
        return                                                    # cross-device: skip (can't hardlink)
    r = Operator(_store(), scope=OperatorScope(read_roots=[str(root)]),
                 classifier=FakeClassifier(), trusted_pubkey=OP).read(str(root / "innocent.txt"))
    assert not r.applied and any("REFUSED" in n for n in r.notes), "a multiply-linked file is refused (no path-confinement)"


def test_execute_rederives_tier_ignoring_a_tampered_plan_tier():   # BLOCK-2 (the important one)
    root = _root(); (root / "keep.txt").write_text("KEEP")
    s = _store(); op = _op(s, root)
    rep, _ = op.preview([Step("delete", path=str(root / "keep.txt"))])
    assert rep.plan_tier == "A3"
    _tamper_field(s.path, rep.plan_seq, "plan_tier", "A1")         # flip the stored field; steps+hash intact
    ex = op.execute(rep.plan_seq)                                 # NO approval
    assert not ex.applied and (root / "keep.txt").exists(), \
        "execute RE-DERIVES the tier from the hash-bound plan; a tampered plan_tier field can't skip approval"


def test_no_file_bytes_leak_into_the_spine():                     # BLOCK-7
    root = _root(); (root / "c.txt").write_text("OLDSECRET")
    s = _store(); op = _op(s, root)
    rep, _ = op.preview([Step("write", path=str(root / "c.txt"), content="NEWSECRET")])
    raw = Path(s.path).read_text()
    assert "NEWSECRET" not in raw and "OLDSECRET" not in raw, "no file bytes in the append-only spine"
    assert op.execute(rep.plan_seq).applied and (root / "c.txt").read_text() == "NEWSECRET", "content came from the 0700 journal"


def test_write_and_undo_preserve_file_mode():                     # BLOCK-3 / BLOCK-4
    root = _root(); f = root / "s.sh"; f.write_text("v1"); os.chmod(f, 0o755)
    s = _store(); op = _op(s, root)
    rep, _ = op.preview([Step("write", path=str(f), content="v2")])
    ex = op.execute(rep.plan_seq)
    assert (f.stat().st_mode & 0o777) == 0o755, "write preserves the original mode (not 0600)"
    op.undo(ex.applied[0])
    assert f.read_text() == "v1" and (f.stat().st_mode & 0o777) == 0o755, "undo restores content AND mode"


def test_undo_is_single_shot_and_wont_clobber_newer_work():       # BLOCK-6
    root = _root(); f = root / "a.txt"; f.write_text("v1")
    s = _store(); op = _op(s, root)
    rep, _ = op.preview([Step("write", path=str(f), content="v2")])
    ex = op.execute(rep.plan_seq)
    # (a) newer work after execute → undo refuses to clobber it
    f.write_text("v3-legit-new-work")
    u = op.undo(ex.applied[0])
    assert f.read_text() == "v3-legit-new-work", "undo will NOT clobber a file changed since execute (hash-bound)"
    assert any("changed since execute" in n or "NOT clobbered" in n for n in u.notes)
    # (b) reset to the executed state, undo once (restores v1), then a SECOND undo is refused
    f.write_text("v2")
    op.undo(ex.applied[0]); r2 = op.undo(ex.applied[0])
    assert not r2.applied and any("already undone" in n for n in r2.notes), "a second undo is refused (single-shot)"


def test_rollback_reports_partial_on_a_failed_restore():          # BLOCK-5
    root = _root(); op = _op(_store(), root)
    n, note = op._rollback([{"op": "restore", "path": str(root / "x.txt"),
                             "pre": "/nonexistent/pre", "pre_mode": None, "post_hash": None}])
    assert n == 0 and "PARTIAL" in note, "a restore that failed is reported PARTIAL — never 'clean rollback'"


def test_two_ring_write_outside_auto_write_is_queued():           # BLOCK-8
    root = _root(); f = root / "a.txt"; f.write_text("v1")
    s = _store(); op = _op(s, root, auto_write=False)             # read ring = root, auto-write = empty
    rep, _ = op.preview([Step("write", path=str(f), content="v2")])
    assert rep.valid and rep.plan_tier == "A2", "a write in the read ring but not the auto-write ring is A2 (queued)"
    assert not op.execute(rep.plan_seq).applied, "an A2 write needs approval"
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(rep.plan_seq)
    assert op.execute(rep.plan_seq).applied and f.read_text() == "v2", "approved → applied"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-7 WS-B (Operator) guarantees hold")
