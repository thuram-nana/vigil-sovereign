"""OPERATOR (Phase 7, WS-B) — opens folders/files and runs terminal commands ON REQUEST, with every
step WARDEN-tiered and the whole thing transactional. Ceiling A2 (proposes; destructive steps queue).

PLAN → PREVIEW → APPROVE → EXECUTE → VERIFY → ROLLBACK/UNDO:
  • tier is DERIVED, never declared — each step's tool token (`fs.read`/`fs.write`/`fs.delete`/
    `shell.exec.<argv0>`) is classified by the fail-closed Rust oracle (`KernelClassifier`), and the
    approval requirement is RE-DERIVED from the hash-bound preview at execute (never a trusted field).
  • scope-gated (two rings): reads/writes must resolve inside the READ ring; a write auto-applies (A1)
    only inside the narrower AUTO-WRITE ring, else it is A2 (queued). Empty rings = deny-all.
  • PREVIEW mutates NOTHING; the approval BINDS to the previewed content hash — before executing, the
    Operator re-previews the CURRENT files and aborts on any mismatch (anti-TOCTOU).
  • the executable plan (with file contents) lives in a 0700 journal, NOT the append-only spine — no
    file bytes leak into immutable memory; the spine record carries only hashes.
  • EXECUTE journals a pre-image (bytes + mode) before each mutating step, applies atomically,
    RESTORES the original mode, and VERIFIES by re-reading the post-image hash.
  • ROLLBACK restores every applied step in reverse and is HONEST about a restore that failed or an
    irreversible `shell` that already ran. UNDO is hash-bound (won't clobber newer work), scope-re-
    resolved, and single-shot (a second undo is refused)."""
from __future__ import annotations

import difflib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from ..config import SIGIL_HOME
from ..reuse import canonical_json, sha256_hex
from .base import Agent, AgentResult, Proposal, Tier
from .operator_scope import OperatorScope

_OP_HOME = SIGIL_HOME / "operator"
_JOURNAL = _OP_HOME / "journal"          # per-execute pre-images
_PLANS = _OP_HOME / "plans"              # executable plans (with content) — off the spine


def _hash_bytes(b: bytes) -> str:
    return sha256_hex(b)


def _secure(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass


@dataclass(frozen=True)
class Step:
    op: str                                   # read | write | delete | shell
    path: Optional[str] = None
    content: Optional[str] = None
    argv: Optional[List[str]] = None
    cwd: Optional[str] = None


def _tool_token(step: Step) -> str:
    if step.op in ("read", "write", "delete"):
        return f"fs.{step.op}"
    if step.op == "shell":
        return f"shell.exec.{Path((step.argv or ['?'])[0]).name}"   # 'exec' → A3 by the oracle
    return "unknown.op"                                              # → fail-closed A3


@dataclass
class StepPreview:
    step: dict
    tool_token: str
    tier: str
    in_scope: bool
    reversible: bool
    detail: str                                # diff/manifest/argv — DISPLAY ONLY (never persisted)
    pre_hash: Optional[str] = None
    post_hash: Optional[str] = None


@dataclass
class PreviewReport:
    valid: bool
    plan_hash: str
    plan_tier: str
    steps: List[StepPreview] = field(default_factory=list)
    reason: str = ""
    plan_seq: Optional[int] = None


class Operator(Agent):
    name = "OPERATOR"
    mandate = "open files + run commands on request; tiered, previewed, transactional, reversible"
    ceiling = Tier.A2

    def __init__(self, store=None, *, scope: Optional[OperatorScope] = None, classifier=None,
                 trusted_pubkey=None):
        super().__init__(store)
        self.scope = scope or OperatorScope()
        self._classifier = classifier
        self._trusted_pubkey = trusted_pubkey

    def _cls(self):
        if self._classifier is None:
            from .kernel_classify import KernelClassifier
            self._classifier = KernelClassifier()
        return self._classifier

    def _tp(self):
        if self._trusted_pubkey is None:
            from ..governor.identity import owner_pubkey
            self._trusted_pubkey = owner_pubkey()
        return self._trusted_pubkey

    # --- B3: grounded read (hardlink-guarded) -----------------------------------------------------
    def read(self, path: str, question: str = "") -> AgentResult:
        rp = self.scope.resolve(path, "read")
        # BLOCK-1: a regular file with >1 hardlink cannot be confined to the ring by path (a link
        # inside the root may alias an out-of-scope inode) → refuse, fail-closed.
        if rp is not None and rp.is_file() and rp.stat().st_nlink > 1:
            rp = None
        if rp is None:
            self.store.append(kind="refusal", source="agent", actor=self.name,
                              payload={"tier": "A0", "decision": "refused", "requested": path,
                                       "reason": "path is outside the Operator read scope (or a hardlink)"})
            res = AgentResult(agent=self.name)
            res.notes.append(f"REFUSED read {path}: outside scope / hardlink (logged, not read)")
            return res
        try:
            data = rp.read_bytes()
        except OSError as e:
            res = AgentResult(agent=self.name)
            res.notes.append(f"could not read {rp}: {e}")
            return res
        return self._dispatch([Proposal("event", {
            "signal": "operator.read", "subject": question or str(rp),
            "path": str(rp), "sha256": _hash_bytes(data), "bytes": len(data),
            "summary": f"read {rp} ({len(data)} bytes)",
            "content": data.decode("utf-8", "replace")[:20000],   # verbatim bytes — authoritative
            "grounded": True,
        }, Tier.A0)])

    # --- B4: preview (no mutation; content journaled off-spine) -----------------------------------
    def _preview_step(self, step: Step) -> StepPreview:
        token = _tool_token(step)
        tier = self._cls().classify(token)
        in_scope, reversible, detail = True, False, ""
        pre_hash = post_hash = None
        if step.op == "shell":
            in_scope = self.scope.in_read(step.cwd) if step.cwd else True
            detail = "argv: " + " ".join(step.argv or []) + (f"  (cwd {step.cwd})" if step.cwd else "")
        else:
            rp = self.scope.resolve(step.path or "", "read")   # both reads AND writes must be in the READ ring
            in_scope = rp is not None
            old = None
            if rp is not None and rp.exists():
                try:
                    old = rp.read_bytes(); pre_hash = _hash_bytes(old)
                except OSError:
                    old = None
            if step.op == "read":
                detail, reversible = f"read {step.path}", True
            elif step.op == "write":
                new = (step.content or "").encode("utf-8")
                post_hash = _hash_bytes(new)
                oldt = (old or b"").decode("utf-8", "replace")
                detail = "".join(difflib.unified_diff(
                    oldt.splitlines(keepends=True), (step.content or "").splitlines(keepends=True),
                    fromfile=f"a/{step.path}", tofile=f"b/{step.path}")) or "(no textual change)"
                reversible = True
            elif step.op == "delete":
                detail = f"DELETE {step.path} (sha256 {pre_hash or 'missing'})"
                reversible = old is not None
        return StepPreview(step=asdict(step), tool_token=token, tier=tier.label(), in_scope=in_scope,
                           reversible=reversible, detail=detail, pre_hash=pre_hash, post_hash=post_hash)

    @staticmethod
    def _plan_hash(previews: List[StepPreview]) -> str:
        basis = [{"step": p.step, "tool_token": p.tool_token, "pre_hash": p.pre_hash,
                  "post_hash": p.post_hash} for p in previews]
        m = canonical_json(basis)
        return sha256_hex(m if isinstance(m, bytes) else m.encode())

    def _effective_tier(self, p: StepPreview) -> Tier:
        t = {"A0": Tier.A0, "A1": Tier.A1, "A2": Tier.A2, "A3": Tier.A3}[p.tier]
        if p.step["op"] in ("write", "delete"):
            if not p.reversible:
                t = max(t, Tier.A3)                                  # irreversible → explicit
            elif not self.scope.in_auto_write(p.step["path"] or ""):
                t = max(t, Tier.A2)                                  # in read ring, not auto-write → queue
        return t

    def preview(self, steps: List[Step], *, subject: str = "") -> tuple[PreviewReport, AgentResult]:
        previews = [self._preview_step(s) for s in steps]
        if any(not p.in_scope for p in previews):
            self.store.append(kind="refusal", source="agent", actor=self.name,
                              payload={"tier": "A0", "decision": "refused", "subject": subject,
                                       "reason": "plan has out-of-scope step(s)"})
            res = AgentResult(agent=self.name)
            res.notes.append("REFUSED plan: out-of-scope step(s) — nothing recorded as executable")
            return PreviewReport(False, "", "A3", previews, "refused: out-of-scope"), res
        plan_hash = self._plan_hash(previews)
        plan_tier = max((self._effective_tier(p) for p in previews), default=Tier.A0)
        # executable plan (WITH content) → 0700 journal, keyed by hash; NEVER the append-only spine
        _secure(_OP_HOME); _secure(_PLANS)
        (_PLANS / f"{plan_hash}.json").write_text(
            json.dumps({"plan_hash": plan_hash, "steps": [asdict(s) for s in steps]}), encoding="utf-8")
        # spine record: REDACTED — hashes only, no file bytes (BLOCK-7)
        redacted = [{"op": s.op, "path": s.path, "argv": s.argv, "cwd": s.cwd,
                     "content_sha256": (_hash_bytes((s.content or "").encode()) if s.op == "write" else None)}
                    for s in steps]
        res = self._dispatch([Proposal("operation", {
            "signal": "operator.plan", "subject": subject or "operator plan",
            "summary": f"plan: {len(steps)} step(s), tier {plan_tier.label()}, hash {plan_hash[:12]}",
            "plan_hash": plan_hash, "plan_tier": plan_tier.label(), "plan_journal": str(_PLANS / f"{plan_hash}.json"),
            "steps_redacted": redacted,
            "previews": [{"op": p.step["op"], "path": p.step.get("path"), "tool_token": p.tool_token,
                          "tier": p.tier, "reversible": p.reversible, "pre_hash": p.pre_hash,
                          "post_hash": p.post_hash} for p in previews],
        }, plan_tier)])
        rep = PreviewReport(True, plan_hash, plan_tier.label(), previews, "previewed (no mutation)")
        rep.plan_seq = res.applied[0] if res.applied else (res.queued[0]["seq"] if res.queued else None)
        return rep, res

    # --- B5: execute --------------------------------------------------------------------------------
    def _approved(self, plan_seq: int) -> bool:
        from ..mesh import authorized_devices
        from .approvals import SIGNAL as APPROVAL_SIGNAL
        from .approvals import verify_approval
        tp = self._tp()
        devices = authorized_devices(self.store, tp)   # the owner + any owner-authorized device may approve
        for r in self.store.iter_records(since_seq=plan_seq):
            p = r.payload
            if (p.get("signal") == APPROVAL_SIGNAL and p.get("target_seq") == plan_seq
                    and p.get("approval") == "approved" and verify_approval(r, tp, extra_pubkeys=devices)):
                return True
        return False

    def execute(self, plan_seq: int) -> AgentResult:
        rec = self.store.get(plan_seq)
        res = AgentResult(agent=self.name)
        if rec is None or rec.payload.get("signal") != "operator.plan":
            res.notes.append(f"seq {plan_seq} is not an operator plan")
            return res
        try:
            steps = [Step(**s) for s in json.loads(Path(rec.payload["plan_journal"]).read_text())["steps"]]
        except (OSError, ValueError, KeyError, TypeError):
            res.notes.append("plan journal missing/unreadable — cannot execute")
            return res
        fresh = [self._preview_step(s) for s in steps]
        # ANTI-TOCTOU: the plan hash (which binds steps + pre/post images) must still match the record.
        if any(not p.in_scope for p in fresh) or self._plan_hash(fresh) != rec.payload.get("plan_hash"):
            self.store.append(kind="refusal", source="agent", actor=self.name,
                              payload={"tier": "A0", "decision": "refused", "target_seq": plan_seq,
                                       "reason": "plan hash changed since preview (file changed / out-of-scope) — aborted"})
            res.notes.append("ABORTED: the world changed since preview (hash mismatch) — nothing executed")
            return res
        # BLOCK-2: RE-DERIVE the tier from the hash-bound previews; never trust the stored plan_tier field.
        plan_tier = max((self._effective_tier(p) for p in fresh), default=Tier.A0)
        if plan_tier in (Tier.A2, Tier.A3) and not self._approved(plan_seq):
            res.notes.append(f"plan is {plan_tier.label()} — needs a verified owner approval of seq {plan_seq}; not executed")
            return res

        jdir = _JOURNAL / f"plan-{plan_seq}"
        _secure(_OP_HOME); _secure(_JOURNAL); _secure(jdir)
        applied: List[dict] = []
        for i, step in enumerate(steps):
            ok, note, inverse = self._apply(step, fresh[i], jdir, i)
            if not ok:
                rolled, rb_note = self._rollback(applied)
                seq = self.store.append(kind="operation", source="agent", actor=self.name,
                                        payload={"signal": "operator.execute", "target_seq": plan_seq,
                                                 "decision": "auto", "tier": "A1", "status": "FAILED+ROLLED_BACK",
                                                 "failed_step": i, "note": note, "rolled_back": rolled,
                                                 "rollback_note": rb_note})
                res.applied.append(seq)
                res.notes.append(f"step {i} FAILED ({note}); rolled back {rolled} step(s). {rb_note}")
                return res
            if inverse is not None:
                applied.append(inverse)
        seq = self._dispatch([Proposal("operation", {
            "signal": "operator.execute", "target_seq": plan_seq, "status": "APPLIED",
            "summary": f"executed plan {plan_seq}: {len(steps)} step(s) applied + verified",
            "journal": str(jdir), "inverses": applied,
        }, Tier.A1)]).applied
        res.applied.extend(seq)
        res.notes.append(f"executed plan {plan_seq}: {len(steps)} step(s) applied, post-images verified")
        return res

    def _apply(self, step: Step, pv: StepPreview, jdir: Path, i: int):
        if step.op == "read":
            return True, "read", None
        if step.op == "shell":
            try:
                proc = subprocess.run(step.argv or [], cwd=step.cwd, capture_output=True, text=True, timeout=120)
            except (subprocess.SubprocessError, OSError) as e:
                return False, f"shell error: {e}", None
            if proc.returncode != 0:
                return False, f"shell exited {proc.returncode}", None
            return True, "shell ok (exit 0; IRREVERSIBLE)", {"op": "irreversible", "step": i, "argv": step.argv}
        rp = self.scope.resolve(step.path or "", "read")
        if rp is None:
            return False, "path left scope at execute time", None
        pre = rp.read_bytes() if rp.exists() else None
        pre_mode = (rp.stat().st_mode & 0o777) if rp.exists() else None
        if pre is not None:
            (jdir / f"{i}.pre").write_bytes(pre)                    # journal pre-image bytes...
        if step.op == "write":
            new = (step.content or "").encode("utf-8")
            fd, tmp = tempfile.mkstemp(dir=str(rp.parent), prefix=".op-")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(new)
                os.replace(tmp, rp)                                  # atomic
            except OSError as e:
                Path(tmp).unlink(missing_ok=True)
                return False, f"write failed: {e}", None
            if pre_mode is not None:
                try:
                    os.chmod(rp, pre_mode)                           # BLOCK-4: preserve the original mode
                except OSError:
                    pass
            if _hash_bytes(rp.read_bytes()) != pv.post_hash:        # VERIFY by re-reading the world
                return False, "post-image hash mismatch after write", None
            inv = {"op": "restore" if pre is not None else "delete-created", "path": str(rp),
                   "pre": str(jdir / f"{i}.pre") if pre is not None else None, "pre_mode": pre_mode,
                   "post_hash": pv.post_hash}
            return True, "write applied + verified", inv
        if step.op == "delete":
            if pre is None:
                return True, "delete: target already absent", None
            try:
                rp.unlink()
            except OSError as e:
                return False, f"delete failed: {e}", None
            if rp.exists():
                return False, "post-image mismatch: file still present after delete", None
            return True, "delete applied + verified", {"op": "restore", "path": str(rp),
                                                       "pre": str(jdir / f"{i}.pre"), "pre_mode": pre_mode,
                                                       "post_hash": None}
        return False, f"unknown op {step.op}", None

    def _restore_one(self, inv: dict, *, verify_unchanged: bool) -> tuple[bool, Optional[str]]:
        """Restore a single inverse. Returns (restored, skip_reason). `verify_unchanged` (undo) refuses
        to clobber a file the owner changed since (hash-bind), and re-resolves the path through scope."""
        path = inv.get("path")
        if verify_unchanged:
            if path is None or self.scope.resolve(path, "read") is None:
                return False, f"{path}: left scope — not restored"
            cur = Path(path)
            cur_hash = _hash_bytes(cur.read_bytes()) if cur.exists() else None
            if inv.get("post_hash") is not None and cur_hash != inv.get("post_hash"):
                return False, f"{path}: changed since execute — NOT clobbered"
            if inv.get("op") == "delete-created" and cur_hash != inv.get("post_hash"):
                return False, f"{path}: changed since execute — not deleted"
        try:
            if inv["op"] == "restore":
                shutil.copyfile(inv["pre"], path)
                if inv.get("pre_mode") is not None:
                    os.chmod(path, inv["pre_mode"])                 # BLOCK-3: restore original mode
            elif inv["op"] == "delete-created":
                Path(path).unlink(missing_ok=True)
            else:
                return False, None                                  # irreversible — handled by caller
            return True, None
        except OSError as e:
            return False, f"{path}: restore FAILED ({e})"

    def _rollback(self, applied: List[dict], *, verify_unchanged: bool = False) -> tuple[int, str]:
        n, failed, irreversible = 0, [], []
        for inv in reversed(applied):
            if inv["op"] == "irreversible":
                irreversible.append(inv.get("step"))
                continue
            ok, why = self._restore_one(inv, verify_unchanged=verify_unchanged)
            if ok:
                n += 1
            elif why:
                failed.append(why)                                  # BLOCK-5: never call a failed restore clean
        parts = []
        if failed:
            parts.append("PARTIAL — not restored: " + "; ".join(failed))
        if irreversible:
            parts.append(f"step(s) {irreversible} IRREVERSIBLE (shell already ran)")
        return n, ("; ".join(parts) if parts else "clean rollback")

    def undo(self, execute_seq: int) -> AgentResult:
        rec = self.store.get(execute_seq)
        res = AgentResult(agent=self.name)
        if rec is None or rec.payload.get("signal") != "operator.execute" or rec.payload.get("status") != "APPLIED":
            res.notes.append(f"seq {execute_seq} is not an applied operator execution")
            return res
        # BLOCK-6: single-shot — refuse a second undo of the same execution.
        for r in self.store.iter_records(since_seq=execute_seq):
            if r.payload.get("signal") == "operator.undo" and r.payload.get("target_seq") == execute_seq:
                res.notes.append(f"execute {execute_seq} was already undone (seq {r.seq}) — refusing a replay")
                return res
        n, note = self._rollback(rec.payload.get("inverses", []), verify_unchanged=True)  # hash-bound, scope-checked
        seq = self.store.append(kind="operation", source="agent", actor=self.name,
                                payload={"signal": "operator.undo", "decision": "auto", "tier": "A1",
                                         "target_seq": execute_seq, "reverted": n, "note": note,
                                         "summary": f"undo of execute {execute_seq}: reverted {n} step(s) — {note}"},
                                supersedes_id=execute_seq)
        res.applied.append(seq)
        res.notes.append(f"undo of {execute_seq}: reverted {n} step(s) — {note}")
        return res
