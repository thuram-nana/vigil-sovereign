"""DELEGATE (Phase 8, WS-G) — the owner-consented identity/account manager + web actor. Manages the
owner's OWN credentials and, with PER-ACTION owner approval, creates accounts / logs in / fills forms /
submits on the owner's behalf. Ceiling A2, and added to NO_PROMOTION_AGENTS — every account/login/
submit/purchase is A3 (explicit, per-action, owner-signed, no promotion; the WARDEN oracle forces this
from the honest tool name). Fuses the Operator transaction (plan → preview-by-reference →
token-bound-approve → re-derive-at-execute → verify) with the egress per-action token.

Offense-free by construction:
  • NO `as_identity`/impersonate parameter exists — fields resolve ONLY from the owner's OWN vault.
  • a DETECTED block (best-effort: CAPTCHA / 403 / 429) STOPS and is surfaced as a positive control; the
    block-check precedes any action, and there is NO browser-escalation code path in the actor at all
    (HTTP-only), so "use a browser to beat a block" is structurally unreachable.
  • ONE approval authorises exactly ONE action: execute is single-shot per step (a second execute of an
    already-applied step is refused), so an approval can never be replayed into repeated POSTs.
  • per-service creation cap (mass creation is out of doctrine), enforced at preview AND re-checked at
    execute (so a batch previewed before any execute cannot outrun the cap); `ActorScope` origin
    allowlist (deny-all), re-checked at execute.
  • credentials resolve from the keyring ONLY at the last instant of execute, into a local var — never a
    Proposal payload, never logged/journaled. The executable step (incl. any literal values) lives in a
    0700 journal OFF the append-only spine; the spine binds by service + URL + page hash + a field_binding
    of NAMES + vault-references + literal-content-hashes + the vault VERSION (a changed URL OR page OR a
    credential rotation OR a literal edit changes the token → the approval no longer verifies)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from ..config import SIGIL_HOME
from ..reuse import sha256_hex
from .actor_gate import ACTION_SIGNAL, action_approved, action_token
from .actor_scope import ActorScope
from .base import Agent, AgentResult, Proposal, Tier
from .web_engine import HttpEngine, detect_block

_ACTOR_HOME = SIGIL_HOME / "actor"
_JOURNAL = _ACTOR_HOME / "steps"     # executable steps (WITH any literal values) — off the append-only spine

# honest tool names — the WARDEN oracle forces each to A3 (explicit, per-action, no-promotion)
_TOOL = {"navigate": "browser.navigate", "fill": "form.fill", "submit": "submit.form",
         "account.create": "account.create", "login": "login", "purchase": "purchase.item"}

_VAULT_REFS = {"vault:password", "vault:email", "vault:username"}


def _valid_source(src) -> bool:
    """A field value is a known source: an owner-vault reference or a literal. Anything else (unknown
    vault key, `env:`/`file:` scheme, non-string) is REFUSED at preview — so the owner never approves a
    field the actor would silently drop, and no unhandled source can reach execute."""
    return isinstance(src, str) and (src in _VAULT_REFS or src.startswith("literal:"))


def _secure(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass


def _redact_source(src: str) -> str:
    """Spine-safe rendering of a field source: vault references pass through (they are references, not
    values); a literal is reduced to a content hash (the value is journaled 0700, never on the spine)."""
    if src.startswith("literal:"):
        return "literal:" + sha256_hex(src[len("literal:"):].encode("utf-8"))[:16]
    return src


@dataclass(frozen=True)
class WebStep:
    service: str
    kind: str                                    # navigate|fill|submit|account.create|login|purchase
    url: str
    fields: dict = field(default_factory=dict)   # {form_field: "vault:password"|"vault:email"|"vault:username"|"literal:..."}
    # NOTE: there is deliberately NO identity/impersonate field — fields resolve ONLY from the owner's own vault.


class Delegate(Agent):
    name = "DELEGATE"
    mandate = "owner-consented identity/account manager + web actor; per-action approved, offense-free"
    ceiling = Tier.A2

    def __init__(self, store=None, *, scope: ActorScope, vault=None, engine=None,
                 classifier=None, trusted_pubkey=None):
        super().__init__(store)
        self.scope = scope
        self._vault = vault
        self.engine = engine or HttpEngine()
        self._classifier = classifier
        self._trusted = trusted_pubkey

    def _vaultobj(self):
        if self._vault is None:
            from .vault import CredentialVault
            self._vault = CredentialVault()
        return self._vault

    def _cls(self):
        if self._classifier is None:
            from .kernel_classify import KernelClassifier
            self._classifier = KernelClassifier()
        return self._classifier

    def _tp(self):
        if self._trusted is None:
            from ..governor.identity import owner_pubkey
            self._trusted = owner_pubkey()
        return self._trusted

    def _field_binding(self, service: str, fields: dict) -> str:
        """A value-free binding: field NAMES + vault-references + literal-CONTENT-HASHES, prefixed with
        the current vault VERSION when any field references the vault (so a rotation → new token →
        re-approval). Deterministically reproducible at execute from the journaled fields + vault state."""
        parts, uses_vault = [], False
        for k in sorted(fields):
            src = fields[k]
            if src.startswith("vault:"):
                uses_vault = True
            parts.append(f"{k}={_redact_source(src)}")
        binding = ";".join(parts)
        if uses_vault:
            rec = self._vaultobj().get_record(service)
            binding = f"vaultv{rec.version if rec else 0}|{binding}"
        return binding

    # --- preview: dry-run GET, block-detect, journal off-spine, queue a per-action A3 (redacted) ---
    def preview(self, steps: List[WebStep]) -> tuple:
        res = AgentResult(agent=self.name)
        queued: List[int] = []
        for step in steps:
            if not self.scope.origin_allowed(step.url):
                self.store.append(kind="refusal", source="agent", actor=self.name,
                                  payload={"tier": "A0", "decision": "refused", "requested": step.url,
                                           "reason": "target origin is not in the owner's ActorScope"})
                res.notes.append(f"REFUSED {step.url}: out of ActorScope")
                continue
            if step.kind == "account.create" and not self.scope.creation_allowed(self.store, step.service, step.url):
                self.store.append(kind="refusal", source="agent", actor=self.name,
                                  payload={"tier": "A0", "decision": "refused", "service": step.service,
                                           "reason": "creation cap for this service/origin (mass account creation is out of doctrine)"})
                res.notes.append(f"REFUSED account.create {step.service}: creation cap")
                continue
            bad = sorted(k for k, v in step.fields.items() if not _valid_source(v))
            if bad:                                          # fail-closed: no silently-dropped fields
                self.store.append(kind="refusal", source="agent", actor=self.name,
                                  payload={"tier": "A0", "decision": "refused", "requested": step.url,
                                           "reason": f"unknown/invalid field source(s) for: {bad}"})
                res.notes.append(f"REFUSED {step.url}: invalid field source(s) {bad}")
                continue
            pv = self.engine.fetch(step.url)                 # A0 dry-run GET — no mutation
            block = detect_block(pv.status, pv.html)
            if block:                                        # STOP + surface — never defeat a block
                self.store.append(kind="finding", source="agent", actor=self.name,
                                  payload={"signal": "web.actor.blocked", "decision": "surfaced", "url": step.url,
                                           "reason": block, "tier": "A0",
                                           "summary": f"{step.url} is blocked ({block}) — surfaced, NOT defeated"})
                res.notes.append(f"BLOCKED {step.url}: {block} — surfaced, not defeated (doctrine)")
                continue
            if not pv.ok:                                    # a non-2xx / unreachable page has nothing to act on
                self.store.append(kind="refusal", source="agent", actor=self.name,
                                  payload={"tier": "A0", "decision": "refused", "requested": step.url,
                                           "reason": f"page not retrievable (status {pv.status}) — nothing to act on"})
                res.notes.append(f"REFUSED {step.url}: page not retrievable (status {pv.status})")
                continue
            page_hash = sha256_hex(pv.html.encode("utf-8", "ignore"))
            fb = self._field_binding(step.service, step.fields)
            token = action_token(step.service, step.kind, step.url, page_hash, fb)
            _secure(_ACTOR_HOME)
            _secure(_JOURNAL)
            # executable step (WITH any literal values) → 0700 journal, keyed by token; NEVER the spine
            (_JOURNAL / f"{token}.json").write_text(json.dumps(
                {"service": step.service, "kind": step.kind, "url": step.url, "fields": step.fields}),
                encoding="utf-8")
            tier = self._cls().classify(_TOOL.get(step.kind, "unknown.op"))   # → A3 for the mutating kinds
            r = self._dispatch([Proposal("event", {
                "signal": ACTION_SIGNAL, "service": step.service, "step_kind": step.kind, "url": step.url,
                "page_sha256": page_hash, "field_binding": fb, "action_token": token,
                "journal": str(_JOURNAL / f"{token}.json"),
                "fields_redacted": [{"name": k, "source": _redact_source(step.fields[k])}
                                    for k in sorted(step.fields)],   # NAMES + refs/hashes only — NO values
                "subject": f"{step.kind} on {step.service} (awaiting owner approval)"}, tier)])
            seq = r.queued[0]["seq"] if r.queued else (r.applied[0] if r.applied else None)
            if seq is not None:
                queued.append(seq)
        return queued, res

    # --- execute: verified approval → re-fetch → block-before-act → re-derive token → last-instant act
    def execute(self, step_seq: int) -> AgentResult:
        res = AgentResult(agent=self.name)
        rec = self.store.get(step_seq)
        if rec is None or rec.payload.get("signal") != ACTION_SIGNAL:
            res.notes.append(f"seq {step_seq} is not a web-actor step")
            return res
        token = rec.payload["action_token"]
        if not action_approved(self.store, step_seq, token, self._tp()):
            res.notes.append(f"step {step_seq} has no verified owner approval — NO request made")
            return res
        # SINGLE-SHOT: one approval authorises exactly ONE action. A step that already produced an applied
        # record is refused (the append-only approval never expires, so without this guard one signature
        # would authorise unbounded repeats). Mirrors the Operator's single-shot undo (BLOCK-6).
        for r in self.store.iter_records(since_seq=step_seq):
            if (r.payload.get("signal") == ACTION_SIGNAL and r.payload.get("status") == "applied"
                    and r.payload.get("target_seq") == step_seq):
                res.notes.append(f"step {step_seq} was already executed (seq {r.seq}) — refusing a replay (per-action)")
                return res
        try:                                                 # executable step lives OFF the spine (0700)
            j = json.loads(Path(rec.payload["journal"]).read_text(encoding="utf-8"))
            service, kind, url, fields = j["service"], j["kind"], j["url"], j["fields"]
        except (OSError, ValueError, KeyError, TypeError):
            res.notes.append("step journal missing/unreadable — cannot execute")
            return res
        if not self.scope.origin_allowed(url):               # re-check scope at execute (belt-and-suspenders)
            self.store.append(kind="refusal", source="agent", actor=self.name,
                              payload={"tier": "A0", "decision": "refused", "target_seq": step_seq, "requested": url,
                                       "reason": "the step URL is not in the owner's ActorScope at execute — aborted"})
            res.notes.append(f"ABORTED: {url} left the ActorScope — no action")
            return res
        pv = self.engine.fetch(url)                          # re-fetch (anti-TOCTOU + block-before-act)
        block = detect_block(pv.status, pv.html)
        if block:
            self.store.append(kind="finding", source="agent", actor=self.name,
                              payload={"signal": "web.actor.blocked", "decision": "surfaced", "url": url,
                                       "reason": block, "tier": "A0",
                                       "summary": f"{url} blocked at execute ({block}) — surfaced, no action"})
            res.notes.append(f"BLOCKED at execute {url}: {block} — surfaced, no action")
            return res
        if not pv.ok:                                        # unreachable/non-2xx at execute → never POST to a dead page
            self.store.append(kind="refusal", source="agent", actor=self.name,
                              payload={"tier": "A0", "decision": "refused", "target_seq": step_seq, "requested": url,
                                       "reason": f"page not retrievable at execute (status {pv.status}) — aborted"})
            res.notes.append(f"ABORTED: {url} not retrievable at execute (status {pv.status}) — no action")
            return res
        # RE-DERIVE the token from the CURRENT url + page hash + vault version + journaled fields; a changed
        # URL OR page OR a credential rotation OR a journal edit → mismatch → abort (never trust a field).
        fresh = action_token(service, kind, url, sha256_hex(pv.html.encode("utf-8", "ignore")),
                             self._field_binding(service, fields))
        if fresh != token:
            self.store.append(kind="refusal", source="agent", actor=self.name,
                              payload={"tier": "A0", "decision": "refused", "target_seq": step_seq,
                                       "reason": "url/page/credential/step changed since approval (token mismatch) — aborted"})
            res.notes.append("ABORTED: the world changed since approval (token mismatch) — no action")
            return res
        # RE-CHECK the creation cap at execute (against committed applied records) so a batch previewed
        # before any execute cannot outrun cap=1 — the preview check alone counts zero applied.
        if kind == "account.create" and not self.scope.creation_allowed(self.store, service, url):
            self.store.append(kind="refusal", source="agent", actor=self.name,
                              payload={"tier": "A0", "decision": "refused", "target_seq": step_seq, "service": service,
                                       "reason": "per-service creation cap reached at execute (mass creation out of doctrine)"})
            res.notes.append(f"REFUSED account.create {service} at execute: creation cap")
            return res
        resolved = self._resolve(service, fields)            # credentials → locals ONLY (never the spine)
        out = self.engine.act({"url": url, "kind": kind}, resolved,
                              pinned_ip=getattr(pv, "resolved_ip", "") or None)   # bind the POST to the vetted IP
        seq = self.store.append(kind="event", source="agent", actor=self.name,
                                payload={"signal": ACTION_SIGNAL, "status": "applied", "target_seq": step_seq,
                                         "service": service, "step_kind": kind, "url": url, "action_token": token,
                                         "result_ok": bool(out.get("ok")), "tier": "A1", "decision": "auto",
                                         "summary": f"{kind} on {service} executed (ok={out.get('ok')})"})
        res.applied.append(seq)
        res.notes.append(f"executed {kind} on {service} (ok={out.get('ok')})")
        return res

    def _resolve(self, service: str, fields: dict) -> dict:
        """Resolve field references to VALUES at the last instant — into a local dict, never the spine."""
        out: dict = {}
        rec = self._vaultobj().get_record(service)
        for name, src in fields.items():
            if src == "vault:password":
                out[name] = self._vaultobj().resolve_password(service) or ""
            elif src == "vault:email":
                out[name] = rec.email if rec else ""
            elif src == "vault:username":
                out[name] = rec.username if rec else ""
            elif src.startswith("literal:"):
                out[name] = src[len("literal:"):]
        return out
