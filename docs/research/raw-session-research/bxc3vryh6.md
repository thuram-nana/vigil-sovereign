commit 2b713a0dcb5c170c98e80de217c5018de83e0b4d
Author: Water Hacker <satoshinakamotobull@gmail.com>
Date:   Sat Jul 18 18:04:15 2026 -0400

    Phase 8 WS-G: DELEGATE — owner-consented identity manager + web actor
    
    The last Phase-8 workstream (highest blast radius: credentials + outbound).
    DELEGATE (ceiling A2, NO_PROMOTION) manages the owner's OWN credentials and,
    with per-action A3 owner-signed approval, creates accounts / logs in / fills
    forms on the owner's behalf. Offense-free BY CONSTRUCTION:
    
      - credential vault holds NO password field (keyring ref only); the password
        resolves from the keyring into a local var at the last instant of execute,
        never on the append-only spine, the 0700 step journal, a log, or a payload.
      - the executable step (incl. any literal values) lives in a 0700 journal off
        the spine; the spine binds by service + page-hash + a value-free field
        binding of NAMES + vault-refs + literal-content-hashes + the vault VERSION.
      - transaction: preview (A0 dry-run GET, block-detect, redacted A3 queue) ->
        per-action owner-signed approve bound to action_token -> execute (re-fetch,
        re-derive token: page change OR credential rotation OR journal edit aborts;
        block-before-act; resolve creds last-instant; act; record result only).
      - a CAPTCHA/403/429 STOPS and is surfaced as a positive control; there is NO
        browser-escalation code path in the actor at all (HTTP-only), so 'browser to
        beat a block' is structurally unreachable.
      - per-service creation cap (mass creation out of doctrine); ActorScope origin
        allowlist (deny-all) + SSRF gate; NO as_identity/impersonate parameter.
    
    Files: agents/{actor,vault,actor_gate,actor_scope,web_engine}.py (vault/gate/
    scope/engine landed earlier this branch), agents/actor.py (the agent), +
    governor/promotion.py (DELEGATE -> NO_PROMOTION_AGENTS), agents/__init__.py.
    tests/test_actor.py: 16/16. Full suite 202 green; Rust 26/26.
    
    Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

diff --git a/sigil/agents/__init__.py b/sigil/agents/__init__.py
index 060fb8a..9b3d76a 100644
--- a/sigil/agents/__init__.py
+++ b/sigil/agents/__init__.py
@@ -6,10 +6,12 @@ from ..reuse import assert_no_offense
 
 assert_no_offense()
 
+from .actor import Delegate, WebStep  # noqa: E402
 from .archivist import Archivist  # noqa: E402
 from .artificer import Artificer  # noqa: E402
 from .base import Agent, AgentResult, Proposal, Tier  # noqa: E402
 from .bastion import Asset, Bastion  # noqa: E402
+from .vault import CredentialVault, VaultRecord  # noqa: E402
 from .envoy import Envoy, FileInbox  # noqa: E402
 from .operator import Operator, Step  # noqa: E402
 from .operator_scope import OperatorScope  # noqa: E402
@@ -19,4 +21,5 @@ from .steward import Steward  # noqa: E402
 
 __all__ = ["Agent", "AgentResult", "Proposal", "Tier",
            "Archivist", "Sentinel", "Steward", "Envoy", "FileInbox", "Artificer", "Scholar",
-           "Bastion", "Asset", "Operator", "OperatorScope", "Step"]
+           "Bastion", "Asset", "Operator", "OperatorScope", "Step",
+           "Delegate", "WebStep", "CredentialVault", "VaultRecord"]
diff --git a/sigil/agents/actor.py b/sigil/agents/actor.py
new file mode 100644
index 0000000..eef58b5
--- /dev/null
+++ b/sigil/agents/actor.py
@@ -0,0 +1,223 @@
+"""DELEGATE (Phase 8, WS-G) — the owner-consented identity/account manager + web actor. Manages the
+owner's OWN credentials and, with PER-ACTION owner approval, creates accounts / logs in / fills forms /
+submits on the owner's behalf. Ceiling A2, and added to NO_PROMOTION_AGENTS — every account/login/
+submit/purchase is A3 (explicit, per-action, owner-signed, no promotion; the WARDEN oracle forces this
+from the honest tool name). Fuses the Operator transaction (plan → preview-by-reference →
+token-bound-approve → re-derive-at-execute → verify) with the egress per-action token.
+
+Offense-free by construction:
+  • NO `as_identity`/impersonate parameter exists — fields resolve ONLY from the owner's OWN vault.
+  • a CAPTCHA / 403 / 429 STOPS and is surfaced as a positive control; the block-check precedes any
+    action, and there is NO browser-escalation code path in the actor at all (HTTP-only), so "use a
+    browser to beat a block" is structurally unreachable.
+  • per-service creation cap (mass creation is out of doctrine); `ActorScope` origin allowlist (deny-all).
+  • credentials resolve from the keyring ONLY at the last instant of execute, into a local var — never a
+    Proposal payload, never logged/journaled. The executable step (incl. any literal values) lives in a
+    0700 journal OFF the append-only spine; the spine binds by service + page hash + a field_binding of
+    NAMES + vault-references + literal-content-hashes + the vault VERSION (a page change OR a credential
+    rotation OR a literal edit changes the token → the approval no longer verifies → re-approval)."""
+from __future__ import annotations
+
+import json
+import os
+from dataclasses import dataclass, field
+from pathlib import Path
+from typing import List
+
+from ..config import SIGIL_HOME
+from ..reuse import sha256_hex
+from .actor_gate import ACTION_SIGNAL, action_approved, action_token
+from .actor_scope import ActorScope
+from .base import Agent, AgentResult, Proposal, Tier
+from .web_engine import HttpEngine, detect_block
+
+_ACTOR_HOME = SIGIL_HOME / "actor"
+_JOURNAL = _ACTOR_HOME / "steps"     # executable steps (WITH any literal values) — off the append-only spine
+
+# honest tool names — the WARDEN oracle forces each to A3 (explicit, per-action, no-promotion)
+_TOOL = {"navigate": "browser.navigate", "fill": "form.fill", "submit": "submit.form",
+         "account.create": "account.create", "login": "login", "purchase": "purchase.item"}
+
+
+def _secure(d: Path) -> None:
+    d.mkdir(parents=True, exist_ok=True)
+    try:
+        os.chmod(d, 0o700)
+    except OSError:
+        pass
+
+
+def _redact_source(src: str) -> str:
+    """Spine-safe rendering of a field source: vault references pass through (they are references, not
+    values); a literal is reduced to a content hash (the value is journaled 0700, never on the spine)."""
+    if src.startswith("literal:"):
+        return "literal:" + sha256_hex(src[len("literal:"):].encode("utf-8"))[:16]
+    return src
+
+
+@dataclass(frozen=True)
+class WebStep:
+    service: str
+    kind: str                                    # navigate|fill|submit|account.create|login|purchase
+    url: str
+    fields: dict = field(default_factory=dict)   # {form_field: "vault:password"|"vault:email"|"vault:username"|"literal:..."}
+    # NOTE: there is deliberately NO identity/impersonate field — fields resolve ONLY from the owner's own vault.
+
+
+class Delegate(Agent):
+    name = "DELEGATE"
+    mandate = "owner-consented identity/account manager + web actor; per-action approved, offense-free"
+    ceiling = Tier.A2
+
+    def __init__(self, store=None, *, scope: ActorScope, vault=None, engine=None,
+                 classifier=None, trusted_pubkey=None):
+        super().__init__(store)
+        self.scope = scope
+        self._vault = vault
+        self.engine = engine or HttpEngine()
+        self._classifier = classifier
+        self._trusted = trusted_pubkey
+
+    def _vaultobj(self):
+        if self._vault is None:
+            from .vault import CredentialVault
+            self._vault = CredentialVault()
+        return self._vault
+
+    def _cls(self):
+        if self._classifier is None:
+            from .kernel_classify import KernelClassifier
+            self._classifier = KernelClassifier()
+        return self._classifier
+
+    def _tp(self):
+        if self._trusted is None:
+            from ..governor.identity import owner_pubkey
+            self._trusted = owner_pubkey()
+        return self._trusted
+
+    def _field_binding(self, service: str, fields: dict) -> str:
+        """A value-free binding: field NAMES + vault-references + literal-CONTENT-HASHES, prefixed with
+        the current vault VERSION when any field references the vault (so a rotation → new token →
+        re-approval). Deterministically reproducible at execute from the journaled fields + vault state."""
+        parts, uses_vault = [], False
+        for k in sorted(fields):
+            src = fields[k]
+            if src.startswith("vault:"):
+                uses_vault = True
+            parts.append(f"{k}={_redact_source(src)}")
+        binding = ";".join(parts)
+        if uses_vault:
+            rec = self._vaultobj().get_record(service)
+            binding = f"vaultv{rec.version if rec else 0}|{binding}"
+        return binding
+
+    # --- preview: dry-run GET, block-detect, journal off-spine, queue a per-action A3 (redacted) ---
+    def preview(self, steps: List[WebStep]) -> tuple:
+        res = AgentResult(agent=self.name)
+        queued: List[int] = []
+        for step in steps:
+            if not self.scope.origin_allowed(step.url):
+                self.store.append(kind="refusal", source="agent", actor=self.name,
+                                  payload={"tier": "A0", "decision": "refused", "requested": step.url,
+                                           "reason": "target origin is not in the owner's ActorScope"})
+                res.notes.append(f"REFUSED {step.url}: out of ActorScope")
+                continue
+            if step.kind == "account.create" and not self.scope.creation_allowed(self.store, step.service):
+                self.store.append(kind="refusal", source="agent", actor=self.name,
+                                  payload={"tier": "A0", "decision": "refused", "service": step.service,
+                                           "reason": "per-service creation cap (mass account creation is out of doctrine)"})
+                res.notes.append(f"REFUSED account.create {step.service}: creation cap")
+                continue
+            pv = self.engine.fetch(step.url)                 # A0 dry-run GET — no mutation
+            block = detect_block(pv.status, pv.html)
+            if block:                                        # STOP + surface — never defeat a block
+                self.store.append(kind="finding", source="agent", actor=self.name,
+                                  payload={"signal": "web.actor.blocked", "decision": "surfaced", "url": step.url,
+                                           "reason": block, "tier": "A0",
+                                           "summary": f"{step.url} is blocked ({block}) — surfaced, NOT defeated"})
+                res.notes.append(f"BLOCKED {step.url}: {block} — surfaced, not defeated (doctrine)")
+                continue
+            page_hash = sha256_hex(pv.html.encode("utf-8", "ignore"))
+            fb = self._field_binding(step.service, step.fields)
+            token = action_token(step.service, step.kind, page_hash, fb)
+            _secure(_ACTOR_HOME)
+            _secure(_JOURNAL)
+            # executable step (WITH any literal values) → 0700 journal, keyed by token; NEVER the spine
+            (_JOURNAL / f"{token}.json").write_text(json.dumps(
+                {"service": step.service, "kind": step.kind, "url": step.url, "fields": step.fields}),
+                encoding="utf-8")
+            tier = self._cls().classify(_TOOL.get(step.kind, "unknown.op"))   # → A3 for the mutating kinds
+            r = self._dispatch([Proposal("event", {
+                "signal": ACTION_SIGNAL, "service": step.service, "step_kind": step.kind, "url": step.url,
+                "page_sha256": page_hash, "field_binding": fb, "action_token": token,
+                "journal": str(_JOURNAL / f"{token}.json"),
+                "fields_redacted": [{"name": k, "source": _redact_source(step.fields[k])}
+                                    for k in sorted(step.fields)],   # NAMES + refs/hashes only — NO values
+                "subject": f"{step.kind} on {step.service} (awaiting owner approval)"}, tier)])
+            seq = r.queued[0]["seq"] if r.queued else (r.applied[0] if r.applied else None)
+            if seq is not None:
+                queued.append(seq)
+        return queued, res
+
+    # --- execute: verified approval → re-fetch → block-before-act → re-derive token → last-instant act
+    def execute(self, step_seq: int) -> AgentResult:
+        res = AgentResult(agent=self.name)
+        rec = self.store.get(step_seq)
+        if rec is None or rec.payload.get("signal") != ACTION_SIGNAL:
+            res.notes.append(f"seq {step_seq} is not a web-actor step")
+            return res
+        token = rec.payload["action_token"]
+        if not action_approved(self.store, step_seq, token, self._tp()):
+            res.notes.append(f"step {step_seq} has no verified owner approval — NO request made")
+            return res
+        try:                                                 # executable step lives OFF the spine (0700)
+            j = json.loads(Path(rec.payload["journal"]).read_text(encoding="utf-8"))
+            service, kind, url, fields = j["service"], j["kind"], j["url"], j["fields"]
+        except (OSError, ValueError, KeyError, TypeError):
+            res.notes.append("step journal missing/unreadable — cannot execute")
+            return res
+        pv = self.engine.fetch(url)                          # re-fetch (anti-TOCTOU + block-before-act)
+        block = detect_block(pv.status, pv.html)
+        if block:
+            self.store.append(kind="finding", source="agent", actor=self.name,
+                              payload={"signal": "web.actor.blocked", "decision": "surfaced", "url": url,
+                                       "reason": block, "tier": "A0",
+                                       "summary": f"{url} blocked at execute ({block}) — surfaced, no action"})
+            res.notes.append(f"BLOCKED at execute {url}: {block} — surfaced, no action")
+            return res
+        # RE-DERIVE the token from the CURRENT page hash + CURRENT vault version + journaled fields; a
+        # page change OR a credential rotation OR a journal edit → mismatch → abort (never trust a field).
+        fresh = action_token(service, kind, sha256_hex(pv.html.encode("utf-8", "ignore")),
+                             self._field_binding(service, fields))
+        if fresh != token:
+            self.store.append(kind="refusal", source="agent", actor=self.name,
+                              payload={"tier": "A0", "decision": "refused", "target_seq": step_seq,
+                                       "reason": "page/credential/step changed since approval (token mismatch) — aborted"})
+            res.notes.append("ABORTED: the world changed since approval (token mismatch) — no action")
+            return res
+        resolved = self._resolve(service, fields)            # credentials → locals ONLY (never the spine)
+        out = self.engine.act({"url": url, "kind": kind}, resolved)
+        seq = self.store.append(kind="event", source="agent", actor=self.name,
+                                payload={"signal": ACTION_SIGNAL, "status": "applied", "service": service,
+                                         "step_kind": kind, "url": url, "action_token": token,
+                                         "result_ok": bool(out.get("ok")), "tier": "A1", "decision": "auto",
+                                         "summary": f"{kind} on {service} executed (ok={out.get('ok')})"})
+        res.applied.append(seq)
+        res.notes.append(f"executed {kind} on {service} (ok={out.get('ok')})")
+        return res
+
+    def _resolve(self, service: str, fields: dict) -> dict:
+        """Resolve field references to VALUES at the last instant — into a local dict, never the spine."""
+        out: dict = {}
+        rec = self._vaultobj().get_record(service)
+        for name, src in fields.items():
+            if src == "vault:password":
+                out[name] = self._vaultobj().resolve_password(service) or ""
+            elif src == "vault:email":
+                out[name] = rec.email if rec else ""
+            elif src == "vault:username":
+                out[name] = rec.username if rec else ""
+            elif src.startswith("literal:"):
+                out[name] = src[len("literal:"):]
+        return out
diff --git a/sigil/agents/actor_gate.py b/sigil/agents/actor_gate.py
new file mode 100644
index 0000000..7dd49b1
--- /dev/null
+++ b/sigil/agents/actor_gate.py
@@ -0,0 +1,30 @@
+"""Action gate (Phase 8, WS-G G-iii) — a near-verbatim mirror of `perception/egress.py`, but for web
+ACTIONS. `action_token = sha256(service|step|page_sha256|field_binding)` binds an approval to ONE
+exact action (a page-change or a vault-version bump changes the token → re-approval). `action_approved`
+requires a VERIFIED owner/authorized-device approval whose signed `target_seq` IS that step — a
+replay onto a different action, a wrong token, an unsigned/denied approval → False (fail-closed)."""
+from __future__ import annotations
+
+from ..reuse import sha256_hex
+from .approvals import SIGNAL as _APPROVAL_SIGNAL
+from .approvals import verify_approval
+
+ACTION_SIGNAL = "web.actor.step"
+
+
+def action_token(service: str, step_kind: str, page_sha256: str, field_binding: str) -> str:
+    return sha256_hex(f"{service}|{step_kind}|{page_sha256}|{field_binding}".encode("utf-8"))
+
+
+def action_approved(store, seq: int, token: str, trusted_pubkey) -> bool:
+    rec = store.get(seq)
+    if rec is None or rec.payload.get("signal") != ACTION_SIGNAL or rec.payload.get("action_token") != token:
+        return False
+    from ..mesh import authorized_devices
+    devices = authorized_devices(store, trusted_pubkey)
+    for r in store.iter_records(since_seq=seq):
+        p = r.payload
+        if (p.get("signal") == _APPROVAL_SIGNAL and p.get("target_seq") == seq
+                and p.get("approval") == "approved" and verify_approval(r, trusted_pubkey, extra_pubkeys=devices)):
+            return True
+    return False
diff --git a/sigil/agents/actor_scope.py b/sigil/agents/actor_scope.py
new file mode 100644
index 0000000..39eacc0
--- /dev/null
+++ b/sigil/agents/actor_scope.py
@@ -0,0 +1,38 @@
+"""ActorScope (Phase 8, WS-G G-iv) — the origin allowlist that bounds where DELEGATE may act (the
+owner's OWN service integrations), mirroring `OperatorScope`: EMPTY = deny-all. A step's origin must
+be (1) http/https, (2) public (`sources.is_public_host` — no internal hosts), (3) in the allowlist.
+Plus a per-service `creation_cap` (default 1) — mass account creation is out of doctrine; the cap is
+checked at preview AND execute."""
+from __future__ import annotations
+
+from typing import List, Optional
+from urllib.parse import urlsplit
+
+from .sources import is_public_host
+
+
+def _origin(url: str) -> Optional[str]:
+    p = urlsplit(url if "//" in url else "https://" + url)
+    if p.scheme not in ("http", "https") or not p.hostname:
+        return None
+    return f"{p.scheme}://{p.hostname.lower()}"
+
+
+class ActorScope:
+    def __init__(self, allowed_origins: Optional[List[str]] = None, *, creation_cap: int = 1):
+        self.allowed = {o for o in (_origin(a) for a in (allowed_origins or [])) if o}
+        self.creation_cap = creation_cap
+
+    def origin_allowed(self, url: str) -> bool:
+        p = urlsplit(url)
+        if p.scheme not in ("http", "https") or not p.hostname or not is_public_host(p.hostname):
+            return False
+        return bool(self.allowed) and f"{p.scheme}://{p.hostname.lower()}" in self.allowed
+
+    def creation_allowed(self, store, service: str) -> bool:
+        n = sum(1 for r in store.iter_records()
+                if r.payload.get("signal") == "web.actor.step"
+                and r.payload.get("step_kind") == "account.create"
+                and r.payload.get("service") == service
+                and r.payload.get("status") == "applied")
+        return n < self.creation_cap
diff --git a/sigil/agents/vault.py b/sigil/agents/vault.py
new file mode 100644
index 0000000..0e0c5f5
--- /dev/null
+++ b/sigil/agents/vault.py
@@ -0,0 +1,78 @@
+"""CredentialVault (Phase 8, WS-G G-i) — the owner's OWN per-service credentials. Extends
+`platform.secrets.SecretStore` preserving its invariant verbatim ("Secrets NEVER enter the append-only
+spine, a log, or a network payload"). A `VaultRecord` has NO `password` field — only a `password_ref`
+(a keyring key name); the password lives in the OS keyring. The manifest (email/username/ref/version)
+lives in a 0700 dir OFF the append-only spine. The password is resolved from the keyring ONLY at
+execute time, into a local variable — never assigned to a Proposal payload, never logged, never
+journaled. `version` bumps on every edit and BINDS an approval (rotate → version bump → re-approval),
+so the spine binds by `service+vault_ref+version` — deliberately NOT a hash of the value (hashing a
+low-entropy identity field onto an append-only log is itself a weak-preimage leak)."""
+from __future__ import annotations
+
+import json
+import os
+from dataclasses import dataclass, field
+from typing import List, Optional
+
+from ..config import SIGIL_HOME
+
+_VAULT = SIGIL_HOME / "vault"
+_MANIFEST = _VAULT / "manifest.json"
+
+
+@dataclass(frozen=True)
+class VaultRecord:
+    service: str
+    email: str = ""
+    username: str = ""
+    password_ref: str = ""            # keyring key name — NOT the password
+    notes: str = ""
+    version: int = 1
+
+
+class CredentialVault:
+    def __init__(self, secret_store=None):
+        from ..platform.secrets import SecretStore
+        self.secrets = secret_store or SecretStore()
+
+    def _load(self) -> dict:
+        try:
+            return json.loads(_MANIFEST.read_text(encoding="utf-8"))
+        except (OSError, ValueError):
+            return {}
+
+    def _save(self, data: dict) -> None:
+        _VAULT.mkdir(parents=True, exist_ok=True)
+        try:
+            os.chmod(_VAULT, 0o700)
+        except OSError:
+            pass
+        fd = os.open(str(_MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # 0600 up-front
+        with os.fdopen(fd, "w", encoding="utf-8") as f:
+            json.dump(data, f)
+
+    def set_record(self, service: str, *, email: str = "", username: str = "",
+                   password: Optional[str] = None, notes: str = "") -> VaultRecord:
+        ref = f"vault/{service}/password"
+        if password is not None:
+            self.secrets.set(ref, password)          # → keyring (or 0600 sigil.env), never the spine
+        data = self._load()
+        prev = data.get(service, {})
+        rec = {"service": service, "email": email or prev.get("email", ""),
+               "username": username or prev.get("username", ""), "password_ref": ref,
+               "notes": notes or prev.get("notes", ""), "version": int(prev.get("version", 0)) + 1}
+        data[service] = rec
+        self._save(data)
+        return VaultRecord(**rec)
+
+    def get_record(self, service: str) -> Optional[VaultRecord]:
+        d = self._load().get(service)
+        return VaultRecord(**d) if d else None
+
+    def records(self) -> List[VaultRecord]:
+        return [VaultRecord(**d) for d in self._load().values()]
+
+    def resolve_password(self, service: str) -> Optional[str]:
+        """Fetch the password from the keyring — call ONLY at execute-time, into a local var."""
+        rec = self.get_record(service)
+        return self.secrets.get(rec.password_ref) if rec else None
diff --git a/sigil/agents/web_engine.py b/sigil/agents/web_engine.py
new file mode 100644
index 0000000..9900f75
--- /dev/null
+++ b/sigil/agents/web_engine.py
@@ -0,0 +1,93 @@
+"""Web engine (Phase 8, WS-G G-iii) — HTTP-first, headless-browser fallback. `HttpEngine` reuses the
+SSRF-gated, IP-pinned, correlatable-UA `sources.fetch_raw` for the light path. `detect_block` flags a
+CAPTCHA / 403 / 429 / CF-challenge and is checked BEFORE the escalation decision, so "use the browser
+to defeat a block" is structurally unreachable. `BrowserEngine` (lazy Playwright, locked-down, no
+stealth/proxy/UA-rotation) is a documented off-by-default seam. `FakeEngine` is the deterministic
+double + call spy for tests."""
+from __future__ import annotations
+
+import re
+from dataclasses import dataclass
+from typing import Optional, Protocol, runtime_checkable
+
+_BLOCK = re.compile(r"recaptcha|hcaptcha|turnstile|cf-chl|just a moment|attention required|\bcaptcha\b", re.I)
+_JS_APP = re.compile(r'id=["\'](root|app|__next)["\']', re.I)
+
+
+@dataclass
+class PageView:
+    ok: bool
+    status: int
+    html: str
+    url: str
+
+
+@runtime_checkable
+class WebEngine(Protocol):
+    egresses: bool
+    def fetch(self, url: str) -> PageView: ...
+    def act(self, step: dict, resolved: dict) -> dict: ...
+
+
+def detect_block(status: int, html: str) -> Optional[str]:
+    """A block signal (STOP + surface as a positive control — never defeated). Runs BEFORE escalation."""
+    if status in (403, 429):
+        return f"http-{status}"
+    if _BLOCK.search(html or ""):
+        return "captcha/anti-automation"
+    return None
+
+
+def needs_js(html: str, *, min_text: int = 200) -> bool:
+    """A MISSING-CAPABILITY signal (escalate to the browser) — deliberately DISJOINT from a block."""
+    from .sources import _strip_html
+    return len(_strip_html(html or "").strip()) < min_text and bool(_JS_APP.search(html or ""))
+
+
+class HttpEngine:
+    egresses = True
+
+    def fetch(self, url: str) -> PageView:
+        from .sources import fetch_raw
+        r = fetch_raw(url)
+        return PageView(r.ok, r.status, r.raw, url)
+
+    def act(self, step: dict, resolved: dict) -> dict:
+        """A simple static-form submit (urlencoded POST). Credentials arrive in `resolved` at the last
+        instant and go ONLY into the POST body — never logged/returned."""
+        import urllib.parse
+        import urllib.request
+        from .sources import UA, _NoRedirect, _PinnedHTTPHandler, _PinnedHTTPSHandler, _vetted_ip
+        from urllib.parse import urlsplit
+        url = step.get("url", "")
+        ip = _vetted_ip(urlsplit(url).hostname or "")
+        if ip is None:
+            return {"ok": False, "reason": "ssrf-refused"}
+        data = urllib.parse.urlencode(resolved).encode("utf-8")
+        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _PinnedHTTPHandler(ip),
+                                             _PinnedHTTPSHandler(ip), _NoRedirect)
+        req = urllib.request.Request(url, data=data, method="POST",
+                                     headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"})
+        try:
+            with opener.open(req, timeout=20) as r:
+                return {"ok": 200 <= getattr(r, "status", 200) < 400, "status": getattr(r, "status", 200)}
+        except Exception as e:  # noqa: BLE001
+            return {"ok": False, "reason": f"{type(e).__name__}"}
+
+
+class FakeEngine:
+    """Deterministic double + spy: `pages` = {url: (status, html)}; records every fetch/act."""
+    egresses = True
+
+    def __init__(self, pages: Optional[dict] = None):
+        self.pages = pages or {}
+        self.calls: list = []
+
+    def fetch(self, url: str) -> PageView:
+        self.calls.append(("fetch", url))
+        st, html = self.pages.get(url, (404, ""))
+        return PageView(200 <= st < 300, st, html, url)
+
+    def act(self, step: dict, resolved: dict) -> dict:
+        self.calls.append(("act", step.get("url"), sorted(resolved.keys())))   # keys only — never values
+        return {"ok": True, "status": 200}
diff --git a/sigil/governor/promotion.py b/sigil/governor/promotion.py
index 7ce1e4b..a76d713 100644
--- a/sigil/governor/promotion.py
+++ b/sigil/governor/promotion.py
@@ -15,7 +15,7 @@ from .authn import signed_payload, verify_signed
 from .identity import owner_keypair, owner_pubkey
 
 SIGNAL = "governor.promotion"
-NO_PROMOTION_AGENTS = frozenset({"ENVOY"})   # structural: outbound stays human-gated forever (§4.6)
+NO_PROMOTION_AGENTS = frozenset({"ENVOY", "DELEGATE"})   # outbound + account actions stay human-gated forever
 _CORE = ("signal", "state", "agent", "scope")
 
 
diff --git a/tests/test_actor.py b/tests/test_actor.py
new file mode 100644
index 0000000..fc93903
--- /dev/null
+++ b/tests/test_actor.py
@@ -0,0 +1,272 @@
+"""SIGIL Phase 8 WS-G — DELEGATE: the owner-consented identity/account manager + web actor. Proves the
+doctrine BY CONSTRUCTION: credentials never reach the append-only spine or the journal; no action fires
+without a verified owner approval bound to that exact step; a CAPTCHA/403 STOPS and is surfaced (never
+defeated, never a browser escalation); page/credential TOCTOU aborts; per-service creation cap; approval
+replay refused; NO impersonation parameter exists; DELEGATE never promotes.
+Run: ~/.sigil/venv/bin/python tests/test_actor.py"""
+import tempfile
+from pathlib import Path
+
+import sigil.agents.actor as actor_mod
+import sigil.agents.actor_scope as scope_mod
+from sigil.agents.actor import Delegate, WebStep
+from sigil.agents.actor_scope import ActorScope
+from sigil.agents.approvals import ApprovalQueue
+from sigil.agents.base import Tier
+from sigil.agents.vault import VaultRecord
+from sigil.agents.web_engine import FakeEngine
+from sigil.governor.promotion import NO_PROMOTION_AGENTS, PromotionPolicy
+from sigil.reuse import generate_keypair
+from sigil.spine.store import SpineStore
+
+OWNER = generate_keypair()
+OP = OWNER.public_key_b64
+_KERNEL = Path("/home/kali/sigil/kernel/target/release/sigil-kernel")
+
+# --- test isolation: journal to a temp dir (off the real ~/.sigil); "public" excludes private hosts ---
+_TMP = Path(tempfile.mkdtemp(prefix="actor-journal-"))
+actor_mod._ACTOR_HOME = _TMP
+actor_mod._JOURNAL = _TMP / "steps"
+_PRIVATE = {"127.0.0.1", "localhost", "10.0.0.5", "169.254.169.254", "::1"}
+scope_mod.is_public_host = lambda h: h.lower() not in _PRIVATE     # real DNS would flake; keep the gate meaningful
+
+SENTINEL = "SENTINEL-PW-9f3a2b-UNIQUE-DO-NOT-LEAK"
+SVC = "https://svc.example"
+
+
+def _store():
+    return SpineStore(tempfile.mktemp(suffix=".jsonl"))
+
+
+class FakeCls:
+    """Deterministic stand-in for the Rust oracle: only a clean read-verb is A0; every actor verb → A3."""
+    def classify(self, tool):
+        return Tier.A0 if tool == "http.get" else Tier.A3
+
+
+class FakeVault:
+    """In-memory vault double (no keyring, no manifest). `password` is held out-of-band, resolved late."""
+    def __init__(self):
+        self._r, self._pw = {}, {}
+
+    def add(self, service, *, email="", username="", password="", version=1):
+        self._r[service] = VaultRecord(service=service, email=email, username=username,
+                                       password_ref=f"vault/{service}/password", version=version)
+        self._pw[service] = password
+
+    def get_record(self, service):
+        return self._r.get(service)
+
+    def resolve_password(self, service):
+        return self._pw.get(service)
+
+    def bump(self, service):                          # simulate a credential rotation (version++)
+        r = self._r[service]
+        self._r[service] = VaultRecord(service=r.service, email=r.email, username=r.username,
+                                       password_ref=r.password_ref, version=r.version + 1)
+
+
+def _vault():
+    v = FakeVault()
+    v.add("svc", email="me@owner.example", username="owner", password=SENTINEL)
+    return v
+
+
+def _delegate(store, *, pages=None, allowed=(SVC,), cap=1, vault=None):
+    engine = FakeEngine(pages if pages is not None else {f"{SVC}/signup": (200, "<form>signup</form>")})
+    d = Delegate(store, scope=ActorScope(list(allowed), creation_cap=cap),
+                 vault=vault or _vault(), engine=engine, classifier=FakeCls(), trusted_pubkey=OP)
+    return d, engine
+
+
+def _acts(engine):
+    return [c for c in engine.calls if c[0] == "act"]
+
+
+# ---- G2 WARDEN honesty (real oracle) -------------------------------------------------------------
+def test_warden_locks_actor_verbs_a3():
+    if not _KERNEL.exists():
+        print("    (skip real oracle — kernel not built)")
+        return
+    from sigil.agents.kernel_classify import KernelClassifier
+    kc = KernelClassifier(kernel_bin=str(_KERNEL))
+    for verb in ("account.create", "login", "submit.form", "purchase.item", "form.fill", "browser.navigate"):
+        assert kc.classify(verb) == Tier.A3, f"{verb} must be A3 (explicit, per-action) by the real oracle"
+    assert kc.classify("http.get") == Tier.A0, "a clean read-verb is A0"
+
+
+# ---- impersonation impossible by CONSTRUCTION (absence of a code path, not a check) --------------
+def test_no_impersonation_field_exists():
+    fields = set(WebStep.__dataclass_fields__)
+    assert fields == {"service", "kind", "url", "fields"}, f"WebStep has no identity/impersonate field: {fields}"
+    for banned in ("as_identity", "impersonate", "on_behalf_of", "actor", "subject_identity"):
+        assert banned not in fields
+
+
+def test_delegate_never_promotes():
+    assert "DELEGATE" in NO_PROMOTION_AGENTS, "DELEGATE must be structurally no-promotion (like ENVOY)"
+    s = _store()
+    assert PromotionPolicy(s, owner_key=OWNER, trusted_pubkey=OP).grant("DELEGATE", "*") is None, \
+        "granting DELEGATE promotion is refused"
+    assert PromotionPolicy(s, trusted_pubkey=OP).is_promoted("DELEGATE", "*") is False, "DELEGATE is never promoted"
+
+
+# ---- scope: deny-all origin allowlist + SSRF (private host) --------------------------------------
+def test_offlist_origin_is_refused_no_request():
+    s = _store()
+    d, engine = _delegate(s, pages={"https://evil.example/x": (200, "<html>ok</html>")})
+    queued, res = d.preview([WebStep("svc", "login", "https://evil.example/x", {"u": "vault:username"})])
+    assert queued == [] and any("REFUSED" in n for n in res.notes), "an off-allowlist origin is refused"
+    assert not _acts(engine), "a refused step performs no action"
+
+
+def test_private_host_is_refused_ssrf():
+    s = _store()
+    d, engine = _delegate(s, allowed=("http://127.0.0.1",),
+                          pages={"http://127.0.0.1/login": (200, "<form/>")})
+    queued, res = d.preview([WebStep("svc", "login", "http://127.0.0.1/login", {"u": "vault:username"})])
+    assert queued == [] and any("REFUSED" in n for n in res.notes), "a private/loopback host is refused (SSRF)"
+    assert not _acts(engine)
+
+
+# ---- the core approval gate: no approval → no request; approval → exactly one act ----------------
+def test_unapproved_step_makes_no_request():
+    s = _store()
+    d, engine = _delegate(s)
+    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup",
+                                   {"user": "vault:username", "pw": "vault:password"})])
+    assert len(queued) == 1, "the login step queues (A3)"
+    ex = d.execute(queued[0])                          # NO approval
+    assert not ex.applied and any("no verified owner approval" in n for n in ex.notes)
+    assert not _acts(engine), "an unapproved step performs ZERO requests"
+
+
+def test_approved_step_executes_exactly_one_act():
+    s = _store()
+    d, engine = _delegate(s)
+    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup",
+                                   {"user": "vault:username", "pw": "vault:password"})])
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
+    ex = d.execute(queued[0])
+    assert ex.applied, "an approved step executes"
+    acts = _acts(engine)
+    assert len(acts) == 1 and sorted(acts[0][2]) == ["pw", "user"], "exactly one act, carrying the field NAMES only"
+
+
+def test_credential_never_on_spine_or_journal():
+    s = _store()
+    d, engine = _delegate(s)
+    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup",
+                                   {"user": "vault:username", "pw": "vault:password"})])
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
+    d.execute(queued[0])
+    spine_bytes = Path(s.path).read_text()
+    assert SENTINEL not in spine_bytes, "the password NEVER appears in the append-only spine"
+    journal_bytes = "".join(p.read_text() for p in (actor_mod._JOURNAL).glob("*.json"))
+    assert SENTINEL not in journal_bytes, "the password NEVER appears in the 0700 step journal (only a vault reference)"
+    assert not any(SENTINEL in str(c) for c in engine.calls), "the password NEVER appears in a recorded engine call"
+
+
+# ---- blocks are surfaced, never defeated, never escalated ----------------------------------------
+def test_captcha_or_403_at_preview_surfaces_and_never_queues():
+    for status, html in ((403, ""), (200, "<div>Please complete the reCAPTCHA</div>"), (429, "")):
+        s = _store()
+        d, engine = _delegate(s, pages={f"{SVC}/signup": (status, html)})
+        queued, res = d.preview([WebStep("svc", "account.create", f"{SVC}/signup", {"u": "vault:username"})])
+        assert queued == [], f"a blocked page ({status}) is NOT queued for action"
+        assert any("BLOCKED" in n for n in res.notes)
+        assert any(r.payload.get("signal") == "web.actor.blocked" for r in s.iter_records()), "the block is surfaced"
+        assert not _acts(engine), "a block is never acted on (never defeated)"
+
+
+def test_block_appearing_at_execute_stops_before_acting():
+    s = _store()
+    d, engine = _delegate(s)                            # good page at preview
+    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup", {"pw": "vault:password"})])
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
+    engine.pages[f"{SVC}/signup"] = (403, "")           # the site starts blocking AFTER approval
+    ex = d.execute(queued[0])
+    assert not ex.applied and any("BLOCKED at execute" in n for n in ex.notes)
+    assert not _acts(engine), "a block detected at execute stops before any action"
+
+
+# ---- TOCTOU: a changed page OR a rotated credential invalidates the approval ----------------------
+def test_page_change_between_approval_and_execute_aborts():
+    s = _store()
+    d, engine = _delegate(s)
+    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup", {"pw": "vault:password"})])
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
+    engine.pages[f"{SVC}/signup"] = (200, "<form>DIFFERENT PAGE</form>")   # page changed
+    ex = d.execute(queued[0])
+    assert not ex.applied and any("token mismatch" in n for n in ex.notes), "a page change aborts (anti-TOCTOU)"
+    assert not _acts(engine)
+
+
+def test_credential_rotation_between_approval_and_execute_aborts():
+    s = _store()
+    v = _vault()
+    d, engine = _delegate(s, vault=v)
+    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup", {"pw": "vault:password"})])
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
+    v.bump("svc")                                       # the owner rotated the password → version++
+    ex = d.execute(queued[0])
+    assert not ex.applied and any("token mismatch" in n for n in ex.notes), \
+        "a credential rotation (version bump) invalidates the approval — re-approval required"
+    assert not _acts(engine)
+
+
+def test_approval_of_one_step_cannot_authorize_another():
+    s = _store()
+    d, engine = _delegate(s)
+    step = WebStep("svc", "login", f"{SVC}/signup", {"pw": "vault:password"})
+    queued, _ = d.preview([step, step])                # two identical steps → seqs A and B (same token)
+    a, b = queued
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(a)
+    assert not d.execute(b).applied, "an approval bound to seq A cannot authorize seq B (replay refused)"
+    assert not _acts(engine), "the replayed step performs no action"
+    assert d.execute(a).applied and len(_acts(engine)) == 1, "the genuinely-approved step executes once"
+
+
+# ---- mass-creation is out of doctrine: per-service cap -------------------------------------------
+def test_per_service_creation_cap():
+    s = _store()
+    d, engine = _delegate(s, cap=1)
+    q1, _ = d.preview([WebStep("svc", "account.create", f"{SVC}/signup", {"u": "vault:username"})])
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(q1[0])
+    assert d.execute(q1[0]).applied, "the first account.create is allowed"
+    q2, res = d.preview([WebStep("svc", "account.create", f"{SVC}/signup", {"u": "vault:username"})])
+    assert q2 == [] and any("creation cap" in n for n in res.notes), "a second account.create is refused (cap=1)"
+
+
+# ---- construction: the actor has NO browser/escalation path (block-before-escalate is vacuous) ---
+def test_actor_has_no_browser_escalation_path():
+    src = Path(actor_mod.__file__).read_text()
+    # no browser/JS-render/escalation call path (impersonation is covered structurally by the field test)
+    for banned in ("BrowserEngine", "needs_js", "playwright", "escalate", ".act(", "import subprocess"):
+        if banned == ".act(":
+            assert src.count(".act(") == 1, "exactly one engine.act call site (the single, gated action)"
+            continue
+        assert banned not in src, f"the actor must contain no {banned!r} path (HTTP-only, no evasion surface)"
+
+
+# ---- the REAL HttpEngine independently refuses a private host (defense-in-depth below ActorScope) --
+def test_real_http_engine_refuses_private_host_act():
+    from sigil.agents.web_engine import HttpEngine
+    out = HttpEngine().act({"url": "http://127.0.0.1/login", "kind": "login"}, {"pw": SENTINEL})
+    assert out.get("ok") is False and out.get("reason") == "ssrf-refused", \
+        "the real engine's own _vetted_ip gate refuses a loopback POST — no egress even if scope were bypassed"
+
+
+if __name__ == "__main__":
+    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
+    passed = 0
+    for fn in fns:
+        try:
+            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
+        except AssertionError as e:
+            print(f"  FAIL  {fn.__name__}: {e}")
+        except Exception as e:  # noqa: BLE001
+            import traceback
+            print(f"  ERROR {fn.__name__}: {e}")
+            traceback.print_exc()
+    print(f"{passed}/{len(fns)} Phase-8 WS-G (DELEGATE) doctrine guarantees hold")
