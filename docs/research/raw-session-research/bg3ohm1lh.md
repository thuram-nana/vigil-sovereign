commit b7a573ef33a7e88c9376f4f5b7382d0eca967de4
Author: Water Hacker <satoshinakamotobull@gmail.com>
Date:   Sat Jul 18 18:27:32 2026 -0400

    Phase 8 WS-G: fix dual-review findings (2 HIGH + 1 MED + honesty/robustness)
    
    Dual review (red-pen + independent adversarial sweep) found and repro'd:
    
      HIGH  execute() was non-idempotent — the append-only approval never
            retires, so one owner signature authorised UNBOUNDED repeated POSTs.
            FIX: single-shot guard — a step with an existing applied record
            (bound by target_seq) is refused (mirrors Operator BLOCK-6). The
            applied record now carries target_seq.
      HIGH  per-service creation cap was preview-only; a batch previewed before
            any execute all saw 0-applied and bypassed cap=1.
            FIX: re-check creation_allowed at EXECUTE for account.create.
      MED   action_token did not bind the URL and the journal was keyed by the
            token, so two same-origin URLs serving identical HTML collided ->
            an approved /login could fire at /promo.
            FIX: URL is now in the token preimage (distinct urls -> distinct
            tokens -> distinct journals); origin_allowed re-checked at execute.
      LOW/MED  fetch pinned IP-A, act re-resolved IP-B (DNS-rebind split).
            FIX: fetch_raw surfaces its vetted IP; the actor threads it into
            act() so the POST binds to the same address the bytes came from.
      LOW   unknown/non-string field sources were silently dropped but shown to
            the owner as approved.  FIX: fail-closed field-source validation at
            preview (only vault refs / literals; a non-string no longer crashes).
      LOW   honesty: web_engine docstring described a non-existent BrowserEngine
            + dead needs_js; block/rotation language over-claimed.  FIX: docs now
            state HTTP-only (no browser path), best-effort block detection, and
            that version-binding covers the set_record path.
      LOW   vault manifest: chmod 0600 on every save (not just create); a hostile
            non-dict / malformed manifest yields no records instead of crashing.
      minor ActorScope now binds the port (port-confusion refused).
    
    +7 negative controls (each fails pre-fix, passes post-fix). WS-G 23/23;
    full suite 209 green; SCRIBE unaffected by the shared fetch_raw change.
    
    Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

diff --git a/sigil/agents/actor.py b/sigil/agents/actor.py
index eef58b5..4e411df 100644
--- a/sigil/agents/actor.py
+++ b/sigil/agents/actor.py
@@ -7,15 +7,19 @@ token-bound-approve → re-derive-at-execute → verify) with the egress per-act
 
 Offense-free by construction:
   • NO `as_identity`/impersonate parameter exists — fields resolve ONLY from the owner's OWN vault.
-  • a CAPTCHA / 403 / 429 STOPS and is surfaced as a positive control; the block-check precedes any
-    action, and there is NO browser-escalation code path in the actor at all (HTTP-only), so "use a
-    browser to beat a block" is structurally unreachable.
-  • per-service creation cap (mass creation is out of doctrine); `ActorScope` origin allowlist (deny-all).
+  • a DETECTED block (best-effort: CAPTCHA / 403 / 429) STOPS and is surfaced as a positive control; the
+    block-check precedes any action, and there is NO browser-escalation code path in the actor at all
+    (HTTP-only), so "use a browser to beat a block" is structurally unreachable.
+  • ONE approval authorises exactly ONE action: execute is single-shot per step (a second execute of an
+    already-applied step is refused), so an approval can never be replayed into repeated POSTs.
+  • per-service creation cap (mass creation is out of doctrine), enforced at preview AND re-checked at
+    execute (so a batch previewed before any execute cannot outrun the cap); `ActorScope` origin
+    allowlist (deny-all), re-checked at execute.
   • credentials resolve from the keyring ONLY at the last instant of execute, into a local var — never a
     Proposal payload, never logged/journaled. The executable step (incl. any literal values) lives in a
-    0700 journal OFF the append-only spine; the spine binds by service + page hash + a field_binding of
-    NAMES + vault-references + literal-content-hashes + the vault VERSION (a page change OR a credential
-    rotation OR a literal edit changes the token → the approval no longer verifies → re-approval)."""
+    0700 journal OFF the append-only spine; the spine binds by service + URL + page hash + a field_binding
+    of NAMES + vault-references + literal-content-hashes + the vault VERSION (a changed URL OR page OR a
+    credential rotation OR a literal edit changes the token → the approval no longer verifies)."""
 from __future__ import annotations
 
 import json
@@ -38,6 +42,15 @@ _JOURNAL = _ACTOR_HOME / "steps"     # executable steps (WITH any literal values
 _TOOL = {"navigate": "browser.navigate", "fill": "form.fill", "submit": "submit.form",
          "account.create": "account.create", "login": "login", "purchase": "purchase.item"}
 
+_VAULT_REFS = {"vault:password", "vault:email", "vault:username"}
+
+
+def _valid_source(src) -> bool:
+    """A field value is a known source: an owner-vault reference or a literal. Anything else (unknown
+    vault key, `env:`/`file:` scheme, non-string) is REFUSED at preview — so the owner never approves a
+    field the actor would silently drop, and no unhandled source can reach execute."""
+    return isinstance(src, str) and (src in _VAULT_REFS or src.startswith("literal:"))
+
 
 def _secure(d: Path) -> None:
     d.mkdir(parents=True, exist_ok=True)
@@ -129,6 +142,13 @@ class Delegate(Agent):
                                            "reason": "per-service creation cap (mass account creation is out of doctrine)"})
                 res.notes.append(f"REFUSED account.create {step.service}: creation cap")
                 continue
+            bad = sorted(k for k, v in step.fields.items() if not _valid_source(v))
+            if bad:                                          # fail-closed: no silently-dropped fields
+                self.store.append(kind="refusal", source="agent", actor=self.name,
+                                  payload={"tier": "A0", "decision": "refused", "requested": step.url,
+                                           "reason": f"unknown/invalid field source(s) for: {bad}"})
+                res.notes.append(f"REFUSED {step.url}: invalid field source(s) {bad}")
+                continue
             pv = self.engine.fetch(step.url)                 # A0 dry-run GET — no mutation
             block = detect_block(pv.status, pv.html)
             if block:                                        # STOP + surface — never defeat a block
@@ -140,7 +160,7 @@ class Delegate(Agent):
                 continue
             page_hash = sha256_hex(pv.html.encode("utf-8", "ignore"))
             fb = self._field_binding(step.service, step.fields)
-            token = action_token(step.service, step.kind, page_hash, fb)
+            token = action_token(step.service, step.kind, step.url, page_hash, fb)
             _secure(_ACTOR_HOME)
             _secure(_JOURNAL)
             # executable step (WITH any literal values) → 0700 journal, keyed by token; NEVER the spine
@@ -171,12 +191,26 @@ class Delegate(Agent):
         if not action_approved(self.store, step_seq, token, self._tp()):
             res.notes.append(f"step {step_seq} has no verified owner approval — NO request made")
             return res
+        # SINGLE-SHOT: one approval authorises exactly ONE action. A step that already produced an applied
+        # record is refused (the append-only approval never expires, so without this guard one signature
+        # would authorise unbounded repeats). Mirrors the Operator's single-shot undo (BLOCK-6).
+        for r in self.store.iter_records(since_seq=step_seq):
+            if (r.payload.get("signal") == ACTION_SIGNAL and r.payload.get("status") == "applied"
+                    and r.payload.get("target_seq") == step_seq):
+                res.notes.append(f"step {step_seq} was already executed (seq {r.seq}) — refusing a replay (per-action)")
+                return res
         try:                                                 # executable step lives OFF the spine (0700)
             j = json.loads(Path(rec.payload["journal"]).read_text(encoding="utf-8"))
             service, kind, url, fields = j["service"], j["kind"], j["url"], j["fields"]
         except (OSError, ValueError, KeyError, TypeError):
             res.notes.append("step journal missing/unreadable — cannot execute")
             return res
+        if not self.scope.origin_allowed(url):               # re-check scope at execute (belt-and-suspenders)
+            self.store.append(kind="refusal", source="agent", actor=self.name,
+                              payload={"tier": "A0", "decision": "refused", "target_seq": step_seq, "requested": url,
+                                       "reason": "the step URL is not in the owner's ActorScope at execute — aborted"})
+            res.notes.append(f"ABORTED: {url} left the ActorScope — no action")
+            return res
         pv = self.engine.fetch(url)                          # re-fetch (anti-TOCTOU + block-before-act)
         block = detect_block(pv.status, pv.html)
         if block:
@@ -186,21 +220,30 @@ class Delegate(Agent):
                                        "summary": f"{url} blocked at execute ({block}) — surfaced, no action"})
             res.notes.append(f"BLOCKED at execute {url}: {block} — surfaced, no action")
             return res
-        # RE-DERIVE the token from the CURRENT page hash + CURRENT vault version + journaled fields; a
-        # page change OR a credential rotation OR a journal edit → mismatch → abort (never trust a field).
-        fresh = action_token(service, kind, sha256_hex(pv.html.encode("utf-8", "ignore")),
+        # RE-DERIVE the token from the CURRENT url + page hash + vault version + journaled fields; a changed
+        # URL OR page OR a credential rotation OR a journal edit → mismatch → abort (never trust a field).
+        fresh = action_token(service, kind, url, sha256_hex(pv.html.encode("utf-8", "ignore")),
                              self._field_binding(service, fields))
         if fresh != token:
             self.store.append(kind="refusal", source="agent", actor=self.name,
                               payload={"tier": "A0", "decision": "refused", "target_seq": step_seq,
-                                       "reason": "page/credential/step changed since approval (token mismatch) — aborted"})
+                                       "reason": "url/page/credential/step changed since approval (token mismatch) — aborted"})
             res.notes.append("ABORTED: the world changed since approval (token mismatch) — no action")
             return res
+        # RE-CHECK the creation cap at execute (against committed applied records) so a batch previewed
+        # before any execute cannot outrun cap=1 — the preview check alone counts zero applied.
+        if kind == "account.create" and not self.scope.creation_allowed(self.store, service):
+            self.store.append(kind="refusal", source="agent", actor=self.name,
+                              payload={"tier": "A0", "decision": "refused", "target_seq": step_seq, "service": service,
+                                       "reason": "per-service creation cap reached at execute (mass creation out of doctrine)"})
+            res.notes.append(f"REFUSED account.create {service} at execute: creation cap")
+            return res
         resolved = self._resolve(service, fields)            # credentials → locals ONLY (never the spine)
-        out = self.engine.act({"url": url, "kind": kind}, resolved)
+        out = self.engine.act({"url": url, "kind": kind}, resolved,
+                              pinned_ip=getattr(pv, "resolved_ip", "") or None)   # bind the POST to the vetted IP
         seq = self.store.append(kind="event", source="agent", actor=self.name,
-                                payload={"signal": ACTION_SIGNAL, "status": "applied", "service": service,
-                                         "step_kind": kind, "url": url, "action_token": token,
+                                payload={"signal": ACTION_SIGNAL, "status": "applied", "target_seq": step_seq,
+                                         "service": service, "step_kind": kind, "url": url, "action_token": token,
                                          "result_ok": bool(out.get("ok")), "tier": "A1", "decision": "auto",
                                          "summary": f"{kind} on {service} executed (ok={out.get('ok')})"})
         res.applied.append(seq)
diff --git a/sigil/agents/actor_gate.py b/sigil/agents/actor_gate.py
index 7dd49b1..db1bee5 100644
--- a/sigil/agents/actor_gate.py
+++ b/sigil/agents/actor_gate.py
@@ -1,8 +1,10 @@
 """Action gate (Phase 8, WS-G G-iii) — a near-verbatim mirror of `perception/egress.py`, but for web
-ACTIONS. `action_token = sha256(service|step|page_sha256|field_binding)` binds an approval to ONE
-exact action (a page-change or a vault-version bump changes the token → re-approval). `action_approved`
-requires a VERIFIED owner/authorized-device approval whose signed `target_seq` IS that step — a
-replay onto a different action, a wrong token, an unsigned/denied approval → False (fail-closed)."""
+ACTIONS. `action_token = sha256(service|step|url|page_sha256|field_binding)` binds an approval to ONE
+exact action — the destination URL is IN the preimage (so an approval can never be rebound to a
+different URL, even one serving identical bytes), alongside the page hash (a page-change aborts) and
+the field binding (a vault-version bump / literal edit aborts). `action_approved` requires a VERIFIED
+owner/authorized-device approval whose signed `target_seq` IS that step — a replay onto a different
+action, a wrong token, an unsigned/denied approval → False (fail-closed)."""
 from __future__ import annotations
 
 from ..reuse import sha256_hex
@@ -12,8 +14,8 @@ from .approvals import verify_approval
 ACTION_SIGNAL = "web.actor.step"
 
 
-def action_token(service: str, step_kind: str, page_sha256: str, field_binding: str) -> str:
-    return sha256_hex(f"{service}|{step_kind}|{page_sha256}|{field_binding}".encode("utf-8"))
+def action_token(service: str, step_kind: str, url: str, page_sha256: str, field_binding: str) -> str:
+    return sha256_hex(f"{service}|{step_kind}|{url}|{page_sha256}|{field_binding}".encode("utf-8"))
 
 
 def action_approved(store, seq: int, token: str, trusted_pubkey) -> bool:
diff --git a/sigil/agents/actor_scope.py b/sigil/agents/actor_scope.py
index 39eacc0..67b6a60 100644
--- a/sigil/agents/actor_scope.py
+++ b/sigil/agents/actor_scope.py
@@ -10,12 +10,20 @@ from urllib.parse import urlsplit
 
 from .sources import is_public_host
 
+_DEFAULT_PORT = {"http": 80, "https": 443}
+
 
 def _origin(url: str) -> Optional[str]:
-    p = urlsplit(url if "//" in url else "https://" + url)
-    if p.scheme not in ("http", "https") or not p.hostname:
+    """Canonical scheme://host:port (default port made explicit) — so `https://h` and `https://h:443`
+    match, but `https://h:8443` does NOT match `https://h` (port confusion is refused)."""
+    try:
+        p = urlsplit(url if "//" in url else "https://" + url)
+        if p.scheme not in ("http", "https") or not p.hostname:
+            return None
+        port = p.port or _DEFAULT_PORT[p.scheme]
+    except ValueError:                      # malformed / out-of-range port → fail-closed
         return None
-    return f"{p.scheme}://{p.hostname.lower()}"
+    return f"{p.scheme}://{p.hostname.lower()}:{port}"
 
 
 class ActorScope:
@@ -27,7 +35,7 @@ class ActorScope:
         p = urlsplit(url)
         if p.scheme not in ("http", "https") or not p.hostname or not is_public_host(p.hostname):
             return False
-        return bool(self.allowed) and f"{p.scheme}://{p.hostname.lower()}" in self.allowed
+        return bool(self.allowed) and _origin(url) in self.allowed
 
     def creation_allowed(self, store, service: str) -> bool:
         n = sum(1 for r in store.iter_records()
diff --git a/sigil/agents/sources.py b/sigil/agents/sources.py
index 5c64940..505170c 100644
--- a/sigil/agents/sources.py
+++ b/sigil/agents/sources.py
@@ -140,6 +140,7 @@ class FetchResult:
     url: str
     headers: dict = field(default_factory=dict)
     reason: str = ""
+    resolved_ip: str = ""    # the vetted, PINNED IP this fetch used (so a caller can bind a follow-up POST to the SAME address)
 
 
 def fetch_raw(ref: str, *, timeout: int = 20, max_bytes: int = 2_000_000) -> FetchResult:
@@ -160,14 +161,14 @@ def fetch_raw(ref: str, *, timeout: int = 20, max_bytes: int = 2_000_000) -> Fet
     try:
         with opener.open(req, timeout=timeout) as r:
             raw = r.read(max_bytes).decode("utf-8", "ignore")
-            return FetchResult(True, getattr(r, "status", 200), raw, ref, headers=dict(r.headers))
+            return FetchResult(True, getattr(r, "status", 200), raw, ref, headers=dict(r.headers), resolved_ip=ip)
     except urllib.error.HTTPError as e:                 # 3xx-not-followed / 4xx / 5xx — surface the code
         body = ""
         try:
             body = e.read(max_bytes).decode("utf-8", "ignore")
         except Exception:  # noqa: BLE001
             pass
-        return FetchResult(False, e.code, body, ref, headers=dict(e.headers or {}), reason=f"http-{e.code}")
+        return FetchResult(False, e.code, body, ref, headers=dict(e.headers or {}), reason=f"http-{e.code}", resolved_ip=ip)
     except (urllib.error.URLError, OSError, ValueError) as e:
         return FetchResult(False, 0, "", ref, reason=f"neterr:{type(e).__name__}")
 
diff --git a/sigil/agents/vault.py b/sigil/agents/vault.py
index 0e0c5f5..2ca188d 100644
--- a/sigil/agents/vault.py
+++ b/sigil/agents/vault.py
@@ -4,9 +4,12 @@ spine, a log, or a network payload"). A `VaultRecord` has NO `password` field 
 (a keyring key name); the password lives in the OS keyring. The manifest (email/username/ref/version)
 lives in a 0700 dir OFF the append-only spine. The password is resolved from the keyring ONLY at
 execute time, into a local variable — never assigned to a Proposal payload, never logged, never
-journaled. `version` bumps on every edit and BINDS an approval (rotate → version bump → re-approval),
-so the spine binds by `service+vault_ref+version` — deliberately NOT a hash of the value (hashing a
-low-entropy identity field onto an append-only log is itself a weak-preimage leak)."""
+journaled. `version` bumps on every edit via `set_record` and BINDS an approval (rotate through the
+vault API → version bump → re-approval), so the spine binds by `service+vault_ref+version` —
+deliberately NOT a hash of the value (hashing a low-entropy identity field onto an append-only log is
+itself a weak-preimage leak). NOTE: a password rotated OUT-OF-BAND directly in the keyring under the
+same `password_ref` (bypassing `set_record`) does not bump `version`; owner credential rotation should
+go through `set_record` so the version binding stays meaningful."""
 from __future__ import annotations
 
 import json
@@ -37,9 +40,10 @@ class CredentialVault:
 
     def _load(self) -> dict:
         try:
-            return json.loads(_MANIFEST.read_text(encoding="utf-8"))
+            data = json.loads(_MANIFEST.read_text(encoding="utf-8"))
         except (OSError, ValueError):
             return {}
+        return data if isinstance(data, dict) else {}      # a hostile/corrupt non-dict manifest → empty, not a crash
 
     def _save(self, data: dict) -> None:
         _VAULT.mkdir(parents=True, exist_ok=True)
@@ -50,6 +54,10 @@ class CredentialVault:
         fd = os.open(str(_MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # 0600 up-front
         with os.fdopen(fd, "w", encoding="utf-8") as f:
             json.dump(data, f)
+        try:
+            os.chmod(str(_MANIFEST), 0o600)                 # enforce 0600 even if the file pre-existed with looser perms
+        except OSError:
+            pass
 
     def set_record(self, service: str, *, email: str = "", username: str = "",
                    password: Optional[str] = None, notes: str = "") -> VaultRecord:
@@ -65,12 +73,20 @@ class CredentialVault:
         self._save(data)
         return VaultRecord(**rec)
 
+    @staticmethod
+    def _rec(d) -> Optional[VaultRecord]:
+        if not isinstance(d, dict):
+            return None
+        try:
+            return VaultRecord(**d)                         # tolerate extra/missing keys in a hostile manifest
+        except TypeError:
+            return None
+
     def get_record(self, service: str) -> Optional[VaultRecord]:
-        d = self._load().get(service)
-        return VaultRecord(**d) if d else None
+        return self._rec(self._load().get(service))
 
     def records(self) -> List[VaultRecord]:
-        return [VaultRecord(**d) for d in self._load().values()]
+        return [r for r in (self._rec(d) for d in self._load().values()) if r is not None]
 
     def resolve_password(self, service: str) -> Optional[str]:
         """Fetch the password from the keyring — call ONLY at execute-time, into a local var."""
diff --git a/sigil/agents/web_engine.py b/sigil/agents/web_engine.py
index 9900f75..b137f14 100644
--- a/sigil/agents/web_engine.py
+++ b/sigil/agents/web_engine.py
@@ -1,9 +1,12 @@
-"""Web engine (Phase 8, WS-G G-iii) — HTTP-first, headless-browser fallback. `HttpEngine` reuses the
-SSRF-gated, IP-pinned, correlatable-UA `sources.fetch_raw` for the light path. `detect_block` flags a
-CAPTCHA / 403 / 429 / CF-challenge and is checked BEFORE the escalation decision, so "use the browser
-to defeat a block" is structurally unreachable. `BrowserEngine` (lazy Playwright, locked-down, no
-stealth/proxy/UA-rotation) is a documented off-by-default seam. `FakeEngine` is the deterministic
-double + call spy for tests."""
+"""Web engine (Phase 8, WS-G G-iii) — HTTP-only. `HttpEngine` reuses the SSRF-gated, IP-pinned,
+correlatable-UA `sources.fetch_raw` for the read path and pins the SAME vetted IP for the write path
+(so the bytes that were block-checked/hashed and the endpoint that receives credentials are one
+address — no DNS-rebinding split). `detect_block` is a BEST-EFFORT flag for a CAPTCHA / 403 / 429 /
+CF-challenge; a DETECTED block STOPS + is surfaced as a positive control (it is not a guarantee that
+every anti-automation page is recognised — a missed soft-block only ever means the actor proceeds as
+approved, never that a block is defeated). There is deliberately NO headless-browser / JS-render path
+in this actor: "use a browser to beat a block" is unreachable because the capability does not exist.
+`FakeEngine` is the deterministic double + call spy for tests."""
 from __future__ import annotations
 
 import re
@@ -11,7 +14,6 @@ from dataclasses import dataclass
 from typing import Optional, Protocol, runtime_checkable
 
 _BLOCK = re.compile(r"recaptcha|hcaptcha|turnstile|cf-chl|just a moment|attention required|\bcaptcha\b", re.I)
-_JS_APP = re.compile(r'id=["\'](root|app|__next)["\']', re.I)
 
 
 @dataclass
@@ -20,17 +22,19 @@ class PageView:
     status: int
     html: str
     url: str
+    resolved_ip: str = ""    # the vetted IP the read used — threaded into act() to bind the write to it
 
 
 @runtime_checkable
 class WebEngine(Protocol):
     egresses: bool
     def fetch(self, url: str) -> PageView: ...
-    def act(self, step: dict, resolved: dict) -> dict: ...
+    def act(self, step: dict, resolved: dict, *, pinned_ip: Optional[str] = None) -> dict: ...
 
 
 def detect_block(status: int, html: str) -> Optional[str]:
-    """A block signal (STOP + surface as a positive control — never defeated). Runs BEFORE escalation."""
+    """A best-effort block signal (STOP + surface as a positive control — never defeated). Runs BEFORE
+    any action. Keys on 403/429 and a fixed anti-automation keyword set; it can MISS a soft-block."""
     if status in (403, 429):
         return f"http-{status}"
     if _BLOCK.search(html or ""):
@@ -38,29 +42,25 @@ def detect_block(status: int, html: str) -> Optional[str]:
     return None
 
 
-def needs_js(html: str, *, min_text: int = 200) -> bool:
-    """A MISSING-CAPABILITY signal (escalate to the browser) — deliberately DISJOINT from a block."""
-    from .sources import _strip_html
-    return len(_strip_html(html or "").strip()) < min_text and bool(_JS_APP.search(html or ""))
-
-
 class HttpEngine:
     egresses = True
 
     def fetch(self, url: str) -> PageView:
         from .sources import fetch_raw
         r = fetch_raw(url)
-        return PageView(r.ok, r.status, r.raw, url)
+        return PageView(r.ok, r.status, r.raw, url, resolved_ip=r.resolved_ip)
 
-    def act(self, step: dict, resolved: dict) -> dict:
+    def act(self, step: dict, resolved: dict, *, pinned_ip: Optional[str] = None) -> dict:
         """A simple static-form submit (urlencoded POST). Credentials arrive in `resolved` at the last
-        instant and go ONLY into the POST body — never logged/returned."""
+        instant and go ONLY into the POST body — never the URL, never logged/returned. The socket is
+        pinned to `pinned_ip` when the caller supplies the IP its read already vetted (binding the write
+        to the block-checked address); otherwise the IP is re-vetted here (fail-closed on private)."""
         import urllib.parse
         import urllib.request
-        from .sources import UA, _NoRedirect, _PinnedHTTPHandler, _PinnedHTTPSHandler, _vetted_ip
         from urllib.parse import urlsplit
+        from .sources import UA, _NoRedirect, _PinnedHTTPHandler, _PinnedHTTPSHandler, _vetted_ip
         url = step.get("url", "")
-        ip = _vetted_ip(urlsplit(url).hostname or "")
+        ip = pinned_ip or _vetted_ip(urlsplit(url).hostname or "")
         if ip is None:
             return {"ok": False, "reason": "ssrf-refused"}
         data = urllib.parse.urlencode(resolved).encode("utf-8")
@@ -72,22 +72,24 @@ class HttpEngine:
             with opener.open(req, timeout=20) as r:
                 return {"ok": 200 <= getattr(r, "status", 200) < 400, "status": getattr(r, "status", 200)}
         except Exception as e:  # noqa: BLE001
-            return {"ok": False, "reason": f"{type(e).__name__}"}
+            return {"ok": False, "reason": f"{type(e).__name__}"}   # type name only — never the body/exception text
 
 
 class FakeEngine:
-    """Deterministic double + spy: `pages` = {url: (status, html)}; records every fetch/act."""
+    """Deterministic double + spy: `pages` = {url: (status, html)}; records every fetch/act (act records
+    the field KEYS and the pinned IP only — never a value)."""
     egresses = True
 
-    def __init__(self, pages: Optional[dict] = None):
+    def __init__(self, pages: Optional[dict] = None, *, resolved_ip: str = "203.0.113.7"):
         self.pages = pages or {}
+        self.resolved_ip = resolved_ip
         self.calls: list = []
 
     def fetch(self, url: str) -> PageView:
         self.calls.append(("fetch", url))
         st, html = self.pages.get(url, (404, ""))
-        return PageView(200 <= st < 300, st, html, url)
+        return PageView(200 <= st < 300, st, html, url, resolved_ip=self.resolved_ip)
 
-    def act(self, step: dict, resolved: dict) -> dict:
-        self.calls.append(("act", step.get("url"), sorted(resolved.keys())))   # keys only — never values
+    def act(self, step: dict, resolved: dict, *, pinned_ip: Optional[str] = None) -> dict:
+        self.calls.append(("act", step.get("url"), sorted(resolved.keys()), pinned_ip))   # keys + IP only — never values
         return {"ok": True, "status": 200}
diff --git a/tests/test_actor.py b/tests/test_actor.py
index fc93903..62b4cea 100644
--- a/tests/test_actor.py
+++ b/tests/test_actor.py
@@ -249,6 +249,87 @@ def test_actor_has_no_browser_escalation_path():
         assert banned not in src, f"the actor must contain no {banned!r} path (HTTP-only, no evasion surface)"
 
 
+# ==== review negative controls (each FAILS on the pre-fix code, PASSES after) =====================
+
+def test_execute_is_single_shot():                                 # sweep FINDING 1 (HIGH)
+    s = _store()
+    d, engine = _delegate(s, pages={f"{SVC}/buy": (200, "<form>buy</form>")})
+    q, _ = d.preview([WebStep("svc", "purchase", f"{SVC}/buy", {"pw": "vault:password"})])
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(q[0])
+    first, second, third = d.execute(q[0]), d.execute(q[0]), d.execute(q[0])
+    assert first.applied and not second.applied and not third.applied, "ONE approval authorises exactly ONE action"
+    assert any("already executed" in n for n in second.notes)
+    assert len(_acts(engine)) == 1, "one owner signature → exactly one POST (an approval can't be replayed into repeats)"
+
+
+def test_creation_cap_holds_against_batched_preview():             # red-pen BLOCK-1 / sweep FINDING 2 (HIGH)
+    s = _store()
+    d, engine = _delegate(s, cap=1)
+    steps = [WebStep("svc", "account.create", f"{SVC}/signup", {"u": "vault:username"}) for _ in range(3)]
+    q, _ = d.preview(steps)
+    assert len(q) == 3, "all three queue at preview (0 applied yet) — the batch-race setup"
+    aq = ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP)
+    for seq in q:
+        aq.approve(seq)
+    applied = sum(1 for seq in q if d.execute(seq).applied)
+    assert applied == 1 and len(_acts(engine)) == 1, "cap=1 holds at EXECUTE despite a batched preview+approve"
+
+
+def test_action_binds_url_no_journal_rebind():                    # red-pen BLOCK-3 (MEDIUM)
+    s = _store()
+    html = "<form>identical bytes</form>"
+    d, engine = _delegate(s, pages={f"{SVC}/login": (200, html), f"{SVC}/promo": (200, html)})
+    q, _ = d.preview([WebStep("svc", "login", f"{SVC}/login", {"pw": "vault:password"}),
+                      WebStep("svc", "login", f"{SVC}/promo", {"pw": "vault:password"})])
+    a, b = q
+    assert s.get(a).payload["action_token"] != s.get(b).payload["action_token"], \
+        "identical-HTML steps at DIFFERENT urls get DIFFERENT tokens (the url is bound into the token)"
+    assert s.get(a).payload["journal"] != s.get(b).payload["journal"], "no journal-file collision across urls"
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(a)
+    assert d.execute(a).applied
+    assert _acts(engine)[-1][1] == f"{SVC}/login", "the credential POST fires at the APPROVED url, not the sibling page"
+
+
+def test_unknown_or_nonstring_field_source_refused():             # sweep FINDING 4/5 (LOW)
+    s = _store()
+    d, engine = _delegate(s)
+    for bad in ({"x": "env:PATH"}, {"y": "file:/etc/passwd"}, {"z": "vault:secret_question"}, {"n": 123}):
+        q, res = d.preview([WebStep("svc", "login", f"{SVC}/signup", bad)])
+        assert q == [] and any("invalid field source" in n for n in res.notes), f"{bad} is refused at preview (no silent drop)"
+    assert not _acts(engine), "an invalid step never acts"
+
+
+def test_actor_scope_binds_port():                                # red-pen minor (port confusion)
+    sc = ActorScope(["https://svc.example"])
+    assert sc.origin_allowed(f"{SVC}/x") is True and sc.origin_allowed("https://svc.example:443/x") is True
+    assert sc.origin_allowed("https://svc.example:8443/x") is False, "a different port does NOT match (port confusion refused)"
+
+
+def test_pinned_ip_is_threaded_from_fetch_to_act():               # sweep FINDING 3 (anti-rebind)
+    s = _store()
+    d, engine = _delegate(s)                                        # FakeEngine.resolved_ip default 203.0.113.7
+    q, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup", {"pw": "vault:password"})])
+    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(q[0])
+    d.execute(q[0])
+    assert _acts(engine)[-1][3] == "203.0.113.7", "the POST is pinned to the SAME vetted IP the block-checked fetch used"
+
+
+def test_vault_tolerates_hostile_manifest():                      # sweep FINDING 7 (LOW)
+    import sigil.agents.vault as vault_mod
+    tmp = Path(tempfile.mktemp(suffix=".json"))
+    orig = vault_mod._MANIFEST
+    vault_mod._MANIFEST = tmp
+    try:
+        v = vault_mod.CredentialVault(secret_store=object())        # object() avoids constructing a real keyring store
+        tmp.write_text("[1,2,3]")                                   # a JSON list, not a dict
+        assert v.get_record("svc") is None and v.records() == [], "a non-dict manifest → no records, not a crash"
+        tmp.write_text('{"svc": {"service": "svc", "bogus": 1}}')   # a record with an unknown key
+        assert v.get_record("svc") is None, "a malformed record is skipped, not crashed on"
+    finally:
+        vault_mod._MANIFEST = orig
+        tmp.unlink(missing_ok=True)
+
+
 # ---- the REAL HttpEngine independently refuses a private host (defense-in-depth below ActorScope) --
 def test_real_http_engine_refuses_private_host_act():
     from sigil.agents.web_engine import HttpEngine
