"""SIGIL Phase 8 WS-G — DELEGATE: the owner-consented identity/account manager + web actor. Proves the
doctrine BY CONSTRUCTION: credentials never reach the append-only spine or the journal; no action fires
without a verified owner approval bound to that exact step; a CAPTCHA/403 STOPS and is surfaced (never
defeated, never a browser escalation); page/credential TOCTOU aborts; per-service creation cap; approval
replay refused; NO impersonation parameter exists; DELEGATE never promotes.
Run: ~/.sigil/venv/bin/python tests/test_actor.py"""
import tempfile
from pathlib import Path

import sigil.agents.actor as actor_mod
import sigil.agents.actor_scope as scope_mod
from sigil.agents.actor import Delegate, WebStep
from sigil.agents.actor_scope import ActorScope
from sigil.agents.approvals import ApprovalQueue
from sigil.agents.base import Tier
from sigil.agents.vault import VaultRecord
from sigil.agents.web_engine import FakeEngine
from sigil.governor.promotion import NO_PROMOTION_AGENTS, PromotionPolicy
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_KERNEL = Path("/home/kali/sigil/kernel/target/release/sigil-kernel")

# --- test isolation: journal to a temp dir (off the real ~/.sigil); "public" excludes private hosts ---
_TMP = Path(tempfile.mkdtemp(prefix="actor-journal-"))
actor_mod._ACTOR_HOME = _TMP
actor_mod._JOURNAL = _TMP / "steps"
_PRIVATE = {"127.0.0.1", "localhost", "10.0.0.5", "169.254.169.254", "::1"}
scope_mod.is_public_host = lambda h: h.lower() not in _PRIVATE     # real DNS would flake; keep the gate meaningful

SENTINEL = "SENTINEL-PW-9f3a2b-UNIQUE-DO-NOT-LEAK"
SVC = "https://svc.example"


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class FakeCls:
    """Deterministic stand-in for the Rust oracle: only a clean read-verb is A0; every actor verb → A3."""
    def classify(self, tool):
        return Tier.A0 if tool == "http.get" else Tier.A3


class FakeVault:
    """In-memory vault double (no keyring, no manifest). `password` is held out-of-band, resolved late."""
    def __init__(self):
        self._r, self._pw = {}, {}

    def add(self, service, *, email="", username="", password="", version=1):
        self._r[service] = VaultRecord(service=service, email=email, username=username,
                                       password_ref=f"vault/{service}/password", version=version)
        self._pw[service] = password

    def get_record(self, service):
        return self._r.get(service)

    def resolve_password(self, service):
        return self._pw.get(service)

    def bump(self, service):                          # simulate a credential rotation (version++)
        r = self._r[service]
        self._r[service] = VaultRecord(service=r.service, email=r.email, username=r.username,
                                       password_ref=r.password_ref, version=r.version + 1)


def _vault():
    v = FakeVault()
    v.add("svc", email="me@owner.example", username="owner", password=SENTINEL)
    return v


def _delegate(store, *, pages=None, allowed=(SVC,), cap=1, vault=None):
    engine = FakeEngine(pages if pages is not None else {f"{SVC}/signup": (200, "<form>signup</form>")})
    d = Delegate(store, scope=ActorScope(list(allowed), creation_cap=cap),
                 vault=vault or _vault(), engine=engine, classifier=FakeCls(), trusted_pubkey=OP)
    return d, engine


def _acts(engine):
    return [c for c in engine.calls if c[0] == "act"]


# ---- G2 WARDEN honesty (real oracle) -------------------------------------------------------------
def test_warden_locks_actor_verbs_a3():
    if not _KERNEL.exists():
        print("    (skip real oracle — kernel not built)")
        return
    from sigil.agents.kernel_classify import KernelClassifier
    kc = KernelClassifier(kernel_bin=str(_KERNEL))
    for verb in ("account.create", "login", "submit.form", "purchase.item", "form.fill", "browser.navigate"):
        assert kc.classify(verb) == Tier.A3, f"{verb} must be A3 (explicit, per-action) by the real oracle"
    assert kc.classify("http.get") == Tier.A0, "a clean read-verb is A0"


# ---- impersonation impossible by CONSTRUCTION (absence of a code path, not a check) --------------
def test_no_impersonation_field_exists():
    fields = set(WebStep.__dataclass_fields__)
    assert fields == {"service", "kind", "url", "fields"}, f"WebStep has no identity/impersonate field: {fields}"
    for banned in ("as_identity", "impersonate", "on_behalf_of", "actor", "subject_identity"):
        assert banned not in fields


def test_delegate_never_promotes():
    assert "DELEGATE" in NO_PROMOTION_AGENTS, "DELEGATE must be structurally no-promotion (like ENVOY)"
    s = _store()
    assert PromotionPolicy(s, owner_key=OWNER, trusted_pubkey=OP).grant("DELEGATE", "*") is None, \
        "granting DELEGATE promotion is refused"
    assert PromotionPolicy(s, trusted_pubkey=OP).is_promoted("DELEGATE", "*") is False, "DELEGATE is never promoted"


# ---- scope: deny-all origin allowlist + SSRF (private host) --------------------------------------
def test_offlist_origin_is_refused_no_request():
    s = _store()
    d, engine = _delegate(s, pages={"https://evil.example/x": (200, "<html>ok</html>")})
    queued, res = d.preview([WebStep("svc", "login", "https://evil.example/x", {"u": "vault:username"})])
    assert queued == [] and any("REFUSED" in n for n in res.notes), "an off-allowlist origin is refused"
    assert not _acts(engine), "a refused step performs no action"


def test_private_host_is_refused_ssrf():
    s = _store()
    d, engine = _delegate(s, allowed=("http://127.0.0.1",),
                          pages={"http://127.0.0.1/login": (200, "<form/>")})
    queued, res = d.preview([WebStep("svc", "login", "http://127.0.0.1/login", {"u": "vault:username"})])
    assert queued == [] and any("REFUSED" in n for n in res.notes), "a private/loopback host is refused (SSRF)"
    assert not _acts(engine)


# ---- the core approval gate: no approval → no request; approval → exactly one act ----------------
def test_unapproved_step_makes_no_request():
    s = _store()
    d, engine = _delegate(s)
    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup",
                                   {"user": "vault:username", "pw": "vault:password"})])
    assert len(queued) == 1, "the login step queues (A3)"
    ex = d.execute(queued[0])                          # NO approval
    assert not ex.applied and any("no verified owner approval" in n for n in ex.notes)
    assert not _acts(engine), "an unapproved step performs ZERO requests"


def test_approved_step_executes_exactly_one_act():
    s = _store()
    d, engine = _delegate(s)
    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup",
                                   {"user": "vault:username", "pw": "vault:password"})])
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
    ex = d.execute(queued[0])
    assert ex.applied, "an approved step executes"
    acts = _acts(engine)
    assert len(acts) == 1 and sorted(acts[0][2]) == ["pw", "user"], "exactly one act, carrying the field NAMES only"


def test_credential_never_on_spine_or_journal():
    s = _store()
    d, engine = _delegate(s)
    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup",
                                   {"user": "vault:username", "pw": "vault:password"})])
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
    d.execute(queued[0])
    spine_bytes = Path(s.path).read_text()
    assert SENTINEL not in spine_bytes, "the password NEVER appears in the append-only spine"
    journal_bytes = "".join(p.read_text() for p in (actor_mod._JOURNAL).glob("*.json"))
    assert SENTINEL not in journal_bytes, "the password NEVER appears in the 0700 step journal (only a vault reference)"
    assert not any(SENTINEL in str(c) for c in engine.calls), "the password NEVER appears in a recorded engine call"


# ---- blocks are surfaced, never defeated, never escalated ----------------------------------------
def test_captcha_or_403_at_preview_surfaces_and_never_queues():
    for status, html in ((403, ""), (200, "<div>Please complete the reCAPTCHA</div>"), (429, "")):
        s = _store()
        d, engine = _delegate(s, pages={f"{SVC}/signup": (status, html)})
        queued, res = d.preview([WebStep("svc", "account.create", f"{SVC}/signup", {"u": "vault:username"})])
        assert queued == [], f"a blocked page ({status}) is NOT queued for action"
        assert any("BLOCKED" in n for n in res.notes)
        assert any(r.payload.get("signal") == "web.actor.blocked" for r in s.iter_records()), "the block is surfaced"
        assert not _acts(engine), "a block is never acted on (never defeated)"


def test_block_appearing_at_execute_stops_before_acting():
    s = _store()
    d, engine = _delegate(s)                            # good page at preview
    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup", {"pw": "vault:password"})])
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
    engine.pages[f"{SVC}/signup"] = (403, "")           # the site starts blocking AFTER approval
    ex = d.execute(queued[0])
    assert not ex.applied and any("BLOCKED at execute" in n for n in ex.notes)
    assert not _acts(engine), "a block detected at execute stops before any action"


# ---- TOCTOU: a changed page OR a rotated credential invalidates the approval ----------------------
def test_page_change_between_approval_and_execute_aborts():
    s = _store()
    d, engine = _delegate(s)
    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup", {"pw": "vault:password"})])
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
    engine.pages[f"{SVC}/signup"] = (200, "<form>DIFFERENT PAGE</form>")   # page changed
    ex = d.execute(queued[0])
    assert not ex.applied and any("token mismatch" in n for n in ex.notes), "a page change aborts (anti-TOCTOU)"
    assert not _acts(engine)


def test_credential_rotation_between_approval_and_execute_aborts():
    s = _store()
    v = _vault()
    d, engine = _delegate(s, vault=v)
    queued, _ = d.preview([WebStep("svc", "login", f"{SVC}/signup", {"pw": "vault:password"})])
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(queued[0])
    v.bump("svc")                                       # the owner rotated the password → version++
    ex = d.execute(queued[0])
    assert not ex.applied and any("token mismatch" in n for n in ex.notes), \
        "a credential rotation (version bump) invalidates the approval — re-approval required"
    assert not _acts(engine)


def test_approval_of_one_step_cannot_authorize_another():
    s = _store()
    d, engine = _delegate(s)
    step = WebStep("svc", "login", f"{SVC}/signup", {"pw": "vault:password"})
    queued, _ = d.preview([step, step])                # two identical steps → seqs A and B (same token)
    a, b = queued
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(a)
    assert not d.execute(b).applied, "an approval bound to seq A cannot authorize seq B (replay refused)"
    assert not _acts(engine), "the replayed step performs no action"
    assert d.execute(a).applied and len(_acts(engine)) == 1, "the genuinely-approved step executes once"


# ---- mass-creation is out of doctrine: per-service cap -------------------------------------------
def test_per_service_creation_cap():
    s = _store()
    d, engine = _delegate(s, cap=1)
    q1, _ = d.preview([WebStep("svc", "account.create", f"{SVC}/signup", {"u": "vault:username"})])
    ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OP).approve(q1[0])
    assert d.execute(q1[0]).applied, "the first account.create is allowed"
    q2, res = d.preview([WebStep("svc", "account.create", f"{SVC}/signup", {"u": "vault:username"})])
    assert q2 == [] and any("creation cap" in n for n in res.notes), "a second account.create is refused (cap=1)"


# ---- construction: the actor has NO browser/escalation path (block-before-escalate is vacuous) ---
def test_actor_has_no_browser_escalation_path():
    src = Path(actor_mod.__file__).read_text()
    # no browser/JS-render/escalation call path (impersonation is covered structurally by the field test)
    for banned in ("BrowserEngine", "needs_js", "playwright", "escalate", ".act(", "import subprocess"):
        if banned == ".act(":
            assert src.count(".act(") == 1, "exactly one engine.act call site (the single, gated action)"
            continue
        assert banned not in src, f"the actor must contain no {banned!r} path (HTTP-only, no evasion surface)"


# ---- the REAL HttpEngine independently refuses a private host (defense-in-depth below ActorScope) --
def test_real_http_engine_refuses_private_host_act():
    from sigil.agents.web_engine import HttpEngine
    out = HttpEngine().act({"url": "http://127.0.0.1/login", "kind": "login"}, {"pw": SENTINEL})
    assert out.get("ok") is False and out.get("reason") == "ssrf-refused", \
        "the real engine's own _vetted_ip gate refuses a loopback POST — no egress even if scope were bypassed"


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
    print(f"{passed}/{len(fns)} Phase-8 WS-G (DELEGATE) doctrine guarantees hold")
