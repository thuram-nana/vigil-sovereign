"""Slice S4 — MFA (TOTP second factor) + the OPTIONAL weaker password login. Four lanes:

  * module lane (`governor.totp`, `ui.totp_replay`, `governor.accounts.hash_password`): the RFC-6238 vectors
    hold; the replay ledger is atomically single-use; scrypt round-trips and rejects a wrong password.
  * registry lane (`AccountsRegistry`): enroll_totp SEALS the secret at rest (the spine grant never carries
    the plaintext), folds through account(), and is PRESERVED across assign_role / a bearer rotation; a
    TOTP-less / pre-slice grant still verifies (the conditional core holds — mutation-checked: reverting to
    an UNCONDITIONAL totp_secret field locks the account out); set_password folds + verifies.
  * HTTP lane (`/api/login`): a login with the correct current code yields a WORKING bearer; a
    wrong / stale / replayed code is 401; a NO-TOTP account logs in exactly as before (backward-compat);
    the optional password login works and a wrong password is 401.
  * FATAL-2: the new modules import no framework/strix, and `totp.py` is pure stdlib.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:packages/core/vigil_core \
     .venv-sovereign/bin/python -m pytest tests/test_login_mfa.py -q
"""
from __future__ import annotations

import base64
import itertools
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from sigil.governor import accounts as acc
from sigil.governor import totp
from sigil.governor.accounts import (
    AccountsRegistry,
    Principal,
    hash_password,
    verify_password,
)
from sigil.governor.authn import signed_payload, verify_signed
from sigil.reuse import generate_keypair, sha256_hex
from sigil.spine.store import SpineStore
from sigil.ui.server import build_server
from sigil.ui.totp_replay import TotpReplayLedger
from vigil_core import is_sealed
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault

TOKEN = "owner-shared-token-abc123"
_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, owner):
    return AccountsRegistry(store, owner_key=owner, trusted_pubkey=owner.public_key_b64)


# ---- a fake TPM so the vault seals deterministically in-test (mirrors test_secrets_sealed) ------------
def make_fake_tpm():
    def run(argv, stdin):
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary"); return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub")
            Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b"")); return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):]); return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            return TpmResult(0, Path(flag("-c")).read_bytes())
        return TpmResult(1, b"")
    return run


# ONE provisioned fake-TPM vault for the whole module. The spine DEK + owner key are sealed under its KEK,
# so every test (registry + HTTP) shares a STABLE KEK — a per-test vault would seal the process-shared
# spine.dek under one KEK and leave a later test's vault unable to open it. Provisioned once at
# SIGIL_HOME/vault (the real owner_vault dir), then injected by the autouse fixture below.
_MODULE_VAULT = None


def _module_vault() -> Vault:
    global _MODULE_VAULT
    if _MODULE_VAULT is None:
        from sigil.config import SIGIL_HOME
        v = Vault(Path(SIGIL_HOME) / "vault", make_fake_tpm())
        if not v.enabled():
            v.provision()
        _MODULE_VAULT = v
    return _MODULE_VAULT


@pytest.fixture(autouse=True)
def _inject_shared_vault(monkeypatch):
    """Make `owner_vault()` the one provisioned fake-TPM vault for every test in this module (so at-rest
    sealing round-trips consistently: TOTP secrets, the spine DEK, and the owner key)."""
    from sigil.platform import vault as vaultmod
    monkeypatch.setattr(vaultmod, "_owner_vault", _module_vault())
    yield


# ============================== module lane ==========================================================

def test_totp_rfc6238_sha1_vectors():
    """RFC-6238 Appendix-B SHA1 test vectors (secret = ASCII '12345678901234567890', 8 digits)."""
    secret = base64.b32encode(b"12345678901234567890").decode("ascii")
    vectors = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471", 2000000000: "69279037"}
    for t, expected in vectors.items():
        step = totp.current_step(t)
        assert totp.code_for_step(secret, step, digits=8) == expected, f"vector t={t}"


def test_totp_verify_window_and_matched_step():
    secret = totp.generate_secret()
    at = 1_700_000_000.0
    step = totp.current_step(at)
    code = totp.code_now(secret, at=at)
    assert totp.verify(secret, code, at=at) == step                       # matches, returns the step
    # a code from one step ago is accepted within the ±1 window and reports THAT step
    prev = totp.code_for_step(secret, step - 1)
    assert totp.verify(secret, prev, at=at) == step - 1
    # a code two steps away is OUTSIDE the ±1 window → refused
    stale = totp.code_for_step(secret, step - 2)
    assert totp.verify(secret, stale, at=at) is None
    assert totp.verify(secret, "000000", at=at) is None                   # wrong code
    assert totp.verify(secret, "12345", at=at) is None                    # wrong length
    assert totp.verify(secret, "abcdef", at=at) is None                   # non-digit


def test_replay_ledger_is_atomic_single_use_per_step():
    led = TotpReplayLedger(tempfile.mktemp(suffix=".totp-replay"))
    assert led.consume("alice", 100) is True                              # first use wins
    assert led.consume("alice", 100) is False                             # replay of the SAME step → refused
    assert led.consume("alice", 101) is True                              # a different step is independent
    assert led.consume("bob", 100) is True                                # a different user is independent


def test_replay_ledger_sweeps_old_markers_and_stays_bounded():
    import os
    led = TotpReplayLedger(tempfile.mktemp(suffix=".totp-replay"), keep_steps=2)
    for s in range(100, 105):
        led.consume("u", s)
    # consuming step 110 sweeps markers older than 110-2=108 (i.e. 100..107) → only 110 remains
    led.consume("u", 110)
    remaining = {int(n.split("-", 1)[0]) for n in os.listdir(led.dir)}
    assert remaining == {110}, remaining


def test_password_hash_roundtrip_and_rejects_wrong_and_malformed():
    h = hash_password("correct horse battery staple")
    assert h.startswith("scrypt$") and "correct" not in h                 # self-describing, no plaintext
    assert verify_password("correct horse battery staple", h) is True
    assert verify_password("wrong password", h) is False
    assert verify_password("x", "not-a-hash") is False                    # malformed stored → fail-closed
    with pytest.raises(ValueError):
        hash_password("short")                                            # <8 chars refused


# ============================== registry lane ========================================================

def test_enroll_totp_is_sealed_at_rest_and_folds():
    owner = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("alice", "operator", bearer_token="alice-bearer-xxxxxxxxxxxx", issued_at=_issue())
    assert reg.account("alice").totp_secret is None                       # bearer-only until enrolled

    secret = totp.generate_secret()
    vault = _module_vault()
    sealed_b64 = base64.b64encode(vault.seal_secret(secret.encode(), context=acc.TOTP_SEAL_CONTEXT)).decode()
    enroll_seq = reg.enroll_totp("alice", sealed_b64, issued_at=_issue())

    # (1) the spine grant carries the SEALED blob, NEVER the plaintext secret
    grant = s.get(enroll_seq).payload
    assert "totp_secret" in grant and grant["totp_secret"] == sealed_b64
    assert secret not in json.dumps(grant), "the PLAINTEXT TOTP secret must never land on the spine"
    assert is_sealed(base64.b64decode(grant["totp_secret"])), "the stored blob must be a real vigil seal"

    # (2) it folds onto the Account, and the server can UNSEAL it to verify a live code
    a = reg.account("alice")
    assert a.totp_secret == sealed_b64 and a.role == "operator"
    recovered = vault.unseal_secret(base64.b64decode(a.totp_secret), context=acc.TOTP_SEAL_CONTEXT).decode()
    assert recovered == secret
    assert totp.verify(recovered, totp.code_now(secret)) is not None
    # the bearer still resolves (enroll preserved the credential)
    assert reg.resolve("alice-bearer-xxxxxxxxxxxx") == Principal(username="alice", role="operator")


def test_enroll_totp_preserved_across_assign_role_and_bearer_rotation():
    owner = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("bob", "viewer", bearer_token="bob-bearer-aaaaaaaaaaaa", issued_at=_issue())
    vault = _module_vault()
    sealed = base64.b64encode(vault.seal_secret(b"JBSWY3DPEHPK3PXP", context=acc.TOTP_SEAL_CONTEXT)).decode()
    reg.enroll_totp("bob", sealed, issued_at=_issue())

    reg.assign_role("bob", "operator", issued_at=_issue())                # a role change must not drop TOTP
    assert reg.account("bob").totp_secret == sealed and reg.account("bob").role == "operator"

    b2, _ = reg.mint_session_bearer("bob", issued_at=_issue())            # a bearer rotation must keep TOTP
    assert reg.resolve(b2) == Principal(username="bob", role="operator")
    assert reg.account("bob").totp_secret == sealed


def test_no_totp_account_folds_with_none_backward_compat():
    owner = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("carol", "analyst", bearer_token="carol-bearer-bbbbbbbbbb", issued_at=_issue())
    a = reg.account("carol")
    assert a.totp_secret is None and a.password_hash is None              # unenrolled → no factors
    # its create grant is byte-identical to the pre-slice form (no totp_secret/password_hash keys present)
    grant = next(r.payload for r in s.iter_records(since_seq=-1)
                 if r.payload.get("signal") == acc.SIGNAL and r.payload.get("username") == "carol")
    assert "totp_secret" not in grant and "password_hash" not in grant


def test_set_password_folds_and_verifies():
    owner = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("dave", "viewer", bearer_token="dave-bearer-cccccccccc", issued_at=_issue())
    reg.set_password("dave", "hunter2-hunter2", issued_at=_issue())
    a = reg.account("dave")
    assert a.password_hash and a.password_hash.startswith("scrypt$")
    assert verify_password("hunter2-hunter2", a.password_hash) is True
    assert verify_password("nope", a.password_hash) is False
    # the plaintext password is nowhere on the spine
    grant = next(r.payload for r in s.iter_records(since_seq=-1)
                 if r.payload.get("signal") == acc.SIGNAL and r.payload.get("password_hash"))
    assert "hunter2-hunter2" not in json.dumps(grant)


# ---- conditional-core / no-lockout regression (mirrors the S3 discipline) ----------------------------

def test_a_preslice_totpless_grant_still_verifies_and_the_conditional_core_is_load_bearing(monkeypatch):
    """A grant with the OLD 7-field core (no totp_secret / password_hash) must still verify and resolve.
    MUTATION: reverting `_core_fields` to an UNCONDITIONAL `+ ("totp_secret",)` appends `"totp_secret":null`
    to the canonical bytes and BREAKS that pre-slice signature — locking the account out. We prove the
    conditional is load-bearing by monkeypatching that regression IN and watching the same grant vanish."""
    owner = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    salt, bearer = "ab" * 16, "PRESLICE-BEARER-" + "z" * 16
    old_core = {"signal": acc.SIGNAL, "username": "legacy", "role": "operator",
                "cred_hash": sha256_hex((salt + bearer).encode("utf-8")), "cred_salt": salt,
                "state": "active", "issued_at": 5.0}                      # exactly the 7 pre-slice fields
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(old_core, owner), "by": "owner"})
    # under the REAL conditional core the pre-slice grant verifies and resolves
    assert reg.resolve(bearer) == Principal(username="legacy", role="operator")
    a = reg.account("legacy")
    assert a is not None and a.totp_secret is None and a.password_hash is None

    # MUTATION: make the core UNCONDITIONAL (always include totp_secret) → the 7-field signature now fails
    monkeypatch.setattr(acc, "_core_fields", lambda p: acc._BASE_CORE + ("totp_secret",))
    reg2 = _reg(s, owner)
    assert reg2.resolve(bearer) is None, "an unconditional totp_secret field must lock out the TOTP-less grant"


def test_malleability_inverse_strip_and_add_totp_both_fail_verify():
    """The inverse of a TOTP grant stays closed: STRIPPING totp_secret verifies over fewer fields → the
    larger signature fails; ADDING totp_secret to a TOTP-less grant verifies over more fields → the smaller
    signature fails. Same shape as the S3 user_pubkey malleability proof."""
    owner = generate_keypair()
    op = owner.public_key_b64
    s = _store()
    reg = _reg(s, owner)
    totpless_seq = reg.create("kl", "viewer", bearer_token="KL" * 20, issued_at=_issue())
    vault = _module_vault()
    sealed = base64.b64encode(vault.seal_secret(b"JBSWY3DPEHPK3PXP", context=acc.TOTP_SEAL_CONTEXT)).decode()
    reg.enroll_totp("kl", sealed, issued_at=_issue())

    totpless = s.get(totpless_seq).payload                                # signed over 7 (no totp_secret)
    keyed = [r.payload for r in s.iter_records(since_seq=-1)
             if r.payload.get("signal") == acc.SIGNAL and r.payload.get("totp_secret")][-1]   # signed over 8
    assert verify_signed(keyed, acc._core_fields(keyed), op) is True      # genuine TOTP grant verifies
    assert verify_signed(totpless, acc._core_fields(totpless), op) is True  # genuine TOTP-less grant verifies
    stripped = {k: v for k, v in keyed.items() if k != "totp_secret"}     # strip → verify over 7, sig was 8
    assert verify_signed(stripped, acc._core_fields(stripped), op) is False
    added = {**totpless, "totp_secret": sealed}                           # add → verify over 8, sig was 7
    assert verify_signed(added, acc._core_fields(added), op) is False


# ============================== HTTP lane ============================================================

def _serve():
    """A live server over an isolated temp spine. The autouse fixture has already made `owner_vault()` the
    shared provisioned fake-TPM vault; the owner key is created (sealed) under it in the test SIGIL_HOME, so
    TOTP secrets, the spine DEK, and the owner key all seal/unseal under one stable KEK."""
    from sigil.governor.identity import ensure_owner_keypair
    ensure_owner_keypair()                                                # owner key (sealed) in the test home
    spine = tempfile.mktemp(suffix=".jsonl")
    SpineStore(spine).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    s = build_server(token=TOKEN, port=0, spine_path=spine)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _post(port, path, body):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}",
         "Host": f"127.0.0.1:{port}", "X-SIGIL-Token": TOKEN}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _login(port, body):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}",
         "Host": f"127.0.0.1:{port}"}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/login", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _authed_get(port, path, token):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"X-SIGIL-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _enroll_totp(port, username):
    """Owner-create an account, set a password, and owner-bind a TOTP factor. Returns the base32 secret the
    provisioning URI hands back ONCE (the test plays the operator who scanned it)."""
    assert _post(port, "/api/action", {"action": "create_account", "username": username,
                                       "role": "operator"})[0] == 200
    assert _post(port, "/api/action", {"action": "set_password", "username": username,
                                       "password": "operator-pass-1"})[0] == 200
    code, d = _post(port, "/api/action", {"action": "enroll_totp", "username": username})
    assert code == 200, d
    assert "provisioning_uri" in d and d["provisioning_uri"].startswith("otpauth://totp/")
    return parse_qs(urlparse(d["provisioning_uri"]).query)["secret"][0]


def test_enroll_returns_uri_once_and_password_plus_totp_yields_working_bearer():
    s, port = _serve()
    try:
        secret = _enroll_totp(port, "otto")
        # correct current code + password → 200 + a bearer that really works downstream
        code = totp.code_now(secret)
        st, d = _login(port, {"username": "otto", "password": "operator-pass-1", "totp": code})
        assert st == 200 and d["authenticated"] is True and d["username"] == "otto"
        bearer = d["bearer"]
        assert bearer and _authed_get(port, "/api/snapshot", bearer) == 200
    finally:
        s.shutdown()


def test_wrong_stale_and_replayed_totp_are_refused():
    s, port = _serve()
    try:
        secret = _enroll_totp(port, "otto")
        # wrong code → 401
        st, d = _login(port, {"username": "otto", "password": "operator-pass-1", "totp": "000000"})
        assert st == 401 and d["authenticated"] is False
        # stale code (5 steps in the past, outside the ±1 window) → 401
        stale = totp.code_for_step(secret, totp.current_step() - 5)
        assert _login(port, {"username": "otto", "password": "operator-pass-1", "totp": stale})[0] == 401
        # correct code first succeeds, then the SAME code replayed (same step) is refused (replay guard)
        code = totp.code_now(secret)
        assert _login(port, {"username": "otto", "password": "operator-pass-1", "totp": code})[0] == 200
        st2, d2 = _login(port, {"username": "otto", "password": "operator-pass-1", "totp": code})
        assert st2 == 401 and "already used" in d2["error"]
        # a missing code for a TOTP-enrolled account is also refused
        assert _login(port, {"username": "otto", "password": "operator-pass-1"})[0] == 401
    finally:
        s.shutdown()


def test_no_totp_account_logs_in_as_before():
    """Backward-compat: an account with NO TOTP enrolled authenticates by bearer exactly as pre-S4 — no
    code required, no gate."""
    s, port = _serve()
    try:
        code, d = _post(port, "/api/action", {"action": "create_account", "username": "plain",
                                              "role": "analyst"})
        assert code == 200
        bearer = d["bearer_token"]
        st, dd = _login(port, {"token": bearer})                         # no totp field at all
        assert st == 200 and dd["authenticated"] is True and dd["username"] == "plain"
        # the owner's legacy shared token also still logs in (never TOTP-gated)
        assert _login(port, {"token": TOKEN})[0] == 200
    finally:
        s.shutdown()


def test_optional_password_login_works_and_wrong_password_is_refused():
    s, port = _serve()
    try:
        assert _post(port, "/api/action", {"action": "create_account", "username": "pete",
                                           "role": "viewer"})[0] == 200
        assert _post(port, "/api/action", {"action": "set_password", "username": "pete",
                                           "password": "s3cret-passphrase"})[0] == 200
        # correct password (no TOTP enrolled) → 200 + a working bearer
        st, d = _login(port, {"username": "pete", "password": "s3cret-passphrase"})
        assert st == 200 and d["authenticated"] is True
        assert d["bearer"] and _authed_get(port, "/api/snapshot", d["bearer"]) == 200
        # wrong password → 401
        st2, d2 = _login(port, {"username": "pete", "password": "WRONG-passphrase"})
        assert st2 == 401 and d2["authenticated"] is False
        # unknown username → same 401 (no user-enumeration signal)
        assert _login(port, {"username": "ghost", "password": "whatever-xx"})[0] == 401
    finally:
        s.shutdown()


# ============================== FATAL-2 =============================================================

def test_fatal2_new_modules_are_offense_free_and_totp_is_stdlib_only():
    import pathlib

    from sigil.reuse import assert_no_offense
    from sigil.ui import totp_replay as _tr
    assert_no_offense()                                                  # must not raise in a sovereign env
    for mod in (totp, _tr):
        src = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
        assert "import framework" not in src and "from framework" not in src
        assert "import strix" not in src and "from strix" not in src
    # totp.py is PURE stdlib — no sigil/vigil_core imports at all
    totp_src = pathlib.Path(totp.__file__).read_text(encoding="utf-8")
    assert "import sigil" not in totp_src and "from sigil" not in totp_src
    assert "import vigil_core" not in totp_src and "from vigil_core" not in totp_src
