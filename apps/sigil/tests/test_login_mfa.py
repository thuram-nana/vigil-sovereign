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


# ISOLATION (do NOT touch the process-shared SIGIL_HOME): this suite needs a PROVISIONED vault so TOTP
# secrets seal, but provisioning at the shared home would seal the shared spine DEK + owner key under a fake
# KEK and PERSIST that on disk — breaking a sibling suite (e.g. test_login_pop) that shares SIGIL_HOME and
# expects the unprovisioned/plaintext default. So we confine EVERY at-rest write to a per-MODULE tmp home and
# redirect the vault + the DEK path + the owner-key paths there (mirroring the safe isolation in
# test_secrets_sealed). The autouse fixture re-applies the redirects per test (monkeypatch reverts them
# after), and — crucially — the on-disk artifacts live under _MODULE_HOME, never the shared SIGIL_HOME.
_MODULE_HOME = Path(tempfile.mkdtemp(prefix="sigil-s4-mfa-home-"))   # isolated; never the shared SIGIL_HOME
_MODULE_VAULT = None


def _module_vault() -> Vault:
    global _MODULE_VAULT
    if _MODULE_VAULT is None:
        v = Vault(_MODULE_HOME / "vault", make_fake_tpm())
        if not v.enabled():
            v.provision()
        _MODULE_VAULT = v
    return _MODULE_VAULT


@pytest.fixture(autouse=True)
def _isolated_vault_and_trust_root_paths(monkeypatch):
    """Redirect the vault + spine-DEK path + owner-key paths to a per-MODULE tmp home, so this suite's
    provisioning/sealing NEVER lands in the process-shared SIGIL_HOME. `envelope.load_or_create_dek` reads
    `config.SPINE_DEK_PATH` via a function-local import, so patching it on the config module takes effect;
    `identity._PRIV/_PUB` are the owner-key files. Result: TOTP secrets, the spine DEK, and the owner key all
    seal/unseal under one stable fake KEK inside _MODULE_HOME — and a sibling suite sharing SIGIL_HOME finds
    it pristine (unprovisioned, plaintext)."""
    from sigil import config as cfg
    from sigil.governor import identity as idmod
    from sigil.platform import vault as vaultmod
    monkeypatch.setattr(vaultmod, "_owner_vault", _module_vault())
    monkeypatch.setattr(cfg, "SPINE_DEK_PATH", _MODULE_HOME / "keys" / "spine.dek")
    monkeypatch.setattr(idmod, "_PRIV", _MODULE_HOME / "keys" / "owner.priv")
    monkeypatch.setattr(idmod, "_PUB", _MODULE_HOME / "keys" / "owner.pub")
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


def test_password_login_runs_one_scrypt_on_every_branch_no_user_enumeration_timing(monkeypatch):
    """BLOCK-1 (user-enumeration TIMING oracle): the password endpoint must run ONE scrypt of equal cost
    regardless of whether the username exists / has a password — else a ~59× timing gap reveals "this account
    has password login". A short-circuit `acct is None or not acct.password_hash or not verify(...)` would skip
    scrypt entirely for the unknown / password-less branches.

    Structural proof (robust in CI vs a flaky wall-clock assertion): spy on `verify_password` and assert a
    scrypt verify runs on EVERY branch — against the DECOY hash for the unknown / password-less cases (equal
    cost), against the real hash for a real account."""
    s, port = _serve()
    try:
        from sigil.governor import accounts as accmod
        assert _post(port, "/api/action", {"action": "create_account", "username": "nopw",
                                           "role": "viewer"})[0] == 200          # exists, NO password
        assert _post(port, "/api/action", {"action": "create_account", "username": "haspw",
                                           "role": "viewer"})[0] == 200
        assert _post(port, "/api/action", {"action": "set_password", "username": "haspw",
                                           "password": "realpw-realpw"})[0] == 200

        seen: list = []
        real_vp = accmod.verify_password

        def _spy(pw, stored):
            seen.append(stored)
            return real_vp(pw, stored)

        monkeypatch.setattr(accmod, "verify_password", _spy)                     # picked up by the func-local import
        assert _login(port, {"username": "ghost-user", "password": "whatever-xx"})[0] == 401   # unknown user
        assert _login(port, {"username": "nopw", "password": "whatever-xx"})[0] == 401          # password-less
        assert _login(port, {"username": "haspw", "password": "wrong-wrong-1"})[0] == 401       # wrong password
        # a scrypt verify ran on ALL THREE branches (no short-circuit) — unknown/password-less used the DECOY
        assert len(seen) == 3, f"a scrypt verify must run on every password branch, got {seen}"
        assert seen[0] == accmod.DECOY_PASSWORD_HASH and seen[1] == accmod.DECOY_PASSWORD_HASH
        assert seen[2] != accmod.DECOY_PASSWORD_HASH                             # the real account used its hash
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


# ============================== W17-1: enrolment must not brick the bearer login gate =================
# Issue #535 — `_login`'s bearer branch called `_check_totp` UNCONDITIONALLY, but the SPA login gate posts
# `{token}` with no code, so a TOTP-enrolled account got a PERMANENT 401 on the only login path the UI can
# drive. The fix scopes the bearer branch to `require=False` (a code-less bearer login is allowed — the
# bearer is a possession credential) WITHOUT disabling the factor (a supplied code is still validated), and
# keeps the session-bootstrapping flows (PoP / password / OIDC) `require=True`. It also ships the enrolment
# path (`sigil accounts enroll-totp`) and a recovery verb (`disable-totp`).

def _create_and_enroll(port, username):
    """Owner-create an account (capturing its ONE-TIME bearer) then owner-bind a TOTP factor. Returns
    (bearer, base32-secret). No password is set — the point is a bearer-only TOTP-enrolled account, exactly
    the shape that got bricked."""
    st, d = _post(port, "/api/action", {"action": "create_account", "username": username, "role": "operator"})
    assert st == 200, d
    bearer = d["bearer_token"]
    code, e = _post(port, "/api/action", {"action": "enroll_totp", "username": username})
    assert code == 200, e
    secret = parse_qs(urlparse(e["provisioning_uri"]).query)["secret"][0]
    return bearer, secret


def test_w171_totp_enrolled_account_is_not_bricked_on_the_bearer_login_gate():
    """FAIL-BEFORE / PASS-AFTER regression (the load-bearing test). A TOTP-enrolled account logs in with
    `{token}` ONLY — exactly what the SPA gate posts — and gets a WORKING session. Reverting ONLY the bearer
    branch's `require=False` hunk (back to a default-`require=True` `_check_totp`) turns this 200 into the
    permanent 401 that was the lockout."""
    s, port = _serve()
    try:
        bearer, _secret = _create_and_enroll(port, "totty")
        st, d = _login(port, {"token": bearer})               # {token} ONLY — no code, as the SPA gate posts
        assert st == 200 and d["authenticated"] is True and d["username"] == "totty", d
        assert _authed_get(port, "/api/snapshot", bearer) == 200          # the session really works downstream
    finally:
        s.shutdown()


def test_w171_bearer_gate_is_not_a_no_op_a_supplied_wrong_code_is_still_refused():
    """NEGATIVE CONTROL (bearer branch): `require=False` lifts only the *requirement* to present a code — it
    does NOT disable the factor. A WRONG code supplied alongside the bearer is refused (so the fix is not a
    blanket bypass), while the CORRECT current code alongside the bearer is accepted."""
    s, port = _serve()
    try:
        bearer, secret = _create_and_enroll(port, "totty2")
        st, d = _login(port, {"token": bearer, "totp": "000000"})         # a code IS present, and it is wrong
        assert st == 401 and d["authenticated"] is False, d               # → refused; the gate is live
        st2, d2 = _login(port, {"token": bearer, "totp": totp.code_now(secret)})
        assert st2 == 200 and d2["authenticated"] is True, d2             # the correct code is accepted
    finally:
        s.shutdown()


def test_w171_password_flow_still_requires_totp_the_second_factor_is_not_disabled():
    """NEGATIVE CONTROL (required branch): the password login (`require=True`) still REFUSES a MISSING code
    and a WRONG code for a TOTP-enrolled account. The fix scopes only the bearer branch — it must not weaken
    the flows that bootstrap a fresh session from a first factor."""
    s, port = _serve()
    try:
        secret = _enroll_totp(port, "totty3")                            # creates account + password + TOTP
        assert _login(port, {"username": "totty3", "password": "operator-pass-1"})[0] == 401     # missing code
        assert _login(port, {"username": "totty3", "password": "operator-pass-1",
                             "totp": "000000"})[0] == 401                                          # wrong code
        st, d = _login(port, {"username": "totty3", "password": "operator-pass-1",
                              "totp": totp.code_now(secret)})
        assert st == 200 and d["authenticated"] is True, d                                         # correct code
    finally:
        s.shutdown()


def test_w171_disable_totp_removes_the_factor_recovery_path():
    """Registry lane for the NEW `disable_totp` — the documented RECOVERY path for a lost authenticator. After
    disabling, the account folds with `totp_secret` None (the factor is gone) while role + bearer + password
    are PRESERVED, and the clear grant OMITS the `totp_secret` key entirely (byte-identical to a
    never-enrolled account's core)."""
    owner = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("erin", "operator", bearer_token="erin-bearer-dddddddddd", issued_at=_issue())
    reg.set_password("erin", "erin-pass-erin", issued_at=_issue())
    vault = _module_vault()
    sealed = base64.b64encode(vault.seal_secret(b"JBSWY3DPEHPK3PXP", context=acc.TOTP_SEAL_CONTEXT)).decode()
    reg.enroll_totp("erin", sealed, issued_at=_issue())
    assert reg.account("erin").totp_secret == sealed                     # enrolled

    disable_seq = reg.disable_totp("erin", issued_at=_issue())
    a = reg.account("erin")
    assert a is not None and a.totp_secret is None                       # the factor is GONE (recovered)
    assert a.role == "operator"                                          # role preserved
    assert a.password_hash and verify_password("erin-pass-erin", a.password_hash)   # password preserved
    assert reg.resolve("erin-bearer-dddddddddd") == Principal(username="erin", role="operator")  # bearer kept
    grant = s.get(disable_seq).payload
    assert "totp_secret" not in grant                                    # a clear grant OMITS the key


def test_w171_cli_accounts_enroll_and_disable_totp_verbs(monkeypatch):
    """CLI lane — `sigil accounts enroll-totp <user>` binds a sealed TOTP factor (folds with `totp_secret`
    set) and `sigil accounts disable-totp <user>` removes it (folds back to None). The owner vault + key are
    the module's isolated fake-TPM instances (autouse fixture); the spine is an isolated temp store so the
    shared SIGIL_HOME is never touched. The account is seeded at a LOW `issued_at` so the CLI's wall-clock
    enrolment always clears the anti-replay high-water (timing-robust, no sleeps)."""
    from types import SimpleNamespace

    from sigil import cli
    from sigil.governor.identity import ensure_owner_keypair
    owner = ensure_owner_keypair()                                       # module-home key (autouse fixture)
    spine = tempfile.mktemp(suffix=".jsonl")
    store = SpineStore(spine)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)        # cmd_accounts' SpineStore() → this store
    reg = AccountsRegistry(store, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    reg.create("clara", "operator", bearer_token="clara-bearer-xxxxxxxx", issued_at=1.0)   # low high-water
    assert reg.account("clara") is not None and reg.account("clara").totp_secret is None

    cli.cmd_accounts(SimpleNamespace(accounts_cmd="enroll-totp", username="clara", role=None))
    assert reg.account("clara").totp_secret is not None                  # the factor is now bound + sealed
    cli.cmd_accounts(SimpleNamespace(accounts_cmd="disable-totp", username="clara", role=None))
    assert reg.account("clara").totp_secret is None                      # recovery: the factor is gone


def test_w171_doc_and_cli_verbs_are_true_of_the_code():
    """DOC-TRUTH guard: the code is the source of truth. Derive the wired accounts verbs from cli.py and the
    bearer-branch scoping from server.py, and assert docs/CLAIM-6-RBAC.md mirrors BOTH — so the doc cannot
    silently drift back to the false 'a TOTP-enrolled account must ALWAYS present a code' claim, and the named
    verbs cannot rot."""
    import re as _re
    repo = Path(__file__).resolve().parents[3]
    cli_src = (repo / "apps" / "sigil" / "sigil" / "cli.py").read_text(encoding="utf-8")
    server_src = (repo / "apps" / "sigil" / "sigil" / "ui" / "server.py").read_text(encoding="utf-8")
    doc = repo / "docs" / "CLAIM-6-RBAC.md"
    # (1) the accounts subparser actually WIRES the new verbs (code = source of truth)
    m = _re.search(r'"accounts_cmd",\s*choices=\[([^\]]*)\]', cli_src)
    assert m, "could not locate the accounts_cmd choices in cli.py"
    verbs = {v.strip().strip("\"'") for v in m.group(1).split(",") if v.strip()}
    assert {"enroll-totp", "disable-totp"} <= verbs, f"CLI must wire the TOTP verbs, got {verbs}"
    assert 'a.accounts_cmd == "enroll-totp"' in cli_src, "cmd_accounts must dispatch enroll-totp"
    assert 'a.accounts_cmd == "disable-totp"' in cli_src, "cmd_accounts must dispatch disable-totp"
    # (2) the bearer branch is scoped (require=False) — the load-bearing fix
    assert "require=False" in server_src, "the bearer branch of _login must call _check_totp(..., require=False)"
    # (3) the doc mirrors both code facts
    if doc.exists():
        text = doc.read_text(encoding="utf-8")
        assert "enroll-totp" in text and "disable-totp" in text, "doc must name the enrolment/recovery verbs"
        assert "require=False" in text, "doc must state the bearer branch is not gated (require=False)"

# ============================== W17-3: the LOGIN FIX SET — enrolment verbs + UI + unauth routes ========
# Issue #537 (builds on W17-1 #535 / W17-2 #536). W17-2 already wired the login GATE (TOTP field + SSO
# button) and the bootstrap routes through `vigil up`; W17-3 completes the ENROLMENT side: the CLI verbs
# `enroll-pubkey` / `set-password` (the TOTP verb landed in W17-1) and the Users-screen enrolment fields
# that drive the SAME owner-signed broker actions. These tests fail on a tree without the fix (the verbs /
# UI wiring / doc lines do not exist) and each carries a negative control proving the gate is not a no-op.

def test_w173_cli_accounts_enroll_pubkey_verb(monkeypatch):
    """CLI lane — `sigil accounts enroll-pubkey <user> --pubkey <b64>` owner-binds the account's Ed25519
    login key (folds with `user_pubkey` set). FAILS on a tree without the fix: the verb is not in the
    argparse choices and cmd_accounts has no branch for it. Negative control in the sibling test below."""
    from types import SimpleNamespace

    from sigil import cli
    from sigil.governor.identity import ensure_owner_keypair
    owner = ensure_owner_keypair()
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    reg = AccountsRegistry(store, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    reg.create("kayla", "operator", bearer_token="kayla-bearer-xxxxxxxx", issued_at=1.0)
    assert reg.account("kayla").user_pubkey is None
    user = generate_keypair()
    cli.cmd_accounts(SimpleNamespace(accounts_cmd="enroll-pubkey", username="kayla", role=None,
                                     pubkey=user.public_key_b64, pubkey_file=None))
    assert reg.account("kayla").user_pubkey == user.public_key_b64      # the key is now owner-bound


def test_w173_cli_enroll_pubkey_rejects_a_garbage_key_negative_control(monkeypatch):
    """NEGATIVE CONTROL — enrol is not a no-op: a malformed public key is REFUSED (fail-closed exit),
    the account is left with NO key bound (a silently-always-failing login can never be created)."""
    from types import SimpleNamespace

    from sigil import cli
    from sigil.governor.identity import ensure_owner_keypair
    owner = ensure_owner_keypair()
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    reg = AccountsRegistry(store, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    reg.create("badkey", "viewer", bearer_token="badkey-bearer-xxxxxx", issued_at=1.0)
    with pytest.raises(SystemExit):
        cli.cmd_accounts(SimpleNamespace(accounts_cmd="enroll-pubkey", username="badkey", role=None,
                                         pubkey="not-a-real-ed25519-key", pubkey_file=None))
    assert reg.account("badkey").user_pubkey is None                    # nothing bound → no broken login


def test_w173_cli_accounts_set_password_verb(monkeypatch):
    """CLI lane — `sigil accounts set-password <user>` prompts (never on argv) and owner-sets a salted
    scrypt password that verifies. FAILS on a tree without the fix (no verb/branch). Negative controls:
    a mismatch and a too-short password are both refused, leaving no password bound."""
    from types import SimpleNamespace

    from sigil import cli
    from sigil.governor.identity import ensure_owner_keypair
    owner = ensure_owner_keypair()
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    reg = AccountsRegistry(store, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    reg.create("pat", "operator", bearer_token="pat-bearer-xxxxxxxxxx", issued_at=1.0)
    assert reg.account("pat").password_hash is None

    # matching, long-enough password → set + verifies
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "operator-pass-1")
    cli.cmd_accounts(SimpleNamespace(accounts_cmd="set-password", username="pat", role=None))
    ph = reg.account("pat").password_hash
    assert ph and verify_password("operator-pass-1", ph) and not verify_password("WRONG-pass-9", ph)

    # NEGATIVE CONTROL 1 — a mismatched confirmation is refused, the existing hash is unchanged
    seq = iter(["one-password-x", "two-password-y"])
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: next(seq))
    with pytest.raises(SystemExit):
        cli.cmd_accounts(SimpleNamespace(accounts_cmd="set-password", username="pat", role=None))
    assert reg.account("pat").password_hash == ph                       # untouched by the refused attempt

    # NEGATIVE CONTROL 2 — a too-short password is refused (fail-closed on weak input)
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "short")
    with pytest.raises(SystemExit):
        cli.cmd_accounts(SimpleNamespace(accounts_cmd="set-password", username="pat", role=None))
    assert reg.account("pat").password_hash == ph


def test_w173_cli_wires_the_enrolment_verbs_and_docs_mirror_them():
    """DOC/CODE-TRUTH — derive the wired accounts verbs from cli.py (source of truth) and assert the two new
    W17-3 verbs are BOTH in the argparse choices AND dispatched, and that docs/CLAIM-6-RBAC.md names them so
    the doc cannot silently drift from the code."""
    import re as _re
    repo = Path(__file__).resolve().parents[3]
    cli_src = (repo / "apps" / "sigil" / "sigil" / "cli.py").read_text(encoding="utf-8")
    m = _re.search(r'"accounts_cmd",\s*choices=\[([^\]]*)\]', cli_src)
    assert m, "could not locate the accounts_cmd choices in cli.py"
    verbs = {v.strip().strip("\"'") for v in m.group(1).split(",") if v.strip()}
    assert {"enroll-pubkey", "set-password"} <= verbs, f"CLI must wire the W17-3 verbs, got {verbs}"
    assert 'a.accounts_cmd == "enroll-pubkey"' in cli_src, "cmd_accounts must dispatch enroll-pubkey"
    assert 'a.accounts_cmd == "set-password"' in cli_src, "cmd_accounts must dispatch set-password"
    doc = repo / "docs" / "CLAIM-6-RBAC.md"
    if doc.exists():
        text = doc.read_text(encoding="utf-8")
        assert "enroll-pubkey" in text and "set-password" in text, "doc must name the W17-3 enrolment verbs"


def test_w173_users_screen_wires_the_three_enrolment_actions():
    """UI-WIRING TRUTH — the Users & Roles screen (packages/vigil-ui/app.js) must actually POST the three
    owner-signed enrolment actions to the broker, so an operator can enrol a public key, a TOTP secret and a
    password from the UI (AC: 'from both the Users screen and the CLI'). Reading app.js as text is the same
    code-is-source-of-truth guard used by test_ui_settings.py. FAILS on a tree without the UI wiring."""
    repo = Path(__file__).resolve().parents[3]
    app_js = (repo / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
    for act in ("enroll_pubkey", "enroll_totp", "set_password"):
        assert 'action: "' + act + '"' in app_js, f"the Users screen must issue the {act} action"
    assert "usersEnrolBlock" in app_js, "usersRow must render the per-account enrolment block"
    # the stale, now-false 'per-user command-UI login is the next slice' claim must be gone (W17-2 shipped it)
    assert "next slice" not in app_js, "the false 'next slice' login claim must be removed (doc-truth)"


def test_w173_end_to_end_enrol_pubkey_and_password_then_login_over_http():
    """END-TO-END over the real HTTP server, exactly what the Users screen / CLI drive: the owner enrols a
    PUBLIC KEY and a PASSWORD on a fresh account, then that account LOGS IN with the password and gets a
    working bearer. This is the enrol-then-login flow the issue says bricks login today. Negative controls
    below: a wrong password is refused, and an UNAUTHENTICATED enrolment attempt is refused (401)."""
    s, port = _serve()
    try:
        st, d = _post(port, "/api/action", {"action": "create_account", "username": "quinn",
                                            "role": "operator"})
        assert st == 200, d
        user = generate_keypair()
        assert _post(port, "/api/action", {"action": "enroll_pubkey", "username": "quinn",
                                           "user_pubkey": user.public_key_b64})[0] == 200
        assert _post(port, "/api/action", {"action": "set_password", "username": "quinn",
                                           "password": "quinn-pass-123"})[0] == 200
        # the account now shows both factors bound in the owner's list (non-secret booleans)
        row = next(a for a in _accounts(port) if a["username"] == "quinn")
        assert row["has_pubkey"] is True and row["has_password"] is True and row["has_totp"] is False
        # LOG IN with the password → 200 + a working bearer (the enrol-then-login flow)
        st, dd = _login(port, {"username": "quinn", "password": "quinn-pass-123"})
        assert st == 200 and dd["authenticated"] is True and dd["username"] == "quinn"
        assert dd["bearer"] and _authed_get(port, "/api/snapshot", dd["bearer"]) == 200
        # NEGATIVE CONTROL 1 — a wrong password is refused (the gate is not a no-op)
        assert _login(port, {"username": "quinn", "password": "WRONG-pass-000"})[0] == 401
        # NEGATIVE CONTROL 2 — enrolment requires an authenticated, authorized caller: a POST with NO token
        # (unauthenticated) is refused by the action gate, never silently enrolling.
        assert _post_no_token(port, "/api/action", {"action": "enroll_pubkey", "username": "quinn",
                                                    "user_pubkey": user.public_key_b64})[0] in (401, 403)
    finally:
        s.shutdown()


def _accounts(port):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/accounts",
                                 headers={"X-SIGIL-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())["accounts"]


def _post_no_token(port, path, body):
    """A POST to the action plane with NO X-SIGIL-Token — the unauthenticated caller. Origin/Host are still
    set so we isolate the AUTH refusal (missing principal), not the anti-rebinding refusal."""
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}",
         "Host": f"127.0.0.1:{port}"}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, (json.loads(e.read().decode()) if e.headers.get("Content-Type", "").startswith("application/json") else {})
