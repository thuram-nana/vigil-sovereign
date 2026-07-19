"""SIGIL Phase 9 W1-D — the bridge's owner-pinned self-signed TLS slice: the cert helper
(`ensure_bridge_cert`) that mints a minimal self-signed cert with the WG IP as a SubjectAlternativeName,
stores cert+key owner-only (dir 0700 / files 0600) under `SIGIL_HOME/bridge/`, and REUSES it so the
sha256 fingerprint is STABLE across restarts (the owner pins it once). Also asserts the bind guard
still refuses a public address for `bridge serve` (fail-closed, minting no cert), plus a loopback TLS
handshake smoke test proving the wrapped socket serves a real HTTPS envelope.

Deterministic by construction: `SIGIL_HOME` is redirected to a fresh temp dir per test and removed
after. No real owner identity, no network beyond loopback:0.
Run: ~/.sigil/venv/bin/python tests/test_bridge_tls.py"""
import contextlib
import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path

import sigil.config as sconfig
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from sigil.bridge.daemon import bind_ok
from sigil.bridge.server import ensure_bridge_cert


@contextlib.contextmanager
def temp_home():
    """Redirect SIGIL_HOME to a throwaway dir so `ensure_bridge_cert` (which reads
    `sigil.config.SIGIL_HOME` at call-time) writes into it, and restore + clean up after."""
    orig = sconfig.SIGIL_HOME
    d = tempfile.mkdtemp(prefix="sigil-tls-")
    sconfig.SIGIL_HOME = Path(d)
    try:
        yield Path(d)
    finally:
        sconfig.SIGIL_HOME = orig
        shutil.rmtree(d, ignore_errors=True)


# ---- the cert helper mints a usable cert+key under SIGIL_HOME/bridge/ -----------------------------
def test_ensure_bridge_cert_creates_cert_and_key():
    with temp_home() as home:
        certfile, keyfile, fp = ensure_bridge_cert("127.0.0.1")
        assert Path(certfile).is_file(), "a cert file is produced"
        assert Path(keyfile).is_file(), "a key file is produced"
        assert Path(certfile).parent == home / "bridge", "cert lives under SIGIL_HOME/bridge/"
        # fingerprint = 32 colon-grouped hex byte pairs of a sha256
        pairs = fp.split(":")
        assert len(pairs) == 32 and all(len(p) == 2 for p in pairs), \
            "fingerprint is sha256 (32 bytes) as colon-grouped hex pairs"
        assert fp == fp.upper(), "fingerprint hex is upper-case (openssl-style)"


# ---- the cert + key are owner-only (secure-file idiom) --------------------------------------------
def test_cert_files_are_owner_only():
    with temp_home():
        certfile, keyfile, _ = ensure_bridge_cert("127.0.0.1")
        assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600, "the private key is 0600"
        assert stat.S_IMODE(os.stat(certfile).st_mode) == 0o600, "the cert is 0600"
        assert stat.S_IMODE(os.stat(Path(certfile).parent).st_mode) == 0o700, "the bridge dir is 0700"


# ---- REUSE: the fingerprint is stable across restarts (pin once) ----------------------------------
def test_fingerprint_stable_across_calls_reuse_not_regenerate():
    with temp_home():
        cf1, kf1, fp1 = ensure_bridge_cert("127.0.0.1")
        key1 = Path(kf1).read_bytes()                        # capture the FIRST key material
        cf2, kf2, fp2 = ensure_bridge_cert("127.0.0.1")      # second call must REUSE, not regenerate
        assert (cf1, kf1) == (cf2, kf2), "the same cert/key paths are used for the same addr"
        assert fp1 == fp2, "the fingerprint is STABLE across calls (the owner pins it exactly once)"
        assert Path(kf2).read_bytes() == key1, "the key file was NOT regenerated (byte-identical)"


# ---- a fresh addr gets its OWN stable cert (not a shared one) -------------------------------------
def test_distinct_addr_gets_distinct_cert():
    with temp_home():
        _, _, fp_lo = ensure_bridge_cert("127.0.0.1")
        _, kf_wg, fp_wg = ensure_bridge_cert("10.7.0.2")     # a WireGuard-style private addr
        assert Path(kf_wg).is_file(), "a distinct addr mints its own cert"
        assert fp_lo != fp_wg, "different bind addresses get independent (distinct) certs"


# ---- the cert parses and carries the WG IP as a SubjectAlternativeName ----------------------------
def test_cert_parses_and_has_ip_san_and_matching_fingerprint():
    with temp_home():
        certfile, _, fp = ensure_bridge_cert("10.7.0.2")
        cert = x509.load_pem_x509_certificate(Path(certfile).read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = [str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)]
        assert "10.7.0.2" in ips, "the WG IP is a SubjectAlternativeName (x509.IPAddress)"
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "10.7.0.2", "the CN is the bind addr"
        # independently recompute the fingerprint: sha256 of the DER cert, colon-grouped upper hex
        der = cert.public_bytes(serialization.Encoding.DER)
        h = hashlib.sha256(der).hexdigest().upper()
        expect = ":".join(h[i:i + 2] for i in range(0, len(h), 2))
        assert fp == expect, "the returned fingerprint == sha256(DER cert)"


# ---- the bind guard still refuses a public addr for `bridge serve` (fail-closed, no cert) ---------
def test_bridge_serve_refuses_public_addr_and_mints_no_cert():
    assert bind_ok("127.0.0.1") is True, "loopback binds"
    assert bind_ok("10.7.0.2") is True, "a private WireGuard addr binds"
    for bad in ("0.0.0.0", "::", "8.8.8.8", "1.2.3.4"):
        assert bind_ok(bad) is False, f"a public/unspecified addr ({bad}) is refused"
    # the CLI handler fails closed on a public addr, BEFORE ensure_bridge_cert → no cert dir created
    from sigil.cli import cmd_bridge_serve

    class _Args:
        addr, port, no_tls = "8.8.8.8", 8734, False

    with temp_home() as home:
        try:
            cmd_bridge_serve(_Args())
            assert False, "cmd_bridge_serve must refuse a public bind address"
        except SystemExit as e:
            assert e.code == 2, "a refused public bind exits 2 (fail-closed)"
        assert not (home / "bridge").exists(), "no cert was minted for a refused public bind"


# ---- loopback TLS smoke: the wrapped listener serves a real HTTPS envelope ------------------------
def test_loopback_tls_handshake_serves_a_real_https_envelope():
    import json
    import ssl
    import threading
    import time
    import urllib.error
    import urllib.request

    from sigil.bridge.server import build_server
    from sigil.reuse import generate_keypair

    with temp_home():
        owner = generate_keypair()                           # inject a pubkey → never touches real owner identity
        spine = tempfile.mktemp(suffix=".jsonl")
        srv = build_server(addr="127.0.0.1", port=0, spine_path=spine,
                           trusted_pubkey=owner.public_key_b64)
        certfile, keyfile, _ = ensure_bridge_cert("127.0.0.1")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)   # exactly what serve() does
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.05)
        try:
            # a client that TRUSTS the pinned self-signed cert (CERT_REQUIRED against our cafile);
            # skip hostname matching for a robust IP-literal handshake across ssl versions.
            cctx = ssl.create_default_context(cafile=certfile)
            cctx.check_hostname = False
            req = urllib.request.Request(f"https://127.0.0.1:{port}/api/pending")
            try:
                with urllib.request.urlopen(req, timeout=5, context=cctx) as r:
                    code, body = r.status, r.read().decode()
            except urllib.error.HTTPError as e:              # 401 (no envelope) is still an HTTPS response
                code, body = e.code, e.read().decode()
            assert code == 401, "the TLS handshake completed and the server answered over HTTPS"
            assert json.loads(body).get("error"), "a valid JSON envelope was served over the pinned TLS socket"
        finally:
            srv.shutdown()
            srv.server_close()
            with contextlib.suppress(OSError):
                os.unlink(spine)


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
    print(f"{passed}/{len(fns)} Phase-9 W1-D (owner-pinned self-signed bridge TLS) guarantees hold")
