"""W6-7 — the /readyz readiness surface on the posture endpoint.

/readyz runs the integrity verifier over the sovereign spine home and returns HTTP 503 when the integrity
property is VIOLATED (so an orchestrator drains a node whose spine has broken) and 200 when it holds. This
test drives the real HTTP route with an injected readiness provider and against a real spine home, and
proves the 200/503 split is not a constant (a clean home → 200, a tampered home → 503).

Boundary-safe: imports only `vigil_integration.posture.endpoint` + `vigil_integration.integrity_verifier`
(no `posture.attest`, so it stays framework-free and runs in the two-env boundary CI job).
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from vigil_core import build_chain, digest_payload, generate_keypair, sign_head

from vigil_integration import integrity_verifier as iv
from vigil_integration.posture.endpoint import serve_posture


def _build_spine(home: Path, *, n: int = 3, scope: str = "sigil", base_ts: int = 1_700_000_000) -> None:
    home.mkdir(parents=True, exist_ok=True)
    contents, digests = [], []
    for i in range(n):
        c = {"scope": scope, "kind": "message", "source": "test", "actor": "user",
             "payload": {"text": f"r{i}"}, "parent_id": None, "supersedes_id": None}
        contents.append(c); digests.append(digest_payload(c))
    entries = build_chain(digests)
    recs = []
    for i, (c, e) in enumerate(zip(contents, entries)):
        ts = datetime.fromtimestamp(base_ts + i, timezone.utc).isoformat()
        recs.append({"seq": e.seq, **c, "ts": ts, "cert_digest": e.cert_digest,
                     "prev_hash": e.prev_hash, "entry_hash": e.entry_hash})
    (home / "spine.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    owner = generate_keypair()
    head = sign_head(entries, engagement_slug=scope, signers=[("owner", owner.private_key_b64)])
    (home / "head.json").write_text(head.model_dump_json(), encoding="utf-8")
    (home / "floor.json").write_text(json.dumps(
        {"schema_version": 1, "scope": scope, "entry_count": head.entry_count, "last_seq": head.last_seq,
         "base_seq": 0, "base_count": 0, "head_sig_hash": head.head_hash}), encoding="utf-8")


def _readyz(port: int) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=10) as r:  # noqa: S310
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _serve(provider):
    srv = serve_posture("127.0.0.1", 0, ".", readyz_provider=provider)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_readyz_200_when_integrity_holds(tmp_path):
    home = tmp_path / "sigil"
    _build_spine(home)

    def provider():
        report = iv.verify_integrity(home, now=1_700_000_010)
        return report.ok, report.to_dict()

    srv = _serve(provider)
    try:
        status, body = _readyz(srv.server_address[1])
        assert status == 200 and body["ok"] is True
    finally:
        srv.shutdown(); srv.server_close()


def test_readyz_503_when_integrity_violated(tmp_path):
    """NEGATIVE CONTROL: a tampered spine flips /readyz to 503 with the failing check named — not a
    constant 200."""
    home = tmp_path / "sigil"
    _build_spine(home)
    lines = (home / "spine.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["entry_hash"] = "0" * 64; lines[1] = json.dumps(rec)
    (home / "spine.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def provider():
        report = iv.verify_integrity(home, now=1_700_000_010)
        return report.ok, report.to_dict()

    srv = _serve(provider)
    try:
        status, body = _readyz(srv.server_address[1])
        assert status == 503 and body["ok"] is False
        assert any(c["check"] == "chain" and c["status"] == iv.FAIL for c in body["checks"])
    finally:
        srv.shutdown(); srv.server_close()


def test_readyz_fail_closed_on_provider_error(tmp_path):
    """A readiness provider that raises must yield 503 (fail-closed), never 200."""
    def provider():
        raise RuntimeError("verifier blew up")

    srv = _serve(provider)
    try:
        status, body = _readyz(srv.server_address[1])
        assert status == 503 and body["ok"] is False
    finally:
        srv.shutdown(); srv.server_close()
