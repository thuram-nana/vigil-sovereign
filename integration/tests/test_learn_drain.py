"""A2c — the OFFENSE learn-grant consumer (`vigil_integration.learn_drain`).

Doctrine under test:
  * a grant is learned ONLY if it verifies under the OWNER public key (single-signer Ed25519 over the
    canonical core) — a forged / wrong-key / tampered / non-object grant is quarantined, never learned;
  * FATAL-2: `verify_grant` uses vigil_core only; `deep_learn` is reached lazily (monkeypatched here so the
    drain logic is exercised without importing the offense engine);
  * a hostile spool file (symlink/FIFO/oversize/non-UTF-8) is quarantined, never followed or hung on;
  * the offense per-slug kill-switch DEFERS (un-claims for retry), 'no_lead' is TERMINAL, dedup is by bytes.
"""

import hashlib
import json

from vigil_core import canonical_json, generate_keypair, sign
from vigil_integration.learn_drain import LearnGrantWatcher, verify_grant

OWNER = generate_keypair()


def _grant(owner=OWNER, slug="loopback", vuln="CVE-2024-0001", approval_seq=5, **override):
    core = {"schema": 1, "kind": "learn_grant", "slug": slug, "vuln_id": vuln, "approval_seq": approval_seq}
    m = canonical_json(core)
    m = m if isinstance(m, bytes) else m.encode("utf-8")
    env = {**core, "sig": sign(owner.private_key_b64, m), "pubkey": owner.public_key_b64}
    env.update(override)
    return env


def _write_incoming(spool, env):
    inc = spool / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(env, sort_keys=True)
    p = inc / (hashlib.sha256(raw.encode()).hexdigest()[:32] + ".json")
    p.write_text(raw, encoding="utf-8")
    return p


class _RecordingWatcher(LearnGrantWatcher):
    """Overrides the lazy `_deep_learn` so the drain logic is tested without the offense engine."""

    def __init__(self, *, status="learned", **kw):
        super().__init__(**kw)
        self._status = status
        self.calls = []

    def _deep_learn(self, slug, vuln_id):
        self.calls.append((slug, vuln_id))
        return self._status


def _watcher(tmp_path, **kw):
    return _RecordingWatcher(spool_dir=tmp_path / "spool", owner_pubkey=OWNER.public_key_b64,
                             skills_dir=tmp_path / "skills", **kw)


# ---- verify_grant: owner-signature, fail-closed ----------------------------

def test_verify_accepts_a_valid_owner_grant():
    core = verify_grant(_grant(), OWNER.public_key_b64)
    assert core and core["vuln_id"] == "CVE-2024-0001" and core["slug"] == "loopback"


def test_verify_is_fail_closed():
    assert verify_grant(_grant(), generate_keypair().public_key_b64) is None      # wrong owner key
    g = _grant(); g.pop("sig"); assert verify_grant(g, OWNER.public_key_b64) is None        # no signature
    g = _grant(); g["slug"] = "evil-scope"; assert verify_grant(g, OWNER.public_key_b64) is None  # tampered
    g = _grant(); g["kind"] = "other"; assert verify_grant(g, OWNER.public_key_b64) is None       # wrong kind
    g = _grant(); g["sig"] = 12345; assert verify_grant(g, OWNER.public_key_b64) is None          # non-str sig


# ---- drain: verify → deep-learn, fail-closed, idempotent -------------------

def test_drain_learns_a_valid_grant_and_is_idempotent(tmp_path):
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant())
    w = _watcher(tmp_path)
    r = w.drain()
    assert r["learned"] == 1 and w.calls == [("loopback", "CVE-2024-0001")]
    assert not list((spool / "incoming").glob("*.json"))          # consumed out of incoming
    _write_incoming(spool, _grant())                              # re-spool the identical grant
    r2 = w.drain()
    assert r2["deduped"] == 1 and len(w.calls) == 1               # not re-learned


def test_drain_rejects_a_forged_grant(tmp_path):
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant(owner=generate_keypair()))      # signed by a NON-owner key
    w = _watcher(tmp_path)
    r = w.drain()
    assert r["rejected"] == 1 and w.calls == []                   # never reached deep_learn
    assert list((spool / "rejected").glob("*.json"))


def test_drain_defers_on_killswitch(tmp_path):
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant())
    w = _watcher(tmp_path, status="halted")
    r = w.drain()
    assert r["halted"] == 1
    assert list((spool / "incoming").glob("*.json"))              # un-claimed back to incoming for retry


def test_drain_no_lead_is_terminal(tmp_path):
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant())
    w = _watcher(tmp_path, status="no_lead")
    r = w.drain()
    assert r["no_lead"] == 1
    assert not list((spool / "incoming").glob("*.json"))          # archived, not retried forever


def test_drain_rejects_a_hostile_symlink(tmp_path):
    spool = tmp_path / "spool"
    inc = spool / "incoming"
    inc.mkdir(parents=True)
    (inc / "evil.json").symlink_to("/etc/passwd")                # a planted symlink must never be followed
    w = _watcher(tmp_path)
    r = w.drain()
    assert r["rejected"] == 1 and w.calls == []
