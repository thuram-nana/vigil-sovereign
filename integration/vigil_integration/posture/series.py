"""posture.series — a signed, anti-rollback ATTESTATION SERIES of posture certificates.

Continuous re-proof turns a point-in-time posture certificate into a signed TIME-LINE: each cycle appends
the fresh certificate's digest to a hash-chained series with a governance m-of-n signed head and a durable
anti-rollback high-water floor (so a rolled-back / truncated series is refused). Built directly on the
vigil_core chain primitives (``build_chain`` / ``append_entry`` / ``sign_head`` / ``verify_head`` +
``highwater``) — sovereign-safe (vigil_core + stdlib only).

Persisted in a series directory:
  * ``ticks/<seq>.json``   — each cycle's posture certificate (canonical bytes)
  * ``chain.json``         — the ChainEntry list (seq, prev_hash, cert_digest, entry_hash)
  * ``head.json``          — the governance-signed SignedChainHead over the chain
  * ``highwater.json``     — the durable anti-rollback floor (entry_count PRIMARY, last_seq secondary)

Determinism: nothing wall-clock / rng enters the chain — a tick's cert_digest is a pure function of the
certificate bytes; the chain/head are pure functions of the digests. The freshness bound is the
certificate's own (bundle-layer) time anchor, not the chain.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from vigil_core import canonical_json, digest_payload
from vigil_core.chain import append_entry, build_chain, sign_head, verify_chain, verify_head
from vigil_core.highwater import (
    HighWaterDowngrade,
    advance_highwater,
    check_highwater,
    highwater_lock,
    load_highwater,
)
from vigil_core.models import ChainEntry, SignedChainHead, TrustRoot


class PostureSeriesError(Exception):
    """A broken / rolled-back / tampered posture series — fail-closed."""


def _paths(series_dir: str | Path):
    d = Path(series_dir).expanduser()
    return d, d / "ticks", d / "chain.json", d / "head.json", d / "highwater.json"


def posture_cert_digest(cert: dict) -> str:
    """The tick digest for a posture certificate — sha256 over its canonical bytes."""
    return "sha256:" + digest_payload(cert)


def _load_chain(chain_path: Path) -> list[ChainEntry]:
    if not chain_path.is_file():
        return []
    return [ChainEntry(**e) for e in json.loads(chain_path.read_text(encoding="utf-8"))]


def append_posture_tick(
    series_dir: str | Path,
    cert: dict,
    *,
    engagement_slug: str,
    signers: list[tuple[str, str]],
) -> SignedChainHead:
    """Append ``cert`` as the next tick: chain its digest, re-sign the head (m-of-n), and advance the
    durable anti-rollback floor — upward-only. Fail-closed: a head that would lower the high-water raises
    (a rollback/truncation is refused before anything is written)."""
    d, ticks, chain_p, head_p, hw_p = _paths(series_dir)
    ticks.mkdir(parents=True, exist_ok=True)
    with highwater_lock(hw_p):
        entries = _load_chain(chain_p)
        digest = posture_cert_digest(cert)
        if entries:
            entries.append(append_entry(entries, digest))
        else:
            entries = build_chain([digest])
        head = sign_head(entries, engagement_slug=engagement_slug, signers=signers)
        ok, reason = check_highwater(head, load_highwater(hw_p))
        if not ok:
            raise PostureSeriesError(f"posture series refuses a rollback: {reason}")
        seq = entries[-1].seq
        (ticks / f"{seq}.json").write_bytes(canonical_json(cert))
        chain_p.write_text(json.dumps([e.model_dump(mode="json") for e in entries], sort_keys=True),
                           encoding="utf-8")
        head_p.write_text(head.model_dump_json(), encoding="utf-8")
        advance_highwater(hw_p, head, _locked=True)
        return head


def verify_posture_series(series_dir: str | Path, trust_root: TrustRoot,
                          *, prev_highwater: Optional[dict] = None) -> tuple[bool, str]:
    """Verify the whole series offline: the chain links cleanly, the governance-signed head anchors it
    (m-of-n over the chain), each tick's persisted certificate re-hashes to its chain digest, and the
    durable floor is not rolled back. Fail-closed."""
    d, ticks, chain_p, head_p, hw_p = _paths(series_dir)
    if not chain_p.is_file() or not head_p.is_file():
        return False, "posture series is empty or missing chain/head"
    entries = _load_chain(chain_p)
    cok, creason = verify_chain(entries)
    if not cok:
        return False, f"chain: {creason}"
    head = SignedChainHead(**json.loads(head_p.read_text(encoding="utf-8")))
    hok, hreason = verify_head(head, entries, trust_root,
                              prev_highwater=prev_highwater if prev_highwater is not None
                              else load_highwater(hw_p))
    if not hok:
        return False, f"head: {hreason}"
    # each tick's persisted certificate must re-hash to its chain digest (the cert is what was attested)
    for e in entries:
        tp = ticks / f"{e.seq}.json"
        if not tp.is_file():
            return False, f"tick {e.seq} certificate missing"
        cert = json.loads(tp.read_text(encoding="utf-8"))
        if posture_cert_digest(cert) != e.cert_digest:
            return False, f"tick {e.seq} certificate does not match its chain digest"
    return True, f"posture series SOUND: {len(entries)} tick(s), head anchored, floor not rolled back"
