"""learn_drain — the OFFENSE-side consumer of the K2b→K3 learn-grant seam (A2 keystone).

The REVERSE of ``spool_watcher`` (sovereign→offense instead of offense→sovereign). It drains
``<spool>/incoming/*.json`` written by the sovereign producer (``sigil.knowledge.learn_grant``), verifies
each ``learn_grant`` under the OWNER'S PUBLIC KEY (single-signer detached Ed25519 over the canonical core),
re-derives the full vulnerability lead from the OFFENSE's OWN intel by ``(slug, vuln_id)``, and runs K3
``deep_learn`` — which writes advisory FIND/DETECT/PREVENT skills, maps DETECT only onto EXISTING oracle
kinds, mints NO fact and bumps no priors.

Boundary + authority invariants (this is the ONE inert seam — treat every byte as hostile):
  * FATAL-2: this module is installed in BOTH venvs, so it imports ``framework.v2`` LAZILY (inside the drain
    step) — importing it in a sovereign context must never pull ``framework``. Verification uses ``vigil_core``
    only (no offense engine needed to check a signature). The ONLY private key material anywhere is the
    OWNER's, held sovereign-side; this side holds only the owner PUBLIC key.
  * FAIL-CLOSED: a bad/absent signature, a wrong pubkey, a non-bounded-regular-UTF-8 file, or any error →
    the file moves to ``rejected/`` and NOTHING is learned. A per-slug offense kill-switch DEFERS a grant
    (moved back to ``incoming/`` to retry after release), never silently drops it.
  * The offense re-derives the lead from ITS OWN intel — the grant is a signed POINTER, not the lead — so a
    tampered seam can at most cause an advisory skill for a CVE already in the offense's scope.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Callable, Optional

from vigil_core import IntegrityError, canonical_json, verify_one

_MAX_BYTES = 256 * 1024  # mirror the producer's envelope cap; a larger file is rejected unread
# The signed CORE fields (must match sigil.knowledge.learn_grant.GRANT_CORE_FIELDS). Reconstructing the core
# from THIS fixed list before verifying stops a hostile extra envelope field riding inside the signed bytes.
GRANT_CORE_FIELDS = ("schema", "kind", "slug", "vuln_id", "approval_seq")


def _canon(core: dict) -> bytes:
    m = canonical_json(core)
    return m if isinstance(m, bytes) else m.encode("utf-8")


def verify_grant(envelope: dict, owner_pubkey: str) -> Optional[dict]:
    """Return the verified CORE ``{schema,kind,slug,vuln_id,approval_seq}`` iff ``envelope`` carries a valid
    owner signature over exactly those fields, else None (fail-closed). Mirrors ``governor.authn.verify_signed``
    with only ``vigil_core`` — no sovereign import."""
    if not owner_pubkey or envelope.get("kind") != "learn_grant" or envelope.get("schema") != 1:
        return None
    sig = envelope.get("sig")
    if not sig or not isinstance(sig, str) or envelope.get("pubkey") != owner_pubkey:
        return None
    core = {k: envelope.get(k) for k in GRANT_CORE_FIELDS}
    try:
        if not verify_one(owner_pubkey, _canon(core), sig):
            return None
    except (IntegrityError, TypeError):
        return None                                          # malformed sig/key material → not authentic
    return core


class LearnGrantWatcher:
    """Drains a sovereign→offense learn-grant spool, verifying each grant and running K3 deep-learn."""

    def __init__(self, *, spool_dir: str | os.PathLike, owner_pubkey: str, skills_dir: str | os.PathLike,
                 now_fn: Optional[Callable[[], "object"]] = None) -> None:
        if not owner_pubkey:
            raise ValueError("owner_pubkey is required — a learn-grant cannot be verified without the owner root")
        self.owner_pubkey = owner_pubkey
        self.skills_dir = Path(skills_dir)
        self._now_fn = now_fn
        self.spool = Path(spool_dir)
        self.incoming = self.spool / "incoming"
        self.working = self.spool / "working"
        self.processed = self.spool / "processed"          # dedup ledger: <sha256> present ⇒ already learned
        self.rejected = self.spool / "rejected"
        for d in (self.incoming, self.working, self.processed, self.rejected):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    @staticmethod
    def _read_regular(path: Path) -> str:
        """Read a REGULAR file without following a symlink or blocking on a FIFO, decode UTF-8. A compromised
        producer that plants a symlink / named pipe / device / non-UTF-8 / oversized blob must never hang or
        crash the drain — every such case is normalised to OSError so the caller quarantines it."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file (symlink/FIFO/device refused)")
            if st.st_size > _MAX_BYTES:
                raise OSError(f"file exceeds {_MAX_BYTES} bytes")
            chunks, remaining = [], _MAX_BYTES + 1
            while remaining > 0:
                b = os.read(fd, remaining)
                if not b:
                    break
                chunks.append(b)
                remaining -= len(b)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        if len(data) > _MAX_BYTES:
            raise OSError(f"file exceeds {_MAX_BYTES} bytes")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OSError(f"not valid UTF-8: {exc}") from exc

    def _quarantine(self, path: Path, reason: str) -> None:
        dest = self.rejected / path.name
        try:
            os.replace(path, dest)
        except OSError:
            dest = self.rejected / (path.name + ".orphan")
        try:
            (self.rejected / (dest.name + ".reason")).write_text(reason[:2000], encoding="utf-8")
        except OSError:
            pass

    def _deep_learn(self, slug: str, vuln_id: str) -> str:
        """LAZILY reach into the offense engine, re-derive the lead from ITS intel, run deep_learn. Returns a
        status: 'learned' | 'no_lead' | 'halted'. Raises on an unexpected engine error (caller rejects)."""
        from framework.v2.authority.killswitch import KillSwitch          # lazy — FATAL-2 keeps this offense-only
        from framework.v2.knowledge_engine.cli import _vuln_leads
        from framework.v2.knowledge_engine.deeplearn import deep_learn

        if slug and KillSwitch(slug).is_tripped():
            return "halted"                                  # DEFER — retried after the operator releases STOP
        leads = _vuln_leads(slug)
        want = vuln_id.strip().upper()
        lead = next((v for v in leads if str(v.get("id", "")).upper() == want), None)
        if lead is None:
            return "no_lead"                                 # the offense intel has no such CVE (feed it first)
        now = self._now_fn() if self._now_fn is not None else __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc)
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        deep_learn(lead, skills_dir=self.skills_dir, now=now)
        return "learned"

    def drain(self) -> dict:
        """Process every file in ``incoming/`` once. Returns {learned, rejected, deduped, no_lead, halted}."""
        learned = rejected = deduped = no_lead = halted = 0
        for src in sorted(self.incoming.glob("*.json")):
            if src.name.startswith(".tmp-"):
                continue
            claimed = self.working / src.name
            try:
                os.replace(src, claimed)                     # atomic CLAIM out of incoming/
            except OSError:
                continue
            try:
                text = self._read_regular(claimed)
            except OSError as exc:
                self._quarantine(claimed, f"unreadable / not a bounded regular UTF-8 file: {exc}")
                rejected += 1
                continue
            marker = self.processed / (hashlib.sha256(text.encode("utf-8")).hexdigest() + ".json")
            if marker.exists():
                try:
                    os.replace(claimed, marker)
                except OSError:
                    self._safe_unlink(claimed)
                deduped += 1
                continue
            try:
                envelope = json.loads(text)
            except ValueError as exc:
                self._quarantine(claimed, f"not valid JSON: {exc}")
                rejected += 1
                continue
            core = verify_grant(envelope, self.owner_pubkey) if isinstance(envelope, dict) else None
            if core is None:
                self._quarantine(claimed, "learn_grant failed owner-signature verification (fail-closed)")
                rejected += 1
                continue
            slug, vuln_id = str(core.get("slug") or ""), str(core.get("vuln_id") or "")
            if not vuln_id:
                self._quarantine(claimed, "learn_grant has no vuln_id")
                rejected += 1
                continue
            try:
                status = self._deep_learn(slug, vuln_id)
            except Exception as exc:  # noqa: BLE001 — any engine error is a refusal, never a partial learn
                self._quarantine(claimed, f"deep_learn failed ({type(exc).__name__}): {exc}")
                rejected += 1
                continue
            if status == "halted":
                try:
                    os.replace(claimed, self.incoming / src.name)   # un-claim → retry after STOP is released
                except OSError:
                    pass
                halted += 1
                continue
            # 'learned' or 'no_lead' are both TERMINAL — archive to the dedup marker so we never re-run.
            try:
                os.replace(claimed, marker)
            except OSError:
                self._safe_unlink(claimed)
            if status == "learned":
                learned += 1
            else:
                no_lead += 1
        return {"learned": learned, "rejected": rejected, "deduped": deduped,
                "no_lead": no_lead, "halted": halted}

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def watch(self, *, interval: float = 2.0, sleep: Callable[[float], None] = None) -> None:
        """Drain in a loop forever (Ctrl-C / SIGTERM to stop). ``sleep`` is injectable for tests."""
        import time
        _sleep = sleep or time.sleep
        while True:
            self.drain()
            _sleep(interval)
