"""integrity_verifier — continuously verify the integrity property the product exists to guarantee.

The whole thesis of this system is a tamper-evident, anti-rollback, signed spine hash-chain. Nothing,
until now, checked that property BETWEEN manual `vigil verify` / `sigil verify` runs: a broken chain link,
a replayed stale head, a rolled-back anti-rollback floor, or a skewed clock could sit undetected until the
next human ran a verify by hand. This module closes that gap with:

  * :func:`verify_integrity` — a per-check integrity audit of a spine home (chain integrity, signed-head
    freshness, anti-rollback floor, clock skew, vault/key state, disk space). Reads ONLY inert on-disk
    bytes; boundary-safe.
  * :func:`run_integrity_monitor` — an OPT-IN periodic loop (injectable cadence) that runs the audit, writes
    a heartbeat, and raises an ALARM on any integrity failure. A missing/stale heartbeat is itself an alarm
    (dead-man semantics), so the verifier's own failure to run is detectable.

FATAL-2 (the two-env boundary): this module is the OFFENSE/integration plane. It NEVER imports `sigil` or
the `framework`. It verifies the SOVEREIGN spine by reading its on-disk artifacts (`spine.jsonl`,
`head.json`, `floor.json`) as INERT bytes — exactly as `doctor` reads the sovereign vault — and reuses ONLY
`vigil_core` (the shared integrity substrate imported by both planes). It holds no owner private key.

HONEST SCOPE (do NOT overclaim — mirrors `sigil.spine.store.verify`'s own §): the chain + binding checks are
UNKEYED sha-256 checks. They catch corruption, a naive field/payload tamper, a delete/reorder/truncate, a
replayed stale head, and a floor rolled back below the head. They do NOT by themselves prove AUTHENTICITY
against a writer who can recompute digests AND re-sign the head — that requires verifying the owner-SIGNED
head under a PINNED trusted key, which this verifier does ONLY when such a key is supplied (`head_trust_root`
/ `head_pubkey`); without it the head is reported ``signature_checked=False`` (structurally consistent, not
authenticity-proven). The continuous check is DETECTION between manual runs, not a replacement for the signed
verify.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from vigil_core import ChainEntry, SignedChainHead, TrustRoot, digest_payload, verify_chain, verify_head
from vigil_core.models import _GENESIS_PREV

# ── check statuses ────────────────────────────────────────────────────────────────────────────────────
OK = "ok"                 # the property holds
FAIL = "fail"             # the property is VIOLATED — an integrity break (flips overall ok False → alarm)
WARN = "warn"             # advisory (e.g. an idle head, low disk) — does NOT flip ok
ABSENT = "absent"         # nothing to verify (a fresh install / never-written spine) — NOT a failure
UNKNOWN = "unknown"       # the check could not run (unreadable/malformed input) — treated fail-SOFT

# Only FAIL flips the overall verdict. UNKNOWN is deliberately NOT a hard fail on the read path (a probe
# that cannot complete on a fresh box must not brick doctor/readyz), but the monitor still surfaces it.
_HARD = {FAIL}

# ── thresholds (env-overridable, fail-closed defaults) ──────────────────────────────────────────────────
# Head recency: a head file not refreshed in this long is WARNed (idle), NOT failed — a quiet system
# legitimately holds an old head. The FAIL for a "stale head" is the STRUCTURAL check (a replayed old head
# that no longer anchors the current spine), which needs no wall clock.
_MAX_HEAD_AGE_S_ENV = "VIGIL_INTEGRITY_MAX_HEAD_AGE_S"
_DEFAULT_MAX_HEAD_AGE_S = 24 * 3600
# Clock skew tolerance: a record dated in the future by more than this, or a supplied trusted reference clock
# diverging from the local clock by more than this, is a FAIL (a skewed clock corrupts every freshness bound).
_MAX_CLOCK_SKEW_S_ENV = "VIGIL_INTEGRITY_MAX_CLOCK_SKEW_S"
_DEFAULT_MAX_CLOCK_SKEW_S = 300
# Disk: below WARN → advisory; below CRITICAL → FAIL (an append that cannot fsync corrupts the spine tail).
_MIN_DISK_WARN_ENV = "VIGIL_INTEGRITY_MIN_DISK_WARN_BYTES"
_DEFAULT_MIN_DISK_WARN = 100 * 1024 * 1024        # 100 MiB
_MIN_DISK_CRIT_ENV = "VIGIL_INTEGRITY_MIN_DISK_CRIT_BYTES"
_DEFAULT_MIN_DISK_CRIT = 10 * 1024 * 1024         # 10 MiB
# Heartbeat staleness (dead-man): a heartbeat older than this — or absent — means the periodic verifier is
# not running, which is itself alarmed.
_MAX_HEARTBEAT_STALENESS_S_ENV = "VIGIL_INTEGRITY_MAX_HEARTBEAT_STALENESS_S"
_DEFAULT_MAX_HEARTBEAT_STALENESS_S = 3600

# On-disk artifact names (mirror sigil.config; read as inert bytes, sigil is NEVER imported — FATAL-2).
_SPINE_FILE = "spine.jsonl"
_HEAD_FILE = "head.json"
_FLOOR_FILE = "floor.json"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
        return v if v >= 0 else default
    except ValueError:
        return default


# ── verdict types ───────────────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class CheckVerdict:
    """One integrity check's result. ``status`` is one of OK/FAIL/WARN/ABSENT/UNKNOWN. Only FAIL is an
    integrity VIOLATION (flips the overall verdict and raises an alarm)."""
    check: str
    status: str
    detail: str

    @property
    def failed(self) -> bool:
        return self.status in _HARD


@dataclass(frozen=True)
class IntegrityReport:
    """The aggregate integrity audit of one spine home. ``ok`` is True IFF no check FAILED."""
    home: str
    checks: tuple[CheckVerdict, ...]
    generated_at: str

    @property
    def ok(self) -> bool:
        return not any(c.failed for c in self.checks)

    @property
    def failures(self) -> tuple[CheckVerdict, ...]:
        return tuple(c for c in self.checks if c.failed)

    def get(self, name: str) -> Optional[CheckVerdict]:
        for c in self.checks:
            if c.check == name:
                return c
        return None

    def to_dict(self) -> dict:
        return {
            "home": self.home,
            "ok": self.ok,
            "generated_at": self.generated_at,
            "checks": [{"check": c.check, "status": c.status, "detail": c.detail} for c in self.checks],
        }


# ── spine reading (inert bytes only) ────────────────────────────────────────────────────────────────────
def _read_records(spine_path: Path) -> list[dict]:
    """Parse the newline-delimited spine into record dicts. Mirrors the store's torn-tail tolerance: the
    final split element (an empty-clean or partial tail) is dropped; a non-JSON / non-object line raises so
    the chain check reports it rather than silently skipping (a skipped tamper is worse than a hard fail)."""
    with open(spine_path, encoding="utf-8") as fh:
        content = fh.read()
    if not content:
        return []
    out: list[dict] = []
    for chunk in content.split("\n")[:-1]:      # drop the final (empty-clean or torn) element, like the store
        if not chunk:
            continue
        obj = json.loads(chunk)                 # a malformed line → JSONDecodeError → caught by the caller
        if not isinstance(obj, dict):
            raise ValueError("spine line is not a JSON object")
        out.append(obj)
    return out


def _load_head(head_path: Path) -> Optional[SignedChainHead]:
    if not head_path.exists():
        return None
    with open(head_path, encoding="utf-8") as fh:
        return SignedChainHead.model_validate_json(fh.read())


def _load_floor(floor_path: Path) -> Optional[dict]:
    if not floor_path.exists():
        return None
    with open(floor_path, encoding="utf-8") as fh:
        obj = json.loads(fh.read())
    return obj if isinstance(obj, dict) else None


def _parse_ts(ts: str) -> Optional[float]:
    """An ISO-8601 record ``ts`` → unix seconds; None if unparseable. Never raises."""
    if not ts:
        return None
    try:
        s = ts.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


# ── the individual checks ───────────────────────────────────────────────────────────────────────────────
def _check_chain(records: list[dict], head: Optional[SignedChainHead]) -> CheckVerdict:
    """Chain integrity: every record's payload still binds to its ``cert_digest`` (catches a field/payload
    edit), and the entries link cleanly under the correct genesis-prev (catches a delete/reorder/truncate/
    entry-hash tamper). For a pruned live window the genesis-prev is the head's ``base_prev_hash`` so a
    legitimately re-based window is NOT false-alarmed."""
    if not records:
        return CheckVerdict("chain", ABSENT, "no spine records to verify")
    entries: list[ChainEntry] = []
    for r in records:
        try:
            content = {
                "scope": r["scope"], "kind": r["kind"], "source": r["source"], "actor": r["actor"],
                "payload": r.get("payload") or {}, "parent_id": r.get("parent_id"),
                "supersedes_id": r.get("supersedes_id"),
            }
            if digest_payload(content) != r["cert_digest"]:
                return CheckVerdict("chain", FAIL,
                                    f"binding break at seq {r.get('seq')}: payload does not match cert_digest "
                                    f"(record tampered)")
            entries.append(ChainEntry(seq=r["seq"], prev_hash=r["prev_hash"],
                                      cert_digest=r["cert_digest"], entry_hash=r["entry_hash"]))
        except (KeyError, TypeError) as exc:
            return CheckVerdict("chain", FAIL, f"malformed record near seq {r.get('seq')}: {exc}")
    genesis_prev = head.base_prev_hash if (head is not None and head.base_seq > 0) else _GENESIS_PREV
    ok, reason = verify_chain(entries, genesis_prev=genesis_prev)
    if not ok:
        return CheckVerdict("chain", FAIL, reason)
    return CheckVerdict("chain", OK, f"{reason} (unkeyed binding + linkage)")


def _check_head_freshness(records: list[dict], head: Optional[SignedChainHead], *, now: float,
                          max_head_age_s: int, head_mtime: Optional[float],
                          head_trust_root: Optional[TrustRoot]) -> CheckVerdict:
    """Signed-head freshness. FAILs on the STRUCTURAL stale-head signals (deterministic, no wall clock):
      * a spine exists but no head anchors it (unanchored);
      * the head does not anchor the CURRENT spine — a replayed OLD head over a longer spine, or a truncated
        spine under a newer head (``head_hash``/``last_seq``/``entry_count`` mismatch);
      * if a pinned ``head_trust_root`` is supplied, the head signature must verify under it (authenticity).
    WARNs (advisory, not a failure) when the head anchors the spine correctly but the file has not been
    refreshed within ``max_head_age_s`` (an idle system)."""
    if head is None:
        if records:
            return CheckVerdict("head_freshness", FAIL,
                                "spine has records but NO signed head anchors it (unanchored — a head "
                                "rollback/removal, or an un-anchored write)")
        return CheckVerdict("head_freshness", ABSENT, "no head and no records (fresh/never-written spine)")

    # Structural consistency: the head must anchor the CURRENT spine tail. A replayed OLD head (lower
    # last_seq than the real tail) or a truncated spine (fewer records than the head commits) fails here.
    try:
        entries = [ChainEntry(seq=r["seq"], prev_hash=r["prev_hash"], cert_digest=r["cert_digest"],
                              entry_hash=r["entry_hash"]) for r in records]
    except (KeyError, TypeError) as exc:
        return CheckVerdict("head_freshness", FAIL,
                            f"a spine record is missing chain fields ({exc}) — cannot anchor the head")
    exp_hash = entries[-1].entry_hash if entries else (head.base_prev_hash or _GENESIS_PREV)
    exp_seq = entries[-1].seq if entries else head.base_seq
    if head.head_hash != exp_hash or head.last_seq != exp_seq \
            or head.entry_count != head.base_count + len(entries):
        return CheckVerdict("head_freshness", FAIL,
                            f"STALE HEAD: the signed head (last_seq={head.last_seq}, "
                            f"entry_count={head.entry_count}) does not anchor the current spine "
                            f"(tail seq={exp_seq}, records={len(entries)}) — a replayed old head or a "
                            f"truncated spine")

    if head_trust_root is not None:
        ok, reason = verify_head(head, entries, head_trust_root, genesis_prev=(
            head.base_prev_hash if head.base_seq > 0 else _GENESIS_PREV))
        if not ok:
            return CheckVerdict("head_freshness", FAIL, f"head does not verify under the pinned trust root: {reason}")

    # Wall-clock recency — advisory only. Prefer the newest record ts; fall back to the head file mtime.
    newest_ts = None
    for r in reversed(records):
        newest_ts = _parse_ts(str(r.get("ts", "")))
        if newest_ts is not None:
            break
    ref = newest_ts if newest_ts is not None else head_mtime
    signed_note = "signature VERIFIED under pinned key" if head_trust_root is not None \
        else "signature NOT checked (no pinned key — structural consistency only)"
    if ref is not None and (now - ref) > max_head_age_s:
        age_h = (now - ref) / 3600.0
        return CheckVerdict("head_freshness", WARN,
                            f"head anchors the spine, but the newest activity is {age_h:.1f}h old "
                            f"(> {max_head_age_s / 3600.0:.1f}h) — idle, not tampered; {signed_note}")
    return CheckVerdict("head_freshness", OK,
                        f"head anchors the current spine (last_seq={head.last_seq}); {signed_note}")


def _check_floor(head: Optional[SignedChainHead], floor: Optional[dict],
                 prev_highwater: Optional[dict]) -> CheckVerdict:
    """Anti-rollback floor. The durable floor's monotonic {last_seq, entry_count} is a watermark the spine
    may never drop below. FAILs when the head has ROLLED BACK below the floor (``head.last_seq <
    floor.last_seq``), or when the floor itself rolled back below a height the verifier has already SEEN
    (``prev_highwater`` — the monitor's own retained watermark, which catches a co-rewrite of head+floor
    together that a same-disk read would otherwise miss)."""
    def _int(d: Optional[dict], k: str) -> Optional[int]:
        if not isinstance(d, dict) or d.get(k) is None:
            return None
        try:
            return int(d[k])
        except (TypeError, ValueError):
            return None

    floor_seq = _int(floor, "last_seq")
    floor_count = _int(floor, "entry_count")
    if floor is None:
        # No floor present. Only alarm if we have previously SEEN one (a strip/delete of a known floor).
        if prev_highwater is not None and (_int(prev_highwater, "last_seq") or 0) > 0:
            return CheckVerdict("floor", FAIL,
                                f"FLOOR STRIPPED: no floor.json present, but the verifier retained a "
                                f"high-water at last_seq={_int(prev_highwater, 'last_seq')} — the floor was "
                                f"removed below a height it was seen at")
        return CheckVerdict("floor", ABSENT, "no durable anti-rollback floor present (pre-floor spine)")

    # Head rolled back below the floor: the spine's head is BELOW a height the durable floor already committed.
    if head is not None and floor_seq is not None and head.last_seq < floor_seq:
        return CheckVerdict("floor", FAIL,
                            f"FLOOR ROLLBACK: head last_seq={head.last_seq} < floor last_seq={floor_seq} — the "
                            f"spine was rolled back below the durable anti-rollback floor")
    if head is not None and floor_count is not None and head.entry_count < floor_count:
        return CheckVerdict("floor", FAIL,
                            f"FLOOR ROLLBACK: head entry_count={head.entry_count} < floor entry_count="
                            f"{floor_count} — the spine was rolled back below the durable floor")

    # The floor itself dropped below a height the verifier already retained (a co-rewrite of head+floor).
    if prev_highwater is not None and floor_seq is not None:
        prev_seq = _int(prev_highwater, "last_seq")
        if prev_seq is not None and floor_seq < prev_seq:
            return CheckVerdict("floor", FAIL,
                                f"FLOOR ROLLBACK: floor last_seq={floor_seq} < the verifier's retained "
                                f"high-water {prev_seq} — the floor was rolled back below a seen height")
    return CheckVerdict("floor", OK,
                        f"durable floor at last_seq={floor_seq} — head at/above it (no rollback below the floor)")


def _check_clock_skew(records: list[dict], *, now: float, trusted_now: Optional[float],
                      max_skew_s: int) -> CheckVerdict:
    """Clock skew. FAILs when the newest record is dated in the FUTURE beyond tolerance (the writer's clock
    ran ahead — a skewed clock corrupts every freshness/expiry bound), or when a supplied TRUSTED reference
    clock (``trusted_now``, e.g. an off-box witnessed-anchor timestamp or an NTP probe) diverges from the
    local clock by more than tolerance."""
    if trusted_now is not None and abs(now - trusted_now) > max_skew_s:
        return CheckVerdict("clock_skew", FAIL,
                            f"CLOCK SKEW: local clock diverges from the trusted reference by "
                            f"{abs(now - trusted_now):.0f}s (> {max_skew_s}s tolerance)")
    newest_ts = None
    for r in reversed(records):
        newest_ts = _parse_ts(str(r.get("ts", "")))
        if newest_ts is not None:
            break
    if newest_ts is not None and (newest_ts - now) > max_skew_s:
        return CheckVerdict("clock_skew", FAIL,
                            f"CLOCK SKEW: the newest spine record is dated {newest_ts - now:.0f}s in the "
                            f"FUTURE (> {max_skew_s}s tolerance) — a skewed writer clock")
    return CheckVerdict("clock_skew", OK,
                        f"no clock skew beyond {max_skew_s}s"
                        + ("" if trusted_now is None else " (checked against a trusted reference)"))


def _check_vault(home: Path) -> CheckVerdict:
    """Sovereign-plane secrets-at-rest state, read WITHOUT importing sigil (FATAL-2): the TPM-sealed KEK
    blobs under ``<home>/vault`` (SEALED) vs a plaintext ``sigil.env`` (UNPROVISIONED). Advisory (WARN when
    unprovisioned — a dev default, not an integrity break)."""
    vault = home / "vault"
    try:
        sealed = (vault / "kek.tpm.pub").is_file() and (vault / "kek.tpm.priv").is_file()
        env_plain = (home / "sigil.env").is_file()
    except OSError as exc:
        return CheckVerdict("vault", UNKNOWN, f"could not read {home}: {exc}")
    if sealed:
        return CheckVerdict("vault", OK, "TPM-sealed KEK provisioned — secrets rest as ciphertext")
    if env_plain:
        return CheckVerdict("vault", WARN, "keys plaintext (sigil.env) — run `sigil vault provision` to seal")
    return CheckVerdict("vault", ABSENT, "no owner vault provisioned yet")


def _check_disk(home: Path, *, warn: int, crit: int) -> CheckVerdict:
    """Disk headroom under the spine home. Below CRITICAL → FAIL (a spine append that cannot fsync corrupts
    the tail); below WARN → advisory."""
    probe = home
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        free = shutil.disk_usage(str(probe)).free
    except OSError as exc:
        return CheckVerdict("disk", UNKNOWN, f"could not stat {probe}: {exc}")
    mib = free / (1024 * 1024)
    if free < crit:
        return CheckVerdict("disk", FAIL,
                            f"CRITICALLY LOW DISK: {mib:.1f} MiB free (< {crit / 1024 / 1024:.0f} MiB) — a "
                            f"spine append may fail to fsync and corrupt the tail")
    if free < warn:
        return CheckVerdict("disk", WARN, f"low disk: {mib:.1f} MiB free (< {warn / 1024 / 1024:.0f} MiB)")
    return CheckVerdict("disk", OK, f"{mib:.0f} MiB free")


# ── the aggregate audit ─────────────────────────────────────────────────────────────────────────────────
def verify_integrity(
    home: str | os.PathLike,
    *,
    now: Optional[float] = None,
    trusted_now: Optional[float] = None,
    prev_highwater: Optional[dict] = None,
    head_trust_root: Optional[TrustRoot] = None,
    max_head_age_s: Optional[int] = None,
    max_clock_skew_s: Optional[int] = None,
) -> IntegrityReport:
    """Audit the integrity property of the spine home at ``home`` (default: reads ``spine.jsonl`` /
    ``head.json`` / ``floor.json`` directly beneath it). Never raises — every check fails SOFT (a malformed
    input is an UNKNOWN, not a crash) except a genuine integrity VIOLATION, which is a FAIL.

    ``now`` (unix seconds) is injectable for determinism (defaults to the wall clock). ``trusted_now`` is an
    OPTIONAL trusted reference clock for the skew check. ``prev_highwater`` is the verifier's own retained
    watermark ({last_seq, entry_count}) — supplied by the monitor to catch a co-rewritten floor. A pinned
    ``head_trust_root`` upgrades the head check from structural-consistency to signature-AUTHENTICITY."""
    home_p = Path(home).expanduser()
    now = time.time() if now is None else now
    max_head_age_s = _env_int(_MAX_HEAD_AGE_S_ENV, _DEFAULT_MAX_HEAD_AGE_S) if max_head_age_s is None else max_head_age_s
    max_clock_skew_s = _env_int(_MAX_CLOCK_SKEW_S_ENV, _DEFAULT_MAX_CLOCK_SKEW_S) if max_clock_skew_s is None else max_clock_skew_s
    warn = _env_int(_MIN_DISK_WARN_ENV, _DEFAULT_MIN_DISK_WARN)
    crit = _env_int(_MIN_DISK_CRIT_ENV, _DEFAULT_MIN_DISK_CRIT)

    spine_path = home_p / _SPINE_FILE
    head_path = home_p / _HEAD_FILE
    floor_path = home_p / _FLOOR_FILE

    # Read the inert bytes once. A malformed spine/head/floor becomes an UNKNOWN check, never a crash.
    try:
        records = _read_records(spine_path) if spine_path.exists() else []
        records_err = None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        records, records_err = [], exc
    try:
        head = _load_head(head_path)
        head_err = None
    except (OSError, ValueError) as exc:
        head, head_err = None, exc
    try:
        floor = _load_floor(floor_path)
        floor_err = None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        floor, floor_err = None, exc
    try:
        head_mtime = head_path.stat().st_mtime if head_path.exists() else None
    except OSError:
        head_mtime = None

    checks: list[CheckVerdict] = []

    # 1) chain integrity — a malformed spine is a FAIL (unparseable bytes cannot attest integrity).
    if records_err is not None:
        checks.append(CheckVerdict("chain", FAIL, f"spine unreadable/malformed: {records_err}"))
    else:
        checks.append(_check_chain(records, head))

    # 2) signed-head freshness
    if head_err is not None:
        checks.append(CheckVerdict("head_freshness", FAIL, f"head unreadable/malformed: {head_err}"))
    else:
        checks.append(_check_head_freshness(records, head, now=now, max_head_age_s=max_head_age_s,
                                            head_mtime=head_mtime, head_trust_root=head_trust_root))

    # 3) anti-rollback floor
    if floor_err is not None:
        checks.append(CheckVerdict("floor", FAIL, f"floor unreadable/malformed: {floor_err}"))
    else:
        checks.append(_check_floor(head, floor, prev_highwater))

    # 4) clock skew
    checks.append(_check_clock_skew(records, now=now, trusted_now=trusted_now, max_skew_s=max_clock_skew_s))

    # 5) vault/key state (advisory)
    checks.append(_check_vault(home_p))

    # 6) disk space
    checks.append(_check_disk(home_p, warn=warn, crit=crit))

    return IntegrityReport(home=str(home_p), checks=tuple(checks),
                           generated_at=datetime.fromtimestamp(now, timezone.utc).isoformat())


# ── the alarm path ──────────────────────────────────────────────────────────────────────────────────────
@dataclass
class Alarm:
    """One integrity alarm — a structured event a sink persists and (later, via W8-1) forwards to a notifier."""
    ts: str
    severity: str            # "critical" (an integrity VIOLATION) | "error" (the verifier itself failed to run)
    kind: str                # "integrity-violation" | "verifier-error" | "heartbeat-stale"
    home: str
    detail: str
    checks: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"ts": self.ts, "severity": self.severity, "kind": self.kind, "home": self.home,
                "detail": self.detail, "checks": self.checks}


class AlarmSink:
    """Where integrity alarms go. The default persists them to a durable JSONL log AND invokes any injectable
    callbacks (the seam W8-1 #467 wires a real notifier onto) AND logs a line to stderr. Tests pass a
    recording callback (or their own sink) to assert an alarm fired."""

    def __init__(self, log_path: Optional[str | os.PathLike] = None,
                 callbacks: Iterable[Callable[[Alarm], Any]] = (), *, echo: bool = True) -> None:
        self.log_path = Path(log_path).expanduser() if log_path else None
        self.callbacks = list(callbacks)
        self.echo = echo

    def emit(self, alarm: Alarm) -> None:
        if self.log_path is not None:
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(alarm.to_dict(), sort_keys=True) + "\n")
            except OSError:
                pass                      # a durable-log write failure must not swallow the callback/echo path
        if self.echo:
            import sys
            print(f"INTEGRITY ALARM [{alarm.severity}] {alarm.kind}: {alarm.detail}", file=sys.stderr)
        for cb in self.callbacks:
            try:
                cb(alarm)
            except Exception:             # noqa: BLE001 — one bad notifier must not silence the others
                pass


def _now_iso(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).isoformat()


def write_heartbeat(path: str | os.PathLike, *, now: float, ok: bool, report: Optional[IntegrityReport],
                    seq: int) -> None:
    """Persist a heartbeat marking that the verifier RAN at ``now`` with verdict ``ok``. A consumer
    (doctor / readyz / the dead-man check) reads this: an ABSENT or STALE heartbeat means the verifier is
    not running, which is itself alarmed."""
    p = Path(path).expanduser()
    beat = {
        "ts": _now_iso(now), "epoch": now, "ok": ok, "seq": seq,
        "failures": [c.check for c in (report.failures if report else ())],
    }
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(beat, sort_keys=True), encoding="utf-8")
        os.replace(str(tmp), str(p))       # atomic — a reader never sees a half-written heartbeat
    except OSError:
        pass


def read_heartbeat(path: str | os.PathLike) -> Optional[dict]:
    p = Path(path).expanduser()
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


def heartbeat_is_stale(path: str | os.PathLike, *, now: Optional[float] = None,
                       max_staleness_s: Optional[int] = None) -> tuple[bool, str]:
    """Dead-man check: is the periodic verifier failing to run? Returns ``(stale, detail)``. STALE (True)
    when the heartbeat is ABSENT (never ran / removed) or older than ``max_staleness_s`` (stopped running).
    Fail-CLOSED: an unreadable/undated heartbeat is treated as stale."""
    now = time.time() if now is None else now
    max_staleness_s = (_env_int(_MAX_HEARTBEAT_STALENESS_S_ENV, _DEFAULT_MAX_HEARTBEAT_STALENESS_S)
                       if max_staleness_s is None else max_staleness_s)
    beat = read_heartbeat(path)
    if beat is None:
        return True, ("no integrity-verifier heartbeat present — the continuous verifier has never run or its "
                      "heartbeat was removed (dead-man)")
    epoch = beat.get("epoch")
    if not isinstance(epoch, (int, float)):
        return True, "integrity-verifier heartbeat has no valid timestamp — treating as stale (fail-closed)"
    age = now - float(epoch)
    if age > max_staleness_s:
        return True, (f"integrity-verifier heartbeat is {age:.0f}s old (> {max_staleness_s}s) — the continuous "
                      f"verifier has stopped running (dead-man)")
    return False, f"integrity-verifier heartbeat is fresh ({age:.0f}s old)"


# ── the periodic monitor ────────────────────────────────────────────────────────────────────────────────
def _default_heartbeat_path(home: Path) -> Path:
    return home / "integrity-heartbeat.json"


def _default_alarm_log(home: Path) -> Path:
    return home / "integrity-alarms.jsonl"


def _default_highwater_path(home: Path) -> Path:
    return home / "integrity-highwater.json"


def _load_highwater(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


def _advance_highwater(path: Path, head: Optional[SignedChainHead], floor: Optional[dict]) -> None:
    """Persist the MONOTONIC max of the head/floor height seen so far — the verifier's own retained
    watermark, which lets the NEXT cycle catch a floor+head co-rewrite (a rollback below a seen height)."""
    prev = _load_highwater(path) or {}
    cur_seq = 0
    if head is not None:
        cur_seq = max(cur_seq, int(head.last_seq))
    if isinstance(floor, dict) and floor.get("last_seq") is not None:
        try:
            cur_seq = max(cur_seq, int(floor["last_seq"]))
        except (TypeError, ValueError):
            pass
    hw_seq = max(int(prev.get("last_seq", 0) or 0), cur_seq)
    cur_count = int(head.entry_count) if head is not None else 0
    hw_count = max(int(prev.get("entry_count", 0) or 0), cur_count)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"last_seq": hw_seq, "entry_count": hw_count}, sort_keys=True),
                        encoding="utf-8")
    except OSError:
        pass


def run_integrity_once(
    home: str | os.PathLike,
    *,
    sink: Optional[AlarmSink] = None,
    now: Optional[float] = None,
    trusted_now: Optional[float] = None,
    head_trust_root: Optional[TrustRoot] = None,
    heartbeat_path: Optional[str | os.PathLike] = None,
    highwater_path: Optional[str | os.PathLike] = None,
    seq: int = 0,
    verify_fn: Callable[..., IntegrityReport] = verify_integrity,
) -> IntegrityReport:
    """One monitor cycle: audit integrity (consulting the retained high-water), write a heartbeat, and — on
    any FAILURE — emit a ``critical`` integrity-violation alarm. If the audit itself CRASHES, emit a
    ``verifier-error`` alarm and still write a (failing) heartbeat, so the verifier's OWN failure is alarmed
    and the dead-man does not silently go quiet."""
    home_p = Path(home).expanduser()
    now = time.time() if now is None else now
    sink = sink or AlarmSink(log_path=_default_alarm_log(home_p))
    heartbeat_path = heartbeat_path or _default_heartbeat_path(home_p)
    highwater_path = Path(highwater_path).expanduser() if highwater_path else _default_highwater_path(home_p)
    prev_hw = _load_highwater(highwater_path)

    try:
        report = verify_fn(home_p, now=now, trusted_now=trusted_now, prev_highwater=prev_hw,
                           head_trust_root=head_trust_root)
    except Exception as exc:  # noqa: BLE001 — the verifier crashing is itself an alarmable condition
        sink.emit(Alarm(ts=_now_iso(now), severity="error", kind="verifier-error", home=str(home_p),
                        detail=f"the integrity verifier itself failed to run: {type(exc).__name__}: {exc}"))
        write_heartbeat(heartbeat_path, now=now, ok=False, report=None, seq=seq)
        raise

    write_heartbeat(heartbeat_path, now=now, ok=report.ok, report=report, seq=seq)
    if not report.ok:
        sink.emit(Alarm(
            ts=_now_iso(now), severity="critical", kind="integrity-violation", home=str(home_p),
            detail="; ".join(f"{c.check}: {c.detail}" for c in report.failures),
            checks=[{"check": c.check, "status": c.status, "detail": c.detail} for c in report.failures]))
    else:
        # Only advance the retained watermark on a CLEAN audit — never ratchet the high-water up from a state
        # we just flagged as rolled-back (that would launder the rollback into the new baseline).
        try:
            _advance_highwater(highwater_path, _load_head(home_p / _HEAD_FILE),
                               _load_floor(home_p / _FLOOR_FILE))
        except (OSError, ValueError):
            pass                          # advancing the watermark is best-effort; never fail a clean audit on it
    return report


def run_integrity_monitor(
    home: str | os.PathLike,
    *,
    cycles: int = 1,
    interval: float = 0.0,
    sleep: Callable[[float], Any] = time.sleep,
    sink: Optional[AlarmSink] = None,
    now_fn: Callable[[], float] = time.time,
    trusted_now_fn: Optional[Callable[[], float]] = None,
    head_trust_root: Optional[TrustRoot] = None,
    heartbeat_path: Optional[str | os.PathLike] = None,
    highwater_path: Optional[str | os.PathLike] = None,
    verify_fn: Callable[..., IntegrityReport] = verify_integrity,
) -> dict:
    """Run ``cycles`` monitor cycles (``cycles<=0`` ⇒ run forever) with an INJECTABLE cadence (``sleep`` /
    ``interval`` — determinism in tests) and an INJECTABLE clock (``now_fn``). Each cycle runs
    :func:`run_integrity_once`. A crashing audit emits a ``verifier-error`` alarm; the loop continues (the
    NEXT cycle re-tries) so a transient read error does not silently kill the continuous verifier — but the
    heartbeat it wrote is a FAILING one, so the dead-man still fires if the crashes persist.

    Returns a summary {cycles_run, violations, errors, last_ok}."""
    home_p = Path(home).expanduser()
    sink = sink or AlarmSink(log_path=_default_alarm_log(home_p))
    violations = 0
    errors = 0
    last_ok: Optional[bool] = None
    i = 0
    forever = cycles <= 0
    while forever or i < cycles:
        now = now_fn()
        trusted_now = trusted_now_fn() if trusted_now_fn is not None else None
        try:
            report = run_integrity_once(
                home_p, sink=sink, now=now, trusted_now=trusted_now, head_trust_root=head_trust_root,
                heartbeat_path=heartbeat_path, highwater_path=highwater_path, seq=i, verify_fn=verify_fn)
            last_ok = report.ok
            if not report.ok:
                violations += 1
        except Exception:  # noqa: BLE001 — already alarmed inside run_integrity_once; keep the loop alive
            errors += 1
            last_ok = False
        i += 1
        if forever or i < cycles:
            sleep(interval)
    return {"cycles_run": i, "violations": violations, "errors": errors, "last_ok": last_ok,
            "home": str(home_p)}


def _resolve_sigil_home() -> Path:
    """SIGIL_HOME (the sovereign spine home) — env override, else ~/.sigil. Read WITHOUT importing sigil
    (FATAL-2)."""
    return Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))


def main(argv: list[str] | None = None) -> int:
    """`vigil verify-integrity` — the continuous integrity verifier. Runs one audit by default (exit
    non-zero on any integrity FAILURE), or a bounded/unbounded watch loop with ``--watch``."""
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="vigil verify-integrity",
        description="continuously verify the spine hash-chain integrity property (chain, head, floor, clock)")
    ap.add_argument("--home", default=None,
                    help="the spine home to verify (default: $SIGIL_HOME or ~/.sigil)")
    ap.add_argument("--watch", action="store_true", help="run periodically instead of once")
    ap.add_argument("--cycles", type=int, default=0,
                    help="with --watch: number of cycles (0 = forever); ignored without --watch")
    ap.add_argument("--interval", type=float, default=300.0, help="with --watch: seconds between cycles")
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = ap.parse_args(argv)

    home = Path(args.home).expanduser() if args.home else _resolve_sigil_home()
    sink = AlarmSink(log_path=_default_alarm_log(home))

    if args.watch:
        summary = run_integrity_monitor(home, cycles=args.cycles, interval=args.interval, sink=sink)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary.get("last_ok") else 1

    report = run_integrity_once(home, sink=sink)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"integrity audit of {report.home} — {'OK' if report.ok else 'FAILED'}")
        for c in report.checks:
            mark = {OK: "OK ", FAIL: "!! ", WARN: ".. ", ABSENT: "-- ", UNKNOWN: "?? "}.get(c.status, "?? ")
            print(f"  {mark}{c.check}: {c.status} — {c.detail}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
