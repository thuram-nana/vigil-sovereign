"""finding_spool — the OFFENSE-side producer of the inert-finding filesystem seam (VIGIL COMMAND P5b).

A confirmed offense finding / detection crosses to the sovereign spine as a signed, INERT JSON envelope
written to a filesystem spool the sovereign watcher drains (``sigil.inbound.spool_watcher``). There is NO
network endpoint on the cockpit — the boundary is a directory, and the only thing that crosses is bytes.

This module is deliberately DEPENDENCY-LIGHT and boundary-safe: it imports stdlib + ``inert_finding``
(which is ``vigil_core``-only) and NOTHING from ``framework`` / ``strix`` / ``sigil``. It does not build or
sign envelopes (the caller does that with the existing builders — ``KeylessOffenseWorker.emit_finding_
envelope`` for findings, ``build_detection_envelope`` for detections); it only WRITES a pre-built envelope
to the spool safely: a 0700 ``incoming/`` dir, a 0600 file, an atomic temp→rename, a content-derived name
(so re-spooling the same envelope is idempotent), and the same size cap the sovereign validator enforces.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from .inert_finding import MAX_ENVELOPE_BYTES

INCOMING = "incoming"


def incoming_dir(spool_dir: str | os.PathLike) -> Path:
    """The 0700 directory the watcher drains. Created if absent (and chmod'd — mkdir is umask-subject)."""
    d = Path(spool_dir) / INCOMING
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def spool_envelope(spool_dir: str | os.PathLike, envelope: str) -> Path:
    """Write one pre-built inert envelope into ``<spool>/incoming/`` and return the path. Fail-closed:
    refuses a non-``str`` (an envelope must be inert bytes/text, never a live object), an empty envelope,
    one over the size cap, or one that is not a JSON object — so obvious garbage never even reaches the
    watcher. The file is created 0600 via a temp+atomic-rename inside the 0700 incoming dir; the name is
    ``<sha256(envelope)[:32]>.json`` so an identical envelope re-spools idempotently (same path)."""
    if not isinstance(envelope, str):
        raise TypeError("envelope must be a str (inert JSON text), not a live object")
    if not envelope.strip():
        raise ValueError("refusing to spool an empty envelope")
    raw = envelope.encode("utf-8")
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ValueError(f"envelope exceeds {MAX_ENVELOPE_BYTES} bytes")
    try:
        obj = json.loads(envelope)
    except ValueError as exc:
        raise ValueError(f"envelope is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict) or obj.get("schema") is None:
        raise ValueError("envelope must be a JSON object carrying a 'schema' field")
    inc = incoming_dir(spool_dir)
    name = hashlib.sha256(raw).hexdigest()[:32] + ".json"
    dest = inc / name
    # temp in the same dir (atomic rename stays on one filesystem); mkstemp is 0600 already.
    fd, tmp = tempfile.mkstemp(dir=str(inc), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)             # atomic publish into the spool
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return dest
