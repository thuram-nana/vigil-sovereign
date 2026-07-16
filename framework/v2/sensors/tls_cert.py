"""sensors.tls_cert — ingest operator-supplied X.509 certificate(s) into weak-crypto posture LEADS.

The capture feed that makes the weak-crypto-artifact oracle (``verify.weak_crypto``, shipped @865274b)
reachable in a real ``engage --fuse-sensors`` run (a ``fusion.json`` task
``{sensor: "tls_cert", args: {cert: "/path/to/cert.pem"}}``). Mirrors ``sensors.cicd.WorkflowScanSensor``
method-for-method: Tier-1, reads a LOCAL cert FILE (PEM or DER) OR a directory of ``*.pem/.crt/.cer/.der``
certs (no network — a LIVE TLS scan is a separate, ACTIVE-gated concern), parses each OFFLINE via
``verify.weak_crypto.signature_descriptors``, and mints one ``NodeKind.CONTROL`` LEAD per certificate,
keyed ``crypto:<source>:<i>``, carrying the parsed ``{signature_algorithm, oid, subject}`` descriptor. The
leads STOP here; the weak-crypto oracle re-verifies a lead to a FACT only for a cert signed with a BROKEN
hash (MD5/SHA-1 — collision-forgeable, no benign use for a cert signature). A modern SHA-256+ cert stays a
LEAD. Pure + total (a non-cert file is a non-ingestion, never a crash).
"""

from __future__ import annotations

import os

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef
from ..verify.weak_crypto import signature_descriptors
from ..worldmodel.models import NodeKind

# An operator-supplied certificate: Admiralty B2 (usually reliable / probably true), like SBOM/MobSF.
_CERT_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)
_MAX_CERTS = 500
_CERT_EXTS = (".pem", ".crt", ".cer", ".der", ".cert")


def _read_cert_files(path: str) -> list[tuple[str, bytes]]:
    """(source-name, raw-bytes) for a single cert file, or every ``*.pem/.crt/.cer/.der/.cert`` under a
    directory (sorted → deterministic). Best-effort: an unreadable file is skipped, never raises."""
    out: list[tuple[str, bytes]] = []
    try:
        if os.path.isdir(path):
            names = sorted(n for n in os.listdir(path) if n.lower().endswith(_CERT_EXTS))
            paths = [(n, os.path.join(path, n)) for n in names]
        elif os.path.isfile(path):
            paths = [(os.path.basename(path), path)]
        else:
            return []
        for name, fp in paths:
            try:
                with open(fp, "rb") as fh:
                    out.append((name, fh.read()))
            except OSError:
                continue
    except OSError:
        return []
    return out


def parse_certs(path: str) -> list[dict]:
    """Parse a cert file/dir into per-certificate descriptors, each tagged with a stable ``check_id``
    (``<source>:<i>``) so the lead and its later oracle-promoted FACT land on the SAME CONTROL node. A
    PEM chain/bundle yields one descriptor per cert (so a weak-hash INTERMEDIATE is judged too).
    Deterministic; ``[]`` when nothing parses."""
    controls: list[dict] = []
    for name, raw in _read_cert_files(path):
        for i, desc in enumerate(signature_descriptors(raw)):
            d = dict(desc)
            d["source"] = name
            d["check_id"] = f"{name}:{i}"
            controls.append(d)
            if len(controls) >= _MAX_CERTS:
                return controls
    return controls


def cert_control_observations(controls: list[dict], *, seq: int, source: str = "tls_cert") -> list[Observation]:
    """Mint one ``NodeKind.CONTROL`` LEAD per certificate, keyed ``crypto:<check_id>``. The parsed
    signatureAlgorithm descriptor (the exact evidence the oracle judges) rides in ``attrs``. GROUNDING_INTEL,
    claim-keyed obs_ids (idempotent), pure."""
    out: list[Observation] = []
    seen: set[str] = set()
    for c in controls:
        cid = str(c.get("check_id") or "").strip()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        ref = EntityRef(kind=NodeKind.CONTROL, key=f"crypto:{cid}")
        attrs = {"lead": True, "unverified": True, "check_id": cid,
                 "signature_algorithm": c.get("signature_algorithm"), "oid": c.get("oid"),
                 "subject": c.get("subject"), "source": c.get("source")}
        out.append(Observation(
            obs_id=f"{source}:{seq}:{ref.node_id}||", source=source,
            source_kind=IntelSourceKind.OPERATOR_INGEST, collector=source, subject=ref,
            relation=None, object=None, attrs={k: v for k, v in attrs.items() if v not in (None, "")},
            source_reliability=_CERT_RELIABILITY, confidence=0.6, seq=seq))
    return out


class CertScanSensor:
    """Ingest operator-provided X.509 certificate(s) and mint weak-crypto posture LEADS. args:
    ``{"cert": "/path/to/cert.pem"}`` (a file or a directory of certs). Passive (Tier-1): reads local
    files, no network (a LIVE TLS scan is a separate ACTIVE-gated concern), no entitlement — kill-switch-
    gated via ``sensors.pipeline.run_sensor``. The leads STOP here; the weak-crypto oracle re-verifies a
    lead to a FACT (a broken-hash signature). Mirrors ``WorkflowScanSensor``."""

    name = "tls_cert"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path = args.get("cert") if isinstance(args, dict) else None
        if not path or not isinstance(path, str):
            return ToolResult(ok=False, note="tls_cert requires args['cert'] (a cert file or dir path)")
        if not (os.path.isfile(path) or os.path.isdir(path)):
            return ToolResult(ok=False, note=f"tls_cert: no cert file/dir at: {path}")
        controls = parse_certs(path)
        return ToolResult(ok=True, summary=f"tls_cert: {len(controls)} certificate(s)",
                          output={"controls": controls})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        controls = out.get("controls")
        if not isinstance(controls, list):
            return []
        return cert_control_observations(controls, seq=seq, source="tls_cert")

    def controls(self, result: ToolResult) -> list[dict]:
        """The retained cert descriptors for the weak-crypto oracle (``confirm_crypto_descriptor``)."""
        out = result.output or {}
        c = out.get("controls")
        return c if isinstance(c, list) else []
