"""time_anchor — an EXTERNAL TIME ANCHOR (RFC3161) over a transparency ``Checkpoint`` (TRUTHENOVATION A1).

The witnessed, time-bounded checkpoint (:mod:`remediation.attestation_witness`) yields a *quorum-median*
"no-later-than" bound: ``T = median(τ_i)`` over the witnesses' own observed clocks. That bound is honest
but WEAK — it assumes a strict-majority-honest **signing** quorum (which a dishonest producer curates) and
bounded inter-witness skew, and it depends on witness honesty and clocks (``WITNESS-TRUST.md`` §4). The
designed, stronger fallback (``WITNESS-TRUST.md`` §5, ``transparency.py:29``) is a single, externally
trusted timestamp over ``checkpoint_hash`` — an **RFC3161 TSA token** — which yields an "existed no-later-
than genTime" that does NOT depend on witness honesty. **When present and verifiable against a pinned TSA
cert, this anchor's genTime SUPERSEDES the median bound.** This module builds that anchor.

WHAT IT BINDS
-------------
The anchor is a real RFC3161 timestamp over :func:`transparency.checkpoint_hash` — the stable, domain-
separated identity of the checkpoint (``transparency.py:97-100``). A TAMPERED checkpoint hashes to a
DIFFERENT value, so its token's message-imprint no longer matches and verification FAILS CLOSED. genTime
is read ONLY from the signature-covered ``TimeStampToken`` (extracted with ``ts -token_out``, NOT from a
text render of the whole response whose unsigned ``PKIStatusInfo`` a producer could rewrite to backdate —
see :func:`_extract_gentime_epoch`), NEVER from the verifier's wall clock.

WHY openssl (no new dependency, no hand-rolled ASN.1)
----------------------------------------------------
"Don't roll your own ASN.1" (``WITNESS-TRUST.md`` §intro). The venvs carry only ``cryptography`` (no
``pyasn1``/``rfc3161ng``/``opentimestamps``), but the system ``openssl`` binary has the ``ts`` subcommand
(present on ubuntu-latest CI runners too). We therefore MINT (``openssl ts -query`` + a TSA's
``openssl ts -reply``) and VERIFY (``openssl ts -verify`` + genTime extraction) via ``subprocess`` — a
REAL RFC3161 token that interoperates with any real third-party TSA when one is configured, with NO new
Python dependency and NO hand-parsed ASN.1.

SIDECAR — the token NEVER enters a signed chain digest
------------------------------------------------------
The token is a SIDECAR attestation attached alongside a checkpoint, not a checkpoint field: it is not in
``Checkpoint.to_dict`` (so ``checkpoint_hash`` is unchanged by anchoring), not in the timed-witness signed
bytes (``attestation_witness._timed_signing_bytes``), and not in the attestation-log tick-chain digest.
Chain determinism is therefore preserved: two runs produce byte-identical chains even though token bytes
vary with genTime.

HONEST VERDICT (TRUTHENOVATION Rule 1/3, the A2/A3 lesson) — CAPABILITY, not a VERIFIED FACT of
independence. The anchor MECHANISM is built + tested (real RFC3161 over ``checkpoint_hash``, offline-
verifiable, supersedes the median). But the DEFAULT :class:`LocalTSA` is a *self-signed local* authority:
a local TSA proves the MECHANISM only — genuine "existed no-later-than T" INDEPENDENCE requires a
THIRD-PARTY TSA (:class:`RemoteTSA`, an operator-configured RFC3161 URL) or a public OpenTimestamps/Bitcoin
calendar. Do NOT flip A1 to VERIFIED FACT for an independence property a local TSA cannot establish.

FATAL-2: sovereign-safe — this module imports ONLY stdlib + ``subprocess`` + ``..transparency`` (which is
``vigil_core``-only). No ``framework.*``, no ``strix.*``, no ``sigil`` import; ``openssl`` is an external
process, not a Python dependency.
"""
from __future__ import annotations

import datetime
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

from .transparency import Checkpoint, checkpoint_hash

_OPENSSL = "openssl"

# The openssl [tsa] config for a local self-signed TSA. Absolute paths are substituted for the cert/key/
# serial so the config is location-independent. ``ess_cert_id_alg = sha256`` is set to silence the benign
# "no value" warning openssl prints otherwise.
_TSA_CONFIG_TEMPLATE = """\
[tsa]
default_tsa = tsa_config1

[tsa_config1]
serial = {serial}
crypto_device = builtin
signer_cert = {cert}
certs = {cert}
signer_key = {key}
default_policy = 1.2.3.4.1
digests = sha256, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
signer_digest = sha256
"""


class TimeAnchorError(RuntimeError):
    """Minting / verifying an external time anchor failed (openssl error, or a freshly minted token that
    did not self-verify). Fail-closed: callers must treat this as "no anchor", never as a silent pass."""


def openssl_ts_available() -> bool:
    """True iff a usable ``openssl`` binary with the ``ts`` subcommand is on PATH. The offline test asserts
    this (it must NOT silently skip): ``openssl ts`` is present on ubuntu-latest CI runners."""
    if shutil.which(_OPENSSL) is None:
        return False
    try:
        r = subprocess.run([_OPENSSL, "ts", "-help"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    # `openssl ts -help` prints its usage to stderr and exits non-zero on some builds; the presence of the
    # ts usage banner is the reliable signal that the subcommand exists.
    return "ts [options]" in (r.stdout + r.stderr) or "Query options" in (r.stdout + r.stderr)


def _require_openssl_ts() -> None:
    if not openssl_ts_available():
        raise TimeAnchorError(
            "openssl with the `ts` subcommand is not available — cannot mint/verify an RFC3161 time anchor"
        )


def _run_openssl(args: "list[str]", *, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([_OPENSSL, *args], capture_output=True, text=True, timeout=timeout)


def _ts_query(digest_hex: str) -> bytes:
    """Build an RFC3161 time-stamp REQUEST (``.tsq``) over the sha256 ``digest_hex`` (the checkpoint hash).
    ``-cert`` asks the TSA to embed its signing certificate so the token is self-contained for verify."""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "req.tsq"
        r = _run_openssl(["ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", str(out)])
        if r.returncode != 0 or not out.exists():
            raise TimeAnchorError(f"openssl ts -query failed: {r.stderr.strip() or r.stdout.strip()}")
        return out.read_bytes()


class TSA(Protocol):
    """A Time Stamping Authority: mints an RFC3161 response (DER ``TimeStampResp`` bytes) for a request,
    and exposes the path to the PINNED cert a verifier checks the resulting token against."""

    @property
    def cert_pin(self) -> str: ...

    def mint(self, query_der: bytes) -> bytes: ...


class LocalTSA:
    """A self-signed LOCAL RFC3161 TSA — the DEFAULT anchor and the CI test authority.

    It generates (once, into ``workdir``) a self-signed EC certificate carrying the ``timeStamping`` EKU
    (with ``CA:true`` so it is its own trust anchor) plus an openssl ``[tsa]`` config, and mints tokens via
    ``openssl ts -reply``. The mint+verify roundtrip is fully self-contained and CI-deterministic in
    OUTCOME (the roundtrip always passes; only genTime, a sidecar, varies).

    HONEST RESIDUAL: a self-signed local TSA proves the MECHANISM only — it establishes no INDEPENDENCE
    (the same host mints and pins). Genuine "existed no-later-than T" independence needs :class:`RemoteTSA`
    (a third-party RFC3161 URL) or a public OpenTimestamps/Bitcoin calendar."""

    def __init__(self, workdir: "str | Path", *, common_name: str = "VIGIL Local TSA (mechanism-only)"):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.cert_path = self.workdir / "tsa.cert.pem"
        self.key_path = self.workdir / "tsa.key.pem"
        self.config_path = self.workdir / "tsa.cnf"
        self.serial_path = self.workdir / "tsa.serial"
        self._common_name = common_name
        self._ensure_material()

    @property
    def cert_pin(self) -> str:
        """Path to the self-signed TSA cert — the pin a verifier checks tokens against."""
        return str(self.cert_path)

    def _ensure_material(self) -> None:
        if self.cert_path.exists() and self.key_path.exists() and self.config_path.exists():
            return
        _require_openssl_ts()
        r = _run_openssl([
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(self.key_path), "-out", str(self.cert_path), "-days", "3650",
            "-subj", f"/CN={self._common_name}",
            "-addext", "basicConstraints=critical,CA:true",
            "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "extendedKeyUsage=critical,timeStamping",
        ])
        if r.returncode != 0 or not self.cert_path.exists():
            raise TimeAnchorError(f"local TSA cert generation failed: {r.stderr.strip()}")
        self.serial_path.write_text("01\n", encoding="ascii")
        self.config_path.write_text(
            _TSA_CONFIG_TEMPLATE.format(
                serial=self.serial_path, cert=self.cert_path, key=self.key_path
            ),
            encoding="ascii",
        )

    def mint(self, query_der: bytes) -> bytes:
        """Mint an RFC3161 token (DER ``TimeStampResp``) for ``query_der`` via ``openssl ts -reply``."""
        _require_openssl_ts()
        with tempfile.TemporaryDirectory() as td:
            req = Path(td) / "req.tsq"
            resp = Path(td) / "resp.tsr"
            req.write_bytes(query_der)
            r = _run_openssl([
                "ts", "-reply", "-config", str(self.config_path), "-section", "tsa_config1",
                "-queryfile", str(req), "-out", str(resp),
            ])
            if r.returncode != 0 or not resp.exists():
                raise TimeAnchorError(f"local TSA ts -reply failed: {r.stderr.strip() or r.stdout.strip()}")
            return resp.read_bytes()


@dataclass(frozen=True)
class RemoteTSA:
    """A REAL third-party RFC3161 TSA reached over HTTP — the INDEPENDENCE path (configured for production).

    ``url`` is the operator-configured RFC3161 endpoint; ``cert_pin`` is the path to the TSA's (or its CA's)
    certificate, PINNED out-of-band. ``mint`` POSTs the ``application/timestamp-query`` and returns the
    ``application/timestamp-reply`` body. Present so the mechanism is production-ready; its genuine
    independence cannot be exercised in an offline test (the honest residual A1 states)."""

    url: str
    cert_pin: str
    timeout: int = 30

    def mint(self, query_der: bytes) -> bytes:
        req = urllib.request.Request(
            self.url, data=query_der, headers={"Content-Type": "application/timestamp-query"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (operator URL)
                return resp.read()
        except OSError as e:
            raise TimeAnchorError(f"remote TSA {self.url} unreachable: {e}") from e


def _extract_gentime_epoch(token_path: Path) -> Optional[int]:
    """Read genTime ONLY from the signature-covered TimeStampToken (its TSTInfo), returned as an integer
    UNIX epoch (UTC seconds); None on any parse failure (fail-closed).

    SECURITY (do NOT parse the whole ``TimeStampResp`` text): the response wraps the signed
    ``TimeStampToken`` in an UNSIGNED ``PKIStatusInfo`` that ``ts -verify`` does NOT cover — and openssl's
    ``-text`` render prints that status section FIRST. A dishonest producer can inject a
    ``statusString`` free-text line (``"\\nTime stamp: Jan 1 2000 GMT"``) that renders BEFORE the real
    signed genTime while the signature still verifies — a BACKDATING forgery of the exact bound this anchor
    establishes. So we extract the signed token ALONE with ``ts -reply -token_out`` (which discards the
    status wrapper entirely) and parse genTime from THAT via ``-token_in -text``. genTime then comes only
    from bytes the TSA signed — an attacker cannot move it without breaking the signature (and if the
    injection instead makes ``-token_out`` fail, this returns None → the caller rejects the anchor)."""
    with tempfile.TemporaryDirectory() as td:
        tst = Path(td) / "tst.der"
        # -token_out: write ONLY the CMS SignedData TimeStampToken (no unsigned PKIStatusInfo) — the
        # signature-covered content. An attacker cannot alter genTime here without breaking the signature.
        r0 = _run_openssl(["ts", "-reply", "-in", str(token_path), "-token_out", "-out", str(tst)])
        if r0.returncode != 0 or not tst.exists():
            return None
        # -token_in: parse the extracted token; its -text now contains ONLY the signed TSTInfo.
        r = _run_openssl(["ts", "-reply", "-in", str(tst), "-token_in", "-text"])
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("time stamp:"):
            value = stripped.split(":", 1)[1].strip()
            try:
                dt = datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                return None
            return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
    return None


def verify_anchor(
    cp: Checkpoint, token: bytes, *, tsa_cert_pin: str
) -> "tuple[bool, Optional[int]]":
    """Verify an RFC3161 token binds ``checkpoint_hash(cp)`` under the PINNED TSA cert; return ``(ok, T)``.

    Runs ``openssl ts -verify -digest <checkpoint_hash> -sha256 -in <token> -CAfile <tsa_cert_pin>`` — which
    checks (a) the token's message-imprint equals the checkpoint hash (a TAMPERED checkpoint → different
    hash → FAIL) and (b) the token's signer chains to the PINNED cert (a token from a WRONG/unpinned TSA →
    FAIL). On success, genTime is extracted from the verified token as the "existed no-later-than T" bound
    (UNIX epoch seconds, read from the SIGNED token — never the verifier wall clock). FAIL-CLOSED: returns
    ``(False, None)`` on any verify failure, missing pin, or genTime parse failure."""
    if not tsa_cert_pin or not Path(tsa_cert_pin).exists():
        return False, None
    try:
        _require_openssl_ts()
    except TimeAnchorError:
        return False, None
    digest_hex = checkpoint_hash(cp)
    with tempfile.TemporaryDirectory() as td:
        tok = Path(td) / "token.tsr"
        tok.write_bytes(token)
        r = _run_openssl([
            "ts", "-verify", "-digest", digest_hex, "-sha256", "-in", str(tok), "-CAfile", tsa_cert_pin,
        ])
        combined = r.stdout + r.stderr
        if r.returncode != 0 or "Verification: OK" not in combined:
            return False, None
        gen = _extract_gentime_epoch(tok)
        if gen is None:
            return False, None
        return True, gen


def anchor_checkpoint(cp: Checkpoint, *, tsa: TSA) -> bytes:
    """Mint a real RFC3161 time-anchor token over ``checkpoint_hash(cp)`` from ``tsa``; return DER bytes.

    Builds an ``openssl ts -query`` over the checkpoint hash, has ``tsa`` mint the reply, then SELF-VERIFIES
    the fresh token against the TSA's own pinned cert before returning — so a mis-minted / non-binding token
    never escapes this function. Store the returned bytes base64 as a SIDECAR (see the module docstring);
    they do NOT enter any signed chain digest. Raises :class:`TimeAnchorError` on any failure (fail-closed).
    """
    _require_openssl_ts()
    query = _ts_query(checkpoint_hash(cp))
    token = tsa.mint(query)
    ok, _gen = verify_anchor(cp, token, tsa_cert_pin=tsa.cert_pin)
    if not ok:
        raise TimeAnchorError("freshly minted RFC3161 token did not self-verify against the TSA cert")
    return token
