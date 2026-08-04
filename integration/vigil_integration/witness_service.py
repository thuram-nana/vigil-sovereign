"""witness_service — TRUTHENOVATION A3: a DEPLOYABLE loopback witness co-sign SERVICE.

VF-1c shipped the witness *protocol* (``remediation.attestation_witness`` — a strict-majority quorum
time-co-signs an attestation head) and A2 shipped the re-proof *loop* that drives it. What stayed DEFERRED
(``apps/sigil/sigil/spine/witness.py:37-39``) was the LIVE CO-SIGN TRANSPORT: until it landed, an
independent witness co-signed on ITS OWN box and the envelope was shuttled back BY HAND (``cosign_envelope``
— the manual stand-in). A3 lands that transport as a real loopback endpoint so N independently-keyed witness
PROCESSES co-sign a real checkpoint series over the wire, and a third party can run one.

What this module is (and, honestly, is NOT):

  * :class:`WitnessService` — one witness PROCESS's logic: it holds ITS OWN Ed25519 key + a tracked tip and,
    on each incoming checkpoint, either returns a TIMED co-signature or REFUSES with a
    :class:`transparency.ConsistencyError`. The anti-equivocation check is NOT re-implemented here — it is
    delegated to :meth:`transparency.Witness.cosign`, the merged, tested honest-witness contract: a witness
    co-signs ONLY an append-only EXTENSION of the tip it has already seen; a fork / split-view / non-append
    submission raises ``ConsistencyError`` and NO signature is produced. The transport carries checkpoints;
    it does not weaken that check. (An exact-replay of the tip the witness just signed is idempotent — the
    same head is not equivocation — and returns the cached co-signature.)
  * :func:`serve_witness` / :func:`run_witness_forever` — bind ``WitnessService`` behind a stdlib
    ``http.server`` on LOOPBACK (or a private/tunnel address; ``bind_ok`` refuses a public / unspecified
    bind, mirroring ``uiproxy.bind_ok``). ``POST /cosign`` co-signs (or 409-refuses a fork); ``GET /pubkey``
    advertises this witness's ``(key_id, public_key_b64)`` for out-of-band roster pinning; ``GET /health``
    is a liveness probe.
  * :func:`submit_checkpoint` — the submit client: fan a checkpoint out to N witness endpoints, GATHER the
    timed co-signatures into a :class:`TimedWitnessedCheckpoint`, and SURFACE every refusal (a refusal is
    the anti-equivocation signal — it is recorded in ``SubmitResult.refusals``, NEVER swallowed). The caller
    then adjudicates the quorum with :func:`verify_timed_witnessed` against an out-of-band-pinned TrustRoot;
    a fork that a witness already committed against breaks that quorum and the verify FAILS CLOSED.

DETERMINISM / SIGNING (the load-bearing invariant): ``observed_time`` is a CALLER INPUT — each witness
supplies its own via an INJECTABLE ``clock`` (default ``int(time.time())``; a test/`--fixed-time` deploy
pins it). Nothing wallclock/rng ever enters the SIGNED bytes: :func:`attestation_witness.timed_cosign`
folds the integer ``observed_time`` into the message; the key is PERSISTENT (loaded, never freshly minted
per co-sign). Two identical series over the same keys + clocks produce identical co-signatures.

HONEST VERDICT (do NOT overclaim — the A2 lesson): A3 is a CAPABILITY — the transport is BUILT, tested, and
SHIPPABLE, and an N-witness LOCAL deployment is proven offline (the mechanism, the co-signing, and the
fork-refusal all run over a real loopback socket, and a third party can run a witness standalone). It is
NOT "witnessed by independent parties in production." The IRREDUCIBLE residual: genuine independence needs
THIRD-PARTY OPERATORS — distinct keys are not distinct operators (``witness.py:guarantee_label``); and at
``threshold==1`` equivocation is DETECTABLE, not prevented. A local N-witness deploy proves the mechanism,
not true independence.

FATAL-2: this module pulls ONLY stdlib + ``vigil_core`` + the sovereign-safe transparency layer
(``transparency`` is ``vigil_core``-only; ``remediation.attestation_witness`` is ``vigil_core`` + that
layer). It NEVER imports ``framework.*`` / ``strix.*`` / ``sigil`` — so a witness process can run in the
offense-free sovereign env AND its test runs in the integration CI leg. It is placed in
``vigil_integration/`` (next to ``transparency.py``), NOT in ``apps/sigil`` (whose tests do not run in the
offense venv — a known CI blind spot), while mirroring the ``sigil-bridge`` daemon PATTERN without importing
sigil.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import signal
import sys
import threading
import time as _time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional
from urllib import error as _urlerror
from urllib import request as _urlrequest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.crypto import KeyPair

from .remediation.attestation_witness import (
    TimedWitnessedCheckpoint,
    TimedWitnessSignature,
    timed_cosign,
)
from .transparency import Checkpoint, ConsistencyError, Witness, checkpoint_hash

# IPv6 tunnel/LAN ranges Python's is_private mislabels or misses — kept in step with uiproxy.bind_ok.
_CGNAT4 = ipaddress.ip_network("100.64.0.0/10")          # Tailscale CGNAT
_ULA6 = ipaddress.ip_network("fc00::/7")                 # IPv6 unique-local
_LINKLOCAL6 = ipaddress.ip_network("fe80::/10")          # IPv6 link-local


def bind_ok(addr: str) -> bool:
    """True iff ``addr`` is safe for a witness to bind: loopback, an IPv4 PRIVATE (RFC1918) / Tailscale-CGNAT
    address, or an IPv6 unique-local (fc00::/7) / link-local (fe80::/10) address — a WireGuard/Tailscale
    tunnel or LAN address. NEVER 0.0.0.0/:: (unspecified) and NEVER a globally-routable address. A byte-for-
    byte behavioural mirror of ``uiproxy.bind_ok`` (re-implemented here so the witness imports no other
    module): the tunnel, not the transport, is the network boundary — a witness must never be a public
    listener (an operator MUST see every checkpoint it is asked to co-sign)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_unspecified:                                 # 0.0.0.0 / :: → refuse
        return False
    if ip.version == 6:
        return ip.is_loopback or ip in _ULA6 or ip in _LINKLOCAL6
    return ip.is_loopback or ip.is_private or ip in _CGNAT4


# --------------------------------------------------------------------------------------------------------
# witness key material — persistent (a co-sign key is NEVER freshly minted per request; a third party mints
# its OWN once and keeps it). Deliberately minimal + sovereign-safe (vigil_core.generate_keypair + stdlib).
# --------------------------------------------------------------------------------------------------------
def _key_id_for(public_key_b64: str) -> str:
    """A stable, human-legible default key id derived from the public key (a third party may override with
    --key-id). It is a LABEL only — trust comes from the pinned public key in the verifier's roster, never
    from this string."""
    safe = "".join(c for c in public_key_b64 if c.isalnum())[:12]
    return f"witness-{safe}"


def load_or_create_witness_key(path: "str | os.PathLike", *, key_id: str = "") -> "tuple[str, KeyPair]":
    """Load the witness's persistent Ed25519 keypair from ``path`` (JSON ``{key_id, public_key_b64,
    private_key_b64}``, 0600), or MINT one ON FIRST RUN and persist it. Returns ``(key_id, KeyPair)``.

    Persistence is what makes a witness a stable, pinnable identity across restarts — the same public key
    every time, so a verifier's out-of-band roster stays valid. A passed ``key_id`` overrides the stored /
    derived one (so an operator can name a witness ``w0`` regardless of its key). Fail-closed on a corrupt
    file (never silently regenerate a key an operator may have already pinned)."""
    p = Path(path)
    if p.exists():
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            kp = KeyPair(public_key_b64=str(obj["public_key_b64"]),
                         private_key_b64=str(obj["private_key_b64"]))
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise ValueError(f"corrupt witness key file {p}: {e}") from e
        kid = key_id or str(obj.get("key_id") or _key_id_for(kp.public_key_b64))
        return kid, kp
    kp = generate_keypair()
    kid = key_id or _key_id_for(kp.public_key_b64)
    p.parent.mkdir(parents=True, exist_ok=True)
    # 0600, owner-only — the private co-sign key must never be world-readable.
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"key_id": kid, "public_key_b64": kp.public_key_b64,
                   "private_key_b64": kp.private_key_b64}, fh, sort_keys=True)
    return kid, kp


# --------------------------------------------------------------------------------------------------------
# the witness process logic — a stateful, anti-equivocating, TIME-bounding co-signer
# --------------------------------------------------------------------------------------------------------
class WitnessService:
    """One witness PROCESS's co-sign logic: its OWN key + a tracked tip. :meth:`cosign` either returns a
    TIMED co-signature over an incoming checkpoint or REFUSES (raises :class:`ConsistencyError`) on a fork /
    split-view / non-append-only submission.

    Anti-equivocation is NOT re-implemented here: :meth:`cosign` delegates the consistency check + tip
    advance to :meth:`transparency.Witness.cosign` (the merged honest-witness contract), then produces the
    timed co-signature. So the transport can carry any checkpoint, but this witness signs ONLY an append-only
    extension of what it has already seen — the whole value of a witness. ``observed_time`` is read from an
    INJECTABLE ``clock`` (a caller input; never inside the signed math), so tests/`--fixed-time` are
    deterministic and a production witness folds in its own real clock reading.
    """

    def __init__(self, key_id: str, keypair: KeyPair, *, clock: Optional[Callable[[], int]] = None):
        self.key_id = key_id
        self._keypair = keypair
        # The tip-tracking honest-witness state machine (would_accept + cosign raise-on-fork + tip advance).
        # We reuse it for the CONSISTENCY guarantee and discard its timeless signature.
        self._witness = Witness(key_id, keypair.private_key_b64)
        self._clock = clock or (lambda: int(_time.time()))
        self._lock = threading.Lock()
        self._last_hash: str = ""
        self._last_sig: Optional[TimedWitnessSignature] = None

    @property
    def public_key_b64(self) -> str:
        return self._keypair.public_key_b64

    def cosign(self, cp: Checkpoint) -> TimedWitnessSignature:
        """Co-sign ``cp`` at this witness's own (injected) observed time, or raise
        :class:`ConsistencyError` if it is not an append-only extension of the tracked tip.

        Idempotent on an exact replay of the tip this witness just signed (same head ⇒ same co-signature,
        same observed_time — a re-submit is not equivocation). Thread-safe: the whole check-then-advance is
        under a lock, so two concurrent requests can never both advance the tip past an uncommitted head."""
        with self._lock:
            if self._last_sig is not None and checkpoint_hash(cp) == self._last_hash:
                return self._last_sig                     # idempotent replay of the last-signed head
            # Delegate the anti-equivocation check + tip advance to the merged honest-witness contract.
            # Raises ConsistencyError (and advances NOTHING) on a fork / non-append-only / split-view.
            self._witness.cosign(cp)                      # timeless Signature discarded — used only for its guard
            observed_time = int(self._clock())            # caller/injected input — never inside the signed math
            sig = timed_cosign(cp, witness_keypair=self._keypair, key_id=self.key_id,
                               observed_time=observed_time)
            self._last_hash = checkpoint_hash(cp)
            self._last_sig = sig
            return sig


# --------------------------------------------------------------------------------------------------------
# the loopback HTTP transport
# --------------------------------------------------------------------------------------------------------
def _checkpoint_from_obj(obj: object) -> Checkpoint:
    """Strictly parse a checkpoint dict from an untrusted request body. Fail-closed on any malformed shape."""
    if not isinstance(obj, dict):
        raise ValueError("checkpoint is not a JSON object")
    try:
        return Checkpoint(
            last_seq=int(obj["last_seq"]),
            entry_count=int(obj["entry_count"]),
            head_hash=str(obj["head_hash"]),
            merkle_root=str(obj["merkle_root"]),
            prev_checkpoint_hash=str(obj.get("prev_checkpoint_hash", "")),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"malformed checkpoint fields: {e}") from e


def _make_handler(service: WitnessService):
    class _WitnessHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):                        # keep the journal clean (systemd captures stdout)
            pass

        def _json(self, code: int, payload: dict) -> None:
            body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path.split("?", 1)[0] == "/pubkey":
                self._json(200, {"key_id": service.key_id, "public_key_b64": service.public_key_b64})
            elif self.path.split("?", 1)[0] == "/health":
                self._json(200, {"ok": True, "key_id": service.key_id})
            else:
                self._json(404, {"error": "not_found"})

        def do_POST(self):  # noqa: N802
            if self.path.split("?", 1)[0] != "/cosign":
                self._json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                length = 0
            raw = self.rfile.read(length) if length > 0 else b""
            try:
                obj = json.loads(raw.decode("utf-8"))
                cp = _checkpoint_from_obj(obj.get("checkpoint") if isinstance(obj, dict) else None)
            except (ValueError, TypeError) as e:
                self._json(400, {"error": "bad_request", "reason": str(e)})
                return
            try:
                sig = service.cosign(cp)
            except ConsistencyError as e:
                # 409 CONFLICT — the anti-equivocation refusal. This is the SIGNAL, surfaced to the client as
                # a distinct status so the submit client records it as a refusal (never a swallowed error).
                self._json(409, {"error": "consistency", "reason": str(e)})
                return
            self._json(200, {"key_id": sig.key_id, "observed_time": sig.observed_time,
                             "signature_b64": sig.signature_b64})

    return _WitnessHandler


def serve_witness(host: str, port: int, service: WitnessService) -> ThreadingHTTPServer:
    """Bind ``service`` behind a threaded HTTP server on ``host:port`` (LOOPBACK / private / tunnel only —
    ``bind_ok`` refuses a public / unspecified bind, fail-closed). Returns the server WITHOUT serving; the
    caller drives ``serve_forever`` (or the test drives it on a thread). ``port==0`` binds an ephemeral port
    (read it back from ``server.server_address[1]``)."""
    if not bind_ok(host):
        raise ValueError(
            f"refusing to bind {host!r}: a witness binds loopback or a PRIVATE (WireGuard/Tailscale/LAN) "
            f"address only — never 0.0.0.0/:: or a public address (the tunnel is the network boundary)")
    return ThreadingHTTPServer((host, port), _make_handler(service))


def run_witness_forever(host: str, port: int, service: WitnessService) -> int:
    """Serve ``service`` until SIGTERM/SIGINT (the systemd daemon entry). Installs graceful signal handlers
    that stop ``serve_forever`` cleanly, mirroring the sigil-bridge daemon pattern (Type=simple + graceful
    SIGTERM). Returns 0 on a clean stop."""
    server = serve_witness(host, port, service)
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    print(f"vigil-witness: {service.key_id} co-signing on http://{bound_host}:{bound_port}  "
          f"(pubkey {service.public_key_b64[:16]}…)", flush=True)

    def _stop(_signum, _frame):
        # shutdown() must run off the serving thread; a short daemon thread is the standard idiom.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


# --------------------------------------------------------------------------------------------------------
# the submit client
# --------------------------------------------------------------------------------------------------------
@dataclass
class SubmitResult:
    """The outcome of fanning one checkpoint out to N witness endpoints. ``signatures`` are the gathered
    timed co-signatures; ``refusals`` are ``(endpoint, reason)`` for each witness that REFUSED (409 — the
    anti-equivocation signal, surfaced not swallowed); ``errors`` are ``(endpoint, reason)`` for transport /
    malformed-response failures. A fork that a witness already committed against lands in ``refusals`` and,
    because that witness's co-signature is then absent, the quorum verify FAILS CLOSED."""
    checkpoint: Checkpoint
    signatures: "list[TimedWitnessSignature]" = field(default_factory=list)
    refusals: "list[tuple[str, str]]" = field(default_factory=list)
    errors: "list[tuple[str, str]]" = field(default_factory=list)

    def as_witnessed(self) -> TimedWitnessedCheckpoint:
        """Bundle the gathered co-signatures into a :class:`TimedWitnessedCheckpoint` (the verifier's input).
        The caller adjudicates the quorum with :func:`verify_timed_witnessed` against an out-of-band-pinned
        TrustRoot — this bundle is NOT self-adjudicating (a refusal simply means a missing signature here)."""
        return TimedWitnessedCheckpoint(checkpoint=self.checkpoint.to_dict(),
                                        witness_signatures=list(self.signatures))


def _post_json(endpoint: str, path: str, payload: dict, *, timeout: float) -> "tuple[int, dict]":
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    req = _urlrequest.Request(endpoint.rstrip("/") + path, data=data, method="POST",
                              headers={"Content-Type": "application/json"})
    try:
        with _urlrequest.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), json.loads(resp.read().decode("utf-8"))
    except _urlerror.HTTPError as e:                       # 4xx/5xx carry a JSON body we want (e.g. the 409)
        try:
            return int(e.code), json.loads(e.read().decode("utf-8"))
        except (ValueError, TypeError, OSError):
            return int(e.code), {"error": "http", "reason": str(e)}


def submit_checkpoint(cp: Checkpoint, endpoints: "list[str]", *, scope: str = "",
                      timeout: float = 10.0) -> SubmitResult:
    """Fan ``cp`` out to each witness ``endpoint`` (``http://host:port``), gathering timed co-signatures.

    Fail-closed + honest: a 200 yields a co-signature; a 409 is recorded as a REFUSAL (the anti-equivocation
    signal — surfaced in ``refusals``, never swallowed); anything else is an error. It NEVER adjudicates the
    quorum itself — the caller runs :func:`verify_timed_witnessed` on ``result.as_witnessed()`` against an
    out-of-band-pinned TrustRoot. If a witness refuses (a fork it already committed against), its signature
    is absent and that verify fails closed."""
    result = SubmitResult(checkpoint=cp)
    for ep in endpoints:
        try:
            status, body = _post_json(ep, "/cosign", {"checkpoint": cp.to_dict(), "scope": scope},
                                      timeout=timeout)
        except (_urlerror.URLError, OSError, ValueError) as e:
            result.errors.append((ep, f"{type(e).__name__}: {e}"))
            continue
        if status == 200:
            try:
                result.signatures.append(TimedWitnessSignature(
                    key_id=str(body["key_id"]), observed_time=int(body["observed_time"]),
                    signature_b64=str(body["signature_b64"])))
            except (KeyError, TypeError, ValueError) as e:
                result.errors.append((ep, f"malformed co-signature response: {e}"))
        elif status == 409:
            result.refusals.append((ep, str(body.get("reason") or "witness refused (consistency)")))
        else:
            result.errors.append((ep, f"HTTP {status}: {body.get('reason') or body.get('error') or body}"))
    return result


def fetch_pubkey(endpoint: str, *, timeout: float = 10.0) -> "tuple[str, str]":
    """GET a witness's advertised ``(key_id, public_key_b64)`` for out-of-band roster assembly / pinning.
    The verifier decides which keys it TRUSTS — this only discovers what a witness advertises."""
    req = _urlrequest.Request(endpoint.rstrip("/") + "/pubkey", method="GET")
    with _urlrequest.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return str(body["key_id"]), str(body["public_key_b64"])


def trust_root_from_endpoints(endpoints: "list[str]", threshold: int, *,
                              timeout: float = 10.0) -> TrustRoot:
    """Build a witness :class:`TrustRoot` by fetching each endpoint's advertised public key. CONVENIENCE for
    a local deploy where the operator runs the witnesses; in a genuine third-party deployment the verifier
    PINS each key out-of-band (a public key fetched from the witness being verified is not independently
    trustworthy). ``is_split_view_resistant`` (checked by the verifier) still requires a strict majority of
    DISTINCT keys."""
    authorizers = []
    for ep in endpoints:
        kid, pub = fetch_pubkey(ep, timeout=timeout)
        authorizers.append(AuthorizerKey(key_id=kid, name=kid, public_key_b64=pub))
    return TrustRoot(threshold=threshold, authorizers=authorizers)


# --------------------------------------------------------------------------------------------------------
# standalone entry (systemd ExecStart + a third party's `python -m vigil_integration.witness_service`)
# --------------------------------------------------------------------------------------------------------
def _cmd_serve(args: argparse.Namespace) -> int:
    fixed = getattr(args, "fixed_time", None)
    clock = (lambda: int(fixed)) if fixed is not None else None   # --fixed-time: deterministic (test/demo)
    key_id, kp = load_or_create_witness_key(args.key, key_id=args.key_id)
    service = WitnessService(key_id, kp, clock=clock)
    return run_witness_forever(args.host, int(args.port), service)


def _cmd_submit(args: argparse.Namespace) -> int:
    endpoints = [e.strip() for e in str(args.endpoints).split(",") if e.strip()]
    cp = _checkpoint_from_obj(json.loads(Path(args.checkpoint).read_text(encoding="utf-8")))
    res = submit_checkpoint(cp, endpoints, scope=args.scope, timeout=args.timeout)
    print(f"=== vigil witness submit — {len(endpoints)} endpoint(s) ===")
    print(f"co-signatures : {len(res.signatures)} ({', '.join(s.key_id for s in res.signatures) or '-'})")
    for ep, why in res.refusals:
        print(f"REFUSED       : {ep} — {why}")            # the anti-equivocation signal, surfaced
    for ep, why in res.errors:
        print(f"error         : {ep} — {why}")
    if args.out:
        Path(args.out).write_text(
            json.dumps(res.as_witnessed().model_dump(mode="json"), sort_keys=True, indent=2),
            encoding="utf-8")
        print(f"witnessed out : {args.out}")
    # Exit non-zero iff a witness REFUSED (equivocation detected) — fail-closed for scripts/timers.
    return 3 if res.refusals else (0 if res.signatures else 2)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vigil-witness",
        description="TRUTHENOVATION A3 — a deployable loopback witness co-sign service (a third party runs one)")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("serve", help="run ONE witness process on loopback (its own key + tracked tip)")
    ps.add_argument("--host", default="127.0.0.1",
                    help="bind address — loopback (default) or a PRIVATE/tunnel IP; a public/0.0.0.0 bind is "
                         "refused (never-public)")
    ps.add_argument("--port", type=int, required=True, help="TCP port (0 = ephemeral)")
    ps.add_argument("--key", required=True,
                    help="path to this witness's persistent key file (minted 0600 on first run)")
    ps.add_argument("--key-id", default="", help="override the witness key id (default: derived from pubkey)")
    ps.add_argument("--fixed-time", type=int, default=None,
                    help="TEST/DEMO ONLY: pin observed_time to this integer (deterministic). Omit in "
                         "production (the witness folds its own real clock reading).")
    ps.set_defaults(func=_cmd_serve)

    pu = sub.add_parser("submit", help="fan a checkpoint out to N witness endpoints and gather co-signatures")
    pu.add_argument("--endpoints", required=True, help="comma-separated http://host:port witness endpoints")
    pu.add_argument("--checkpoint", required=True, help="a JSON file holding the checkpoint dict to co-sign")
    pu.add_argument("--scope", default="", help="optional scope string bound into the submission")
    pu.add_argument("--out", default="", help="write the gathered TimedWitnessedCheckpoint JSON here")
    pu.add_argument("--timeout", type=float, default=10.0, help="per-endpoint timeout (s)")
    pu.set_defaults(func=_cmd_submit)
    return p


def main(argv: "Optional[list[str]]" = None) -> int:
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
