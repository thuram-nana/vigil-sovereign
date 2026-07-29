"""approval_broker — the file-backed pending-approval queue + owner-signed-token inbox (VIGIL A2).

This closes the M2 loop. :mod:`live.approval_token` gives a per-action, single-use, owner-signed token
that upgrades a WARDEN ``queue`` to ``allow`` for EXACTLY ONE action; :mod:`live.wiring.build_approval_gate`
consumes such a token. Nothing, until now, PUBLISHED the pending request the owner signs, minted the nonce,
or fed the gate a token. This module is that transport:

  * ``<base>/approvals/pending/<request_id>.json`` — the OFFENSE worker publishes what it wants to run
    (tool, the gate-seen target, the args-digest, a single-use nonce, and a REDACTED args preview). The
    request is public-safe (no secret, no private key) so it is fine to sit on a shared engagement home the
    sovereign signer also reads.
  * ``<base>/approvals/signed/<request_id>.json`` — the SOVEREIGN signer (``vigil approve`` / the sovereign
    cockpit — the only party holding the owner PRIVATE key) writes the owner-signed token here. The offense
    worker reads it back and the gate spends it, ONCE, atomically.

The offense worker mints the nonce (unpredictable, ``secrets.token_hex``) and derives a deterministic
``request_id = sha256(action_digest || 0x00 || nonce)[:16]`` so a re-publish of the SAME action is
idempotent. The token binds the action; the ledger (``nonce_ledger``) enforces single-use; the authority
pins the owner key. A token NEVER widens scope — it only satisfies the WARDEN human leg for an action the
CRUCIBLE gate already put in-envelope (``queue``). A CRUCIBLE ``deny`` stays ``deny``, untouched.

FATAL-2 / import-clean: ``vigil_core`` + stdlib + relative imports ONLY (never ``framework`` / ``strix`` /
``sigil`` at module scope). It holds NO private key, so it is safe to import in either environment; only the
sovereign signer supplies a private key, and it never touches this module's persisted state with one.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .approval_token import _APPROVAL_SCHEMA, ApprovalAction, ApprovalAuthority, ApprovalToken

# The dict-aware secret redactor + the free-string scrubber (ONE F3 vocabulary). Both are import-clean
# (pydantic + stdlib; no framework), so reusing them here keeps the module offense/sovereign-safe.
from ..tools import redact_tool_args
from ..tools.mcp_registry import _redact_str

__all__ = [
    "PendingRequest",
    "ApprovalBroker",
    "publish_pending",
    "list_pending",
    "write_signed_token",
    "find_signed_token",
    "approvals_root",
    "authority_path",
    "persist_authority",
    "load_authority",
    "provision_authority_material",
]

# env knobs (documented). The ONLY time use is the human-approval poll window — a dead-man's-switch,
# never oracle/learning math.
_WAIT_ENV = "VIGIL_APPROVAL_WAIT_SECONDS"
_MAX_WAIT_SECONDS = 900.0          # cap the human-approval poll window at the token dead-man's-switch bound
_POLL_INTERVAL = 0.25              # seconds between signed/ polls while blocking
_PREVIEW_CAP = 2000                # bound the redacted args preview written to disk

_APPROVALS_DIRNAME = "approvals"
_PENDING_DIRNAME = "pending"
_SIGNED_DIRNAME = "signed"
_AUTHORITY_FILE = "approval-authority.json"

_PENDING_SCHEMA = "vigil-approval-pending-v1"
_AUTHORITY_SCHEMA = "vigil-approval-authority-v1"


# ---------------------------------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------------------------------


def approvals_root(base_dir: Any) -> Path:
    """The approvals root ``<base>/approvals`` (holds ``pending/`` + ``signed/``)."""
    return Path(base_dir) / _APPROVALS_DIRNAME


def authority_path(base_dir: Any) -> Path:
    """Where the PUBLIC :class:`ApprovalAuthority` is persisted (``<base>/approval-authority.json``)."""
    return Path(base_dir) / _AUTHORITY_FILE


def _pending_dir(root: Any) -> Path:
    return Path(root) / _PENDING_DIRNAME


def _signed_dir(root: Any) -> Path:
    return Path(root) / _SIGNED_DIRNAME


def _default_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------------------------------
# atomic, secret-free JSON persistence
# ---------------------------------------------------------------------------------------------------


def _atomic_write_json(path: Path, obj: dict) -> None:
    """Atomically write ``obj`` as canonical JSON at ``path`` (0600, fsync'd, then ``os.replace``). The
    tmp name is unique so concurrent writers of the SAME (deterministic) content never corrupt each other."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    tmp = path.parent / (path.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp), str(path))
    finally:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass


def _safe_component(value: Any) -> str:
    """A filesystem-safe id component: no separators, no ``..``, no NUL. Returns "" if unsafe."""
    s = str(value or "").strip()
    if not s or "/" in s or "\\" in s or ".." in s or "\x00" in s:
        return ""
    return s


# ---------------------------------------------------------------------------------------------------
# the pending request (public-safe — no secret, no private key)
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PendingRequest:
    request_id: str
    tool_name: str
    target: str
    action_digest: str
    nonce: str
    args_preview: str
    created_at_iso: str


def _request_id(action_digest: str, nonce: str) -> str:
    body = (str(action_digest) + "\x00" + str(nonce)).encode("utf-8")
    return hashlib.sha256(body).hexdigest()[:16]


def _redact_preview(preview: Any) -> str:
    """A REDACTED, length-bounded preview of the args for the human — NEVER a raw secret. A dict is scrubbed
    with the dict-aware ``redact_tool_args`` (masks values under secret keys + inline secrets); anything else
    is stringified + run through the free-string scrubber. Total (any failure → an empty preview)."""
    try:
        if isinstance(preview, dict):
            safe = redact_tool_args(preview)
            s = json.dumps(safe, sort_keys=True, ensure_ascii=False, default=str)
        elif isinstance(preview, str):
            s = _redact_str(preview)
        else:
            s = _redact_str(str(preview))
    except Exception:  # noqa: BLE001 — a preview is advisory; a redaction error yields an empty preview
        return ""
    return s[:_PREVIEW_CAP]


def _read_pending_file(path: Path) -> Optional[PendingRequest]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    fields = ("request_id", "tool_name", "target", "action_digest", "nonce", "args_preview",
              "created_at_iso")
    vals = {k: obj.get(k) for k in fields}
    if not all(isinstance(v, str) for v in vals.values()):
        return None
    return PendingRequest(**vals)  # type: ignore[arg-type]


def publish_pending(root: Any, action: ApprovalAction, *, nonce: str, args_preview: Any,
                    now_iso: str) -> PendingRequest:
    """Atomically publish ``pending/<request_id>.json`` for ``action`` (idempotent: reuse if it exists).
    ``args_preview`` is REDACTED before it touches disk, so no secret is persisted. ``nonce`` is the
    offense-minted single-use nonce; ``request_id`` is derived from ``(action_digest, nonce)``."""
    if type(action) is not ApprovalAction:
        raise TypeError("publish_pending needs an ApprovalAction")
    rid = _request_id(action.action_digest, nonce)
    path = _pending_dir(root) / f"{rid}.json"
    existing = _read_pending_file(path)
    if existing is not None:
        return existing  # idempotent — a re-publish of the same (action, nonce) reuses the record
    req = PendingRequest(
        request_id=rid, tool_name=action.tool_name, target=action.target,
        action_digest=action.action_digest, nonce=str(nonce),
        args_preview=_redact_preview(args_preview), created_at_iso=str(now_iso),
    )
    _atomic_write_json(path, {"schema": _PENDING_SCHEMA, **asdict(req)})
    return req


def list_pending(root: Any) -> list[PendingRequest]:
    """Every well-formed pending request under ``root/pending`` (deterministic filename order). The
    sovereign signer reads these to display + sign. Total: an absent/unreadable dir yields ``[]``."""
    d = _pending_dir(root)
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return []
    out: list[PendingRequest] = []
    for name in names:
        if not name.endswith(".json"):
            continue
        req = _read_pending_file(d / name)
        if req is not None:
            out.append(req)
    return out


# ---------------------------------------------------------------------------------------------------
# the signed-token inbox
# ---------------------------------------------------------------------------------------------------


def _token_to_json(token: ApprovalToken) -> dict:
    return {
        "schema": token.schema,
        "tool_name": token.tool_name,
        "target": token.target,
        "action_digest": token.action_digest,
        "not_before": token.not_before,
        "not_after": token.not_after,
        "nonce": token.nonce,
        "key_id": token.key_id,
        "signature_b64": token.signature_b64,
    }


def _token_from_json(obj: Any) -> Optional[ApprovalToken]:
    """Reconstruct an :class:`ApprovalToken` with the EXACT field types ``approval_token._well_formed``
    demands (str fields; a real, non-bool numeric window). Any malformed record → None (fail-closed)."""
    if not isinstance(obj, dict):
        return None
    try:
        tool_name = obj["tool_name"]
        target = obj["target"]
        action_digest = obj["action_digest"]
        nonce = obj["nonce"]
        key_id = obj["key_id"]
        signature_b64 = obj["signature_b64"]
        not_before = obj["not_before"]
        not_after = obj["not_after"]
    except (KeyError, TypeError):
        return None
    schema = obj.get("schema", _APPROVAL_SCHEMA)
    strs = (tool_name, target, action_digest, nonce, key_id, signature_b64, schema)
    if not all(isinstance(x, str) for x in strs):
        return None
    if isinstance(not_before, bool) or isinstance(not_after, bool):
        return None
    if not isinstance(not_before, (int, float)) or not isinstance(not_after, (int, float)):
        return None
    return ApprovalToken(
        tool_name=tool_name, target=target, action_digest=action_digest,
        not_before=float(not_before), not_after=float(not_after),
        nonce=nonce, key_id=key_id, signature_b64=signature_b64, schema=schema,
    )


def write_signed_token(root: Any, request_id: str, token: ApprovalToken) -> Path:
    """SOVEREIGN: atomically write the owner-signed ``token`` to ``signed/<request_id>.json``. ``request_id``
    is validated as a safe filename component (it can never escape the dir)."""
    if type(token) is not ApprovalToken:
        raise TypeError("write_signed_token needs an ApprovalToken")
    rid = _safe_component(request_id)
    if not rid:
        raise ValueError("invalid request_id (unsafe filename component)")
    path = _signed_dir(root) / f"{rid}.json"
    _atomic_write_json(path, _token_to_json(token))
    return path


def find_signed_token(root: Any, action: ApprovalAction) -> Optional[tuple[ApprovalToken, ApprovalAction]]:
    """OFFENSE: the first owner-signed token under ``signed/`` whose ``(tool_name, target, action_digest)``
    match ``action`` exactly, as ``(token, action)`` — else None. Reconstructs with EXACT types so the
    downstream ``consume_token`` re-derives byte-identical signing material. Total (any read error skipped)."""
    if type(action) is not ApprovalAction:
        return None
    d = _signed_dir(root)
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return None
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            obj = json.loads((d / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        token = _token_from_json(obj)
        if token is None:
            continue
        if token.matches(action):
            return token, action
    return None


# ---------------------------------------------------------------------------------------------------
# authority persistence (PUBLIC key only on disk — safe to load offense-side)
# ---------------------------------------------------------------------------------------------------


def persist_authority(base_dir: Any, *, owner_key_id: str, owner_public_key_b64: str) -> Path:
    """Persist ONLY the PUBLIC :class:`ApprovalAuthority` to ``<base>/approval-authority.json``. Validated
    fail-closed FIRST (``ApprovalAuthority`` rejects a non-canonical / low-order / malformed key), so a bad
    key is never written."""
    ApprovalAuthority(owner_key_id=owner_key_id, owner_public_key_b64=owner_public_key_b64)  # validates
    path = authority_path(base_dir)
    _atomic_write_json(path, {"schema": _AUTHORITY_SCHEMA, "owner_key_id": owner_key_id,
                              "owner_public_key_b64": owner_public_key_b64})
    return path


def load_authority(base_dir: Any) -> Optional[ApprovalAuthority]:
    """OFFENSE-side loader — PUBLIC key ONLY (safe to load offense-side). None if absent/malformed
    (fail-closed: the caller then keeps today's standing-boolean / hard-block behaviour)."""
    try:
        obj = json.loads(authority_path(base_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    kid = obj.get("owner_key_id")
    pub = obj.get("owner_public_key_b64")
    if not (isinstance(kid, str) and kid and isinstance(pub, str) and pub):
        return None
    try:
        return ApprovalAuthority(owner_key_id=kid, owner_public_key_b64=pub)
    except Exception:  # noqa: BLE001 — a malformed/low-order persisted key is a no-authority (fail-closed)
        return None


def provision_authority_material(base_dir: Any, *, key_id: str = "owner") -> tuple[Path, str, str]:
    """SOVEREIGN provisioning: mint a FRESH owner keypair, persist ONLY the PUBLIC authority to
    ``<base>/approval-authority.json``, and RETURN the private key (to be shown ONCE and exported as
    ``VIGIL_APPROVAL_OWNER_KEY`` — never written under ``<base>``, which the keyless offense worker opens
    as its own vault). Returns ``(authority_path, owner_public_key_b64, owner_private_key_b64)``."""
    from vigil_core import generate_keypair
    kp = generate_keypair()
    path = persist_authority(base_dir, owner_key_id=key_id, owner_public_key_b64=kp.public_key_b64)
    return path, kp.public_key_b64, kp.private_key_b64


# ---------------------------------------------------------------------------------------------------
# the broker — binds "the action being authorized" + a no-arg token_source() for the gate
# ---------------------------------------------------------------------------------------------------


def _resolve_wait(wait_seconds: Optional[float]) -> float:
    """The human-approval poll window: an explicit ``wait_seconds`` wins, else ``VIGIL_APPROVAL_WAIT_SECONDS``,
    else 0 (non-blocking — an unattended run denies immediately). Capped at the token dead-man's bound."""
    raw: Any = wait_seconds
    if raw is None:
        raw = os.environ.get(_WAIT_ENV, "")
    try:
        val = float(raw) if str(raw).strip() != "" else 0.0
    except (TypeError, ValueError):
        return 0.0
    if val != val or val < 0:  # NaN / negative → non-blocking (fail-closed)
        return 0.0
    return min(val, _MAX_WAIT_SECONDS)


class ApprovalBroker:
    """Over an approvals ``root`` (``<base>/approvals``): bind the action currently being authorized, publish
    its pending request, and expose a no-arg :meth:`token_source` the gate calls. Offense-safe (holds no
    private key). One offense-minted nonce per DISTINCT action-digest keeps a re-publish idempotent; the
    ledger's single-use then means an identical action, once approved+consumed, needs a fresh approval."""

    def __init__(self, root: Any, *, wait_seconds: Optional[float] = None,
                 now: Callable[[], float] = time.time, clock_iso: Optional[Callable[[], str]] = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._root = Path(root)
        self._wait = _resolve_wait(wait_seconds)
        self._now = now
        self._clock_iso = clock_iso or _default_iso
        self._sleep = sleep
        self._current: Optional[ApprovalAction] = None
        self._preview: Any = None
        self._nonces: dict[str, str] = {}  # action_digest -> offense-minted nonce (stable per run)

    @property
    def root(self) -> Path:
        return self._root

    def bind(self, action: Optional[ApprovalAction], *, args_preview: Any = None) -> None:
        """Set the action currently being authorized (and the preview the human will see). A non-action
        (or None) unbinds — :meth:`token_source` then returns None so the gate stays queued (fail-closed)."""
        self._current = action if type(action) is ApprovalAction else None
        self._preview = args_preview

    def _nonce_for(self, action: ApprovalAction) -> str:
        n = self._nonces.get(action.action_digest)
        if n is None:
            n = secrets.token_hex(16)
            self._nonces[action.action_digest] = n
        return n

    def publish_current(self) -> Optional[PendingRequest]:
        action = self._current
        if type(action) is not ApprovalAction:
            return None
        try:
            return publish_pending(self._root, action, nonce=self._nonce_for(action),
                                   args_preview=self._preview, now_iso=self._clock_iso())
        except Exception:  # noqa: BLE001 — a publish error just means no pending appears (fail-closed)
            return None

    def token_source(self) -> Optional[tuple]:
        """No-arg: publish the bound action's pending request (idempotent) then return
        ``find_signed_token(root, action)`` — optionally BLOCKING up to the poll window for a matching
        owner-signed token. None (no bound action / no token in time) leaves the gate queued (fail-closed)."""
        action = self._current
        if type(action) is not ApprovalAction:
            return None
        self.publish_current()
        deadline = self._now() + self._wait
        while True:
            found = find_signed_token(self._root, action)
            if found is not None:
                return found
            remaining = deadline - self._now()
            if remaining <= 0:
                return None
            self._sleep(min(_POLL_INTERVAL, remaining))
