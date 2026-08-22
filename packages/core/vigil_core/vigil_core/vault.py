"""vigil_core.vault — at-rest sealing of secret files under a TPM-sealed KEK (audit G1).

The shared vault used by BOTH envs (sovereign SIGIL for the owner key/secrets, offense worker for the
operator key) — living in vigil_core so neither side re-implements it and the two-env boundary is
unaffected. Opt-in and non-bricking by construction:

  * UNTIL :meth:`Vault.provision` is run once (sealing a fresh KEK to this machine's TPM), the vault is
    DISABLED and every read/write is EXACTLY today's plaintext behaviour (a loud "unsealed" status is
    surfaced) — nothing changes, nothing can break.
  * ONCE provisioned, writes seal + reads unseal transparently; a legacy plaintext file MIGRATES on first
    read NON-DESTRUCTIVELY — the sealed copy is verified to round-trip BEFORE the plaintext is replaced,
    so a migration can never lose the secret.
  * If the TPM later cannot unseal (moved disk / tooling gone), sealed reads fail CLOSED
    (:class:`VaultLocked`) — never a silent plaintext fallback.

The TPM is reached only through :mod:`vigil_core.kek`'s injectable runner seam, so the whole vault is
unit-tested deterministically with a fake TPM; the live path activates once ``tpm2-tools`` + ``tss`` group
are configured (one-time operator setup).
"""
from __future__ import annotations

import os
import shutil
import threading
from pathlib import Path
from typing import Optional

from .kek import (
    _SEAL_PRIV, _SEAL_PUB, KekError, TpmRunner, _default_tpm_runner, is_provisioned, load_kek,
    load_kek_from, provision_kek, reseal_kek,
)
from .rotation import RotationError, rewrap_or_seal, verify_opens_to
from .sealing import SealError, is_sealed, new_kek, seal, unseal


class VaultLocked(Exception):
    """The vault is provisioned (sealed mode) but the KEK could not be unsealed from the TPM — sealed
    material cannot be read. Fail-closed; NEVER degrades to plaintext."""


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes with mode 0600 set BEFORE the secret lands, then atomically replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))


class Vault:
    """Seals/opens secret files under a TPM-sealed KEK. ``vault_dir`` holds the sealed-KEK blobs;
    ``runner`` is the injectable tpm2 seam (a fake in tests, the real subprocess in production)."""

    def __init__(self, vault_dir, runner: TpmRunner = _default_tpm_runner) -> None:
        self._dir = Path(vault_dir)
        self._runner = runner
        self._kek_cache: Optional[bytes] = None
        # The PREVIOUS KEK — populated ONLY while a rotation's `.prev` blobs exist on disk (a rotation is in
        # progress, or an interrupted one has not been reconciled). It lets a read during the crash window —
        # after the active KEK has been swapped but before every secret file has been re-wrapped — still open
        # a file that is momentarily still under the old KEK, so a rotation never leaves data unreadable.
        # After a rotation COMPLETES the `.prev` blobs are removed and the old KEK no longer decrypts.
        self._prev_kek_cache: Optional[bytes] = None
        self._lock = threading.RLock()

    # --- provisioning + status --------------------------------------------------------------------

    def enabled(self) -> bool:
        """True iff a sealed KEK has been provisioned here (i.e. sealing is ON)."""
        return is_provisioned(self._dir)

    def provision(self) -> None:
        """One-time: generate + TPM-seal a fresh KEK for this machine. Raises :class:`KekError` if the
        TPM is unavailable (fail-closed — never provisions a fake/plaintext KEK). Existing plaintext key
        files are migrated lazily (on their next read), non-destructively."""
        provision_kek(self._dir, runner=self._runner)
        with self._lock:
            self._kek_cache = None  # force a fresh unseal next use

    def status(self) -> str:
        return ("sealed (TPM-sealed KEK)" if self.enabled()
                else "UNSEALED — trust-root keys/secrets are PLAINTEXT at rest; run `sigil vault provision`")

    # --- read / write / migrate -------------------------------------------------------------------

    def _kek(self) -> bytes:
        with self._lock:
            if self._kek_cache is None:
                try:
                    self._kek_cache = load_kek(self._dir, runner=self._runner)
                except KekError as e:
                    raise VaultLocked(f"cannot unseal the KEK from the TPM: {e}") from e
            return self._kek_cache

    def _prev_kek(self) -> Optional[bytes]:
        """The PREVIOUS KEK, loaded from the `.prev` sealed blobs iff they exist (a rotation is in progress
        or was interrupted). ``None`` in the normal, no-rotation state. A `.prev` present but unopenable
        (TPM gone) returns ``None`` — the active KEK is the source of truth; the fallback is best-effort."""
        with self._lock:
            pub = self._dir / (_SEAL_PUB + ".prev")
            priv = self._dir / (_SEAL_PRIV + ".prev")
            if not (pub.exists() and priv.exists()):
                self._prev_kek_cache = None
                return None
            if self._prev_kek_cache is None:
                try:
                    self._prev_kek_cache = load_kek_from(self._dir, _SEAL_PUB + ".prev", _SEAL_PRIV + ".prev",
                                                         runner=self._runner)
                except KekError:
                    return None
            return self._prev_kek_cache

    def _open(self, blob: bytes, *, context: bytes) -> bytes:
        """Unseal ``blob`` under the ACTIVE KEK, falling back to the PREVIOUS KEK ONLY when a rotation's
        `.prev` blobs exist AND the active KEK cannot open it — the crash-window read guarantee that a
        rotation never leaves a secret unreadable. In the normal state (no `.prev`) this is exactly
        ``unseal(active_kek, ...)`` — byte-identical behaviour, no fallback attempted."""
        try:
            return unseal(self._kek(), bytes(blob), context=context)
        except SealError:
            prev = self._prev_kek()
            if prev is not None:
                return unseal(prev, bytes(blob), context=context)  # SealError propagates if this also fails
            raise

    def read_text_secret(self, path, *, context: bytes) -> Optional[str]:
        """Read a UTF-8 secret (e.g. a base64 private key). Transparently unseals a sealed file, or
        returns plaintext (legacy). When the vault is ENABLED and the file is still plaintext, migrate it
        non-destructively first. Returns None if absent/empty. Fail-closed on a sealed file we can't open."""
        p = Path(path)
        try:
            raw = p.read_bytes()
        except OSError:
            return None
        if is_sealed(raw):
            try:
                return self._open(raw, context=context).decode("utf-8")
            except SealError as e:
                raise VaultLocked(f"sealed secret {p.name} failed to open: {e}") from e
        text = raw.decode("utf-8", errors="strict").strip()
        if not text:
            return None
        if self.enabled():
            self._migrate_text(p, text, context)  # opportunistic, non-destructive
        return text

    def write_text_secret(self, path, value: str, *, context: bytes) -> None:
        """Persist a UTF-8 secret — sealed when the vault is enabled, else plaintext (unchanged legacy
        behaviour). Atomic + 0600."""
        p = Path(path)
        if self.enabled():
            blob = seal(self._kek(), value.encode("utf-8"), context=context)
            _atomic_write_bytes(p, blob)
        else:
            _atomic_write_bytes(p, value.encode("utf-8"))

    def seal_secret(self, plaintext: bytes, *, context: bytes) -> bytes:
        """Seal a secret BLOB (not a file) under the vault KEK — for a secret that must ride SEALED inside an
        owner-signed spine record (e.g. an account's TOTP shared secret, which — unlike a one-way-hashed
        bearer — must be RECOVERABLE to verify codes, so it is sealed rather than hashed). Unlike
        :meth:`write_text_secret`, there is NO plaintext fallback: a secret that must be sealed has no
        business landing in the clear, so this REQUIRES the vault provisioned and raises
        :class:`VaultLocked` otherwise (fail-closed). ``context`` binds the blob to its purpose (AEAD AAD)."""
        if not self.enabled():
            raise VaultLocked("vault is not provisioned — cannot seal a secret at rest "
                              "(run `sigil vault provision` once on this machine)")
        return seal(self._kek(), bytes(plaintext), context=context)

    def unseal_secret(self, blob: bytes, *, context: bytes) -> bytes:
        """Open a blob produced by :meth:`seal_secret` under the SAME ``context``. Requires the vault
        provisioned; raises :class:`VaultLocked` if it is not, if the TPM cannot unseal the KEK, or if the
        blob is tampered/wrong-context (fail-closed — never returns an unauthenticated value)."""
        if not self.enabled():
            raise VaultLocked("vault is not provisioned — cannot open a sealed secret")
        try:
            return self._open(bytes(blob), context=context)
        except SealError as e:
            raise VaultLocked(f"sealed secret failed to open: {e}") from e

    def _migrate_text(self, path: Path, text: str, context: bytes) -> None:
        """Seal an existing plaintext secret IN PLACE, non-destructively: seal → VERIFY the sealed copy
        round-trips to the exact original → only THEN atomically replace the plaintext. A migration can
        never lose or corrupt the key. Idempotent (a second call sees a sealed file and no-ops)."""
        kek = self._kek()
        blob = seal(kek, text.encode("utf-8"), context=context)
        if unseal(kek, blob, context=context).decode("utf-8") != text:  # paranoia: prove recoverability
            raise VaultLocked(f"refusing to migrate {path.name}: sealed copy did not round-trip")
        _atomic_write_bytes(path, blob)

    # --- binary secrets (raw-byte key material, e.g. the WARDEN Ed25519 seed) ----------------------

    def read_bytes_secret(self, path, *, context: bytes) -> Optional[bytes]:
        """Read a raw-BYTES secret (e.g. the WARDEN kernel key — 32 raw Ed25519 seed bytes, NOT UTF-8).
        The binary twin of :meth:`read_text_secret`: transparently unseals a sealed file, or returns the
        raw plaintext (legacy). When the vault is ENABLED and the file is still plaintext, migrate it
        non-destructively first. Returns None if absent/empty. Fail-closed on a sealed file it can't open."""
        p = Path(path)
        try:
            raw = p.read_bytes()
        except OSError:
            return None
        if not raw:
            return None
        if is_sealed(raw):
            try:
                return self._open(raw, context=context)
            except SealError as e:
                raise VaultLocked(f"sealed secret {p.name} failed to open: {e}") from e
        if self.enabled():
            self._migrate_bytes(p, raw, context)  # opportunistic, non-destructive
        return raw

    def write_bytes_secret(self, path, value: bytes, *, context: bytes) -> None:
        """Persist a raw-BYTES secret — sealed when the vault is enabled, else plaintext (unchanged legacy
        behaviour). Atomic + 0600."""
        p = Path(path)
        data = bytes(value)
        _atomic_write_bytes(p, seal(self._kek(), data, context=context) if self.enabled() else data)

    def seal_file(self, path, *, context: bytes) -> str:
        """Seal an EXISTING plaintext key file at rest, non-destructively — the fix for a WARDEN kernel key
        the Rust kernel wrote plaintext-0600 even on a TPM host (audit W9-2). Reads the raw bytes, and iff
        the vault is enabled and the file is not already sealed, seals + VERIFIES the sealed copy round-trips
        to the exact original BEFORE atomically replacing the plaintext (a seal can never lose the key).
        Returns a status: ``"sealed"`` / ``"already-sealed"`` / ``"disabled"`` (vault off — left plaintext) /
        ``"absent"`` (no such file). Idempotent."""
        p = Path(path)
        try:
            raw = p.read_bytes()
        except OSError:
            return "absent"
        if not raw:
            return "absent"
        if is_sealed(raw):
            return "already-sealed"
        if not self.enabled():
            return "disabled"
        self._migrate_bytes(p, raw, context)
        return "sealed"

    def _migrate_bytes(self, path: Path, raw: bytes, context: bytes) -> None:
        """Seal an existing plaintext BYTES secret in place, non-destructively (the binary twin of
        :meth:`_migrate_text`): seal → VERIFY it round-trips to the exact original → only THEN atomically
        replace. Idempotent."""
        kek = self._kek()
        blob = seal(kek, raw, context=context)
        if unseal(kek, blob, context=context) != raw:  # paranoia: prove recoverability
            raise VaultLocked(f"refusing to seal {path.name}: sealed copy did not round-trip")
        _atomic_write_bytes(path, blob)

    # --- KEK rotation (verify-then-swap, fail-closed) ---------------------------------------------

    def rotate_kek(self, secret_files, *, embedded_secrets) -> dict:
        """Rotate the TPM-sealed KEK: mint a FRESH KEK, seal it to the TPM, and RE-WRAP every secret file
        that rests under the KEK so each moves from old-KEK custody to new-KEK custody — WITHOUT touching
        the plaintext the files protect (the DEK bytes, the owner/WARDEN key bytes are unchanged, so the
        spine hash-chain and every owner signature stay byte-for-byte intact).

        ``secret_files`` is ``[(path, context), ...]`` — every file sealed under this KEK (the owner private
        key, the spine DEK, the WARDEN kernel key, …), each with the AEAD ``context`` it was sealed under.

        ``embedded_secrets`` (REQUIRED, keyword-only) is ``[(label, blob, context), ...]`` — every secret
        sealed DIRECTLY under this KEK via :meth:`seal_secret` that rides INSIDE the immutable owner-signed
        spine (account TOTP second factors, any other embedded seal), NOT a file on disk. Such a blob's
        ciphertext is signed into the append-only chain, so it CANNOT be re-wrapped in place — re-wrapping
        would change the ciphertext and thus every downstream ``cert_digest``/signature, which only the W9-1
        re-genesis path can re-establish. Therefore this method FAILS CLOSED: if ANY embedded secret is
        present and opens under the CURRENT KEK, the whole rotation is REFUSED (rotating would strip the only
        key that can open it → permanent, silent loss, e.g. an MFA lockout). There is deliberately NO default
        — a caller MUST make an explicit decision; pass ``embedded_secrets=[]`` only when it has PROVEN none
        exist. (This detection is the fix for the red-pen BLOCK: enumerate + refuse, never a printed note.)

        Verify-then-swap, fail-closed (never leave data under a half-rotated key):
          1. refuse if any ``embedded_secrets`` blob is live under the current KEK (see above);
          2. re-wrap every file IN MEMORY under the new KEK, PROVING each (new key opens to the exact
             original; the OLD key no longer opens it — :func:`rotation.rewrap`);
          3. seal the new KEK to the TPM at STAGED blob names and VERIFY it unseals back to the new KEK;
          4. stage every re-wrapped file to ``<path>.rot`` and re-verify it opens under the new KEK;
          5. COMMIT: snapshot the old KEK blobs to ``.prev`` (the crash-window read anchor), swap in the new
             KEK, then swap each re-wrapped file into place, then drop ``.prev`` — after which the OLD KEK no
             longer decrypts anything.
        Any failure BEFORE the commit unlinks all staged artifacts and raises :class:`RotationError`, leaving
        every original untouched under the OLD KEK. During the commit a read of a not-yet-swapped file falls
        back to the ``.prev`` KEK (:meth:`_open`), so an interrupted commit never orphans a secret."""
        if not self.enabled():
            raise RotationError("cannot rotate the KEK — the vault is not provisioned (no KEK to rotate)")
        with self._lock:
            try:
                old_kek = self._kek()
            except VaultLocked as e:
                raise RotationError(f"cannot rotate: the current KEK will not unseal ({e})") from e
            # 1) FAIL-CLOSED on KEK-direct spine-embedded secrets: they cannot be re-wrapped in place (their
            #    ciphertext is signed into the immutable spine), so rotating the KEK would orphan them forever.
            self._refuse_if_embedded_secrets_would_orphan(old_kek, embedded_secrets)
            fresh = new_kek()
            if fresh == old_kek:  # astronomically unlikely; still fail-closed rather than a silent no-op
                raise RotationError("fresh KEK collided with the current KEK — aborting")

            pub_rot, priv_rot = _SEAL_PUB + ".rot", _SEAL_PRIV + ".rot"
            plan: list[tuple[Path, bytes, bytes, bytes]] = []  # (path, context, new_blob, expected_plaintext)
            staged_files: list[Path] = []
            try:
                # 1) re-wrap every existing secret file in memory, with both controls enforced. A file that
                #    cannot be opened/re-wrapped fails the WHOLE rotation (fail-closed) — never a partial roll.
                for path, ctx in secret_files:
                    p = Path(path)
                    try:
                        raw = p.read_bytes()
                    except OSError:
                        continue  # a secret that does not exist yet is simply not rotated
                    if not raw:
                        continue
                    expected = self._open(raw, context=ctx) if is_sealed(raw) else raw
                    new_blob = rewrap_or_seal(old_kek, fresh, raw, context=ctx)  # RotationError on any failure
                    plan.append((p, ctx, new_blob, expected))
                staged_files = [p.with_name(p.name + ".rot") for (p, _c, _b, _e) in plan]
                # 2) seal the fresh KEK to STAGED TPM blobs and prove it unseals back (the TPM leg; a fake
                #    keyring stub in tests, the real tpm2 seal on a provisioned host).
                reseal_kek(self._dir, fresh, runner=self._runner, pub_name=pub_rot, priv_name=priv_rot)
                if load_kek_from(self._dir, pub_rot, priv_rot, runner=self._runner) != fresh:
                    raise RotationError("the freshly-sealed KEK did not unseal back to itself (TPM seal leg failed)")
                # 3) stage every re-wrapped file and re-verify it opens under the new KEK from disk.
                for (p, ctx, new_blob, expected), staged in zip(plan, staged_files):
                    _atomic_write_bytes(staged, new_blob)
                    if not verify_opens_to(fresh, staged.read_bytes(), expected, context=ctx):
                        raise RotationError(f"staged re-wrap of {p.name} did not verify under the new KEK")
            except RotationError:
                self._cleanup_rotation(staged_files, pub_rot, priv_rot)
                raise
            except Exception as e:  # KekError / VaultLocked / SealError / OSError — all fail-closed
                self._cleanup_rotation(staged_files, pub_rot, priv_rot)
                raise RotationError(f"KEK rotation aborted before commit (nothing swapped): {e}") from e

            # 4) COMMIT. Snapshot the old KEK so a read during the swap window can fall back to it.
            shutil.copyfile(self._dir / _SEAL_PUB, self._dir / (_SEAL_PUB + ".prev"))
            shutil.copyfile(self._dir / _SEAL_PRIV, self._dir / (_SEAL_PRIV + ".prev"))
            os.replace(self._dir / pub_rot, self._dir / _SEAL_PUB)
            os.replace(self._dir / priv_rot, self._dir / _SEAL_PRIV)
            self._kek_cache = fresh          # the active KEK is now the fresh one
            self._prev_kek_cache = old_kek   # reads of not-yet-swapped files fall back to this
            for (p, _ctx, _blob, _exp), staged in zip(plan, staged_files):
                os.replace(staged, p)
            # every file is now under the new KEK — retire the old one so it no longer decrypts.
            for suffix in (".prev",):
                for name in (_SEAL_PUB, _SEAL_PRIV):
                    try:
                        (self._dir / (name + suffix)).unlink()
                    except OSError:
                        pass
            self._prev_kek_cache = None
            return {"rotated": len(plan), "files": [str(p) for (p, _c, _b, _e) in plan]}

    def _refuse_if_embedded_secrets_would_orphan(self, old_kek: bytes, embedded_secrets) -> None:
        """Fail-closed guard (red-pen BLOCK): a KEK-direct secret that lives INSIDE the immutable owner-signed
        spine (an :meth:`seal_secret` blob — e.g. an account TOTP second factor) cannot be re-wrapped in place,
        so rotating the KEK out from under it would render it permanently unrecoverable. If ANY supplied
        ``embedded_secrets`` blob is sealed AND opens under the current KEK, REFUSE the whole rotation and name
        the offenders. A blob that is not sealed, or does not open under the current KEK, is not a live secret
        this rotation would orphan and is skipped. Malformed input is refused (fail-closed)."""
        orphaned: list[str] = []
        for entry in embedded_secrets:
            try:
                label, blob, ctx = entry
                b = bytes(blob)
            except (TypeError, ValueError) as e:
                raise RotationError(f"embedded-secret entry must be (label, blob, context) bytes: {e}") from e
            if not is_sealed(b):
                continue
            try:
                unseal(old_kek, b, context=bytes(ctx))
            except SealError:
                continue  # not openable under the current KEK — not a live secret this rotation would orphan
            orphaned.append(str(label))
        if orphaned:
            raise RotationError(
                f"refusing to rotate the KEK: {len(orphaned)} spine-embedded secret(s) are sealed DIRECTLY "
                f"under it and cannot be re-wrapped in place (their ciphertext is signed into the immutable "
                f"owner-signed spine) — rotating would PERMANENTLY orphan them (e.g. account TOTP second "
                f"factors → silent MFA lockout, no recovery). Disable/re-enroll them, or re-key via the W9-1 "
                f"re-genesis path. Offending secrets: [{', '.join(sorted(orphaned))}]")

    # --- crash reconciliation (an interrupted commit must never leave the OLD KEK valid forever) --------

    def rotation_incomplete(self) -> bool:
        """True iff a ``.prev`` KEK anchor is present on disk — a KEK rotation swapped in the new KEK but was
        interrupted before it retired the old one. Until reconciled the OLD KEK still decrypts (resurrection),
        and some files may still rest under it. A cheap disk check for the doctor posture / boot reconciler."""
        return ((self._dir / (_SEAL_PUB + ".prev")).exists()
                and (self._dir / (_SEAL_PRIV + ".prev")).exists())

    def reconcile_kek_rotation(self, secret_files, *, embedded_secrets=()) -> dict:
        """Finish an interrupted KEK rotation (red-pen HIGH: an interrupted commit leaves the OLD KEK valid
        forever, undetected). If a ``.prev`` anchor is present, re-wrap every secret FILE that still rests
        under the OLD (``.prev``) KEK to the ACTIVE KEK — proving each — and only then DELETE ``.prev`` so the
        old KEK can no longer decrypt anything. Run from the CLI (``sigil key reconcile``); it is NOT yet
        auto-invoked at boot / ``vigil up`` — an incomplete rotation is SURFACED (doctor reports
        key-sealing=INCOMPLETE and ``sigil key status`` prints a warning) but an operator must run it.

        Idempotent + fail-closed: no ``.prev`` → no-op; a file that cannot be re-wrapped/proven, or the
        ``.prev`` KEK being unreadable while a file still needs it, ABORTS and leaves ``.prev`` in place (the
        fallback stays, nothing is orphaned) rather than dropping the old key. Defence-in-depth: refuses to
        retire ``.prev`` while any ``embedded_secrets`` blob still opens ONLY under it (rotate_kek already
        refuses those pre-commit, so this can only bite a hand-corrupted state — still fail-closed)."""
        if not self.rotation_incomplete():
            return {"reconciled": 0, "status": "clean"}
        with self._lock:
            try:
                active = self._kek()
            except VaultLocked as e:
                raise RotationError(f"cannot reconcile: the active KEK will not unseal ({e})") from e
            reconciled: list[str] = []
            for path, ctx in secret_files:
                p = Path(path)
                try:
                    raw = p.read_bytes()
                except OSError:
                    continue
                if not raw or not is_sealed(raw):
                    continue
                try:
                    unseal(active, raw, context=ctx)
                    continue  # already under the active KEK — nothing to do
                except SealError:
                    pass
                prev = self._prev_kek()
                if prev is None:
                    raise RotationError(f"reconcile aborted: {p.name} is not under the active KEK and the "
                                        f"`.prev` KEK is unreadable — keeping `.prev` (fail-closed)")
                try:
                    expected = unseal(prev, raw, context=ctx)
                    new_blob = rewrap_or_seal(prev, active, raw, context=ctx)
                except (SealError, RotationError) as e:
                    raise RotationError(f"reconcile aborted re-wrapping {p.name} to the active KEK "
                                        f"(keeping `.prev`): {e}") from e
                staged = p.with_name(p.name + ".rot")
                _atomic_write_bytes(staged, new_blob)
                if not verify_opens_to(active, staged.read_bytes(), expected, context=ctx):
                    try:
                        staged.unlink()
                    except OSError:
                        pass
                    raise RotationError(f"reconcile aborted: re-wrap of {p.name} did not verify under the "
                                        f"active KEK (keeping `.prev`)")
                os.replace(staged, p)
                reconciled.append(str(p))
            # Every file now opens under the active KEK. Before retiring `.prev`, refuse if any embedded secret
            # still opens ONLY under it (would be orphaned by dropping the fallback).
            self._refuse_if_embedded_orphaned_by_dropping_prev(active, embedded_secrets)
            for name in (_SEAL_PUB, _SEAL_PRIV):
                try:
                    (self._dir / (name + ".prev")).unlink()
                except OSError:
                    pass
            self._prev_kek_cache = None
            return {"reconciled": len(reconciled), "files": reconciled, "status": "completed"}

    def _refuse_if_embedded_orphaned_by_dropping_prev(self, active: bytes, embedded_secrets) -> None:
        """Refuse to retire ``.prev`` if any embedded secret is sealed and opens ONLY under the ``.prev`` KEK
        (not under the active KEK) — dropping ``.prev`` would orphan it. Fail-closed."""
        prev = self._prev_kek()
        if prev is None:
            return
        orphaned: list[str] = []
        for entry in embedded_secrets:
            try:
                label, blob, ctx = entry
                b, c = bytes(blob), bytes(ctx)
            except (TypeError, ValueError) as e:
                raise RotationError(f"embedded-secret entry must be (label, blob, context) bytes: {e}") from e
            if not is_sealed(b):
                continue
            try:
                unseal(active, b, context=c)
                continue  # safe: already under the active KEK
            except SealError:
                pass
            try:
                unseal(prev, b, context=c)
            except SealError:
                continue  # opens under neither — not orphaned by dropping `.prev`
            orphaned.append(str(label))
        if orphaned:
            raise RotationError(
                f"reconcile aborted: {len(orphaned)} spine-embedded secret(s) open only under the `.prev` KEK "
                f"— retiring it would orphan them (e.g. TOTP → MFA lockout). Keeping `.prev` (fail-closed). "
                f"Offending secrets: [{', '.join(sorted(orphaned))}]")

    def _cleanup_rotation(self, staged_files, pub_rot: str, priv_rot: str) -> None:
        """Best-effort removal of every staged rotation artifact after a pre-commit failure — the originals
        are untouched, so this just tidies the aborted attempt (fail-closed: nothing was swapped)."""
        for staged in staged_files:
            try:
                Path(staged).unlink()
            except OSError:
                pass
        for name in (pub_rot, priv_rot):
            try:
                (self._dir / name).unlink()
            except OSError:
                pass
