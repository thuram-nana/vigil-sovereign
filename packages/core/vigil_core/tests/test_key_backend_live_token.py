"""LIVE PKCS#11 token exercise for the hardware owner-key backend (W9-6, issue #439).

THE IRREDUCIBLE RESIDUAL, HONESTLY LABELLED. This is the ONLY part of W9-6 that a hosted CI runner cannot
run: it drives the real ``open_pkcs11_signer`` against an actual PKCS#11 provider (an HSM / YubiKey, or a
SoftHSM2 token for a dev exercise). It is SKIPPED unless BOTH are true:

  * the ``pkcs11`` python binding is importable (``importorskip``), and
  * ``VIGIL_PKCS11_LIVE=1`` is set AND ``VIGIL_PKCS11_MODULE`` points at a provider ``.so`` holding an
    Ed25519 key object labelled by ``VIGIL_PKCS11_KEY_LABEL`` (default ``owner``).

To run it against SoftHSM2 locally (a documented dev exercise, not a CI job):

    softhsm2-util --init-token --free --label vigil-token --so-pin 1234 --pin 1234
    # import/generate an Ed25519 key object labelled `owner` on that token, then:
    VIGIL_PKCS11_LIVE=1 \
      VIGIL_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
      VIGIL_PKCS11_TOKEN_LABEL=vigil-token VIGIL_PKCS11_KEY_LABEL=owner VIGIL_PKCS11_PIN=1234 \
      pytest packages/core/vigil_core/tests/test_key_backend_live_token.py -q

The fail-closed selection logic and the no-private-material guarantee are proven WITHOUT hardware in
``test_key_backend.py``; this only confirms the real token round-trips end-to-end.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("pkcs11", reason="python-pkcs11 binding not installed (hardware residual)")

from vigil_core import verify_one  # noqa: E402
from vigil_core.key_backend import BACKEND_ENV, Pkcs11Backend, select_owner_backend  # noqa: E402

_LIVE = os.environ.get("VIGIL_PKCS11_LIVE", "").strip() in ("1", "true", "yes")
_MODULE = os.environ.get("VIGIL_PKCS11_MODULE", "").strip()

pytestmark = pytest.mark.skipif(
    not (_LIVE and _MODULE),
    reason="live PKCS#11 token not provisioned (set VIGIL_PKCS11_LIVE=1 + VIGIL_PKCS11_MODULE=...)",
)


def test_live_token_signs_and_verifies_under_its_own_public_key():
    env = dict(os.environ)
    env[BACKEND_ENV] = env.get(BACKEND_ENV, "pkcs11")
    backend = select_owner_backend(env=env)
    assert isinstance(backend, Pkcs11Backend)
    assert backend.holds_private_material is False

    msg = b"vigil/W9-6 live-token owner authorization"
    sig = backend.sign(msg)
    # the signature verifies under the public key the token reports — the token signed, in-process code
    # never held the private scalar.
    assert verify_one(backend.public_key_b64, msg, sig)
