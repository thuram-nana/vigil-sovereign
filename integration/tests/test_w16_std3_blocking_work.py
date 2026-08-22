"""W16-STD-3 residual (blocking-work markers) — #529.

The clear-win security fixes of #529 landed in this slice and are proved elsewhere:
  * (1) `authorize-destruction` is single-use via O_EXCL — `test_destruction_provision.py`
        (`test_write_single_use_authorization_*`).
  * (3) the spine segment manifest is signed + tamper-refused — `apps/sigil/tests/test_spine_manifest_signature.py`.
  * (4) `LocalTSA` is documented honestly as a CAPABILITY (not independence) and `RemoteTSA` (a third-party
        RFC3161 URL) is the supported independence path — see `time_anchor.py` (pre-existing, unchanged).

Two residuals are deliberately NOT closed in this slice and are tracked here as xfail so they stay visible
in a required CI job (they xPASS the moment they are implemented):

  (2) OWNER-ROOT the offense usage-ledger + attestation log. They are already hash-chained, signed (operator
      key), durable-head-pinned and anti-rollback anchored — an entry cannot be silently forged/rewritten.
      Binding them to the OWNER key specifically is constrained by the two-env boundary (the offense plane
      deliberately holds NO owner private key), so it needs an owner-delegated signer flowed across the
      boundary — a larger change than this slice. Related: [W9-1] #434 (owner-root + rotation).

  (4b) Make the PRODUCTION posture actively warn/require an external TSA (today the honest limitation is
      documented and RemoteTSA is available, but nothing forces external-TSA in a production profile).
"""
from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="#529 (2): owner-key binding of the offense ledgers is blocking-work (two-env "
                          "boundary — offense holds no owner key); needs an owner-delegated signer (W9-1 #434)",
                   strict=False)
def test_offense_usage_ledger_is_owner_key_rooted():
    from vigil_integration.live import wiring
    # A marker the owner-root wiring will expose when the offense ledgers are bound to an owner-delegated key.
    assert getattr(wiring, "OFFENSE_LEDGER_OWNER_ROOTED", False)


@pytest.mark.xfail(reason="#529 (4b): a production posture that WARNS/REQUIRES an external TSA is blocking-work "
                          "(LocalTSA is honestly documented + RemoteTSA supported today)",
                   strict=False)
def test_production_posture_requires_external_tsa():
    from vigil_integration import time_anchor
    # A guard the production profile will expose to refuse/warn on a LocalTSA-only anchor.
    assert hasattr(time_anchor, "require_external_tsa")
