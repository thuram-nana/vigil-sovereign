"""AS-2i (sovereign leg) — the AEGIS tenant-MONITORING seam subtree is a DOCUMENTED exclusion in the sovereign
backup coverage contract.

By default the AEGIS publish/secrets dirs live UNDER the cross-plane seam (``<SIGIL_HOME>/credit-lease``, which
is already excluded here), so the sovereign leg never captures them. This classifies the ``aegis`` top-level
name EXCLUDED so that if an override (VIGIL_MONITORING_PUBLISH_DIR / VIGIL_MONITORING_SECRETS_DIR, or
VIGIL_BASE_DIR pointed at SIGIL_HOME) ever places ``aegis/`` directly under SIGIL_HOME, it is a documented
drop (never captured, never resurrected on restore) and the structural coverage test stays honest — fail-closed.

    PYTHONPATH=apps/sigil:packages/core/vigil_core python -m pytest \\
        apps/sigil/tests/test_backup_aegis_exclusion.py -q
"""
from __future__ import annotations

from sigil import backup
from vigil_core.aegis_seam import AEGIS_SEAM_SUBDIR


def test_aegis_seam_is_a_documented_exclusion():
    assert AEGIS_SEAM_SUBDIR in backup.EXCLUDED_TOP_LEVEL
    assert backup.classify_top_level(AEGIS_SEAM_SUBDIR) == "excluded"
    reason = backup._EXCLUSION_REASONS[AEGIS_SEAM_SUBDIR]
    assert "AS-2i" in reason and "monitoring" in reason.lower()      # the documented reason, not a silent skip


def test_aegis_seam_is_never_captured():
    assert AEGIS_SEAM_SUBDIR not in backup.CAPTURED_TOP_LEVEL
