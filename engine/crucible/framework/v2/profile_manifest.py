"""
profile_manifest — the stdlib source of truth for the engagement-PROFILE roster artifact.

``engage --profile {surface,deep,full}`` is a PURE flag-expansion convenience: it flips EXISTING
``enable_*`` opt-in flags, adds NO oracle, relaxes NO safety gate, and fabricates NO finding. So that the
roster a run actually exercised is AUDITABLE after the fact, ``run_engagement`` records the resolved profile
name, the exact resolved ``enable_*`` flag set, and any plan-named packs that have no flag yet (deferred to a
later wave) to a FRAMEWORK-OWNED, stdlib-readable run-dir artifact ``<run_dir>/_engagement_profile.json``.

This mirrors the ``inconclusive_manifest`` / proof-degradation contract exactly: a framework-owned run-dir
JSON file written atomically and read back with the Python stdlib only. FATAL-2 clean — this module imports
only the stdlib; a console/dossier consumer reads the same file through :func:`read_profile_manifest`.

DETERMINISTIC. Canonical JSON (``sort_keys``), no wall-clock / rng, atomic tmp + ``os.replace`` swap, so two
runs with the same profile + roster produce byte-identical bytes and a torn write never leaves a half file.

RUN-DIR-GATED. The artifact is written only when a run dir is resolvable (the console exports one via
``$VIGIL_PROOF_RUN_DIR``; a hand-run CLI engage with no console has none). Absent run dir => nothing written
=> byte-identical, exactly like the inconclusive manifest.

SCHEMA  <run_dir>/_engagement_profile.json  ==
    {"profile": "<surface|deep|full>",
     "flags": {"enable_browser_xss": <bool>, "enable_domxss": <bool>, ...},   # the FULL resolved roster
     "deferred_packs": ["<pack>", ...]}                                       # plan-named, no flag yet (sorted)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# The run-dir artifact filename (the single constant every producer/reader keys on).
PROFILE_ARTIFACT = "_engagement_profile.json"


def write_profile_manifest(run_dir: Any, profile: str, flags: Any, deferred: Any = ()) -> bool:
    """Persist the resolved engagement ``profile`` + its exact ``flags`` roster (a mapping of
    ``enable_*`` name -> bool) + the plan-named ``deferred`` packs (no flag yet) to
    ``<run_dir>/_engagement_profile.json`` (see the SCHEMA above). Deterministic (canonical JSON, no
    wall-clock/rng) and atomic (tmp + ``os.replace``). Best-effort/total: any error returns False and never
    raises into the engage pass. Returns True iff the file was written.

    Written whenever a run dir is resolvable — INCLUDING ``surface`` (recording the default roster is still
    an audit fact). A falsy ``run_dir`` => no write (byte-identical), so ``make gate`` (which sets no run
    dir) is untouched."""
    try:
        if not run_dir:
            return False
        flags_map = {str(k): bool(v) for k, v in dict(flags or {}).items()}
        deferred_list = sorted({str(p) for p in (deferred or ()) if str(p).strip()})
        doc = {
            "profile": str(profile or "surface"),
            "flags": flags_map,
            "deferred_packs": deferred_list,
        }
        d = Path(run_dir)
        d.mkdir(parents=True, exist_ok=True)
        path = d / PROFILE_ARTIFACT
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)         # atomic swap
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return True
    except Exception:
        return False


def read_profile_manifest(run_dir: Any) -> dict:
    """Read ``<run_dir>/_engagement_profile.json`` (stdlib only; never trusts the producer). Returns::

        {"present": bool,                 # a parseable artifact EXISTS
         "profile": str,                  # "" when absent / unparseable
         "flags": {name: bool, ...},      # {} when absent / unparseable
         "enabled_flags": [name, ...],    # sorted subset of flags that are True
         "deferred_packs": [pack, ...]}   # sorted

    Absent / empty / unparseable => a byte-identical empty reading (present=False). Never raises."""
    out = {"present": False, "profile": "", "flags": {}, "enabled_flags": [], "deferred_packs": []}
    try:
        path = Path(run_dir) / PROFILE_ARTIFACT
        if not path.is_file():
            return out
        raw = path.read_text(encoding="utf-8")
        if not raw.strip():
            return out
        try:
            doc = json.loads(raw)
        except ValueError:
            return out
        if not isinstance(doc, dict):
            return out
        flags = doc.get("flags")
        flags_map = {str(k): bool(v) for k, v in flags.items()} if isinstance(flags, dict) else {}
        deferred = doc.get("deferred_packs")
        deferred_list = sorted({str(p) for p in deferred}) if isinstance(deferred, list) else []
        out.update({
            "present": True,
            "profile": str(doc.get("profile") or ""),
            "flags": flags_map,
            "enabled_flags": sorted(k for k, v in flags_map.items() if v),
            "deferred_packs": deferred_list,
        })
        return out
    except OSError:
        return out
    except Exception:
        return out
