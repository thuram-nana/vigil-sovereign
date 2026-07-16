"""sensors.android_manifest — ingest a raw (decoded) AndroidManifest.xml into mobile posture LEADS.

The SOUND, offline capture feed for the mobile-posture oracle's ``exported_content_provider`` rule. The
adversarial soundness map ruled that re-deriving an unguarded exported component from MobSF's *summarised*
findings would be string-trust; the manifest XML is a SELF-CONTAINED artifact CRUCIBLE can parse itself
(exactly like the workflow YAML and the cert), so the oracle re-derives the weakness from the literal
attributes. Tier-1, offline (reads a LOCAL decoded ``AndroidManifest.xml`` — e.g. ``apktool d`` output —
no network, no APK unpacking), kill-switch-gated via ``sensors.pipeline.run_sensor``.

It mints one ``APPLICATION`` node + one ``CONTROL`` LEAD per ``<provider>``, keyed
``mobile:component:provider:<name>`` (the SAME ``mobile:`` namespace + parsed shape as ``sensors.mobile``,
so it reuses ``mobsf_observations`` and the SAME ``engage_fusion._reverify_mobile`` promotion path). The
mobile-posture oracle promotes a lead to a FACT ONLY for a provider EXPLICITLY ``android:exported="true"``
with ZERO permission guards; a guarded or non-explicitly-exported provider stays an honest LEAD. Pure +
total: a malformed manifest is a non-ingestion, never a crash.
"""

from __future__ import annotations

import os
from xml.etree import ElementTree  # noqa: S405 — parse only; entities bounded + never fetched (see run())

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Observation
from .mobile import mobsf_observations

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_MAX_BYTES = 8 * 1024 * 1024   # bound the read (a manifest is tiny; caps a pathological/expansion blob)
_MAX_PROVIDERS = 500


def _attr(elem: ElementTree.Element, name: str) -> str | None:
    """An ``android:`` namespaced attribute (ElementTree expands the prefix to the full NS URI), falling
    back to the bare name for a namespace-less manifest fragment."""
    return elem.get(_ANDROID_NS + name) if elem.get(_ANDROID_NS + name) is not None else elem.get(name)


def parse_android_manifest(text: str) -> dict:
    """Parse a decoded ``AndroidManifest.xml`` into ``{app, controls, urls}`` (the ``sensors.mobile``
    shape). One control per ``<provider>``, retaining the LITERAL export + guard attributes the oracle
    re-derives. PURE + total — invalid XML / an unknown shape yields ``{}``, never an exception."""
    if not isinstance(text, str) or "<manifest" not in text:
        return {}
    # Defense-in-depth: a real (decoded) AndroidManifest NEVER carries a DTD/entity declaration, so reject
    # one outright — this makes the XXE / entity-expansion safety EXPLICIT rather than leaning on the
    # runtime expat's (version-dependent) billion-laughs guard and no-external-fetch default.
    low = text.lower()
    if "<!doctype" in low or "<!entity" in low:
        return {}
    try:
        root = ElementTree.fromstring(text)   # ET (py3) never fetches external entities; input is bounded
    except Exception:
        return {}
    package = (root.get("package") or "").strip()
    if not package:
        return {}
    controls: list[dict] = []
    for i, p in enumerate(root.iter("provider")):
        if len(controls) >= _MAX_PROVIDERS:
            break
        name = (_attr(p, "name") or f"provider_{i}").strip()
        has_path_perm = any(c.tag.rsplit("}", 1)[-1] == "path-permission" for c in p)
        controls.append({
            "check_id": f"component:provider:{name}", "category": "manifest",
            "rule": "exported_content_provider", "name": name,
            "title": f"exported content provider {name}", "severity": "warning",
            "exported": _attr(p, "exported"), "permission": _attr(p, "permission"),
            "read_permission": _attr(p, "readPermission"),
            "write_permission": _attr(p, "writePermission"),
            "has_path_permission": has_path_perm,
        })
    app = {"package": package, "name": package, "version": ""}
    return {"app": app, "controls": controls, "urls": []}


class AndroidManifestSensor:
    """Ingest an operator-provided decoded ``AndroidManifest.xml`` and mint mobile posture LEADS. args:
    ``{"manifest": "/path/to/AndroidManifest.xml"}``. Passive (Tier-1): reads a local file, no network,
    no APK unpacking, no entitlement — kill-switch-gated via ``sensors.pipeline.run_sensor``. The leads
    STOP here; the mobile-posture oracle re-verifies an EXPLICITLY-exported unguarded content provider to
    a FACT. Reuses the ``sensors.mobile`` observation minter + fusion path."""

    name = "android_manifest"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path = args.get("manifest") if isinstance(args, dict) else None
        if not path or not isinstance(path, str):
            return ToolResult(ok=False, note="android_manifest requires args['manifest'] (an AndroidManifest.xml path)")
        if not os.path.isfile(path):
            return ToolResult(ok=False, note=f"android_manifest: manifest not found: {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(_MAX_BYTES)
        except OSError as e:
            return ToolResult(ok=False, note=f"android_manifest: could not read manifest: {e}")
        parsed = parse_android_manifest(text)
        n = len(parsed.get("controls") or [])
        return ToolResult(ok=True, summary=f"android_manifest: {n} provider(s)", output={"parsed": parsed})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        parsed = out.get("parsed")
        if not isinstance(parsed, dict):
            return []
        return mobsf_observations(parsed, seq=seq, source="android_manifest")
