"""
Tests for the Android-manifest posture sensor (decoded AndroidManifest.xml offline ingest).

A decoded ``AndroidManifest.xml`` is ingested (offline) as a gated sensor → provider CONTROL LEADS
(``GROUNDING_INTEL``), never facts. The sensor STOPS at leads; the mobile-posture oracle
(``verify.mobile_posture``) re-verifies a lead to a FACT only for an EXPLICITLY exported unguarded content
provider — wired through ``engage_fusion`` (``test_engage_fusion.py``). Mirrors ``test_cicd_sensor``.
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.agents.tools import ToolContext
from framework.v2.sensors import AndroidManifestSensor, parse_android_manifest
from framework.v2.sensors.builtin import register_builtin_sensors
from framework.v2.agents.tools.base import ToolRegistry
from framework.v2.worldmodel.models import NodeKind

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.app">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
  <application>
    <provider android:name="com.demo.Unguarded" android:exported="true" android:authorities="com.demo.a"/>
    <provider android:name="com.demo.Guarded" android:exported="true" android:permission="com.demo.PERM"/>
    <provider android:name="com.demo.NotExported" android:exported="false"/>
    <activity android:name="com.demo.Main"/>
  </application>
</manifest>"""


def test_parse_extracts_package_and_providers():
    p = parse_android_manifest(_MANIFEST)
    assert p["app"]["package"] == "com.demo.app"
    # 3 <provider> elements (the <activity> is not a provider)
    assert len(p["controls"]) == 3
    unguarded = next(c for c in p["controls"] if c["name"] == "com.demo.Unguarded")
    assert unguarded["rule"] == "exported_content_provider" and unguarded["exported"] == "true"
    assert unguarded["permission"] is None
    guarded = next(c for c in p["controls"] if c["name"] == "com.demo.Guarded")
    assert guarded["permission"] == "com.demo.PERM"


def test_parse_is_total_on_garbage_and_no_package():
    assert parse_android_manifest("not xml at all") == {}
    assert parse_android_manifest("<manifest></manifest>") == {}       # no package attr → nothing
    assert parse_android_manifest("<other package='x'/>") == {}        # not a manifest


def test_dtd_or_entity_declaration_is_rejected():
    # defense-in-depth: a decoded AndroidManifest never has a DTD/entity; reject one (XXE / billion-laughs)
    bomb = ('<?xml version="1.0"?><!DOCTYPE manifest [<!ENTITY a "x">]>'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">'
            '<application><provider android:name="P" android:exported="true"/></application></manifest>')
    assert parse_android_manifest(bomb) == {}
    xxe = ('<!DOCTYPE m [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x"/>')
    assert parse_android_manifest(xxe) == {}


def test_path_permission_child_is_detected():
    m = ("""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">"""
         """<application><provider android:name="P" android:exported="true">"""
         """<path-permission android:pathPrefix="/x" android:permission="com.x.P"/>"""
         """</provider></application></manifest>""")
    ctl = parse_android_manifest(m)["controls"][0]
    assert ctl["has_path_permission"] is True


def test_normalize_mints_provider_leads_in_the_mobile_namespace():
    s = AndroidManifestSensor()
    ctx = ToolContext(slug="alpha")
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.write(fd, _MANIFEST.encode())
    os.close(fd)
    try:
        res = s.run({"manifest": path}, ctx)
        assert res.ok and res.summary == "android_manifest: 3 provider(s)"
        obs = s.normalize(res, ctx, seq=1)
        controls = [o for o in obs if o.subject.kind is NodeKind.CONTROL]
        # leads land in the shared mobile: namespace (so they reuse the mobile fusion path)
        assert controls and all(o.subject.key.startswith("mobile:component:provider:") for o in controls)
        assert all(o.attrs.get("unverified") is True for o in controls)     # a lead, never a fact
    finally:
        os.unlink(path)


def test_sensor_missing_and_absent_manifest_degrade_cleanly():
    ctx = ToolContext(slug="alpha")
    assert not AndroidManifestSensor().run({}, ctx).ok
    assert not AndroidManifestSensor().run({"manifest": "/no/such/AndroidManifest.xml"}, ctx).ok


def test_registered_in_default_registry():
    reg = register_builtin_sensors(ToolRegistry())
    assert "android_manifest" in reg
