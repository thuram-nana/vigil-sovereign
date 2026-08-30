"""The `meridian` entry in the loopback-range manifest is well-formed and points at a runnable target."""

from __future__ import annotations

import importlib.util
import os
import sys

from conftest import REPO_ROOT


def _load_range_targets():
    path = os.path.join(REPO_ROOT, "tools", "livefire", "range_targets.py")
    spec = importlib.util.spec_from_file_location("range_targets_under_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclass field resolution looks the module up in sys.modules
    spec.loader.exec_module(mod)
    return mod


def test_manifest_validates_with_meridian_registered():
    rt = _load_range_targets()
    manifest = rt.Manifest()
    manifest.validate()  # raises on any malformed target, incl. a process target with no script
    target = manifest.get("meridian")
    assert target.kind == "process"
    assert target.script == "range/meridian_target.py"
    assert target.http_port == 19010
    assert target.ready["marker"] == "MERIDIAN National Permits"


def test_registered_script_exists_and_is_the_target_launcher():
    script = os.path.join(REPO_ROOT, "range", "meridian_target.py")
    assert os.path.isfile(script)
    body = open(script, encoding="utf-8").read()
    assert "vigil_range.meridian.__main__" in body
