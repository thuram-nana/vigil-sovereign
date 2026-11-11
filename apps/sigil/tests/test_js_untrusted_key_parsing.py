"""CQ-1 — two client-side parsers of USER-CONTROLLED key/value text never write an inherited property
(CodeQL js/remote-property-injection). Both are executed from their own shipped source under node.

  * ``packages/vigil-ui/app.js`` ``hashQuery()`` keeps only the keys the app reads (run / tab / id / slug), each
    written under the app's OWN constant name — a ``__proto__`` / ``constructor`` / unknown key is dropped;
  * the public CVSS calculator's ``parseVector()`` only ever keys its result by a metric id from its OWN
    ORDER list, and only with a value that metric allows.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_VUI = _ROOT / "packages" / "vigil-ui" / "app.js"
_CVSS = _ROOT / "apps" / "sigil" / "sigil" / "ui" / "public_site" / "tools" / "cvss-calculator" / "cvss.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _slice(src: str, start: str, end_after: str) -> str:
    i = src.index(start)
    return src[i:src.index(end_after, i) + len(end_after)]


def _node(prog: str):
    r = subprocess.run(["node", "-e", prog], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_hash_query_keeps_only_the_keys_the_app_reads():
    src = _VUI.read_text(encoding="utf-8")
    fn = _slice(src, "  const HASH_KEYS = ", "\n    return out;\n  }")
    prog = ("var location = {hash: '#/run?run=abc&__proto__=x&constructor=y&polluted=1&tab&id=7&slug=s%2F1'};\n"
            + fn + "\nconst q = hashQuery();\n"
            "process.stdout.write(JSON.stringify({q, keys: Object.keys(q), protoSame: Object.getPrototypeOf(q) ==="
            " Object.prototype, clean: ({}).polluted === undefined && ({}).x === undefined}));")
    got = _node(prog)
    assert got["q"] == {"run": "abc", "tab": "", "id": "7", "slug": "s/1"}    # what every caller reads, unchanged
    assert got["keys"] == ["run", "tab", "id", "slug"]                      # __proto__ / constructor / unknown dropped
    assert got["protoSame"] is True and got["clean"] is True
    # every caller reads ONLY a kept key
    import re
    reads = set(re.findall(r"hashQuery\(\)\)?\.(\w+)", src)) | {"run", "tab", "id"}
    assert reads <= {"run", "tab", "id", "slug"}, reads


def test_cvss_parse_vector_keys_only_by_its_own_metric_ids():
    src = _CVSS.read_text(encoding="utf-8")
    head = _slice(src, "  var METRICS = [", "return o[0]; }); });")
    fn = _slice(src, "  function parseVector(str) {", "\n    return sel;\n  }")
    prog = (head + "\n" + fn + "\nconst out = [\n"
            " parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),\n"
            " parseVector('AV:N/__PROTO__:X/CONSTRUCTOR:Y/__proto__:N/AV:Z/ZZ:N/av:l'),\n"
            "];\nprocess.stdout.write(JSON.stringify({out, clean: ({}).X === undefined && ({}).N === undefined}));")
    got = _node(prog)
    assert got["out"][0] == {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    assert got["out"][1] == {"AV": "L"}                                # only real ids with allowed values
    assert got["clean"] is True
