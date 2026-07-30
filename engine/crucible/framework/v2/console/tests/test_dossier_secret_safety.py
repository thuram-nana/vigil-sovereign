"""Red-pen BLOCK regression: `vigil dossier --session` must NOT ship operator secrets in the clear.

A URL with HTTP basic-auth (extremely common as a pentest target) or a pasted token, stored as a VALUE
under a non-secret key (chat text, a session/thread target, a graph node label), must be redacted in EVERY
exported artifact — including index.html — by the value-level redactor that complements the key-name masker.
"""
from __future__ import annotations

import json
import zipfile

from framework.v2.report.dossier import build_session_dossier


def test_no_secret_leaks_into_the_session_dossier(tmp_path):
    chat = tmp_path / "chat.jsonl"
    chat.write_text(json.dumps({
        "role": "user",
        "text": "scan http://admin:s3cr3t@10.0.0.5/ with token sk-live-ABCD1234",
        "target": "http://admin:s3cr3t@10.0.0.5/",
    }) + "\n")
    out = tmp_path / "d.zip"
    build_session_dossier(
        session_id="sess1", run_dirs=[], out_zip=str(out), engagement_slug="eng",
        session_meta={"id": "sess1", "slug": "eng", "name": "http://admin:s3cr3t@10.0.0.5/", "run_ids": []},
        chat_transcript=str(chat),
        graph={"nodes": [{"label": "http://admin:s3cr3t@10.0.0.5/"}], "edges": []},
        open_threads=[{"run_id": "r1", "status": "running", "target": "http://admin:s3cr3t@10.0.0.5/"}],
    )
    z = zipfile.ZipFile(out)
    for name in z.namelist():
        data = z.read(name).decode("utf-8", "replace")
        assert "s3cr3t" not in data, f"password leaked in the clear into {name}"
        assert "sk-live-ABCD1234" not in data, f"token leaked in the clear into {name}"
    # the host is preserved (useful for the handoff); only the credential is stripped.
    chat_out = z.read("session/chat-transcript.jsonl").decode("utf-8")
    assert "10.0.0.5" in chat_out and "[redacted]" in chat_out
