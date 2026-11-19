#!/usr/bin/env python3
"""The reference HTML→PDF renderer for VIGIL's customer report export (PR-G, Area 6) — an OPS-LAYER tool.

It belongs to NO VIGIL environment: the customer/sovereign venv never installs a renderer (``ui/report_pdf`` refuses a
renderer that lives inside it). The owner provisions it in its own environment, for example:

    python3 -m venv /opt/vigil-report-renderer
    /opt/vigil-report-renderer/bin/pip install weasyprint
    install -m 0755 tools/report_pdf/render_pdf.py /opt/vigil-report-renderer/bin/vigil-render-pdf
    sed -i '1s|.*|#!/opt/vigil-report-renderer/bin/python|' /opt/vigil-report-renderer/bin/vigil-render-pdf

and then sets ``VIGIL_REPORT_PDF_RENDERER=/opt/vigil-report-renderer/bin/vigil-render-pdf`` in the cockpit environment.
(``ui/report_pdf`` also refuses a renderer that its group or others may write, so keep the 0755 mode and a root- or
owner-only directory.)

The contract (``ui/report_pdf``): the report HTML on stdin, the PDF on stdout, exit 0. It fetches NOTHING — the report
is self-contained, so every URL but an inline base64 ``data:`` image is refused, and that one is decoded here (no
network, no file access). WeasyPrint runs no JavaScript. Exit 3: the renderer library is not installed in this
environment; exit 4: the document could not be rendered. Nothing is written to stdout on failure.
"""
from __future__ import annotations

import base64
import binascii
import re
import sys

# data:<image mime>;base64,<payload> — the only URL form the report carries (its wordmark).
_DATA_URI = re.compile(r"data:(image/(?:svg\+xml|png|jpeg|gif|webp));base64,([A-Za-z0-9+/=\s]*)", re.ASCII)
_MAX_DATA_BYTES = 2 * 1024 * 1024


def no_fetch(url, *args, **kwargs) -> dict:
    """WeasyPrint's ``url_fetcher``: decode an inline base64 ``data:`` image; refuse EVERY other URL (http(s), file,
    ftp, a relative path, a non-base64 or non-image data: URI) — the report never needs one."""
    m = _DATA_URI.fullmatch(str(url))
    if m is None:
        raise ValueError("the VIGIL report renderer fetches no URL")
    try:
        raw = base64.b64decode("".join(m.group(2).split()), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("the VIGIL report renderer refuses a malformed data: URI") from None
    if len(raw) > _MAX_DATA_BYTES:
        raise ValueError("the VIGIL report renderer refuses an oversized data: URI")
    return {"string": raw, "mime_type": m.group(1), "redirected_url": str(url)}


def main() -> int:
    try:
        from weasyprint import HTML
    except Exception:  # noqa: BLE001 — the library is absent or broken in this environment
        sys.stderr.write("vigil-render-pdf: weasyprint is not installed in this renderer's environment\n")
        return 3
    try:
        doc = sys.stdin.buffer.read().decode("utf-8")
        pdf = HTML(string=doc, url_fetcher=no_fetch).write_pdf()
    except Exception as exc:  # noqa: BLE001 — any render failure is one clean refusal
        sys.stderr.write(f"vigil-render-pdf: the report could not be rendered ({type(exc).__name__})\n")
        return 4
    sys.stdout.buffer.write(pdf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
