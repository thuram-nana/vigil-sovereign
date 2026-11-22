"""PR-G (Area 6) — the PDF leg of the report export: the deterministic HTML report (``ui/report_export``) handed to
an owner/ops-provisioned HTML→PDF renderer that lives OUTSIDE the customer venv.

VIGIL-LIMIT:LIMIT-report-pdf-renderer-unprovisioned — the renderer is an ops-layer dependency the owner provisions
(a headless renderer in its own environment, e.g. ``tools/report_pdf/render_pdf.py`` in a dedicated venv). Until the
owner sets ``VIGIL_REPORT_PDF_RENDERER`` to it, the PDF export REFUSES (fail-closed) and the HTML report — which is
complete on its own — stays the download. The sovereign venv never imports or installs a renderer (FATAL-2 and
dependency hygiene: a renderer is a large native dependency the customer plane must not carry).

THE CONTRACT with the renderer: an absolute path to ONE executable; the report HTML on its stdin; the PDF on its
stdout; exit 0. It runs with a fixed argv (no shell), a minimal environment, a private temporary working directory, a
wall-clock timeout (its whole process group is killed on expiry) and an output-size cap, and its output must be a PDF
(``%PDF-`` header, ``%%EOF`` trailer). Before it runs, the path must resolve to a regular executable file that is not
group- or world-writable and is NOT inside the running (customer) venv. Every refusal is a ``ReportPdfUnavailable``
whose message is customer-safe (never the path, never the renderer's output).

FATAL-2: sovereign-side — stdlib only; ``assert_no_offense`` at import. It touches no target and mints nothing.
"""
from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from ..reuse import assert_no_offense

assert_no_offense()

PDF_CONTENT_TYPE = "application/pdf"
RENDER_TIMEOUT_S = 20.0               # one render, wall clock (the edge's hop for the PDF action outwaits it)
MAX_PDF_BYTES = 20 * 1024 * 1024      # a report PDF larger than this is refused, never relayed
_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
_UNSET = "PDF export is not set up on this deployment — download the HTML report instead"


class ReportPdfUnavailable(RuntimeError):
    """The PDF could not be produced: no renderer provisioned, a renderer that fails a check, or a render that failed,
    timed out or returned something that is not a PDF. The message is customer-safe."""


def _inside(path: Path, root: str) -> bool:
    try:
        path.relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def renderer_path() -> Path:
    """The provisioned renderer, checked: ``config.report_pdf_renderer()`` is set, absolute, resolves to a regular
    executable file that no group/other may write, and lies OUTSIDE the running venv. Raises ``ReportPdfUnavailable``
    (fail-closed) on any miss."""
    from .. import config
    raw = config.report_pdf_renderer()
    if not raw:
        raise ReportPdfUnavailable(_UNSET)
    p = Path(raw)
    if not p.is_absolute():
        raise ReportPdfUnavailable("the PDF renderer is misconfigured (its path must be absolute)")
    try:
        real = p.resolve(strict=True)
        st = real.stat()
    except OSError:
        raise ReportPdfUnavailable("the PDF renderer is not installed where it is configured") from None
    if not stat.S_ISREG(st.st_mode) or not os.access(real, os.X_OK):
        raise ReportPdfUnavailable("the PDF renderer is not an executable file")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ReportPdfUnavailable("the PDF renderer is writable by others, so it is not trusted")
    if sys.prefix != sys.base_prefix and _inside(real, sys.prefix):
        raise ReportPdfUnavailable("the PDF renderer must live outside the customer environment")
    return real


def _kill_group(proc: "subprocess.Popen") -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)       # start_new_session: the renderer leads its own process group
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        pass


def render_pdf(html_text: str, *, timeout_s: float = RENDER_TIMEOUT_S, max_bytes: int = MAX_PDF_BYTES) -> bytes:
    """The PDF of ``html_text`` from the provisioned renderer (see the module docstring for the contract). Raises
    ``ReportPdfUnavailable`` on every failure — never returns partial or non-PDF bytes."""
    exe = renderer_path()
    with tempfile.TemporaryDirectory(prefix="vigil-report-") as td:
        src, dst = Path(td) / "report.html", Path(td) / "report.pdf"
        src.write_bytes(html_text.encode("utf-8"))
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            try:
                proc = subprocess.Popen([str(exe)], stdin=fin, stdout=fout, stderr=subprocess.DEVNULL, cwd=td,
                                        env={**_ENV, "HOME": td, "TMPDIR": td}, close_fds=True,
                                        start_new_session=True)
            except OSError:
                raise ReportPdfUnavailable("the PDF renderer could not be started") from None
            try:
                rc = proc.wait(timeout=float(timeout_s))
            except subprocess.TimeoutExpired:
                _kill_group(proc)
                raise ReportPdfUnavailable("the PDF renderer took too long") from None
        if rc != 0:
            raise ReportPdfUnavailable(f"the PDF renderer failed (exit {rc})")
        size = dst.stat().st_size
        if size == 0 or size > int(max_bytes):
            raise ReportPdfUnavailable("the PDF renderer returned an empty or oversized document")
        data = dst.read_bytes()
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
        raise ReportPdfUnavailable("the PDF renderer returned something that is not a PDF")
    return data
