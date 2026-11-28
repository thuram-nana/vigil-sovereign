"""Adversarial tests for the customer KNOWLEDGE upload content-safety gate (``sigil.tenant_knowledge.content_safety``
wired into ``store.ingest_document``). This is the highest-risk customer input surface - a customer uploads a document
that VIGIL parses / chunks / embeds / persists - so the defences are proven here by construction, fail-closed:

  * STRUCTURAL ALLOWLIST - a body whose MAGIC bytes mark it an executable / archive / compressed / Office-OLE / PDF /
    image / media / font / database is REFUSED, by its bytes (never a spoofable extension), with NOTHING written;
  * STRICT TEXT - a NUL byte, a control-dense blob, or a body that does not decode cleanly as UTF-8 / UTF-16 is refused
    (the old lossy ``decode(errors="replace")`` hole is closed); valid UTF-8 / markdown / CSV is accepted and indexed;
  * SANITISER - a bidi-override / zero-width / Trojan-Source payload is stripped out of the stored chunk + snippet and
    the text is NFC-normalised, so nothing invisible reaches a vector or a citation;
  * CAPS - an oversized body and a document that chunks past the chunk cap are refused with nothing written;
  * the SCAN HOOK - a configured scanner that reports an infection, errors, or times out REFUSES the upload
    (fail-closed); unconfigured it is a no-op and the structural defences still apply;
  * ISOLATION - a rejected upload writes NOTHING to the org's per-org spine or index, and never touches another tenant.

Offense-free (FATAL-2): the module is pure stdlib + sigil.config; a subprocess probe asserts no offense module loads.

Fakes mirror ``test_customer_knowledge`` - an in-memory bag-of-words embedder + index, so the heavy local deps
(onnxruntime / qdrant-client) are never needed and a rejected write is observable as 'no rows, no spine record'.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import subprocess
import sys
import types

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)

from sigil import config
from sigil import tenant_knowledge as tk
from sigil.spine.store import SpineStore
from sigil.tenant_knowledge import content_safety as cs
from sigil.tenant_knowledge import store as TKS
from sigil.tenant_knowledge.store import KnowledgeCapError, KnowledgeError

_SCAN_ENV = "VIGIL_CUSTOMER_KNOWLEDGE_SCAN_CMD"


# ---------------------------------------------------------------------------- in-memory fake embed + index -------

def _vec(text: str) -> "list[float]":
    v = [0.0] * config.EMBED_DIM
    for w in set(re.findall(r"[a-z0-9]+", text.lower())):
        v[int(hashlib.sha256(w.encode()).hexdigest(), 16) % config.EMBED_DIM] += 1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


class _FakeIndex:
    def __init__(self, registry: dict, path, collection: str) -> None:
        self.rows = registry.setdefault(str(path), [])

    def upsert(self, points):
        ids = {p[0] for p in points}
        self.rows[:] = [r for r in self.rows if r[0] not in ids] + list(points)
        return len(points)

    def search(self, qv, k):
        def cos(a, b):
            return sum(x * y for x, y in zip(a, b))
        scored = sorted(((cos(qv, vec), pl) for _id, vec, pl in self.rows), key=lambda x: -x[0])
        return [{"score": s, **pl} for s, pl in scored[:k] if s >= TKS.MIN_SCORE]


@pytest.fixture()
def corpus(tmp_path, monkeypatch):
    """Per-org corpora under tmp (never the shared SIGIL_HOME); a fresh fake-backend registry we can inspect to prove
    a rejected upload wrote NOTHING to the org's index."""
    monkeypatch.setattr(config, "CUSTOMER_KNOWLEDGE_DIR", tmp_path / "knowledge")
    reg: dict = {}
    be = {"embed_passages": lambda ts: [_vec(t) for t in ts], "embed_query": _vec,
          "open_index": lambda path, coll: _FakeIndex(reg, path, coll)}
    return types.SimpleNamespace(be=be, reg=reg, tmp=tmp_path)


def _spine_doc_count(org: str) -> int:
    p = tk.corpus_root(org) / "spine" / "spine.jsonl"
    if not p.exists():
        return 0
    return sum(1 for r in SpineStore(p).iter_records() if r.kind == "document")


def _index_rows(c, org: str) -> list:
    return c.reg.get(str(tk.corpus_root(org) / "qdrant"), [])


def _assert_nothing_written(c, org: str) -> None:
    assert _spine_doc_count(org) == 0, "a rejected upload must write NO document record to the per-org spine"
    assert _index_rows(c, org) == [], "a rejected upload must write NO vector into the per-org index"


# ===================================================================== 1. the magic-byte structural allowlist =====

# label -> a representative body carrying that type's real magic signature. These are REJECTED by structure because a
# text corpus has no use for any of them; each is only ever a smuggling / exploitation vector.
_MAGIC_BODIES = {
    "exe-mz":      b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff",       # DOS/PE
    "exe-elf":     b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # ELF
    "exe-macho":   b"\xfe\xed\xfa\xce\x00\x00\x00\x07\x00\x00\x00\x03",         # Mach-O (BE32)
    "exe-macho-fat": b"\xca\xfe\xba\xbe\x00\x00\x00\x02\x01\x00\x00\x07",       # Mach-O fat / Java class
    "exe-shebang": b"#!/bin/sh\nrm -rf / --no-preserve-root\n",                 # shebang script
    "zip":         b"PK\x03\x04\x14\x00\x00\x00\x08\x00payloaddata",            # ZIP/JAR/OOXML (docx/xlsx)
    "zip-empty":   b"PK\x05\x06\x00\x00\x00\x00\x00\x00",                       # ZIP end-of-central-dir
    "zip-spanned": b"PK\x07\x08\x00\x00\x00\x00\x00\x00",                       # ZIP spanned
    "gzip":        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03",                 # GZIP
    "bzip2":       b"BZh91AY&SY\x00\x00",                                       # BZIP2
    "xz":          b"\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4",                         # XZ
    "7z":          b"7z\xbc\xaf\x27\x1c\x00\x04\x00\x00",                       # 7-Zip
    "rar":         b"Rar!\x1a\x07\x00\xcf\x90s\x00",                            # RAR v4
    "zstd":        b"\x28\xb5\x2f\xfd\x00\x58\x00\x00",                         # Zstandard
    "tar":         b"./evil.sh".ljust(257, b"\x00") + b"ustar\x0000" + b"\x00" * 100,  # TAR ustar @257
    "ole":         b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 24,          # OLE/CFB (legacy .doc/.xls macro)
    "pdf":         b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj",                      # PDF
    "png":         b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01",      # PNG
    "jpeg":        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01",                     # JPEG
    "gif":         b"GIF89a\x01\x00\x01\x00\x80",                               # GIF
    "bmp":         b"BM\x8a\x00\x00\x00\x00\x00\x00\x00",                       # BMP
    "ico":         b"\x00\x00\x01\x00\x01\x00\x10\x10",                         # ICO
    "riff-webp":   b"RIFF\x24\x00\x00\x00WEBPVP8 ",                             # RIFF/WEBP
    "ogg":         b"OggS\x00\x02\x00\x00\x00\x00\x00\x00",                     # OGG
    "mp3-id3":     b"ID3\x03\x00\x00\x00\x00\x00\x21",                          # MP3 (ID3)
    "mp4-ftyp":    b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00",                 # MP4
    "woff":        b"wOFF\x00\x01\x00\x00\x00\x00\x01\x00",                     # WOFF
    "woff2":       b"wOF2\x00\x01\x00\x00\x00\x00\x01\x00",                     # WOFF2
    "ttf":         b"\x00\x01\x00\x00\x00\x0c\x00\x80\x00\x03",                 # TrueType
    "otf":         b"OTTO\x00\x0c\x00\x80\x00\x03",                            # OpenType
    "sqlite":      b"SQLite format 3\x00" + b"\x00" * 32,                       # SQLite DB
}


@pytest.mark.parametrize("label", sorted(_MAGIC_BODIES))
def test_each_magic_type_is_refused_with_nothing_written(corpus, label):
    body = _MAGIC_BODIES[label]
    # classify recognises it as a non-text binary (not 'text')
    assert cs.classify(body) != "text"
    with pytest.raises(KnowledgeError):
        tk.ingest_document("acme", f"{label}.txt", body, **corpus.be)   # a .txt EXTENSION cannot smuggle it in
    _assert_nothing_written(corpus, "acme")


def test_refusal_names_the_reason_but_never_echoes_the_bytes(corpus):
    # an honest, customer-facing refusal: it names WHY (a category) and never leaks the uploaded content back.
    secret = b"SECRET-TOKEN-ZZZ"
    with pytest.raises(KnowledgeError) as ei:
        cs.assert_allowed(b"MZ" + secret, "x.txt")
    msg = str(ei.value)
    assert "executable" in msg and "SECRET-TOKEN-ZZZ" not in msg


def test_magic_is_matched_by_bytes_not_filename_extension(corpus):
    # the same ELF body refused regardless of a benign-looking name; a real .txt with that content is still refused.
    for name in ("a.txt", "a.md", "a.csv", "notes"):
        with pytest.raises(KnowledgeError):
            tk.ingest_document("acme", name, _MAGIC_BODIES["exe-elf"], **corpus.be)
    _assert_nothing_written(corpus, "acme")


# ===================================================================== 2. strict-text validation =================

def test_nul_byte_is_refused(corpus):
    body = b"a perfectly ordinary looking sentence\x00with an embedded nul byte"
    assert b"\x00" in body
    with pytest.raises(KnowledgeError, match="NUL"):
        tk.ingest_document("acme", "nul.txt", body, **corpus.be)
    _assert_nothing_written(corpus, "acme")


def test_high_control_ratio_blob_is_refused(corpus):
    # valid single-byte UTF-8, no NUL, but dense with C0 control characters (not tab/newline/CR) => obfuscated binary.
    body = b"A" + bytes([0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x0b, 0x0c, 0x0e, 0x0f, 0x10, 0x11])
    assert b"\x00" not in body
    with pytest.raises(KnowledgeError, match="control"):
        tk.ingest_document("acme", "ctrl.txt", body, **corpus.be)
    _assert_nothing_written(corpus, "acme")


def test_tab_newline_cr_do_not_count_as_control(corpus):
    # a document that is ALL legitimate whitespace structure is admitted (none of \t \n \r trips the control ratio).
    body = ("col1\tcol2\r\n" + "value\tvalue\r\n" * 40).encode("utf-8")
    out = tk.ingest_document("acme", "table.tsv", body, **corpus.be)
    assert out["chunks"] >= 1 and _spine_doc_count("acme") >= 1


def test_invalid_utf8_is_refused_strictly_not_mangled(corpus):
    # 0xC3 0x28 is an invalid 2-byte UTF-8 sequence (NOT a BOM start, so it is decoded as UTF-8, strictly).
    body = b"legitimate looking prose \xc3\x28 and more text after the bad byte"
    # the OLD lossy path would have SILENTLY accepted this (the hole we closed):
    assert body.decode("utf-8", errors="replace")  # lossy decode "succeeds" with a replacement char
    with pytest.raises(KnowledgeError, match="valid UTF-8"):
        tk.ingest_document("acme", "bad.txt", body, **corpus.be)
    _assert_nothing_written(corpus, "acme")


def test_lone_continuation_byte_is_refused(corpus):
    with pytest.raises(KnowledgeError, match="valid UTF-8"):
        tk.ingest_document("acme", "bad2.txt", b"text then a stray \x80 byte", **corpus.be)
    _assert_nothing_written(corpus, "acme")


@pytest.mark.parametrize("name,body", [
    ("markdown.md", b"# Security Runbook\n\nEscalate incidents to the on-call engineer immediately.\n"),
    ("hosts.csv", b"host,role\nweb01,frontend\ndb01,database\ncache01,redis\n"),
    ("plain.txt", b"Our organization uses hardware security keys and single sign-on for every administrator."),
    ("unicode.txt", "résumé café naïve — accented prose is fine".encode("utf-8")),
])
def test_valid_text_is_accepted_and_indexed(corpus, name, body):
    out = tk.ingest_document("acme", name, body, **corpus.be)
    assert out["chunks"] >= 1 and out["filename"] == name
    assert _spine_doc_count("acme") >= 1
    assert _index_rows(corpus, "acme"), "accepted text must be embedded into the per-org index"


def test_utf16_le_and_be_with_bom_are_accepted(corpus):
    text = "incident response runbook escalate to the security engineer on call"
    tk.ingest_document("acme", "u16le.txt", b"\xff\xfe" + text.encode("utf-16-le"), **corpus.be)
    tk.ingest_document("acme", "u16be.txt", b"\xfe\xff" + text.encode("utf-16-be"), **corpus.be)
    names = {d["filename"] for d in tk.list_documents("acme", **corpus.be)["documents"]}
    assert {"u16le.txt", "u16be.txt"} <= names


# ===================================================================== 3. the Unicode sanitiser ===================

def test_bidi_and_zero_width_payload_is_sanitised_out_of_the_stored_chunk(corpus):
    # a Trojan-Source style payload: bidi override + isolates + zero-width, interleaved with real words.
    # built from chr() so NO invisible character appears in this source file (ruff PLE2502/PLE2515-clean)
    bidi = {"rlo": chr(0x202E), "pop": chr(0x202C), "zwsp": chr(0x200B), "zwnj": chr(0x200C),
            "zwj": chr(0x200D), "lri": chr(0x2066), "pdi": chr(0x2069), "bom": chr(0xFEFF)}
    payload = ("quarterly finance review {rlo} reversed-section {pop} "
               "zero{zwsp}width{zwnj}joiners{zwj} and {lri}isolate{pdi} end-marker {bom} bom").format(**bidi)
    tk.ingest_document("acme", "trojan.md", payload.encode("utf-8"), **corpus.be)
    spine = tk.corpus_root("acme") / "spine" / "spine.jsonl"
    store = SpineStore(spine)
    stored = [store.decrypted(r).payload["text"] for r in store.iter_records() if r.kind == "document"]
    assert stored, "the document was accepted (its visible text is fine) and chunked"
    for chunk in stored:
        assert not any(ord(ch) in cs._STRIP_CODEPOINTS for ch in chunk), "no zero-width / bidi control may survive"
        for bad in bidi.values():
            assert bad not in chunk
    # the real words survive the sanitiser
    joined = " ".join(stored)
    assert "quarterly" in joined and "finance" in joined and "end-marker" in joined
    # the index snippet is sanitised too (nothing invisible reaches a citation)
    for _id, _vec, payload_dict in _index_rows(corpus, "acme"):
        assert not any(ord(ch) in cs._STRIP_CODEPOINTS for ch in payload_dict["text"])


def test_sanitizer_nfc_normalises_and_keeps_whitespace():
    decomposed = "café \t line\n next\r end"   # 'e' + combining acute U+0301
    out = cs.sanitize_text(decomposed)
    assert "café" in out                          # composed to NFC U+00E9
    assert "́" not in out
    assert "\t" in out and "\n" in out and "\r" in out  # legitimate whitespace preserved


def test_sanitizer_strips_controls_and_nul_but_is_inert_on_clean_text():
    assert cs.sanitize_text("plain readable text") == "plain readable text"
    assert "\x00" not in cs.sanitize_text("a\x00b")
    assert cs.sanitize_text("a\x01\x07\x1f\x7f\x9bb") == "ab"


# ===================================================================== 4. decode_text + classify units ===========

def test_decode_text_strips_bom_and_decodes_utf16():
    assert cs.decode_text(b"\xef\xbb\xbfcaf\xc3\xa9") == "café"      # UTF-8 BOM consumed
    assert cs.decode_text(b"\xff\xfe" + "hi".encode("utf-16-le")) == "hi"
    assert cs.decode_text(b"\xfe\xff" + "hi".encode("utf-16-be")) == "hi"


def test_decode_text_is_strict():
    with pytest.raises(KnowledgeError):
        cs.decode_text(b"bad \xc3\x28 byte")


def test_classify_labels():
    assert cs.classify(b"") == "empty"
    assert cs.classify(b"plain ascii text") == "text"
    assert cs.classify(b"\x89PNG\r\n\x1a\n") == "png"
    assert cs.classify(b"\xff\xd8\xff\xe0") == "jpeg"
    assert cs.classify(b"\x80\x81\x82 not utf8 no signature") == "binary"


# ===================================================================== 5. the caps (size + chunk) =================

def test_oversized_body_is_refused_with_nothing_written(corpus, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_KNOWLEDGE_MAX_DOC_BYTES", "32")
    with pytest.raises(KnowledgeCapError, match="too large"):
        tk.ingest_document("acme", "big.txt", b"x" * 33, **corpus.be)
    _assert_nothing_written(corpus, "acme")


def test_chunk_cap_is_enforced_with_nothing_written(corpus, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_KNOWLEDGE_MAX_CHUNKS", "2")
    # small in bytes, but chunks into far more than 2 pieces (the pathological under-byte-cap case)
    body = ("alpha bravo charlie delta echo foxtrot " * 400).encode("utf-8")
    assert len(body) < config.customer_knowledge_max_doc_bytes()
    with pytest.raises(KnowledgeCapError, match="too many chunks"):
        tk.ingest_document("acme", "fragmented.txt", body, **corpus.be)
    _assert_nothing_written(corpus, "acme")


def test_chunk_cap_default_allows_an_ordinary_document(corpus):
    out = tk.ingest_document("acme", "ordinary.txt", ("word " * 2000).encode("utf-8"), **corpus.be)
    assert out["chunks"] <= config.customer_knowledge_max_chunks()


# ===================================================================== 6. the fail-closed malware-scan hook =======

def _write_scanner(tmp_path, name: str, script: str):
    p = tmp_path / name
    p.write_text(script)
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR | stat.S_IWUSR)
    return p


def test_scan_unconfigured_is_a_noop_but_structural_checks_still_apply(corpus, monkeypatch):
    monkeypatch.delenv(_SCAN_ENV, raising=False)
    assert config.customer_knowledge_scan_cmd() == []
    # unconfigured: valid text flows through
    assert tk.ingest_document("acme", "ok.txt", b"an ordinary organization document", **corpus.be)["chunks"] >= 1
    # ...yet a binary is STILL refused (the always-on structural allowlist does not depend on a scanner)
    with pytest.raises(KnowledgeError):
        tk.ingest_document("acme", "mz.txt", _MAGIC_BODIES["exe-mz"], **corpus.be)


def test_scan_rejects_infection_and_writes_nothing(corpus, monkeypatch, tmp_path):
    scanner = _write_scanner(tmp_path, "av_infected.sh", "#!/bin/sh\ncat >/dev/null\nexit 1\n")
    monkeypatch.setenv(_SCAN_ENV, str(scanner))
    with pytest.raises(KnowledgeError, match="malware scanner"):
        tk.ingest_document("acme", "doc.txt", b"this is otherwise perfectly valid text", **corpus.be)
    _assert_nothing_written(corpus, "acme")


def test_scan_actually_receives_the_bytes_on_stdin(corpus, monkeypatch, tmp_path):
    # a scanner that exits non-zero ONLY when the stdin content carries a marker proves the body is piped to it.
    scanner = _write_scanner(tmp_path, "av_marker.sh", "#!/bin/sh\nif grep -q EICARMARK; then exit 1; fi\nexit 0\n")
    monkeypatch.setenv(_SCAN_ENV, str(scanner))
    # clean content passes the scanner (exit 0) and is ingested
    assert tk.ingest_document("acme", "clean.txt", b"benign organization onboarding notes", **corpus.be)["chunks"] >= 1
    # content carrying the marker is refused by the scanner (exit 1)
    with pytest.raises(KnowledgeError, match="malware scanner"):
        tk.ingest_document("acme", "evil.txt", b"contains the EICARMARK token inline", **corpus.be)


def test_scan_fails_closed_when_the_scanner_binary_is_missing(corpus, monkeypatch, tmp_path):
    monkeypatch.setenv(_SCAN_ENV, str(tmp_path / "does_not_exist.sh"))
    with pytest.raises(KnowledgeError, match="could not be malware-scanned"):
        tk.ingest_document("acme", "doc.txt", b"valid text that never gets to be written", **corpus.be)
    _assert_nothing_written(corpus, "acme")


def test_scan_fails_closed_on_timeout(corpus, monkeypatch, tmp_path):
    scanner = _write_scanner(tmp_path, "av_slow.sh", "#!/bin/sh\nsleep 30\n")
    monkeypatch.setenv(_SCAN_ENV, str(scanner))
    monkeypatch.setattr(cs, "_SCAN_TIMEOUT_SECONDS", 0.5)   # shrink the budget so the test is fast
    with pytest.raises(KnowledgeError, match="could not be malware-scanned"):
        tk.ingest_document("acme", "doc.txt", b"valid text that the slow scanner never clears", **corpus.be)
    _assert_nothing_written(corpus, "acme")


def test_scan_clean_scanner_allows_valid_text(corpus, monkeypatch, tmp_path):
    scanner = _write_scanner(tmp_path, "av_clean.sh", "#!/bin/sh\ncat >/dev/null\nexit 0\n")
    monkeypatch.setenv(_SCAN_ENV, str(scanner))
    out = tk.ingest_document("acme", "doc.txt", b"a clean organization policy document", **corpus.be)
    assert out["chunks"] >= 1 and _spine_doc_count("acme") >= 1


def test_malformed_scan_cmd_fails_closed_not_off(monkeypatch):
    # A SET-but-unparseable scanner command must RAISE (so ingest fails closed), never silently return OFF: an
    # operator that configured a scanner must never have it downgraded to a no-op by a typo, ingesting unscanned bytes.
    monkeypatch.setenv(_SCAN_ENV, 'clamscan "unbalanced')   # unbalanced quote => cannot parse to an argv
    with pytest.raises(config.ScanCmdError):
        config.customer_knowledge_scan_cmd()


def test_ingest_refuses_when_scan_cmd_is_misconfigured(corpus, monkeypatch):
    # End-to-end: a misconfigured (set-but-unparseable) scanner refuses the upload (fail closed) and writes nothing,
    # even for otherwise-valid text - the configured-but-broken scanner does not let the document through.
    monkeypatch.setenv(_SCAN_ENV, 'clamscan "unbalanced')
    with pytest.raises(KnowledgeError, match="could not be malware-scanned"):
        tk.ingest_document("acme", "doc.txt", b"otherwise perfectly valid organization text", **corpus.be)
    _assert_nothing_written(corpus, "acme")


# ===================================================================== 7. isolation under rejection ==============

def test_a_rejected_upload_never_touches_another_tenant(corpus):
    # org B holds a real document; a rejected (binary) upload for org A writes nothing anywhere and leaves B intact.
    tk.ingest_document("globex", "real.txt", b"globex production network topology notes", **corpus.be)
    assert _spine_doc_count("globex") == 1
    with pytest.raises(KnowledgeError):
        tk.ingest_document("acme", "mal.txt", _MAGIC_BODIES["zip"], **corpus.be)
    _assert_nothing_written(corpus, "acme")
    assert _spine_doc_count("globex") == 1                  # the other tenant is untouched
    assert len(_index_rows(corpus, "globex")) == 1


def test_sequential_rejections_leave_a_pristine_corpus(corpus):
    for label in ("exe-elf", "pdf", "sqlite", "gzip"):
        with pytest.raises(KnowledgeError):
            tk.ingest_document("acme", f"{label}.txt", _MAGIC_BODIES[label], **corpus.be)
    with pytest.raises(KnowledgeError, match="NUL"):
        tk.ingest_document("acme", "nul.txt", b"text\x00text", **corpus.be)
    _assert_nothing_written(corpus, "acme")
    assert tk.list_documents("acme", **corpus.be)["count"] == 0


# ===================================================================== 8. FATAL-2 (offense-free content_safety) ===

def test_content_safety_is_offense_free_fatal2():
    probe = (
        "import sys; import sigil.tenant_knowledge.content_safety as c; "
        "c.assert_allowed(b'plain text body', 'f.txt'); "
        "c.sanitize_text('x'); c.classify(b'x'); "
        "bad=[m for m in sys.modules if m in ('framework','strix') or m.startswith(('framework.','strix.'))]; "
        "assert not bad, bad; print('ok')"
    )
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env=env)
    assert out.returncode == 0 and "ok" in out.stdout, out.stderr
