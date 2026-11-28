"""Content-safety gate for the customer KNOWLEDGE upload path - the highest-risk customer input surface.

A customer uploads a document that VIGIL then parses / chunks / embeds / persists into that org's own corpus. The
corpus indexes **TEXT only** (a chunk of prose becomes a vector + a signed spine record). Therefore ANYTHING that is
not clean, inert text has no legitimate place here, and a binary / archive / PDF / Office / executable body is only ever
a smuggling or exploitation vector. This module is the always-on, FAIL-CLOSED structural defence that enforces that
invariant at the server, before any decode / chunk / spine write - the client is NEVER trusted.

Three always-on structural defences (pure stdlib, no network, no shell, no third-party parser):

  1. a MAGIC-BYTE reject-list (:func:`assert_allowed`) - a body whose leading bytes match a known executable / archive
     / compressed / Office-OLE / PDF / image / media / font / database signature is refused OUTRIGHT, by its bytes, not
     by a (spoofable) filename extension. We reject by structure because the store has no use for any of those types.
  2. a STRICT TEXT validator (:func:`assert_allowed` -> :func:`decode_text`) - the body must decode cleanly as UTF-8 (or
     UTF-16 LE/BE via a BOM) with NO lossy replacement; a NUL byte in the decoded text is refused, and a body whose
     fraction of C0/C1 control characters (tab/newline/carriage-return excluded) exceeds :data:`_MAX_CONTROL_RATIO` is
     refused. This is what stops obfuscated binary smuggled as "text" and the lossy ``decode(errors="replace")`` hole.
  3. a UNICODE SANITISER (:func:`sanitize_text`) - before indexing, NULs and C0/C1 controls (keeping tab/newline/CR),
     zero-width characters and bidi override/isolate controls are stripped and the text is NFC-normalised, so a
     Trojan-Source / zero-width payload can never reach a chunk, a vector, or a citation snippet.

Plus one FAIL-CLOSED, optional plug point:

  4. a malware-scan hook (:func:`scan`) - when an external scanner is configured (``config.customer_knowledge_scan_cmd``
     / ``VIGIL_CUSTOMER_KNOWLEDGE_SCAN_CMD``, e.g. ClamAV ``clamdscan -`` / ``clamscan -``), the raw bytes are piped to
     it on stdin under a bounded timeout with NO shell; the upload is refused if the scanner reports an infection
     (non-zero exit) OR if it errors / times out (a configured-but-broken scanner must never let an upload through).
     When unconfigured it is a documented no-op - the structural allowlist + strict-text validator are always on.

FATAL-2: ``assert_no_offense()`` at import. Pure stdlib (``subprocess`` + ``unicodedata``) plus ``sigil.config`` and the
corpus error types; it imports NO offense-plane module (``framework`` / ``strix``).
"""
from __future__ import annotations

import subprocess
import unicodedata

from ..reuse import assert_no_offense

assert_no_offense()

from .. import config
from .store import KnowledgeError

__all__ = ["classify", "assert_allowed", "decode_text", "sanitize_text", "scan"]

# --------------------------------------------------------------------------------------- the magic-byte reject-list --
# Each row is (label, family, offset, signature). ``label`` is the specific diagnostic tag :func:`classify` returns;
# ``family`` is the customer-facing category named in a refusal (never the raw bytes); the body is rejected when
# ``data[offset:offset+len(signature)] == signature``. These are REJECTED (not allowed) because the knowledge corpus
# indexes plain TEXT only - an executable / archive / PDF / Office / image / media / font / database has no place in a
# text corpus and is only ever a smuggling or exploitation vector. The table is explicit and byte-literal on purpose.
_SIGNATURES: "list[tuple[str, str, int, bytes]]" = [
    # --- executables / loadable code ------------------------------------------------------------------------------
    ("exe-mz",       "an executable",              0, b"\x4d\x5a"),                      # DOS/PE "MZ"
    ("exe-elf",      "an executable",              0, b"\x7f\x45\x4c\x46"),              # ELF "\x7fELF"
    ("exe-macho-32", "an executable",              0, b"\xfe\xed\xfa\xce"),              # Mach-O 32 (BE)
    ("exe-macho-64", "an executable",              0, b"\xfe\xed\xfa\xcf"),              # Mach-O 64 (BE)
    ("exe-macho-le32", "an executable",            0, b"\xce\xfa\xed\xfe"),              # Mach-O 32 (LE)
    ("exe-macho-le64", "an executable",            0, b"\xcf\xfa\xed\xfe"),              # Mach-O 64 (LE)
    ("exe-macho-fat", "an executable",             0, b"\xca\xfe\xba\xbe"),              # Mach-O fat / Java class
    ("exe-shebang",  "an executable script",       0, b"\x23\x21"),                      # "#!" shebang
    # --- archives / compressed streams ----------------------------------------------------------------------------
    ("zip",          "an archive or compressed file", 0, b"\x50\x4b\x03\x04"),           # ZIP/JAR/OOXML local header
    ("zip-empty",    "an archive or compressed file", 0, b"\x50\x4b\x05\x06"),           # ZIP end-of-central-dir
    ("zip-spanned",  "an archive or compressed file", 0, b"\x50\x4b\x07\x08"),           # ZIP spanned
    ("gzip",         "an archive or compressed file", 0, b"\x1f\x8b"),                    # GZIP
    ("bzip2",        "an archive or compressed file", 0, b"\x42\x5a\x68"),                # BZIP2 "BZh"
    ("xz",           "an archive or compressed file", 0, b"\xfd\x37\x7a\x58\x5a\x00"),    # XZ
    ("7z",           "an archive or compressed file", 0, b"\x37\x7a\xbc\xaf\x27\x1c"),    # 7-Zip
    ("rar",          "an archive or compressed file", 0, b"\x52\x61\x72\x21\x1a\x07"),    # RAR "Rar!\x1a\x07"
    ("zstd",         "an archive or compressed file", 0, b"\x28\xb5\x2f\xfd"),            # Zstandard
    ("tar",          "an archive or compressed file", 257, b"\x75\x73\x74\x61\x72"),      # TAR "ustar" @257
    # --- Office / OLE compound (macro vector) ---------------------------------------------------------------------
    ("ole",          "an Office or OLE document",   0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),  # CFB/OLE2 (.doc/.xls)
    # --- documents ------------------------------------------------------------------------------------------------
    ("pdf",          "a PDF document",              0, b"\x25\x50\x44\x46\x2d"),          # "%PDF-"
    # --- images ---------------------------------------------------------------------------------------------------
    ("png",          "an image",                    0, b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"),  # PNG
    ("jpeg",         "an image",                    0, b"\xff\xd8\xff"),                  # JPEG
    ("gif",          "an image",                    0, b"\x47\x49\x46\x38"),              # GIF "GIF8"
    ("bmp",          "an image",                    0, b"\x42\x4d"),                      # BMP "BM"
    ("ico",          "an image",                    0, b"\x00\x00\x01\x00"),              # ICO
    # --- media containers (audio / video) -------------------------------------------------------------------------
    ("riff",         "a media file",                0, b"\x52\x49\x46\x46"),              # RIFF (WEBP/WAV/AVI)
    ("ogg",          "a media file",                0, b"\x4f\x67\x67\x53"),              # OGG "OggS"
    ("mp3-id3",      "a media file",                0, b"\x49\x44\x33"),                  # MP3 "ID3"
    ("mp4-ftyp",     "a media file",                4, b"\x66\x74\x79\x70"),              # MP4 "ftyp" @4
    # --- fonts ----------------------------------------------------------------------------------------------------
    ("woff",         "a font",                      0, b"\x77\x4f\x46\x46"),              # WOFF "wOFF"
    ("woff2",        "a font",                      0, b"\x77\x4f\x46\x32"),              # WOFF2 "wOF2"
    ("ttf",          "a font",                      0, b"\x00\x01\x00\x00"),              # TrueType
    ("otf",          "a font",                      0, b"\x4f\x54\x54\x4f"),              # OpenType "OTTO"
    # --- embedded database ----------------------------------------------------------------------------------------
    ("sqlite",       "a database file",             0, b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00"),  # "SQLite format 3\x00"
]

#: The most C0/C1 control characters (tab/newline/carriage-return excluded) a body may contain, as a fraction of the
#: decoded text. Clean prose is ~0%; a value above this means obfuscated binary smuggled as "text". Deliberately small.
_MAX_CONTROL_RATIO = 0.02

#: A bounded wall-clock budget for the optional external malware scanner. A scanner that outlives it is treated as a
#: fault and the upload is refused (fail-closed). Operators that run a slow on-demand engine should raise this.
_SCAN_TIMEOUT_SECONDS = 30.0

#: Unicode codepoints stripped by :func:`sanitize_text` in addition to the C0/C1 control range. Zero-width characters
#: (U+200B..U+200D, U+FEFF) and bidirectional override / embedding / isolate controls (U+202A..U+202E, U+2066..U+2069)
#: are the Trojan-Source / homoglyph-smuggling vectors: invisible in a chunk yet able to reorder how it reads.
_STRIP_CODEPOINTS = frozenset(
    {0x200B, 0x200C, 0x200D, 0xFEFF}
    | set(range(0x202A, 0x202E + 1))
    | set(range(0x2066, 0x2069 + 1))
)


def _match_signature(data: bytes) -> "str | None":
    """Return the ``label`` of the first magic signature ``data`` matches, or ``None`` - a pure byte comparison."""
    for label, _family, offset, sig in _SIGNATURES:
        if data[offset:offset + len(sig)] == sig:
            return label
    return None


def _family_for(label: str) -> str:
    """The customer-facing category word for a signature ``label`` (never the raw bytes)."""
    for lab, family, _offset, _sig in _SIGNATURES:
        if lab == label:
            return family
    return "a binary file"


def _decode_strict(data: bytes) -> str:
    """Decode ``data`` as text with NO lossy replacement: UTF-8 by default, or UTF-16 LE/BE / UTF-8 via a leading BOM.
    The BOM is consumed (not carried into the text). Any byte that is not valid in the chosen encoding raises
    :class:`KnowledgeError` - this is the strict replacement for the old ``decode("utf-8", errors="replace")`` hole."""
    try:
        if data[:3] == b"\xef\xbb\xbf":                       # UTF-8 BOM
            return data[3:].decode("utf-8")
        if data[:2] == b"\xff\xfe":                           # UTF-16 LE BOM
            return data[2:].decode("utf-16-le")
        if data[:2] == b"\xfe\xff":                           # UTF-16 BE BOM
            return data[2:].decode("utf-16-be")
        return data.decode("utf-8")
    except (UnicodeDecodeError, UnicodeError):
        raise KnowledgeError(
            "this document is not valid UTF-8 / UTF-16 text; the knowledge corpus accepts plain text only") from None


def _control_ratio(text: str) -> float:
    """The fraction of ``text`` that is a C0/C1 control character other than tab / newline / carriage-return."""
    if not text:
        return 0.0
    bad = 0
    for ch in text:
        o = ord(ch)
        if o in (0x09, 0x0A, 0x0D):                           # tab / LF / CR are legitimate text
            continue
        if o < 0x20 or o == 0x7F or 0x80 <= o <= 0x9F:        # C0 controls, DEL, C1 controls
            bad += 1
    return bad / len(text)


def classify(data: bytes) -> str:
    """Best-effort structural label for ``data`` (diagnostic; :func:`assert_allowed` is the authoritative gate).
    Returns a magic-signature ``label`` for a recognised binary type, ``"empty"`` for an empty body, ``"binary"`` for
    a body that is not valid text, or ``"text"`` otherwise."""
    if not data:
        return "empty"
    label = _match_signature(data)
    if label is not None:
        return label
    try:
        _decode_strict(data)
    except KnowledgeError:
        return "binary"
    return "text"


def assert_allowed(data: bytes, filename: str) -> None:
    """FAIL-CLOSED structural gate: refuse ``data`` unless it is clean, inert text the corpus can index. Raises
    :class:`KnowledgeError` (a clean customer-facing refusal that names the reason, never the file's bytes) when the
    body matches a known binary / archive / document / media magic signature, is not strictly decodable text, carries a
    NUL byte, or is too dense with control characters. Returns ``None`` when the body is admissible. ``filename`` is
    accepted for a uniform contract and for future extension-corroboration; the verdict is driven only by the bytes."""
    del filename                                              # the verdict is by CONTENT, never a (spoofable) name
    if not data:
        raise KnowledgeError("a document body must not be empty")
    label = _match_signature(data)
    if label is not None:
        raise KnowledgeError(
            f"this document looks like {_family_for(label)}, not text; the knowledge corpus accepts plain "
            f"UTF-8 / UTF-16 text only")
    text = _decode_strict(data)                               # strict: raises on any invalid byte (no replacement)
    if "\x00" in text:
        raise KnowledgeError("this document contains a NUL byte and was refused; the corpus accepts plain text only")
    if _control_ratio(text) > _MAX_CONTROL_RATIO:
        raise KnowledgeError(
            "this document contains too many control characters to be plain text and was refused")


def decode_text(data: bytes) -> str:
    """Strictly decode ``data`` to text (UTF-8, or UTF-16 LE/BE / UTF-8 via a BOM), with NO lossy replacement. Raises
    :class:`KnowledgeError` on any invalid byte. Call :func:`assert_allowed` first; this is the decode the store uses in
    place of the old lossy ``data.decode("utf-8", errors="replace")``."""
    return _decode_strict(data)


def sanitize_text(text: str) -> str:
    """Return an inert, index-safe copy of ``text``: strip NULs and C0/C1 control characters (keeping tab / newline /
    carriage-return), strip zero-width characters and bidirectional override / embedding / isolate controls (the
    Trojan-Source vectors), then NFC-normalise. The result carries the same readable content with none of the invisible
    machinery that could reorder how a chunk reads or smuggle a hidden payload into a vector or a citation snippet."""
    out: "list[str]" = []
    for ch in text:
        o = ord(ch)
        if o in (0x09, 0x0A, 0x0D):                           # keep tab / LF / CR
            out.append(ch)
            continue
        if o < 0x20 or o == 0x7F or 0x80 <= o <= 0x9F:        # drop C0 controls, DEL, C1 controls (incl. NUL)
            continue
        if o in _STRIP_CODEPOINTS:                            # drop zero-width + bidi controls
            continue
        out.append(ch)
    return unicodedata.normalize("NFC", "".join(out))


def scan(data: bytes, filename: str) -> None:
    """FAIL-CLOSED external malware-scan hook. When a scanner is configured (``config.customer_knowledge_scan_cmd`` /
    ``VIGIL_CUSTOMER_KNOWLEDGE_SCAN_CMD``) the raw ``data`` is piped to it on stdin as an argv list (NO shell, NO
    network) under :data:`_SCAN_TIMEOUT_SECONDS`; the upload is REFUSED (``KnowledgeError``) if the scanner reports an
    infection (non-zero exit) OR if it errors / times out / is missing / is MISCONFIGURED (a configured-but-broken
    scanner must never let an upload through). When UNCONFIGURED this is a documented no-op - the structural allowlist
    and strict-text validator are the always-on defences. ``filename`` is never passed to the command (no injection).

    Deploy note: point ``VIGIL_CUSTOMER_KNOWLEDGE_SCAN_CMD`` at a real engine that reads stdin and exits non-zero on
    detection, e.g. ``clamdscan --no-summary -`` (daemon) or ``clamscan --no-summary -`` (standalone)."""
    del filename                                              # never interpolate a customer-controlled name into argv
    try:
        argv = config.customer_knowledge_scan_cmd()
    except config.ScanCmdError:
        # the scanner is SET but its command is unparseable: fail CLOSED (never ingest unscanned content when an
        # operator intended scanning on). A loud refusal is strictly safer than a silent downgrade to OFF.
        raise KnowledgeError(
            "this document could not be malware-scanned and was refused; please try again later") from None
    if not argv:
        return                                                # unconfigured: documented no-op (structural checks stay)
    try:
        proc = subprocess.run(                                # noqa: S603 - argv list, shell=False, bytes on stdin
            argv, input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=_SCAN_TIMEOUT_SECONDS, shell=False, check=False)
    except (OSError, subprocess.SubprocessError):
        # missing binary, spawn failure, or TIMEOUT (subprocess.TimeoutExpired) -> fail CLOSED, refuse the upload.
        raise KnowledgeError(
            "this document could not be malware-scanned and was refused; please try again later") from None
    if proc.returncode != 0:
        raise KnowledgeError("this document was rejected by the malware scanner")
