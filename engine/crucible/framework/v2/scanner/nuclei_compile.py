"""
scanner.nuclei_compile — compile a Nuclei YAML TEMPLATE into a CRUCIBLE library entry (Workstream D.3).

CRUCIBLE already drives the nuclei BINARY as a gated sensor and mints its output as leads
(``sensors.web_scanner``). This module is the other, offline direction: it reads a Nuclei TEMPLATE
DEFINITION (the YAML itself) and COMPILES a supported subset into a native ``scanner.library``
:class:`~scanner.library.LibraryEntry`, so CRUCIBLE can run the template's logic through its OWN
engine and — crucially — re-verify the match with its OWN deterministic oracle. No nuclei binary is
needed to run a compiled entry.

Prove-don't-guess, by construction:
  * The template's own verdict is NEVER trusted. A Nuclei ``word`` match at a path compiles to a
    ``signature`` oracle spec (``PathProbeCheck``): when it runs, the finding is confirmed ONLY when a
    distinctive signature actually appears in a REAL 2xx response — the predicate/ACHIEVED-STATE
    oracle re-fires over first-party evidence. Until that oracle fires, the match is a
    PROVENANCE-TAGGED LEAD, never a fact. The compiled entry carries its origin in
    ``payload_family = "nuclei:<id>"`` and a ``nuclei-template:<id>`` reference.
  * A template outside the supported subset compiles to nothing (``supported=False`` with a reason) —
    it degrades cleanly, never guesses.

OFF by default + gate-neutral: the compiler is a pure function that RETURNS entries to the caller. It
writes nothing into the shipped ``library_entries/`` directory, so a compiled entry never enters the
benchmark/scan/engage default path and the regression gate stays byte-identical. An operator opts in
by compiling templates and passing the entries to a campaign explicitly (``library_entries=``).

DETERMINISM: parsing YAML and shaping an entry is a pure, replayable function of the template text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..common.errors import CrucibleError
from .library import LibraryEntry, OracleSpec

# Nuclei severities -> CRUCIBLE finding-template severities.
_SEVERITY_MAP: dict[str, str] = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info", "unknown": "Info", "": "Info",
}

# The bug classes a compiled signature check may claim. A ``signature`` oracle spec compiles to a
# PathProbeCheck whose confirmation is the predicate/ACHIEVED-STATE oracle, so the class MUST be one
# that routes to ACHIEVED-STATE (see verify.verifier.BUG_CLASS_ORACLES). A word-match-at-a-path is an
# exposure detection, so the vocabulary here is deliberately the exposure family. Default: exposure.
_EXPOSURE_CLASSES: frozenset[str] = frozenset({"exposure", "sensitive_exposure", "security_misconfiguration"})
_DEFAULT_BUG_CLASS = "exposure"

# A tiny CWE -> class hint (best-effort; anything unmapped falls back to the default exposure class).
_CWE_HINTS: dict[str, str] = {
    "cwe-200": "sensitive_exposure",   # exposure of sensitive information
    "cwe-538": "sensitive_exposure",   # file/dir info exposure
    "cwe-16": "security_misconfiguration",
    "cwe-1004": "security_misconfiguration",
}

# The BaseURL interpolation nuclei uses for the target root; we strip it to a relative probe path.
_BASE_URL_TOKENS: tuple[str, ...] = ("{{BaseURL}}", "{{RootURL}}", "{{Hostname}}")


class NucleiCompileError(CrucibleError):
    """A template is unreadable/unparseable. A plain recoverable error — this module authors a check,
    it makes no trust decision, so a bad template is a data error, never an ethics crossing."""


@dataclass(frozen=True)
class CompiledTemplate:
    """The outcome of compiling one Nuclei template. ``supported`` is True with a populated ``entry``
    when the template fell in the subset this compiler understands; otherwise ``entry`` is None and
    ``reason`` explains why (the template degrades cleanly rather than being force-fit). ``template_id``
    is the source template's id (provenance)."""

    template_id: str
    supported: bool
    entry: LibraryEntry | None = None
    reason: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _first(value: Any) -> Any:
    """The first element of a list, the value itself if scalar, or None if empty."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _strip_base_url(path: str) -> str | None:
    """Turn a nuclei path (``{{BaseURL}}/actuator/env``) into a relative probe path (``/actuator/env``).
    Returns None when the path carries interpolation OTHER than the leading BaseURL token — the
    PathProbeCheck only fetches a fixed path, so a templated/computed path is unsupported."""
    p = path.strip()
    for tok in _BASE_URL_TOKENS:
        if p.startswith(tok):
            p = p[len(tok):]
            break
    if "{{" in p or "}}" in p:
        return None   # residual interpolation -> not a fixed path
    if not p.startswith("/"):
        p = "/" + p
    return p


def _extract_word_matcher(request: dict) -> tuple[str | None, tuple[str, ...]]:
    """Find a ``word`` matcher over the response BODY and return ``(signature, warnings)``. The first
    word of the first body ``word`` matcher becomes the signature (PathProbeCheck confirms a single
    distinctive substring). Returns ``(None, ...)`` when no usable body word matcher exists."""
    matchers = request.get("matchers")
    warnings: list[str] = []
    if not isinstance(matchers, list) or not matchers:
        return None, ("template has no matchers",)
    for m in matchers:
        if not isinstance(m, dict):
            continue
        if m.get("type") != "word":
            continue
        part = (m.get("part") or "body")
        if part != "body":
            warnings.append(f"skipped a word matcher on part={part!r} (only body is supported)")
            continue
        words = m.get("words")
        if isinstance(words, list) and words and isinstance(words[0], str) and words[0].strip():
            if len(words) > 1:
                warnings.append(f"used only the first of {len(words)} words as the signature")
            return words[0], tuple(warnings)
    return None, tuple(warnings) or ("no body 'word' matcher found",)


def _bug_class_from_info(info: dict) -> str:
    """Derive a compiled bug_class from the template's classification CWEs / tags, defaulting to the
    exposure class. Always returns a class that routes to the ACHIEVED-STATE oracle."""
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cwes = classification.get("cwe-id")
    for cwe in (cwes if isinstance(cwes, list) else [cwes]):
        hint = _CWE_HINTS.get(str(cwe).strip().lower())
        if hint in _EXPOSURE_CLASSES:
            return hint
    return _DEFAULT_BUG_CLASS


def _references(template_id: str, info: dict) -> list[str]:
    """Provenance + citations: the CWE ids the template declares, its external references, and a
    ``nuclei-template:<id>`` tag so a compiled finding traces back to its origin."""
    refs: list[str] = []
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cwes = classification.get("cwe-id")
    for cwe in (cwes if isinstance(cwes, list) else [cwes] if cwes else []):
        c = str(cwe).strip().upper()
        if c:
            refs.append(c)
    ext = info.get("reference")
    for r in (ext if isinstance(ext, list) else [ext] if ext else []):
        rs = str(r).strip()
        if rs:
            refs.append(rs)
    refs.append(f"nuclei-template:{template_id}")
    # de-dupe, order-preserving
    seen: set[str] = set()
    return [r for r in refs if not (r in seen or seen.add(r))]


# ---------------------------------------------------------------------------
# the compiler
# ---------------------------------------------------------------------------


def compile_nuclei_template(source: str | dict) -> CompiledTemplate:
    """Compile one Nuclei template (YAML text or an already-parsed dict) into a
    :class:`CompiledTemplate`.

    Supported subset (first slice): an HTTP template (``http:`` or legacy ``requests:``) whose first
    request is a ``GET`` of a single fixed ``{{BaseURL}}``-rooted path, with a body ``word`` matcher.
    That compiles to a ``signature`` :class:`~scanner.library.OracleSpec` (a ``PathProbeCheck``), whose
    match the predicate/ACHIEVED-STATE oracle re-verifies over a real response. Anything else (POST,
    raw requests, computed paths, regex/dsl/status-only matchers, header matchers) is returned as
    ``supported=False`` with a reason — it degrades cleanly, never guesses."""
    if isinstance(source, str):
        try:
            import yaml   # local import: pyyaml is a light dep, keep it off the module load path
            data = yaml.safe_load(source)
        except Exception as e:   # noqa: BLE001 - any YAML error is a clean "unparseable" outcome
            raise NucleiCompileError(f"could not parse nuclei template YAML: {e}") from e
    else:
        data = source
    if not isinstance(data, dict):
        raise NucleiCompileError("nuclei template must be a mapping (id/info/http)")

    template_id = str(data.get("id") or "").strip()
    if not template_id:
        raise NucleiCompileError("nuclei template is missing an 'id'")
    info = data.get("info") if isinstance(data.get("info"), dict) else {}

    def _unsupported(reason: str, warnings: tuple[str, ...] = ()) -> CompiledTemplate:
        return CompiledTemplate(template_id=template_id, supported=False, reason=reason, warnings=warnings)

    http = data.get("http")
    if http is None:
        http = data.get("requests")   # legacy key
    if not isinstance(http, list) or not http or not isinstance(http[0], dict):
        return _unsupported("no http/requests block (only HTTP templates are supported)")
    request = http[0]

    # raw requests (a full HTTP request blob) are out of the fixed-path subset.
    if request.get("raw") is not None:
        return _unsupported("raw HTTP requests are not supported (only method+path templates)")

    method = str(request.get("method") or "GET").upper()
    if method != "GET":
        return _unsupported(f"only GET templates are supported, got {method}")

    path_val = _first(request.get("path"))
    if not isinstance(path_val, str) or not path_val.strip():
        return _unsupported("template has no usable single path")
    probe_path = _strip_base_url(path_val)
    if probe_path is None:
        return _unsupported(f"path carries interpolation beyond BaseURL: {path_val!r}")

    signature, warnings = _extract_word_matcher(request)
    if not signature:
        return _unsupported("no supported body 'word' matcher to re-verify", warnings)

    severity = _SEVERITY_MAP.get(str(info.get("severity", "")).strip().lower(), "Info")
    bug_class = _bug_class_from_info(info)
    title = str(info.get("name") or template_id).strip() or template_id

    try:
        entry = LibraryEntry(
            id=f"nuclei-{template_id}",
            bug_class=bug_class,
            title=title,
            severity=severity,
            applies_when={"always": True},
            oracle=OracleSpec(kind="signature", probe_path=probe_path, signature=signature, http_method="GET"),
            references=_references(template_id, info),
            remediation=str(info.get("remediation") or ""),
            payload_family=f"nuclei:{template_id}",
        )
    except Exception as e:   # noqa: BLE001 - a schema rejection is a clean unsupported outcome, not a crash
        return _unsupported(f"compiled entry failed schema validation: {e}", warnings)

    return CompiledTemplate(template_id=template_id, supported=True, entry=entry, warnings=warnings)


def compile_nuclei_templates(sources: list[str | dict]) -> list[CompiledTemplate]:
    """Compile many templates, order-preserving. Each element is YAML text or a parsed dict. An
    individual unparseable template is captured as ``supported=False`` (it never sinks the batch)."""
    out: list[CompiledTemplate] = []
    for src in sources:
        try:
            out.append(compile_nuclei_template(src))
        except NucleiCompileError as e:
            out.append(CompiledTemplate(template_id="<unparseable>", supported=False, reason=str(e)))
    return out


def compile_nuclei_dir(directory: str | Path) -> list[CompiledTemplate]:
    """Compile every ``*.yaml`` / ``*.yml`` template under ``directory`` (sorted, deterministic). A
    file that cannot be read/parsed becomes a ``supported=False`` entry naming the file, never a crash.
    The entries are RETURNED, not written into the shipped library — the caller decides whether to run
    them (off by default)."""
    d = Path(directory)
    if not d.is_dir():
        raise NucleiCompileError(f"nuclei template directory not found: {directory}")
    results: list[CompiledTemplate] = []
    for f in sorted([*d.glob("*.yaml"), *d.glob("*.yml")]):
        try:
            results.append(compile_nuclei_template(f.read_text(encoding="utf-8")))
        except (OSError, NucleiCompileError) as e:
            results.append(CompiledTemplate(template_id=f.name, supported=False, reason=str(e)))
    return results


def compiled_entries(results: list[CompiledTemplate]) -> list[LibraryEntry]:
    """The successfully-compiled :class:`~scanner.library.LibraryEntry` objects from a batch — the
    subset an operator would hand to a campaign as ``library_entries``."""
    return [r.entry for r in results if r.supported and r.entry is not None]
