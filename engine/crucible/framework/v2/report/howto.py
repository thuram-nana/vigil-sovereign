"""
report.howto — a deterministic, per-finding "how to verify / test / patch" block.

The rest of the report layer states WHAT was found and (for a fact) that a retained
oracle proof re-fired. This module answers the operator's next question — "so what do
*I* run to re-check it, and exactly where do I fix it?" — for EACH finding individually,
instead of the same class-level command for all of them.

It is a pure function of the graded finding. There is no wallclock and no RNG here, so a
stable finding yields a stable block every time. It sends no traffic and reads no target;
it only parses fields the finding already carries and re-uses the report layer's own
class-remediation table (``generate._remediation_for``).

Honesty is load-bearing and split by grade:

  * A **FACT** re-fired its deterministic oracle at report time, so its block names the
    oracle that fired + its rationale and points at the REAL re-executable proof: run
    ``python3 -m framework.v2 verify`` over the RAW retained ``reverifiable.json`` (its
    confidence is the raw oracle value, so it re-fires and reports ``OK``). It honestly warns
    that running ``verify`` over a rendered/calibrated report instead may show a calibration
    delta (a ``CLAIM-MISMATCH``) that is EXPECTED, not tampering, and that the verifier lists
    rows by index + the re-fired oracle (never the slug/certificate digest — the digest is a
    cross-reference only). If the finding's retained evidence carries a reproduce-from-raw
    capture (:mod:`evidence.poc`), the block also points at the replay harness.
  * A **LEAD** (LLM-advisory, or a recorded oracle proof that no longer re-verifies) has NO
    re-executable proof. Its block says "how to CONFIRM this lead" and never implies the
    finding is proven — ``verify`` re-checks proven certificates, and a lead carries none.

Neither branch invents a CLI flag or a capability the tool does not have.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .generate import _remediation_for
from .grounding import GRADE_DEMOTED, GradedFinding

# The ONE real re-verification entry point (see verify/reverify.py). It takes a positional
# path to the retained re-verifiable material and re-fires each finding's pure oracle over
# its retained evidence, reporting `OK` when it reproduces. It reports `OK` over the RAW
# reverifiable.json (raw oracle confidence); over a rendered/calibrated report a legitimate
# calibration delta reads as a CLAIM-MISMATCH (expected, not tampering). There is NO
# per-certificate scoping flag and it prints rows by index + the re-fired oracle (never the
# slug/digest) — so neither is invented as a locator the verifier emits.
VERIFY_COMMAND = "python3 -m framework.v2 verify <reverifiable.json>"

# HTTP methods a surface token may lead with. Used only to split a "GET /path" surface into
# method + location; a surface that does not lead with one is treated as a bare location.
_HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
)

# A path-template parameter: `{id}` (OpenAPI/Express) or `:id` (Rails/Express). Group 1 is
# the brace form, group 2 the colon form.
_TEMPLATE_RE = re.compile(r"\{([^{}/]+)\}|:([A-Za-z_][A-Za-z0-9_]*)")

# Keys inside a retained oracle_context that betray a reproduce-from-raw PoC capture (the
# evidence.poc byte-refs). A plain differential/boolean context carries none of these, so a
# normal finding never triggers the PoC-replay pointer.
_POC_REF_KEYS = frozenset({"request_bytes_ref", "response_bytes_ref", "poc_code_ref", "poc"})


def _first_query_key(query: str) -> str | None:
    """The first parameter name in a query string: ``"q="`` -> ``"q"``, ``"id=1&x=2"`` ->
    ``"id"``. Returns ``None`` for an empty/nameless query."""
    for pair in query.split("&"):
        key = pair.split("=", 1)[0].strip()
        if key:
            return key
    return None


def parse_surface(surface: str | None) -> tuple[str | None, str | None, str | None]:
    """Split a finding's ``surface`` string into ``(method, location, parameter)`` — all
    deterministic, all best-effort, each ``None`` when absent.

    Handles the shapes findings actually carry: ``"GET /search?q="`` ->
    ``("GET", "/search", "q")``; ``"GET /order/{id}"`` -> ``("GET", "/order/{id}", "id")``;
    ``"POST /login"`` -> ``("POST", "/login", None)``; a bare ``"/x?a=1"`` ->
    ``(None, "/x", "a")``. Never raises; an opaque surface returns all-``None`` for
    ``method``/``parameter`` so callers can treat it as "no extra surface data"."""
    s = (surface or "").strip()
    if not s:
        return (None, None, None)

    method: str | None = None
    rest = s
    head, _, tail = s.partition(" ")
    if head in _HTTP_METHODS:
        method = head
        rest = tail.strip()

    tokens = rest.split()
    url = tokens[0] if tokens else rest
    param: str | None = None

    if "?" in url:
        path, _, query = url.partition("?")
        url = path
        param = _first_query_key(query)

    if param is None:
        m = _TEMPLATE_RE.search(url)
        if m:
            param = m.group(1) or m.group(2)

    # a trailing "param=name" / "key=value" hint after the location (e.g. "POST /cb user_id=")
    if param is None:
        for tok in tokens[1:]:
            if "=" in tok:
                key = tok.split("=", 1)[0].strip()
                if key:
                    param = key
                    break

    return (method, url or None, param)


def _surface_phrase(method: str | None, location: str | None) -> str:
    """A compact `<METHOD> <location>` phrase (either half may be missing)."""
    if method and location:
        return f"{method} {location}"
    return location or method or ""


def _safe_span(s: str | None) -> str:
    """Sanitise a finding-authored token for weaving inside a Markdown code span: strip
    backticks + control chars so an odd/hostile surface (findings are LLM-authored) can't
    close the span and inject markup. Display-only — these values are never used as a shell
    arg or a path, so this is Markdown integrity, not a security control."""
    return re.sub(r"[`\r\n\t]+", "", str(s or "")).strip()


def finding_specific_remediation(finding) -> str:  # noqa: ANN001 - FindingPayload or mapping-like
    """The class-level remediation rule (``generate._remediation_for``) woven with the
    finding's OWN parameter/surface so it reads as finding-specific. Falls back to the
    verbatim class text when there is no parameter to weave in — never fabricates a
    surface the finding does not carry."""
    base = _remediation_for(getattr(finding, "bug_class", "") or "")
    method, location, param = parse_surface(getattr(finding, "surface", "") or "")
    if not param:
        return base
    where = _surface_phrase(method, location)
    if where:
        return f"For `{_safe_span(param)}` on `{_safe_span(where)}`: {base}"
    return f"For `{_safe_span(param)}`: {base}"


def _oracle_context_has_poc(finding) -> bool:  # noqa: ANN001
    """True iff the finding's retained ``oracle_context`` carries a reproduce-from-raw PoC
    capture (an :mod:`evidence.poc` byte-ref), at the top level or one dict deep. A plain
    differential/boolean context carries none, so this stays False for normal findings and
    the PoC-replay pointer is only emitted when there is genuinely a capture to re-drive."""
    oc = getattr(finding, "oracle_context", None)
    if not isinstance(oc, dict) or not oc:
        return False
    for key, val in oc.items():
        if key in _POC_REF_KEYS:
            return True
        if isinstance(val, dict):
            if any(k in _POC_REF_KEYS for k in val):
                return True
    return False


@dataclass(frozen=True)
class HowTo:
    """The structured, deterministic per-finding how-to block — the unit both the technical
    Markdown report and the machine exports draw from, so a human and a machine describe
    verification identically.

    ``is_fact`` splits every honesty-sensitive field: a fact carries its firing oracle +
    certificate + a real re-check note; a lead carries ``None`` for those and a
    confirm-this-lead note that never implies proof."""

    grounding: str                       # "fact" | "demoted" | "lead"
    is_fact: bool
    surface: str
    method: str | None
    location: str | None
    parameter: str | None
    oracle_kind: str | None              # fact only
    oracle_rationale: str                # fact only ("" otherwise)
    verify_command: str
    certificate: str | None              # "sha256:<digest>" for a fact, else None
    verify_note: str
    poc_replay: str | None               # pointer to the reproduce-from-raw capture, if any
    remediation: str                     # finding-specific


def build_howto(g: GradedFinding) -> HowTo:
    """Build the how-to block for one graded finding. Pure + deterministic."""
    f = g.finding
    method, location, param = parse_surface(f.surface)
    grounding = "fact" if g.is_fact else ("demoted" if g.grade == GRADE_DEMOTED else "lead")

    certificate = f"sha256:{g.certificate_digest}" if (g.is_fact and g.certificate_digest) else None

    if g.is_fact:
        oracle_name = g.oracle_kind or "its oracle"
        cert_ref = f" This finding's certificate is `{certificate}` for cross-reference." if certificate else ""
        # HONEST re-verify guidance: `verify` reports `OK` over the RAW retained re-verifiable
        # material (reverifiable.json — its confidence is the raw oracle value). Run over a
        # RENDERED/calibrated report instead and a legitimate calibration delta reads as a
        # CLAIM-MISMATCH — expected, not tampering. The verifier lists rows by index + the oracle
        # that re-fired (never the slug or the certificate digest), so we don't claim it prints those.
        verify_note = (
            f"Re-run this finding's proof yourself, offline: `{VERIFY_COMMAND}` over the retained "
            f"re-verifiable material — the `reverifiable.json` written by `scan --reverifiable-out` "
            f"(or the dossier's `proof-bundle/reverifiable.json`). Each retained oracle_context "
            f"re-fires its oracle over the captured bytes and reports `OK` when it reproduces; here "
            f"that oracle is `{oracle_name}`. (Running `verify` over a RENDERED report instead may "
            f"show a confidence delta from calibration — that is expected, NOT tampering; and the "
            f"verifier lists rows by index + the re-fired oracle, not by slug or digest.)" + cert_ref
        )
        poc_replay = None
        if _oracle_context_has_poc(f):
            poc_replay = (
                "This finding's retained evidence includes a reproduce-from-raw capture "
                "(see `evidence/poc.py`); re-drive it over the captured bytes with the replay "
                "harness (`framework.v2.verify.replay_harness`) — a pure, offline re-fire."
            )
    else:
        # A lead — LLM-advisory, or a recorded proof that no longer re-verifies. No proof to
        # re-execute: say how to CONFIRM it, and never imply it is a fact.
        base = (
            "This finding is a LEAD, not a proven fact — "
            + ("its recorded oracle proof did NOT re-verify at report time"
               if g.grade == GRADE_DEMOTED
               else "no deterministic oracle fired for it")
            + ". To CONFIRM it, reproduce the test against the surface above and capture the "
            "oracle signal (a divergent response, an out-of-band callback, an achieved state); "
            "only a fired deterministic oracle promotes it to a fact."
        )
        verify_note = (
            base
            + f" (`{VERIFY_COMMAND}` re-checks proven certificates; this lead carries none.)"
        )
        poc_replay = None

    return HowTo(
        grounding=grounding,
        is_fact=g.is_fact,
        surface=(f.surface or "").strip(),
        method=method,
        location=location,
        parameter=param,
        oracle_kind=g.oracle_kind if g.is_fact else None,
        oracle_rationale=(f.oracle_rationale or "") if g.is_fact else "",
        verify_command=VERIFY_COMMAND,
        certificate=certificate,
        verify_note=verify_note,
        poc_replay=poc_replay,
        remediation=finding_specific_remediation(f),
    )


def has_howto(g: GradedFinding) -> bool:
    """Whether the how-to block adds anything BEYOND what the finding's fields already show
    in the report (its raw ``surface`` line and the class-level remediation section).

    True when the surface parses into a concrete method or parameter, or the finding carries
    a reproduce-from-raw PoC capture. This is the byte-identity gate for the technical
    report: a finding whose surface yields no extra structure appends nothing, so its
    rendered bytes are unchanged."""
    h = build_howto(g)
    return bool(h.method or h.parameter or h.poc_replay)


def _surface_line(h: HowTo) -> str:
    where = _safe_span(_surface_phrase(h.method, h.location) or h.surface or "(unspecified)")
    if h.parameter:
        return f"**Surface:** `{where}` — parameter `{_safe_span(h.parameter)}`  "
    return f"**Surface:** `{where}`  "


def howto_markdown(g: GradedFinding) -> list[str]:
    """The how-to block as Markdown lines for the technical report. Returns ``[]`` when
    :func:`has_howto` is False, so an opaque-surface finding stays byte-identical."""
    if not has_howto(g):
        return []
    h = build_howto(g)
    if h.is_fact:
        L = ["#### How to verify, test & patch this finding", ""]
        L.append(_surface_line(h))
        oracle = f"`{h.oracle_kind}`" if h.oracle_kind else "the deterministic oracle"
        if h.oracle_rationale:
            L.append(f"**Oracle that fired:** {oracle} — {h.oracle_rationale}  ")
        else:
            L.append(f"**Oracle that fired:** {oracle}  ")
        L.append(f"**Re-check the proof:** {h.verify_note}  ")
        if h.poc_replay:
            L.append(f"**Reproduce from raw:** {h.poc_replay}  ")
        L.append(f"**Fix (finding-specific):** {h.remediation}  ")
    else:
        L = ["#### How to confirm this lead", ""]
        L.append(_surface_line(h))
        L.append(f"**Confirm this lead:** {h.verify_note}  ")
        L.append(f"**Fix (only after confirmation):** {h.remediation}  ")
    L.append("")
    return L


def howto_export(g: GradedFinding) -> dict:
    """The how-to block as a deterministic, JSON-safe dict for the machine exports (the
    ``how_to_verify`` property on each JSON finding + SARIF result). Insertion-ordered so it
    reads top-down; every value is a pure function of the finding."""
    h = build_howto(g)
    return {
        "grounding": h.grounding,
        "is_fact": h.is_fact,
        "surface": {
            "method": h.method,
            "location": h.location,
            "parameter": h.parameter,
        },
        "oracle": (
            {"kind": h.oracle_kind, "rationale": h.oracle_rationale}
            if h.is_fact else None
        ),
        "verify_command": h.verify_command,
        "certificate": h.certificate,
        "verify_note": h.verify_note,
        "poc_replay": h.poc_replay,
        "remediation": h.remediation,
    }
