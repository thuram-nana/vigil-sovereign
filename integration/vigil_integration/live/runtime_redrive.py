"""runtime_redrive — runner-owned gated HTTP re-drive → signed FACT for the RESPONSE-DERIVED vuln classes
whose deterministic oracle is NOT the predicate oracle that :mod:`live.web_redrive` hardcodes.

It extends the exact, already-reviewed ``web_redrive`` discipline — a gated, DNS-pinned, proxy-free send
(reused verbatim: :func:`web_redrive._gated_web_send`) → the RUNNER (never a tool) crafts the probe → the
existing deterministic oracle judges the FRESH captured bytes → one atomic evidence branch is admitted
against its declared capability → ``certify_admitted(provenance="live_redrive")`` mints a signed,
offline-re-verifiable FACT — to three more MERIDIAN-planted classes:

  * ``path_traversal``   — the ``side_effect`` oracle over a KNOWN file-content signature (``root:x:0:0:``):
                           proof the file was actually READ, not that the path merely reflected.
  * ``xss`` (reflected)  — the ``reflection_context`` oracle: a unique canary that reaches an EXECUTABLE
                           HTML position (a tag name / ``<script>`` / an ``on*`` handler), never inert text.
  * ``exposure``         — the ``predicate`` oracle: a distinctive secret signature (``DB_PASSWORD`` /
                           ``propertySources``) at a fixed framework path (``/.env`` / ``/actuator/env``).

Unlike ``web_redrive`` (which probes EVERY web class on one URL), this runs ONLY the CLAIMED class, so a
minted FACT is inherently that class — no sibling cross-attribution. Soundness is inherited unchanged: the
gated send refuses out-of-scope / kill-switched traffic before any byte is sent; a probe that established no
channel is INCONCLUSIVE, never CLEAN ("found nothing ≠ CLEAN"); a body VIGIL could not decode is likewise
INCONCLUSIVE; and the oracle over the target's FRESH bytes — never the LLM's claimed context — decides. All
three branches are response-body/service-response derived and therefore NOT clean-capable.

FATAL-2: every framework-touching import is FUNCTION-LOCAL — importing this module co-loads no offense engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# The classes this runner mints as FACTs, each mapped to its ONE registered evidence branch + the oracle
# whose deterministic decision procedure adjudicates it. Named by value (the framework enums are resolved
# function-locally, FATAL-2). Kept in lockstep with docs/capability-matrix/evidence-branches.json.
RUNTIME_FACT_CLASSES = ("path_traversal", "xss", "exposure")

_BRANCH_FOR = {
    "path_traversal": "path_traversal.file_signature",
    "xss": "xss.reflected_execution",
    "exposure": "exposure.secret_signature",
}

# Candidate query-parameter names synthesised for the point-check classes when the proposed URL does not
# already carry a usable parameter, so the insertion surface EXISTS to be rendered into (mirrors
# web_redrive._candidate_redirect_names). A CLEAN would be bounded to these names — but these branches are
# not clean-capable, so the set only bounds where a FACT is SOUGHT, never a claim of absence.
_PATH_TRAVERSAL_PARAMS = ("file", "path", "filename", "name", "doc", "document", "page", "template",
                          "download", "read", "include", "view")
_XSS_PARAMS = ("q", "query", "search", "s", "ref", "name", "keyword", "term", "message", "comment",
               "title", "redirect")
_MAX_CANDIDATE_NAMES = 12

# Fixed framework/CMS paths + the distinctive signature each leaks, for the exposure class. Each signature is
# specific enough that its presence is the proof (the predicate oracle over the response body); a 404 or a
# signature-less body does not fire (PathProbeCheck returns None on 404 — nothing to adjudicate).
_EXPOSURE_PROBES = (
    ("/.env", "DB_PASSWORD="),                 # value form (key=value), not the bare key a JS bundle names
    ("/actuator/env", "spring.datasource"),    # a Spring config property, not merely "propertySources"
    ("/.git/config", "[core]"),
)


@dataclass
class RuntimeRedriveResult:
    url: str
    bug_class: str
    facts: list = field(default_factory=list)          # AdapterResult (is_fact), signed
    leads: list = field(default_factory=list)          # AdapterResult (channel-confirmed non-fact)
    inconclusive: list = field(default_factory=list)   # (bug_class, item) — no channel / unreadable body
    admissions: list = field(default_factory=list)     # (branch, verdict, reason) — the audit trail
    branch_verdicts: dict = field(default_factory=dict)  # bug_class -> {branch: verdict}
    contexts: dict = field(default_factory=dict)       # finding_ref -> oracle_context (offline re-verify)
    surfaces: dict = field(default_factory=dict)       # bug_class -> set(surface actually EXAMINED)
    refused: bool = False
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)

    def family_verdict(self, bug_class: str) -> str:
        """The conservative composition over every branch of ``bug_class`` (see verdict.compose)."""
        from .verdict import compose  # noqa: PLC0415
        verdicts = list(self.branch_verdicts.get(bug_class, {}).values())
        if not verdicts:
            return "INCONCLUSIVE"
        return compose(verdicts).value


def _candidate_query_names(url: str, base_names: "tuple[str, ...]") -> "list[str]":
    """Query-parameter names to probe: the names the URL already carries FIRST (so the endpoint's real
    parameter is exercised), then the well-known set for breadth, de-duped case-insensitively and capped.
    Purely lexical — no network."""
    from urllib.parse import parse_qsl, urlsplit  # noqa: PLC0415
    names: "list[str]" = []
    seen: "set[str]" = set()
    try:
        for k, _v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            low = k.lower()
            if k and low not in seen:
                names.append(k)
                seen.add(low)
    except Exception:  # noqa: BLE001 — a malformed URL simply contributes no grounded names
        pass
    for n in base_names:
        if n.lower() not in seen:
            names.append(n)
            seen.add(n.lower())
    return names[:_MAX_CANDIDATE_NAMES]


def _url_with_param(url: str, name: str, value: str = "x") -> str:
    """``url`` guaranteed to carry a ``name`` query parameter (append if absent). Lexical only."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit  # noqa: PLC0415
    sp = urlsplit(url)
    pairs = parse_qsl(sp.query, keep_blank_values=True)
    if any(k.lower() == name.lower() for k, _ in pairs):
        return url
    pairs.append((name, value))
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(pairs), sp.fragment))


def runtime_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                    claimed_class: str, timeout: float = 8.0) -> RuntimeRedriveResult:
    """Re-drive ``url`` for the single CLAIMED response-derived class through a gated send + the matching
    deterministic oracle, and mint a signed FACT ONLY when the oracle confirms CAUSATION (not mere presence)
    over VIGIL's OWN live capture:

      * path_traversal — a benign CONTROL request (a non-traversal file value) must NOT already contain the
        file-content signature; only when the signature appears under the TRAVERSAL payload but not the
        control is it attributable to a file read (a docs page that merely prints ``root:x:0:0:`` is refused).
      * xss (reflected) — the reflection oracle must report the ``html_tag`` context (the canary became a live
        element); mere presence inside a ``<script>`` string literal or a ``<noscript>`` block is NOT accepted.
      * exposure — a random CONTROL path must NOT return the signature (a 200 soft-404 / catch-all that serves
        the signature everywhere is refused); the signature is value-shaped so a JS bundle naming the key does
        not match.

    A probe that established no channel is INCONCLUSIVE (never CLEAN). Returns a :class:`RuntimeRedriveResult`.
    Never raises (a probe error is recorded and what held is returned)."""
    import hashlib  # noqa: PLC0415 — stdlib; deterministic control tokens (no rng, determinism invariant)

    from framework.v2.scanner.checks import (  # noqa: PLC0415
        ContentSignatureCheck, MarkerReflectionCheck, PathProbeCheck)
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.oracles import (  # noqa: PLC0415
        predicate_oracle, reflection_context_oracle, side_effect_oracle)
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate
    from framework.v2.verify.verifier import normalize_bug_class  # noqa: PLC0415

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, branch_ids, compose  # noqa: PLC0415
    from .web_redrive import _gated_web_send  # noqa: PLC0415 — the reviewed gated, DNS-pinned, no-proxy send

    bug_class = normalize_bug_class(claimed_class)
    res = RuntimeRedriveResult(url=url, bug_class=bug_class)
    if bug_class not in RUNTIME_FACT_CLASSES:
        res.notes.append(f"{bug_class!r} is not a runtime-redrive class")
        return res
    branch = _BRANCH_FOR[bug_class]
    if branch not in branch_ids():
        res.notes.append(f"branch {branch!r} is not registered — cannot admit (fail-closed)")
        return res

    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res

    send, state = _gated_web_send(slug, timeout=timeout)
    nonce = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]

    def _body(resp: Any) -> str:
        return str(resp.get("body", "")) if isinstance(resp, dict) else str(resp)

    def _admit(context: dict, item: str, surface: str, *, fired: bool, conclusive: bool,
               body_unreadable: bool) -> None:
        res.surfaces.setdefault(bug_class, set()).add(surface)
        observed = {"channel_established": True, "body_semantically_available": not body_unreadable,
                    "gate_authorized": True}
        finding = {"check_id": f"rt:{bug_class}:{item}#{branch}", "bug_class": bug_class,
                   "insertion_point": item, "oracle_context": context}
        admitted = admit(branch, fired=fired, conclusive=conclusive, observed=observed)
        res.admissions.append((branch, admitted.verdict.value, admitted.reason))
        bm = res.branch_verdicts.setdefault(bug_class, {})
        prior = bm.get(branch)
        bm[branch] = compose([prior, admitted.verdict.value]).value if prior else admitted.verdict.value
        r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                             provenance="live_redrive")
        res.contexts[r.finding_ref] = context
        if r.is_fact:
            res.facts.append(r)
        elif admitted.verdict is Verdict.INCONCLUSIVE:
            res.inconclusive.append((bug_class, f"{item}#{branch}"))
        else:
            res.leads.append(r)

    try:
        if bug_class == "path_traversal":
            sig = "root:x:0:0:"
            chk = ContentSignatureCheck(id="path-traversal", bug_class="path_traversal",
                                        payload="../../../../etc/passwd", signature=sig)
            control_value = f"vigilctl{nonce}.txt"    # a benign, non-traversal file value (baseline)
            for name in _candidate_query_names(url, _PATH_TRAVERSAL_PARAMS):
                probe_url = _url_with_param(url, name)
                tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
                point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                              if p.name.lower() == name.lower()), None)
                if point is None:
                    continue
                # CONTROL first: if the benign response already carries the file signature, the page prints it
                # regardless of input — NOT attributable to a traversal → refuse (BLOCK-1 fix).
                before = state["channels"]
                try:
                    control = send(tmpl.render(point, control_value))
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"path_traversal control error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before:
                    res.inconclusive.append((bug_class, f"{probe_url}#control"))
                    continue
                if sig in _body(control):
                    res.notes.append(f"path_traversal: signature present in the benign control on {name!r} — "
                                     "not attributable to a traversal → LEAD")
                    continue
                # TREATMENT: the traversal payload. The signature is now attributable to the file read.
                before2, before_bodies = state["channels"], state["body_unavailable"]
                ctx_obj = chk.probe(tmpl, point, send)
                if state["channels"] <= before2:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                if ctx_obj is None:
                    continue
                context = ctx_obj.to_verifier_context()
                signal = side_effect_oracle(context.get("marker", ""), context.get("observed_sink", ""))
                _admit(context, f"{probe_url}#{point.id}", f"query:{name}",
                       fired=signal.fired, conclusive=signal.conclusive,
                       body_unreadable=state["body_unavailable"] > before_bodies)

        elif bug_class == "xss":
            chk = MarkerReflectionCheck(id="reflected-xss", bug_class="xss",
                                        payload_template="\"'><x{marker}>")
            for name in _candidate_query_names(url, _XSS_PARAMS):
                probe_url = _url_with_param(url, name)
                tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
                point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                              if p.name.lower() == name.lower()), None)
                if point is None:
                    continue
                before, before_bodies = state["channels"], state["body_unavailable"]
                try:
                    ctx_obj = chk.probe(tmpl, point, send)
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"xss probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                if ctx_obj is None:
                    continue
                context = ctx_obj.to_verifier_context()
                signal = reflection_context_oracle(context.get("marker", ""), context.get("observed_sink", ""))
                # SOUND breakout ONLY: the canary must have become a live ELEMENT (html_tag). Mere presence
                # inside a <script> string literal or a <noscript> block is NOT a proven breakout (BLOCK-3 fix).
                ctxkind = (getattr(signal, "observed", {}) or {}).get("context")
                accepted = bool(signal.fired) and ctxkind == "html_tag"
                _admit(context, f"{probe_url}#{point.id}", f"query:{name}",
                       fired=accepted, conclusive=(signal.conclusive if accepted else False),
                       body_unreadable=state["body_unavailable"] > before_bodies)

        else:  # exposure — a request-level fixed-path probe with a random-path (soft-404) control
            tmpl = RequestTemplate(HttpRequest(method="GET", url=url))
            rand_path = f"/vigil-{nonce}-notfound"
            for probe_path, signature in _EXPOSURE_PROBES:
                # CONTROL: a definitely-nonexistent path. PathProbeCheck returns a context only for a non-404
                # response whose body carries the signature, so a non-None control means the signature is
                # served EVERYWHERE (a 200 soft-404 / catch-all) — refuse (BLOCK-2 fix).
                ctl = PathProbeCheck(id=f"exposure-ctl{probe_path}", bug_class="exposure",
                                     probe_path=rand_path, signature=signature)
                try:
                    control_ctx = ctl.probe(tmpl, send)
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"exposure control error [{probe_path}]: {type(e).__name__}: {e}")
                    continue
                if control_ctx is not None:
                    res.notes.append(f"exposure: signature {signature!r} also served at a random path "
                                     "(soft-404 / catch-all) — not path-specific → LEAD")
                    continue
                chk = PathProbeCheck(id=f"exposure{probe_path}", bug_class="exposure",
                                     probe_path=probe_path, signature=signature)
                before, before_bodies = state["channels"], state["body_unavailable"]
                try:
                    ctx_obj = chk.probe(tmpl, send)
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"exposure probe error [{probe_path}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before:
                    res.inconclusive.append((bug_class, f"{url}#{probe_path}"))
                    continue
                if ctx_obj is None:
                    continue
                context = ctx_obj.to_verifier_context()
                signal = predicate_oracle(context.get("observed_evidence", {}), context.get("predicate", {}))
                _admit(context, f"{url}#{probe_path}", f"path:{probe_path}",
                       fired=signal.fired, conclusive=signal.conclusive,
                       body_unreadable=state["body_unavailable"] > before_bodies)
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"runtime_redrive error: {type(e).__name__}: {e}")
    return res
