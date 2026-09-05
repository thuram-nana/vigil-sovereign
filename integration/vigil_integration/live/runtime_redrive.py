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


# ---------------------------------------------------------------------------------------------------
# Two-identity read differential — broken object-level authorization (bola / idor)
# ---------------------------------------------------------------------------------------------------

# The classes proven by a two-identity cross-object read. bola and idor are the same mechanism (a broken
# object-level authorization); each keeps its own registered branch so the certificate names the class the
# claim asserted. Kept in lockstep with docs/capability-matrix/evidence-branches.json.
ACCESS_FACT_CLASSES = ("bola", "idor")

_ACCESS_BRANCH_FOR = {
    "bola": "bola.cross_tenant_read",
    "idor": "idor.cross_tenant_read",
}


def _cookie_send(base_send, cookie: "Optional[str]"):
    """Wrap a gated ``send`` so every request carries (or omits) a specific session Cookie. A None/empty
    cookie sends anonymously (any pre-existing Cookie header is stripped so the identity is unambiguous)."""
    def _s(req):
        headers = [h for h in (getattr(req, "headers", []) or []) if str(h[0]).lower() != "cookie"]
        if cookie:
            headers = headers + [("Cookie", cookie)]
        return base_send(req.model_copy(update={"headers": headers}))
    return _s


def access_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                   claimed_class: str, victim_cookie: str, attacker_cookie: "Optional[str]" = None,
                   ref_param: str = "", victim_ref: str = "", timeout: float = 8.0
                   ) -> RuntimeRedriveResult:
    """Re-drive a broken-object-level-authorization (bola / idor) claim as a TWO-IDENTITY cross-object read
    and mint a signed FACT ONLY when an UNDER-privileged identity actually receives the content that only the
    PRIVILEGED (owning) identity should see, judged by the achieved-state predicate over VIGIL's own gated
    capture: the attacker got 200, the victim's body has real content, and the attacker's body CONTAINS it.

    ``victim_cookie`` authenticates the owner (the ground-truth privileged read); ``attacker_cookie`` is the
    under-privileged identity (None = anonymous). For an object-level read pass ``ref_param``+``victim_ref``
    (the object reference the attacker reads cross-tenant); with neither, the whole ``url`` is compared as-is.
    The cookies + reference are the operator/engage-supplied 'where to look' — the FACT is decided by the wire
    bytes. A missing victim cookie, a failed/empty privileged read, a 403/empty attacker response, or a
    privileged body the attacker did NOT receive all stay a LEAD (fail-closed). No credential is minted or
    logged; the cookie is used only to establish the differential. FATAL-2: imports function-local."""
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.adapter import FindingContext  # noqa: PLC0415
    from framework.v2.verify.oracles import predicate_oracle  # noqa: PLC0415
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate
    from framework.v2.verify.verifier import normalize_bug_class  # noqa: PLC0415

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415
    from .verdict import Verdict, admit, branch_ids, compose  # noqa: PLC0415
    from .web_redrive import _gated_web_send  # noqa: PLC0415 — the reviewed gated, DNS-pinned, no-proxy send

    bug_class = normalize_bug_class(claimed_class)
    res = RuntimeRedriveResult(url=url, bug_class=bug_class)
    if bug_class not in ACCESS_FACT_CLASSES:
        res.notes.append(f"{bug_class!r} is not an access-redrive class")
        return res
    branch = _ACCESS_BRANCH_FOR[bug_class]
    if branch not in branch_ids():
        res.notes.append(f"branch {branch!r} is not registered — cannot admit (fail-closed)")
        return res
    if not str(victim_cookie or "").strip():
        res.notes.append("no privileged (victim) session supplied — cannot establish the differential → LEAD")
        return res
    if attacker_cookie and str(attacker_cookie).strip() == str(victim_cookie).strip():
        # reading your OWN object is not a cross-tenant read — the two identities must differ, else a same
        # identity trivially "contains" its own body and would false-FACT a BOLA.
        res.notes.append("attacker and victim identities are identical — not a cross-tenant read → LEAD")
        return res

    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res

    base_send, state = _gated_web_send(slug, timeout=timeout)
    victim_send = _cookie_send(base_send, victim_cookie)
    attacker_send = _cookie_send(base_send, attacker_cookie)
    anon_send = _cookie_send(base_send, None)   # the "is this object actually access-controlled?" control

    # object-level: render the object reference into the named query point (synthesising the param if the
    # proposed url does not already carry it); page-level: use the url as-is.
    if ref_param and victim_ref:
        probe_url = _url_with_param(url, ref_param)
        tmpl = RequestTemplate(HttpRequest(method="GET", url=probe_url))
        point = next((p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                      if p.name == ref_param), None)
        if point is None:
            res.notes.append(f"ref_param {ref_param!r} could not be established on the url → LEAD")
            return res
        victim_req = tmpl.render(point, victim_ref)
        attacker_req = tmpl.render(point, victim_ref)
        item = f"{probe_url}#{ref_param}={victim_ref}"
    else:
        tmpl = RequestTemplate(HttpRequest(method="GET", url=url))
        victim_req = tmpl.request
        attacker_req = tmpl.request
        item = url

    before = state["channels"]
    try:
        victim = victim_send(victim_req)
        attacker = attacker_send(attacker_req)
        anon = anon_send(attacker_req)   # same object reference, NO session — the access-control control
    except Exception as e:  # noqa: BLE001 — a transport error confirms nothing (fail-closed)
        res.notes.append(f"access probe error: {type(e).__name__}: {e}")
        return res
    if state["channels"] - before < 3:
        res.inconclusive.append((bug_class, item))   # victim + attacker + anon must each open a real channel
        return res

    victim_body = (str(victim.get("body", "")) if isinstance(victim, dict) else str(victim)).strip()
    attacker_body = str(attacker.get("body", "")) if isinstance(attacker, dict) else str(attacker)
    attacker_status = int(attacker.get("status", 0)) if isinstance(attacker, dict) else 0
    anon_body = str(anon.get("body", "")) if isinstance(anon, dict) else str(anon)

    # SOUND cross-tenant BOLA: the attacker (a DIFFERENT authenticated identity) received the victim's object
    # content, AND the object is demonstrably access-controlled — an ANONYMOUS request does NOT receive it.
    # Without the anon leg a PUBLIC object (served to everyone) or a total-no-auth endpoint would false-FACT:
    # a public object read by another user is not a broken object-level authorization. When anon also receives
    # the content the case is indistinguishable (public vs missing-auth) from the wire, so it stays a LEAD.
    context = FindingContext.from_predicate(
        {"attacker_status": attacker_status, "victim_body": victim_body, "attacker_body": attacker_body,
         "anon_body": anon_body},
        {"all": [
            {"eq": [{"var": "attacker_status"}, 200]},
            {"min_len": [{"var": "victim_body"}, 8]},
            {"contains": [{"var": "attacker_body"}, {"var": "victim_body"}]},
            {"not": {"contains": [{"var": "anon_body"}, {"var": "victim_body"}]}},
        ]},
        bug_class=bug_class,
    ).to_verifier_context()
    signal = predicate_oracle(context.get("observed_evidence", {}), context.get("predicate", {}))
    observed = {"channel_established": True, "gate_authorized": True}
    finding = {"check_id": f"access:{bug_class}:{item}#{branch}", "bug_class": bug_class,
               "insertion_point": ref_param or "", "oracle_context": context}
    admitted = admit(branch, fired=signal.fired, conclusive=signal.conclusive, observed=observed)
    res.admissions.append((branch, admitted.verdict.value, admitted.reason))
    res.branch_verdicts.setdefault(bug_class, {})[branch] = admitted.verdict.value
    r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                         provenance="live_redrive")
    res.contexts[r.finding_ref] = context
    if r.is_fact:
        res.facts.append(r)
    elif admitted.verdict is Verdict.INCONCLUSIVE:
        res.inconclusive.append((bug_class, f"{item}#{branch}"))
    else:
        res.leads.append(r)
    return res
