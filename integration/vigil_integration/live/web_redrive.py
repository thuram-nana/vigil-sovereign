"""web_redrive — a runner-owned, gated HTTP re-drive → ACHIEVED_STATE FACT (Wave #3, the web column).

A web tool (httpx / katana / nuclei) PROPOSES a URL; this re-drives it — the RUNNER (never the tool) crafts
the probe, sends it through a GATED HTTP client, and the existing deterministic ``predicate_oracle`` judges
the captured response. It mints a signed, offline-re-verifiable FACT for the web classes whose predicate is
a DEFINITE, EXPLOITABLE proposition over observed values (scoped to the co-located condition, not a loose
substring match — a benign reflecting page does not false-FACT):

  * open_redirect   — a 30x whose Location host == the injected canary host (or a meta/JS redirect to it);
  * cors            — Access-Control-Allow-Origin reflects the evil origin (or ``*``) AND ...-Credentials=true;
  * host_header_injection — a hostile Host header became a redirect Location authority (or a ``//evil`` in body);
  * graphql_introspection — VIGIL's OWN introspection query returns a well-formed schema (data.__schema.types).

It REUSES the shipped ``scanner.checks`` probes verbatim (same crafting + the exact predicate the oracle
already trusts) driven by a gated ``send`` — so nothing about the oracle or the predicate is reinvented; only
the transport is made charter-gated. A grype/nuclei match never mints a FACT; only this re-drive + the oracle
do (criterion-6). ``provenance="live_redrive"`` — the evidence is the runner's own live, gated capture.

FATAL-2: framework + urllib imports are FUNCTION-LOCAL; importing this module co-loads no offense engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# the web classes this wave mints as FACTs (each has a definite, exploitable-condition ACHIEVED_STATE predicate).
WEB_FACT_CLASSES = ("open_redirect", "cors", "host_header_injection", "graphql_introspection",
                    "oidc_redirect_uri")

# The subset of WEB_FACT_CLASSES a re-drive may mint from an LLM-SUPPLIED class claim (the autonomous engage
# seam, wiring._live_web_redrive_fact). oidc_redirect_uri is EXCLUDED: its distinguishing A07 impact (a broken
# redirect_uri at an OAuth/OIDC authorization endpoint that leaks the auth code/token) is NOT verified by any
# predicate — the live evidence is byte-identical to a plain open_redirect (a 3xx Location to the canary
# host), so the OIDC classification rests ENTIRELY on the claimant's label. That is defensible when the claim
# is a tool report (proof.run, where web_redrive still accepts oidc), but NOT when the claim is the model's
# free text: an honest / hallucinating / prompt-injected LLM could label a plain open redirect "oidc" and
# obtain a signed A07 certificate the deterministic layer only proved as A01. Until an OIDC-specific oracle
# (independent code/token evidence) exists, the LLM-claim seam never upgrades to oidc. (red-pen BLOCK-1)
LLM_CLAIM_WEB_FACT_CLASSES = tuple(c for c in WEB_FACT_CLASSES if c != "oidc_redirect_uri")

# ---------------------------------------------------------------------------
# HexStrike W2 — endpoint response-DISTINGUISHABILITY (the L7 analogue of the TCP tcp_handshake reachability
# FACT). Historical identifier: ``endpoint_liveness`` / ``achieved_state.endpoint_liveness``.
#
# THE NARROWED CLAIM (after two red-pen BLOCKs). This FACT does NOT claim "a live endpoint" / "a real
# resource" / "the endpoint exists". It claims EXACTLY: **VIGIL's own gated GET of this URL served content
# distinguishable from a same-shape, multi-sample-stable not-found baseline (i.e. it is not a soft-404 phantom
# of that shape).** A special-cased error page, a stub, or any distinguishable-but-not-"live" response is a
# TRUE statement of that narrowed claim; it is never upgraded to "live".
#
# A web-discovery tool (httpx / ffuf / …) PROPOSES a URL; the RUNNER (never the tool) sends PLAIN gated GETs
# (no canary) and the EXISTING ACHIEVED_STATE predicate_oracle adjudicates. Reuses ACHIEVED_STATE (no new
# OracleKind, so `make gate` stays byte-identical); the FACT is minted only by admit(branch) +
# certify_admitted(provenance="live_redrive") over VIGIL's OWN gated capture.
#
# SOUNDNESS (near-zero-FP, the soft-404 firewall — HARDENED twice). Two failure modes were found and closed:
#   BLOCK-1 (coarse char-class): a control of a WIDER class than the route (e.g. a random alnum control on a
#     hex/uuid route) 404s as a route-MISS while a well-formed nonexistent target soft-404s 200 → false FACT.
#     FIXED by a NARROW-CLASS, structure-preserving mirror: the control mirrors the target segment's exact
#     per-position character class (digits→digits, lower/upper-hex→same-hex, uuid dashes preserved, base64
#     alphabet preserved, alpha/alnum→same), same length + extension, RANDOMIZED. If the class is AMBIGUOUS
#     (e.g. all-a–f letters, which is both alpha and hex) or otherwise not confidently mirrorable, it FAILS
#     CLOSED to a LEAD — never a coarse-bucket guess. A root/directory URL (no last segment) also fails closed.
#   BLOCK-2 (bounded not-found body space): a soft-404 whose not-found body is one of a SMALL set (random per
#     request, or per path) let two controls COLLIDE on one body ~1/b of the time → a spurious "stable
#     baseline" the target differs from → an INTERMITTENT false FACT. FIXED by MULTI-SAMPLE stability: the
#     baseline is many DISTINCT same-shape controls, EACH resampled, and the target itself resampled; a FACT
#     requires EVERY control sample to agree on status AND body-hash (a bounded/varying space fails to agree
#     across many samples → no baseline → LEAD) AND the target to be stable across its resamples.
#
# The FACT fires ONLY when VIGIL's own gated GETs show: (1) the target is a served status (2xx/3xx) and is
# STABLE across its resamples; (2) all control samples reached a channel and AGREE on one status AND one
# body-hash (a multi-sample-stable not-found baseline); and (3) the target is DISTINGUISHABLE from that
# baseline by a different status OR a different body-hash. The predicate is a pure JSON AST over RAW status
# codes + RAW body hashes of every sample, so the certificate re-verifies OFFLINE like every predicate_oracle
# FACT. The CLEAN direction (a channel-confirmed hard 404/410 at the exact URL, control-independent, bounded
# to the probed URL) is unchanged.
ENDPOINT_LIVENESS_BUG_CLASS = "endpoint_liveness"
ENDPOINT_LIVENESS_BRANCH = "achieved_state.endpoint_liveness"
# served-resource statuses the TARGET must return (2xx/3xx). 401/403/405/5xx are deliberately NOT minted here:
# they are exists-but-gated / error responses that a plain GET cannot soundly separate from a blanket policy,
# so they stay INCONCLUSIVE. A definite hard not-found at the TARGET (404/410) is the channel-confirmed CLEAN
# case — bounded to the EXACT probed URL, never an enumeration-completeness claim.
_TARGET_ABSENT_STATUSES = frozenset({404, 410})
# Multi-sample budget (BLOCK-2). DISTINCT same-shape controls dominate robustness against a per-PATH bounded
# body space; resampling each control + the target dominates robustness against a per-REQUEST varying body.
# All control samples must agree for a baseline; the per-run false-FACT window on a b-element bounded space is
# ~ (1/b)^(N_CONTROLS-1), driven to ~0 by the DISTINCT count.
_LIVENESS_CONTROLS = 10         # DISTINCT same-shape not-found control URLs (dominates per-PATH robustness)
_LIVENESS_RESAMPLES = 2         # times EACH control is fetched (catches per-REQUEST variance)
_LIVENESS_TARGET_SAMPLES = 3    # times the TARGET is fetched (its response must be stable across these)
# The FLOOR of distinct same-shape controls a FACT needs: a short segment / small alphabet (e.g. a single
# digit) cannot yield the full _LIVENESS_CONTROLS distinct siblings, so the runner uses AS MANY distinct as
# the mirror space allows, down to this floor; fewer than this ⇒ the baseline is too thin to multi-sample ⇒
# FAIL CLOSED to a LEAD. The predicate is generated for the ACTUAL sample count and retained per-finding, so a
# variable count still re-verifies offline against exactly the predicate that was minted.
_MIN_LIVENESS_CONTROLS = 4


def _build_liveness_predicate(n_control_samples: int, n_target_samples: int) -> dict:
    """Generate the liveness FACT predicate as a pure JSON AST over RAW per-sample values (no rubber-stamp —
    every decision is an AST op over retained raw statuses + body hashes, so the certificate re-verifies
    OFFLINE). Fires iff: the target is 2xx/3xx and STABLE across its samples; ALL ``n_control_samples`` control
    samples reached a channel and AGREE on one status AND one body-hash (a multi-sample-stable not-found
    baseline); and the target is DISTINGUISHABLE from that baseline by status or body-hash. The AST is
    generated for the EXACT number of samples the runner captured and retained with the finding, so a
    variable control count (a short-segment URL yields fewer distinct siblings) still re-verifies offline."""
    clauses: list = [
        {"ge": [{"var": "target_0_status"}, 200]},
        {"not": {"ge": [{"var": "target_0_status"}, 400]}},
    ]
    # target STABLE across its resamples (an unstable target — random content — cannot be soundly judged).
    for j in range(1, n_target_samples):
        clauses.append({"eq": [{"var": "target_0_status"}, {"var": f"target_{j}_status"}]})
        clauses.append({"eq": [{"var": "target_0_sha"}, {"var": f"target_{j}_sha"}]})
    # baseline: control_0 reached a real channel (status >= 100), and EVERY control sample agrees on both
    # status AND body-hash — a multi-sample-stable not-found baseline (a bounded/varying space fails this).
    clauses.append({"ge": [{"var": "control_0_status"}, 100]})
    for i in range(1, n_control_samples):
        clauses.append({"eq": [{"var": "control_0_status"}, {"var": f"control_{i}_status"}]})
        clauses.append({"eq": [{"var": "control_0_sha"}, {"var": f"control_{i}_sha"}]})
    # DISTINGUISHABLE: the (stable) target differs from the (stable) baseline by status or body-hash.
    clauses.append({"any": [
        {"not": {"eq": [{"var": "target_0_status"}, {"var": "control_0_status"}]}},
        {"not": {"eq": [{"var": "target_0_sha"}, {"var": "control_0_sha"}]}},
    ]})
    return {"all": clauses}


@dataclass
class WebLivenessResult:
    """The outcome of ONE endpoint-liveness re-drive of a single URL. ``fact`` is a signed AdapterResult when
    VIGIL's own gated GETs proved a live endpoint distinct from its SAME-SHAPE not-found controls; ``context``
    is the retained oracle_context (predicate + raw statuses + raw body hashes) for OFFLINE re-verify.
    Otherwise ``lead`` holds a labelled lead (soft-404 / hard-404 CLEAN / unreachable / no-sound-control).
    ``outcome`` is one of positive|clean|inconclusive|deceptive_no_fact|refused."""

    url: str
    control_urls: list = field(default_factory=list)
    fact: Any = None
    lead: Any = None
    context: "dict | None" = None
    outcome: str = ""
    target_status: int = 0
    control_statuses: list = field(default_factory=list)
    note: str = ""
    refused: bool = False

    @property
    def is_fact(self) -> bool:
        return self.fact is not None


def _alnum_class_alphabet(alnum_chars: "set[str]") -> "str | None":
    """The alphabet of the NARROWEST well-known character class that contains EXACTLY the observed alnum
    characters, or ``None`` when the class is AMBIGUOUS (BLOCK-1 fail-closed). The candidate classes form a
    subset lattice (digits ⊂ hex ⊂ alnum; alpha ⊂ alnum; …). A control drawn from the target's narrowest
    class is ⊆ the route's accepted class (the target is accepted, so its class ⊆ the route's), so the control
    is route-valid and a 404 on it is a real not-found, not a route-miss. When two INCOMPARABLE minimal classes
    both fit (e.g. all a–f letters, which is both lower-alpha and lower-hex) the route class is genuinely
    ambiguous → return None → the caller fails closed to a LEAD rather than guess a wider bucket."""
    import string  # noqa: PLC0415 — stdlib, function-local
    classes = {
        "digits": set(string.digits),
        "lower_hex": set("0123456789abcdef"),
        "upper_hex": set("0123456789ABCDEF"),
        "lower_alpha": set(string.ascii_lowercase),
        "upper_alpha": set(string.ascii_uppercase),
        "alpha": set(string.ascii_letters),
        "lower_alnum": set(string.ascii_lowercase + string.digits),
        "upper_alnum": set(string.ascii_uppercase + string.digits),
        "alnum": set(string.ascii_letters + string.digits),
    }
    containing = {name: s for name, s in classes.items() if alnum_chars and alnum_chars <= s}
    if not containing:
        return None
    # minimal = no OTHER containing class is a strict subset of it. A unique minimum ⇒ that class; otherwise
    # (0 or ≥2 incomparable minima) the shape is ambiguous ⇒ fail closed.
    minimal = [name for name, s in containing.items()
               if not any(other != name and containing[other] < s for other in containing)]
    if len(minimal) != 1:
        return None
    return "".join(sorted(classes[minimal[0]]))


def _same_shape_sibling(seg: str, rand: Any) -> "str | None":
    """A randomized NARROW-CLASS, STRUCTURE-PRESERVING sibling of the last path segment ``seg``, or ``None``
    when its shape cannot be confidently mirrored (BLOCK-1 fail-closed → the caller degrades to a LEAD).

    Per-position mirror: every NON-alphanumeric character (a ``-`` in a UUID, an ``_``/``+``/``=`` in base64,
    an internal ``.``) is KEPT IN PLACE so the STRUCTURE is preserved; every alphanumeric position is replaced
    by a random character from the NARROWEST class the segment's alnum characters fit
    (:func:`_alnum_class_alphabet`) — hex→hex, uuid→uuid (dashes kept, hex in the hex slots), base64→base64
    alnum, numeric→numeric, alpha/alnum→same. Preserves LENGTH and a trailing EXTENSION (``foo.php`` →
    ``<same-len>.php``). Returns ``None`` (fail closed) when there is no alnum position to randomise or the
    class is ambiguous. Pure/lexical — no network, no fixed literal a signature rule can fingerprint."""
    if not seg:
        return None
    stem, dot, ext = seg.rpartition(".")
    if dot and stem and 1 <= len(ext) <= 8 and ext.isalnum():
        base, suffix = stem, "." + ext
    else:
        base, suffix = seg, ""
    if not base:
        return None
    alnum_positions = [i for i, c in enumerate(base) if c.isalnum()]
    if not alnum_positions:
        return None   # nothing to randomise (all separators) — cannot mirror
    alphabet = _alnum_class_alphabet({base[i] for i in alnum_positions})
    if alphabet is None:
        return None   # ambiguous class — fail closed (do not guess a coarse bucket)
    chars = list(base)
    for i in alnum_positions:
        chars[i] = rand.choice(alphabet)
    return "".join(chars) + suffix


def _liveness_control_urls(url: str, n: int = _LIVENESS_CONTROLS) -> "list[str]":
    """Return UP TO ``n`` NARROW-CLASS, structure-preserving, randomized, DISTINCT sibling control URLs of
    ``url`` under the SAME origin (scheme/host/port) and the SAME parent directory — the last path segment
    mirrored by :func:`_same_shape_sibling`. Best-effort: a short segment / small alphabet (e.g. a single
    digit, whose mirror space is only 10) yields fewer than ``n``; the caller enforces the
    :data:`_MIN_LIVENESS_CONTROLS` floor and fails closed below it. Returns ``[]`` when there is no mirrorable
    last segment (a root/directory URL like ``/`` or ``/api/``) or the shape is ambiguous/un-mirrorable.
    Same host as the target, so each is authorised by the identical charter scope the target GET is (the
    host-pin invariant). Purely lexical over the URL — no network."""
    import secrets  # noqa: PLC0415 — stdlib, function-local
    from urllib.parse import urlsplit, urlunsplit  # noqa: PLC0415 — stdlib, function-local
    rand = secrets.SystemRandom()
    parts = urlsplit(url)
    path = parts.path or "/"
    slash = path.rfind("/")
    parent = path[: slash + 1] if slash >= 0 else "/"
    seg = path[slash + 1:] if slash >= 0 else path
    if not seg:
        return []   # a root/directory URL has no last segment to mirror — fail closed to a LEAD
    if _same_shape_sibling(seg, rand) is None:
        return []   # shape cannot be mirrored / ambiguous class → fail closed
    urls: "list[str]" = []
    tokens: "set[str]" = {seg}
    # collect as many DISTINCT same-shape siblings as the mirror space allows, up to n. Bounded retries per
    # slot; when the space is exhausted (many misses in a row) we stop with what we have — the caller enforces
    # the minimum. All siblings are != the target segment (seeded into ``tokens``).
    misses = 0
    while len(urls) < n and misses < 256:
        tok = _same_shape_sibling(seg, rand)
        if tok is None:                       # (shape checked above; defensive)
            break
        if tok in tokens:
            misses += 1
            continue
        tokens.add(tok)
        urls.append(urlunsplit((parts.scheme, parts.netloc, parent + tok, "", "")))
    return urls


def endpoint_liveness_redrive(url: str, *, slug: str, engagement_slug: str,
                             signers: "list[tuple[str, str]]", timeout: float = 8.0) -> WebLivenessResult:
    """Re-drive ``url`` with VIGIL's OWN plain gated GET (no canary) and mint a signed ACHIEVED_STATE FACT
    when the URL is a LIVE endpoint the server distinguishes from nonexistent SAME-SHAPE siblings. The L7
    analogue of the TCP handshake reachability FACT. Returns a :class:`WebLivenessResult`. NEVER raises.

    Order (fail-closed): pre-flight the charter gate ONCE (a refused engagement means VIGIL never observed the
    target — no channel, so no fact and no CLEAN); GET the target through the gated send; GET two SAME-SHAPE
    not-found controls; run the predicate_oracle over the RAW statuses + RAW body hashes; admit through the
    ``achieved_state.endpoint_liveness`` branch; certify only a FACT admission. The CLEAN direction (a
    channel-confirmed hard 404/410 at the exact URL) is control-independent and bounded to the probed URL."""
    from framework.v2.scanner.insertion import HttpRequest  # noqa: PLC0415 (FATAL-2: function-local)
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate

    from ..oracle_adapter import AdapterResult, certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit  # noqa: PLC0415

    res = WebLivenessResult(url=url)
    finding_ref = f"web:endpoint_liveness:{url}"

    # PRE-FLIGHT the gate ONCE: a refused engagement (kill-switch / out-of-scope / no-slug / bad URL) means
    # VIGIL never observed the target — there is NO channel, so we must NOT mint and must NOT report a
    # channel-confirmed CLEAN. Return refused with zero adjudication (no traffic).
    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.outcome = "refused"
        res.note = f"refused before any traffic: {refusal}"
        return res

    def _status(resp: "dict | None") -> int:
        return int((resp or {}).get("status", 0) or 0)

    def _sha(resp: "dict | None") -> str:
        return str((resp or {}).get("raw_sha256", "") or "")

    send, _state = _gated_web_send(slug, timeout=timeout)
    control_urls = _liveness_control_urls(url)
    # enforce the multi-sample FLOOR: below _MIN_LIVENESS_CONTROLS distinct same-shape siblings the not-found
    # baseline is too thin to be trusted, so fail closed (no controls ⇒ the FACT cannot fire; a hard-404 target
    # can still be a control-independent CLEAN).
    if len(control_urls) < _MIN_LIVENESS_CONTROLS:
        control_urls = []
    res.control_urls = list(control_urls)
    try:
        # TARGET first, resampled T times — its response must be STABLE across resamples (a random-content
        # target cannot be soundly judged). All sends are total (a refusal/error is a status-0 _EMPTY).
        target_samples = [send(HttpRequest(method="GET", url=url)) for _ in range(_LIVENESS_TARGET_SAMPLES)]
        target_statuses = [_status(t) for t in target_samples]
        target_channel = any(s >= 100 for s in target_statuses)
        target_all_absent = target_channel and all(s in _TARGET_ABSENT_STATUSES for s in target_statuses)
        # CONTROLS: each DISTINCT same-shape URL resampled K times (BLOCK-2 multi-sample stability). Skipped
        # when the target had no channel (deceptive), when no sound same-shape control exists (fail closed),
        # or when the target is a hard not-found (the CLEAN path is control-independent).
        control_samples: list = []
        if target_channel and control_urls and not target_all_absent:
            for c in control_urls:
                for _ in range(_LIVENESS_RESAMPLES):
                    control_samples.append(send(HttpRequest(method="GET", url=c)))
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return a lead
        res.outcome = "inconclusive"
        res.note = f"probe error: {type(e).__name__}: {e}"
        res.lead = AdapterResult("lead", res.note, ENDPOINT_LIVENESS_BUG_CLASS, finding_ref,
                                 outcome="inconclusive")
        return res

    if not target_channel:
        # DECEPTIVE: the tool claimed the URL, but VIGIL's OWN gated GET reached no channel (transport error /
        # mid-run gate deny). NOT reproducible ⇒ NO fact (never a CLEAN — no channel means nothing examined).
        res.outcome = "deceptive_no_fact"
        res.note = ("VIGIL's own gated GET reached no channel — the tool's URL claim is not reproducible "
                    "(deceptive_no_fact)")
        res.lead = AdapterResult("lead", res.note, ENDPOINT_LIVENESS_BUG_CLASS, finding_ref,
                                 outcome="inconclusive")
        return res

    res.target_status = target_statuses[0]
    res.control_statuses = sorted({_status(s) for s in control_samples})
    # observed_evidence: EVERY raw sample (status + raw body hash), keyed for the generated predicate AST — no
    # rubber-stamp, the AST does all the comparing. The predicate is generated for the ACTUAL captured sample
    # count (short-segment URLs yield fewer distinct siblings, so the count varies) and retained WITH the
    # finding, so the certificate re-verifies offline against exactly the predicate that was minted. An empty
    # control set (fail-closed / hard-404 skip) yields a predicate whose control_0 clause references an absent
    # var ⇒ it cannot fire ⇒ no FACT.
    observed_evidence: dict = {"target_url": url, "control_urls": list(control_urls)}
    for j, t in enumerate(target_samples):
        observed_evidence[f"target_{j}_status"] = _status(t)
        observed_evidence[f"target_{j}_sha"] = _sha(t)
    for i, s in enumerate(control_samples):
        observed_evidence[f"control_{i}_status"] = _status(s)
        observed_evidence[f"control_{i}_sha"] = _sha(s)
    context = {"predicate": _build_liveness_predicate(len(control_samples), _LIVENESS_TARGET_SAMPLES),
               "observed_evidence": observed_evidence}

    # The ACHIEVED_STATE predicate decides the FIRE over VIGIL's own multi-sample captures; the runner computes
    # CONCLUSIVENESS (predicate_oracle is always conclusive, but this branch must distinguish a channel-
    # confirmed hard-404 CLEAN from a soft-404 / no-sound-control / unstable ambiguity). A non-fire is
    # conclusive ONLY when the target was a definite hard not-found (404/410) on EVERY resample — then the exact
    # URL is a channel-confirmed non-served endpoint (CLEAN, bounded to THIS URL, control-independent). A
    # non-fire where the target served but the multi-sample same-shape baseline did not corroborate a
    # distinction (soft-404 / bounded-body / echo / unstable / no mirrorable control) is INCONCLUSIVE.
    signal = _oracle_signal(context)
    fired = signal.fired
    conclusive = fired or target_all_absent
    admitted = admit(ENDPOINT_LIVENESS_BRANCH, fired=fired, conclusive=conclusive,
                     observed={"channel_established": True, "gate_authorized": True})

    finding = {"check_id": finding_ref, "bug_class": ENDPOINT_LIVENESS_BUG_CLASS,
               "insertion_point": url, "oracle_context": context}
    r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                         provenance="live_redrive")
    if r.is_fact:
        res.fact = r
        res.context = context
        res.outcome = "positive"
        # NARROWED CLAIM (never "live endpoint"): served content distinguishable from a multi-sample-stable
        # same-shape not-found baseline.
        res.note = (f"served content DISTINGUISHABLE from a multi-sample-stable same-shape not-found baseline: "
                    f"target status {res.target_status} over {_LIVENESS_TARGET_SAMPLES} samples vs "
                    f"{len(control_samples)} control samples across {len(control_urls)} same-shape siblings "
                    f"(not a soft-404 phantom of that shape). NOT a claim that the endpoint is 'live'/real.")
        return res
    # not a FACT — a labelled lead. classify: CLEAN (channel-confirmed hard-404, bounded to THIS url) vs
    # INCONCLUSIVE (soft-404 / bounded-body / no-sound-control / ambiguous). certify_admitted stamped r.outcome.
    res.lead = r
    res.outcome = "clean" if admitted.verdict is Verdict.CLEAN else "inconclusive"
    if admitted.verdict is Verdict.CLEAN:
        res.note = (f"channel-confirmed hard not-found ({res.target_status}) at THIS exact URL — CLEAN bounded "
                    f"to the probed URL only, never a claim that no other endpoint exists")
    elif not control_urls:
        res.note = ("no sound NARROW-CLASS same-shape control for this URL (a root/directory URL or an "
                    "ambiguous/un-mirrorable last segment) — fails closed to a LEAD")
    else:
        res.note = (f"no distinguishable-content FACT: target {res.target_status}, control statuses "
                    f"{res.control_statuses} — the server does not distinguish this URL from a same-shape "
                    f"sibling across multi-sampling (soft-404 / bounded-body / echo / unstable baseline); a LEAD")
    return res


@dataclass
class WebRedriveResult:
    url: str
    facts: list = field(default_factory=list)     # AdapterResult (status=="fact"), signed
    leads: list = field(default_factory=list)     # AdapterResult (status=="lead") — CHANNEL-CONFIRMED
    inconclusive: list = field(default_factory=list)  # (bug_class, item) — a probe with NO channel; never CLEAN
    admissions: list = field(default_factory=list)    # (branch, verdict, reason) — the audit trail
    branch_verdicts: dict = field(default_factory=dict)  # bug_class -> {branch: verdict}
    contexts: dict = field(default_factory=dict)  # finding_ref -> oracle_context (offline re-verify)
    insertion_surfaces: dict = field(default_factory=dict)  # bug_class -> set(surface) actually EXAMINED
    probed_redirect_param_names: list = field(default_factory=list)  # candidate names on the synth carriers
    refused: bool = False
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)

    def surfaces_probed(self, bug_class: str) -> list:
        """The insertion surfaces on which ``bug_class`` was ACTUALLY examined (a channel was established),
        in a stable order. A surface only appears here if a real HTTP response came back on it — a
        gate-refused or transport-errored probe examined nothing and is deliberately excluded."""
        return sorted(self.insertion_surfaces.get(bug_class, set()))

    def coverage_statement(self, bug_class: str) -> str:
        """Name the insertion surfaces a CLEAN for ``bug_class`` is BOUNDED to.

        The product thesis is a SOUND negative: a CLEAN must mean "examined here and found nothing", never
        "did not look". So a family CLEAN is only honest when it also names WHERE it looked. An empty
        coverage set is not a clean bill of health — it is INCONCLUSIVE (nothing was examined)."""
        surfaces = self.surfaces_probed(bug_class)
        if not surfaces:
            return (f"{bug_class}: no insertion surface established a channel — INCONCLUSIVE, not CLEAN "
                    f"(nothing was examined)")
        return (f"{bug_class}: examined across insertion surfaces [{', '.join(surfaces)}]; any CLEAN is "
                f"bounded to these surfaces and the probed redirect-parameter names, never a claim of "
                f"absence on a surface or parameter name not examined")

    def family_coverage(self) -> dict:
        """Every examined family -> the insertion surfaces it was examined on (for persisted reporting)."""
        return {bug: self.surfaces_probed(bug) for bug in self.insertion_surfaces}

    def family_verdict(self, bug_class: str) -> str:
        """The conservative composition over every branch of ``bug_class`` (see verdict.compose).

        Reporting must use this rather than any single branch: a CLEAN header branch sitting beside a FACT
        body branch would otherwise be summarised as a clean family, asserting safety no branch established."""
        from .verdict import compose  # noqa: PLC0415
        return compose(list(self.branch_verdicts.get(bug_class, {}).values())).value

    def family_verdicts(self) -> dict:
        """Every examined family, conservatively composed."""
        return {bug: self.family_verdict(bug) for bug in self.branch_verdicts}


def _gated_web_send(slug: str, *, timeout: float = 8.0):
    """Return ``(send, state)``. ``send`` is a ``scanner.checks.Send`` —
    ``send(HttpRequest) -> {status, body, headers, latency_ms}`` — that AUTHORIZES each request's URL
    through the URL-shaped active-recon gate (kill-switch → single-host → ACTIVE_RECON → charter scope →
    http(s), no embedded creds) BEFORE issuing it, follows NO redirects (so the raw Location is captured),
    and is bounded.

    ``state`` is a mutable ``{"channels": int, "no_channel": int}`` counter the runner uses to tell a
    GENUINE observation from a NON-observation. A refusal (per-request gate deny / kill-switch tripped
    mid-run) or any transport error (connection refused, timeout, DNS failure) increments ``no_channel``
    and returns a status-0 empty response — the check sees nothing and mints no FACT (never an un-gated
    send). The runner MUST NOT treat a no-channel probe as a "channel-confirmed CLEAN": no channel means
    INCONCLUSIVE, not clean (the "found nothing != CLEAN" invariant). Only a real HTTP response — any
    status, including 4xx/5xx — increments ``channels``."""
    import time
    import urllib.error
    import urllib.request

    from framework.v2.verify.reachability_cloud import _authorize  # the URL-shaped gate (offense-side)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D401
            return None

    from urllib.parse import urlsplit

    from .body_decode import MAX_RAW_BYTES, decode_body
    from .dns_pin import pinned_handlers, resolve_and_validate

    def _address_authorized(address: str) -> bool:
        """Re-ask the SAME gate about the resolved address. Reusing the charter decision (rather than a
        second, looser rule) is what keeps the pin honest: an address the gate would refuse as a target is
        refused as a destination."""
        scheme = "https" if str(address).count(":") > 1 else "http"   # bracket IPv6 for the URL form
        literal = f"[{address}]" if str(address).count(":") > 1 else address
        return _authorize(f"http://{literal}/", slug) is None

    _EMPTY = {"status": 0, "body": "", "headers": [], "latency_ms": 0.0,
              "body_semantically_available": False, "body_unavailable_reason": "no channel"}
    state = {"channels": 0, "no_channel": 0, "body_unavailable": 0}

    def send(req: Any) -> dict:
        if _authorize(req.url, slug) is not None:
            state["no_channel"] += 1
            return dict(_EMPTY)   # refused (gate deny / kill-switch mid-run) — NO channel, not a CLEAN
        data = req.body.encode("utf-8") if getattr(req, "body", None) else None
        r = urllib.request.Request(req.url, data=data, method=getattr(req, "method", "GET"))
        for k, v in getattr(req, "headers", []) or []:
            r.add_header(k, v)
        if not r.has_header("Accept-encoding"):
            # Ask only for encodings we can reverse. A target may still answer with something else (some
            # CDNs compress unconditionally) — that path is handled by decode_body, which refuses rather
            # than guessing, so the body is INCONCLUSIVE rather than silently mangled.
            r.add_header("Accept-Encoding", "gzip, deflate, identity")
        # An EMPTY ProxyHandler is MANDATORY (mirrors the shipped gated connector): without it urllib honours
        # http_proxy/https_proxy/ALL_PROXY, so the real TCP peer would be a proxy the gate never authorized —
        # the charter/single-host scope check would pass while traffic went elsewhere, and the proxy's bytes
        # would be labelled provenance="live_redrive". No auth handler either: the probe stays anonymous.
        # DNS time-of-check/time-of-use: the gate authorized a NAME, but urllib would resolve that name
        # again at connect time, so nothing binds the authorization to the endpoint actually reached
        # (rebinding, a short TTL, a poisoned resolver, or a multi-A record with one address out of scope).
        # Resolve once, require EVERY address to satisfy the same charter scope the gate used, then PIN the
        # connection to the validated address while still presenting the original hostname for TLS/Host.
        parts = urlsplit(req.url)
        target_host = parts.hostname or ""
        target_port = parts.port or (443 if parts.scheme == "https" else 80)
        resolution = resolve_and_validate(target_host, target_port, _address_authorized)
        if not resolution.allowed:
            state["no_channel"] += 1
            refused = dict(_EMPTY)
            refused["body_unavailable_reason"] = resolution.refused_reason
            return refused
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect,
                                             *pinned_handlers(resolution.pinned))
        t0 = time.monotonic()
        try:
            # Read ONE BYTE PAST the bound: reading exactly the cap cannot distinguish "the response was
            # this long" from "the response was longer and we hold a prefix", and a body-dependent NEGATIVE
            # over a prefix cannot prove the absence of markup.
            with opener.open(r, timeout=timeout) as resp:
                status, raw, headers = resp.status, resp.read(MAX_RAW_BYTES + 1), list(resp.headers.items())
        except urllib.error.HTTPError as e:      # a 4xx/5xx is a real, useful response — a genuine channel
            status, raw, headers = e.code, e.read(MAX_RAW_BYTES + 1), list(e.headers.items())
        except Exception:                        # noqa: BLE001 — transport error (no channel) → INCONCLUSIVE
            state["no_channel"] += 1
            return dict(_EMPTY)
        state["channels"] += 1
        headers = [(str(k), str(v)) for k, v in headers]
        truncated = len(raw) > MAX_RAW_BYTES
        body = decode_body(raw[:MAX_RAW_BYTES], headers, truncated=truncated)
        # The capture carries its own decoding provenance so an adjudicator can tell "the document said
        # nothing" from "we never read the document".
        if not body.body_semantically_available:
            # A real channel, but NOT a readable document. Header-derived evidence in this same response
            # stays adjudicable; body-derived evidence must not be scored as CLEAN over bytes we never
            # decoded, so the runner is told.
            state["body_unavailable"] += 1
        return {"status": status, "body": body.text, "headers": headers,
                "latency_ms": (time.monotonic() - t0) * 1000.0,
                "pinned_ip": resolution.pinned, "resolved_addresses": list(resolution.addresses),
                "raw_sha256": body.raw_sha256, "raw_len": body.raw_len,
                "content_encoding": body.content_encoding, "charset": body.charset,
                "decoded": body.decoded, "truncated": body.truncated,
                "body_semantically_available": body.body_semantically_available,
                "body_unavailable_reason": body.reason}

    return send, state


def benign_control_fetch(url: str, *, slug: str, timeout: float = 8.0) -> "bytes | None":
    """One VIGIL-owned, GATED, benign GET of ``url`` (no payload, no canary) — the CONTROL an error-signature
    proof is compared against (S6). Its response BODY bytes are what ``verify.oracles.error_signature_oracle``
    checks the exploit response against: the same datastore/parser error present in BOTH the exploit and this
    benign control means the page always errors ⇒ NOT attributable ⇒ the mint stays a LEAD.

    It reuses the SAME charter-gated, DNS-pinned, proxy-free send as the web re-drive (kill-switch →
    single-host → ACTIVE_RECON → charter scope), so a control is only ever fetched from an in-scope target.
    Returns the decoded body bytes when a real channel was established AND the whole document was read and
    soundly decoded, else ``None`` — a refusal (out of scope / kill-switch), a transport error, an
    un-decodable body, OR a body the send could only capture as a PREFIX (``truncated``: the document was
    longer than ``MAX_RAW_BYTES``) all yield ``None``. The truncated-but-decodable case is the load-bearing
    one: the send caps the control at ``MAX_RAW_BYTES`` while the observed side is the (uncapped) retained
    blob, so returning a decoded PREFIX would let the oracle compare an error present in the full observed
    response against a control from which that error was merely truncated away — an always-erroring page
    whose datastore error sits past the cap would then mint a FALSE FACT. A control we cannot soundly
    adjudicate over (``not body_semantically_available``) is therefore refused: the caller degrades the FACT
    to a LEAD (fail-closed), never adjudicates over bytes it never read. NEVER raises."""
    if not str(url or "").strip():
        return None
    try:
        from framework.v2.scanner.insertion import HttpRequest  # noqa: PLC0415 — FATAL-2 (offense plane)
        from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate

        # PRE-FLIGHT the gate ONCE (mirrors ``web_redrive``): a refused engagement means VIGIL never observed
        # the target, so there is no control to compare against — refuse rather than send.
        if _authorize(url, slug) is not None:
            return None
        send, state = _gated_web_send(slug, timeout=timeout)
        resp = send(HttpRequest(method="GET", url=url))
        if state["channels"] <= 0:
            return None   # no channel established (gate deny mid-run / transport error) ⇒ no control
        # Refuse a control the module cannot soundly adjudicate OVER THE WHOLE DOCUMENT. ``send`` reads only
        # ``MAX_RAW_BYTES`` and sets ``body_semantically_available = decoded and not truncated``; the observed
        # side (proof/run.py::_resolve) is the UNCAPPED retained blob. A truncated (or un-decodable) control
        # would be captured ASYMMETRICALLY against the observed bytes — an error past the cap absent from the
        # prefix would fail to suppress a fire — so mirror the web_redrive runner's INCONCLUSIVE handling
        # (``state["body_unavailable"]``) and refuse. A None control ⇒ the caller keeps the mint fail-closed.
        if not resp.get("body_semantically_available"):
            return None
        body = resp.get("body")
        if isinstance(body, (bytes, bytearray)):
            return bytes(body) or None
        if isinstance(body, str):
            return body.encode("utf-8", errors="replace") or None
        return None
    except Exception:  # noqa: BLE001 — a control fetch must never raise into the mint; no channel ⇒ None
        return None


# The insertion surfaces this re-drive probes for open-redirect. A redirect parameter is NOT only a query
# value: apps read next/returnTo from a URL PATH segment, a COOKIE, a urlencoded BODY, or a JSON BODY just as
# often. A bare GET template exposes only the URL, so restricting the re-drive to QUERY_VALUE / URL_PATH_SEG
# meant those other surfaces were ABSENT from adjudication — not reported unexamined, simply missing, which
# reads to a consumer as "nothing there" and let a redirect reachable ONLY via a cookie/body param be
# reported CLEAN (a latent false-CLEAN). The runner therefore SYNTHESISES the cookie / urlencoded / JSON
# carriers (each with the correct method + Content-Type) so those insertion points EXIST to be rendered into
# and adjudicated by the SAME admission path. No benign-twin baseline is needed for soundness: the
# OpenRedirectCheck predicate fires ONLY on a real navigation to the UNIQUE canary HOST — which the app can
# only reach by using the injected value as a redirect target — so a benign reflection never false-FACTs.
# QUERY_NAME / BODY_FORM_NAME / JSON_KEY stay OUT as an ORACLE BOUNDARY: a canary injected as a parameter
# NAME does not model the redirect-VALUE property under test.
#
# Named by VALUE, not by enum member: the framework import is function-local (FATAL-2), so this module must
# not reference InsertionKind at import time. _redirect_templates() resolves them where the enum is available.

# Well-known redirect-parameter names tried on the synthesised cookie/body/JSON carriers, in addition to any
# name the proposed URL itself carries. A CLEAN over the synthesised surfaces is BOUNDED to this candidate
# set — stated honestly in the coverage statement — never a claim that no body/cookie redirect exists under
# some other name. Kept small so the re-drive's request footprint stays bounded.
_REDIRECT_PARAM_NAMES = (
    "next", "url", "redirect", "redirect_uri", "redirect_url", "returnto", "return_url",
    "returnurl", "return", "dest", "destination", "continue",
)
_MAX_CANDIDATE_REDIRECT_NAMES = 12


def _candidate_redirect_names(url: str) -> "list[str]":
    """Redirect-parameter names to try on the synthesised cookie/body/JSON carriers.

    GROUNDED first in the names the proposed URL actually carries (so an endpoint's real redirect parameter
    is exercised on EVERY surface, not only the query), then a small fixed set of well-known names for
    breadth, de-duplicated case-insensitively and capped. Purely lexical over the URL — no network."""
    from urllib.parse import parse_qsl, urlsplit  # noqa: PLC0415 — stdlib, function-local (style parity)
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
    for n in _REDIRECT_PARAM_NAMES:
        if n not in seen:
            names.append(n)
            seen.add(n)
    return names[:_MAX_CANDIDATE_REDIRECT_NAMES]


def _redirect_templates(url, names, http_request, insertion_kind, request_template):
    """The ``(RequestTemplate, insertion-kinds)`` carriers the open-redirect re-drive probes.

    Four carriers, each restricted to the surface it introduces so the URL query/path is not re-probed by the
    body carriers: the bare GET (URL query + path), a GET with a synthesised Cookie header, a POST with a
    urlencoded body, and a POST with a JSON body. ``names`` (from :func:`_candidate_redirect_names`) are the
    redirect-parameter names placed on the synthesised carriers — the caller passes them so it can also record
    the CLEAN's parameter-name bound. Every carrier feeds the identical admission path, so each surface's
    outcome is attributed and capability-checked like any other. Returns a list; never raises."""
    import json  # noqa: PLC0415 — stdlib, function-local
    templates = [
        (request_template(http_request(method="GET", url=url)),
         (insertion_kind.QUERY_VALUE, insertion_kind.URL_PATH_SEG)),
    ]
    if names:
        cookie = "; ".join(f"{n}=redir" for n in names)
        templates.append((
            request_template(http_request(method="GET", url=url, headers=[("Cookie", cookie)])),
            (insertion_kind.COOKIE_VALUE,)))
        form = "&".join(f"{n}=redir" for n in names)
        templates.append((
            request_template(http_request(
                method="POST", url=url,
                headers=[("Content-Type", "application/x-www-form-urlencoded")], body=form)),
            (insertion_kind.BODY_FORM_VALUE,)))
        js = json.dumps({n: "redir" for n in names}, separators=(",", ":"))
        templates.append((
            request_template(http_request(
                method="POST", url=url, headers=[("Content-Type", "application/json")], body=js)),
            (insertion_kind.JSON_VALUE,)))
    return templates


def _oracle_signal(context: "dict"):
    """Run the deterministic oracle over the retained context and return its (fired, conclusive) signal.

    Kept separate from minting so admission can see the oracle's answer BEFORE any certificate exists."""
    from framework.v2.verify.oracles import predicate_oracle  # noqa: PLC0415 (FATAL-2: function-local)

    evidence = context.get("observed_evidence") or {}
    predicate = context.get("predicate") or {}
    return predicate_oracle(evidence, predicate)


def _branch_outcomes(bug_class: str, context: "dict", overall_fired: bool) -> "list[tuple[str, bool]]":
    """Every ATOMIC branch outcome present in this response, as ``(branch_id, fired)``.

    Deliberately NOT "one branch per response". A single response can carry a 302 ``Location``, a body
    meta-refresh AND a JavaScript sink at once; collapsing that to a single branch by precedence would
    discard real evidence and, worse, hide the LIMITATIONS of the branches it dropped — the body branches
    are not CLEAN-capable, so silently reporting only the header branch would let a response look more
    conclusively examined than it was.

    Each outcome is admitted separately, so each is judged against ITS OWN declared capability and appears
    in the audit trail with its own verdict."""
    evidence = context.get("observed_evidence") or {}
    followed = bool(evidence.get("followed_redirect"))
    body = evidence.get("body") or ""
    # A Location host equals the target only when the response ACTUALLY REDIRECTED. Without this, a status
    # 200 that merely reflects the canary into a Location header (or a render-dependent body/JS redirect on
    # a page that also sets Location) was attributed to the `location_header` branch — laundering
    # body/JS-derived, render-dependent evidence into a 3xx-header FACT whose DECLARED evidence surface was
    # never observed. The status gate MUST match the oracle's own Location disjunct (checks.py: a 3xx status
    # AND a matching Location host), so the branch fires exactly when its declared evidence is present.
    is_redirect = int(evidence.get("status", 0) or 0) in (301, 302, 303, 307, 308)
    location_host = evidence.get("location_host")

    if bug_class == "cors":
        return [("cors.reflected_origin_with_credentials", overall_fired)]

    if bug_class == "graphql_introspection":
        # A single, oracle-driven branch: the check's predicate already IS the exploitable proposition (a
        # well-formed schema returned to VIGIL's own introspection query), so the branch simply mirrors the
        # oracle's verdict over that live capture — no per-response decomposition to do (like cors).
        return [("graphql_introspection.schema_returned", overall_fired)]

    if bug_class == "host_header_injection":
        # The host-header Location disjunct is itself status-free (checks.py:HostHeaderCheck), so branch and
        # oracle already agree here — do not add a gate the oracle does not have.
        evil = evidence.get("evil_host")
        emitted = evidence.get("emitted_url_hosts") or []
        return [
            ("host_header.location_header", bool(evil) and location_host == evil),
            ("host_header.body_emission", bool(evil) and evil in emitted and not followed),
        ]

    prefix = "oidc_redirect_uri" if bug_class == "oidc_redirect_uri" else "open_redirect"
    canary = evidence.get("canary_host")
    outcomes = [(f"{prefix}.location_header",
                 bool(canary) and is_redirect and location_host == canary)]
    meta_fired = js_fired = False
    if canary and body:
        from framework.v2.scanner.checks import js_sink_hosts, meta_refresh_hosts  # noqa: PLC0415
        meta_fired = canary in meta_refresh_hosts(body) and not followed
        js_fired = canary in js_sink_hosts(body) and not followed
    outcomes.append((f"{prefix}.body_markup", meta_fired))
    if prefix == "open_redirect":       # the SSO check has no registered JS-sink branch
        outcomes.append(("open_redirect.js_sink", js_fired))
    return outcomes


def web_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                timeout: float = 8.0, claimed_class: str = "") -> WebRedriveResult:
    """Re-drive ``url`` through the shipped web checks via a gated send and mint a signed FACT for every
    ACHIEVED_STATE predicate the oracle confirms over VIGIL's OWN live capture. The predicates are scoped to
    the exploitable, co-located condition (a real navigation target / reflected-origin+creds), and a probe
    that established no channel is INCONCLUSIVE (never CLEAN). Returns a :class:`WebRedriveResult`."""
    from framework.v2.scanner.checks import (  # noqa: PLC0415
        CorsActiveCheck,
        GraphqlIntrospectionCheck,
        HostHeaderCheck,
        OpenRedirectCheck,
    )
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: PLC0415
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — the URL-shaped gate

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, compose as _compose  # noqa: PLC0415

    res = WebRedriveResult(url=url)
    # PRE-FLIGHT the gate ONCE: a refused engagement (kill-switch / out-of-scope / no-slug / bad URL) means
    # VIGIL never observed the target, so there is NO channel — we must NOT run the checks and let their
    # empty captures be mislabelled a "channel-confirmed CLEAN" (the "found nothing ≠ CLEAN" invariant). We
    # return refused with zero adjudications. The per-request gate in `send` remains as defence-in-depth.
    refusal = _authorize(url, slug)
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        return res

    send, state = _gated_web_send(slug, timeout=timeout)
    template = RequestTemplate(HttpRequest(method="GET", url=url))

    def _run(probe_fn, bug_class: str, item: str, *, surface: str = "") -> None:
        """Run one check, but adjudicate ONLY if the probe established a real channel. A probe whose every
        send was gate-refused (kill-switch tripped mid-run) or errored (connection refused / timeout)
        observed NOTHING — it is INCONCLUSIVE, never a 'channel-confirmed CLEAN' (the 'found nothing !=
        CLEAN' invariant). We snapshot the channel counter around the probe to decide.

        ``surface`` names the insertion surface this probe examined (e.g. ``json_value``); it is recorded as
        EXAMINED only when a channel was established, so the coverage statement can bound a CLEAN to the
        surfaces actually reached and never count a no-channel probe as coverage."""
        before, before_bodies = state["channels"], state["body_unavailable"]
        ctx = probe_fn()
        had_channel = state["channels"] > before
        if not had_channel:
            res.inconclusive.append((bug_class, item))   # no observation → do NOT let it become CLEAN
            return
        if surface:
            res.insertion_surfaces.setdefault(bug_class, set()).add(surface)
        body_unreadable = state["body_unavailable"] > before_bodies
        if ctx is None:
            return
        context = ctx.to_verifier_context()
        finding = {"check_id": f"web:{bug_class}:{item}", "bug_class": bug_class,
                   "insertion_point": item, "oracle_context": context}

        # ADMISSION DECIDES, MINTING EXECUTES. Run the deterministic oracle, attribute the outcome to ONE
        # registered evidence branch, and let admit() apply that branch's declared capabilities against what
        # this observation actually supports. Calling confirm_and_certify directly would let a verdict reach
        # a certificate without any capability check ever running.
        signal = _oracle_signal(context)
        observed = {
            "channel_established": True,
            "body_semantically_available": not body_unreadable,
            "not_followed_redirect": not bool(context.get("observed_evidence", {}).get("followed_redirect")),
            "gate_authorized": True,
        }
        # One admission PER ATOMIC BRANCH OUTCOME. A response carrying several kinds of evidence yields
        # several admissions, each judged against its own declared capability, so nothing is hidden by the
        # precedence of a stronger sibling.
        for branch, fired in _branch_outcomes(bug_class, context, signal.fired):
            admitted = admit(branch, fired=fired, conclusive=signal.conclusive, observed=observed)
            res.admissions.append((branch, admitted.verdict.value, admitted.reason))
            # STRONGEST-wins across insertion points, not last-wins. `_run` fires once PER insertion point,
            # all with the same branch names, so a benign point processed AFTER the firing one used to
            # overwrite its verdict — reporting a family as INCONCLUSIVE while it held a live signed FACT
            # (?next=<redirect>&utm_source=x is an everyday URL). A branch is FACT for the family if ANY
            # point produced a FACT; compose() over {prior, new} takes the stronger under the same lattice.
            branch_map = res.branch_verdicts.setdefault(bug_class, {})
            prior = branch_map.get(branch)
            branch_map[branch] = _compose([prior, admitted.verdict.value]).value if prior else admitted.verdict.value
            per_branch = dict(finding, check_id=f"{finding['check_id']}#{branch}")
            r = certify_admitted(per_branch, admitted, engagement_slug=engagement_slug, signers=signers,
                                 provenance="live_redrive")
            res.contexts[r.finding_ref] = context
            if r.is_fact:
                res.facts.append(r)
            elif admitted.verdict is Verdict.INCONCLUSIVE:
                res.inconclusive.append((bug_class, f"{item}#{branch}"))
                res.notes.append(f"{bug_class} [{branch}]: {admitted.reason}")
            else:
                res.leads.append(r)

    try:
        # request-level checks (add an evil Origin / Host to the whole request)
        _run(lambda: CorsActiveCheck().probe(template, send), "cors", url, surface="origin_header")
        _run(lambda: HostHeaderCheck().probe(template, send), "host_header_injection", url,
             surface="host_header")
        # graphql introspection: VIGIL POSTs its OWN minimal introspection query and the oracle fires only on
        # a well-formed returned schema — a definite proposition, so a single oracle-driven branch (like cors).
        _run(lambda: GraphqlIntrospectionCheck().probe(template, send), "graphql_introspection", url,
             surface="graphql_introspection_query")
        # oidc redirect_uri: CLASS-GATED (run ONLY when the CLAIMED class is exactly "oidc_redirect_uri").
        # OidcRedirectUriCheck's predicate is observationally IDENTICAL to open_redirect (a 3xx Location to
        # the canary host, or a meta-refresh to it), so running it unconditionally would UPGRADE a plain
        # open_redirect endpoint that merely carries a redirect_uri param to the higher-severity oidc class
        # (A07 vs A01) — a severity-overclaim, the inverse of the S6 relabel. The OIDC-authorization semantic
        # is carried by the CLAIM, never the 302; the check itself no-ops unless redirect_uri is present.
        if claimed_class == "oidc_redirect_uri":
            from framework.v2.scanner.sso import OidcRedirectUriCheck  # noqa: PLC0415 (FATAL-2: function-local)
            _run(lambda: OidcRedirectUriCheck().probe(template, send), "oidc_redirect_uri", url,
                 surface="redirect_uri_query")
        # per-insertion-point: open-redirect injects the canary into each redirect insertion point, across
        # EVERY surface a redirect parameter is really taken from — the URL query/path, a Cookie, a
        # urlencoded body, and a JSON body. The runner synthesises the cookie/body/JSON carriers (see
        # _redirect_templates) so those insertion points EXIST to be rendered into; each carrier is restricted
        # to the surface it introduces so the URL is not re-probed. Every outcome flows through the SAME
        # admission path, so each surface is attributed and capability-checked like any other.
        orc = OpenRedirectCheck()
        # the candidate redirect-parameter names placed on the synthesised cookie/body/JSON carriers — recorded
        # so the location_header CLEAN's parameter-name bound is machine-readable, not prose-only.
        names = _candidate_redirect_names(url)
        res.probed_redirect_param_names = list(names)
        for tmpl, kinds in _redirect_templates(url, names, HttpRequest, InsertionKind, RequestTemplate):
            for point in tmpl.insertion_points(kinds=kinds):
                _run(lambda t=tmpl, p=point: orc.probe(t, p, send), "open_redirect",
                     f"{url}#{point.id}", surface=point.kind.value)
    except Exception as e:  # noqa: BLE001 — a probe error never fabricates a FACT; record + return what held
        res.notes.append(f"probe error: {type(e).__name__}: {e}")
    return res
