"""
scanner.forgery_acceptance — the ACCEPTANCE achieved-state dual of the OFFLINE structural-forgery FACT.

``verify.jwt_forgery`` / ``verify.saml_forgery`` (producers ``scanner.jwt.JwtForgeryCheck`` /
``scanner.sso.SamlForgeryCheck``) prove a captured token/assertion is *itself* structurally FORGEABLE — a
pure, zero-traffic offline fact. That offline ``jwt_forgeable`` / ``saml_structural_forgery`` FACT is
INDEPENDENT of everything below and is unaffected by it. This module proves the strictly-stronger LIVE fact
that the operator's own SP/RP actually **GRANTED ACCESS** to a forged token: it synthesises a forged JWT / SAML
assertion carrying a fresh, unique attacker identity, replays it live through the gated ``send``, and fires
ONLY on an **ACHIEVED READ OF A VICTIM-PRIVATE DATUM**.

WHY SIX ROUNDS OF CONTENT HEURISTICS FAILED. An achieved authenticated/accepted state CANNOT be proven from
response CONTENT. Every content heuristic tried — a unique per-probe nonce, ref-independence, a substance
floor, a 16-phrase English deny-signature denylist, a same-target *marker differential*, and finally
(round-5) a difflib *same-shape SIMILARITY SCORE* — was defeated by a benign app whose response merely VARIES
by credential presence. The sixth variant defeats the similarity score itself: a benign NON-granting app that
renders an identity-echoing soft-200 in the site shell scores ~0.95 similar to its own deny control yet
differs in one chrome token also present in the grant, minting a DURABLE / OFFLINE false FACT. There is no
score, phrase list, or marker set over response bytes that separates a soft grant from a soft denial.

THE SOUND REDUCTION — an achieved read of a victim-PRIVATE datum (this reuses the Wave-3.1 IDOR/BOLA
differential that PASSED adversarial review, in ``scanner.checks.IdorCheck``: ``is_substantive_success`` +
``valid_discriminator`` + a substantive-2xx SAME-SHAPE negative reference, and NO similarity score). The
credential-under-test (the forged ``alg:none`` token / the NameID-tampered assertion) confirms the achieved
state ONLY when a genuine, operator-supplied victim-PRIVATE discriminator ``D`` satisfies ALL of:

  (a) ``D`` is PRESENT in the credential-under-test's read of the protected resource (the FORGED-token
      response) — the achieved private read;
  (b) ``D`` is PRESENT in a POSITIVE reference (a legitimate-VALID-token / validly-signed-assertion read) —
      proving ``D`` is the real private content the app serves an authorised user, not chrome;
  (c) ``D`` is ABSENT from a SUBSTANTIVE SAME-SHAPE NEGATIVE reference (an invalid-token read that returns a
      substantive 2xx RENDERING THE SAME resource) — the access-gated absence that rules out chrome/boilerplate.
      A denial / empty / error / different-shape negative reference is REFUSED (``is_substantive_success`` fails
      ⇒ fail-closed to a LEAD): its absent marker is VACUOUS (absent because unrendered, not because private);
  (d) ``D`` is a valid discriminator (:func:`valid_discriminator`: non-trivial, not whitespace, not a substring
      of any VIGIL sentinel / the per-probe nonce, NOT reflected from the request, AND NOT present in / derivable
      from the FORGED TOKEN's own decoded claim VALUES — its ``sub`` / ``email`` / ``name`` / SAML attribute /
      NameID values). The attacker controls the forged (``alg:none`` / NameID-tampered, unsigned) token, so any
      token-claim value echoed back is REFLECTION of attacker-supplied data, never an achieved read of server-side
      private content: ``D`` must be SERVER-SIDE private data about the impersonated identity that is ABSENT from
      the forged token.

WHY THIS IS SOUND — AND WHERE THE PRIOR "A BENIGN APP CANNOT MINT" CLAIM WAS TOO STRONG. Clause (a) ALONE is not
enough. A benign app that REJECTS the forge can still ECHO a value it DECODED FROM THE FORGED TOKEN — a JWT
``email``/``name`` claim, a SAML assertion ``mail`` attribute — on its (non-granting) reject page. That echo is
REFLECTION of attacker-controlled token data, NOT a leak of server-side private content; yet it would put the
operator's ``D`` into the forged response (clause a), into a legit reference for the same real identity (clause b),
and leave it absent from a control that does not echo it (clause c) — minting a FALSE ``achieved_state`` on
jwt/oidc/saml (``D=email`` is the canonical example, a natural config, not misuse). Clause (d) therefore REFUSES
any ``D`` present in / derivable from the FORGED TOKEN's own decoded claim values — the request-reflection guard
COMBINED WITH a forged-token-claim guard (the runner parses the JWT payload / SAML assertion it minted and excises
those values, re-derived in the predicate AST so an offline re-verify enforces the same bound). What survives as
``D`` is SERVER-SIDE private data about the impersonated identity that is ABSENT from the forged token, so a benign
non-granting app — however it echoes token claims, however its response varies by credential presence, however
much chrome it renders — cannot supply it. Chrome / identity-echo the operator might mistake for private content
is additionally caught by clause (c): it is rendered on the substantive-2xx same-shape invalid-token control too,
so its absence-in-control fails.

THE DEFEATED HEURISTICS ARE DEMOTED, NOT KEPT AS PROOF. The difflib structural-similarity ratio survives ONLY
as a weak advisory recorded in the evidence (``same_shape_similarity``); it is NOT an admission gate and does
NOT decide a fire. The deny-phrase denylist survives ONLY as a weak advisory (``forged_deny_signature_hits``);
it does NOT enter the predicate. The load-bearing proof is the private-read differential (a)–(d) alone.

THE RESIDUAL AND THE HONEST LEAD-DOWNGRADE. The substantive-2xx negative control is auto-derived (a well-formed
bad-signature token the app processes and denies). A correct app typically denies it with a TERSE 401 / a login
redirect — NOT a substantive same-shape 2xx — so for the auto-derived wired input clause (c) cannot be robustly
established and all three ``*_forgery_accepted`` classes DOWNGRADE to a rigorous LEAD (``fact_capable: false`` +
``blocking_work``). A residual remains even for a supplied substantive-2xx control: a pathological benign app
with TWO distinct same-status substantive-2xx deny views differing in one chrome token also present in the grant
(the same residual Wave-3.1 documents). Closing it — and lifting the class to a runtime FACT — needs an operator
producer of BOTH the victim-PRIVATE ``D`` (+ the legitimate-valid-token POSITIVE reference) AND a CERTIFIED
substantive same-shape deny reference captured from the SAME rendering path. Until then the oracle mints a FACT
only in the genuinely-sound sub-case it can prove (a supplied substantive same-shape control lacking a genuine
private ``D``), and yields an honest LEAD everywhere else. It NEVER mints a false FACT: a benign app (INCLUDING one
that echoes a decoded token claim on its reject page — caught by clause (d)'s forged-token-claim guard), a terse
control, a missing ``D`` or a missing reference all fail closed to a LEAD.

Additional guarantees carried over:
  * **FIX #2 — a fresh RANDOM per-probe nonce as the forged identity.** Every probe mints
    ``crucible-forged-<128-bit-random>`` as the forged ``sub``/``NameID``, retains it in the oracle context, and
    the predicate ASSERTS the RAW forged body reflects it — so a fire proves the FORGED identity specifically
    was processed (it cannot have pre-existed, and is not shared across probes).
  * **FIX #3 — the reflected nonce is EXCISED before the discriminator search.** The forged ``sub``/``NameID``
    (and the sub/role/email VIGIL derived from it) is reflected in the response, so it is excised
    (``_excise`` → ``*_content``) before ``D`` is searched, and markers overlapping the nonce are dropped up
    front (``_sound_markers``). The nonce reflection proves the token was PROCESSED (asserted over the RAW body);
    the achieved private read must be proven by ``D`` OUTSIDE the reflected nonce.
  * **Refusal #7 — no embedded-key path.** The forge is ``alg:none`` (an unsigned token a correct RP rejects).
    The embedded-key confusion (``jwk`` / ``x5c`` / ``jku`` / ``x5u``) is DELIBERATELY not attempted.
  * **LOW — a 3xx auth-failure redirect is NON-acceptance.** A 3xx carries no rendered body, so neither the
    positive reference nor the forged response can be a substantive success on a bare redirect — a redirect to a
    login/error page never fires (a conservative miss, sound).

**Runtime status (honest).** ``forgery_acceptance_checks`` is opt-in and gated on TWO gated-workflow inputs the
operator must supply per flow — the victim-PRIVATE discriminator baseline (``success_markers``) AND a legitimate
VALID token (the POSITIVE reference) — and NOTHING in the default scan/engage roster populates either, so the
achieved-acceptance FACT is **capability-not-operating**: the three ``*_forgery_accepted`` evidence branches are
declared ``fact_capable: false`` until a gated-workflow producer of a genuine private ``D`` + the positive
reference + a CERTIFIED substantive same-shape negative reference is wired — see
``docs/capability-matrix/evidence-branches.json`` (``blocking_work``). The oracle below is sound for the sub-case
it fires (a substantive same-shape control lacking a genuine SERVER-SIDE, token-absent private ``D``), but it is
NOT a blanket guarantee: a terse / different-shape control, a benign app (INCLUDING one that echoes a decoded
token claim — clause (d)), or a missing ``D``/reference mints NOTHING rather than a false FACT.

Doctrine (constitution §II, §VI), inherited from ``scanner.sso``:
  * **Own integration only.** Every request rides the injected, gated ``send`` (charter / scope / kill-switch
    / egress), so an off-scope IdP is refused before a byte leaves the box.
  * **Correlatable.** The forged marker is the greppable ``crucible-forged-*`` prefix.
  * **Opt-in + gated-workflow.** These checks are NOT in ``DEFAULT_REQUEST_CHECKS`` and mint nothing without
    BOTH the ``success_markers`` baseline and the ``legit_token``/``legit_saml`` positive reference, so the
    default benchmark sends zero forgery-acceptance requests and the ``make gate`` stays byte-identical.

The ORACLE — never this code — decides: each check hands the raw observed values plus a declarative predicate to
``FindingContext.from_predicate`` (the ACHIEVED_STATE predicate oracle). Both are JSON, so a confirmed finding
re-verifies offline from its certificate exactly like every other achieved-state class.
"""

from __future__ import annotations

import difflib
import secrets
from dataclasses import dataclass

from ..verify.adapter import FindingContext
from . import jwt as _jwt
from . import sso as _sso
from .checks import Send
from .insertion import HttpRequest, RequestTemplate

# A status a minimally-correct endpoint returns when it REJECTS a token/assertion. Retained as a coarse
# non-rejection gate for audit continuity; the ACTUAL proof of acceptance is the private-read differential
# below. (3xx is handled by the substantive-success bound — a redirect has no rendered body, so it cannot be
# a substantive success.)
_REJECTED = [0, 400, 401, 403, 404, 500, 502, 503]

# The forged identity marker prefix — greppable + per-probe-unique (FIX #2). ``crucible-*`` is the framework's
# correlatable-traffic convention; the random suffix makes the marker unforgeable and impossible to pre-exist.
_MARKER_PREFIX = "crucible-forged-"

# --- SHARED GUARD SEMANTICS (Wave-3 vacuous-predicate fix, aligned with scanner.checks) --------------------
# A contains/not-contains check is only SUBSTANTIVE when the body is a real 2xx success rendering real content
# and the marker is a real discriminator, so a predicate can never be satisfied TRIVIALLY by an empty/errored/
# soft-denied body or an empty/too-short/whitespace/colliding marker.

# The minimum stripped length of a body that can count as a genuine rendered response — as a positive grant
# reference, as the achieved forged read, OR as the substantive same-shape negative control. A shorter body
# (an empty 200, a one-word error) cannot serve any of those roles.
_MIN_SUBSTANTIVE_BODY = 16

# The minimum length (after strip) of an operator private discriminator that can DISCRIMINATE a genuine private
# read from a denied page. A 1–2 char or whitespace marker matches almost any body and proves nothing.
_MIN_DISCRIMINATOR = 3

# Multi-word denial / error PHRASES that mark a 2xx body as a SOFT-deny / soft-error rather than a real rendered
# resource (the SAME list Wave-3.1 uses in scanner.checks). A substantive read of a private resource never
# consists of one of these. This is a SUBSTANTIVENESS gate (fail-closed): over-rejecting only DOWNGRADES a
# would-be FACT to a LEAD — it can NEVER mint a false FACT. It is NOT the acceptance proof and NOT a fail-open
# "no-deny-phrase ⇒ granted" heuristic (that is the defeated content heuristic); it only refuses a soft-deny
# body from masquerading as a substantive rendered response. Single ambiguous words ("error", "forbidden",
# "unauthorized") are deliberately EXCLUDED so legitimate content that merely mentions them stays substantive.
_BARE_ERROR_SIGNATURES: tuple[str, ...] = (
    "access denied", "access is denied", "permission denied", "not authorized",
    "you are not authorized", "you do not have permission", "insufficient privileges",
    "insufficient permission", "authentication required", "authentication failed",
    "must be logged in", "please log in", "please login", "login required",
    "not logged in", "internal server error", "service unavailable",
)

# Length cap on each body before the O(n*m) difflib match, so the (advisory) same-shape scoring stays bounded.
_SHAPE_CAP = 40000

# WEAK ADVISORY ONLY. Bare error/deny signatures once formed the *gate* separating a soft-200 grant from a
# soft-200 denial — an unsound content heuristic a benign non-denylisted soft-200 defeated. They are retained
# here solely to record ``forged_deny_signature_hits`` in the evidence for a human reviewer; they do NOT enter
# the predicate AST and do NOT decide a fire. (Distinct from ``_BARE_ERROR_SIGNATURES`` above, which is a
# fail-closed substantiveness gate — it can only DOWNGRADE a FACT, never mint one.)
_DENY_SIGNATURES = (
    "access denied", "login failed", "authentication failed", "authorization failed",
    "not authorized", "unauthorized", "forbidden", "invalid credentials",
    "invalid token", "invalid assertion", "please log in", "please sign in",
    "session expired", "permission denied", "authentication required", "login required",
)


def _new_marker() -> str:
    """A FRESH RANDOM per-probe forged-identity nonce (FIX #2). 128 bits of entropy → cannot pre-exist in the
    app and is never shared across probes, so a fire over it proves THIS forged identity was honoured."""
    return _MARKER_PREFIX + secrets.token_hex(16)


def _is_bare_error(body: str) -> bool:
    """True iff a stripped body carries a soft-deny / soft-error PHRASE (:data:`_BARE_ERROR_SIGNATURES`) — a
    2xx body that is really a denial, not a rendered resource. Fail-closed substantiveness input only."""
    low = str(body or "").lower()
    return any(sig in low for sig in _BARE_ERROR_SIGNATURES)


def is_substantive_success(status: object, body: object) -> bool:
    """SHARED GUARD (aligned with Wave-3.1 ``scanner.checks.is_substantive_success``). A response counts as a
    genuine rendered resource — and so may serve as the POSITIVE grant reference, the achieved FORGED read, OR
    the SUBSTANTIVE SAME-SHAPE negative control — ONLY when it is a real success with real content:
    ``status ∈ [200, 300)`` AND ``len(body.strip()) >= _MIN_SUBSTANTIVE_BODY`` AND the body is NOT a bare
    soft-deny / soft-error phrase. The deny-phrase gate here is fail-CLOSED (a soft-deny is treated as
    non-substantive, downgrading a would-be FACT to a LEAD) — it is NOT the acceptance proof and can never mint
    a false FACT; it is the OPPOSITE direction of the defeated "no-deny-phrase ⇒ granted" heuristic. Every clause
    here is re-derived over RAW observed values in the predicate AST too, so an offline re-verify enforces the
    SAME gate. There is NO similarity score: same-shape-ness is established by BOTH reads being substantive-2xx
    renderings of the SAME replayed resource, exactly as Wave-3.1's substantive-2xx peer control is."""
    if not (200 <= _int(status) < 300):
        return False
    stripped = str(body or "").strip()
    if len(stripped) < _MIN_SUBSTANTIVE_BODY:
        return False
    return not _is_bare_error(stripped)


def _substantive_success_clauses(status_var: str, body_var: str) -> "list[dict]":
    """DSL clauses (AND-composed) that RE-DERIVE :func:`is_substantive_success` over the RETAINED raw evidence,
    so offline predicate re-verification enforces the SAME floor the live probe did — a durable
    ``oracle_context`` built from a non-substantive body (an empty 200, a terse deny, a soft-deny phrase) can
    never re-fire. The predicate DSL's ``min_len`` measures the stored body (stored STRIPPED), so the length
    floor matches the Python helper; each soft-deny phrase is an ``icontains`` refusal (same as Wave-3.1)."""
    clauses: list[dict] = [
        {"ge": [{"var": status_var}, 200]},
        {"not": {"ge": [{"var": status_var}, 300]}},
        {"min_len": [{"var": body_var}, _MIN_SUBSTANTIVE_BODY]},
    ]
    clauses += [{"not": {"icontains": [{"var": body_var}, sig]}} for sig in _BARE_ERROR_SIGNATURES]
    return clauses


def valid_discriminator(marker: object, nonce: str = "", reflectable: str = "", token_claims: str = "") -> bool:
    """SHARED GUARD (clause (d)). An operator discriminator is a usable candidate victim-PRIVATE datum ``D``
    ONLY when it is a non-trivial, non-vacuous, non-reflected token: not ``None``, ``len(marker.strip()) >=
    _MIN_DISCRIMINATOR``, not pure whitespace, not carrying the excision sentinel, NOT overlapping the per-probe
    ``nonce`` (neither a substring of it nor containing it — else it is satisfiable by PURE REFLECTION of the
    attacker nonce), NOT reflected from the request (not a substring of ``reflectable`` — the request's own
    echoable content: URL, header values, body — so a value the app merely echoes back from the request can
    never masquerade as an achieved read of private content; the Wave-3.1 ref-independence analog), AND NOT
    present in / derivable from the FORGED TOKEN's own decoded claim values (not a substring of ``token_claims``
    — the concatenated VALUES of the forged JWT payload / SAML assertion the runner minted). The attacker
    controls the forged (``alg:none`` / NameID-tampered, unsigned) token, so a value the app decoded FROM the
    forged token and echoed back (e.g. an ``email``/``name`` claim, a SAML ``mail`` attribute) is REFLECTION of
    attacker-supplied data, NOT an achieved read of server-side private content — this is the round-6 BLOCK fix
    (a benign app that rejects the forge but echoes a decoded token claim on its reject page). Any of these is
    dropped before it can be admitted to ``D``. (Admission to ``D`` additionally requires present-in-legit AND
    present-in-forged AND absent-in-control — see :func:`_acceptance_context`.)"""
    if marker is None:
        return False
    m = str(marker)
    if len(m.strip()) < _MIN_DISCRIMINATOR:
        return False
    if _EXCISION_SENTINEL in m:
        return False
    if nonce and (m in nonce or nonce in m):
        return False
    if reflectable and m in reflectable:
        return False
    if token_claims and m in token_claims:
        return False
    return True


def _shape_similarity(forged_content: str, control_content: str) -> float:
    """A bounded difflib structural-similarity ratio in [0, 1] between the forged response and the negative
    control (both nonce-excised, stripped). WEAK ADVISORY ONLY (round-6): it is recorded in the evidence for a
    human reviewer, it is NOT an admission gate, and it does NOT decide a fire. The sixth variant proved this
    score is a defeatable content heuristic (a benign non-granting app scores ~0.95 yet is not a grant), so it
    was demoted from the round-5 admission gate to an advisory. Inputs are length-capped (:data:`_SHAPE_CAP`)."""
    a = str(forged_content or "")[:_SHAPE_CAP]
    b = str(control_content or "")[:_SHAPE_CAP]
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _int(v: object) -> int:
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _status(resp: object) -> int:
    return int(resp.get("status", 0)) if isinstance(resp, dict) else 0


def _body(resp: object) -> str:
    return str(resp.get("body", "")) if isinstance(resp, dict) else str(resp)


def _deny_signature_hits(body: str) -> "list[str]":
    """WEAK ADVISORY. The deny/error signatures present in ``body`` (case-insensitive), recorded in the
    evidence for a human reviewer. NOT a gate: the fire decision is the private-read differential, never these
    phrases."""
    low = str(body or "").lower()
    return [sig for sig in _DENY_SIGNATURES if sig in low]


# A redaction sentinel substituted for each excised reflected forged value (FIX #3). It is a control character
# that (a) cannot legitimately appear in an operator discriminator — validated in ``valid_discriminator`` — and
# (b), unlike deleting the nonce, cannot bridge the text on either side of the excised nonce into a spurious
# match (``"AAA<nonce>BBB"`` becomes ``"AAA\x00BBB"``, never ``"AAABBB"``).
_EXCISION_SENTINEL = "\x00"


def _request_reflectable(req: "HttpRequest") -> str:
    """The request's own echoable content — the URL, every header value, and the body — concatenated. A
    candidate discriminator that is a substring of THIS is 'reflected from the request' (clause (d)): the app
    could be echoing the operator's own request bytes back, so it cannot serve as proof of an achieved read of
    PRIVATE content. Used to drop such candidates in :func:`_sound_markers` (the Wave-3.1 ref-independence
    analog). Total / defensive — a missing field contributes nothing."""
    parts: list[str] = [str(getattr(req, "url", "") or "")]
    try:
        for _k, v in list(getattr(req, "headers", []) or []):
            parts.append(str(v))
    except Exception:
        pass
    parts.append(str(getattr(req, "body", "") or ""))
    return "\n".join(p for p in parts if p)


def _claim_values(*objs: object) -> "list[str]":
    """Clause (d) — every scalar VALUE reachable in the given decoded token-claims structures (a forged JWT
    header/payload dict, a list of SAML attribute values), flattened to non-empty stripped strings. KEYS are NOT
    collected — only VALUES, since the attacker controls the values a broken app might echo back from the forged
    token. ``None`` and ``bool`` are skipped; dicts, lists, tuples and sets are walked recursively. The result
    seeds the forged-token-claim reflection guard: any candidate ``D`` present in one of these values is dropped
    (it would be a REFLECTION of attacker-supplied token content, never an achieved server-side private read)."""
    out: list[str] = []

    def walk(v: object) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple, set)):
            for x in v:
                walk(x)
        elif v is None or isinstance(v, bool):
            return
        else:
            s = str(v).strip()
            if s:
                out.append(s)

    for o in objs:
        walk(o)
    return out


def _forged_jwt_claims(forged: str, header: object, forged_payload: object) -> "list[str]":
    """Clause (d) — the decoded claim VALUES of the FORGED JWT the runner minted. Decode the actual forged token
    (so the values are exactly what was sent), falling back to the header/payload dicts if the re-decode ever
    fails. These attacker-controlled values seed the forged-token-claim reflection guard (a ``D`` echoed from any
    of them is REFLECTION, not an achieved server-side private read)."""
    try:
        fh, fp, _ = _jwt.decode(forged)
        return _claim_values(fh, fp)
    except Exception:
        return _claim_values(header, forged_payload)


def _saml_claim_values(xml_text: str) -> "list[str]":
    """Clause (d) — every attacker-controllable text / attribute VALUE in a (forged, un-re-signed) SAML
    assertion: the tampered ``NameID``, every ``AttributeValue``, and every other element text / tail / XML
    attribute the attacker set. A NameID-tampered assertion is NOT re-signed, so ALL of its content is
    attacker-controlled — any of it echoed back by the SP is REFLECTION, not an achieved read of server-side
    private content. Total / defensive: a parse failure yields no claims (the guard then simply adds nothing
    rather than raising). Over-collection is SAFE — it can only DOWNGRADE a would-be FACT to a LEAD, never mint
    one."""
    try:
        root = _sso.safe_parse_xml(xml_text)
    except Exception:
        return []
    out: list[str] = []
    for el in root.iter():
        for s in (el.text, el.tail):
            if s and str(s).strip():
                out.append(str(s).strip())
        for v in el.attrib.values():
            if v and str(v).strip():
                out.append(str(v).strip())
    return out


def _reflected_forged_values(marker: str, forged_values: "tuple[str, ...]") -> "list[str]":
    """The exact strings VIGIL injected that the target may REFLECT: the per-probe nonce and every
    sub/role/email value built from it. Every one embeds the 128-bit random nonce, so excising them from a
    response body can only remove OUR reflection — never genuine operator content — and returning them
    longest-first strips a superset (e.g. the OIDC ``<nonce>@sso-test.invalid`` email) before the bare nonce
    nested inside it, so no fragment of a reflected value survives."""
    vals = {marker, *(str(v) for v in forged_values if str(v))}
    return sorted((v for v in vals if v), key=len, reverse=True)


def _excise(body: str, reflected: "list[str]") -> str:
    """FIX #3 — return ``body`` with every reflected forged value replaced by :data:`_EXCISION_SENTINEL`.
    A discriminator search over the result can NEVER be satisfied by the reflected attacker nonce (pure
    reflection): the nonce reflection proves only that the token was PROCESSED, while the achieved private read
    must be proven by ``D`` OUTSIDE the reflected nonce."""
    out = body
    for v in reflected:
        out = out.replace(v, _EXCISION_SENTINEL)
    return out


def _sound_markers(
    success_markers: "tuple[str, ...]", marker: str, reflectable: str = "", token_claims: str = ""
) -> "list[str]":
    """FIX #3 + clause (d) — the operator discriminators that are SOUND candidate victim-PRIVATE data ``D``,
    i.e. every marker that is a :func:`valid_discriminator` against the per-probe forged ``marker`` (the nonce)
    AND is not reflected from the request (``reflectable``) AND is not present in / derivable from the FORGED
    TOKEN's own decoded claim values (``token_claims`` — the round-6 fix). This drops, up front and before
    anything enters ``D`` or the predicate AST, the vacuous (empty / pure-whitespace / ``< _MIN_DISCRIMINATOR``
    chars), the nonce-overlapping (a substring of, or containing, the ``crucible-forged-<hex>`` nonce), the
    request-reflected, the forged-token-claim-reflected (an echoed ``email``/``name``/attribute value), and
    anything carrying the excision sentinel. (Admission to ``D`` further requires present-in-legit AND
    present-in-forged AND absent-in-control.) If every supplied marker is dropped, the caller mints nothing (a
    rigorous LEAD)."""
    return [str(m) for m in success_markers
            if valid_discriminator(m, nonce=marker, reflectable=reflectable, token_claims=token_claims)]


def _acceptance_context(
    legit_resp: object,
    forged_resp: object,
    control_resp: object,
    marker: str,
    success_markers: "tuple[str, ...]",
    bug_class: str,
    *,
    forged_values: "tuple[str, ...]" = (),
    reflectable: str = "",
    token_claims: "tuple[str, ...]" = (),
) -> "FindingContext | None":
    """Build the ACHIEVED_STATE predicate context proving a forged token achieved a READ OF A VICTIM-PRIVATE
    DATUM, by the private-read differential (a)–(d). This reuses the Wave-3.1 IDOR/BOLA machinery
    (``scanner.checks.IdorCheck``): ``is_substantive_success`` on all three reads, ``valid_discriminator``, a
    substantive-2xx SAME-SHAPE negative reference, and NO similarity score.

    The three live responses are the same-target references:

      * ``legit_resp``   — the operator's legitimate VALID token replayed live: the POSITIVE reference (clause b).
      * ``forged_resp``  — the forged ``alg:none`` / NameID-tampered token (attacker per-probe nonce identity):
        the credential-under-test's achieved read (clause a).
      * ``control_resp`` — a well-formed but bad-signature token the app processes and DENIES: the SUBSTANTIVE
        SAME-SHAPE NEGATIVE reference (clause c). It must be a substantive 2xx RENDERING THE SAME resource; a
        denial / empty / error / different-shape control is REFUSED (fail-closed to a LEAD), because its absent
        marker would be VACUOUS (absent because unrendered, not because private).

    ``D`` (the victim-private discriminators) is DERIVED here (in Python, mirrored in the AST): every operator
    ``success_marker`` that is a :func:`valid_discriminator` (nonce-disjoint, non-vacuous, NOT reflected from the
    request, AND NOT present in / derivable from the FORGED TOKEN's own decoded claim values — ``token_claims``,
    the round-6 fix) AND present in the NONCE-EXCISED positive-reference body AND present in the NONCE-EXCISED
    forged body AND absent from the NONCE-EXCISED substantive negative-control body. If no ``D`` survives — or the
    positive reference, the forged response, OR the negative control is not a substantive success — the caller
    mints NOTHING (returns ``None`` — a rigorous LEAD, never a false CLEAN).

    The predicate (evaluated by ``verify.oracles.predicate_oracle``, NOT by this code) fires iff ALL hold,
    re-derived over RAW observed values so an offline re-verify enforces the identical gate:

      1. the FORGED response is a substantive success — ``forged_status ∈ [200, 300)``, the nonce-excised forged
         body has ``≥ _MIN_SUBSTANTIVE_BODY`` chars, and it is not a soft-deny phrase (never a 3xx/4xx/5xx);
      2. the POSITIVE reference is a substantive success too — a real authenticated-grant baseline;
      3. the NEGATIVE control is a substantive success too (clause c) — a 2xx that RENDERED the same resource,
         not a terse deny / redirect / empty / soft-deny phrase; a non-substantive control ⇒ the context is not
         built (a LEAD), so the absent-in-control clause is never vacuous;
      4. FIX #2 — the forged identity's UNIQUE per-probe nonce is reflected in the RAW forged body (the token was
         PROCESSED; the read is bound to the forged identity, which cannot have pre-existed);
      5. every ``D`` is PRESENT in the nonce-excised POSITIVE-reference body (clause b — ``D`` is real private
         content the app serves an authorised user);
      6. every ``D`` is PRESENT in the nonce-excised FORGED body (clause a — the achieved private read: the
         forged identity reached the victim's private content); AND
      7. every ``D`` is ABSENT from the nonce-excised substantive NEGATIVE-control body (clause c — the
         access-gated absence that proves ``D`` is private, not chrome/boilerplate rendered to any credential); AND
      8. every ``D`` is ABSENT from ``forged_token_claims`` (clause d, round-6) — the concatenated decoded claim
         VALUES of the FORGED token the runner minted (the JWT payload / SAML assertion). A ``D`` the app merely
         DECODED FROM the attacker-controlled forged token and echoed back is REFLECTION, not an achieved read of
         server-side private content; re-derived here so an offline re-verify rejects a token-claim-echo certificate.

    NO SIMILARITY SCORE. Round-5 gated clause 7 on a difflib ``_shape_similarity(forged, control) >= 0.5``
    admission score; the sixth variant defeated it (a benign non-granting app scores ~0.95 yet is not a grant).
    The score is DEMOTED to a weak advisory (``same_shape_similarity``, recorded only). Same-shape-ness is
    established SOUNDLY by clause 3 — the negative control being a substantive-2xx rendering of the SAME replayed
    resource — exactly as Wave-3.1's substantive-2xx peer control establishes it, with the SAME documented
    residual (a pathological benign app with two distinct same-status substantive-2xx deny views differing in one
    chrome token also present in the grant). That residual, plus the fact that an auto-derived bad-signature
    control is typically a terse reject (not a substantive same-shape 2xx), is why the WIRED class is declared
    ``fact_capable: false`` and yields a LEAD until a genuine private ``D`` + a CERTIFIED substantive same-shape
    negative reference are supplied — see ``docs/capability-matrix/evidence-branches.json`` (``blocking_work``).

    The surviving ``D``, the substantive-length thresholds, the exact excised reflected values and the FORGED
    token's decoded claim values (``forged_token_claims``) ride literally in the predicate AST + the observed
    evidence (alongside the raw and excised bodies, the advisory same-shape similarity score, and the advisory
    ``forged_deny_signature_hits``), so the finding re-verifies offline byte-for-byte AND the same differential
    (including clause (d)'s forged-token-claim guard) re-fires under offline predicate re-verification."""
    # clause (d), round-6: the concatenated decoded claim VALUES of the FORGED token (JWT payload / SAML
    # assertion the runner minted). Any candidate D present in these is attacker-supplied token content the app
    # could merely echo back — a REFLECTION, not an achieved server-side private read — so it is dropped up front
    # (and re-derived in the predicate AST for offline durability). Newline-joined to prevent cross-value bridging.
    token_claims_blob = "\n".join(str(c) for c in token_claims if str(c).strip())
    candidates = _sound_markers(success_markers, marker, reflectable, token_claims_blob)
    if not candidates:
        return None
    reflected = _reflected_forged_values(marker, forged_values)
    legit_body = _body(legit_resp)
    forged_body = _body(forged_resp)
    control_body = _body(control_resp)
    legit_content = _excise(legit_body, reflected).strip()       # nonce EXCISED + trimmed — the searched bodies
    forged_content = _excise(forged_body, reflected).strip()
    control_content = _excise(control_body, reflected).strip()
    # Python-side fail-closed (all re-derived in the AST below so an offline re-verify enforces each one):
    #   * the POSITIVE reference must be a substantive grant — else there is no baseline for D to be present in;
    #   * the FORGED response must be a substantive success — an error/empty/redirect/soft-deny is no read;
    #   * (clause c) the NEGATIVE control must be a SUBSTANTIVE SAME-SHAPE read — a 2xx rendering the same
    #     resource. A denial / empty / error / different-shape control is REFUSED (fail-closed to a LEAD): its
    #     absent marker would be VACUOUS (absent because unrendered, not because access-gated). This is the
    #     Wave-3.1 substantive-2xx peer-control rule — NOT a similarity score.
    if not is_substantive_success(_status(legit_resp), legit_content):
        return None
    if not is_substantive_success(_status(forged_resp), forged_content):
        return None
    if not is_substantive_success(_status(control_resp), control_content):
        return None
    # Derive D: a victim-private discriminator that survived clause (d) (candidates already exclude the
    # request-reflected AND the forged-token-claim-reflected) AND is PRESENT in the positive reference AND PRESENT
    # in the forged read AND ABSENT from the substantive same-shape negative control. The absent-in-control clause
    # is the access-gated proof (chrome/boilerplate rendered on the same-shape control is disqualified here); the
    # present-in-forged clause is the achieved private read. A benign app can only put attacker-controlled token
    # content (excluded by clause d) or shared chrome (excluded by clause c) into the forged read, so it derives
    # no server-side-private D and mints nothing.
    grant_discriminators = [
        m for m in candidates
        if m in legit_content and m in forged_content and m not in control_content
    ]
    if not grant_discriminators:
        return None   # no ACHIEVED read of an access-gated private datum ⇒ rigorous LEAD, never a FACT/CLEAN
    observed = {
        "forged_status": _status(forged_resp),
        "forged_body": forged_body,                 # RAW — proves the token was PROCESSED (nonce reflected)
        "forged_content": forged_content,           # nonce EXCISED + stripped — substantive-success + D judged over THIS
        "legit_status": _status(legit_resp),
        "legit_body": legit_body,                    # RAW — the positive-reference audit
        "legit_content": legit_content,              # nonce EXCISED + stripped — the positive private-read reference
        "control_status": _status(control_resp),
        "control_body": control_body,                # RAW — retained for audit
        "control_content": control_content,          # nonce EXCISED + stripped — the substantive same-shape negative reference (D must be absent)
        "forged_marker": marker,
        "reflected_forged_values": reflected,        # audit: exactly what was excised before the discriminator search
        "forged_token_claims": token_claims_blob,    # clause (d): decoded claim VALUES of the FORGED token — every D must be ABSENT from these
        "grant_discriminators": grant_discriminators,  # D: valid, non-reflected, non-token-claim, present-in-legit, present-in-forged, absent-in-control
        "forged_deny_signature_hits": _deny_signature_hits(forged_content),  # WEAK ADVISORY only — not a gate
        "min_substantive_len": _MIN_SUBSTANTIVE_BODY,
        # WEAK ADVISORY (round-6, demoted from the round-5 admission gate): the difflib structural similarity of
        # the forged response and the negative control. Recorded for a human reviewer ONLY; it does NOT gate the
        # fire (the sixth variant proved this score is a defeatable content heuristic).
        "same_shape_similarity": round(_shape_similarity(forged_content, control_content), 4),
        "rejected": _REJECTED,
    }
    predicate = {"all": [
        # (0) coarse non-rejection gate (subsumed by the 2xx bound below; retained for audit continuity)
        {"not": {"in": [{"var": "forged_status"}, {"var": "rejected"}]}},
        # (1) the FORGED response is a substantive success (a real 2xx render; never a 3xx/4xx/5xx/soft-deny)
        *_substantive_success_clauses("forged_status", "forged_content"),
        # (2) the POSITIVE reference is a substantive success too — a real authenticated-grant baseline
        *_substantive_success_clauses("legit_status", "legit_content"),
        # (3) clause (c): the NEGATIVE control is a SUBSTANTIVE SAME-SHAPE read (a 2xx rendering the same
        # resource) — re-derived offline so a terse / soft-deny / different-shape control is rejected DURABLY,
        # never leaving a vacuous absent-in-control clause.
        *_substantive_success_clauses("control_status", "control_content"),
        # (4) FIX #2 — the token was PROCESSED: the unique per-probe nonce is reflected in the RAW forged body
        {"contains": [{"var": "forged_body"}, {"var": "forged_marker"}]},
        # (5) clause (b): every D is PRESENT in the POSITIVE reference (D is real private content)
        *[{"contains": [{"var": "legit_content"}, g]} for g in grant_discriminators],
        # (6) clause (a): every D is PRESENT in the FORGED response (the achieved private read)
        *[{"contains": [{"var": "forged_content"}, g]} for g in grant_discriminators],
        # (7) clause (c): every D is ABSENT from the substantive NEGATIVE control (D is access-gated private
        # content, not chrome — the load-bearing differential)
        *[{"not": {"contains": [{"var": "control_content"}, g]}} for g in grant_discriminators],
        # (8) clause (d), round-6: every D is ABSENT from the FORGED token's own decoded claim values (a value the
        # app decoded from the attacker-controlled forged token and echoed back is REFLECTION, not an achieved
        # server-side private read). Re-derived offline so a token-claim-echo certificate is rejected on re-verify.
        *[{"not": {"contains": [{"var": "forged_token_claims"}, g]}} for g in grant_discriminators],
    ]}
    return FindingContext.from_predicate(observed, predicate, bug_class=bug_class)


def _corrupt_jwt_signature(token: str) -> str:
    """A well-formed but BAD-SIGNATURE negative control from a legit token: keep the header+payload segments
    verbatim (so the app decodes and processes it through the SAME auth path) and replace ONLY the signature
    segment with a distinct constant, so a correct verifier rejects it. Unlike a malformed ``aaa.bbb.ccc``
    parse-error, this reaches the app's genuine DENY view — the substantive same-shape reference the access-gated
    absence (clause c) is measured against. An app that accepts it (accept-everything) grants the ORIGINAL
    identity, so ``D`` appears in the control and is disqualified.

    Round-6 caveat (why the wired class is a LEAD): this auto-derived control is NOT guaranteed to be a
    SUBSTANTIVE SAME-SHAPE deny — a correct app usually rejects a bad signature with a terse 401 / a login
    redirect, which :func:`is_substantive_success` REFUSES (clause c fails ⇒ a LEAD, mint nothing). The FACT
    sub-case needs the app's own substantive same-shape deny view of the SAME resource, the ``blocking_work`` in
    the capability matrix."""
    parts = token.split(".")
    if len(parts) == 3:
        parts[2] = "Y3J1Y2libGUtaW52YWxpZC1zaWc"  # b64url("crucible-invalid-sig"), never a valid HMAC/RSA sig
        return ".".join(parts)
    return token + ".Y3J1Y2libGUtaW52YWxpZC1zaWc"


def _invalidate_saml_signature(xml_text: str) -> str:
    """A well-formed, assertion-BEARING but BAD-SIGNATURE negative control from a legit SAMLResponse: append a
    distinct sentinel to every ``ds:SignatureValue`` so the signature no longer verifies, while KEEPING the
    assertion and its original NameID intact. A correct SP rejects it (signature mismatch) through the same
    deny path a tampered assertion takes — the substantive same-shape reference the access-gated absence
    (clause c) is measured against."""
    root = _sso.safe_parse_xml(xml_text)
    changed = False
    for sv in root.iter(f"{{{_sso._NS_DS}}}SignatureValue"):
        sv.text = f"{sv.text or ''}-crucible-invalidated"
        changed = True
    if not changed:
        raise ValueError("no ds:SignatureValue present to invalidate")
    return _sso._serialize(root)


@dataclass(frozen=True)
class JwtForgeryAcceptanceCheck:
    """Confirm the operator's app GRANTED ACCESS to a forged JWT by an ACHIEVED READ OF A VICTIM-PRIVATE DATUM.
    Forge an ``alg:none`` copy of the request's captured JWT carrying a fresh random attacker ``sub`` (the
    per-probe nonce), replay it, replay the operator's ``legit_token`` (the POSITIVE reference) and a well-formed
    bad-signature control (the SUBSTANTIVE SAME-SHAPE NEGATIVE reference). Fires ONLY when a victim-PRIVATE
    discriminator ``D`` is PRESENT in the forged read (the achieved private read) AND PRESENT in the legit
    positive reference AND ABSENT from a substantive-2xx same-shape invalid-token control — proven over the RAW
    evidence by the ACHIEVED_STATE predicate oracle, with NO similarity score.

    ``success_markers`` are the operator-supplied CANDIDATE victim-PRIVATE data (an account number, a private note,
    a balance the authenticated resource renders SERVER-SIDE) — NOT chrome / success banners AND NOT a value the
    forged token itself carries: only a genuinely private, TOKEN-ABSENT datum survives the differential. Chrome is
    rendered on the substantive same-shape control too and is disqualified (clause c); and a value the app DECODED
    FROM the forged token and echoed back — an ``email``/``name``/``sub`` claim — is REFLECTION of attacker content,
    disqualified by clause (d)'s forged-token-claim guard (round-6: a benign app that rejects the forge but echoes a
    decoded claim on its reject page must NOT mint). Without BOTH ``success_markers`` and ``legit_token`` it mints
    nothing (a rigorous LEAD; the offline ``jwt_forgeable`` FACT still stands). Round-6 downgrade: a bad-signature
    control is typically a terse reject, NOT a substantive same-shape deny, so the wired class is a LEAD
    (``fact_capable: false``); the FACT fires only when the control is a substantive same-shape read of the same
    resource lacking a genuine token-absent private ``D``. Refusal #7: ``alg:none`` only — the embedded-key
    (``jwk``/``x5c``/``jku``/``x5u``) forge is never attempted."""

    id: str = "jwt-forgery-accepted"
    bug_class: str = "jwt_forgery_accepted"
    location: str = "authorization"
    # The operator-supplied victim-PRIVATE discriminator baseline (a gated-workflow input): CANDIDATE private
    # data, each validated (non-trivial, nonce-disjoint, non-reflected) and then admitted to D only if
    # present-in-legit AND present-in-forged AND absent-in-control. Empty ⇒ LEAD.
    success_markers: tuple[str, ...] = ()
    # The operator-supplied legitimate VALID token (a gated-workflow input): the POSITIVE reference, replayed
    # live to capture the authenticated private-read state D must be present in. Empty ⇒ LEAD (no positive
    # reference ⇒ never a FACT).
    legit_token: str = ""

    def probe(self, template: RequestTemplate, send: Send) -> "FindingContext | None":
        if not self.success_markers or not self.legit_token:
            return None   # no private-datum baseline OR no positive reference ⇒ rigorous LEAD, never a FACT/CLEAN
        req = template.request
        token = _jwt.extract_token(req, self.location)
        if token is None:
            return None
        try:
            header, payload, _ = _jwt.decode(token)
        except Exception:
            return None
        marker = _new_marker()
        forged_payload = {**payload, "sub": marker}
        forged = _jwt.encode_none(header, forged_payload)   # refusal #7: alg:none only
        legit_resp = send(_jwt.with_token(req, self.location, self.legit_token))
        forged_resp = send(_jwt.with_token(req, self.location, forged))
        control_resp = send(_jwt.with_token(req, self.location, _corrupt_jwt_signature(self.legit_token)))
        return _acceptance_context(legit_resp, forged_resp, control_resp, marker,
                                   self.success_markers, self.bug_class,
                                   reflectable=_request_reflectable(req),
                                   token_claims=tuple(_forged_jwt_claims(forged, header, forged_payload)))


@dataclass(frozen=True)
class OidcForgeryAcceptanceCheck:
    """Confirm the operator's OIDC Relying Party GRANTED ACCESS to a forged ``id_token`` by an ACHIEVED READ OF
    A VICTIM-PRIVATE DATUM. Forge an ``alg:none`` copy of the request's captured ``id_token`` carrying a fresh
    random attacker ``sub``/``email`` (the per-probe nonce), replay it, replay the operator's ``legit_token``
    (POSITIVE reference) and a well-formed bad-signature control (the SUBSTANTIVE SAME-SHAPE NEGATIVE reference).
    Fires ONLY when a victim-PRIVATE ``D`` is present in the forged read AND the legit positive reference AND
    absent from a substantive-2xx same-shape invalid-token control — NO similarity score. ``success_markers`` are
    candidate SERVER-SIDE victim-PRIVATE data, NOT chrome and NOT a claim the forged id_token carries: an
    ``email``/``name`` value the RP decoded from the forged token and echoed back is REFLECTION, disqualified by
    clause (d)'s forged-token-claim guard (round-6). Without BOTH ``success_markers`` and ``legit_token`` it mints
    nothing. Round-6 downgrade: a bad-signature id_token control is typically a terse reject, not a substantive
    same-shape deny, so the wired class is a LEAD (``fact_capable: false``). Refusal #7: ``alg:none`` only. The
    sibling of :class:`JwtForgeryAcceptanceCheck` for the RP callback surface (an ``id_token`` field or header,
    via ``scanner.sso._extract_jwt``)."""

    id: str = "oidc-forgery-accepted"
    bug_class: str = "oidc_forgery_accepted"
    location: str = "id_token"   # a urlencoded field name, or "header:<Name>"
    success_markers: tuple[str, ...] = ()
    legit_token: str = ""

    def probe(self, template: RequestTemplate, send: Send) -> "FindingContext | None":
        if not self.success_markers or not self.legit_token:
            return None
        req = template.request
        token = _sso._extract_jwt(req, self.location)
        if token is None:
            return None
        try:
            header, payload, _ = _jwt.decode(token)
        except Exception:
            return None
        marker = _new_marker()
        email = f"{marker}@sso-test.invalid"
        forged_payload = {**payload, "sub": marker, "email": email}
        forged = _jwt.encode_none(header, forged_payload)
        legit_resp = send(_sso._place_jwt(req, self.location, self.legit_token))
        forged_resp = send(_sso._place_jwt(req, self.location, forged))
        control_resp = send(_sso._place_jwt(req, self.location, _corrupt_jwt_signature(self.legit_token)))
        # FIX #3: the email (a derived value that also embeds the nonce) is a reflected forged value too, so
        # it is excised from the searched bodies before the discriminator search — a marker satisfied only by
        # the reflected email suffix (e.g. "sso-test.invalid") cannot mint a FACT either.
        # Clause (d): the forged id_token's OTHER surviving claims (a captured ``name``/``given_name`` the forge
        # keeps, ``email`` is overridden with the nonce email) seed the forged-token-claim reflection guard.
        return _acceptance_context(legit_resp, forged_resp, control_resp, marker,
                                   self.success_markers, self.bug_class, forged_values=(email,),
                                   reflectable=_request_reflectable(req),
                                   token_claims=tuple(_forged_jwt_claims(forged, header, forged_payload)))


@dataclass(frozen=True)
class SamlForgeryAcceptanceCheck:
    """Confirm the operator's SAML Service Provider GRANTED ACCESS to a forged assertion by an ACHIEVED READ OF
    A VICTIM-PRIVATE DATUM. Rewrite the captured ``SAMLResponse``'s ``NameID`` to a fresh random attacker marker
    WITHOUT re-signing (the per-probe nonce), replay it, replay the operator's ``legit_saml`` (a validly-signed
    Response — the POSITIVE reference) and a well-formed assertion-bearing bad-signature control (the SUBSTANTIVE
    SAME-SHAPE NEGATIVE reference). Fires ONLY when a victim-PRIVATE ``D`` is present in the tampered-assertion
    read AND the legit positive reference AND absent from a substantive-2xx same-shape invalid-signature control
    — NO similarity score. ``success_markers`` are candidate SERVER-SIDE victim-PRIVATE data, NOT chrome and NOT a
    value the tampered assertion carries: the tampered assertion is un-re-signed, so any of its NameID / attribute
    values (e.g. a ``mail`` attribute) the SP decoded and echoed back is REFLECTION, disqualified by clause (d)'s
    forged-token-claim guard (round-6). Without BOTH ``success_markers`` and ``legit_saml`` it mints nothing (the
    offline ``saml_structural_forgery`` FACT still stands). A correct SP rejects the tampered assertion (signature
    mismatch), so it does not fire. Round-6 downgrade: an invalidated-signature control the SP rejects with a terse
    401/403 is not a substantive same-shape deny, so the wired class is a LEAD (``fact_capable: false``); the FACT
    needs the SP's own substantive same-shape deny view of the same ACS resource."""

    id: str = "saml-forgery-accepted"
    bug_class: str = "saml_forgery_accepted"
    field_name: str = "SAMLResponse"
    success_markers: tuple[str, ...] = ()
    # The operator-supplied legitimate VALID SAMLResponse (a gated-workflow input): base64 POST-binding value
    # OR raw XML. The POSITIVE reference; the well-formed bad-signature NEGATIVE control is derived from it.
    # Empty ⇒ LEAD.
    legit_saml: str = ""

    def probe(self, template: RequestTemplate, send: Send) -> "FindingContext | None":
        if not self.success_markers or not self.legit_saml:
            return None
        req = template.request
        raw = _sso.extract_form_field(req, self.field_name)
        if not raw:
            return None
        xml_text = _sso.decode_saml(raw)
        if not xml_text:
            return None
        legit_xml = _sso.decode_saml(self.legit_saml) or self.legit_saml   # accept base64 OR raw XML
        marker = _new_marker()
        try:
            tampered = _sso.tamper_assertion(xml_text, marker)
            control_xml = _invalidate_saml_signature(legit_xml)
        except Exception:
            return None
        legit_resp = send(_sso.with_form_field(req, self.field_name, _sso.encode_saml(legit_xml)))
        forged_resp = send(_sso.with_form_field(req, self.field_name, _sso.encode_saml(tampered)))
        control_resp = send(_sso.with_form_field(req, self.field_name, _sso.encode_saml(control_xml)))
        # Clause (d): the tampered assertion is UN-re-signed, so ALL of its text/attribute values are
        # attacker-controlled (the tampered NameID plus every kept AttributeValue — e.g. a ``mail`` attribute).
        # Any of them echoed back by the SP is REFLECTION, not an achieved server-side private read.
        return _acceptance_context(legit_resp, forged_resp, control_resp, marker,
                                   self.success_markers, self.bug_class,
                                   reflectable=_request_reflectable(req),
                                   token_claims=tuple(_saml_claim_values(tampered)))


def forgery_acceptance_checks(
    success_markers: "tuple[str, ...]",
    *,
    legit_token: str = "",
    legit_saml: str = "",
) -> "tuple[object, ...]":
    """The opt-in, gated-workflow forgery-ACCEPTANCE arsenal, bound to the operator's victim-PRIVATE discriminator
    baseline AND a legitimate VALID token / assertion (the POSITIVE reference). NOT part of
    ``DEFAULT_REQUEST_CHECKS`` and never instantiated with an empty baseline in the default roster — a caller
    (the gated-workflow wiring) passes the operator's ``success_markers`` (candidate victim-PRIVATE data) plus
    the per-surface positive reference. With an empty baseline OR no positive reference every check returns
    ``None`` (mints nothing), so the default scan/benchmark is byte-for-byte unchanged."""
    return (
        JwtForgeryAcceptanceCheck(success_markers=success_markers, legit_token=legit_token),
        OidcForgeryAcceptanceCheck(success_markers=success_markers, legit_token=legit_token),
        SamlForgeryAcceptanceCheck(success_markers=success_markers, legit_saml=legit_saml),
    )
