"""verify.oracle_version — a content-derived version identity for each oracle kind.

The Proof-Carrying Findings (PCF) standard requires a certificate to name the EXACT oracle *id@version*,
so a verifier re-runs the SAME decision procedure that produced the verdict and can detect that the oracle
body changed since the certificate was issued. CRUCIBLE oracles carry a *kind* (``OracleKind``) but have no
version. This module derives one: ``oracle_version(kind)`` is a sha256 over the canonical SOURCE of the pure
function(s) that ``verifier._run`` dispatches ``kind`` to — so ANY change to an oracle's body changes its
version, and a certificate minted under the old body is detectably *stale* at re-verification.

The version is captured at MINT time and signed into the certificate (see ``evidence/certify.py``); a
verifier compares that stamped version against the CURRENT ``oracle_version(kind)``. If they differ, the
retained proof still re-fires but under a different procedure than the one the issuer signed — a fact PCF
requires be surfaced (and which the PCF verifier treats fail-closed).

Pure + deterministic: the hash is a stable function of the oracle source, identical across runs and across
machines holding the same source. Uses the SOURCE (not bytecode) so it is portable across Python versions —
the reference implementation ships with source. If the source is unavailable (a frozen/zipped deployment),
the version is the empty string and a PCF verifier reports it cannot confirm the version rather than guessing.

SCOPE OF "the oracle body", STATED EXPLICITLY (AUDIT-B6). ``inspect.getsource`` returns COMMENTS AND
DOCSTRINGS as well as code, and this module deliberately keeps them in the hash. That is defensible here
and not an accident: across these oracles a comment or a docstring routinely IS the specification of the
decision procedure — the precision rules, the measured false-positive shapes, the reason a set is closed.
An edit that changes what the procedure is understood to decide should be visible to a re-verifier even
when the AST is untouched. The direct consequence, which an operator must be told rather than left to
discover: a DOCSTRING-ONLY edit bumps ``oracle_version`` and makes every certificate of that kind report
"oracle version mismatch" at ``evidence/pcf.py:216``. That happened in this very slice to
``side_effect``, whose AST body hash is byte-identical (``e099244d2b399297``) at 838e0b42, 1ccd18a5,
9bc3e632 and here — only its prose changed.

That is only acceptable while the version is ACTUALLY DETERMINISTIC. It was not: three kinds
(``command_injection_breakout``, ``nosql_injection_breakout``, ``secret_credential_validity``) produced a
different version per process — see ``_canon`` and ``oracles._CMD_ALT`` — which turned that loud,
designed ``pcf.py:216`` failure into unreadable noise and made a genuine docstring bump indistinguishable
from a hash-seed artefact. Both defects are fixed, and
``evidence/tests/test_evidence_hardening.py::test_B6_oracle_version_is_deterministic_across_processes``
holds the line across REAL subprocesses at differing ``PYTHONHASHSEED`` values, over every kind.
"""

from __future__ import annotations

import ast
import functools
import hashlib
import importlib
import importlib.util
import inspect
import sys
import textwrap
import types
from functools import lru_cache
from typing import Any, Callable

from . import oracles
from .models import OracleKind

# The repository's own top-level package. A callable / class / constant whose ``__module__`` is this package
# (or a submodule of it) is an IN-REPO "sibling": its SOURCE is bound into the version, so a change to its
# body is detectable at re-verification. Anything else is genuinely third-party — named only
# (``module.qualname``), never sourced — so the version tracks THIS engine's decision procedure and not a
# library's release. Derived from the oracles module's own dotted name so it needs no hard-coded literal.
_REPO_TOP = oracles.__name__.split(".", 1)[0]


def _in_repo_modname(modname: Any) -> bool:
    """True iff ``modname`` names the repo's own top package or a submodule of it (an in-repo sibling)."""
    return isinstance(modname, str) and (modname == _REPO_TOP or modname.startswith(_REPO_TOP + "."))


def _in_repo_obj(obj: Any) -> bool:
    """Is ``obj`` an in-repo callable/class/constant? Unwraps ``functools.partial`` chains (whose own
    ``__module__`` is ``functools``, which would hide an in-repo target), and for an instance-callable falls
    back to the module its TYPE is defined in — so a partial over an in-repo function, an in-repo bound
    method, and an instance of an in-repo callable class are all recognised as in-repo rather than
    mis-classed third-party."""
    depth = 0
    while isinstance(obj, functools.partial) and depth < 64:
        obj = obj.func
        depth += 1
    if _in_repo_modname(getattr(obj, "__module__", None)):
        return True
    if not isinstance(obj, (types.FunctionType, type)):
        return _in_repo_modname(getattr(type(obj), "__module__", None))
    return False

# The pure oracle function(s) each kind dispatches to in ``verifier._run``. A kind whose dispatch selects
# more than one function by context keys (TLS_WEAKNESS → protocol/cipher OR cert-signature; ACHIEVED_STATE
# → predicate OR expected/observed) lists ALL of them, so editing ANY body changes the kind's version.
# A test pins ``set(_ORACLE_FNS) == set(OracleKind)`` so a newly-added kind must register here.
_ORACLE_FNS: dict[OracleKind, tuple[Callable[..., Any], ...]] = {
    OracleKind.DIFFERENTIAL_RESPONSE: (oracles.differential_response_oracle,),
    OracleKind.TIMING: (oracles.timing_oracle,),
    OracleKind.BOOLEAN_INFERENCE: (oracles.boolean_inference_oracle,),
    OracleKind.ACHIEVED_STATE: (oracles.predicate_oracle, oracles.achieved_state_oracle),
    OracleKind.SIDE_EFFECT: (oracles.side_effect_oracle,),
    OracleKind.REFLECTION_CONTEXT: (oracles.reflection_context_oracle,),
    # EVALUATION dispatches by ctx key to the SSTI/EL evaluation oracle OR the SSI-specialised
    # ssi_evaluation_oracle (Wave-4.1) — both listed so editing EITHER body changes the kind's version.
    OracleKind.EVALUATION: (oracles.evaluation_oracle, oracles.ssi_evaluation_oracle),
    OracleKind.ERROR_SIGNATURE: (oracles.error_signature_oracle,),
    OracleKind.DOM_EXECUTION: (oracles.dom_execution_oracle,),
    OracleKind.SANITIZER_SIGNAL: (oracles.sanitizer_signal_oracle,),
    OracleKind.OOB_CALLBACK: (oracles.oob_callback_oracle,),
    OracleKind.SERVICE_REACHABILITY: (oracles.service_reachability_oracle,),
    OracleKind.ACTIVE_EXPOSURE: (oracles.anonymous_reachable_oracle,),
    OracleKind.TLS_WEAKNESS: (oracles.tls_weakness_oracle, oracles.weak_crypto_artifact_oracle),
    # M1.3 TLS certificate validity — its OWN dedicated kind so editing the validity derivation changes ONLY
    # oracle_version(CERTIFICATE_VALIDITY), never TLS_WEAKNESS. The transitive-closure walker picks up the
    # module-level _cert_validity_* helpers + the _CERT_VALIDITY_DEFECTS vocabulary the oracle references, so
    # editing any of them makes a certificate minted under the old body detectably stale.
    OracleKind.CERTIFICATE_VALIDITY: (oracles.certificate_validity_oracle,),
    OracleKind.VERSION_RANGE: (oracles.version_range_oracle,),
    OracleKind.POLICY_PATH: (oracles.policy_path_oracle,),
    OracleKind.SYSTEM_PROMPT_DISCLOSURE: (oracles.system_prompt_disclosure_oracle,),
    OracleKind.PROMPT_INJECTION: (oracles.prompt_injection_oracle,),
    OracleKind.AUTOMATED_ACCESS: (oracles.honeypot_hit_oracle,),
    OracleKind.CREDENTIAL_STUFFING: (oracles.credential_stuffing_oracle,),
    OracleKind.SQL_INJECTION_BREAKOUT: (oracles.sql_injection_breakout_oracle,),
    OracleKind.COMMAND_INJECTION_BREAKOUT: (oracles.command_injection_breakout_oracle,),
    OracleKind.NOSQL_INJECTION_BREAKOUT: (oracles.nosql_injection_breakout_oracle,),
    OracleKind.K8S_POSTURE: (oracles.k8s_posture_oracle,),
    OracleKind.K8S_WORKLOAD_POSTURE: (oracles.k8s_workload_posture_oracle,),
    OracleKind.CLOUD_POSTURE: (oracles.cloud_posture_oracle,),
    OracleKind.MESH_POSTURE: (oracles.mesh_posture_oracle,),
    OracleKind.CICD_POSTURE: (oracles.cicd_posture_oracle,),
    OracleKind.MOBILE_POSTURE: (oracles.mobile_posture_oracle,),
    OracleKind.EMAIL_AUTH_POSTURE: (oracles.email_auth_posture_oracle,),
    OracleKind.IDENTITY_POSTURE: (oracles.identity_posture_oracle,),
    OracleKind.SSO_ASSERTION_FORGERY: (oracles.jwt_forgery_oracle,),
    OracleKind.SAML_STRUCTURAL_FORGERY: (oracles.saml_forgery_oracle,),
    OracleKind.IMDS_CREDENTIAL_CAPTURE: (oracles.imds_credential_capture_oracle,),
    OracleKind.SECRET_CREDENTIAL_VALIDITY: (oracles.exposed_secret_validity_oracle,),
    OracleKind.GCP_SA_IMPERSONATION: (oracles.gcp_sa_impersonation_oracle,),
    OracleKind.IAM_ESCALATION_PRIMITIVE: (oracles.iam_escalation_oracle,),
    OracleKind.K8S_RBAC_VERB_GRANT: (oracles.k8s_rbac_verb_grant_oracle,),
    # W16-STD-5 client-side posture-weakness oracles (clickjacking / CSRF / postMessage).
    OracleKind.CLICKJACKING_POSTURE: (oracles.clickjacking_posture_oracle,),
    OracleKind.CSRF_POSTURE: (oracles.csrf_posture_oracle,),
    OracleKind.POSTMESSAGE_POSTURE: (oracles.postmessage_posture_oracle,),
    # Wave-2.2 client-side prototype pollution (achieved-state).
    OracleKind.PROTOTYPE_POLLUTION: (oracles.prototype_pollution_oracle,),
    # Wave-2.4 CSP permissive-policy posture (retained-header parse; the achieved bypass reuses
    # DOM_EXECUTION and so needs no _ORACLE_FNS entry of its own).
    OracleKind.CSP_POSTURE: (oracles.csp_posture_oracle,),
    # Wave-3.2 session fixation (CWE-384) — its OWN dedicated kind so editing its differential body changes
    # ONLY oracle_version(SESSION_FIXATION), never oracle_version(ACHIEVED_STATE).
    OracleKind.SESSION_FIXATION: (oracles.session_fixation_oracle,),
    # Wave-4.5 MFA bypass (CWE-287/CWE-308) — its OWN dedicated kind. The transitive-closure version machinery
    # picks up the shared _sfx_private_read_achieved differential it reuses, so editing that helper changes BOTH
    # oracle_version(MFA_BYPASS) and oracle_version(SESSION_FIXATION); editing mfa_bypass_oracle changes ONLY
    # oracle_version(MFA_BYPASS) (session_fixation_oracle does not reference it), never ACHIEVED_STATE.
    OracleKind.MFA_BYPASS: (oracles.mfa_bypass_oracle,),
    # Wave-4.3 password-reset / account-recovery token invariant (CWE-640/613/330) — its OWN dedicated kind so
    # editing its reuse/collision body changes ONLY oracle_version(PASSWORD_RESET_INVARIANT), never
    # oracle_version(ACHIEVED_STATE) (the cross-user reset sub-property reuses ACHIEVED_STATE, adding no fn here).
    OracleKind.PASSWORD_RESET_INVARIANT: (oracles.password_reset_invariant_oracle,),
    # Wave-5.1 static source-code rule (the SAST bridge). Only the entry point is listed; the transitive-
    # closure walker captures the tier dispatch (_static_tier_hit) and every FACT-capable tier helper +
    # constant it references, plus the insecure-randomness fail-closed LEAD guard, so editing ANY FACT-capable
    # tier body (broken-crypto / insecure-flag / direct-taint) — or the insecure-randomness fail-closed guard —
    # changes oracle_version(STATIC_RULE) and a certificate minted under the old body is detectably stale.
    OracleKind.STATIC_RULE: (oracles.static_rule_oracle,),
}


def _coerce_kind(kind: Any) -> OracleKind | None:
    """Accept an ``OracleKind`` or its string value (a certificate stores ``confirmed_by`` as a str)."""
    if isinstance(kind, OracleKind):
        return kind
    try:
        return OracleKind(str(kind))
    except ValueError:
        return None


class _SourceUnavailable(Exception):
    """A reachable function's source could not be read (a frozen/zipped deployment)."""


class _UnclassifiableInRepoCallable(Exception):
    """The reachable-source walk reached an IN-REPO callable it cannot classify and cannot resolve to source
    — one that is neither a plain ``types.FunctionType`` nor a class: a ``functools.partial``, a
    bound/inherited method, or an instance with ``__call__``. Its decision procedure cannot be sourced from a
    module-global reference, so the version would silently omit it and a changed procedure would ship under an
    unchanged id@version. This is raised as a FAIL-CLOSED build error — deliberately NOT the stale-safe ``""``
    of ``_SourceUnavailable`` (which ``oracle_version`` swallows). The omission must be fixed at the source
    (register the callable, or expose the underlying in-repo function), not hidden behind a stale-safe hash.
    NOTE: genuinely third-party callables reached the same way are NOT an error — they are named-only by
    design (see ``_canon``), because binding a library's source would make the version track that library."""


def _referenced_names(fn: Callable[..., Any]) -> set[str]:
    """Every global NAME a function/lambda references, walked transitively through nested code objects
    (comprehensions, inner closures) so a name used only inside a nested scope is still seen. The single
    ``co_names`` walker shared by the reachable-source closure (``_reachable_source_blob._walk_body``) and by
    ``_canon``'s constant binding (``_canon_referenced_consts``)."""
    code = getattr(fn, "__code__", None)
    if code is None:
        return set()
    names: set[str] = set()
    stack = [code]
    while stack:
        c = stack.pop()
        names.update(c.co_names)
        for const in c.co_consts:
            if isinstance(const, types.CodeType):
                stack.append(const)
    return names


def _canon_referenced_consts(fn: Callable[..., Any], _seen: frozenset[int],
                             _covered: frozenset[int] = frozenset()) -> str:
    """The module-level CONSTANTS *and* the UNCOVERED IN-REPO helper CALLABLES an in-repo lambda/function
    references, canonicalised and appended so their VALUES / SOURCE enter the version. When such a callable is
    nested inside a constant container (``_canon`` recurses into the container and SOURCE-binds the callable),
    only its SOURCE TEXT was captured — anything it merely *references by name* appears only as a token in that
    text, so mutating that referent changed the decision but left the version byte-identical.

    TWO holes are closed here, both of the same shape (a referent reached ONLY inside a source-bound
    lambda/nested function — i.e. one the closure walk never captured on its own):
      * A module-level CONSTANT it calls (AUDIT-B: the ``_SECRET_*`` regexes the ``_SECRET_RECOGNIZERS``
        lambdas match against) → bound by its canonical VALUE.
      * An IN-REPO helper FUNCTION/METHOD it calls that is NOT already covered by the closure walk
        (``id(val) not in _covered``) → recurse through ``_canon``'s source-binding arm so the helper's
        SOURCE enters the version; mutating that helper's body now changes the version.

    THE ``_covered`` GUARD — why it is load-bearing (and how it keeps this ZERO-DELTA). ``_covered`` is the
    id-set of every in-repo function/class ``_reachable_source_blob`` already captured as its OWN standalone
    source record. A helper reached BOTH inside a source-bound callable AND directly by the walk (today:
    ``oracles._imds_text``, which the ``_SECRET_RECOGNIZERS`` identity functions call and which the walk also
    reaches on its own) is ALREADY in the version once — binding it again here would only DUPLICATE its source
    and change the hash for no soundness gain, invalidating every existing certificate of that kind. Skipping a
    covered helper leaves the shipped oracles byte-identical while still binding a genuinely uncovered helper
    (one reached ONLY inside the source-bound callable) — the exact latent hole. There is no such uncovered
    helper today, which is why closing the hole is a zero-delta change.

    Each name in the callable's ``co_names`` is resolved against its DEFINING module
    (``sys.modules[fn.__module__]`` — the same rule ``_walk_body`` uses for a walked function, NOT
    ``fn.__globals__``, which for a compiler-generated method would bind ``dataclasses`` internals by heap
    address). A module-level CONSTANT (``_is_hashable_constant``) is bound by its canonical value; an UNCOVERED
    in-repo function/method (the predicate MIRRORS ``_canon``'s source-binding arm) is source-bound via
    ``_canon``. A name that resolves to a module, a class, a genuinely THIRD-PARTY callable, or a COVERED
    in-repo helper is deliberately NOT bound here. Determinism is preserved — names are sorted, a regex binds
    by its canonical PATTERN (``_canon`` → ``repr``) and a callable by its SOURCE, never by object identity —
    and ``_seen`` (function ids) breaks any reference cycle so mutual/self references terminate."""
    if id(fn) in _seen:
        return ""
    seen = _seen | {id(fn)}
    modname = getattr(fn, "__module__", None)
    mod = sys.modules.get(modname) if modname else None
    if mod is None:
        return ""
    g = vars(mod)
    parts: list[str] = []
    for nm in sorted(_referenced_names(fn)):
        val = g.get(nm)
        if val is None:
            continue
        if _is_hashable_constant(val):
            # a module-level CONSTANT the callable references → bind by canonical VALUE.
            parts.append(f"{nm}={_canon(val, seen, _covered)}")
        elif (_in_repo_modname(getattr(val, "__module__", None))
              and (inspect.isfunction(val) or inspect.ismethod(val))
              and id(val) not in _covered):
            # AUDIT-B (this slice): an IN-REPO helper FUNCTION/METHOD the callable CALLS, reached ONLY inside
            # this source-bound lambda/nested function AND not already captured by the closure walk,
            # previously entered the version by NAME only (it appears solely as a token in the lambda's
            # captured TEXT), so mutating that helper's BODY left the version byte-identical — a staleness
            # hole. Recurse through ``_canon``'s existing source-binding arm so the helper's SOURCE (and,
            # transitively, ITS own referenced constants + uncovered in-repo callables) enters the version.
            # ``seen`` breaks any reference cycle; ``_covered`` prevents re-binding an already-captured helper
            # (which would change the hash for no soundness gain — see the ``_covered`` note above).
            parts.append(f"{nm}={_canon(val, seen, _covered)}")
    return ("|consts:" + ",".join(parts)) if parts else ""


def _canon(obj: Any, _seen: frozenset[int] = frozenset(),
           _covered: frozenset[int] = frozenset()) -> str:
    """A canonical, hash-stable repr of a module-level constant — ORDER-INDEPENDENT for sets/frozensets/
    dicts so the version does not depend on PYTHONHASHSEED (the version must be identical across processes
    and machines). Falls back to ``repr`` for scalars, compiled regexes, ip_address objects, etc.

    AUDIT-B6 — ``repr`` MUST NOT BE THE FALLBACK FOR A CALLABLE. ``_is_hashable_constant`` excludes a
    top-level callable, but a callable nested INSIDE a constant container was still reached and
    ``repr``-ed: ``oracles._SECRET_RECOGNIZERS`` holds lambdas, so this recursed to
    ``repr(<function <lambda> at 0x7f65…>)`` and hashed a HEAP ADDRESS. Measured:
    ``oracle_version(secret_credential_validity)`` differed in all TEN of ten separate processes, across
    five pinned ``PYTHONHASHSEED`` values — so every certificate of that kind was permanently
    "oracle_version CHANGED since mint" and could never verify fully-sound. That falsifies CRUCIBLE
    invariant 6 (determinism) for the version identity, and it turns the loud ``pcf.py:216`` failure into
    unreadable noise.

    A callable is therefore named STABLY. For an IN-REPO function/method (defined anywhere in this repo's
    own package, not only ``verify.oracles``) the name carries its SOURCE, so the version still changes when
    the callable's behaviour changes (a lambda in a dict literal yields its defining line, which is what
    distinguishes the sibling lambdas of one recognizer row) — and an in-repo sibling nested in a constant
    is never reduced to a name-only token that could hide a changed body. For anything else — a builtin, a C
    function, a genuinely third-party callable, a class used as a factory — only the stable
    ``module.qualname`` is used, because embedding third-party source would make this version track
    library versions instead of this engine's decision procedure.

    AUDIT-B (this slice) — CONSTANTS *and UNCOVERED IN-REPO HELPER CALLABLES* REACHED ONLY INSIDE A
    SOURCE-BOUND LAMBDA/NESTED FUNCTION are now covered. Source-binding a callable captured only its TEXT, so
    a module-level constant it *calls* (the ``_SECRET_*`` regexes referenced solely inside the
    ``_SECRET_RECOGNIZERS`` lambdas) entered the version by NAME only — mutating ``_SECRET_AWS_KEY_ID_RE``
    flipped a decision yet left ``oracle_version(SECRET_CREDENTIAL_VALIDITY)`` byte-identical. Likewise an
    in-repo helper FUNCTION a source-bound callable *calls*, reached ONLY inside it, entered by NAME only, so
    mutating that helper's body left the version byte-identical. When an IN-REPO function/lambda is
    source-bound here, ``_canon_referenced_consts`` now binds both the module-level constants it references
    (by canonical value) AND the in-repo helper functions it references that are NOT already captured by the
    closure walk (``_covered``) — resolved against the callable's DEFINING module — so both holes are closed
    while genuinely third-party names, and helpers the walk already captured, are left untouched and
    determinism is preserved."""
    if callable(obj):
        mod = getattr(obj, "__module__", None) or "?"
        name = (getattr(obj, "__qualname__", None) or getattr(obj, "__name__", None)
                or type(obj).__name__)
        src = ""
        deps = ""
        if _in_repo_modname(mod) and (inspect.isfunction(obj) or inspect.ismethod(obj)):
            try:
                src = "|" + inspect.getsource(obj).strip()
            except (OSError, TypeError):
                src = "|<source-unavailable>"
            # ALSO bind the module-level constants AND uncovered in-repo helper callables this in-repo
            # callable references — otherwise a constant (a `_SECRET_*` regex) or an in-repo helper FUNCTION
            # used only inside a lambda nested in a container enters the version by name only, and a changed
            # pattern / changed helper body ships under an unchanged id@version. ``_covered`` (the walk's
            # already-captured functions) keeps an already-covered helper from being re-bound here.
            deps = _canon_referenced_consts(obj, _seen, _covered)
        return f"<callable {mod}.{name}{src}{deps}>"
    if isinstance(obj, (set, frozenset)):
        return "{" + ",".join(sorted(_canon(x, _seen, _covered) for x in obj)) + "}"
    if isinstance(obj, dict):
        return "{" + ",".join(f"{_canon(k, _seen, _covered)}:{_canon(v, _seen, _covered)}"
                              for k, v in sorted(obj.items(), key=lambda kv: repr(kv[0]))) + "}"
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_canon(x, _seen, _covered) for x in obj) + "]"
    return repr(obj)


def _is_hashable_constant(val: Any) -> bool:
    """A module-level VALUE that is a constant (not a module, not a callable function/class): strings,
    numbers, frozensets/tuples, compiled regexes, ip_address objects, etc. — the validation constants an
    oracle's decision procedure depends on."""
    return not isinstance(val, types.ModuleType) and not callable(val)


def _reachable_source_blob(fns: tuple[Callable[..., Any], ...]) -> bytes:
    """The canonical source of the TRANSITIVE closure the oracle's decision procedure actually depends on
    (audit B2). Starting from ``fns`` the walk captures, and follows into, every IN-REPO helper it reaches:

      * a module-global FUNCTION or CLASS defined in the SAME module as the function referencing it (walked
        via its ``co_names``, including names used inside nested comprehensions/closures), and
      * an in-repo helper pulled in by an ``import`` statement INSIDE a walked function's body — the LOCAL
        imports that keep the module graph acyclic (``from .oob import verify_oob_receipt``,
        ``from .version import version_in_affected``, ``from ..scanner.sso import ...``). These are followed
        into their OWN defining module (their ``co_names`` resolve against THEIR globals, transitively).

    plus every module-level constant (an IP set, a regex, a path marker) reachable the same way. So editing
    a helper body — even one that lives behind a class, or in a sibling module reached only by a local
    import — OR a validation constant changes the version; the entry function alone no longer hides a
    changed procedure.

    EXACTLY WHAT IS AND IS NOT COVERED (stated so no re-verifier is surprised):
      * IN-REPO functions/classes reached via a same-module global reference, or via a local in-repo import
        inside a walked body → their SOURCE is bound (covered, transitively).
      * IN-REPO constants reached either way → their canonical value is bound (covered).
      * A module-level CONSTANT reached ONLY inside a SOURCE-BOUND in-repo lambda/nested function — i.e. a
        callable ``_canon`` source-binds because it lives INSIDE a constant container this walk recorded
        (the ``_SECRET_*`` regexes referenced solely inside the ``_SECRET_RECOGNIZERS`` lambdas) → its
        canonical VALUE is now bound too (covered, via ``_canon_referenced_consts``), resolved against the
        callable's DEFINING module. Editing such a regex now changes the version; before this slice it did
        not, so the changed decision procedure shipped under an unchanged id@version.
      * An IN-REPO helper FUNCTION/METHOD reached ONLY inside such a SOURCE-BOUND in-repo lambda/nested
        function (i.e. a helper the lambda *calls*, whose name appears solely in the lambda's captured TEXT)
        AND not already captured as its own record by this walk → its SOURCE is now bound too (covered, via
        ``_canon_referenced_consts`` recursing through ``_canon``'s source-binding arm, gated on the walk's
        ``_covered`` id-set). Mutating that helper's body now changes the version; before this slice it did
        not. This is latent — no shipped oracle reaches an in-repo helper ONLY this way today (a helper such
        as ``_imds_text`` that a recognizer's identity function calls is ALSO reached directly by the walk and
        so is ``_covered`` and NOT re-bound), so the version values are byte-identical — closing the hole
        before a future recognizer relies on a helper reached solely inside a source-bound callable. The
        constants are canonicalised only AFTER the walk finishes, so ``_covered`` is complete when the deps of
        a constant-nested callable are computed.
      * A cross-module in-repo function/class reached only by a MODULE-GLOBAL name (e.g. ``OracleKind`` /
        ``OracleSignal`` imported at module top) is deliberately NOT walked into here — it belongs to the
        model layer, not the decision procedure, and following it would balloon every version identically;
        it is neither sourced nor named (unchanged from prior behaviour, so existing versions stay stable).
      * GENUINELY THIRD-PARTY callables (``urllib``'s ``urlsplit``, a ``typing`` alias, a C function) are
        left alone — never sourced (a library's version is out of scope) and, reached via a module-global,
        skipped rather than name-bound, so they do not perturb an oracle's version.
      * An IN-REPO callable that is neither a plain function nor a class — a ``functools.partial``, a
        bound/inherited method, or an instance with ``__call__`` — reached via a module-global reference
        CANNOT be sourced this way. Rather than silently skip it (the old behaviour, which would let its
        changed procedure ship under an unchanged version) the walk FAILS CLOSED and raises
        ``_UnclassifiableInRepoCallable``. None are live today; if one is introduced the build breaks until
        it is handled explicitly. Raises ``_SourceUnavailable`` if any reachable function's source is missing.

    AUDIT (prior slice) — THE CLASS HOLE, now closed: ``reflection_context_oracle`` -> ``_ReflectionScanner``
    used to stop dead at the class (its ``handle_data``/``handle_starttag`` bodies, the ``_js_scan`` lexer,
    and ``_EVENT_HANDLER_ATTRIBUTES`` / ``_INERT_TEXT_CONTAINERS`` / ``_JS_MIME_ESSENCES`` were invisible).
    A class is now visited and its methods walked. AUDIT (this slice) — THE CROSS-MODULE / LOCAL-IMPORT
    HOLE: the walk followed only same-module ``types.FunctionType``, so ``verify_oob_receipt`` (OOB_CALLBACK),
    ``version_in_affected`` (VERSION_RANGE) and the ``scanner.sso`` parse/tree helpers (SAML_STRUCTURAL_FORGERY)
    — each reached ONLY by a local import and each the actual decision procedure — were INVISIBLE: mutating
    them left the version byte-identical. Both holes are built up to meet the claim, per CLAIM DISCIPLINE."""
    seen_fns: set[int] = set()
    seen_consts: set[str] = set()
    func_srcs: list[str] = []
    pending_consts: list[tuple[str, Any]] = []

    def _record_const(name: str, val: Any) -> None:
        # DEFER canonicalisation: a constant may contain a source-bound in-repo callable whose deps must be
        # deduplicated against EVERY function the walk captures (``_covered``), and that set is only complete
        # once the walk finishes. Recording (name, val) here and canonicalising below keeps the deps check
        # complete and order-independent (``const_reprs`` is sorted at the end regardless).
        if name not in seen_consts:
            seen_consts.add(name)
            pending_consts.append((name, val))

    def _follow_global(name: str, val: Any, own_module: str | None) -> None:
        """Follow a MODULE-GLOBAL name reference found in a walked function's ``co_names``. Functions and
        classes are walked into ONLY when defined in ``own_module`` (the module of the referencing function),
        which keeps a cross-module model type like ``OracleKind`` out and leaves existing versions stable. A
        constant is recorded. A callable that is neither a plain function nor a class fails closed if in-repo,
        and is otherwise (genuinely third-party) skipped."""
        if isinstance(val, types.FunctionType):
            if getattr(val, "__module__", None) == own_module:
                visit(val)
        elif isinstance(val, type):
            if getattr(val, "__module__", None) == own_module:
                visit_class(val)
        elif _is_hashable_constant(val):
            _record_const(name, val)
        elif callable(val):
            if _in_repo_obj(val):
                raise _UnclassifiableInRepoCallable(
                    f"in-repo callable {name!r} ({val!r}, module "
                    f"{getattr(val, '__module__', None)!r}) is neither a plain function nor a class "
                    f"(functools.partial / bound method / instance-callable); its source cannot be bound "
                    f"into the oracle version from a module-global reference. Register it explicitly or "
                    f"expose the underlying in-repo function rather than let a changed procedure ship "
                    f"under an unchanged id@version.")
            # else: genuinely third-party (urllib / typing / a C function) — skipped, unchanged behaviour.
        # else: a module or other non-callable non-const — nothing to bind.

    def _follow_local_import(name: str, obj: Any) -> None:
        """Follow an object EXPLICITLY imported by a statement inside a walked function body. Unlike a
        module-global reference this is an explicit dependency of the decision procedure, so an in-repo
        function/class is walked into regardless of which module defines it (continuing in ITS own module).
        A constant is recorded. An in-repo callable that is neither a plain function nor a class fails
        closed; a third-party import contributes nothing and is ignored."""
        if isinstance(obj, types.FunctionType) and _in_repo_obj(obj):
            visit(obj)
        elif isinstance(obj, type) and _in_repo_obj(obj):
            visit_class(obj)
        elif _is_hashable_constant(obj):
            if _in_repo_obj(obj) or not callable(obj):
                _record_const(name, obj)
        elif callable(obj) and _in_repo_obj(obj):
            raise _UnclassifiableInRepoCallable(
                f"in-repo callable {name!r} ({obj!r}) imported locally is neither a plain function nor a "
                f"class; its source cannot be bound into the oracle version. Expose the underlying in-repo "
                f"function rather than let a changed procedure ship under an unchanged id@version.")
        # else: a third-party import / module — nothing to bind.

    def _local_in_repo_imports(fn: Callable[..., Any]):
        """Yield ``(bound_name, object)`` for every IN-REPO object brought in by an ``import`` statement
        inside ``fn``'s own body (module-level imports are not in ``fn``'s source and so are not seen here —
        which is why a top-level ``from .models import OracleKind`` is not followed). Third-party imports are
        never even imported: the module name is resolved first and skipped unless it is in-repo, so a
        ``from lxml import etree`` guard costs nothing and pulls in no optional dependency."""
        try:
            src = inspect.getsource(fn)
        except (OSError, TypeError):
            return
        try:
            tree = ast.parse(textwrap.dedent(src))
        except SyntaxError:
            return
        modname = getattr(fn, "__module__", None)
        mod = sys.modules.get(modname) if modname else None
        pkg = getattr(mod, "__package__", None)
        if not pkg and modname and "." in modname:
            pkg = modname.rsplit(".", 1)[0]
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                rel = "." * node.level + (node.module or "")
                try:
                    absmod = importlib.util.resolve_name(rel, pkg) if node.level else (node.module or "")
                except (ImportError, ValueError):
                    continue
                if not _in_repo_modname(absmod):
                    continue   # third-party (lxml/signxml/...) — never imported
                try:
                    imported = importlib.import_module(absmod)
                except Exception:
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    obj = getattr(imported, alias.name, None)
                    if obj is not None:
                        yield (alias.asname or alias.name, obj)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if not _in_repo_modname(alias.name):
                        continue
                    try:
                        imported = importlib.import_module(alias.name)
                    except Exception:
                        continue
                    yield (alias.asname or alias.name.split(".", 1)[0], imported)

    def _module_ns(own_module: str | None) -> dict[str, Any]:
        """The DEFINING module's globals for a walked function. Deliberately NOT ``fn.__globals__``: a
        compiler-generated method (a ``@dataclass`` ``__init__`` / ``__eq__``) carries a SYNTHETIC globals
        dict from the ``dataclasses`` module, so resolving its ``co_names`` there would bind
        ``MISSING=<dataclasses._MISSING_TYPE object at 0x…>`` — a HEAP ADDRESS — into the version, breaking
        determinism. Keying on ``__module__`` resolves such a method's names against ITS class's real module
        (where those internal names are absent and simply skipped), matching the pre-slice behaviour, while
        still giving a genuine cross-module helper its own module's namespace."""
        mod = sys.modules.get(own_module) if own_module else None
        return vars(mod) if mod is not None else {}

    def _walk_body(fn: Callable[..., Any], own_module: str | None) -> None:
        g = _module_ns(own_module)
        for name in _referenced_names(fn):
            val = g.get(name)
            if val is None:
                continue
            _follow_global(name, val, own_module)
        for bound_name, obj in _local_in_repo_imports(fn):
            _follow_local_import(bound_name, obj)

    def visit(fn: Callable[..., Any]) -> None:
        if id(fn) in seen_fns:
            return
        seen_fns.add(id(fn))
        try:
            func_srcs.append(inspect.getsource(fn))
        except (OSError, TypeError) as exc:
            raise _SourceUnavailable() from exc
        _walk_body(fn, getattr(fn, "__module__", None))

    def visit_class(cls: type) -> None:
        """A class defined in-repo IS part of the decision procedure (``_ReflectionScanner`` is the whole
        HTML/JS context decision, and ``scanner.sso.XxeBlocked`` gates the SAML parse). Capture its source
        and keep walking through its own methods — resolving THEIR names against the class's OWN module — so
        the helpers and constants they reference join the closure instead of being invisible."""
        if id(cls) in seen_fns:
            return
        seen_fns.add(id(cls))
        try:
            func_srcs.append(inspect.getsource(cls))
        except (OSError, TypeError) as exc:
            raise _SourceUnavailable() from exc
        own_module = getattr(cls, "__module__", None)
        for attr in sorted(vars(cls)):
            member = vars(cls)[attr]
            member = getattr(member, "__func__", member)          # classmethod / staticmethod
            if not isinstance(member, types.FunctionType):
                continue
            _walk_body(member, own_module)

    for fn in fns:
        visit(fn)
    # The walk is complete: ``seen_fns`` now names EVERY in-repo function/class captured as its own standalone
    # source record. Canonicalise the deferred constants against that ``_covered`` set, so a constant-nested
    # source-bound callable's deps bind only an in-repo helper the walk did NOT already capture (a helper
    # reached ONLY inside such a callable — the latent hole). An already-covered helper (e.g. ``_imds_text``,
    # reached directly by the walk) is skipped, so this stays byte-identical for the shipped oracles.
    covered = frozenset(seen_fns)
    const_reprs = [f"{name}={_canon(val, _covered=covered)}" for name, val in pending_consts]
    # Sorted so the blob is independent of traversal order → stable across runs/machines.
    parts = sorted(func_srcs) + sorted(const_reprs)
    return "\x00".join(parts).encode("utf-8")


@lru_cache(maxsize=None)
def oracle_version(kind: Any) -> str:
    """The version identity for ``kind`` — ``"sha256:<hex>"`` over the canonical source of its oracle
    function(s) AND the transitive closure of module-level helpers + constants its decision procedure
    depends on (audit B2), or ``""`` when the kind is unknown or its source is unavailable (a frozen
    deployment). Pure + deterministic. Accepts an ``OracleKind`` or its string value."""
    ok = _coerce_kind(kind)
    if ok is None:
        return ""
    fns = _ORACLE_FNS.get(ok)
    if not fns:
        return ""
    try:
        blob = _reachable_source_blob(fns)
    except _SourceUnavailable:
        return ""   # source unavailable → cannot derive a version (verifier reports, never guesses)
    return "sha256:" + hashlib.sha256(blob).hexdigest()
