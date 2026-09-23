"""
scanner.access_control — the OPT-IN access-control check pack (Workstream D.2).

CRUCIBLE can already CONFIRM broken access control: the four memory-less classes
(``idor`` / ``bola`` / ``bfla`` / ``broken_access_control`` / ``authorization`` /
``mass_assignment`` / ``privilege_escalation``) all route to the ACHIEVED-STATE oracle
(``verify.verifier.BUG_CLASS_ORACLES``), and ``scanner.checks.IdorCheck`` already implements the
two-identity cross-read that fires it. What was missing is a SEEDED set: these checks are NOT in
``DEFAULT_CHECKS`` and cannot be — a broken-access-control test is fundamentally a TWO-IDENTITY
experiment (act as the attacker, compare against what a *different* identity legitimately sees), so it
needs a second authenticated ``send`` and a per-target object/endpoint reference the operator must
supply. There is no honest way to autodiscover those.

This module ships them behind an EXPLICIT OPT-IN, default OFF:

  * ``build_access_control_checks(config, enabled=False)`` returns ``()`` unless the operator both
    passes a populated :class:`AccessControlConfig` (the victim identity + references) AND flips
    ``enabled=True``. So the pack is inert by default: it never enters ``DEFAULT_CHECKS``, never lands
    in ``library_entries/``, and therefore never sends a byte on the benchmark/scan/engage gate path.
  * Every check confirms via the SAME deterministic ACHIEVED-STATE / predicate oracle already in the
    engine — no new oracle, no new confirmation machinery. A 403 / empty / different response fails the
    predicate and does NOT fire, so a correctly-authorised endpoint is never a false positive. A negative
    control proves 'absent' ONLY when that control read is itself a SUBSTANTIVE SUCCESS (round-3): an
    absent-because-errored/empty/404/403 body proves NOTHING and fails closed to a LEAD, never a FACT.

PROVE-DON'T-GUESS: the oracle decides over the RAW two-identity evidence (the attacker's status+body
vs. the victim/ground-truth body). The check never asserts the finding itself. The mere presence of a
numeric id or an admin route is a LEAD, never a fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, ClassVar, Iterable

from ..verify.adapter import FindingContext
from .checks import Check, IdorCheck, Send
from .insertion import HttpRequest, InsertionPoint, RequestTemplate

# The seven access-control classes this pack seeds. Each routes to the ACHIEVED-STATE oracle.
ACCESS_CONTROL_CLASSES: tuple[str, ...] = (
    "idor", "bola", "bfla", "broken_access_control",
    "authorization", "mass_assignment", "privilege_escalation",
)


# ---------------------------------------------------------------------------
# mass-assignment — inject a privileged field, prove it PERSISTED (state change)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MassAssignmentCheck:
    """Mass assignment via a PROVEN state change, not a reflected echo.

    As the attacker, it (1) reads the object back to a baseline, (2) submits a mutation that injects a
    privileged field (``field=privileged_value``) into the point, (3) reads the object back again. The
    achieved-state predicate confirms ONLY when the privileged value is present in the AFTER read but
    ABSENT from the BEFORE read — i.e. the server accepted a field the attacker should never be able to
    set, and it PERSISTED. A response that merely echoes the field, or an object that already carried
    the value, fails the predicate (no false positive).

    READBACK IDENTITY (soundness): persistence is confirmed by the AUTHORITATIVE-OWNER *view* of the
    object, NEVER by the WRITE's own response. The write response is DISCARDED; the before/after are a
    SEPARATE ``readback_request`` issued via ``readback_send`` (the owner / ground-truth session). That
    readback MUST be a non-mutating read (GET/HEAD) — a write cannot serve as its own persisted-state
    proof, so a WRITE response that merely echoes the injected field can never confirm. If the configured
    ``readback_request`` is itself a mutating method the probe returns None (a LEAD, nothing minted).
    Runs only on the point named ``field``; other points return None."""

    id: str
    field: str
    privileged_value: str
    readback_send: Send
    readback_request: HttpRequest
    bug_class: str = "mass_assignment"

    # HTTP methods that are safe to use as a persisted-state readback (they cannot themselves mutate, so
    # the AFTER read reflects server state, not a write-echo). Anything else is refused.
    _READBACK_METHODS: ClassVar[frozenset[str]] = frozenset({"GET", "HEAD"})

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        if point.name != self.field:
            return None
        # Enforce the readback identity: the AFTER read must be an authoritative-owner *view* (a safe,
        # non-mutating request), never the write's own echo. A mutating readback cannot soundly prove
        # persistence, so fail closed to a LEAD rather than mint off a write-echo.
        if self.readback_request.method.strip().upper() not in self._READBACK_METHODS:
            return None
        before = self._read()
        send(template.render(point, self.privileged_value))   # the mass-assignment attempt (response DISCARDED)
        after = self._read()
        # A distinctive marker the privileged field would produce in the persisted object.
        marker = f'"{self.field}":"{self.privileged_value}"'
        alt_marker = f'"{self.field}": "{self.privileged_value}"'   # tolerate a space after the colon
        return FindingContext.from_predicate(
            {"before": before, "after": after, "value": self.privileged_value,
             "m1": marker, "m2": alt_marker},
            {"all": [
                {"any": [
                    {"contains": [{"var": "after"}, {"var": "m1"}]},
                    {"contains": [{"var": "after"}, {"var": "m2"}]},
                ]},
                {"not": {"any": [
                    {"contains": [{"var": "before"}, {"var": "m1"}]},
                    {"contains": [{"var": "before"}, {"var": "m2"}]},
                ]}},
            ]},
            bug_class=self.bug_class,
        )

    def _read(self) -> str:
        resp = self.readback_send(self.readback_request)
        return str(resp.get("body", "")) if isinstance(resp, dict) else str(resp)


# ---------------------------------------------------------------------------
# config + the opt-in factory
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrossAccessSpec:
    """One two-identity cross-access probe: as the attacker, request the object/endpoint reference
    ``victim_ref`` at the point named ``ref_param``; confirm the attacker reached the privileged
    identity's PRIVATE content. ``bug_class`` labels the class (idor/bola/bfla/broken_access_control/
    authorization/privilege_escalation) — all confirmed by the same achieved-state cross-read.

    ``victim_discriminator`` is the per-identity marker that ONLY the victim's authoritative record
    contains — and it MUST be a REF-INDEPENDENT victim-PRIVATE token (a private email, an invoice number,
    an account secret), NOT the requested object id itself. A ref-derived value (the object id, or any
    substring of ``victim_ref``) is pure REFLECTION: a secured app that echoes the requested id in a 200
    soft-deny body would otherwise mint a false FACT with ZERO unauthorized read, so the check refuses a
    discriminator that is a substring of ``victim_ref``. It is what makes the confirmation SOUND: a fire
    requires the attacker's cross-read to reach THIS marker, never a whole-body containment that
    false-positives on shared boilerplate. Empty ⇒ the probe cannot soundly fire (a rigorous LEAD).
    ``control_ref`` is an attacker-OWNED reference and is MANDATORY for a FACT: the marker must be ABSENT
    from the attacker's own object — the negative control that PROVES a global/boilerplate string is not
    mistaken for a victim-unique one. That control read (like the victim and attacker cross-read) must be a
    SUBSTANTIVE SUCCESS (round-3): a 404/403/empty control makes the not-contains VACUOUS (absence-in-an-error
    proves nothing), so a non-substantive control fails closed to a LEAD. Empty ⇒ the probe returns None (a
    LEAD); 'victim-unique' is enforced by this SUBSTANTIVE control differential, never accepted as a bare
    operator assertion. A FACT further requires TWO same-ref negative baselines (both on ``AccessControlConfig``):
    a no-credential (logged-out) baseline (``nocred_send``: a valid gating proof — a substantive 2xx OR a genuine
    401/403 denial) AND — decisively (round-5, SAME-SHAPE) — a same-ref UNAUTHORIZED-AUTHENTICATED baseline
    (``unauth_send``: a THIRD attacker-controlled principal that also lacks access to victim_ref) that must be a
    SUBSTANTIVE SAME-SHAPE read — a 2xx that RENDERED the same object, the same class as the attacker's
    substantive cross-read (NOT a 401/403 denial) — and the marker must be ABSENT from BOTH. The
    unauthorized-authenticated baseline is what defeats the round-3 fourth-variant FP (a per-object reflected
    token echoed into an authenticated soft-deny is echoed by ANY same-shape read of the object, so it appears in
    that baseline too); a DENIAL there never renders the object, so a reflected token is absent from it VACUOUSLY —
    accepting a denial (as round-4 did) let a reflected slug mint a durable false FACT. Ref-independence is NOT
    the anti-reflection proof — the SAME-SHAPE 3-view differential (owner-present, attacker-present,
    peer-same-shape-absent) is. A config missing a baseline, OR whose unauthorized-authenticated baseline is a
    denial / not a substantive same-shape read, is a rigorous LEAD, never a FACT."""

    bug_class: str
    ref_param: str
    victim_ref: str
    victim_discriminator: str = ""
    control_ref: str = ""


@dataclass(frozen=True)
class AccessControlConfig:
    """What the operator MUST supply to seed the pack (there is no default that could be safe to run
    blind). ``victim_send`` is a ``Send`` authenticated as the *other* identity (the victim / a
    higher-privileged user) — the ground truth a cross-read is compared against. ``cross_specs`` name
    the object/endpoint references to probe; ``mass_assignment`` (optional) configures the field-
    injection probe."""

    victim_send: Send
    cross_specs: tuple[CrossAccessSpec, ...] = ()
    mass_assignment: MassAssignmentCheck | None = None
    # An id prefix so the seeded checks are traceable back to this pack in a report.
    id_prefix: str = "ac"
    # The no-credential (logged-out) baseline send — a request that carries NO identity. MANDATORY for a
    # cross-read FACT: the discriminator must be ABSENT from a logged-out GET of victim_ref, proving the
    # content is authorization-gated rather than public/reflected. None ⇒ the cross-read checks are seeded
    # baseline-less and can only ever produce a LEAD (never a FACT), fail-closed.
    nocred_send: Send | None = None
    # The same-ref UNAUTHORIZED-AUTHENTICATED baseline send (round-4, SAME-SHAPE round-5) — a request
    # authenticated as a THIRD, attacker-controlled identity that ALSO lacks access to victim_ref. MANDATORY for a
    # cross-read FACT and it must yield a SUBSTANTIVE SAME-SHAPE read (a 2xx that RENDERED the same object, NOT a
    # 401/403 denial): the discriminator must be ABSENT from this principal's same-shape read of victim_ref, the
    # DECISIVE anti-reflection proof that the datum is genuinely access-gated PRIVATE content (a per-object
    # reflected token is echoed by ANY same-shape read of the object, so it would appear here too; a denial never
    # renders the object, so its absent marker is vacuous). None, a denial, or a non-substantive read ⇒ the
    # cross-read checks DOWNGRADE to a LEAD (never a FACT), the enforced boundary.
    unauth_send: Send | None = None


def default_cross_specs(
    *, ref_param: str = "id", victim_ref: str = "", victim_discriminator: str = "", control_ref: str = "",
) -> tuple[CrossAccessSpec, ...]:
    """A ready-to-edit set covering the six cross-access classes on a single reference point — the
    operator overrides ``ref_param``/``victim_ref``/``victim_discriminator`` per target (and typically
    supplies distinct references per class). ``victim_ref`` / ``victim_discriminator`` default to empty;
    a blank reference or a blank discriminator cannot confirm anything (the predicate needs the victim's
    real per-identity marker), so this is a template, not an auto-runnable set."""
    return tuple(
        CrossAccessSpec(bug_class=bc, ref_param=ref_param, victim_ref=victim_ref,
                        victim_discriminator=victim_discriminator, control_ref=control_ref)
        for bc in ("idor", "bola", "bfla", "broken_access_control", "authorization", "privilege_escalation")
    )


def build_access_control_checks(
    config: AccessControlConfig | None, *, enabled: bool = False
) -> tuple[Check, ...]:
    """The OPT-IN seed. Returns ``()`` unless ``enabled=True`` AND ``config`` is populated — so the
    pack is default-OFF and gate-neutral (nothing enters the default check set or the library).

    When enabled, it builds one :class:`~scanner.checks.IdorCheck` per cross-access spec (all six
    cross classes share that two-identity achieved-state mechanism, differing only in the bug_class
    label) plus the :class:`MassAssignmentCheck` if configured. Every check confirms via the existing
    ACHIEVED-STATE oracle; a correctly-authorised endpoint fails the predicate and is never a finding."""
    if not enabled or config is None:
        return ()
    checks: list[Check] = []
    for i, spec in enumerate(config.cross_specs):
        checks.append(IdorCheck(
            id=f"{config.id_prefix}-{spec.bug_class}-{i}",
            ref_param=spec.ref_param,
            victim_ref=spec.victim_ref,
            victim_send=config.victim_send,
            bug_class=spec.bug_class,
            victim_discriminator=spec.victim_discriminator,
            control_ref=spec.control_ref,
            nocred_send=config.nocred_send,
            unauth_send=config.unauth_send,
        ))
    if config.mass_assignment is not None:
        checks.append(config.mass_assignment)
    return tuple(checks)


# ---------------------------------------------------------------------------
# operator CLI wiring — build a config from --ac-victim-header / --ac-ref
# ---------------------------------------------------------------------------
#
# The pack fundamentally needs OPERATOR input: a second authenticated identity (the
# victim / ground truth) and the object/endpoint references to cross-read. There is no
# safe autodiscovery for either. These helpers turn the small, honest CLI surface
# (`--ac-victim-header NAME: VALUE`, repeatable; `--ac-ref bug_class:ref_param:victim_ref`,
# repeatable) into an :class:`AccessControlConfig`, mirroring how ``IdorCheck`` is
# configured. They are TOTAL — a malformed argument is reported (via ``on_warn``) and
# skipped, never raised — and return ``None`` when no usable reference was supplied, so a
# bare ``--access-control`` is an explicit, documented no-op rather than a silent guess.


def _merge_victim_headers(
    base: list[tuple[str, str]], override: tuple[tuple[str, str], ...]
) -> list[tuple[str, str]]:
    """The victim identity's headers REPLACE any same-named header on the rendered
    request (case-insensitive) and append the rest — so a victim ``Cookie`` / ``Authorization``
    actually swaps the attacker's session rather than duplicating the header."""
    override_names = {k.lower() for k, _ in override}
    kept = [(k, v) for k, v in base if k.lower() not in override_names]
    return kept + list(override)


def victim_send_with_headers(base_send: Send, headers: tuple[tuple[str, str], ...]) -> Send:
    """Wrap ``base_send`` so every request it issues first carries the victim identity's
    headers — the same gated send, re-authenticated as the *other* user. With no headers it
    returns ``base_send`` unchanged (both identities are the same client — only meaningful
    when the object is genuinely public)."""
    if not headers:
        return base_send

    def _send(req: HttpRequest) -> dict:
        merged = req.model_copy(update={"headers": _merge_victim_headers(list(req.headers), headers)})
        return base_send(merged)

    return _send


# Header names that carry identity — stripped to build the no-credential (logged-out) baseline. The
# operator's own victim-header names are added on top (they are, by definition, the identity headers for
# THIS target), so the baseline is a genuine logged-out request regardless of the auth scheme used.
_AUTH_HEADER_NAMES: frozenset[str] = frozenset(
    {"cookie", "authorization", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"})


def nocred_send_stripping(base_send: Send, extra_names: tuple[str, ...] = ()) -> Send:
    """Wrap ``base_send`` so every request it issues has its IDENTITY headers REMOVED — the
    no-credential / logged-out baseline. Strips the common auth headers plus any ``extra_names`` (the
    operator's victim-header names, which are the identity headers for this target). This proves the
    cross-read content is authorization-gated: if the logged-out baseline still reaches the discriminator,
    the content is public/reflected and the achieved-read predicate correctly does NOT fire.

    Caveat: it can only strip headers present on the RENDERED request; a credential injected INSIDE
    ``base_send`` (a session that adds a cookie internally) is not visible here, so for such executors the
    operator should pass a genuinely credential-free base. The redrive runner uses the anonymous gated send
    directly as its baseline, so the signed-cert path does not rely on this stripping."""
    strip = _AUTH_HEADER_NAMES | {n.lower() for n in extra_names}

    def _send(req: HttpRequest) -> dict:
        kept = [(k, v) for k, v in list(req.headers) if k.lower() not in strip]
        return base_send(req.model_copy(update={"headers": kept}))

    return _send


def parse_victim_header(raw: str) -> tuple[str, str] | None:
    """Parse a ``Name: Value`` header. Returns None (caller warns) on a malformed value."""
    if ":" not in raw:
        return None
    name, _, value = raw.partition(":")
    name = name.strip()
    if not name:
        return None
    return (name, value.strip())


def parse_cross_spec(raw: str) -> CrossAccessSpec | None:
    """Parse ``bug_class:ref_param:victim_ref[|discriminator[|control_ref]]`` into a
    :class:`CrossAccessSpec`.

    The colon-delimited head is the original grammar (``bug_class:ref_param:victim_ref``); ``victim_ref``
    may itself contain colons (a URL / UUID) — only the first two colons split. The pipe-delimited tail
    carries the victim-UNIQUE discriminator (a per-identity marker only the victim's authoritative record
    contains) and the attacker-owned ``control_ref``. ``|`` is used (not another colon) so a colon-bearing
    ``victim_ref`` is never mistaken for the discriminator.

    A FACT requires BOTH the discriminator AND the ``control_ref`` (the mandatory negative control that
    proves the marker is victim-unique, not shared boilerplate). Backward-compatible parsing: a bare
    ``bug_class:ref_param:victim_ref`` (or one missing the ``control_ref``) still parses, but the probe then
    cannot soundly fire — it is a rigorous LEAD, the fail-closed behaviour that replaces the reverted
    whole-body false positive. Returns None (caller warns) when the class is not an access-control class or
    the head shape is wrong."""
    head, _, tail = raw.partition("|")
    parts = head.split(":", 2)
    if len(parts) != 3:
        return None
    bug_class, ref_param, victim_ref = (p.strip() for p in parts)
    if bug_class not in ACCESS_CONTROL_CLASSES or not ref_param:
        return None
    discriminator, control_ref = "", ""
    if tail:
        tparts = tail.split("|", 1)
        discriminator = tparts[0].strip()
        if len(tparts) == 2:
            control_ref = tparts[1].strip()
    return CrossAccessSpec(bug_class=bug_class, ref_param=ref_param, victim_ref=victim_ref,
                           victim_discriminator=discriminator, control_ref=control_ref)


def config_from_cli(
    base_send: Send,
    victim_headers: Iterable[str],
    refs: Iterable[str],
    *,
    unauth_headers: Iterable[str] = (),
    id_prefix: str = "ac",
    on_warn: Callable[[str], None] | None = None,
) -> AccessControlConfig | None:
    """Build an :class:`AccessControlConfig` from the operator's CLI arguments, wrapping
    ``base_send`` (the gated executor's send, or ``loopback_send``) as the victim identity via
    ``--ac-victim-header``. Returns ``None`` when no valid ``--ac-ref`` was supplied — the pack
    then seeds nothing, so ``--access-control`` alone is a documented no-op the caller can note.

    ``unauth_headers`` (``--ac-unauth-header``) bind a THIRD, attacker-controlled identity that also
    LACKS access to the victim's object — the round-4 same-ref UNAUTHORIZED-AUTHENTICATED baseline. It
    is what makes a cross-read FACT sound (the discriminator must be ABSENT from this principal's read
    of victim_ref, so a per-object reflected token echoed into an authenticated soft-deny cannot mint).
    Without it the seeded cross-read checks DOWNGRADE to a LEAD (never a FACT) — the enforced boundary.

    Every victim / unauth request rides the SAME gated ``base_send`` (each identity is authenticated by
    swapped headers, not by bypassing the safety stack), and confirmation stays with the achieved-state
    oracle — this tests the operator's OWN authorization, never a third party."""
    def _warn(msg: str) -> None:
        if on_warn is not None:
            on_warn(msg)

    specs: list[CrossAccessSpec] = []
    for raw in refs:
        spec = parse_cross_spec(raw)
        if spec is None:
            _warn(f"ignoring malformed --ac-ref {raw!r} "
                  f"(expected bug_class:ref_param:victim_ref, class one of {', '.join(ACCESS_CONTROL_CLASSES)})")
            continue
        specs.append(spec)
    if not specs:
        return None

    headers: list[tuple[str, str]] = []
    for raw in victim_headers:
        parsed = parse_victim_header(raw)
        if parsed is None:
            _warn(f"ignoring malformed --ac-victim-header {raw!r} (expected 'Name: Value')")
            continue
        headers.append(parsed)

    unauth_hdrs: list[tuple[str, str]] = []
    for raw in unauth_headers:
        parsed = parse_victim_header(raw)
        if parsed is None:
            _warn(f"ignoring malformed --ac-unauth-header {raw!r} (expected 'Name: Value')")
            continue
        unauth_hdrs.append(parsed)

    victim_send = victim_send_with_headers(base_send, tuple(headers))
    # The no-credential baseline strips the identity headers (the common auth headers plus the operator's
    # own victim-header names) so a cross-read FACT is minted only when a logged-out request is DENIED the
    # discriminator — proving the content is authorization-gated, not public/reflected.
    nocred_send = nocred_send_stripping(base_send, tuple(name for name, _ in headers))
    # The round-4 same-ref unauthorized-authenticated baseline: a THIRD identity's headers swapped onto the
    # SAME gated send. None when no --ac-unauth-header was supplied ⇒ the pack seeds LEAD-only checks.
    unauth_send = victim_send_with_headers(base_send, tuple(unauth_hdrs)) if unauth_hdrs else None
    return AccessControlConfig(victim_send=victim_send, cross_specs=tuple(specs),
                               nocred_send=nocred_send, unauth_send=unauth_send, id_prefix=id_prefix)


# ---------------------------------------------------------------------------
# finding builder — turn a confirmed cross-read / mass-assignment context into
# the finding dict the admission choke (oracle_adapter.certify_admitted) consumes
# ---------------------------------------------------------------------------


def access_control_finding(
    ctx: "FindingContext", *, check_id: str, insertion_point: str = ""
) -> dict:
    """Wrap a confirmed :class:`~verify.adapter.FindingContext` (from an :class:`IdorCheck` cross-read or a
    :class:`MassAssignmentCheck` state-change probe) into the finding dict the admission/minting choke reads
    — ``{check_id, bug_class, insertion_point, oracle_context}``. The retained ``oracle_context`` is the
    JSON-safe predicate + observed values, so the signed certificate re-verifies offline (the pure
    achieved-state predicate oracle re-fires over the retained evidence). The runner mints ONLY via
    ``oracle_adapter.certify_admitted(provenance="live_redrive")`` against the class's registered evidence
    branch — this helper never mints, it only shapes."""
    return {
        "check_id": check_id,
        "bug_class": ctx.bug_class,
        "insertion_point": insertion_point,
        "oracle_context": ctx.to_verifier_context(),
    }
