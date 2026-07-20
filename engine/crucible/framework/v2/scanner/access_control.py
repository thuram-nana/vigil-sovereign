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
    predicate and does NOT fire, so a correctly-authorised endpoint is never a false positive.

PROVE-DON'T-GUESS: the oracle decides over the RAW two-identity evidence (the attacker's status+body
vs. the victim/ground-truth body). The check never asserts the finding itself. The mere presence of a
numeric id or an admin route is a LEAD, never a fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

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

    ``readback_send`` + ``readback_request`` are how the object is re-fetched (typically the ground-
    truth / owner view). Runs only on the point named ``field``; other points return None."""

    id: str
    field: str
    privileged_value: str
    readback_send: Send
    readback_request: HttpRequest
    bug_class: str = "mass_assignment"

    def probe(self, template: RequestTemplate, point: InsertionPoint, send: Send) -> FindingContext | None:
        if point.name != self.field:
            return None
        before = self._read()
        send(template.render(point, self.privileged_value))   # the mass-assignment attempt
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
    identity's content. ``bug_class`` labels the class (idor/bola/bfla/broken_access_control/
    authorization/privilege_escalation) — all confirmed by the same achieved-state cross-read."""

    bug_class: str
    ref_param: str
    victim_ref: str


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


def default_cross_specs(*, ref_param: str = "id", victim_ref: str = "") -> tuple[CrossAccessSpec, ...]:
    """A ready-to-edit set covering the six cross-access classes on a single reference point — the
    operator overrides ``ref_param``/``victim_ref`` per target (and typically supplies distinct
    references per class). ``victim_ref`` defaults to empty; a blank reference cannot confirm anything
    (the predicate needs the victim's real content), so this is a template, not an auto-runnable set."""
    return tuple(
        CrossAccessSpec(bug_class=bc, ref_param=ref_param, victim_ref=victim_ref)
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
    """Parse ``bug_class:ref_param:victim_ref`` into a :class:`CrossAccessSpec`. ``victim_ref``
    may itself contain colons (a URL / UUID) — only the first two delimiters split. Returns None
    (caller warns) when the class is not an access-control class or the shape is wrong."""
    parts = raw.split(":", 2)
    if len(parts) != 3:
        return None
    bug_class, ref_param, victim_ref = (p.strip() for p in parts)
    if bug_class not in ACCESS_CONTROL_CLASSES or not ref_param:
        return None
    return CrossAccessSpec(bug_class=bug_class, ref_param=ref_param, victim_ref=victim_ref)


def config_from_cli(
    base_send: Send,
    victim_headers: Iterable[str],
    refs: Iterable[str],
    *,
    id_prefix: str = "ac",
    on_warn: Callable[[str], None] | None = None,
) -> AccessControlConfig | None:
    """Build an :class:`AccessControlConfig` from the operator's CLI arguments, wrapping
    ``base_send`` (the gated executor's send, or ``loopback_send``) as the victim identity via
    ``--ac-victim-header``. Returns ``None`` when no valid ``--ac-ref`` was supplied — the pack
    then seeds nothing, so ``--access-control`` alone is a documented no-op the caller can note.

    Every victim request rides the SAME gated ``base_send`` (the second identity is authenticated
    by swapped headers, not by bypassing the safety stack), and confirmation stays with the
    achieved-state oracle — this tests the operator's OWN authorization, never a third party."""
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

    victim_send = victim_send_with_headers(base_send, tuple(headers))
    return AccessControlConfig(victim_send=victim_send, cross_specs=tuple(specs), id_prefix=id_prefix)
