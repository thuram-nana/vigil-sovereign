"""
defender.telemetry — model the telemetry an action emits.

A deterministic map from an `ActionDescriptor` to the `ActionSignal`s it
would write across telemetry channels. This is the "what would I trip"
half of self-awareness — pure modelling, no traffic, no mutation.

The model is intentionally conservative and legible: it encodes the
common, well-understood signals (an access-log line, a WAF event on a
payload, an auth-log failure series, a netflow fan-out). It is not a
fidelity simulation of a specific SIEM. Operators tune it per
environment by supplying their own rules (rules.py) rather than by
hiding signals here.
"""

from __future__ import annotations

from .models import ActionDescriptor, ActionKind, ActionSignal


def _int_attr(descriptor: ActionDescriptor, key: str, default: int) -> int:
    raw = descriptor.attributes.get(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _http_access(descriptor: ActionDescriptor, status: int) -> ActionSignal:
    return ActionSignal(
        channel="http_access_log",
        fields={
            "method": descriptor.method,
            "path": descriptor.target_surface,
            "user_agent": descriptor.user_agent,
            "status": status,
            "requests": descriptor.requests,
        },
        note="request reaches the web/access tier and is logged",
    )


def _http_request(descriptor: ActionDescriptor) -> list[ActionSignal]:
    return [_http_access(descriptor, _int_attr(descriptor, "status", 200))]


def _login_attempt(descriptor: ActionDescriptor) -> list[ActionSignal]:
    failed = _int_attr(descriptor, "failed_count", max(descriptor.requests - 1, 0))
    return [
        _http_access(descriptor, _int_attr(descriptor, "status", 401)),
        ActionSignal(
            channel="auth_log",
            fields={
                "outcome": descriptor.attributes.get("outcome", "failure"),
                "failed_count": failed,
                "user": descriptor.attributes.get("user", "unknown"),
            },
            note="authentication subsystem records the attempt",
        ),
    ]


def _injection_probe(descriptor: ActionDescriptor) -> list[ActionSignal]:
    inj_class = descriptor.attributes.get("inj_class", "sql_injection")
    marker = descriptor.attributes.get("payload_marker", "' OR 1=1 --")
    return [
        _http_access(descriptor, _int_attr(descriptor, "status", 200)),
        ActionSignal(
            channel="waf",
            fields={
                "category": inj_class,
                "payload_marker": marker,
                "path": descriptor.target_surface,
            },
            note="payload pattern is the kind of thing a WAF/IDS signature targets",
        ),
    ]


def _directory_bruteforce(descriptor: ActionDescriptor) -> list[ActionSignal]:
    distinct = _int_attr(descriptor, "distinct_paths", descriptor.requests)
    return [
        ActionSignal(
            channel="http_access_log",
            fields={
                "method": descriptor.method,
                "status": 404,
                "distinct_404": distinct,
                "user_agent": descriptor.user_agent,
                "requests": descriptor.requests,
            },
            note="a burst of distinct 404s is a classic scan signature",
        )
    ]


def _port_scan(descriptor: ActionDescriptor) -> list[ActionSignal]:
    ports = _int_attr(descriptor, "distinct_ports", descriptor.requests)
    return [
        ActionSignal(
            channel="netflow",
            fields={
                "distinct_ports": ports,
                "connection_type": descriptor.attributes.get("connection_type", "syn"),
            },
            note="connection fan-out across many ports shows in flow records",
        )
    ]


def _generic(descriptor: ActionDescriptor) -> list[ActionSignal]:
    return [_http_access(descriptor, _int_attr(descriptor, "status", 200))]


class TelemetryModel:
    """Maps action kinds to their signal builders. Operators can register
    additional kinds without editing this module."""

    def __init__(self) -> None:
        self._builders = {
            ActionKind.HTTP_REQUEST: _http_request,
            ActionKind.LOGIN_ATTEMPT: _login_attempt,
            ActionKind.INJECTION_PROBE: _injection_probe,
            ActionKind.DIRECTORY_BRUTEFORCE: _directory_bruteforce,
            ActionKind.PORT_SCAN: _port_scan,
            ActionKind.GENERIC: _generic,
        }

    def emit(self, descriptor: ActionDescriptor) -> list[ActionSignal]:
        builder = self._builders.get(descriptor.kind, _generic)
        return builder(descriptor)


_DEFAULT_MODEL = TelemetryModel()


def model_telemetry(descriptor: ActionDescriptor) -> list[ActionSignal]:
    """Signals the default telemetry model attributes to this action."""
    return _DEFAULT_MODEL.emit(descriptor)
