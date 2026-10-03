"""
Production security-event emission boundary.

This module deliberately contains no authorization logic.

Security decisions are made by the existing security controls. This
module accepts already-normalized SecurityEvent objects and delivers
them to an observability sink.

A telemetry sink can observe authority, but cannot create authority.
"""

from __future__ import annotations

import inspect
from enum import Enum
from typing import Any, Callable, Protocol, runtime_checkable

from app.security_observability import (
    SecurityEvent,
    SecurityEventValidationError,
)


class SecurityEventEmissionError(RuntimeError):
    """
    Raised when normalized security telemetry cannot be emitted.

    Emission failure does not alter the security decision represented
    by the event.
    """


@runtime_checkable
class SecurityEventSink(Protocol):
    """
    Destination for already-normalized SecurityEvent objects.
    """

    def emit(
        self,
        event: SecurityEvent,
    ) -> None:
        ...


class InMemorySecurityEventSink:
    """
    Deterministic in-memory sink for testing and evaluation.

    This is intentionally not the production persistence mechanism.
    """

    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []

    @property
    def events(self) -> tuple[SecurityEvent, ...]:
        return tuple(self._events)

    def emit(
        self,
        event: SecurityEvent,
    ) -> None:
        if not isinstance(event, SecurityEvent):
            raise SecurityEventValidationError(
                "Security event sink requires "
                "a SecurityEvent instance."
            )

        self._events.append(event)


class LegacyAuditInvocationMode(str, Enum):
    """
    Explicitly supported existing log_event(...) API shapes.
    """

    EVENT_TYPE_MAPPING = "event_type_mapping"

    EVENT_TYPE_KWARGS = "event_type_kwargs"

    EVENT_TYPE_KEYWORD_MAPPING = (
        "event_type_keyword_mapping"
    )


_LEGACY_DETAIL_PARAMETER_NAMES = frozenset(
    {
        "details",
        "data",
        "metadata",
        "payload",
    }
)


def detect_legacy_audit_invocation_mode(
    log_event_fn: Callable[..., Any],
) -> LegacyAuditInvocationMode:
    """
    Detect only explicitly supported log_event signatures.

    Unknown signatures fail closed instead of guessing.
    """

    if not callable(log_event_fn):
        raise SecurityEventEmissionError(
            "Legacy audit log_event target is not callable."
        )

    try:
        signature = inspect.signature(
            log_event_fn
        )
    except (TypeError, ValueError) as exc:
        raise SecurityEventEmissionError(
            "Unable to inspect legacy audit log_event "
            "signature."
        ) from exc

    parameters = list(
        signature.parameters.values()
    )

    positional = [
        parameter
        for parameter in parameters
        if parameter.kind
        in {
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }
    ]

    keyword_only = [
        parameter
        for parameter in parameters
        if parameter.kind
        is inspect.Parameter.KEYWORD_ONLY
    ]

    has_var_keyword = any(
        parameter.kind
        is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )

    has_var_positional = any(
        parameter.kind
        is inspect.Parameter.VAR_POSITIONAL
        for parameter in parameters
    )

    if has_var_positional:
        raise SecurityEventEmissionError(
            "Legacy audit log_event signatures using "
            "*args are not supported."
        )

    # Existing style:
    #
    #     log_event(event_type, **details)
    #
    if (
        len(positional) >= 1
        and has_var_keyword
    ):
        return (
            LegacyAuditInvocationMode
            .EVENT_TYPE_KWARGS
        )

    # Existing style:
    #
    #     log_event(event_type, details)
    #
    if len(positional) == 2:
        return (
            LegacyAuditInvocationMode
            .EVENT_TYPE_MAPPING
        )

    # Explicit keyword mapping style:
    #
    #     log_event(event_type, *, details=...)
    #
    if len(positional) == 1:
        matching = [
            parameter
            for parameter in keyword_only
            if parameter.name
            in _LEGACY_DETAIL_PARAMETER_NAMES
        ]

        if len(matching) == 1:
            return (
                LegacyAuditInvocationMode
                .EVENT_TYPE_KEYWORD_MAPPING
            )

    raise SecurityEventEmissionError(
        "Unsupported legacy audit log_event signature."
    )


class LegacyAuditSecurityEventSink:
    """
    Adapter from canonical SecurityEvent records to the existing
    app.audit.log_event(...) mechanism.

    The adapter never accepts arbitrary telemetry dictionaries.
    """

    def __init__(
        self,
        log_event_fn: Callable[..., Any],
    ) -> None:
        self._log_event_fn = log_event_fn

        self._invocation_mode = (
            detect_legacy_audit_invocation_mode(
                log_event_fn
            )
        )

        self._keyword_mapping_name = (
            self._resolve_keyword_mapping_name()
        )

    @property
    def invocation_mode(
        self,
    ) -> LegacyAuditInvocationMode:
        return self._invocation_mode

    def _resolve_keyword_mapping_name(
        self,
    ) -> str | None:
        if (
            self._invocation_mode
            is not LegacyAuditInvocationMode
            .EVENT_TYPE_KEYWORD_MAPPING
        ):
            return None

        signature = inspect.signature(
            self._log_event_fn
        )

        matching = [
            parameter.name
            for parameter
            in signature.parameters.values()
            if (
                parameter.kind
                is inspect.Parameter.KEYWORD_ONLY
                and parameter.name
                in _LEGACY_DETAIL_PARAMETER_NAMES
            )
        ]

        if len(matching) != 1:
            raise SecurityEventEmissionError(
                "Unable to resolve legacy audit "
                "keyword mapping parameter."
            )

        return matching[0]

    def emit(
        self,
        event: SecurityEvent,
    ) -> None:
        if not isinstance(event, SecurityEvent):
            raise SecurityEventValidationError(
                "Legacy audit adapter requires "
                "a SecurityEvent instance."
            )

        payload = event.to_dict()

        # The existing audit API receives event_type separately.
        # Keep one canonical value and avoid contradictory copies.
        details = {
            key: value
            for key, value in payload.items()
            if key != "event_type"
        }

        if (
            self._invocation_mode
            is LegacyAuditInvocationMode
            .EVENT_TYPE_MAPPING
        ):
            self._log_event_fn(
                event.event_type.value,
                details,
            )
            return

        if (
            self._invocation_mode
            is LegacyAuditInvocationMode
            .EVENT_TYPE_KWARGS
        ):
            self._log_event_fn(
                event.event_type.value,
                **details,
            )
            return

        if (
            self._invocation_mode
            is LegacyAuditInvocationMode
            .EVENT_TYPE_KEYWORD_MAPPING
        ):
            assert (
                self._keyword_mapping_name
                is not None
            )

            self._log_event_fn(
                event.event_type.value,
                **{
                    self._keyword_mapping_name:
                    details
                },
            )
            return

        raise SecurityEventEmissionError(
            "Unknown legacy audit invocation mode."
        )


def build_existing_audit_security_event_sink(
) -> LegacyAuditSecurityEventSink:
    """
    Adapt the repository's existing app.audit.log_event function.

    Import is local so simply importing this module does not configure
    or mutate audit behavior.
    """

    from app.audit import log_event

    return LegacyAuditSecurityEventSink(
        log_event
    )


class SecurityEventEmitter:
    """
    Small boundary responsible only for telemetry delivery.

    The emitter does not own or derive authorization state.
    """

    def __init__(
        self,
        sink: SecurityEventSink,
    ) -> None:
        if not isinstance(
            sink,
            SecurityEventSink,
        ):
            raise SecurityEventEmissionError(
                "Security event sink does not implement "
                "the required emit(event) interface."
            )

        self._sink = sink

    @property
    def sink(self) -> SecurityEventSink:
        return self._sink

    def emit(
        self,
        event: SecurityEvent,
    ) -> None:
        if not isinstance(event, SecurityEvent):
            raise SecurityEventValidationError(
                "SecurityEventEmitter requires "
                "a SecurityEvent instance."
            )

        sink_failed = False

        try:
            self._sink.emit(event)

        except SecurityEventValidationError:
            raise

        except Exception:
            # Do not include raw sink exception text because downstream
            # sink failures may themselves contain sensitive provider
            # or transport details.
            sink_failed = True

        if sink_failed:
            raise SecurityEventEmissionError(
                "Security event emission failed via "
                f"{type(self._sink).__name__}."
            ) from None


def emit_security_event(
    event: SecurityEvent,
    *,
    sink: SecurityEventSink,
) -> None:
    """
    Convenience entrypoint without global mutable sink configuration.
    """

    SecurityEventEmitter(
        sink
    ).emit(
        event
    )
