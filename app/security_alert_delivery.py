"""
Framework-independent delivery boundary for canonical SecurityAlert data.

Alert storage/delivery is observability state only.

It is not authentication, authorization, tenant, session, workflow,
execution-attempt, or provider authority.
"""

from __future__ import annotations

from threading import Lock
from typing import Protocol

from app.security_detection import SecurityAlert


class SecurityAlertDeliveryError(RuntimeError):
    """
    Raised when an alert sink receives an invalid alert object.

    Delivery failures remain observational failures and cannot alter
    security authority.
    """


class SecurityAlertSink(Protocol):
    """
    Minimal structured alert-delivery protocol.
    """

    def emit(
        self,
        alert: SecurityAlert,
    ) -> None:
        ...


class InMemorySecurityAlertSink:
    """
    Thread-safe process-local structured alert sink.

    The immutable tuple returned by `alerts` prevents callers from
    mutating internal alert collection state.
    """

    def __init__(
        self,
    ) -> None:

        self._alerts: list[
            SecurityAlert
        ] = []

        self._lock = Lock()


    def emit(
        self,
        alert: SecurityAlert,
    ) -> None:

        if not isinstance(
            alert,
            SecurityAlert,
        ):
            raise SecurityAlertDeliveryError(
                "Security alert sink requires "
                "a SecurityAlert instance."
            )


        with self._lock:

            self._alerts.append(
                alert
            )


    @property
    def alerts(
        self,
    ) -> tuple[
        SecurityAlert,
        ...,
    ]:

        with self._lock:

            return tuple(
                self._alerts
            )


# Process-local alert collection.
#
# This is structured observability state only and must never be consulted
# to authorize or deny application behavior.
_PROCESS_SECURITY_ALERT_SINK = (
    InMemorySecurityAlertSink()
)


def get_process_security_alert_sink(
) -> InMemorySecurityAlertSink:
    """
    Return the process-local structured security-alert sink.
    """

    return (
        _PROCESS_SECURITY_ALERT_SINK
    )


def _reset_process_security_alert_sink_for_tests(
) -> InMemorySecurityAlertSink:
    """
    Replace process-local alert state for isolated tests.

    This private helper modifies observability state only.
    """

    global _PROCESS_SECURITY_ALERT_SINK

    _PROCESS_SECURITY_ALERT_SINK = (
        InMemorySecurityAlertSink()
    )

    return (
        _PROCESS_SECURITY_ALERT_SINK
    )
