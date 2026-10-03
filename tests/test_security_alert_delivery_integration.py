from __future__ import annotations

import logging

import pytest

import app.security_observability_integrations as integrations
from app.security_alert_delivery import (
    InMemorySecurityAlertSink,
    SecurityAlertDeliveryError,
    _reset_process_security_alert_sink_for_tests,
    get_process_security_alert_sink,
)
from app.security_detection import (
    SecurityAlert,
    SecurityAlertType,
    SecurityDetectionRuleId,
)
from app.security_event_emitter import (
    InMemorySecurityEventSink,
)
from app.security_metrics import (
    SecurityMetricName,
    SecurityMetricsRegistry,
)
from app.security_observability import (
    SecurityEvent,
    SecurityEventType,
    SecurityOutcome,
    SecurityReasonCode,
    SecuritySeverity,
    SecuritySourceComponent,
)


def _matching_event() -> SecurityEvent:

    return SecurityEvent(
        event_type=(
            SecurityEventType
            .MCP_TOOL_INVOCATION_DENIED
        ),
        severity=(
            SecuritySeverity.HIGH
        ),
        outcome=(
            SecurityOutcome.DENIED
        ),
        source_component=(
            SecuritySourceComponent
            .TOOL_DISPATCHER
        ),
        tenant_id=
            "tenant-alert-context",
        workflow_id=
            "WF-ALERT-CONTEXT",
        reason_code=(
            SecurityReasonCode
            .TOOL_NOT_AUTHORIZED
        ),
    )


def _nonmatching_event() -> SecurityEvent:

    return SecurityEvent(
        event_type=(
            SecurityEventType
            .MCP_TOOL_INVOCATION_ALLOWED
        ),
        severity=(
            SecuritySeverity.INFO
        ),
        outcome=(
            SecurityOutcome.ALLOWED
        ),
        source_component=(
            SecuritySourceComponent
            .TOOL_DISPATCHER
        ),
    )


def _install_observers(
    monkeypatch: pytest.MonkeyPatch,
):
    audit_sink = (
        InMemorySecurityEventSink()
    )

    metrics = (
        SecurityMetricsRegistry()
    )

    alerts = (
        InMemorySecurityAlertSink()
    )


    monkeypatch.setattr(
        integrations,
        "build_existing_audit_security_event_sink",
        lambda:
            audit_sink,
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_metrics_registry",
        lambda:
            metrics,
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_alert_sink",
        lambda:
            alerts,
    )


    return (
        audit_sink,
        metrics,
        alerts,
    )


def _general_metric_count(
    registry: SecurityMetricsRegistry,
) -> int:

    return sum(
        sample.value
        for sample
        in registry.snapshot()
        if (
            sample.name
            == SecurityMetricName
            .SECURITY_EVENTS_TOTAL
        )
    )


def test_alert_sink_records_exact_immutable_alert():
    sink = (
        InMemorySecurityAlertSink()
    )


    event = (
        _matching_event()
    )


    alert = (
        integrations
        .evaluate_security_event(
            event
        )
    )


    assert isinstance(
        alert,
        SecurityAlert,
    )


    sink.emit(
        alert
    )


    assert (
        sink.alerts
        == (
            alert,
        )
    )

    assert isinstance(
        sink.alerts,
        tuple,
    )


def test_alert_sink_rejects_non_alert():
    sink = (
        InMemorySecurityAlertSink()
    )


    with pytest.raises(
        SecurityAlertDeliveryError
    ):

        sink.emit(
            object()
        )


def test_process_alert_sink_getter_and_test_reset_are_explicit():
    first = (
        _reset_process_security_alert_sink_for_tests()
    )

    assert (
        get_process_security_alert_sink()
        is first
    )


    second = (
        _reset_process_security_alert_sink_for_tests()
    )

    assert (
        second
        is not first
    )

    assert (
        get_process_security_alert_sink()
        is second
    )

    assert (
        second.alerts
        == ()
    )


def test_matching_event_reaches_audit_metrics_detection_and_alert(
    monkeypatch: pytest.MonkeyPatch,
):
    (
        audit_sink,
        metrics,
        alerts,
    ) = _install_observers(
        monkeypatch
    )


    event = (
        _matching_event()
    )


    assert (
        integrations
        ._emit_best_effort(
            event
        )
        is True
    )


    assert (
        audit_sink.events
        == (
            event,
        )
    )

    assert (
        _general_metric_count(
            metrics
        )
        == 1
    )

    assert len(
        alerts.alerts
    ) == 1


    alert = (
        alerts.alerts[
            0
        ]
    )


    assert (
        alert.rule_id
        is (
            SecurityDetectionRuleId
            .UNAUTHORIZED_MCP_TOOL
        )
    )

    assert (
        alert.alert_type
        is (
            SecurityAlertType
            .UNAUTHORIZED_MCP_TOOL
        )
    )

    assert (
        alert.source_event_id
        == event.event_id
    )

    assert (
        alert.tenant_id
        == event.tenant_id
    )

    assert (
        alert.workflow_id
        == event.workflow_id
    )


def test_nonmatching_event_produces_no_alert(
    monkeypatch: pytest.MonkeyPatch,
):
    (
        audit_sink,
        metrics,
        alerts,
    ) = _install_observers(
        monkeypatch
    )


    event = (
        _nonmatching_event()
    )


    assert (
        integrations
        ._emit_best_effort(
            event
        )
        is True
    )


    assert (
        audit_sink.events
        == (
            event,
        )
    )

    assert (
        _general_metric_count(
            metrics
        )
        == 1
    )

    assert (
        alerts.alerts
        == ()
    )


def test_detection_failure_preserves_audit_metrics_and_return_value(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    (
        audit_sink,
        metrics,
        alerts,
    ) = _install_observers(
        monkeypatch
    )


    def fail_detection(
        event,
    ):
        raise RuntimeError(
            "token=DETECTION-SECRET"
        )


    monkeypatch.setattr(
        integrations,
        "evaluate_security_event",
        fail_detection,
    )


    caplog.set_level(
        logging.ERROR
    )


    event = (
        _matching_event()
    )


    result = (
        integrations
        ._emit_best_effort(
            event
        )
    )


    assert result is True

    assert (
        audit_sink.events
        == (
            event,
        )
    )

    assert (
        _general_metric_count(
            metrics
        )
        == 1
    )

    assert (
        alerts.alerts
        == ()
    )

    assert (
        "Canonical security detection evaluation failed"
        in caplog.text
    )

    assert (
        "RuntimeError"
        in caplog.text
    )

    assert (
        "DETECTION-SECRET"
        not in caplog.text
    )

    assert (
        "token="
        not in caplog.text
    )


def test_alert_delivery_failure_preserves_audit_metrics_and_true_result(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    audit_sink = (
        InMemorySecurityEventSink()
    )

    metrics = (
        SecurityMetricsRegistry()
    )


    class FailingAlertSink:

        def emit(
            self,
            alert,
        ) -> None:

            raise RuntimeError(
                "password=ALERT-SECRET"
            )


    monkeypatch.setattr(
        integrations,
        "build_existing_audit_security_event_sink",
        lambda:
            audit_sink,
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_metrics_registry",
        lambda:
            metrics,
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_alert_sink",
        lambda:
            FailingAlertSink(),
    )


    caplog.set_level(
        logging.ERROR
    )


    event = (
        _matching_event()
    )


    result = (
        integrations
        ._emit_best_effort(
            event
        )
    )


    assert result is True

    assert (
        audit_sink.events
        == (
            event,
        )
    )

    assert (
        _general_metric_count(
            metrics
        )
        == 1
    )

    assert (
        "Canonical security alert delivery failed"
        in caplog.text
    )

    assert (
        "RuntimeError"
        in caplog.text
    )

    assert (
        "ALERT-SECRET"
        not in caplog.text
    )

    assert (
        "password="
        not in caplog.text
    )


def test_audit_failure_still_allows_metrics_detection_and_alert(
    monkeypatch: pytest.MonkeyPatch,
):
    metrics = (
        SecurityMetricsRegistry()
    )

    alerts = (
        InMemorySecurityAlertSink()
    )


    def fail_audit():
        raise RuntimeError(
            "audit-secret"
        )


    monkeypatch.setattr(
        integrations,
        "build_existing_audit_security_event_sink",
        fail_audit,
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_metrics_registry",
        lambda:
            metrics,
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_alert_sink",
        lambda:
            alerts,
    )


    assert (
        integrations
        ._emit_best_effort(
            _matching_event()
        )
        is False
    )


    assert (
        _general_metric_count(
            metrics
        )
        == 1
    )

    assert len(
        alerts.alerts
    ) == 1


def test_metrics_failure_still_allows_detection_and_alert(
    monkeypatch: pytest.MonkeyPatch,
):
    audit_sink = (
        InMemorySecurityEventSink()
    )

    alerts = (
        InMemorySecurityAlertSink()
    )


    class FailingMetrics:

        def observe(
            self,
            event,
        ) -> None:

            raise RuntimeError(
                "metrics-secret"
            )


    monkeypatch.setattr(
        integrations,
        "build_existing_audit_security_event_sink",
        lambda:
            audit_sink,
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_metrics_registry",
        lambda:
            FailingMetrics(),
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_alert_sink",
        lambda:
            alerts,
    )


    event = (
        _matching_event()
    )


    assert (
        integrations
        ._emit_best_effort(
            event
        )
        is True
    )


    assert (
        audit_sink.events
        == (
            event,
        )
    )

    assert len(
        alerts.alerts
    ) == 1


def test_observer_order_is_audit_metrics_detection_alert(
    monkeypatch: pytest.MonkeyPatch,
):
    order = []


    class AuditSink:

        def emit(
            self,
            event,
        ) -> None:

            order.append(
                "audit"
            )


    class Metrics:

        def observe(
            self,
            event,
        ) -> None:

            order.append(
                "metrics"
            )


    class Alerts:

        def emit(
            self,
            alert,
        ) -> None:

            order.append(
                "alert"
            )


    original_evaluate = (
        integrations
        .evaluate_security_event
    )


    def evaluate(
        event,
    ):
        order.append(
            "detection"
        )

        return original_evaluate(
            event
        )


    monkeypatch.setattr(
        integrations,
        "build_existing_audit_security_event_sink",
        lambda:
            AuditSink(),
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_metrics_registry",
        lambda:
            Metrics(),
    )

    monkeypatch.setattr(
        integrations,
        "evaluate_security_event",
        evaluate,
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_alert_sink",
        lambda:
            Alerts(),
    )


    assert (
        integrations
        ._emit_best_effort(
            _matching_event()
        )
        is True
    )


    assert order == [
        "audit",
        "metrics",
        "detection",
        "alert",
    ]


def test_alert_delivery_does_not_add_raw_sensitive_fields(
    monkeypatch: pytest.MonkeyPatch,
):
    (
        _,
        _,
        alerts,
    ) = _install_observers(
        monkeypatch
    )


    assert (
        integrations
        ._emit_best_effort(
            _matching_event()
        )
        is True
    )


    assert len(
        alerts.alerts
    ) == 1


    payload = (
        alerts.alerts[
            0
        ].to_dict()
    )


    for forbidden in (
        "access_token",
        "refresh_token",
        "id_token",
        "password",
        "client_secret",
        "prompt",
        "rag_content",
        "tool_output",
        "provider_response",
        "exception",
        "exception_text",
        "ticket_id",
        "sys_id",
    ):

        assert (
            forbidden
            not in payload
        )
