from __future__ import annotations

import logging

import pytest

import app.security_observability_integrations as integrations
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


def _event(
    *,
    outcome: SecurityOutcome,
    reason_code: SecurityReasonCode | None = None,
    with_high_cardinality: bool = False,
) -> SecurityEvent:

    kwargs = {}


    if with_high_cardinality:

        kwargs.update(
            {
                "request_id":
                    "REQ-DO-NOT-LABEL",
                "principal_ref":
                    "PRINCIPAL-DO-NOT-LABEL",
                "tenant_id":
                    "tenant-do-not-label",
                "session_ref":
                    "SESSION-DO-NOT-LABEL",
                "workflow_id":
                    "WF-DO-NOT-LABEL",
                "execution_attempt_ref":
                    (
                        "EA1-"
                        + (
                            "a"
                            * 64
                        )
                    ),
                "provider_correlation_id":
                    (
                        "VMAI-"
                        + (
                            "b"
                            * 64
                        )
                    ),
            }
        )


    return SecurityEvent(
        event_type=(
            SecurityEventType
            .MCP_TOOL_INVOCATION_DENIED
        ),
        severity=(
            SecuritySeverity.HIGH
        ),
        outcome=
            outcome,
        source_component=(
            SecuritySourceComponent
            .TOOL_DISPATCHER
        ),
        reason_code=
            reason_code,
        **kwargs,
    )


def _install_observers(
    monkeypatch: pytest.MonkeyPatch,
):
    audit_sink = (
        InMemorySecurityEventSink()
    )

    metrics_registry = (
        SecurityMetricsRegistry()
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
            metrics_registry,
    )


    return (
        audit_sink,
        metrics_registry,
    )


def _metric_values(
    registry: SecurityMetricsRegistry,
) -> dict[
    SecurityMetricName,
    int,
]:
    values = {}


    for sample in registry.snapshot():

        values[
            sample.name
        ] = (
            values.get(
                sample.name,
                0,
            )
            + sample.value
        )


    return values


def test_allowed_event_is_audited_and_counted_once(
    monkeypatch: pytest.MonkeyPatch,
):
    audit_sink, registry = (
        _install_observers(
            monkeypatch
        )
    )


    event = _event(
        outcome=
            SecurityOutcome.ALLOWED,
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


    values = (
        _metric_values(
            registry
        )
    )


    assert (
        values[
            SecurityMetricName
            .SECURITY_EVENTS_TOTAL
        ]
        == 1
    )

    assert (
        SecurityMetricName
        .SECURITY_DENIALS_TOTAL
        not in values
    )

    assert (
        SecurityMetricName
        .SECURITY_REVIEW_REQUIRED_TOTAL
        not in values
    )


def test_denied_event_increments_general_and_denial_once(
    monkeypatch: pytest.MonkeyPatch,
):
    audit_sink, registry = (
        _install_observers(
            monkeypatch
        )
    )


    event = _event(
        outcome=
            SecurityOutcome.DENIED,
        reason_code=(
            SecurityReasonCode
            .TOOL_NOT_AUTHORIZED
        ),
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


    values = (
        _metric_values(
            registry
        )
    )


    assert (
        values[
            SecurityMetricName
            .SECURITY_EVENTS_TOTAL
        ]
        == 1
    )

    assert (
        values[
            SecurityMetricName
            .SECURITY_DENIALS_TOTAL
        ]
        == 1
    )

    assert (
        SecurityMetricName
        .SECURITY_REVIEW_REQUIRED_TOTAL
        not in values
    )


def test_review_required_event_increments_general_and_review_once(
    monkeypatch: pytest.MonkeyPatch,
):
    audit_sink, registry = (
        _install_observers(
            monkeypatch
        )
    )


    event = _event(
        outcome=(
            SecurityOutcome
            .REVIEW_REQUIRED
        ),
        reason_code=(
            SecurityReasonCode
            .NEEDS_REVIEW
        ),
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


    values = (
        _metric_values(
            registry
        )
    )


    assert (
        values[
            SecurityMetricName
            .SECURITY_EVENTS_TOTAL
        ]
        == 1
    )

    assert (
        values[
            SecurityMetricName
            .SECURITY_REVIEW_REQUIRED_TOTAL
        ]
        == 1
    )

    assert (
        SecurityMetricName
        .SECURITY_DENIALS_TOTAL
        not in values
    )


def test_metrics_failure_does_not_suppress_audit_or_change_true_result(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    audit_sink = (
        InMemorySecurityEventSink()
    )


    class FailingMetricsRegistry:

        def observe(
            self,
            event,
        ) -> None:
            raise RuntimeError(
                "access_token=METRICS-SECRET"
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
            FailingMetricsRegistry(),
    )


    caplog.set_level(
        logging.ERROR
    )


    event = _event(
        outcome=
            SecurityOutcome.ALLOWED,
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
        "Canonical security metrics observation failed"
        in caplog.text
    )

    assert (
        "RuntimeError"
        in caplog.text
    )

    assert (
        "METRICS-SECRET"
        not in caplog.text
    )

    assert (
        "access_token"
        not in caplog.text
    )


def test_audit_failure_still_attempts_metrics_and_preserves_false_result(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    registry = (
        SecurityMetricsRegistry()
    )


    def fail_audit():
        raise RuntimeError(
            "password=AUDIT-SECRET"
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
            registry,
    )


    caplog.set_level(
        logging.ERROR
    )


    event = _event(
        outcome=
            SecurityOutcome.DENIED,
        reason_code=(
            SecurityReasonCode
            .TOOL_NOT_AUTHORIZED
        ),
    )


    result = (
        integrations
        ._emit_best_effort(
            event
        )
    )


    assert result is False


    values = (
        _metric_values(
            registry
        )
    )


    assert (
        values[
            SecurityMetricName
            .SECURITY_EVENTS_TOTAL
        ]
        == 1
    )

    assert (
        values[
            SecurityMetricName
            .SECURITY_DENIALS_TOTAL
        ]
        == 1
    )

    assert (
        "existing security decision preserved"
        in caplog.text
    )

    assert (
        "AUDIT-SECRET"
        not in caplog.text
    )

    assert (
        "password"
        not in caplog.text
    )


def test_both_observers_can_fail_without_exception_escape(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    class FailingMetricsRegistry:

        def observe(
            self,
            event,
        ) -> None:
            raise RuntimeError(
                "token=METRICS-SECRET"
            )


    def fail_audit():
        raise RuntimeError(
            "secret=AUDIT-SECRET"
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
            FailingMetricsRegistry(),
    )


    caplog.set_level(
        logging.ERROR
    )


    result = (
        integrations
        ._emit_best_effort(
            _event(
                outcome=
                    SecurityOutcome.DENIED,
                reason_code=(
                    SecurityReasonCode
                    .TOOL_NOT_AUTHORIZED
                ),
            )
        )
    )


    assert result is False

    assert (
        "AUDIT-SECRET"
        not in caplog.text
    )

    assert (
        "METRICS-SECRET"
        not in caplog.text
    )

    assert (
        "secret="
        not in caplog.text
    )

    assert (
        "token="
        not in caplog.text
    )


def test_integrated_metrics_never_label_correlation_identifiers(
    monkeypatch: pytest.MonkeyPatch,
):
    _, registry = (
        _install_observers(
            monkeypatch
        )
    )


    assert (
        integrations
        ._emit_best_effort(
            _event(
                outcome=
                    SecurityOutcome.DENIED,
                reason_code=(
                    SecurityReasonCode
                    .TOOL_NOT_AUTHORIZED
                ),
                with_high_cardinality=True,
            )
        )
        is True
    )


    forbidden_values = {
        "REQ-DO-NOT-LABEL",
        "PRINCIPAL-DO-NOT-LABEL",
        "tenant-do-not-label",
        "SESSION-DO-NOT-LABEL",
        "WF-DO-NOT-LABEL",
    }


    for sample in registry.snapshot():

        label_values = {
            value
            for (
                _,
                value,
            ) in sample.labels
        }


        assert not (
            label_values
            & forbidden_values
        )


def test_one_emit_call_observes_metrics_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
):
    audit_sink, registry = (
        _install_observers(
            monkeypatch
        )
    )


    event = _event(
        outcome=
            SecurityOutcome.ALLOWED,
    )


    assert (
        integrations
        ._emit_best_effort(
            event
        )
        is True
    )


    assert len(
        audit_sink.events
    ) == 1


    general_samples = [
        sample
        for sample
        in registry.snapshot()
        if (
            sample.name
            == SecurityMetricName
            .SECURITY_EVENTS_TOTAL
        )
    ]


    assert len(
        general_samples
    ) == 1

    assert (
        general_samples[
            0
        ].value
        == 1
    )
