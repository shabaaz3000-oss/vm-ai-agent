from __future__ import annotations

from types import MappingProxyType

import pytest

from app.security_metrics import (
    NO_REASON_LABEL,
    PROHIBITED_SECURITY_METRIC_LABELS,
    SECURITY_METRIC_LABEL_SCHEMA,
    SecurityMetricName,
    SecurityMetricsRegistry,
    SecurityMetricValidationError,
    security_metric_series_bounds,
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
    outcome: str,
    reason_code: str | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_type=(
            SecurityEventType
            .MCP_TOOL_INVOCATION_DENIED
        ),
        severity=(
            SecuritySeverity.HIGH
        ),
        outcome=(
            SecurityOutcome(
                outcome
            )
        ),
        source_component=(
            SecuritySourceComponent
            .TOOL_DISPATCHER
        ),
        reason_code=(
            SecurityReasonCode(
                reason_code
            )
            if reason_code
            is not None
            else None
        ),
    )


def _samples_by_name(
    registry: SecurityMetricsRegistry,
) -> dict[
    SecurityMetricName,
    list,
]:
    result = {}


    for sample in registry.snapshot():

        result.setdefault(
            sample.name,
            [],
        ).append(
            sample
        )


    return result


def test_metric_label_schema_is_read_only_and_bounded():
    assert isinstance(
        SECURITY_METRIC_LABEL_SCHEMA,
        MappingProxyType,
    )

    assert (
        set(
            SECURITY_METRIC_LABEL_SCHEMA
        )
        == {
            SecurityMetricName
            .SECURITY_EVENTS_TOTAL,

            SecurityMetricName
            .SECURITY_DENIALS_TOTAL,

            SecurityMetricName
            .SECURITY_REVIEW_REQUIRED_TOTAL,
        }
    )


    for labels in (
        SECURITY_METRIC_LABEL_SCHEMA
        .values()
    ):

        assert not (
            set(
                labels
            )
            & PROHIBITED_SECURITY_METRIC_LABELS
        )


def test_security_events_total_counts_every_canonical_event():
    registry = (
        SecurityMetricsRegistry()
    )


    allowed = _event(
        outcome="allowed",
    )

    denied = _event(
        outcome="denied",
        reason_code=
            "tool_not_authorized",
    )


    registry.observe(
        allowed
    )

    registry.observe(
        allowed
    )

    registry.observe(
        denied
    )


    samples = (
        _samples_by_name(
            registry
        )
    )


    event_samples = (
        samples[
            SecurityMetricName
            .SECURITY_EVENTS_TOTAL
        ]
    )


    assert len(
        event_samples
    ) == 2


    counts = {
        dict(
            sample.labels
        )["outcome"]:
            sample.value
        for sample in event_samples
    }


    assert counts == {
        "allowed": 2,
        "denied": 1,
    }


def test_denial_counter_uses_only_bounded_reason_code():
    registry = (
        SecurityMetricsRegistry()
    )


    registry.observe(
        _event(
            outcome="denied",
            reason_code=
                "tool_not_authorized",
        )
    )


    samples = (
        _samples_by_name(
            registry
        )
    )


    denial_samples = (
        samples[
            SecurityMetricName
            .SECURITY_DENIALS_TOTAL
        ]
    )


    assert len(
        denial_samples
    ) == 1


    labels = dict(
        denial_samples[
            0
        ].labels
    )


    assert labels == {
        "event_type":
            (
                SecurityEventType
                .MCP_TOOL_INVOCATION_DENIED
                .value
            ),
        "reason_code":
            "tool_not_authorized",
        "source_component":
            (
                SecuritySourceComponent
                .TOOL_DISPATCHER
                .value
            ),
    }


def test_missing_reason_uses_one_fixed_bounded_value():
    registry = (
        SecurityMetricsRegistry()
    )


    registry.observe(
        _event(
            outcome="denied",
        )
    )


    samples = (
        _samples_by_name(
            registry
        )
    )


    labels = dict(
        samples[
            SecurityMetricName
            .SECURITY_DENIALS_TOTAL
        ][0].labels
    )


    assert (
        labels[
            "reason_code"
        ]
        == NO_REASON_LABEL
    )

    assert (
        NO_REASON_LABEL
        == "none"
    )


def test_review_required_counter_is_independent_from_denial_counter():
    registry = (
        SecurityMetricsRegistry()
    )


    registry.observe(
        _event(
            outcome=
                "review_required",
            reason_code=
                "needs_review",
        )
    )


    samples = (
        _samples_by_name(
            registry
        )
    )


    assert (
        SecurityMetricName
        .SECURITY_REVIEW_REQUIRED_TOTAL
        in samples
    )

    assert (
        SecurityMetricName
        .SECURITY_DENIALS_TOTAL
        not in samples
    )


    review = (
        samples[
            SecurityMetricName
            .SECURITY_REVIEW_REQUIRED_TOTAL
        ][0]
    )


    labels = dict(
        review.labels
    )


    assert (
        labels[
            "reason_code"
        ]
        == "needs_review"
    )


def test_high_cardinality_event_fields_never_appear_as_labels():
    registry = (
        SecurityMetricsRegistry()
    )


    event = SecurityEvent(
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
        request_id=
            "REQ-HIGH-CARDINALITY",
        principal_ref=
            "PRINCIPAL-HIGH-CARDINALITY",
        tenant_id=
            "tenant-alpha",
        session_ref=
            "SESSION-HIGH-CARDINALITY",
        workflow_id=
            "WF-HIGH-CARDINALITY",
        execution_attempt_ref=
            (
                "EA1-"
                + (
                    "a"
                    * 64
                )
            ),
        provider_correlation_id=
            (
                "VMAI-"
                + (
                    "b"
                    * 64
                )
            ),
        reason_code=(
            SecurityReasonCode
            .TOOL_NOT_AUTHORIZED
        ),
    )


    registry.observe(
        event
    )


    for sample in registry.snapshot():

        label_names = {
            name
            for (
                name,
                _,
            ) in sample.labels
        }

        label_values = {
            value
            for (
                _,
                value,
            ) in sample.labels
        }


        assert not (
            label_names
            & PROHIBITED_SECURITY_METRIC_LABELS
        )


        for forbidden_value in (
            "REQ-HIGH-CARDINALITY",
            "PRINCIPAL-HIGH-CARDINALITY",
            "tenant-alpha",
            "SESSION-HIGH-CARDINALITY",
            "WF-HIGH-CARDINALITY",
        ):

            assert (
                forbidden_value
                not in label_values
            )


def test_series_bounds_are_derived_only_from_enum_cardinality():
    bounds = (
        security_metric_series_bounds()
    )


    assert isinstance(
        bounds,
        MappingProxyType,
    )


    expected_events = (
        len(
            SecurityEventType
        )
        * len(
            SecuritySeverity
        )
        * len(
            SecurityOutcome
        )
        * len(
            SecuritySourceComponent
        )
    )


    expected_reason_metric = (
        len(
            SecurityEventType
        )
        * (
            len(
                SecurityReasonCode
            )
            + 1
        )
        * len(
            SecuritySourceComponent
        )
    )


    assert (
        bounds[
            SecurityMetricName
            .SECURITY_EVENTS_TOTAL
        ]
        == expected_events
    )

    assert (
        bounds[
            SecurityMetricName
            .SECURITY_DENIALS_TOTAL
        ]
        == expected_reason_metric
    )

    assert (
        bounds[
            SecurityMetricName
            .SECURITY_REVIEW_REQUIRED_TOTAL
        ]
        == expected_reason_metric
    )


def test_snapshot_is_immutable_and_deterministic():
    registry = (
        SecurityMetricsRegistry()
    )


    registry.observe(
        _event(
            outcome="allowed",
        )
    )

    registry.observe(
        _event(
            outcome="denied",
            reason_code=
                "tool_not_authorized",
        )
    )


    first = (
        registry.snapshot()
    )

    second = (
        registry.snapshot()
    )


    assert isinstance(
        first,
        tuple,
    )

    assert first == second

    assert (
        tuple(
            (
                sample.name.value,
                sample.labels,
            )
            for sample in first
        )
        == tuple(
            sorted(
                (
                    sample.name.value,
                    sample.labels,
                )
                for sample in first
            )
        )
    )


def test_non_security_event_is_rejected():
    registry = (
        SecurityMetricsRegistry()
    )


    with pytest.raises(
        SecurityMetricValidationError
    ):

        registry.observe(
            object()
        )
