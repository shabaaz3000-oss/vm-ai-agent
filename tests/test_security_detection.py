from __future__ import annotations

from dataclasses import FrozenInstanceError
from types import MappingProxyType

import pytest

from app.security_detection import (
    SECURITY_DETECTION_RULE_INDEX,
    SECURITY_DETECTION_RULES,
    SecurityAlert,
    SecurityAlertType,
    SecurityDetectionRuleId,
    SecurityDetectionValidationError,
    evaluate_security_event,
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
    event_type: SecurityEventType = (
        SecurityEventType
        .MCP_TOOL_INVOCATION_DENIED
    ),
    outcome: SecurityOutcome = (
        SecurityOutcome.DENIED
    ),
    reason_code: SecurityReasonCode | None = None,
) -> SecurityEvent:

    return SecurityEvent(
        event_type=
            event_type,
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
    )


@pytest.mark.parametrize(
    (
        "reason_code",
        "expected_rule",
        "expected_type",
        "expected_severity",
    ),
    (
        (
            SecurityReasonCode.CROSS_TENANT,
            (
                SecurityDetectionRuleId
                .CROSS_TENANT_ACTIVITY
            ),
            (
                SecurityAlertType
                .CROSS_TENANT_ACTIVITY
            ),
            SecuritySeverity.HIGH,
        ),
        (
            (
                SecurityReasonCode
                .SECURITY_BINDING_MISMATCH
            ),
            (
                SecurityDetectionRuleId
                .SECURITY_BINDING_MISMATCH
            ),
            (
                SecurityAlertType
                .SECURITY_BINDING_MISMATCH
            ),
            SecuritySeverity.HIGH,
        ),
        (
            (
                SecurityReasonCode
                .PROVIDER_CORRELATION_MISMATCH
            ),
            (
                SecurityDetectionRuleId
                .PROVIDER_CORRELATION_MISMATCH
            ),
            (
                SecurityAlertType
                .PROVIDER_CORRELATION_MISMATCH
            ),
            SecuritySeverity.HIGH,
        ),
        (
            SecurityReasonCode.PROVIDER_AMBIGUOUS,
            (
                SecurityDetectionRuleId
                .PROVIDER_AMBIGUITY
            ),
            (
                SecurityAlertType
                .PROVIDER_AMBIGUITY
            ),
            SecuritySeverity.HIGH,
        ),
        (
            (
                SecurityReasonCode
                .EXECUTION_ATTEMPT_MISMATCH
            ),
            (
                SecurityDetectionRuleId
                .EXECUTION_ATTEMPT_MISMATCH
            ),
            (
                SecurityAlertType
                .EXECUTION_ATTEMPT_MISMATCH
            ),
            SecuritySeverity.HIGH,
        ),
    ),
)
def test_high_confidence_reason_rules(
    reason_code,
    expected_rule,
    expected_type,
    expected_severity,
):
    alert = evaluate_security_event(
        _event(
            reason_code=
                reason_code,
        )
    )


    assert alert is not None

    assert (
        alert.rule_id
        is expected_rule
    )

    assert (
        alert.alert_type
        is expected_type
    )

    assert (
        alert.severity
        is expected_severity
    )


def test_stale_processing_detection():
    alert = evaluate_security_event(
        _event(
            event_type=(
                SecurityEventType
                .WORKFLOW_STALE_PROCESSING_DETECTED
            ),
            outcome=(
                SecurityOutcome.SUCCESS
            ),
        )
    )


    assert alert is not None

    assert (
        alert.rule_id
        is (
            SecurityDetectionRuleId
            .WORKFLOW_STALE_PROCESSING
        )
    )

    assert (
        alert.severity
        is SecuritySeverity.MEDIUM
    )


def test_direct_prompt_injection_detection():
    alert = evaluate_security_event(
        _event(
            event_type=(
                SecurityEventType
                .AI_DIRECT_PROMPT_INJECTION_BLOCKED
            ),
            outcome=(
                SecurityOutcome.BLOCKED
            ),
            reason_code=(
                SecurityReasonCode
                .PROMPT_INJECTION_DETECTED
            ),
        )
    )


    assert alert is not None

    assert (
        alert.rule_id
        is (
            SecurityDetectionRuleId
            .DIRECT_PROMPT_INJECTION
        )
    )


def test_tool_output_injection_suspicion_detection():
    alert = evaluate_security_event(
        _event(
            event_type=(
                SecurityEventType
                .AI_TOOL_OUTPUT_PROMPT_INJECTION_SUSPECTED
            ),
            outcome=(
                SecurityOutcome.AMBIGUOUS
            ),
            reason_code=(
                SecurityReasonCode
                .PROMPT_INJECTION_DETECTED
            ),
        )
    )


    assert alert is not None

    assert (
        alert.rule_id
        is (
            SecurityDetectionRuleId
            .TOOL_OUTPUT_INJECTION_SUSPECTED
        )
    )


def test_unauthorized_mcp_tool_detection():
    alert = evaluate_security_event(
        _event(
            event_type=(
                SecurityEventType
                .MCP_TOOL_INVOCATION_DENIED
            ),
            outcome=(
                SecurityOutcome.DENIED
            ),
            reason_code=(
                SecurityReasonCode
                .TOOL_NOT_AUTHORIZED
            ),
        )
    )


    assert alert is not None

    assert (
        alert.rule_id
        is (
            SecurityDetectionRuleId
            .UNAUTHORIZED_MCP_TOOL
        )
    )

    assert (
        alert.severity
        is SecuritySeverity.MEDIUM
    )


def test_needs_review_is_low_severity_operational_alert():
    alert = evaluate_security_event(
        _event(
            event_type=(
                SecurityEventType
                .WORKFLOW_NEEDS_REVIEW
            ),
            outcome=(
                SecurityOutcome
                .REVIEW_REQUIRED
            ),
            reason_code=(
                SecurityReasonCode
                .NEEDS_REVIEW
            ),
        )
    )


    assert alert is not None

    assert (
        alert.rule_id
        is (
            SecurityDetectionRuleId
            .WORKFLOW_NEEDS_REVIEW
        )
    )

    assert (
        alert.severity
        is SecuritySeverity.LOW
    )


def test_allowed_non_matching_event_produces_no_alert():
    alert = evaluate_security_event(
        _event(
            event_type=(
                SecurityEventType
                .MCP_TOOL_INVOCATION_ALLOWED
            ),
            outcome=(
                SecurityOutcome.ALLOWED
            ),
        )
    )


    assert alert is None


def test_first_matching_rule_prioritizes_cross_tenant_authority_violation():
    event = _event(
        event_type=(
            SecurityEventType
            .MCP_TOOL_INVOCATION_DENIED
        ),
        outcome=(
            SecurityOutcome.DENIED
        ),
        reason_code=(
            SecurityReasonCode
            .CROSS_TENANT
        ),
    )


    alert = evaluate_security_event(
        event
    )


    assert alert is not None

    assert (
        alert.rule_id
        is (
            SecurityDetectionRuleId
            .CROSS_TENANT_ACTIVITY
        )
    )


def test_alert_copies_only_canonical_correlation_context():
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
            "REQ-1",
        principal_ref=
            "PRINCIPAL-REF-1",
        tenant_id=
            "tenant-1",
        session_ref=
            "SESSION-REF-1",
        workflow_id=
            "WF-12345678",
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


    alert = evaluate_security_event(
        event
    )


    assert alert is not None

    assert (
        alert.source_event_id
        == event.event_id
    )

    assert (
        alert.request_id
        == event.request_id
    )

    assert (
        alert.principal_ref
        == event.principal_ref
    )

    assert (
        alert.tenant_id
        == event.tenant_id
    )

    assert (
        alert.session_ref
        == event.session_ref
    )

    assert (
        alert.workflow_id
        == event.workflow_id
    )

    assert (
        alert.execution_attempt_ref
        == event.execution_attempt_ref
    )

    assert (
        alert.provider_correlation_id
        == event.provider_correlation_id
    )


def test_alert_serialization_omits_absent_optional_context():
    alert = evaluate_security_event(
        _event(
            reason_code=(
                SecurityReasonCode
                .TOOL_NOT_AUTHORIZED
            ),
        )
    )


    assert alert is not None

    payload = (
        alert.to_dict()
    )


    assert (
        payload[
            "rule_id"
        ]
        == (
            SecurityDetectionRuleId
            .UNAUTHORIZED_MCP_TOOL
            .value
        )
    )

    assert (
        payload[
            "alert_type"
        ]
        == (
            SecurityAlertType
            .UNAUTHORIZED_MCP_TOOL
            .value
        )
    )


    for field in (
        "request_id",
        "principal_ref",
        "tenant_id",
        "session_ref",
        "workflow_id",
        "execution_attempt_ref",
        "provider_correlation_id",
    ):

        assert (
            field
            not in payload
        )


def test_security_alert_is_immutable():
    alert = evaluate_security_event(
        _event(
            reason_code=(
                SecurityReasonCode
                .TOOL_NOT_AUTHORIZED
            ),
        )
    )


    assert isinstance(
        alert,
        SecurityAlert,
    )


    with pytest.raises(
        FrozenInstanceError
    ):

        alert.severity = (
            SecuritySeverity.CRITICAL
        )


def test_rule_table_is_immutable_and_rule_ids_are_unique():
    assert isinstance(
        SECURITY_DETECTION_RULES,
        tuple,
    )

    assert isinstance(
        SECURITY_DETECTION_RULE_INDEX,
        MappingProxyType,
    )


    ids = [
        rule.rule_id
        for rule
        in SECURITY_DETECTION_RULES
    ]


    assert len(
        ids
    ) == len(
        set(
            ids
        )
    )

    assert len(
        SECURITY_DETECTION_RULES
    ) == 10


def test_all_rule_dimensions_are_bounded_enums():
    for rule in (
        SECURITY_DETECTION_RULES
    ):

        assert isinstance(
            rule.rule_id,
            SecurityDetectionRuleId,
        )

        assert isinstance(
            rule.alert_type,
            SecurityAlertType,
        )

        assert isinstance(
            rule.alert_severity,
            SecuritySeverity,
        )


        if (
            rule.event_type
            is not None
        ):

            assert isinstance(
                rule.event_type,
                SecurityEventType,
            )


        if (
            rule.outcome
            is not None
        ):

            assert isinstance(
                rule.outcome,
                SecurityOutcome,
            )


        if (
            rule.reason_code
            is not None
        ):

            assert isinstance(
                rule.reason_code,
                SecurityReasonCode,
            )


def test_detection_rejects_noncanonical_input():
    with pytest.raises(
        SecurityDetectionValidationError
    ):

        evaluate_security_event(
            object()
        )


def test_alert_model_has_no_raw_sensitive_content_fields():
    forbidden = {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "password",
        "secret",
        "prompt",
        "rag_content",
        "tool_output",
        "provider_response",
        "exception",
        "exception_text",
        "ticket_id",
        "sys_id",
    }


    alert_fields = set(
        SecurityAlert.__annotations__
    )


    assert not (
        alert_fields
        & forbidden
    )
