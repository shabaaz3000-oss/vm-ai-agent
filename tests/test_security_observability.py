from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from uuid import UUID

import pytest

from app.security_observability import (
    SECURITY_EVENT_SCHEMA_VERSION,
    SecurityAction,
    SecurityEvent,
    SecurityEventType,
    SecurityEventValidationError,
    SecurityOutcome,
    SecurityReasonCode,
    SecurityResourceType,
    SecuritySeverity,
    SecuritySourceComponent,
    security_event_from_mapping,
    serialize_security_event,
)


def _event() -> SecurityEvent:
    return SecurityEvent(
        event_type=(
            SecurityEventType
            .WORKFLOW_EXECUTION_CLAIMED
        ),
        severity=SecuritySeverity.INFO,
        outcome=SecurityOutcome.SUCCESS,
        source_component=(
            SecuritySourceComponent.EXECUTION
        ),
        request_id="req-123",
        principal_ref="principal-ref-123",
        tenant_id="tenant-alpha",
        session_ref="session-correlation-123",
        workflow_id="WF-123",
        execution_attempt_ref="attempt-456",
        provider_correlation_id=(
            "vm-ai:v1:tenant-alpha:WF-123:attempt-456"
        ),
        resource_type=(
            SecurityResourceType.EXECUTION_ATTEMPT
        ),
        action=SecurityAction.CLAIM_EXECUTION,
    )


def test_security_event_generates_server_owned_fields():
    event = _event()

    assert (
        event.schema_version
        == SECURITY_EVENT_SCHEMA_VERSION
    )

    UUID(event.event_id)

    assert event.occurred_at.tzinfo is not None


def test_security_event_serializes_canonical_envelope():
    event = _event()

    payload = json.loads(
        serialize_security_event(event)
    )

    assert payload["schema_version"] == "1.0"
    assert (
        payload["event_type"]
        == "security.workflow.execution_claimed"
    )
    assert payload["severity"] == "info"
    assert payload["outcome"] == "success"
    assert (
        payload["source_component"]
        == "execution"
    )
    assert payload["tenant_id"] == "tenant-alpha"
    assert payload["workflow_id"] == "WF-123"
    assert (
        payload["execution_attempt_ref"]
        == "attempt-456"
    )
    assert (
        payload["action"]
        == "claim_execution"
    )
    assert payload["occurred_at"].endswith("Z")


def test_security_event_omits_none_optional_fields():
    event = SecurityEvent(
        event_type=(
            SecurityEventType
            .AUTHORIZATION_DENIED
        ),
        severity=SecuritySeverity.MEDIUM,
        outcome=SecurityOutcome.DENIED,
        source_component=(
            SecuritySourceComponent.AUTH
        ),
    )

    payload = event.to_dict()

    assert "tenant_id" not in payload
    assert "workflow_id" not in payload
    assert "reason_code" not in payload


def test_security_event_is_immutable():
    event = _event()

    with pytest.raises(FrozenInstanceError):
        event.tenant_id = "tenant-bravo"


def test_mapping_adapter_generates_server_owned_event_id():
    event = security_event_from_mapping(
        {
            "event_type": (
                "security.authorization."
                "cross_tenant_denied"
            ),
            "severity": "high",
            "outcome": "denied",
            "source_component": "auth",
            "tenant_id": "tenant-alpha",
            "resource_type": "tenant",
            "action": "authorize",
            "reason_code": "cross_tenant",
        }
    )

    UUID(event.event_id)

    assert (
        event.event_type
        is SecurityEventType
        .AUTHORIZATION_CROSS_TENANT_DENIED
    )
    assert event.severity is SecuritySeverity.HIGH
    assert event.outcome is SecurityOutcome.DENIED
    assert (
        event.reason_code
        is SecurityReasonCode.CROSS_TENANT
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "event_id",
        "occurred_at",
        "schema_version",
    ],
)
def test_mapping_adapter_rejects_server_owned_fields(
    field_name: str,
):
    values = {
        "event_type": (
            "security.authorization.denied"
        ),
        "severity": "medium",
        "outcome": "denied",
        "source_component": "auth",
        field_name: "attacker-controlled",
    }

    with pytest.raises(
        SecurityEventValidationError,
        match="Server-owned fields",
    ):
        security_event_from_mapping(values)


@pytest.mark.parametrize(
    "field_name",
    [
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "password",
        "client_secret",
        "authorization_header",
        "cookie",
        "access_key",
        "secret_key",
        "private_key",
        "raw_prompt",
        "document_content",
        "retrieved_evidence",
        "tool_output",
        "request_body",
        "response_body",
    ],
)
def test_mapping_adapter_rejects_sensitive_fields(
    field_name: str,
):
    values = {
        "event_type": (
            "security.authorization.denied"
        ),
        "severity": "high",
        "outcome": "denied",
        "source_component": "auth",
        field_name: "DO-NOT-LOG",
    }

    with pytest.raises(
        SecurityEventValidationError,
        match="Sensitive field",
    ):
        security_event_from_mapping(values)


def test_mapping_adapter_rejects_nested_sensitive_fields():
    values = {
        "event_type": (
            "security.provider.request_completed"
        ),
        "severity": "high",
        "outcome": "failed",
        "source_component": (
            "servicenow_provider"
        ),
        "metadata": {
            "provider": {
                "password": "DO-NOT-LOG",
            }
        },
    }

    with pytest.raises(
        SecurityEventValidationError,
        match="Sensitive field",
    ):
        security_event_from_mapping(values)


def test_mapping_adapter_rejects_unknown_metadata():
    values = {
        "event_type": (
            "security.provider.request_completed"
        ),
        "severity": "info",
        "outcome": "success",
        "source_component": (
            "servicenow_provider"
        ),
        "metadata": {
            "arbitrary": "value",
        },
    }

    with pytest.raises(
        SecurityEventValidationError,
        match="Unknown security-event fields",
    ):
        security_event_from_mapping(values)


def test_mapping_adapter_rejects_unknown_event_type():
    with pytest.raises(
        SecurityEventValidationError,
        match="Unsupported event_type",
    ):
        security_event_from_mapping(
            {
                "event_type": (
                    "security.attacker."
                    "invented_event"
                ),
                "severity": "high",
                "outcome": "denied",
                "source_component": "auth",
            }
        )


def test_mapping_adapter_rejects_unknown_reason_code():
    with pytest.raises(
        SecurityEventValidationError,
        match="Unsupported reason_code",
    ):
        security_event_from_mapping(
            {
                "event_type": (
                    "security.authorization.denied"
                ),
                "severity": "medium",
                "outcome": "denied",
                "source_component": "auth",
                "reason_code": (
                    "attacker_supplied_reason"
                ),
            }
        )


def test_reference_fields_reject_control_characters():
    with pytest.raises(
        SecurityEventValidationError,
        match="control characters",
    ):
        SecurityEvent(
            event_type=(
                SecurityEventType
                .AUTHORIZATION_DENIED
            ),
            severity=SecuritySeverity.HIGH,
            outcome=SecurityOutcome.DENIED,
            source_component=(
                SecuritySourceComponent.AUTH
            ),
            tenant_id=(
                "tenant-alpha\n"
                "FAKE_EVENT=allowed"
            ),
        )


def test_reference_fields_reject_blank_values():
    with pytest.raises(
        SecurityEventValidationError,
        match="must not be blank",
    ):
        SecurityEvent(
            event_type=(
                SecurityEventType
                .MCP_SESSION_VALIDATION_FAILED
            ),
            severity=SecuritySeverity.MEDIUM,
            outcome=SecurityOutcome.DENIED,
            source_component=(
                SecuritySourceComponent.MCP_SESSION
            ),
            session_ref="   ",
        )


def test_direct_constructor_rejects_raw_enum_strings():
    with pytest.raises(
        SecurityEventValidationError,
        match="event_type must be",
    ):
        SecurityEvent(
            event_type=(
                "security.authorization.denied"
            ),
            severity=SecuritySeverity.HIGH,
            outcome=SecurityOutcome.DENIED,
            source_component=(
                SecuritySourceComponent.AUTH
            ),
        )


def test_serializer_rejects_arbitrary_mapping():
    with pytest.raises(
        SecurityEventValidationError,
        match="requires a SecurityEvent",
    ):
        serialize_security_event(
            {
                "event_type": (
                    "security.authorization.denied"
                ),
                "token": "DO-NOT-LOG",
            }
        )


def test_prompt_injection_event_uses_bounded_values():
    event = SecurityEvent(
        event_type=(
            SecurityEventType
            .AI_DIRECT_PROMPT_INJECTION_BLOCKED
        ),
        severity=SecuritySeverity.HIGH,
        outcome=SecurityOutcome.BLOCKED,
        source_component=(
            SecuritySourceComponent.AGENT
        ),
        resource_type=(
            SecurityResourceType.RETRIEVAL
        ),
        action=(
            SecurityAction
            .INSPECT_PROMPT_INJECTION
        ),
        reason_code=(
            SecurityReasonCode
            .PROMPT_INJECTION_DETECTED
        ),
    )

    payload = event.to_dict()

    assert (
        payload["event_type"]
        == "security.ai.direct_prompt_injection_blocked"
    )
    assert payload["outcome"] == "blocked"
    assert (
        payload["reason_code"]
        == "prompt_injection_detected"
    )


def test_two_events_receive_different_event_ids():
    first = _event()
    second = _event()

    assert first.event_id != second.event_id
