"""
Deterministic security detections derived from canonical SecurityEvent data.

Detection is observational only.

A detection rule cannot authenticate a principal, select a tenant,
authorize retrieval, validate an MCP session, authorize a tool, approve
workflow execution, establish execution-attempt authority, or resolve
provider reconciliation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Mapping
from uuid import uuid4

from app.security_observability import (
    SecurityEvent,
    SecurityEventType,
    SecurityOutcome,
    SecurityReasonCode,
    SecuritySeverity,
    SecuritySourceComponent,
)


class SecurityDetectionValidationError(ValueError):
    """
    Raised when detection evaluation is given an invalid canonical input
    or a rule violates the bounded deterministic rule contract.
    """


class SecurityDetectionRuleId(str, Enum):
    CROSS_TENANT_ACTIVITY = (
        "DET-CROSS-TENANT-001"
    )

    SECURITY_BINDING_MISMATCH = (
        "DET-BINDING-001"
    )

    PROVIDER_CORRELATION_MISMATCH = (
        "DET-PROVIDER-CORRELATION-001"
    )

    PROVIDER_AMBIGUITY = (
        "DET-PROVIDER-AMBIGUITY-001"
    )

    EXECUTION_ATTEMPT_MISMATCH = (
        "DET-EXECUTION-ATTEMPT-001"
    )

    WORKFLOW_STALE_PROCESSING = (
        "DET-WORKFLOW-STALE-001"
    )

    DIRECT_PROMPT_INJECTION = (
        "DET-AI-PROMPT-INJECTION-001"
    )

    TOOL_OUTPUT_INJECTION_SUSPECTED = (
        "DET-AI-TOOL-OUTPUT-001"
    )

    UNAUTHORIZED_MCP_TOOL = (
        "DET-MCP-TOOL-AUTHZ-001"
    )

    WORKFLOW_NEEDS_REVIEW = (
        "DET-WORKFLOW-REVIEW-001"
    )


class SecurityAlertType(str, Enum):
    CROSS_TENANT_ACTIVITY = (
        "cross_tenant_activity"
    )

    SECURITY_BINDING_MISMATCH = (
        "security_binding_mismatch"
    )

    PROVIDER_CORRELATION_MISMATCH = (
        "provider_correlation_mismatch"
    )

    PROVIDER_AMBIGUITY = (
        "provider_ambiguity"
    )

    EXECUTION_ATTEMPT_MISMATCH = (
        "execution_attempt_mismatch"
    )

    WORKFLOW_STALE_PROCESSING = (
        "workflow_stale_processing"
    )

    DIRECT_PROMPT_INJECTION = (
        "direct_prompt_injection"
    )

    TOOL_OUTPUT_INJECTION_SUSPECTED = (
        "tool_output_injection_suspected"
    )

    UNAUTHORIZED_MCP_TOOL = (
        "unauthorized_mcp_tool"
    )

    WORKFLOW_NEEDS_REVIEW = (
        "workflow_needs_review"
    )


@dataclass(
    frozen=True,
    slots=True,
)
class SecurityDetectionRule:
    """
    One bounded deterministic single-event detection rule.

    None means that field is not part of the rule predicate. No rule
    accepts arbitrary caller predicates or executable callbacks.
    """

    rule_id: SecurityDetectionRuleId

    alert_type: SecurityAlertType

    alert_severity: SecuritySeverity

    event_type: SecurityEventType | None = None

    outcome: SecurityOutcome | None = None

    reason_code: SecurityReasonCode | None = None


    def matches(
        self,
        event: SecurityEvent,
    ) -> bool:

        if (
            self.event_type
            is not None
            and event.event_type
            is not self.event_type
        ):
            return False


        if (
            self.outcome
            is not None
            and event.outcome
            is not self.outcome
        ):
            return False


        if (
            self.reason_code
            is not None
            and event.reason_code
            is not self.reason_code
        ):
            return False


        return True


@dataclass(
    frozen=True,
    slots=True,
)
class SecurityAlert:
    """
    Immutable responder-facing result of one deterministic rule match.

    Alert correlation fields are investigation context only. They are
    not authorization state and are not metric labels.
    """

    alert_id: str

    detected_at: str

    rule_id: SecurityDetectionRuleId

    alert_type: SecurityAlertType

    severity: SecuritySeverity

    source_event_id: str

    source_event_type: SecurityEventType

    source_event_outcome: SecurityOutcome

    source_component: SecuritySourceComponent

    reason_code: SecurityReasonCode | None = None

    request_id: str | None = None

    principal_ref: str | None = None

    tenant_id: str | None = None

    session_ref: str | None = None

    workflow_id: str | None = None

    execution_attempt_ref: str | None = None

    provider_correlation_id: str | None = None


    def to_dict(
        self,
    ) -> dict[
        str,
        object,
    ]:

        payload: dict[
            str,
            object,
        ] = {
            "alert_id":
                self.alert_id,
            "detected_at":
                self.detected_at,
            "rule_id":
                self.rule_id.value,
            "alert_type":
                self.alert_type.value,
            "severity":
                self.severity.value,
            "source_event_id":
                self.source_event_id,
            "source_event_type":
                self.source_event_type.value,
            "source_event_outcome":
                self.source_event_outcome.value,
            "source_component":
                self.source_component.value,
        }


        optional = {
            "reason_code":
                (
                    self.reason_code.value
                    if self.reason_code
                    is not None
                    else None
                ),
            "request_id":
                self.request_id,
            "principal_ref":
                self.principal_ref,
            "tenant_id":
                self.tenant_id,
            "session_ref":
                self.session_ref,
            "workflow_id":
                self.workflow_id,
            "execution_attempt_ref":
                self.execution_attempt_ref,
            "provider_correlation_id":
                self.provider_correlation_id,
        }


        for (
            name,
            value,
        ) in optional.items():

            if value is not None:

                payload[
                    name
                ] = value


        return payload


SECURITY_DETECTION_RULES = (
    # Highest-confidence authority-boundary violations first.
    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .CROSS_TENANT_ACTIVITY
        ),
        alert_type=(
            SecurityAlertType
            .CROSS_TENANT_ACTIVITY
        ),
        alert_severity=(
            SecuritySeverity.HIGH
        ),
        reason_code=(
            SecurityReasonCode.CROSS_TENANT
        ),
    ),

    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .SECURITY_BINDING_MISMATCH
        ),
        alert_type=(
            SecurityAlertType
            .SECURITY_BINDING_MISMATCH
        ),
        alert_severity=(
            SecuritySeverity.HIGH
        ),
        reason_code=(
            SecurityReasonCode
            .SECURITY_BINDING_MISMATCH
        ),
    ),

    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .PROVIDER_CORRELATION_MISMATCH
        ),
        alert_type=(
            SecurityAlertType
            .PROVIDER_CORRELATION_MISMATCH
        ),
        alert_severity=(
            SecuritySeverity.HIGH
        ),
        reason_code=(
            SecurityReasonCode
            .PROVIDER_CORRELATION_MISMATCH
        ),
    ),

    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .PROVIDER_AMBIGUITY
        ),
        alert_type=(
            SecurityAlertType
            .PROVIDER_AMBIGUITY
        ),
        alert_severity=(
            SecuritySeverity.HIGH
        ),
        reason_code=(
            SecurityReasonCode
            .PROVIDER_AMBIGUOUS
        ),
    ),

    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .EXECUTION_ATTEMPT_MISMATCH
        ),
        alert_type=(
            SecurityAlertType
            .EXECUTION_ATTEMPT_MISMATCH
        ),
        alert_severity=(
            SecuritySeverity.HIGH
        ),
        reason_code=(
            SecurityReasonCode
            .EXECUTION_ATTEMPT_MISMATCH
        ),
    ),

    # Operationally significant workflow state.
    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .WORKFLOW_STALE_PROCESSING
        ),
        alert_type=(
            SecurityAlertType
            .WORKFLOW_STALE_PROCESSING
        ),
        alert_severity=(
            SecuritySeverity.MEDIUM
        ),
        event_type=(
            SecurityEventType
            .WORKFLOW_STALE_PROCESSING_DETECTED
        ),
    ),

    # Successfully detected/blocked AI-security signals.
    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .DIRECT_PROMPT_INJECTION
        ),
        alert_type=(
            SecurityAlertType
            .DIRECT_PROMPT_INJECTION
        ),
        alert_severity=(
            SecuritySeverity.MEDIUM
        ),
        event_type=(
            SecurityEventType
            .AI_DIRECT_PROMPT_INJECTION_BLOCKED
        ),
        outcome=(
            SecurityOutcome.BLOCKED
        ),
    ),

    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .TOOL_OUTPUT_INJECTION_SUSPECTED
        ),
        alert_type=(
            SecurityAlertType
            .TOOL_OUTPUT_INJECTION_SUSPECTED
        ),
        alert_severity=(
            SecuritySeverity.MEDIUM
        ),
        event_type=(
            SecurityEventType
            .AI_TOOL_OUTPUT_PROMPT_INJECTION_SUSPECTED
        ),
        outcome=(
            SecurityOutcome.AMBIGUOUS
        ),
    ),

    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .UNAUTHORIZED_MCP_TOOL
        ),
        alert_type=(
            SecurityAlertType
            .UNAUTHORIZED_MCP_TOOL
        ),
        alert_severity=(
            SecuritySeverity.MEDIUM
        ),
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
    ),

    # Operational review signal. This is deliberately lower severity
    # than authority-boundary violations.
    SecurityDetectionRule(
        rule_id=(
            SecurityDetectionRuleId
            .WORKFLOW_NEEDS_REVIEW
        ),
        alert_type=(
            SecurityAlertType
            .WORKFLOW_NEEDS_REVIEW
        ),
        alert_severity=(
            SecuritySeverity.LOW
        ),
        event_type=(
            SecurityEventType
            .WORKFLOW_NEEDS_REVIEW
        ),
        outcome=(
            SecurityOutcome
            .REVIEW_REQUIRED
        ),
    ),
)


SECURITY_DETECTION_RULE_INDEX: Mapping[
    SecurityDetectionRuleId,
    SecurityDetectionRule,
] = MappingProxyType(
    {
        rule.rule_id:
            rule
        for rule in SECURITY_DETECTION_RULES
    }
)


def _new_alert_id(
) -> str:

    return (
        "ALERT-"
        + uuid4().hex
    )


def _utc_now_iso(
) -> str:

    return (
        datetime.now(
            timezone.utc
        )
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )


def evaluate_security_event(
    event: SecurityEvent,
) -> SecurityAlert | None:
    """
    Evaluate one canonical SecurityEvent against ordered deterministic
    v1 rules.

    At most one alert is produced. The first matching rule wins, which
    gives authority-boundary violations precedence over lower-priority
    operational signals.

    Evaluation does not mutate the source event or any security state.
    """

    if not isinstance(
        event,
        SecurityEvent,
    ):
        raise SecurityDetectionValidationError(
            "Security detection requires "
            "a canonical SecurityEvent."
        )


    for rule in (
        SECURITY_DETECTION_RULES
    ):

        if not rule.matches(
            event
        ):
            continue


        return SecurityAlert(
            alert_id=
                _new_alert_id(),
            detected_at=
                _utc_now_iso(),
            rule_id=
                rule.rule_id,
            alert_type=
                rule.alert_type,
            severity=
                rule.alert_severity,
            source_event_id=
                event.event_id,
            source_event_type=
                event.event_type,
            source_event_outcome=
                event.outcome,
            source_component=
                event.source_component,
            reason_code=
                event.reason_code,
            request_id=
                event.request_id,
            principal_ref=
                event.principal_ref,
            tenant_id=
                event.tenant_id,
            session_ref=
                event.session_ref,
            workflow_id=
                event.workflow_id,
            execution_attempt_ref=
                event.execution_attempt_ref,
            provider_correlation_id=
                event.provider_correlation_id,
        )


    return None
