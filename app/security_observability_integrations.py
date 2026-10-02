"""
Adapters between existing authoritative security decisions and
canonical Step 50 security telemetry.

These functions observe decisions that have already been made by
existing security controls.

They do not grant access, derive authority, select tenants, approve
workflows, or mutate security state.

Canonical telemetry is deliberately best-effort at these integration
points so an observability failure cannot replace or alter the
underlying security decision.
"""

from __future__ import annotations

import logging

from app.security_event_emitter import (
    SecurityEventEmitter,
    build_existing_audit_security_event_sink,
)
from app.security_observability import (
    SecurityAction,
    SecurityEvent,
    SecurityEventType,
    SecurityOutcome,
    SecurityReasonCode,
    SecurityResourceType,
    SecuritySeverity,
    SecuritySourceComponent,
)


_LOGGER = logging.getLogger(__name__)


_RETRIEVAL_DENIAL_REASON_CODES = {
    "tenant_mismatch":
        SecurityReasonCode.CROSS_TENANT,

    "missing_tenant_scope":
        SecurityReasonCode.DOCUMENT_ACL_DENIED,

    "principal_acl_denied":
        SecurityReasonCode.DOCUMENT_ACL_DENIED,

    "group_acl_denied":
        SecurityReasonCode.DOCUMENT_ACL_DENIED,

    "group_membership_unavailable":
        SecurityReasonCode.RETRIEVAL_ACL_DENIED,

    "invalid_group_authority":
        SecurityReasonCode.RETRIEVAL_ACL_DENIED,

    "classification_denied":
        SecurityReasonCode.RETRIEVAL_ACL_DENIED,

    "invalid_retrieval_access":
        SecurityReasonCode.RETRIEVAL_ACL_DENIED,

    "invalid_authorization_metadata":
        SecurityReasonCode.RETRIEVAL_ACL_DENIED,
}


def _report_emission_failure(
    exc: BaseException,
) -> None:
    """
    Report a telemetry failure without copying raw exception text.

    Sink/provider exceptions may themselves contain secrets.
    """

    _LOGGER.error(
        "Canonical security telemetry emission failed; "
        "existing security decision preserved. "
        "error_type=%s",
        type(exc).__name__,
    )


def _emit_best_effort(
    event: SecurityEvent,
) -> bool:
    try:
        sink = (
            build_existing_audit_security_event_sink()
        )

        SecurityEventEmitter(
            sink
        ).emit(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False

    return True


def emit_api_tenant_binding_denied_security_event(
) -> bool:
    """
    Observe authoritative failure to resolve a server-owned API
    principal -> tenant binding.

    No caller-supplied tenant and no raw username are recorded.
    """

    try:
        event = SecurityEvent(
            event_type=(
                SecurityEventType
                .IDENTITY_TENANT_BINDING_DENIED
            ),
            severity=SecuritySeverity.MEDIUM,
            outcome=SecurityOutcome.DENIED,
            source_component=(
                SecuritySourceComponent.API
            ),
            resource_type=(
                SecurityResourceType.TENANT
            ),
            action=SecurityAction.BIND_TENANT,
            reason_code=(
                SecurityReasonCode.TENANT_UNBOUND
            ),
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False


def emit_retrieval_authorization_security_event(
    *,
    allowed: bool,
    reason: str,
    tenant_id: str,
) -> bool:
    """
    Observe an already-computed RAG authorization decision.

    `tenant_id` must come from the trusted RetrievalPrincipal.

    The raw legacy authorization reason is mapped into the bounded
    Step 50 reason vocabulary and is never copied into arbitrary
    telemetry metadata.
    """

    try:
        if allowed:
            event_type = (
                SecurityEventType
                .RAG_RETRIEVAL_ALLOWED
            )

            severity = SecuritySeverity.INFO

            outcome = SecurityOutcome.ALLOWED

            reason_code = None

        else:
            event_type = (
                SecurityEventType
                .RAG_RETRIEVAL_DENIED
            )

            outcome = SecurityOutcome.DENIED

            reason_code = (
                _RETRIEVAL_DENIAL_REASON_CODES
                .get(
                    reason,
                    SecurityReasonCode
                    .RETRIEVAL_ACL_DENIED,
                )
            )

            severity = (
                SecuritySeverity.HIGH
                if reason
                == "tenant_mismatch"
                else SecuritySeverity.MEDIUM
            )

        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            outcome=outcome,
            source_component=(
                SecuritySourceComponent.RETRIEVER
            ),
            tenant_id=tenant_id,
            resource_type=(
                SecurityResourceType.RETRIEVAL
            ),
            action=SecurityAction.RETRIEVE,
            reason_code=reason_code,
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False


def emit_direct_prompt_injection_blocked_security_event(
) -> bool:
    """
    Observe the existing direct-input prompt-injection block.

    Raw prompt text, detector matches, username, and role are
    deliberately absent from the canonical event.
    """

    try:
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
            action=(
                SecurityAction
                .INSPECT_PROMPT_INJECTION
            ),
            reason_code=(
                SecurityReasonCode
                .PROMPT_INJECTION_DETECTED
            ),
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False

def emit_tool_output_prompt_injection_suspected_security_event(
) -> bool:
    """
    Observe prompt-injection-like content detected in a tool result.

    This event records suspicion only. The current runtime does not
    block the tool result at this decision point.

    Raw tool output, detector matches, tool name, username, prompt
    text, and model content are deliberately excluded.
    """

    try:
        event = SecurityEvent(
            event_type=(
                SecurityEventType
                .AI_TOOL_OUTPUT_PROMPT_INJECTION_SUSPECTED
            ),
            severity=SecuritySeverity.MEDIUM,
            outcome=SecurityOutcome.AMBIGUOUS,
            source_component=(
                SecuritySourceComponent.AGENT
            ),
            resource_type=(
                SecurityResourceType.MCP_TOOL
            ),
            action=(
                SecurityAction
                .INSPECT_PROMPT_INJECTION
            ),
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False

