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

from app.security_observability_correlation import build_execution_attempt_ref

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

_MCP_SESSION_VALIDATION_REASON_CODES = {
    "session_not_found":
        SecurityReasonCode.SESSION_MISSING,

    "principal_mismatch":
        SecurityReasonCode.SECURITY_BINDING_MISMATCH,

    "tenant_mismatch":
        SecurityReasonCode.CROSS_TENANT,

    "session_revoked":
        SecurityReasonCode.SESSION_REVOKED,

    "session_expired":
        SecurityReasonCode.SESSION_EXPIRED,
}


def emit_mcp_session_validation_failed_security_event(
    *,
    reason: str,
    tenant_id: str | None,
    session_ref: str | None = None,
) -> bool:
    """
    # canonical trusted session correlation is supplied by the authoritative caller
    Observe an authoritative MCP session validation denial.

    For session_not_found there is no authoritative session tenant,
    so tenant_id is deliberately omitted.

    For all other branches, tenant_id must come from the retrieved
    authoritative MCPSession, not from caller-supplied tenant input.

    Raw session IDs, usernames, tokens, and caller authority claims
    are deliberately excluded.
    """

    try:
        reason_code = (
            _MCP_SESSION_VALIDATION_REASON_CODES[
                reason
            ]
        )

        if reason == "session_not_found":
            canonical_tenant_id = None

        else:
            if tenant_id is None:
                raise ValueError(
                    "Authoritative session tenant is required "
                    "for this validation failure."
                )

            canonical_tenant_id = tenant_id

        severity = (
            SecuritySeverity.HIGH
            if reason in {
                "principal_mismatch",
                "tenant_mismatch",
            }
            else SecuritySeverity.MEDIUM
        )

        event = SecurityEvent(
            event_type=(
                SecurityEventType
                .MCP_SESSION_VALIDATION_FAILED
            ),
            severity=severity,
            outcome=SecurityOutcome.DENIED,
            source_component=(
                SecuritySourceComponent.MCP_SESSION
            ),
            tenant_id=canonical_tenant_id,
            session_ref=session_ref,
            resource_type=(
                SecurityResourceType.MCP_SESSION
            ),
            action=SecurityAction.VALIDATE_SESSION,
            reason_code=reason_code,
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False


def emit_mcp_session_revoked_security_event(
    *,
    tenant_id: str,
    session_ref: str | None = None,
) -> bool:
    """
    # canonical trusted session correlation is supplied by the authoritative caller
    Observe a completed authoritative MCP session revocation.

    This helper must be called only after the session store has
    accepted the authoritative revocation state transition.

    Raw session IDs and principal identifiers are not emitted.
    """

    try:
        event = SecurityEvent(
            event_type=(
                SecurityEventType
                .MCP_SESSION_REVOKED
            ),
            severity=SecuritySeverity.MEDIUM,
            outcome=SecurityOutcome.REVOKED,
            source_component=(
                SecuritySourceComponent.MCP_SESSION
            ),
            tenant_id=tenant_id,
            session_ref=session_ref,
            resource_type=(
                SecurityResourceType.MCP_SESSION
            ),
            action=SecurityAction.REVOKE_SESSION,
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False

_MCP_TOOL_INVOCATION_DENIAL_REASON_CODES = {
    "tool_not_authorized":
        SecurityReasonCode.TOOL_NOT_AUTHORIZED,

    "security_binding_mismatch":
        SecurityReasonCode.SECURITY_BINDING_MISMATCH,
}


def emit_mcp_tool_invocation_allowed_security_event(
    *,
    tenant_id: str,
    session_ref: str | None = None,
) -> bool:
    """
    # canonical trusted session correlation is supplied by the authoritative caller
    Observe an MCP tool invocation authorization that has already
    passed the dispatcher's existing policy checks.

    No raw tool name, raw session identifier, principal identifier,
    prompt content, or caller-supplied provenance is emitted.
    """

    try:
        event = SecurityEvent(
            event_type=(
                SecurityEventType
                .MCP_TOOL_INVOCATION_ALLOWED
            ),
            severity=SecuritySeverity.INFO,
            outcome=SecurityOutcome.ALLOWED,
            source_component=(
                SecuritySourceComponent
                .TOOL_DISPATCHER
            ),
            tenant_id=tenant_id,
            session_ref=session_ref,
            resource_type=(
                SecurityResourceType.MCP_TOOL
            ),
            action=SecurityAction.INVOKE_TOOL,
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False


def emit_mcp_tool_invocation_denied_security_event(
    *,
    tenant_id: str,
    reason: str,
    session_ref: str | None = None,
) -> bool:
    """
    # canonical trusted session correlation is supplied by the authoritative caller
    Observe an MCP tool invocation denial produced by an existing
    dispatcher enforcement point.

    `reason` is mapped into the bounded Step 50 vocabulary and is
    never copied into arbitrary canonical metadata.
    """

    try:
        reason_code = (
            _MCP_TOOL_INVOCATION_DENIAL_REASON_CODES[
                reason
            ]
        )

        severity = (
            SecuritySeverity.HIGH
            if (
                reason
                == "security_binding_mismatch"
            )
            else SecuritySeverity.MEDIUM
        )

        event = SecurityEvent(
            event_type=(
                SecurityEventType
                .MCP_TOOL_INVOCATION_DENIED
            ),
            severity=severity,
            outcome=SecurityOutcome.DENIED,
            source_component=(
                SecuritySourceComponent
                .TOOL_DISPATCHER
            ),
            tenant_id=tenant_id,
            session_ref=session_ref,
            resource_type=(
                SecurityResourceType.MCP_TOOL
            ),
            action=SecurityAction.INVOKE_TOOL,
            reason_code=reason_code,
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False


def _trusted_execution_attempt_ref(
    *,
    tenant_id: str | None,
    workflow_id: str,
    execution_attempt_id: str | None,
) -> str | None:
    """
    Derive pseudonymous execution-attempt correlation only when
    the authoritative workflow state contains a tenant and exact
    execution-attempt identifier.

    Legacy tenant-unbound workflows retain authoritative workflow
    correlation but deliberately omit execution_attempt_ref.
    """

    if tenant_id is None:
        return None

    if execution_attempt_id is None:
        return None

    return build_execution_attempt_ref(
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        execution_attempt_id=execution_attempt_id,
    )


def emit_workflow_execution_claimed_security_event(
    *,
    tenant_id: str | None,
    workflow_id: str,
    execution_attempt_id: str | None,
) -> bool:
    """
    Observe a successful authoritative workflow execution claim.

    Inputs must come from the WorkflowResult returned by the
    authoritative claim operation, never directly from request
    parameters.
    """

    try:
        execution_attempt_ref = (
            _trusted_execution_attempt_ref(
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                execution_attempt_id=
                    execution_attempt_id,
            )
        )

        event = SecurityEvent(
            event_type=(
                SecurityEventType
                .WORKFLOW_EXECUTION_CLAIMED
            ),
            severity=SecuritySeverity.INFO,
            outcome=SecurityOutcome.ALLOWED,
            source_component=(
                SecuritySourceComponent.EXECUTION
            ),
            tenant_id=tenant_id,
            workflow_id=workflow_id,
            execution_attempt_ref=
                execution_attempt_ref,
            resource_type=(
                SecurityResourceType
                .EXECUTION_ATTEMPT
            ),
            action=SecurityAction.CLAIM_EXECUTION,
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False


def emit_workflow_needs_review_security_event(
    *,
    tenant_id: str | None,
    workflow_id: str,
    execution_attempt_id: str | None,
) -> bool:
    """
    Observe an authoritative successful transition into
    NEEDS_REVIEW.

    The raw execution_attempt_id is used only to derive the
    pseudonymous correlation reference and is never emitted.
    """

    try:
        execution_attempt_ref = (
            _trusted_execution_attempt_ref(
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                execution_attempt_id=
                    execution_attempt_id,
            )
        )

        event = SecurityEvent(
            event_type=(
                SecurityEventType
                .WORKFLOW_NEEDS_REVIEW
            ),
            severity=SecuritySeverity.HIGH,
            outcome=(
                SecurityOutcome.REVIEW_REQUIRED
            ),
            source_component=(
                SecuritySourceComponent.EXECUTION
            ),
            tenant_id=tenant_id,
            workflow_id=workflow_id,
            execution_attempt_ref=
                execution_attempt_ref,
            resource_type=(
                SecurityResourceType
                .EXECUTION_ATTEMPT
            ),
            action=(
                SecurityAction.TRANSITION_WORKFLOW
            ),
            reason_code=(
                SecurityReasonCode.NEEDS_REVIEW
            ),
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False


def emit_workflow_stale_processing_detected_security_event(
    *,
    tenant_id: str | None,
    workflow_id: str,
    execution_attempt_id: str | None,
) -> bool:
    """
    Observe authoritative stale execution state after the stale
    recovery operation has established the condition and committed
    its transition.

    This event does not perform recovery or authorize a retry.
    """

    try:
        execution_attempt_ref = (
            _trusted_execution_attempt_ref(
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                execution_attempt_id=
                    execution_attempt_id,
            )
        )

        event = SecurityEvent(
            event_type=(
                SecurityEventType
                .WORKFLOW_STALE_PROCESSING_DETECTED
            ),
            severity=SecuritySeverity.HIGH,
            outcome=(
                SecurityOutcome.REVIEW_REQUIRED
            ),
            source_component=(
                SecuritySourceComponent.EXECUTION
            ),
            tenant_id=tenant_id,
            workflow_id=workflow_id,
            execution_attempt_ref=
                execution_attempt_ref,
            resource_type=(
                SecurityResourceType
                .EXECUTION_ATTEMPT
            ),
            action=SecurityAction.RECONCILE,
            reason_code=(
                SecurityReasonCode
                .STALE_EXECUTION_ATTEMPT
            ),
        )

        return _emit_best_effort(
            event
        )

    except Exception as exc:
        _report_emission_failure(exc)

        return False
