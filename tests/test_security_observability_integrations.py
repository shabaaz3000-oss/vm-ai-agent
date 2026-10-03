from __future__ import annotations

import logging
from pathlib import Path

import pytest

import app.security_observability_integrations as integrations
from app.security_observability import (
    SecurityEventType,
    SecurityOutcome,
    SecurityReasonCode,
    SecuritySeverity,
)


def _capture_events(
    monkeypatch: pytest.MonkeyPatch,
):
    events = []

    def capture(event):
        events.append(event)
        return True

    monkeypatch.setattr(
        integrations,
        "_emit_best_effort",
        capture,
    )

    return events


def test_api_tenant_binding_denial_is_safe(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_api_tenant_binding_denied_security_event()
        is True
    )

    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .IDENTITY_TENANT_BINDING_DENIED
    )

    assert (
        event.outcome
        is SecurityOutcome.DENIED
    )

    assert (
        event.reason_code
        is SecurityReasonCode.TENANT_UNBOUND
    )

    payload = event.to_dict()

    # No tenant exists at this decision point.
    assert "tenant_id" not in payload

    # Raw authenticated principal identifiers are not
    # introduced before pseudonymous principal correlation.
    assert "principal_ref" not in payload
    assert "username" not in payload


def test_rag_allowed_uses_authoritative_tenant(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_retrieval_authorization_security_event(
            allowed=True,
            reason="allowed",
            tenant_id="tenant-alpha",
        )
        is True
    )

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .RAG_RETRIEVAL_ALLOWED
    )

    assert (
        event.outcome
        is SecurityOutcome.ALLOWED
    )

    assert (
        event.severity
        is SecuritySeverity.INFO
    )

    assert event.tenant_id == "tenant-alpha"
    assert event.reason_code is None


def test_cross_tenant_rag_denial_maps_to_bounded_reason(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    integrations.emit_retrieval_authorization_security_event(
        allowed=False,
        reason="tenant_mismatch",
        tenant_id="tenant-alpha",
    )

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .RAG_RETRIEVAL_DENIED
    )

    assert (
        event.reason_code
        is SecurityReasonCode.CROSS_TENANT
    )

    assert (
        event.severity
        is SecuritySeverity.HIGH
    )

    payload = event.to_dict()

    assert (
        "tenant_mismatch"
        not in payload.values()
    )


@pytest.mark.parametrize(
    "legacy_reason",
    [
        "missing_tenant_scope",
        "principal_acl_denied",
        "group_acl_denied",
    ],
)
def test_document_acl_denials_are_normalized(
    monkeypatch: pytest.MonkeyPatch,
    legacy_reason: str,
):
    events = _capture_events(
        monkeypatch
    )

    integrations.emit_retrieval_authorization_security_event(
        allowed=False,
        reason=legacy_reason,
        tenant_id="tenant-alpha",
    )

    assert (
        events[0].reason_code
        is SecurityReasonCode
        .DOCUMENT_ACL_DENIED
    )


@pytest.mark.parametrize(
    "legacy_reason",
    [
        "group_membership_unavailable",
        "invalid_group_authority",
        "classification_denied",
        "invalid_retrieval_access",
        "invalid_authorization_metadata",
        "future_unknown_reason",
    ],
)
def test_other_rag_denials_use_bounded_reason(
    monkeypatch: pytest.MonkeyPatch,
    legacy_reason: str,
):
    events = _capture_events(
        monkeypatch
    )

    integrations.emit_retrieval_authorization_security_event(
        allowed=False,
        reason=legacy_reason,
        tenant_id="tenant-alpha",
    )

    event = events[0]

    assert (
        event.reason_code
        is SecurityReasonCode
        .RETRIEVAL_ACL_DENIED
    )

    assert (
        legacy_reason
        not in event.to_dict().values()
    )


def test_direct_prompt_block_omits_sensitive_content(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_direct_prompt_injection_blocked_security_event()
        is True
    )

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .AI_DIRECT_PROMPT_INJECTION_BLOCKED
    )

    assert (
        event.outcome
        is SecurityOutcome.BLOCKED
    )

    assert (
        event.reason_code
        is SecurityReasonCode
        .PROMPT_INJECTION_DETECTED
    )

    payload = event.to_dict()

    for forbidden in (
        "prompt",
        "matches",
        "username",
        "role",
        "tool_output",
    ):
        assert forbidden not in payload


def test_emission_failure_preserves_security_path(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    def fail():
        raise RuntimeError(
            "access_token=DO-NOT-SURFACE"
        )

    monkeypatch.setattr(
        integrations,
        "build_existing_audit_security_event_sink",
        fail,
    )

    caplog.set_level(
        logging.ERROR
    )

    result = (
        integrations
        .emit_direct_prompt_injection_blocked_security_event()
    )

    assert result is False

    assert (
        "existing security decision preserved"
        in caplog.text
    )

    assert (
        "DO-NOT-SURFACE"
        not in caplog.text
    )

    assert (
        "access_token"
        not in caplog.text
    )


def test_production_wiring_exists():
    api_text = Path(
        "app/api_security_context.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    retriever_text = Path(
        "app/retriever.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    agent_text = Path(
        "app/agent.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        "emit_api_tenant_binding_denied_"
        "security_event()"
        in api_text
    )

    assert (
        "emit_retrieval_authorization_"
        "security_event("
        in retriever_text
    )

    assert (
        "emit_direct_prompt_injection_"
        "blocked_security_event()"
        in agent_text
    )


def test_tool_output_suspicion_is_not_falsely_reported_as_block():
    agent_text = Path(
        "app/agent.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        "AGENT_TOOL_PROMPT_INJECTION_SUSPECTED"
        in agent_text
    )

    # Step 50.2C2 intentionally does not attach the canonical
    # "...blocked" event to this legacy suspicion point.
    suspected_index = agent_text.index(
        "AGENT_TOOL_PROMPT_INJECTION_SUSPECTED"
    )

    following = agent_text[
        suspected_index:
        suspected_index + 700
    ]

    assert (
        "emit_direct_prompt_injection_"
        "blocked_security_event"
        not in following
    )



def test_tool_output_prompt_suspicion_emits_truthful_canonical_event(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_tool_output_prompt_injection_suspected_security_event()
        is True
    )

    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .AI_TOOL_OUTPUT_PROMPT_INJECTION_SUSPECTED
    )

    assert (
        event.outcome
        is SecurityOutcome.AMBIGUOUS
    )

    assert (
        event.severity
        is SecuritySeverity.MEDIUM
    )

    payload = event.to_dict()

    assert (
        payload["resource_type"]
        == "mcp_tool"
    )

    for forbidden in (
        "prompt",
        "matches",
        "username",
        "role",
        "tool",
        "tool_output",
        "result",
    ):
        assert forbidden not in payload


def test_tool_output_suspicion_production_wiring_is_not_block_event():
    agent_text = Path(
        "app/agent.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    legacy_index = agent_text.index(
        "AGENT_TOOL_PROMPT_INJECTION_SUSPECTED"
    )

    following = agent_text[
        legacy_index:
        legacy_index + 1000
    ]

    assert (
        "emit_tool_output_prompt_injection_"
        "suspected_security_event()"
        in following
    )

    assert (
        "AI_TOOL_OUTPUT_PROMPT_INJECTION_BLOCKED"
        not in following
    )

    assert (
        "emit_direct_prompt_injection_"
        "blocked_security_event()"
        not in following
    )


def test_mcp_session_validation_missing_omits_untrusted_tenant(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    result = (
        integrations
        .emit_mcp_session_validation_failed_security_event(
            reason="session_not_found",
            tenant_id="caller-controlled-tenant",
        )
    )

    assert result is True
    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .MCP_SESSION_VALIDATION_FAILED
    )

    assert (
        event.reason_code
        is SecurityReasonCode.SESSION_MISSING
    )

    assert event.tenant_id is None
    assert event.outcome is SecurityOutcome.DENIED

    payload = event.to_dict()

    assert "tenant_id" not in payload
    assert "session_ref" not in payload
    assert "principal_ref" not in payload


@pytest.mark.parametrize(
    (
        "reason",
        "expected_reason",
        "expected_severity",
    ),
    [
        (
            "principal_mismatch",
            SecurityReasonCode
            .SECURITY_BINDING_MISMATCH,
            SecuritySeverity.HIGH,
        ),
        (
            "tenant_mismatch",
            SecurityReasonCode.CROSS_TENANT,
            SecuritySeverity.HIGH,
        ),
        (
            "session_revoked",
            SecurityReasonCode.SESSION_REVOKED,
            SecuritySeverity.MEDIUM,
        ),
        (
            "session_expired",
            SecurityReasonCode.SESSION_EXPIRED,
            SecuritySeverity.MEDIUM,
        ),
    ],
)
def test_mcp_session_validation_failure_uses_bounded_reason(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_reason: SecurityReasonCode,
    expected_severity: SecuritySeverity,
):
    events = _capture_events(
        monkeypatch
    )

    result = (
        integrations
        .emit_mcp_session_validation_failed_security_event(
            reason=reason,
            tenant_id="tenant-alpha",
        )
    )

    assert result is True
    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .MCP_SESSION_VALIDATION_FAILED
    )

    assert (
        event.reason_code
        is expected_reason
    )

    assert (
        event.severity
        is expected_severity
    )

    assert (
        event.tenant_id
        == "tenant-alpha"
    )

    payload = event.to_dict()

    assert "session_ref" not in payload
    assert "principal_ref" not in payload


def test_mcp_session_validation_unknown_reason_fails_observability_only(
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(
        logging.ERROR
    )

    result = (
        integrations
        .emit_mcp_session_validation_failed_security_event(
            reason="future_unknown_reason",
            tenant_id="tenant-alpha",
        )
    )

    assert result is False

    assert (
        "existing security decision preserved"
        in caplog.text
    )


def test_mcp_session_revoked_event_uses_authoritative_tenant(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    result = (
        integrations
        .emit_mcp_session_revoked_security_event(
            tenant_id="tenant-alpha",
        )
    )

    assert result is True
    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .MCP_SESSION_REVOKED
    )

    assert (
        event.outcome
        is SecurityOutcome.REVOKED
    )

    assert (
        event.tenant_id
        == "tenant-alpha"
    )

    payload = event.to_dict()

    assert "session_ref" not in payload
    assert "principal_ref" not in payload


def test_mcp_session_production_wiring_preserves_legacy_events():
    text = Path(
        "app/mcp_session.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        text.count(
            "emit_mcp_session_validation_failed_"
            "security_event("
        )
        == 5
    )

    assert (
        text.count(
            "emit_mcp_session_revoked_"
            "security_event("
        )
        == 1
    )

    assert (
        text.count(
            '"MCP_SESSION_VALIDATION_BLOCKED"'
        )
        == 5
    )

    assert (
        text.count(
            '"MCP_SESSION_REVOKED"'
        )
        == 1
    )


def test_mcp_tool_invocation_allowed_uses_trusted_tenant(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_mcp_tool_invocation_allowed_security_event(
            tenant_id="tenant-alpha",
        )
        is True
    )

    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .MCP_TOOL_INVOCATION_ALLOWED
    )

    assert (
        event.outcome
        is SecurityOutcome.ALLOWED
    )

    assert (
        event.severity
        is SecuritySeverity.INFO
    )

    assert (
        event.tenant_id
        == "tenant-alpha"
    )

    payload = event.to_dict()

    assert (
        payload["source_component"]
        == "tool_dispatcher"
    )

    assert (
        payload["resource_type"]
        == "mcp_tool"
    )

    assert (
        payload["action"]
        == "invoke_tool"
    )

    assert "session_ref" not in payload
    assert "principal_ref" not in payload
    assert "tool" not in payload


@pytest.mark.parametrize(
    (
        "reason",
        "expected_reason",
        "expected_severity",
    ),
    [
        (
            "tool_not_authorized",
            SecurityReasonCode.TOOL_NOT_AUTHORIZED,
            SecuritySeverity.MEDIUM,
        ),
        (
            "security_binding_mismatch",
            SecurityReasonCode
            .SECURITY_BINDING_MISMATCH,
            SecuritySeverity.HIGH,
        ),
    ],
)
def test_mcp_tool_invocation_denied_uses_bounded_reason(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_reason: SecurityReasonCode,
    expected_severity: SecuritySeverity,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_mcp_tool_invocation_denied_security_event(
            tenant_id="tenant-alpha",
            reason=reason,
        )
        is True
    )

    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .MCP_TOOL_INVOCATION_DENIED
    )

    assert (
        event.outcome
        is SecurityOutcome.DENIED
    )

    assert (
        event.reason_code
        is expected_reason
    )

    assert (
        event.severity
        is expected_severity
    )

    payload = event.to_dict()

    assert "tool" not in payload
    assert "session_ref" not in payload
    assert "principal_ref" not in payload


def test_mcp_tool_invocation_unknown_reason_is_observability_only(
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(
        logging.ERROR
    )

    result = (
        integrations
        .emit_mcp_tool_invocation_denied_security_event(
            tenant_id="tenant-alpha",
            reason="future_unknown_reason",
        )
    )

    assert result is False

    assert (
        "existing security decision preserved"
        in caplog.text
    )


def test_mcp_session_validation_event_includes_trusted_session_ref(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_mcp_session_validation_failed_security_event(
            reason="session_revoked",
            tenant_id="tenant-alpha",
            session_ref="a1b2c3d4e5f60708",
        )
        is True
    )

    assert len(events) == 1

    payload = events[0].to_dict()

    assert (
        payload["session_ref"]
        == "a1b2c3d4e5f60708"
    )

    assert (
        payload["tenant_id"]
        == "tenant-alpha"
    )

    assert "session_id" not in payload


def test_mcp_session_missing_event_can_omit_session_ref(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_mcp_session_validation_failed_security_event(
            reason="session_not_found",
            tenant_id=None,
            session_ref=None,
        )
        is True
    )

    payload = events[0].to_dict()

    assert "session_ref" not in payload
    assert "tenant_id" not in payload


def test_mcp_session_revocation_event_includes_trusted_session_ref(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_mcp_session_revoked_security_event(
            tenant_id="tenant-alpha",
            session_ref="a1b2c3d4e5f60708",
        )
        is True
    )

    payload = events[0].to_dict()

    assert (
        payload["session_ref"]
        == "a1b2c3d4e5f60708"
    )

    assert "session_id" not in payload


def test_mcp_tool_events_include_trusted_session_ref(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_mcp_tool_invocation_allowed_security_event(
            tenant_id="tenant-alpha",
            session_ref="a1b2c3d4e5f60708",
        )
        is True
    )

    assert (
        integrations
        .emit_mcp_tool_invocation_denied_security_event(
            tenant_id="tenant-alpha",
            reason="tool_not_authorized",
            session_ref="a1b2c3d4e5f60708",
        )
        is True
    )

    assert len(events) == 2

    for event in events:
        payload = event.to_dict()

        assert (
            payload["session_ref"]
            == "a1b2c3d4e5f60708"
        )

        assert "session_id" not in payload
        assert "username" not in payload
        assert "principal_id" not in payload


def test_workflow_execution_claimed_event_uses_authoritative_correlation(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_workflow_execution_claimed_security_event(
            tenant_id="tenant-alpha",
            workflow_id="WF-12345678",
            execution_attempt_id="EXEC-DEADBEEF",
        )
        is True
    )

    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        is SecurityEventType
        .WORKFLOW_EXECUTION_CLAIMED
    )

    assert (
        event.outcome
        is SecurityOutcome.ALLOWED
    )

    payload = event.to_dict()

    assert (
        payload["tenant_id"]
        == "tenant-alpha"
    )

    assert (
        payload["workflow_id"]
        == "WF-12345678"
    )

    assert (
        payload["execution_attempt_ref"]
        .startswith(
            "EA1-"
        )
    )

    assert (
        "EXEC-DEADBEEF"
        not in payload["execution_attempt_ref"]
    )

    assert "execution_attempt_id" not in payload


def test_legacy_unbound_claim_omits_execution_attempt_ref(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_workflow_execution_claimed_security_event(
            tenant_id=None,
            workflow_id="WF-12345678",
            execution_attempt_id="EXEC-DEADBEEF",
        )
        is True
    )

    payload = events[0].to_dict()

    assert (
        payload["workflow_id"]
        == "WF-12345678"
    )

    assert "tenant_id" not in payload
    assert "execution_attempt_ref" not in payload
    assert "execution_attempt_id" not in payload


def test_workflow_needs_review_event_uses_derived_attempt_ref(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_workflow_needs_review_security_event(
            tenant_id="tenant-alpha",
            workflow_id="WF-12345678",
            execution_attempt_id="EXEC-DEADBEEF",
        )
        is True
    )

    payload = events[0].to_dict()

    assert (
        payload["event_type"]
        == "security.workflow.needs_review"
    )

    assert (
        payload["outcome"]
        == "review_required"
    )

    assert (
        payload["reason_code"]
        == "needs_review"
    )

    assert (
        payload["execution_attempt_ref"]
        .startswith(
            "EA1-"
        )
    )

    assert "execution_attempt_id" not in payload


def test_stale_processing_event_uses_derived_attempt_ref(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_workflow_stale_processing_detected_security_event(
            tenant_id="tenant-alpha",
            workflow_id="WF-12345678",
            execution_attempt_id="EXEC-DEADBEEF",
        )
        is True
    )

    payload = events[0].to_dict()

    assert (
        payload["event_type"]
        == "security.workflow.stale_processing_detected"
    )

    assert (
        payload["outcome"]
        == "review_required"
    )

    assert (
        payload["reason_code"]
        == "stale_execution_attempt"
    )

    assert (
        payload["execution_attempt_ref"]
        .startswith(
            "EA1-"
        )
    )

    assert "execution_attempt_id" not in payload


def test_workflow_execution_correlation_failure_is_observability_only(
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(
        logging.ERROR
    )

    result = (
        integrations
        .emit_workflow_execution_claimed_security_event(
            tenant_id="tenant-alpha",
            workflow_id=" WF-INVALID",
            execution_attempt_id="EXEC-DEADBEEF",
        )
    )

    assert result is False

    assert (
        "existing security decision preserved"
        in caplog.text
    )
