from __future__ import annotations

import inspect

import pytest

import app.execution as execution
import app.tools.ticketing as ticketing_tool
import app.workflow_store as workflow_store

from app.auth import Principal

from app.models import (
    AIAnalysis,
    RiskResult,
    TicketDraft,
    WorkflowResult,
    WorkflowSecurity,
)

from app.security_context import SecurityContext

from app.workflow_tenant import (
    bind_workflow_tenant,
)


def context(
    *,
    tenant_id="tenant-alpha",
    principal_id="approver-alpha",
    role="APPROVER",
):

    return SecurityContext(
        principal_id=principal_id,
        role=role,
        retrieval_access="standard",
        tenant_id=tenant_id,
        session_id=(
            "session-"
            + principal_id
            + "-"
            + tenant_id
            + "-"
            + role.lower()
        ),
    )


def workflow(
    *,
    workflow_id="WF-TENANT0002",
):

    return WorkflowResult(
        workflow_id=workflow_id,
        status="AWAITING_APPROVAL",
        finding_id="FIND-0001",
        asset_name="internet-web-01",
        cve="CVE-2026-12345",

        risk=RiskResult(
            score=100,
            rating="CRITICAL",
            sla_hours=24,
            factors=[
                "Listed in CISA KEV",
            ],
        ),

        security=WorkflowSecurity(
            prompt_injection_detected=False,
            human_review_required=True,
        ),

        analysis=AIAnalysis(
            executive_summary=
                "Critical vulnerability.",

            rationale=[
                "Critical risk.",
            ],

            remediation=
                "Deploy approved patch.",

            compensating_controls=[
                "Maintain WAF.",
            ],

            validation_steps=[
                "Run authenticated rescan.",
            ],

            confidence="HIGH",

            requires_human_review=True,

            ticket_summary=
                "Remediate vulnerability.",

            ticket_description=
                "Validated ticket draft.",
        ),

        ticket=TicketDraft(
            short_description=
                "CRITICAL vulnerability",

            priority="P1",

            asset_name=
                "internet-web-01",

            cve="CVE-2026-12345",

            assignment_group=
                "Vulnerability Management",

            risk_rating="CRITICAL",

            risk_score=100,

            sla_hours=24,

            description=
                "Validated ticket.",

            remediation=
                "Deploy approved patch.",

            validation_steps=[
                "Run authenticated rescan.",
            ],
        ),
    )


def bound(
    *,
    tenant_id="tenant-alpha",
    workflow_id="WF-TENANT0002",
):

    return bind_workflow_tenant(
        workflow(
            workflow_id=workflow_id,
        ),
        security_context=context(
            tenant_id=tenant_id,
        ),
    )


def db(
    tmp_path,
    monkeypatch,
    filename,
):

    monkeypatch.setenv(
        "VM_AI_DB_PATH",
        str(
            tmp_path
            / filename
        ),
    )


def test_bound_workflow_requires_context_before_claim(
    tmp_path,
    monkeypatch,
):

    db(
        tmp_path,
        monkeypatch,
        "missing-context.db",
    )

    result = bound()

    workflow_store.save_workflow(
        result
    )

    with pytest.raises(
        PermissionError,
        match="requires trusted security context",
    ):
        workflow_store \
            .claim_workflow_for_execution(
                result.workflow_id
            )

    stored = (
        workflow_store.get_workflow(
            result.workflow_id
        )
    )

    assert (
        stored.status
        == "AWAITING_APPROVAL"
    )

    assert (
        stored.execution_attempt_id
        is None
    )


def test_cross_tenant_claim_fails_before_processing(
    tmp_path,
    monkeypatch,
):

    db(
        tmp_path,
        monkeypatch,
        "cross-tenant.db",
    )

    result = bound(
        tenant_id="tenant-alpha",
    )

    workflow_store.save_workflow(
        result
    )

    with pytest.raises(
        PermissionError,
        match="different tenant",
    ):
        workflow_store \
            .claim_workflow_for_execution(
                result.workflow_id,
                security_context=context(
                    tenant_id=
                        "tenant-bravo",
                ),
            )

    stored = (
        workflow_store.get_workflow(
            result.workflow_id
        )
    )

    assert (
        stored.status
        == "AWAITING_APPROVAL"
    )

    assert (
        stored.execution_attempt_id
        is None
    )


def test_matching_tenant_can_claim(
    tmp_path,
    monkeypatch,
):

    db(
        tmp_path,
        monkeypatch,
        "matching.db",
    )

    result = bound()

    workflow_store.save_workflow(
        result
    )

    claimed = (
        workflow_store
        .claim_workflow_for_execution(
            result.workflow_id,
            security_context=
                context(),
        )
    )

    assert claimed.status == "PROCESSING"

    assert (
        claimed.tenant_id
        == "tenant-alpha"
    )


def test_legacy_unbound_claim_still_works(
    tmp_path,
    monkeypatch,
):

    db(
        tmp_path,
        monkeypatch,
        "legacy.db",
    )

    result = workflow()

    workflow_store.save_workflow(
        result
    )

    claimed = (
        workflow_store
        .claim_workflow_for_execution(
            result.workflow_id
        )
    )

    assert claimed.status == "PROCESSING"

    assert claimed.tenant_id is None


def test_principal_mismatch_blocks_before_atomic_claim(
    monkeypatch,
):

    called = False

    def fake_claim(
        *args,
        **kwargs,
    ):
        nonlocal called
        called = True
        raise AssertionError(
            "Atomic claim must not occur."
        )

    monkeypatch.setattr(
        execution,
        "claim_workflow_for_execution",
        fake_claim,
    )

    with pytest.raises(
        PermissionError,
        match="principal mismatch",
    ):
        execution \
            .claim_and_execute_workflow(
                workflow_id=
                    "WF-TENANT0002",

                approved_by=
                    "approver-alpha",

                security_context=
                    context(
                        principal_id=
                            "approver-bravo",
                    ),
            )

    assert called is False


def test_non_approver_context_blocks_before_claim(
    monkeypatch,
):

    called = False

    def fake_claim(
        *args,
        **kwargs,
    ):
        nonlocal called
        called = True
        raise AssertionError(
            "Atomic claim must not occur."
        )

    monkeypatch.setattr(
        execution,
        "claim_workflow_for_execution",
        fake_claim,
    )

    with pytest.raises(
        PermissionError,
        match="APPROVER security context",
    ):
        execution \
            .claim_and_execute_workflow(
                workflow_id=
                    "WF-TENANT0002",

                approved_by=
                    "analyst-alpha",

                security_context=
                    context(
                        principal_id=
                            "analyst-alpha",

                        role="ANALYST",
                    ),
            )

    assert called is False


def test_cross_tenant_execution_never_reaches_provider(
    tmp_path,
    monkeypatch,
):

    db(
        tmp_path,
        monkeypatch,
        "cross-exec.db",
    )

    result = bound(
        tenant_id="tenant-alpha",
    )

    workflow_store.save_workflow(
        result
    )

    provider_called = False

    def fake_provider(
        *,
        ticket,
        approval,
    ):
        nonlocal provider_called
        provider_called = True
        raise AssertionError(
            "Provider must not be reached."
        )

    monkeypatch.setattr(
        execution,
        "_create_ticket_with_selected_provider",
        fake_provider,
    )

    with pytest.raises(
        PermissionError,
        match="different tenant",
    ):
        execution \
            .claim_and_execute_workflow(
                workflow_id=
                    result.workflow_id,

                approved_by=
                    "approver-bravo",

                security_context=
                    context(
                        tenant_id=
                            "tenant-bravo",

                        principal_id=
                            "approver-bravo",
                    ),
            )

    assert provider_called is False

    stored = (
        workflow_store.get_workflow(
            result.workflow_id
        )
    )

    assert (
        stored.status
        == "AWAITING_APPROVAL"
    )


def test_direct_bound_execution_requires_context(
    monkeypatch,
):

    provider_called = False

    def fake_provider(
        *,
        ticket,
        approval,
    ):
        nonlocal provider_called
        provider_called = True

    monkeypatch.setattr(
        execution,
        "_create_ticket_with_selected_provider",
        fake_provider,
    )

    with pytest.raises(
        PermissionError,
        match="requires trusted security context",
    ):
        execution \
            .approve_and_execute_workflow(
                result=bound(),
                approved_by=
                    "approver-alpha",
            )

    assert provider_called is False


def test_tool_forwards_trusted_context(
    monkeypatch,
):

    principal = Principal(
        username="approver-alpha",
        role="APPROVER",
    )

    security_context = context()

    completed_data = (
        bound()
        .model_dump()
    )

    completed_data.update(
        {
            "status":
                "TICKET_CREATED",

            "approval_id":
                "APR-TEST0001",

            "ticket_id":
                "INC0012345",
        }
    )

    completed = (
        WorkflowResult
        .model_validate(
            completed_data
        )
    )

    captured = {}

    def fake_execute(
        *,
        workflow_id,
        approved_by,
        security_context,
    ):
        captured["workflow_id"] = workflow_id
        captured["approved_by"] = approved_by
        captured["security_context"] = (
            security_context
        )
        return completed

    monkeypatch.setattr(
        ticketing_tool,
        "claim_and_execute_workflow",
        fake_execute,
    )


    monkeypatch.setattr(
        ticketing_tool,
        "log_event",
        lambda *args, **kwargs: None,
    )

    result = (
        ticketing_tool
        .execute_ticket_workflow(
            principal=principal,
            workflow_id=
                "WF-TENANT0002",
            security_context=
                security_context,
        )
    )

    assert result == completed

    assert (
        captured["security_context"]
        is security_context
    )


def test_execution_surfaces_accept_no_raw_tenant_authority():

    claim_signature = inspect.signature(
        execution
        .claim_and_execute_workflow
    )

    tool_signature = inspect.signature(
        ticketing_tool
        .execute_ticket_workflow
    )

    assert set(
        claim_signature.parameters
    ) == {
        "workflow_id",
        "approved_by",
        "security_context",
    }

    assert (
        claim_signature.parameters[
            "security_context"
        ].kind
        is inspect.Parameter.KEYWORD_ONLY
    )

    assert (
        tool_signature.parameters[
            "security_context"
        ].kind
        is inspect.Parameter.KEYWORD_ONLY
    )

    for signature in (
        claim_signature,
        tool_signature,
    ):
        for forbidden in (
            "tenant",
            "tenant_id",
            "assignment_group",
            "provider",
            "instance_url",
        ):
            assert (
                forbidden
                not in signature.parameters
            )
