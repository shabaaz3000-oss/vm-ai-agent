from __future__ import annotations

import pytest

import app.workflow_store as workflow_store

from app.models import AIAnalysis
from app.models import RiskResult
from app.models import TicketDraft
from app.models import WorkflowResult
from app.models import WorkflowSecurity

from app.security_context import (
    SecurityContext,
)

from app.workflow_tenant import (
    WorkflowTenantBindingError,
    bind_workflow_tenant,
    require_workflow_tenant,
)


def make_context(
    *,
    tenant_id:
        str = "tenant-alpha",
    principal_id:
        str = "approver-alpha",
) -> SecurityContext:

    return SecurityContext(
        principal_id=
            principal_id,

        role=
            "APPROVER",

        retrieval_access=
            "standard",

        tenant_id=
            tenant_id,

        session_id=
            (
                "session-"
                + principal_id
                + "-"
                + tenant_id
            ),
    )


def make_result() -> WorkflowResult:

    return WorkflowResult(
        workflow_id=
            "WF-TENANT0001",

        status=
            "AWAITING_APPROVAL",

        finding_id=
            "FIND-0001",

        asset_name=
            "internet-web-01",

        cve=
            "CVE-2026-12345",

        risk=
            RiskResult(
                score=100,
                rating="CRITICAL",
                sla_hours=24,
                factors=[
                    "Listed in CISA KEV",
                    "Internet exposed",
                ],
            ),

        security=
            WorkflowSecurity(
                prompt_injection_detected=False,
                human_review_required=True,
            ),

        analysis=
            AIAnalysis(
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

                confidence=
                    "HIGH",

                requires_human_review=
                    True,

                ticket_summary=
                    "Remediate vulnerability.",

                ticket_description=
                    "Validated ticket draft.",
            ),

        ticket=
            TicketDraft(
                short_description=
                    "CRITICAL vulnerability",

                priority=
                    "P1",

                asset_name=
                    "internet-web-01",

                cve=
                    "CVE-2026-12345",

                assignment_group=
                    "Vulnerability Management",

                risk_rating=
                    "CRITICAL",

                risk_score=
                    100,

                sla_hours=
                    24,

                description=
                    "Validated ticket.",

                remediation=
                    "Deploy approved patch.",

                validation_steps=[
                    "Run authenticated rescan.",
                ],
            ),
    )


def test_legacy_workflow_is_explicitly_unbound():

    result = make_result()

    assert result.tenant_id is None


def test_trusted_security_context_binds_workflow_tenant():

    original = make_result()

    bound = bind_workflow_tenant(
        original,
        security_context=
            make_context(),
    )

    assert original.tenant_id is None

    assert (
        bound.tenant_id
        == "tenant-alpha"
    )


def test_binding_preserves_authoritative_ticket():

    original = make_result()

    bound = bind_workflow_tenant(
        original,
        security_context=
            make_context(),
    )

    assert (
        bound.ticket
        == original.ticket
    )

    assert (
        bound.risk
        == original.risk
    )

    assert (
        bound.workflow_id
        == original.workflow_id
    )


def test_same_tenant_revalidation_is_allowed():

    first = bind_workflow_tenant(
        make_result(),
        security_context=
            make_context(),
    )

    second = bind_workflow_tenant(
        first,
        security_context=
            make_context(
                principal_id=
                    "another-authorized-user",
            ),
    )

    assert second == first


def test_cross_tenant_rebinding_fails_closed():

    bound = bind_workflow_tenant(
        make_result(),
        security_context=
            make_context(
                tenant_id=
                    "tenant-alpha",
            ),
    )

    with pytest.raises(
        WorkflowTenantBindingError,
        match="different tenant",
    ):

        bind_workflow_tenant(
            bound,
            security_context=
                make_context(
                    tenant_id=
                        "tenant-bravo",
                ),
        )


def test_unbound_workflow_cannot_pass_tenant_gate():

    with pytest.raises(
        WorkflowTenantBindingError,
        match="does not contain trusted tenant authority",
    ):

        require_workflow_tenant(
            make_result(),
            security_context=
                make_context(),
        )


def test_matching_bound_workflow_passes_tenant_gate():

    context = make_context()

    bound = bind_workflow_tenant(
        make_result(),
        security_context=context,
    )

    assert (
        require_workflow_tenant(
            bound,
            security_context=context,
        )
        == "tenant-alpha"
    )


def test_cross_tenant_context_cannot_use_bound_workflow():

    bound = bind_workflow_tenant(
        make_result(),
        security_context=
            make_context(
                tenant_id=
                    "tenant-alpha",
            ),
    )

    with pytest.raises(
        WorkflowTenantBindingError,
        match="different tenant",
    ):

        require_workflow_tenant(
            bound,
            security_context=
                make_context(
                    tenant_id=
                        "tenant-bravo",
                ),
        )


def test_workflow_store_preserves_tenant_binding(
    tmp_path,
    monkeypatch,
):

    monkeypatch.setenv(
        "VM_AI_DB_PATH",
        str(
            tmp_path
            / "tenant-workflows.db"
        ),
    )

    bound = bind_workflow_tenant(
        make_result(),
        security_context=
            make_context(),
    )

    workflow_store.save_workflow(
        bound
    )

    retrieved = (
        workflow_store.get_workflow(
            bound.workflow_id
        )
    )

    assert (
        retrieved.tenant_id
        == "tenant-alpha"
    )

    assert retrieved == bound


def test_atomic_execution_claim_preserves_tenant_binding(
    tmp_path,
    monkeypatch,
):

    monkeypatch.setenv(
        "VM_AI_DB_PATH",
        str(
            tmp_path
            / "tenant-claim.db"
        ),
    )

    bound = bind_workflow_tenant(
        make_result(),
        security_context=
            make_context(),
    )

    workflow_store.save_workflow(
        bound
    )

    claimed = (
        workflow_store
        .claim_workflow_for_execution(
            bound.workflow_id
        )
    )

    assert (
        claimed.status
        == "PROCESSING"
    )

    assert (
        claimed.tenant_id
        == "tenant-alpha"
    )


def test_recovery_preserves_tenant_binding(
    tmp_path,
    monkeypatch,
):

    monkeypatch.setenv(
        "VM_AI_DB_PATH",
        str(
            tmp_path
            / "tenant-recovery.db"
        ),
    )

    bound = bind_workflow_tenant(
        make_result(),
        security_context=
            make_context(),
    )

    workflow_store.save_workflow(
        bound
    )

    workflow_store \
        .claim_workflow_for_execution(
            bound.workflow_id
        )

    review = (
        workflow_store
        .mark_workflow_needs_review(
            workflow_id=
                bound.workflow_id,

            reason=
                "Manual reconciliation required.",
        )
    )

    assert (
        review.status
        == "NEEDS_REVIEW"
    )

    assert (
        review.tenant_id
        == "tenant-alpha"
    )


def test_binding_api_does_not_accept_raw_tenant_argument():

    import inspect

    bind_signature = inspect.signature(
        bind_workflow_tenant
    )

    require_signature = inspect.signature(
        require_workflow_tenant
    )

    assert set(
        bind_signature.parameters
    ) == {
        "result",
        "security_context",
    }

    assert set(
        require_signature.parameters
    ) == {
        "result",
        "security_context",
    }

    for signature in (
        bind_signature,
        require_signature,
    ):

        for forbidden in (
            "tenant_id",
            "tenant",
            "principal",
            "ticket",
            "provider",
            "assignment_group",
        ):

            assert (
                forbidden
                not in signature.parameters
            )
