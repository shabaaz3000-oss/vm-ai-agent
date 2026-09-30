from __future__ import annotations

import inspect
import json

from pathlib import Path

import pytest

from fastapi.testclient import (
    TestClient,
)

import app.api as api_module
import app.api_security_context as api_context

from app.api import app

from app.auth import Principal

from app.models import (
    AIAnalysis,
    RiskResult,
    TicketDraft,
    WorkflowResult,
    WorkflowSecurity,
)

from app.providers.servicenow_client import (
    ServiceNowClientError,
)

from app.tools.registry import (
    get_llm_visible_tools,
)


ANALYST_TOKEN = (
    "analyst-secret-token"
)

APPROVER_TOKEN = (
    "approver-secret-token"
)

WORKFLOW_ID = (
    "WF-API-SNOW0001"
)

OLD_ATTEMPT = (
    "EXEC-API00001"
)


client = TestClient(
    app
)


@pytest.fixture(autouse=True)
def isolated_environment(
    monkeypatch,
):

    monkeypatch.setenv(
        "VM_AI_ANALYST_TOKEN",
        ANALYST_TOKEN,
    )

    monkeypatch.setenv(
        "VM_AI_APPROVER_TOKEN",
        APPROVER_TOKEN,
    )

    monkeypatch.setenv(
        "VM_AI_API_TENANT_BINDINGS",
        json.dumps(
            {
                "api-analyst":
                    "tenant-alpha",

                "api-approver":
                    "tenant-alpha",
            }
        ),
    )


def analyst_headers():

    return {
        "Authorization":
            f"Bearer {ANALYST_TOKEN}"
    }


def approver_headers():

    return {
        "Authorization":
            f"Bearer {APPROVER_TOKEN}"
    }


def result(
    *,
    status=
        "TICKET_CREATED",

    ticket_id=
        "INC0012345",
):

    return WorkflowResult(
        workflow_id=
            WORKFLOW_ID,

        tenant_id=
            "tenant-alpha",

        status=
            status,

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
                ],
            ),

        security=
            WorkflowSecurity(
                prompt_injection_detected=
                    False,

                human_review_required=
                    True,
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

        execution_attempt_id=
            OLD_ATTEMPT,

        ticket_id=
            ticket_id,
    )


def test_api_context_builder_exposes_no_raw_tenant_or_session():

    signature = inspect.signature(
        api_context
        .build_api_security_context
    )

    assert set(
        signature.parameters
    ) == {
        "principal",
    }

    assert (
        "tenant_id"
        not in signature.parameters
    )

    assert (
        "session_id"
        not in signature.parameters
    )


def test_api_context_uses_server_owned_tenant_binding():

    principal = Principal(
        username=
            "api-approver",

        role=
            "APPROVER",

        retrieval_access=
            "standard",
    )

    context = (
        api_context
        .build_api_security_context(
            principal
        )
    )

    assert (
        context.principal_id
        == "api-approver"
    )

    assert (
        context.role
        == "APPROVER"
    )

    assert (
        context.tenant_id
        == "tenant-alpha"
    )

    assert (
        context.session_id
        .startswith(
            "api-"
        )
    )


def test_unmapped_principal_fails_closed(
    monkeypatch,
):

    monkeypatch.setenv(
        "VM_AI_API_TENANT_BINDINGS",
        json.dumps(
            {
                "different-principal":
                    "tenant-alpha",
            }
        ),
    )

    principal = Principal(
        username=
            "api-approver",

        role=
            "APPROVER",

        retrieval_access=
            "standard",
    )

    with pytest.raises(
        api_context.APITenantBindingError
    ):

        api_context \
            .build_api_security_context(
                principal
            )


def test_malformed_binding_configuration_fails_closed(
    monkeypatch,
):

    monkeypatch.setenv(
        "VM_AI_API_TENANT_BINDINGS",
        "{bad-json",
    )

    with pytest.raises(
        api_context
        .APIContextConfigurationError
    ):

        api_context \
            .load_api_tenant_bindings()


def test_unnormalized_binding_configuration_is_rejected(
    monkeypatch,
):

    monkeypatch.setenv(
        "VM_AI_API_TENANT_BINDINGS",
        json.dumps(
            {
                "api-approver":
                    " tenant-alpha",
            }
        ),
    )

    with pytest.raises(
        api_context
        .APIContextConfigurationError
    ):

        api_context \
            .load_api_tenant_bindings()


def test_resolution_route_requires_authentication():

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        )
    )

    assert (
        response.status_code
        == 401
    )


def test_analyst_cannot_use_resolution_route():

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            analyst_headers(),
    )

    assert (
        response.status_code
        == 403
    )

    assert (
        "approver role"
        in response.json()[
            "detail"
        ].lower()
    )


def test_approver_route_derives_trusted_context_and_ignores_body(
    monkeypatch,
):

    captured = {}

    def fake_resolve(
        workflow_id,
        *,
        security_context,
    ):

        captured[
            "workflow_id"
        ] = workflow_id

        captured[
            "security_context"
        ] = security_context

        return result()

    monkeypatch.setattr(
        api_module,
        "resolve_servicenow_workflow",
        fake_resolve,
    )

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            approver_headers(),

        json={
            "outcome":
                "CONFIRMED",

            "tenant_id":
                "tenant-attacker",

            "correlation_id":
                "attacker-controlled",

            "ticket_id":
                "INC9999999",

            "sys_id":
                (
                    "ffffffff"
                    "ffffffff"
                    "ffffffff"
                    "ffffffff"
                ),

            "query":
                "active=true^ORpriority=1",
        },
    )

    assert (
        response.status_code
        == 200
    )

    assert (
        captured[
            "workflow_id"
        ]
        == WORKFLOW_ID
    )

    trusted = captured[
        "security_context"
    ]

    assert (
        trusted.principal_id
        == "api-approver"
    )

    assert (
        trusted.role
        == "APPROVER"
    )

    assert (
        trusted.tenant_id
        == "tenant-alpha"
    )

    assert (
        trusted.tenant_id
        != "tenant-attacker"
    )

    assert (
        trusted.session_id
        .startswith(
            "api-"
        )
    )


def test_openapi_contract_has_no_request_body():

    schema = app.openapi()

    operation = (
        schema[
            "paths"
        ][
            (
                "/workflows/"
                "{workflow_id}/"
                "servicenow-resolution"
            )
        ][
            "post"
        ]
    )

    assert (
        "requestBody"
        not in operation
    )


def test_unmapped_approver_is_denied_before_resolution(
    monkeypatch,
):

    monkeypatch.setenv(
        "VM_AI_API_TENANT_BINDINGS",
        json.dumps(
            {
                "someone-else":
                    "tenant-alpha",
            }
        ),
    )

    called = {
        "value":
            False,
    }

    def should_not_run(
        *args,
        **kwargs,
    ):

        called[
            "value"
        ] = True

        raise AssertionError(
            "Resolution engine must not run."
        )

    monkeypatch.setattr(
        api_module,
        "resolve_servicenow_workflow",
        should_not_run,
    )

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            approver_headers(),
    )

    assert (
        response.status_code
        == 403
    )

    assert (
        called[
            "value"
        ]
        is False
    )


def test_missing_binding_configuration_returns_503(
    monkeypatch,
):

    monkeypatch.delenv(
        "VM_AI_API_TENANT_BINDINGS",
        raising=False,
    )

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            approver_headers(),
    )

    assert (
        response.status_code
        == 503
    )


def test_unknown_workflow_returns_404(
    monkeypatch,
):

    def missing(
        *args,
        **kwargs,
    ):

        raise KeyError(
            WORKFLOW_ID
        )

    monkeypatch.setattr(
        api_module,
        "resolve_servicenow_workflow",
        missing,
    )

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            approver_headers(),
    )

    assert (
        response.status_code
        == 404
    )

    assert (
        response.json()[
            "detail"
        ]
        == "Workflow not found."
    )


def test_resolution_permission_failure_returns_409(
    monkeypatch,
):

    def denied(
        *args,
        **kwargs,
    ):

        raise PermissionError(
            "Workflow remains NEEDS_REVIEW."
        )

    monkeypatch.setattr(
        api_module,
        "resolve_servicenow_workflow",
        denied,
    )

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            approver_headers(),
    )

    assert (
        response.status_code
        == 409
    )


def test_servicenow_lookup_failure_returns_502(
    monkeypatch,
):

    def external_failure(
        *args,
        **kwargs,
    ):

        raise ServiceNowClientError(
            "external failure"
        )

    monkeypatch.setattr(
        api_module,
        "resolve_servicenow_workflow",
        external_failure,
    )

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            approver_headers(),
    )

    assert (
        response.status_code
        == 502
    )

    assert (
        response.json()[
            "detail"
        ]
        == (
            "ServiceNow reconciliation "
            "lookup failed."
        )
    )


def test_resolution_audit_uses_nonsecret_session_correlation(
    monkeypatch,
):

    events = []

    monkeypatch.setattr(
        api_module,
        "resolve_servicenow_workflow",
        lambda *args, **kwargs:
            result(),
    )

    monkeypatch.setattr(
        api_module,
        "log_event",
        lambda event_type, details=None:
            events.append(
                (
                    event_type,
                    details or {},
                )
            ),
    )

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            approver_headers(),
    )

    assert (
        response.status_code
        == 200
    )

    event_types = [
        item[
            0
        ]
        for item in events
    ]

    assert (
        "SERVICENOW_RECONCILIATION_REQUESTED"
        in event_types
    )

    assert (
        "SERVICENOW_RECONCILIATION_RESOLVED"
        in event_types
    )

    for (
        event_type,
        details,
    ) in events:

        if not event_type.startswith(
            "SERVICENOW_RECONCILIATION_"
        ):

            continue

        assert (
            "session_id"
            not in details
        )

        serialized = json.dumps(
            details
        ).lower()

        assert (
            "password"
            not in serialized
        )

        assert (
            "authorization"
            not in serialized
        )

    requested = next(
        details
        for (
            event_type,
            details,
        ) in events
        if event_type
        == "SERVICENOW_RECONCILIATION_REQUESTED"
    )

    assert (
        requested[
            "principal_id"
        ]
        == "api-approver"
    )

    assert (
        requested[
            "tenant_id"
        ]
        == "tenant-alpha"
    )

    assert (
        requested[
            "session_correlation_id"
        ]
    )


def test_permission_failure_emits_denied_audit(
    monkeypatch,
):

    events = []

    monkeypatch.setattr(
        api_module,
        "resolve_servicenow_workflow",
        lambda *args, **kwargs:
            (
                _ for _
                in ()
            ).throw(
                PermissionError(
                    "denied"
                )
            ),
    )

    monkeypatch.setattr(
        api_module,
        "log_event",
        lambda event_type, details=None:
            events.append(
                event_type
            ),
    )

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            approver_headers(),
    )

    assert (
        response.status_code
        == 409
    )

    assert (
        "SERVICENOW_RECONCILIATION_DENIED"
        in events
    )


def test_external_failure_emits_failed_audit(
    monkeypatch,
):

    events = []

    monkeypatch.setattr(
        api_module,
        "resolve_servicenow_workflow",
        lambda *args, **kwargs:
            (
                _ for _
                in ()
            ).throw(
                ServiceNowClientError(
                    "external failure"
                )
            ),
    )

    monkeypatch.setattr(
        api_module,
        "log_event",
        lambda event_type, details=None:
            events.append(
                event_type
            ),
    )

    response = client.post(
        (
            "/workflows/"
            f"{WORKFLOW_ID}/"
            "servicenow-resolution"
        ),

        headers=
            approver_headers(),
    )

    assert (
        response.status_code
        == 502
    )

    assert (
        "SERVICENOW_RECONCILIATION_FAILED"
        in events
    )


def test_resolution_is_not_llm_visible():

    names = {
        spec.name
        for spec in
        get_llm_visible_tools()
    }

    assert (
        "servicenow_resolution"
        not in names
    )

    assert (
        "resolve_servicenow_workflow"
        not in names
    )


def test_resolution_is_not_mcp_exposed():

    source = (
        Path(
            "app/mcp_server.py"
        )
        .read_text(
            encoding="utf-8-sig",
        )
    )

    assert (
        "resolve_servicenow_workflow"
        not in source
    )

    assert (
        "servicenow-resolution"
        not in source
    )


def test_resolution_is_not_registered_as_model_tool():

    registry_source = (
        Path(
            "app/tools/registry.py"
        )
        .read_text(
            encoding="utf-8-sig",
        )
    )

    openai_source = (
        Path(
            "app/tools/openai_tools.py"
        )
        .read_text(
            encoding="utf-8-sig",
        )
    )

    for source in (
        registry_source,
        openai_source,
    ):

        assert (
            "resolve_servicenow_workflow"
            not in source
        )

        assert (
            "servicenow-resolution"
            not in source
        )
