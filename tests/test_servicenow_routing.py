from __future__ import annotations

import inspect

import pytest

import app.execution as execution
import app.providers.servicenow_ticket_provider as servicenow_module

from app.models import TicketDraft

from app.providers.servicenow_routing import (
    ROUTING_ENVIRONMENT_VARIABLE,
    ServiceNowRoutingConfigurationError,
    ServiceNowRoutingError,
    ServiceNowRoutingPolicy,
)

from app.providers.servicenow_ticket_provider import (
    ServiceNowTicketProvider,
)

from app.providers.ticket_provider_factory import (
    TicketProviderConfigurationError,
    build_ticket_provider,
)

from app.ticket_execution_context import (
    TicketExecutionContext,
)


TENANT_ALPHA = "tenant-alpha"
TENANT_BRAVO = "tenant-bravo"

GROUP_ALPHA = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

GROUP_BRAVO = (
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)


class FakeClient:

    def __init__(
        self,
    ) -> None:

        self.payload = None

    def create_record(
        self,
        payload,
    ):

        self.payload = payload

        return {
            "number":
                "INC0012345",

            "sys_id":
                (
                    "cccccccccccccccc"
                    "cccccccccccccccc"
                ),
        }

    def close(
        self,
    ) -> None:

        return None


def ticket(
    *,
    assignment_group:
        str = "Attacker Controlled Group",
) -> TicketDraft:

    return TicketDraft(
        short_description=
            "CRITICAL vulnerability",

        priority=
            "P1",

        asset_name=
            "internet-web-01",

        cve=
            "CVE-2026-12345",

        assignment_group=
            assignment_group,

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
    )


def context(
    *,
    tenant_id:
        str = TENANT_ALPHA,
) -> TicketExecutionContext:

    return TicketExecutionContext(
        tenant_id=
            tenant_id,

        workflow_id=
            "WF-ROUTING-0001",

        execution_attempt_id=
            "EXEC-ROUTING-0001",
    )


def policy(
) -> ServiceNowRoutingPolicy:

    return ServiceNowRoutingPolicy(
        {
            TENANT_ALPHA:
                GROUP_ALPHA,

            TENANT_BRAVO:
                GROUP_BRAVO,
        }
    )


def provider(
) -> tuple[
    ServiceNowTicketProvider,
    FakeClient,
]:

    client = FakeClient()

    return (
        ServiceNowTicketProvider(
            client,
            routing_policy=
                policy(),
        ),
        client,
    )


def test_environment_policy_resolves_exact_tenant():

    configured = (
        ServiceNowRoutingPolicy
        .from_environment(
            {
                ROUTING_ENVIRONMENT_VARIABLE:
                    (
                        '{"tenant-alpha":'
                        '"AAAAAAAAAAAAAAAA'
                        'AAAAAAAAAAAAAAAA"}'
                    ),
            }
        )
    )

    assert (
        configured
        .resolve_assignment_group(
            TENANT_ALPHA
        )
        == GROUP_ALPHA
    )


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "[]",
        '""',
        '{"tenant-alpha":"short"}',
        (
            '{"tenant-alpha":'
            '"zzzzzzzzzzzzzzzz'
            'zzzzzzzzzzzzzzzz"}'
        ),
        (
            '{" tenant-alpha":'
            f'"{GROUP_ALPHA}"'
            '}'
        ),
    ],
)
def test_malformed_server_routing_fails_closed(
    raw,
):

    with pytest.raises(
        ServiceNowRoutingConfigurationError
    ):

        ServiceNowRoutingPolicy \
            .from_environment(
                {
                    ROUTING_ENVIRONMENT_VARIABLE:
                        raw,
                }
            )


def test_duplicate_tenant_json_key_is_rejected():

    raw = (
        '{"tenant-alpha":'
        f'"{GROUP_ALPHA}",'
        '"tenant-alpha":'
        f'"{GROUP_BRAVO}"'
        '}'
    )

    with pytest.raises(
        ServiceNowRoutingConfigurationError
    ):

        ServiceNowRoutingPolicy \
            .from_environment(
                {
                    ROUTING_ENVIRONMENT_VARIABLE:
                        raw,
                }
            )


def test_unknown_tenant_has_no_default_route():

    with pytest.raises(
        ServiceNowRoutingError,
        match="No ServiceNow",
    ):

        policy() \
            .resolve_assignment_group(
                "tenant-charlie"
            )


def test_payload_ignores_ticket_assignment_group():

    candidate = ticket(
        assignment_group=
            "Attacker Controlled Group",
    )

    payload = (
        ServiceNowTicketProvider
        .build_payload(
            ticket=candidate,

            assignment_group_sys_id=
                GROUP_ALPHA,

            correlation_id=
                "APR-ROUTING",
        )
    )

    assert (
        payload[
            "assignment_group"
        ]
        == GROUP_ALPHA
    )

    assert (
        payload[
            "assignment_group"
        ]
        != candidate.assignment_group
    )


def test_provider_requires_execution_context_before_routing(
    monkeypatch,
):

    candidate_provider, client = (
        provider()
    )

    approval_consumed = False

    def fake_consume(
        *,
        ticket,
        approval,
    ):

        nonlocal approval_consumed

        approval_consumed = True

        return True

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        fake_consume,
    )

    with pytest.raises(
        PermissionError,
        match="execution context",
    ):

        candidate_provider.create_ticket(
            ticket=ticket(),

            approval={
                "approval_id":
                    "APR-ROUTING",
            },
        )

    assert approval_consumed is False
    assert client.payload is None


def test_unknown_tenant_fails_before_approval_consumption(
    monkeypatch,
):

    candidate_provider, client = (
        provider()
    )

    approval_consumed = False

    def fake_consume(
        *,
        ticket,
        approval,
    ):

        nonlocal approval_consumed

        approval_consumed = True

        return True

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        fake_consume,
    )

    with pytest.raises(
        ServiceNowRoutingError
    ):

        candidate_provider.create_ticket(
            ticket=ticket(),

            approval={
                "approval_id":
                    "APR-ROUTING",
            },

            execution_context=
                context(
                    tenant_id=
                        "tenant-charlie",
                ),
        )

    assert approval_consumed is False
    assert client.payload is None


def test_ticket_and_approval_cannot_override_trusted_route(
    monkeypatch,
):

    candidate_provider, client = (
        provider()
    )

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        lambda **kwargs:
            True,
    )

    result = (
        candidate_provider
        .create_ticket(
            ticket=
                ticket(
                    assignment_group=
                        "Attacker Group",
                ),

            approval={
                "approval_id":
                    "APR-ROUTING",

                "assignment_group":
                    GROUP_BRAVO,

                "tenant_id":
                    TENANT_BRAVO,
            },

            execution_context=
                context(
                    tenant_id=
                        TENANT_ALPHA,
                ),
        )
    )

    assert (
        client.payload[
            "assignment_group"
        ]
        == GROUP_ALPHA
    )

    assert (
        result[
            "assignment_group"
        ]
        == GROUP_ALPHA
    )


def test_different_trusted_tenants_route_deterministically(
    monkeypatch,
):

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        lambda **kwargs:
            True,
    )

    for (
        tenant_id,
        expected_group,
    ) in (
        (
            TENANT_ALPHA,
            GROUP_ALPHA,
        ),
        (
            TENANT_BRAVO,
            GROUP_BRAVO,
        ),
    ):

        candidate_provider, client = (
            provider()
        )

        candidate_provider \
            .create_ticket(
                ticket=ticket(),

                approval={
                    "approval_id":
                        "APR-ROUTING",
                },

                execution_context=
                    context(
                        tenant_id=
                            tenant_id,
                    ),
            )

        assert (
            client.payload[
                "assignment_group"
            ]
            == expected_group
        )


def test_execution_helper_forwards_trusted_context(
    monkeypatch,
):

    captured = {}

    class FakeProvider:

        provider_name = "fake"

        def create_ticket(
            self,
            *,
            ticket,
            approval,
            execution_context=None,
        ):

            captured[
                "execution_context"
            ] = execution_context

            return {
                "ticket_id":
                    "INC0012345",
            }

        def close(
            self,
        ):

            return None

    monkeypatch.setattr(
        execution,
        "build_ticket_provider",
        lambda:
            FakeProvider(),
    )

    trusted_context = context()

    execution \
        ._create_ticket_with_selected_provider(
            ticket=object(),

            approval={
                "approval_id":
                    "APR-ROUTING",
            },

            execution_context=
                trusted_context,
        )

    assert (
        captured[
            "execution_context"
        ]
        is trusted_context
    )


def test_execution_helper_exposes_no_raw_routing_parameters():

    signature = inspect.signature(
        execution
        ._create_ticket_with_selected_provider
    )

    assert set(
        signature.parameters
    ) == {
        "ticket",
        "approval",
        "execution_context",
    }

    for forbidden in (
        "tenant",
        "tenant_id",
        "assignment_group",
        "assignment_group_sys_id",
        "provider",
        "provider_name",
        "instance_url",
        "url",
    ):

        assert (
            forbidden
            not in signature.parameters
        )


def test_servicenow_provider_factory_requires_routing_configuration():

    environ = {
        "TICKET_PROVIDER":
            "servicenow",

        "SERVICENOW_INSTANCE_URL":
            "https://example.service-now.com",

        "SERVICENOW_USERNAME":
            "integration-user",

        "SERVICENOW_PASSWORD":
            "server-secret",
    }

    with pytest.raises(
        TicketProviderConfigurationError,
        match="routing",
    ):

        build_ticket_provider(
            environ
        )


def test_servicenow_factory_loads_server_owned_routing():

    environ = {
        "TICKET_PROVIDER":
            "servicenow",

        "SERVICENOW_INSTANCE_URL":
            "https://example.service-now.com",

        "SERVICENOW_USERNAME":
            "integration-user",

        "SERVICENOW_PASSWORD":
            "server-secret",

        ROUTING_ENVIRONMENT_VARIABLE:
            (
                '{"tenant-alpha":'
                f'"{GROUP_ALPHA}"'
                '}'
            ),
    }

    candidate_provider = (
        build_ticket_provider(
            environ
        )
    )

    try:

        assert (
            candidate_provider
            ._routing_policy
            .resolve_assignment_group(
                TENANT_ALPHA
            )
            == GROUP_ALPHA
        )

    finally:

        candidate_provider.close()
