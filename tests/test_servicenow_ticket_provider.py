from __future__ import annotations

import app.providers.servicenow_ticket_provider as servicenow_module

from app.models import TicketDraft
from app.providers.servicenow_ticket_provider import (
    ServiceNowTicketProvider,
)
from app.providers.ticket_provider import (
    TicketProvider,
)


from app.ticket_execution_context import (
    TicketExecutionContext,
)

from app.providers.servicenow_routing import (
    ServiceNowRoutingPolicy,
)


_TEST_TENANT_ID = "tenant-alpha"

_TEST_GROUP_SYS_ID = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def _test_execution_context(
) -> TicketExecutionContext:

    return TicketExecutionContext(
        tenant_id=
            _TEST_TENANT_ID,

        workflow_id=
            "WF-SERVICENOW-TEST",

        execution_attempt_id=
            "EXEC-SERVICENOW-TEST",
    )


def _test_routing_policy(
) -> ServiceNowRoutingPolicy:

    return ServiceNowRoutingPolicy(
        {
            _TEST_TENANT_ID:
                _TEST_GROUP_SYS_ID,
        }
    )



class FakeClient:

    def __init__(self):
        self.payload = None

    def create_record(
        self,
        payload,
    ):
        self.payload = dict(
            payload
        )

        return {
            "sys_id":
                "0123456789abcdef",

            "number":
                "INC0012345",
        }


def ticket() -> TicketDraft:

    return TicketDraft(
        short_description=
            "Patch critical vulnerability",

        priority=
            "P1",

        asset_name=
            "server01",

        cve=
            "CVE-2026-12345",

        assignment_group=
            "Vulnerability Management",

        risk_rating=
            "CRITICAL",

        risk_score=
            98,

        sla_hours=
            24,

        description=
            "Critical vulnerability requires remediation.",

        remediation=
            "Apply the vendor security update.",

        validation_steps=[
            "Confirm package version.",
            "Run authenticated vulnerability scan.",
        ],
    )


def test_servicenow_provider_satisfies_contract():

    provider = ServiceNowTicketProvider(
        FakeClient(),
                   routing_policy=_test_routing_policy(),
    )

    assert isinstance(
        provider,
        TicketProvider,
    )


def test_payload_is_strictly_allowlisted():

    payload = (
        ServiceNowTicketProvider
        .build_payload(
            ticket=ticket(),
            correlation_id=
                "APR-12345678",
            assignment_group_sys_id=_TEST_GROUP_SYS_ID,
        )
    )

    assert set(
        payload
    ) == {
        "short_description",
        "description",
        "priority",
        "assignment_group",
        "correlation_id",
    }


def test_authoritative_ticket_fields_are_mapped():

    payload = (
        ServiceNowTicketProvider
        .build_payload(
            ticket=ticket(),
            correlation_id=
                "APR-12345678",
            assignment_group_sys_id=_TEST_GROUP_SYS_ID,
        )
    )

    assert (
        payload["priority"]
        == "1"
    )

    assert (
        payload["assignment_group"]
        == _TEST_GROUP_SYS_ID
    )

    assert (
        payload["correlation_id"]
        == "APR-12345678"
    )

    assert (
        "CVE-2026-12345"
        in payload["description"]
    )

    assert (
        "server01"
        in payload["description"]
    )


def test_all_application_priorities_map_to_servicenow_values():

    expected = {
        "P1": "1",
        "P2": "2",
        "P3": "3",
        "P4": "4",
    }

    base = ticket()

    for (
        application_priority,
        servicenow_priority,
    ) in expected.items():

        candidate = TicketDraft.model_validate(
            {
                **base.model_dump(),

                "priority":
                    application_priority,
            }
        )

        payload = (
            ServiceNowTicketProvider
            .build_payload(
                ticket=candidate,

                correlation_id=
                    "APR-PRIORITY-MAP",
                assignment_group_sys_id=_TEST_GROUP_SYS_ID,
            )
        )

        assert (
            payload["priority"]
            == servicenow_priority
        )


def test_provider_normalizes_external_result(
    monkeypatch,
):

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        lambda *,
        ticket,
        approval:
            True,
    )

    client = FakeClient()

    provider = ServiceNowTicketProvider(
        client,
                   routing_policy=_test_routing_policy(),
    )

    result = provider.create_ticket(
        ticket=ticket(),
        approval={
            "approval_id":
                "APR-12345678",
        },
                 execution_context=_test_execution_context(),
    )

    assert (
        result["ticket_id"]
        == "INC0012345"
    )

    assert (
        result["external_sys_id"]
        == "0123456789abcdef"
    )

    assert (
        result["provider"]
        == "servicenow"
    )

    assert (
        result["approval_id"]
        == "APR-12345678"
    )


def test_approval_dictionary_cannot_override_payload(
    monkeypatch,
):

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        lambda *,
        ticket,
        approval:
            True,
    )

    client = FakeClient()

    provider = ServiceNowTicketProvider(
        client,
                   routing_policy=_test_routing_policy(),
    )

    provider.create_ticket(
        ticket=ticket(),
        approval={
            "approval_id":
                "APR-12345678",

            "priority":
                "5",

            "assignment_group":
                "Attacker Controlled Group",

            "short_description":
                "Injected ticket",

            "table":
                "sys_user",

            "instance_url":
                "https://attacker.example",
        },
        execution_context=_test_execution_context(),
    )

    assert (
        client.payload["priority"]
        == "1"
    )

    assert (
        client.payload["assignment_group"]
        == _TEST_GROUP_SYS_ID
    )

    assert (
        client.payload["short_description"]
        == "Patch critical vulnerability"
    )

    assert (
        "table"
        not in client.payload
    )

    assert (
        "instance_url"
        not in client.payload
    )


def test_blank_approval_id_is_rejected():

    provider = ServiceNowTicketProvider(
        FakeClient(),
                   routing_policy=_test_routing_policy(),
    )

    try:
        provider.create_ticket(
            ticket=ticket(),
            approval={
                "approval_id":
                    "   ",
            },
            execution_context=_test_execution_context(),
        )

    except ValueError:
        pass

    else:
        raise AssertionError(
            "Blank approval_id was accepted."
        )
