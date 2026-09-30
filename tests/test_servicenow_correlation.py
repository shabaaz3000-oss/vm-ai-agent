from __future__ import annotations

import pytest

import app.providers.servicenow_ticket_provider as servicenow_module

from app.models import TicketDraft

from app.providers.servicenow_client import (
    ServiceNowTransportError,
)

from app.providers.servicenow_correlation import (
    ServiceNowCorrelationError,
    build_servicenow_correlation_id,
)

from app.providers.servicenow_routing import (
    ServiceNowRoutingPolicy,
)

from app.providers.servicenow_ticket_provider import (
    ServiceNowTicketProvider,
)

from app.providers.ticket_provider import (
    TicketProviderAmbiguousOutcomeError,
)

from app.ticket_execution_context import (
    TicketExecutionContext,
)


GROUP_SYS_ID = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def context(
    *,
    tenant_id="tenant-alpha",
    workflow_id="WF-CORRELATION-0001",
    execution_attempt_id="EXEC-1234ABCD",
):

    return TicketExecutionContext(
        tenant_id=
            tenant_id,

        workflow_id=
            workflow_id,

        execution_attempt_id=
            execution_attempt_id,
    )


def ticket():

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
            "Untrusted Display Group",

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


def policy():

    return ServiceNowRoutingPolicy(
        {
            "tenant-alpha":
                GROUP_SYS_ID,
        }
    )


class RecordingClient:

    def __init__(
        self,
        *,
        error=None,
    ):

        self.payloads = []
        self.error = error

    def create_record(
        self,
        payload,
    ):

        self.payloads.append(
            payload
        )

        if self.error is not None:

            raise self.error

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
    ):

        return None


def provider(
    client,
):

    return ServiceNowTicketProvider(
        client,
        routing_policy=
            policy(),
    )


def test_correlation_is_stable_for_same_execution():

    first = (
        build_servicenow_correlation_id(
            context()
        )
    )

    second = (
        build_servicenow_correlation_id(
            context()
        )
    )

    assert first == second

    assert first.startswith(
        "VMAI-"
    )

    assert len(first) == 69


@pytest.mark.parametrize(
    (
        "changed_context"
    ),
    [
        context(
            tenant_id=
                "tenant-bravo",
        ),
        context(
            workflow_id=
                "WF-CORRELATION-0002",
        ),
        context(
            execution_attempt_id=
                "EXEC-9999FFFF",
        ),
    ],
)
def test_trusted_execution_dimensions_change_correlation(
    changed_context,
):

    assert (
        build_servicenow_correlation_id(
            changed_context
        )
        !=
        build_servicenow_correlation_id(
            context()
        )
    )


def test_missing_execution_attempt_is_rejected():

    with pytest.raises(
        ServiceNowCorrelationError,
        match="execution_attempt_id",
    ):

        build_servicenow_correlation_id(
            context(
                execution_attempt_id=None,
            )
        )


def test_provider_uses_execution_identity_not_approval_id(
    monkeypatch,
):

    client = RecordingClient()

    candidate = provider(
        client
    )

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        lambda **kwargs:
            True,
    )

    trusted_context = context()

    candidate.create_ticket(
        ticket=ticket(),

        approval={
            "approval_id":
                "APR-ATTEMPT-ONE",
        },

        execution_context=
            trusted_context,
    )

    expected = (
        build_servicenow_correlation_id(
            trusted_context
        )
    )

    assert (
        client.payloads[
            0
        ][
            "correlation_id"
        ]
        == expected
    )

    assert (
        client.payloads[
            0
        ][
            "correlation_id"
        ]
        != "APR-ATTEMPT-ONE"
    )


def test_different_approval_ids_do_not_change_execution_correlation(
    monkeypatch,
):

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        lambda **kwargs:
            True,
    )

    trusted_context = context()

    observed = []

    for approval_id in (
        "APR-FIRST",
        "APR-SECOND",
    ):

        client = RecordingClient()

        provider(
            client
        ).create_ticket(
            ticket=ticket(),

            approval={
                "approval_id":
                    approval_id,
            },

            execution_context=
                trusted_context,
        )

        observed.append(
            client.payloads[
                0
            ][
                "correlation_id"
            ]
        )

    assert observed[
        0
    ] == observed[
        1
    ]


def test_transport_failure_becomes_generic_ambiguous_outcome(
    monkeypatch,
):

    client = RecordingClient(
        error=
            ServiceNowTransportError(
                "uncertain outcome"
            )
    )

    candidate = provider(
        client
    )

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        lambda **kwargs:
            True,
    )

    trusted_context = context()

    expected = (
        build_servicenow_correlation_id(
            trusted_context
        )
    )

    with pytest.raises(
        TicketProviderAmbiguousOutcomeError
    ) as captured:

        candidate.create_ticket(
            ticket=ticket(),

            approval={
                "approval_id":
                    "APR-AMBIGUOUS",
            },

            execution_context=
                trusted_context,
        )

    assert (
        captured.value
        .correlation_id
        == expected
    )

    assert len(
        client.payloads
    ) == 1


def test_missing_execution_attempt_fails_before_approval_consumption(
    monkeypatch,
):

    client = RecordingClient()

    candidate = provider(
        client
    )

    consumed = False

    def fake_consume(
        **kwargs,
    ):

        nonlocal consumed

        consumed = True

        return True

    monkeypatch.setattr(
        servicenow_module,
        "consume_approval",
        fake_consume,
    )

    with pytest.raises(
        ServiceNowCorrelationError
    ):

        candidate.create_ticket(
            ticket=ticket(),

            approval={
                "approval_id":
                    "APR-NO-ATTEMPT",
            },

            execution_context=
                context(
                    execution_attempt_id=None,
                ),
        )

    assert consumed is False

    assert client.payloads == []
