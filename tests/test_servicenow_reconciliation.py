from __future__ import annotations

import httpx
import pytest

from app.models import WorkflowResult

import app.servicenow_reconciliation as reconciliation

from app.providers.servicenow_client import (
    ServiceNowClient,
    ServiceNowLookupError,
)

from app.providers.servicenow_config import (
    ServiceNowSettings,
)

from app.providers.servicenow_correlation import (
    ServiceNowCorrelationError,
    build_servicenow_correlation_id,
    validate_servicenow_correlation_id,
)

from app.security_context import (
    SecurityContext,
)

from app.ticket_execution_context import (
    TicketExecutionContext,
)


CORRELATION = (
    "VMAI-"
    + (
        "a"
        * 64
    )
)

SYS_ID = (
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)


def settings():

    return ServiceNowSettings(
        instance_url=
            "https://example.service-now.com",

        username=
            "integration-user",

        password=
            "server-secret",
    )


def context(
    *,
    tenant_id=
        "tenant-alpha",

    role=
        "APPROVER",
):

    return SecurityContext(
        principal_id=
            "approver@example.com",

        role=
            role,

        retrieval_access=
            "standard",

        tenant_id=
            tenant_id,

        session_id=
            "session-reconcile",
    )


def workflow(
    *,
    status=
        "NEEDS_REVIEW",

    tenant_id=
        "tenant-alpha",

    execution_attempt_id=
        "EXEC-1234ABCD",
):

    # Use the real authoritative workflow model. model_construct()
    # lets these focused reconciliation tests populate only the
    # fields exercised by the boundary while preserving the
    # production isinstance(WorkflowResult) security invariant.

    return WorkflowResult.model_construct(
        workflow_id=
            "WF-RECONCILE-0001",

        status=
            status,

        tenant_id=
            tenant_id,

        execution_attempt_id=
            execution_attempt_id,
    )


class FakeReconciliationClient:

    def __init__(
        self,
        records,
    ):

        self.records = records
        self.correlation_ids = []
        self.closed = False

    def find_records_by_correlation_id(
        self,
        correlation_id,
    ):

        self.correlation_ids.append(
            correlation_id
        )

        return list(
            self.records
        )

    def close(
        self,
    ):

        self.closed = True


def expected_correlation():

    return (
        build_servicenow_correlation_id(
            TicketExecutionContext(
                tenant_id=
                    "tenant-alpha",

                workflow_id=
                    "WF-RECONCILE-0001",

                execution_attempt_id=
                    "EXEC-1234ABCD",
            )
        )
    )


def test_correlation_validator_accepts_only_application_format():

    assert (
        validate_servicenow_correlation_id(
            CORRELATION
        )
        == CORRELATION
    )


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "APR-1234",
        "VMAI-short",
        (
            "VMAI-"
            + (
                "A"
                * 64
            )
        ),
        (
            "VMAI-"
            + (
                "a"
                * 63
            )
            + "^"
        ),
        (
            "VMAI-"
            + (
                "a"
                * 64
            )
            + "^ORactive=true"
        ),
    ],
)
def test_correlation_validator_rejects_query_injection_shapes(
    candidate,
):

    with pytest.raises(
        ServiceNowCorrelationError
    ):

        validate_servicenow_correlation_id(
            candidate
        )


def test_client_uses_fixed_get_query_authority():

    observed = []

    def handler(
        request,
    ):

        observed.append(
            request
        )

        return httpx.Response(
            200,
            json={
                "result": [],
            },
        )

    client = ServiceNowClient(
        settings(),
        transport=
            httpx.MockTransport(
                handler
            ),
    )

    try:

        result = (
            client
            .find_records_by_correlation_id(
                CORRELATION
            )
        )

    finally:

        client.close()

    assert result == []

    assert len(
        observed
    ) == 1

    request = observed[
        0
    ]

    assert (
        request.method
        == "GET"
    )

    assert (
        request.url.path
        == "/api/now/table/incident"
    )

    params = dict(
        request.url.params
    )

    assert params == {
        "sysparm_query":
            (
                "correlation_id="
                + CORRELATION
            ),

        "sysparm_fields":
            "sys_id,number,correlation_id",

        "sysparm_limit":
            "2",
    }


def test_invalid_correlation_is_rejected_before_http():

    request_count = 0

    def handler(
        request,
    ):

        nonlocal request_count

        request_count += 1

        return httpx.Response(
            500
        )

    client = ServiceNowClient(
        settings(),
        transport=
            httpx.MockTransport(
                handler
            ),
    )

    try:

        with pytest.raises(
            ServiceNowCorrelationError
        ):

            client \
                .find_records_by_correlation_id(
                    (
                        CORRELATION
                        + "^ORactive=true"
                    )
                )

    finally:

        client.close()

    assert request_count == 0


def test_client_normalizes_single_matching_record():

    def handler(
        request,
    ):

        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sys_id":
                            SYS_ID.upper(),

                        "number":
                            "INC0012345",

                        "correlation_id":
                            CORRELATION,
                    }
                ],
            },
        )

    client = ServiceNowClient(
        settings(),
        transport=
            httpx.MockTransport(
                handler
            ),
    )

    try:

        records = (
            client
            .find_records_by_correlation_id(
                CORRELATION
            )
        )

    finally:

        client.close()

    assert records == [
        {
            "sys_id":
                SYS_ID,

            "number":
                "INC0012345",

            "correlation_id":
                CORRELATION,
        }
    ]


def test_client_rejects_mismatched_correlation():

    def handler(
        request,
    ):

        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sys_id":
                            SYS_ID,

                        "number":
                            "INC0012345",

                        "correlation_id":
                            (
                                "VMAI-"
                                + (
                                    "c"
                                    * 64
                                )
                            ),
                    }
                ],
            },
        )

    client = ServiceNowClient(
        settings(),
        transport=
            httpx.MockTransport(
                handler
            ),
    )

    try:

        with pytest.raises(
            ServiceNowLookupError,
            match="does not match",
        ):

            client \
                .find_records_by_correlation_id(
                    CORRELATION
                )

    finally:

        client.close()


def test_client_rejects_more_than_two_results():

    records = [
        {
            "sys_id":
                (
                    character
                    * 32
                ),

            "number":
                f"INC000000{index}",

            "correlation_id":
                CORRELATION,
        }
        for index, character
        in enumerate(
            (
                "a",
                "b",
                "c",
            ),
            start=1,
        )
    ]

    def handler(
        request,
    ):

        return httpx.Response(
            200,
            json={
                "result":
                    records,
            },
        )

    client = ServiceNowClient(
        settings(),
        transport=
            httpx.MockTransport(
                handler
            ),
    )

    try:

        with pytest.raises(
            ServiceNowLookupError,
            match="more records",
        ):

            client \
                .find_records_by_correlation_id(
                    CORRELATION
                )

    finally:

        client.close()


def test_reconciliation_requires_needs_review(
    monkeypatch,
):

    monkeypatch.setattr(
        reconciliation,
        "get_workflow",
        lambda workflow_id:
            workflow(
                status=
                    "PROCESSING",
            ),
    )

    with pytest.raises(
        reconciliation
        .ServiceNowReconciliationError,
        match="NEEDS_REVIEW",
    ):

        reconciliation \
            .reconcile_servicenow_workflow(
                "WF-RECONCILE-0001",
                security_context=
                    context(),
            )


def test_reconciliation_requires_approver_role(
    monkeypatch,
):

    with pytest.raises(
        reconciliation
        .ServiceNowReconciliationError,
        match="APPROVER",
    ):

        reconciliation \
            .reconcile_servicenow_workflow(
                "WF-RECONCILE-0001",
                security_context=
                    context(
                        role=
                            "ANALYST",
                    ),
            )


def test_cross_tenant_reconciliation_fails_before_client(
    monkeypatch,
):

    client_built = False

    monkeypatch.setattr(
        reconciliation,
        "get_workflow",
        lambda workflow_id:
            workflow(),
    )

    def build_client():

        nonlocal client_built

        client_built = True

        raise AssertionError(
            "Client must not be built."
        )

    monkeypatch.setattr(
        reconciliation,
        (
            "_build_servicenow_"
            "reconciliation_client"
        ),
        build_client,
    )

    with pytest.raises(
        PermissionError
    ):

        reconciliation \
            .reconcile_servicenow_workflow(
                "WF-RECONCILE-0001",
                security_context=
                    context(
                        tenant_id=
                            "tenant-bravo",
                    ),
            )

    assert client_built is False


def test_missing_execution_attempt_fails_before_client(
    monkeypatch,
):

    client_built = False

    monkeypatch.setattr(
        reconciliation,
        "get_workflow",
        lambda workflow_id:
            workflow(
                execution_attempt_id=None,
            ),
    )

    def build_client():

        nonlocal client_built

        client_built = True

        raise AssertionError(
            "Client must not be built."
        )

    monkeypatch.setattr(
        reconciliation,
        (
            "_build_servicenow_"
            "reconciliation_client"
        ),
        build_client,
    )

    with pytest.raises(
        ServiceNowCorrelationError,
        match="execution_attempt_id",
    ):

        reconciliation \
            .reconcile_servicenow_workflow(
                "WF-RECONCILE-0001",
                security_context=
                    context(),
            )

    assert client_built is False


@pytest.mark.parametrize(
    (
        "records",
        "expected_outcome",
        "expected_count",
    ),
    [
        (
            [],
            "NOT_FOUND",
            0,
        ),
        (
            [
                {
                    "sys_id":
                        SYS_ID,

                    "number":
                        "INC0012345",

                    "correlation_id":
                        CORRELATION,
                }
            ],
            "CONFIRMED",
            1,
        ),
        (
            [
                {
                    "sys_id":
                        SYS_ID,

                    "number":
                        "INC0012345",

                    "correlation_id":
                        CORRELATION,
                },
                {
                    "sys_id":
                        (
                            "cccccccccccccccc"
                            "cccccccccccccccc"
                        ),

                    "number":
                        "INC0012346",

                    "correlation_id":
                        CORRELATION,
                },
            ],
            "CONFLICT",
            2,
        ),
    ],
)
def test_reconciliation_classifies_external_truth_without_mutation(
    monkeypatch,
    records,
    expected_outcome,
    expected_count,
):

    fake_client = (
        FakeReconciliationClient(
            records
        )
    )

    candidate_workflow = (
        workflow()
    )

    monkeypatch.setattr(
        reconciliation,
        "get_workflow",
        lambda workflow_id:
            candidate_workflow,
    )

    monkeypatch.setattr(
        reconciliation,
        (
            "_build_servicenow_"
            "reconciliation_client"
        ),
        lambda:
            fake_client,
    )

    result = (
        reconciliation
        .reconcile_servicenow_workflow(
            "WF-RECONCILE-0001",
            security_context=
                context(),
        )
    )

    assert (
        result.outcome
        == expected_outcome
    )

    assert (
        result.match_count
        == expected_count
    )

    assert (
        result.correlation_id
        == expected_correlation()
    )

    assert fake_client.closed is True

    assert fake_client.correlation_ids == [
        expected_correlation()
    ]

    # Read-only reconciliation must not alter the workflow.

    assert (
        candidate_workflow.status
        == "NEEDS_REVIEW"
    )


def test_confirmed_result_returns_external_identifiers(
    monkeypatch,
):

    fake_client = (
        FakeReconciliationClient(
            [
                {
                    "sys_id":
                        SYS_ID,

                    "number":
                        "INC0012345",

                    "correlation_id":
                        CORRELATION,
                }
            ]
        )
    )

    monkeypatch.setattr(
        reconciliation,
        "get_workflow",
        lambda workflow_id:
            workflow(),
    )

    monkeypatch.setattr(
        reconciliation,
        (
            "_build_servicenow_"
            "reconciliation_client"
        ),
        lambda:
            fake_client,
    )

    result = (
        reconciliation
        .reconcile_servicenow_workflow(
            "WF-RECONCILE-0001",
            security_context=
                context(),
        )
    )

    assert (
        result.ticket_number
        == "INC0012345"
    )

    assert (
        result.external_sys_id
        == SYS_ID
    )


def test_reconciliation_surface_exposes_no_raw_query_authority():

    import inspect

    signature = inspect.signature(
        reconciliation
        .reconcile_servicenow_workflow
    )

    assert set(
        signature.parameters
    ) == {
        "workflow_id",
        "security_context",
    }

    for forbidden in (
        "correlation_id",
        "sysparm_query",
        "query",
        "table",
        "url",
        "tenant_id",
        "ticket_number",
        "sys_id",
    ):

        assert (
            forbidden
            not in signature.parameters
        )


def test_reconciliation_client_builder_requires_servicenow_provider(
    monkeypatch,
):

    monkeypatch.setenv(
        "TICKET_PROVIDER",
        "mock",
    )

    with pytest.raises(
        reconciliation
        .ServiceNowReconciliationError,
        match="server-selected",
    ):

        reconciliation \
            ._build_servicenow_reconciliation_client()
