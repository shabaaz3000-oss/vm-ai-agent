from __future__ import annotations

import os
import runpy

from concurrent.futures import (
    ThreadPoolExecutor,
)

from pathlib import Path

from threading import Barrier

import psycopg
import pytest

from psycopg import sql

from app.workflow_postgresql_schema import (
    provision_postgresql_workflow_schema,
)

from app.workflow_postgresql_store import (
    PostgreSQLWorkflowStore,
)


# ------------------------------------------------------------
# REUSE EXISTING VALID WORKFLOW / SECURITY-CONTEXT FIXTURES
# ------------------------------------------------------------
#
# The existing tenant-execution test module is the canonical
# source for valid WorkflowResult and SecurityContext fixtures.
# Loading those helper definitions avoids duplicating complex
# workflow model construction in this PostgreSQL integration
# suite.
# ------------------------------------------------------------

_existing_helpers = runpy.run_path(
    str(
        Path(__file__)
        .with_name(
            "test_workflow_tenant_execution.py"
        )
    )
)

workflow = (
    _existing_helpers[
        "workflow"
    ]
)

bound = (
    _existing_helpers[
        "bound"
    ]
)

context = (
    _existing_helpers[
        "context"
    ]
)


# ------------------------------------------------------------
# POSTGRES TEST CONFIGURATION
# ------------------------------------------------------------

def postgres_database_url() -> str:
    """
    Provision workflow schema with the deployment identity,
    then grant the existing least-privileged runtime identity
    only SELECT, INSERT, and UPDATE.
    """

    database_url = os.environ.get(
        "TEST_POSTGRES_DATABASE_URL"
    )

    admin_database_url = os.environ.get(
        "TEST_POSTGRES_ADMIN_DATABASE_URL"
    )

    if (
        not database_url
        or not admin_database_url
    ):
        pytest.skip(
            "PostgreSQL integration-test URLs "
            "are not configured"
        )

    provision_postgresql_workflow_schema(
        database_url=
            admin_database_url
    )

    with psycopg.connect(
        admin_database_url,
        autocommit=True,
    ) as connection:

        role = connection.execute(
            """
            SELECT 1
            FROM pg_roles
            WHERE rolname = %s
            """,
            (
                "vm_ai_runtime",
            ),
        ).fetchone()

        if role is None:

            connection.execute(
                """
                CREATE ROLE vm_ai_runtime LOGIN
                """
            )

        database_name = (
            connection.execute(
                """
                SELECT current_database()
                """
            ).fetchone()[0]
        )

        connection.execute(
            """
            REVOKE CREATE ON SCHEMA public
            FROM PUBLIC
            """
        )

        connection.execute(
            sql.SQL(
                """
                REVOKE TEMPORARY ON DATABASE {}
                FROM PUBLIC
                """
            ).format(
                sql.Identifier(
                    database_name
                )
            )
        )

        connection.execute(
            sql.SQL(
                """
                GRANT CONNECT ON DATABASE {}
                TO vm_ai_runtime
                """
            ).format(
                sql.Identifier(
                    database_name
                )
            )
        )

        connection.execute(
            """
            GRANT USAGE ON SCHEMA public
            TO vm_ai_runtime
            """
        )

        connection.execute(
            """
            REVOKE ALL PRIVILEGES
            ON TABLE workflows
            FROM PUBLIC
            """
        )

        connection.execute(
            """
            GRANT SELECT, INSERT, UPDATE
            ON TABLE workflows
            TO vm_ai_runtime
            """
        )

        # Administrative test cleanup is intentionally performed
        # using the deployment identity, never the runtime role.
        connection.execute(
            """
            TRUNCATE TABLE workflows
            """
        )

    return database_url


# ------------------------------------------------------------
# LEAST-PRIVILEGED RUNTIME
# ------------------------------------------------------------

def test_runtime_identity_cannot_delete_workflow_rows():

    database_url = (
        postgres_database_url()
    )

    with pytest.raises(
        psycopg.errors.InsufficientPrivilege
    ):

        with psycopg.connect(
            database_url
        ) as connection:

            connection.execute(
                """
                DELETE FROM workflows
                WHERE FALSE
                """
            )


def test_store_bulk_clear_is_denied():

    database_url = (
        postgres_database_url()
    )

    store = PostgreSQLWorkflowStore(
        database_url=database_url
    )

    with pytest.raises(
        PermissionError,
        match="does not permit bulk workflow deletion",
    ):
        store.clear_workflows()


# ------------------------------------------------------------
# CROSS-INSTANCE SHARED AUTHORITY
# ------------------------------------------------------------

def test_workflow_created_on_one_instance_is_visible_on_another():

    database_url = (
        postgres_database_url()
    )

    first = PostgreSQLWorkflowStore(
        database_url=database_url
    )

    second = PostgreSQLWorkflowStore(
        database_url=database_url
    )

    result = workflow()

    first.save_workflow(
        result
    )

    authoritative = (
        second.get_workflow(
            result.workflow_id
        )
    )

    assert authoritative == result


# ------------------------------------------------------------
# DISTRIBUTED ATOMIC CLAIM
# ------------------------------------------------------------

def test_multi_instance_claim_has_exactly_one_winner():

    database_url = (
        postgres_database_url()
    )

    first = PostgreSQLWorkflowStore(
        database_url=database_url
    )

    second = PostgreSQLWorkflowStore(
        database_url=database_url
    )

    authoritative_store = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    result = workflow()

    first.save_workflow(
        result
    )

    barrier = Barrier(
        2
    )

    def compete(
        store: PostgreSQLWorkflowStore,
    ) -> bool:

        barrier.wait(
            timeout=10
        )

        try:
            store \
                .claim_workflow_for_execution(
                    result.workflow_id
                )

        except PermissionError:
            return False

        return True

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        first_future = (
            executor.submit(
                compete,
                first,
            )
        )

        second_future = (
            executor.submit(
                compete,
                second,
            )
        )

        outcomes = (
            first_future.result(),
            second_future.result(),
        )

    assert sorted(
        outcomes
    ) == [
        False,
        True,
    ]

    authoritative = (
        authoritative_store
        .get_workflow(
            result.workflow_id
        )
    )

    assert (
        authoritative.status
        == "PROCESSING"
    )

    assert (
        authoritative
        .execution_attempt_id
        is not None
    )


# ------------------------------------------------------------
# CROSS-TENANT CLAIM MUST NOT CONSUME AUTHORITY
# ------------------------------------------------------------

def test_cross_tenant_claim_does_not_mutate_authoritative_state():

    database_url = (
        postgres_database_url()
    )

    store = PostgreSQLWorkflowStore(
        database_url=database_url
    )

    result = bound(
        tenant_id=
            "tenant-alpha",
    )

    store.save_workflow(
        result
    )

    with pytest.raises(
        PermissionError,
        match="different tenant",
    ):

        store \
            .claim_workflow_for_execution(
                result.workflow_id,
                security_context=
                    context(
                        tenant_id=
                            "tenant-bravo",
                    ),
            )

    authoritative = (
        store.get_workflow(
            result.workflow_id
        )
    )

    assert (
        authoritative.status
        == "AWAITING_APPROVAL"
    )

    assert (
        authoritative
        .execution_attempt_id
        is None
    )


# ------------------------------------------------------------
# DISTRIBUTED HUMAN RECONCILIATION
# ------------------------------------------------------------

def test_multi_instance_reconciliation_has_exactly_one_winner():

    database_url = (
        postgres_database_url()
    )

    first = PostgreSQLWorkflowStore(
        database_url=database_url
    )

    second = PostgreSQLWorkflowStore(
        database_url=database_url
    )

    authoritative_store = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    approver_context = (
        context(
            role="APPROVER",
        )
    )

    result = bound()

    first.save_workflow(
        result
    )

    claimed = (
        first
        .claim_workflow_for_execution(
            result.workflow_id,
            security_context=
                approver_context,
        )
    )

    review = (
        first
        .mark_workflow_needs_review(
            result.workflow_id,
            (
                "External ticket result "
                "requires reconciliation."
            ),
        )
    )

    assert (
        review.execution_attempt_id
        == claimed.execution_attempt_id
    )

    barrier = Barrier(
        2
    )

    def compete(
        store: PostgreSQLWorkflowStore,
        ticket_id: str,
    ) -> tuple[bool, str | None]:

        barrier.wait(
            timeout=10
        )

        try:
            resolved = (
                store
                .confirm_reconciled_ticket_creation(
                    result.workflow_id,
                    expected_execution_attempt_id=
                        review.execution_attempt_id,
                    ticket_id=
                        ticket_id,
                    security_context=
                        approver_context,
                )
            )

        except PermissionError:
            return (
                False,
                None,
            )

        return (
            True,
            resolved.ticket_id,
        )

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        first_future = (
            executor.submit(
                compete,
                first,
                "INC-RECON-A",
            )
        )

        second_future = (
            executor.submit(
                compete,
                second,
                "INC-RECON-B",
            )
        )

        outcomes = (
            first_future.result(),
            second_future.result(),
        )

    winners = [
        ticket_id
        for won, ticket_id
        in outcomes
        if won
    ]

    assert len(winners) == 1

    authoritative = (
        authoritative_store
        .get_workflow(
            result.workflow_id
        )
    )

    assert (
        authoritative.status
        == "TICKET_CREATED"
    )

    assert (
        authoritative.ticket_id
        == winners[0]
    )

    assert (
        authoritative
        .execution_attempt_id
        == review.execution_attempt_id
    )
