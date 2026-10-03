from __future__ import annotations

import os
import runpy

from datetime import timedelta

from concurrent.futures import (
    ThreadPoolExecutor,
)

from pathlib import Path

from threading import Barrier

import psycopg
import pytest

from psycopg import sql

from app.workflow_postgresql_schema import (
    WORKFLOW_SCHEMA_COMMENT,
    WORKFLOW_SCHEMA_VERSION,
    provision_postgresql_workflow_schema,
    validate_postgresql_workflow_schema,
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
# VERSIONED SCHEMA / DEPLOYMENT BOUNDARY
# ------------------------------------------------------------


def test_runtime_identity_can_validate_workflow_schema():
    database_url = (
        postgres_database_url()
    )

    version = (
        validate_postgresql_workflow_schema(
            database_url=database_url
        )
    )

    assert (
        version
        == WORKFLOW_SCHEMA_VERSION
    )


def test_runtime_validation_rejects_incompatible_schema_version():
    database_url = (
        postgres_database_url()
    )

    admin_database_url = (
        os.environ[
            "TEST_POSTGRES_ADMIN_DATABASE_URL"
        ]
    )

    try:

        with psycopg.connect(
            admin_database_url,
            autocommit=True,
        ) as connection:

            connection.execute(
                """
                COMMENT ON TABLE workflows IS
                'vm_ai_agent_workflow_schema:v999'
                """
            )

        with pytest.raises(
            RuntimeError,
            match="version is incompatible",
        ):

            validate_postgresql_workflow_schema(
                database_url=database_url
            )

    finally:

        # Restore using deployment/admin authority directly.
        #
        # Do NOT call the provisioner here: by design it must
        # reject an unknown/future version rather than silently
        # rewrite it.
        with psycopg.connect(
            admin_database_url,
            autocommit=True,
        ) as connection:

            connection.execute(
                sql.SQL(
                    """
                    COMMENT ON TABLE workflows IS {}
                    """
                ).format(
                    sql.Literal(
                        WORKFLOW_SCHEMA_COMMENT
                    )
                )
            )


def test_deployment_provisioner_adopts_compatible_unversioned_schema():
    database_url = (
        postgres_database_url()
    )

    admin_database_url = (
        os.environ[
            "TEST_POSTGRES_ADMIN_DATABASE_URL"
        ]
    )

    with psycopg.connect(
        admin_database_url,
        autocommit=True,
    ) as connection:

        # Simulate the pre-versioning Step 49.3 schema:
        # correct structure, no schema-version comment.
        connection.execute(
            """
            COMMENT ON TABLE workflows IS NULL
            """
        )

    with pytest.raises(
        RuntimeError,
        match="version is incompatible",
    ):

        validate_postgresql_workflow_schema(
            database_url=database_url
        )

    provision_postgresql_workflow_schema(
        database_url=
            admin_database_url
    )

    version = (
        validate_postgresql_workflow_schema(
            database_url=database_url
        )
    )

    assert (
        version
        == WORKFLOW_SCHEMA_VERSION
    )

    with psycopg.connect(
        admin_database_url,
        autocommit=True,
    ) as connection:

        comment = connection.execute(
            """
            SELECT obj_description(
                'public.workflows'::regclass,
                'pg_class'
            )
            """
        ).fetchone()[0]

    assert (
        comment
        == WORKFLOW_SCHEMA_COMMENT
    )


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
        first.mark_workflow_needs_review(result.workflow_id, 'External ticket result requires reconciliation.', expected_execution_attempt_id=claimed.execution_attempt_id, security_context=approver_context)
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


# ============================================================
# STEP 49.4 ? ADVERSARIAL DISTRIBUTED RECOVERY
# ============================================================


def test_multi_instance_stale_recovery_has_exactly_one_winner():

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

    claimed = (
        first
        .claim_workflow_for_execution(
            result.workflow_id
        )
    )

    assert (
        claimed.processing_started_at
        is not None
    )

    effective_now = (
        claimed.processing_started_at
        + timedelta(
            seconds=301
        )
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
                .mark_stale_processing_for_review(
                    result.workflow_id,
                    stale_after_seconds=300,
                    now=effective_now,
                )

        except PermissionError:
            return False

        return True

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        first_future = executor.submit(
            compete,
            first,
        )

        second_future = executor.submit(
            compete,
            second,
        )

        outcomes = (
            first_future.result(),
            second_future.result(),
        )

    assert sorted(outcomes) == [
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
        == "NEEDS_REVIEW"
    )

    assert (
        authoritative.execution_attempt_id
        == claimed.execution_attempt_id
    )

    assert (
        authoritative.recovery_reason
        is not None
    )


def test_multi_instance_retry_authorization_has_exactly_one_winner():

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

    approver = context(
        role="APPROVER",
    )

    result = bound()

    first.save_workflow(
        result
    )

    claimed = (
        first
        .claim_workflow_for_execution(
            result.workflow_id,
            security_context=approver,
        )
    )

    review = (
        first.mark_workflow_needs_review(result.workflow_id, 'External action outcome is ambiguous.', expected_execution_attempt_id=claimed.execution_attempt_id, security_context=approver)
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
            store.authorize_reconciled_retry(
                result.workflow_id,
                expected_execution_attempt_id=
                    review.execution_attempt_id,
                security_context=approver,
            )

        except PermissionError:
            return False

        return True

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        first_future = executor.submit(
            compete,
            first,
        )

        second_future = executor.submit(
            compete,
            second,
        )

        outcomes = (
            first_future.result(),
            second_future.result(),
        )

    assert sorted(outcomes) == [
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
        == "AWAITING_APPROVAL"
    )

    # The ambiguous attempt remains attached for audit provenance
    # until the next fresh execution claim.
    assert (
        authoritative.execution_attempt_id
        == claimed.execution_attempt_id
    )

    assert authoritative.approval_id is None
    assert authoritative.ticket_id is None


def test_stale_reconciliation_attempt_is_rejected_after_fresh_claim():

    database_url = (
        postgres_database_url()
    )

    first_instance = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    restarted_instance = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    approver = context(
        role="APPROVER",
    )

    result = bound()

    first_instance.save_workflow(
        result
    )

    first_claim = (
        first_instance
        .claim_workflow_for_execution(
            result.workflow_id,
            security_context=approver,
        )
    )

    first_instance.mark_workflow_needs_review(result.workflow_id, 'First execution requires reconciliation.', expected_execution_attempt_id=first_claim.execution_attempt_id, security_context=approver)

    first_instance \
        .authorize_reconciled_retry(
            result.workflow_id,
            expected_execution_attempt_id=
                first_claim.execution_attempt_id,
            security_context=approver,
        )

    second_claim = (
        restarted_instance
        .claim_workflow_for_execution(
            result.workflow_id,
            security_context=approver,
        )
    )

    assert (
        second_claim.execution_attempt_id
        != first_claim.execution_attempt_id
    )

    restarted_instance.mark_workflow_needs_review(result.workflow_id, 'Second execution requires reconciliation.', expected_execution_attempt_id=second_claim.execution_attempt_id, security_context=approver)

    with pytest.raises(
        PermissionError,
        match="execution attempt changed",
    ):
        first_instance \
            .confirm_reconciled_ticket_creation(
                result.workflow_id,
                expected_execution_attempt_id=
                    first_claim.execution_attempt_id,
                ticket_id="INC-STALE-ATTEMPT",
                security_context=approver,
            )

    authoritative = (
        restarted_instance
        .get_workflow(
            result.workflow_id
        )
    )

    assert (
        authoritative.status
        == "NEEDS_REVIEW"
    )

    assert (
        authoritative.execution_attempt_id
        == second_claim.execution_attempt_id
    )

    assert authoritative.ticket_id is None


def test_restarted_instance_can_recover_stale_processing_state():

    database_url = (
        postgres_database_url()
    )

    original_instance = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    result = workflow()

    original_instance.save_workflow(
        result
    )

    claimed = (
        original_instance
        .claim_workflow_for_execution(
            result.workflow_id
        )
    )

    assert (
        claimed.processing_started_at
        is not None
    )

    # Simulate process loss by abandoning the original store
    # instance and constructing a completely new runtime store.
    del original_instance

    restarted_instance = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    recovered = (
        restarted_instance
        .mark_stale_processing_for_review(
            result.workflow_id,
            stale_after_seconds=300,
            now=(
                claimed.processing_started_at
                + timedelta(
                    seconds=301
                )
            ),
        )
    )

    assert (
        recovered.status
        == "NEEDS_REVIEW"
    )

    assert (
        recovered.execution_attempt_id
        == claimed.execution_attempt_id
    )

    authoritative = (
        restarted_instance
        .get_workflow(
            result.workflow_id
        )
    )

    assert authoritative == recovered


def test_confirm_vs_retry_race_has_exactly_one_resolution():

    database_url = (
        postgres_database_url()
    )

    confirmation_instance = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    retry_instance = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    authoritative_store = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    approver = context(
        role="APPROVER",
    )

    result = bound()

    confirmation_instance.save_workflow(
        result
    )

    claimed = (
        confirmation_instance
        .claim_workflow_for_execution(
            result.workflow_id,
            security_context=approver,
        )
    )

    review = (
        confirmation_instance.mark_workflow_needs_review(result.workflow_id, 'Human reconciliation required.', expected_execution_attempt_id=claimed.execution_attempt_id, security_context=approver)
    )

    assert (
        review.execution_attempt_id
        == claimed.execution_attempt_id
    )

    barrier = Barrier(
        2
    )

    def confirm() -> str:

        barrier.wait(
            timeout=10
        )

        try:
            confirmation_instance \
                .confirm_reconciled_ticket_creation(
                    result.workflow_id,
                    expected_execution_attempt_id=
                        review.execution_attempt_id,
                    ticket_id="INC-RACE-CONFIRMED",
                    security_context=approver,
                )

        except PermissionError:
            return "lost"

        return "confirmed"

    def retry() -> str:

        barrier.wait(
            timeout=10
        )

        try:
            retry_instance \
                .authorize_reconciled_retry(
                    result.workflow_id,
                    expected_execution_attempt_id=
                        review.execution_attempt_id,
                    security_context=approver,
                )

        except PermissionError:
            return "lost"

        return "retry"

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        confirm_future = executor.submit(
            confirm
        )

        retry_future = executor.submit(
            retry
        )

        outcomes = {
            confirm_future.result(),
            retry_future.result(),
        }

    assert "lost" in outcomes

    assert (
        "confirmed" in outcomes
        or "retry" in outcomes
    )

    assert len(outcomes) == 2

    authoritative = (
        authoritative_store
        .get_workflow(
            result.workflow_id
        )
    )

    assert authoritative.status in {
        "TICKET_CREATED",
        "AWAITING_APPROVAL",
    }

    if (
        authoritative.status
        == "TICKET_CREATED"
    ):
        assert (
            authoritative.ticket_id
            == "INC-RACE-CONFIRMED"
        )

    else:
        assert authoritative.ticket_id is None


def test_retry_then_competing_claims_create_one_fresh_attempt():

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

    approver = context(
        role="APPROVER",
    )

    result = bound()

    first.save_workflow(
        result
    )

    ambiguous_claim = (
        first
        .claim_workflow_for_execution(
            result.workflow_id,
            security_context=approver,
        )
    )

    review = (
        first.mark_workflow_needs_review(result.workflow_id, 'Ambiguous external write.', expected_execution_attempt_id=ambiguous_claim.execution_attempt_id, security_context=approver)
    )

    first.authorize_reconciled_retry(
        result.workflow_id,
        expected_execution_attempt_id=
            review.execution_attempt_id,
        security_context=approver,
    )

    barrier = Barrier(
        2
    )

    def compete(
        store: PostgreSQLWorkflowStore,
    ) -> str | None:

        barrier.wait(
            timeout=10
        )

        try:
            claimed = (
                store
                .claim_workflow_for_execution(
                    result.workflow_id,
                    security_context=approver,
                )
            )

        except PermissionError:
            return None

        return claimed.execution_attempt_id

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        first_future = executor.submit(
            compete,
            first,
        )

        second_future = executor.submit(
            compete,
            second,
        )

        attempt_ids = [
            value
            for value in (
                first_future.result(),
                second_future.result(),
            )
            if value is not None
        ]

    assert len(attempt_ids) == 1

    fresh_attempt_id = attempt_ids[0]

    assert (
        fresh_attempt_id
        != ambiguous_claim.execution_attempt_id
    )

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
        authoritative.execution_attempt_id
        == fresh_attempt_id
    )


def test_save_workflow_cannot_overwrite_existing_postgresql_authority():

    database_url = (
        postgres_database_url()
    )

    store = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    original = workflow()

    store.save_workflow(
        original
    )

    hostile_data = (
        original.model_dump()
    )

    hostile_data.update(
        {
            "status":
                "TICKET_CREATED",

            "ticket_id":
                "VM-UNTRUSTED-OVERWRITE",
        }
    )

    hostile = (
        type(original)
        .model_validate(
            hostile_data
        )
    )

    with pytest.raises(
        PermissionError,
        match=(
            "cannot overwrite "
            "authoritative state"
        ),
    ):

        store.save_workflow(
            hostile
        )

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    assert authoritative == original


def test_complete_workflow_execution_persists_postgresql_authority():

    database_url = (
        postgres_database_url()
    )

    store = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    original = workflow()

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id
        )
    )

    completed = (
        store
        .complete_workflow_execution(
            original.workflow_id,
            expected_execution_attempt_id=
                claimed.execution_attempt_id,
            approval_id=
                "APR-PG-AUTH0001",
            ticket_id=
                "VM-PG-AUTH0001",
        )
    )

    assert (
        completed.status
        == "TICKET_CREATED"
    )

    assert (
        completed.execution_attempt_id
        == claimed.execution_attempt_id
    )

    assert (
        completed.approval_id
        == "APR-PG-AUTH0001"
    )

    assert (
        completed.ticket_id
        == "VM-PG-AUTH0001"
    )

    assert (
        store.get_workflow(
            original.workflow_id
        )
        == completed
    )


def test_complete_workflow_execution_rejects_stale_postgresql_attempt():

    database_url = (
        postgres_database_url()
    )

    store = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    original = workflow()

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id
        )
    )

    with pytest.raises(
        PermissionError,
        match="execution attempt changed",
    ):

        store \
            .complete_workflow_execution(
                original.workflow_id,
                expected_execution_attempt_id=
                    "EXEC-STALE-PG-AUTHORITY",
                approval_id=
                    "APR-PG-STALE0001",
                ticket_id=
                    "VM-PG-STALE0001",
            )

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    assert authoritative == claimed

    assert (
        authoritative.status
        == "PROCESSING"
    )


def test_reject_workflow_authoritatively_persists_postgresql_state():

    database_url = (
        postgres_database_url()
    )

    store = (
        PostgreSQLWorkflowStore(
            database_url=database_url
        )
    )

    original = workflow()

    store.save_workflow(
        original
    )

    rejected = (
        store
        .reject_workflow_authoritatively(
            original.workflow_id
        )
    )

    assert (
        rejected.status
        == "REJECTED"
    )

    assert rejected.approval_id is None

    assert rejected.ticket_id is None

    assert (
        store.get_workflow(
            original.workflow_id
        )
        == rejected
    )

    with pytest.raises(
        PermissionError,
        match="awaiting approval",
    ):

        store \
            .claim_workflow_for_execution(
                original.workflow_id
            )


def test_postgresql_needs_review_rejects_stale_execution_attempt():

    database_url = (
        postgres_database_url()
    )

    store = (
        PostgreSQLWorkflowStore(
            database_url=
                database_url
        )
    )

    original = workflow()

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id
        )
    )

    with pytest.raises(
        PermissionError,
        match="execution attempt changed",
    ):

        store \
            .mark_workflow_needs_review(
                original.workflow_id,
                "Synthetic ambiguous outcome.",
                expected_execution_attempt_id=
                    "EXEC-STALE-PG-REVIEW0001",
            )

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    assert authoritative == claimed

    assert (
        authoritative.status
        == "PROCESSING"
    )


def test_postgresql_needs_review_rejects_cross_tenant_context():

    database_url = (
        postgres_database_url()
    )

    store = (
        PostgreSQLWorkflowStore(
            database_url=
                database_url
        )
    )

    alpha = context(
        tenant_id=
            "tenant-alpha",
    )

    bravo = context(
        tenant_id=
            "tenant-bravo",
    )

    original = bound(
        tenant_id=
            "tenant-alpha",
    )

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id,
            security_context=
                alpha,
        )
    )

    with pytest.raises(
        PermissionError,
        match="different tenant",
    ):

        store \
            .mark_workflow_needs_review(
                original.workflow_id,
                "Synthetic ambiguous outcome.",
                expected_execution_attempt_id=
                    claimed.execution_attempt_id,
                security_context=
                    bravo,
            )

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    assert authoritative == claimed

    assert (
        authoritative.status
        == "PROCESSING"
    )

    assert (
        authoritative.tenant_id
        == "tenant-alpha"
    )


def test_postgresql_needs_review_requires_context_for_tenant_bound_workflow():

    database_url = (
        postgres_database_url()
    )

    store = (
        PostgreSQLWorkflowStore(
            database_url=
                database_url
        )
    )

    approver_context = context(
        tenant_id=
            "tenant-alpha",
    )

    original = bound(
        tenant_id=
            "tenant-alpha",
    )

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id,
            security_context=
                approver_context,
        )
    )

    with pytest.raises(
        PermissionError,
        match="requires trusted security context",
    ):

        store \
            .mark_workflow_needs_review(
                original.workflow_id,
                "Synthetic ambiguous outcome.",
                expected_execution_attempt_id=
                    claimed.execution_attempt_id,
            )

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    assert authoritative == claimed

    assert (
        authoritative.status
        == "PROCESSING"
    )


def test_multi_instance_needs_review_has_exactly_one_winner():

    database_url = (
        postgres_database_url()
    )

    first = PostgreSQLWorkflowStore(
        database_url=
            database_url
    )

    second = PostgreSQLWorkflowStore(
        database_url=
            database_url
    )

    authoritative_store = (
        PostgreSQLWorkflowStore(
            database_url=
                database_url
        )
    )

    original = workflow()

    first.save_workflow(
        original
    )

    claimed = (
        first
        .claim_workflow_for_execution(
            original.workflow_id
        )
    )

    barrier = Barrier(
        2
    )

    def compete(
        store: PostgreSQLWorkflowStore,
    ) -> tuple[bool, str | None]:

        barrier.wait(
            timeout=10
        )

        try:

            reviewed = (
                store
                .mark_workflow_needs_review(
                    original.workflow_id,
                    (
                        "Distributed ambiguity "
                        "requires reconciliation."
                    ),
                    expected_execution_attempt_id=
                        claimed.execution_attempt_id,
                )
            )

        except PermissionError:

            return (
                False,
                None,
            )

        return (
            True,
            reviewed.execution_attempt_id,
        )

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
        won
        for won, _attempt
        in outcomes
    ) == [
        False,
        True,
    ]

    winner_attempts = [
        attempt
        for won, attempt
        in outcomes
        if won
    ]

    assert winner_attempts == [
        claimed.execution_attempt_id
    ]

    authoritative = (
        authoritative_store
        .get_workflow(
            original.workflow_id
        )
    )

    assert (
        authoritative.status
        == "NEEDS_REVIEW"
    )

    assert (
        authoritative.execution_attempt_id
        == claimed.execution_attempt_id
    )

    assert (
        authoritative.recovery_reason
        == (
            "Distributed ambiguity "
            "requires reconciliation."
        )
    )

# ============================================================
# STEP 50.8C ? POSTGRESQL SECURITY OBSERVABILITY
# ============================================================


def test_postgresql_claim_race_telemetry_uses_only_committed_authority(
    monkeypatch,
):
    """
    PostgreSQL chooses the winner.

    Telemetry observes the result.

    The losing claim must not promote an uncommitted candidate
    execution attempt into canonical correlation.
    """

    from concurrent.futures import (
        ThreadPoolExecutor,
    )

    from threading import (
        Barrier,
    )

    import app.security_observability_integrations as integrations

    from app.security_observability import (
        build_execution_attempt_ref,
    )


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


    approver = context(
        role="APPROVER",
    )

    result = bound()


    first.save_workflow(
        result
    )


    events = []


    def capture(
        event,
    ):
        events.append(
            event
        )

        return True


    monkeypatch.setattr(
        integrations,
        "_emit_best_effort",
        capture,
    )


    barrier = Barrier(
        2
    )


    def compete(
        store: PostgreSQLWorkflowStore,
    ) -> str | None:

        barrier.wait(
            timeout=10
        )


        try:

            claimed = (
                store
                .claim_workflow_for_execution(
                    result.workflow_id,
                    security_context=
                        approver,
                )
            )

        except PermissionError:

            return None


        return (
            claimed
            .execution_attempt_id
        )


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


        attempt_ids = [
            value
            for value in (
                first_future.result(),
                second_future.result(),
            )
            if value is not None
        ]


    assert len(
        attempt_ids
    ) == 1


    winning_attempt = (
        attempt_ids[
            0
        ]
    )


    assert (
        winning_attempt
        is not None
    )


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
        == winning_attempt
    )

    assert (
        authoritative.tenant_id
        is not None
    )


    denial_payloads = [
        event.to_dict()
        for event in events
        if (
            event.to_dict()[
                "event_type"
            ]
            ==
            (
                "security.workflow."
                "execution_claim_denied"
            )
        )
    ]


    assert len(
        denial_payloads
    ) == 1


    denial = (
        denial_payloads[
            0
        ]
    )


    assert (
        denial[
            "reason_code"
        ]
        == "execution_already_claimed"
    )

    assert (
        denial[
            "source_component"
        ]
        == "workflow_postgresql_store"
    )


    # PROCESSING is detected from authoritative row state
    # before parsing a candidate/current attempt for
    # correlation. Therefore the denial is intentionally
    # uncorrelated rather than copying the caller lookup.
    assert (
        denial.get(
            "workflow_id"
        )
        is None
    )

    assert (
        denial.get(
            "tenant_id"
        )
        is None
    )

    assert (
        denial.get(
            "execution_attempt_ref"
        )
        is None
    )


    assert (
        winning_attempt
        not in str(
            denial
        )
    )


    # Exercise the same canonical success adapter used by
    # claim_and_execute_workflow, but feed it the result
    # re-read from PostgreSQL authority.
    events.clear()


    assert (
        integrations
        .emit_workflow_execution_claimed_security_event(
            tenant_id=
                authoritative.tenant_id,

            workflow_id=
                authoritative.workflow_id,

            execution_attempt_id=
                authoritative
                .execution_attempt_id,
        )
        is True
    )


    assert len(
        events
    ) == 1


    claim_payload = (
        events[
            0
        ]
        .to_dict()
    )


    expected_ref = (
        build_execution_attempt_ref(
            tenant_id=
                authoritative.tenant_id,

            workflow_id=
                authoritative.workflow_id,

            execution_attempt_id=
                winning_attempt,
        )
    )


    assert (
        claim_payload[
            "event_type"
        ]
        == "security.workflow.execution_claimed"
    )

    assert (
        claim_payload[
            "workflow_id"
        ]
        == authoritative.workflow_id
    )

    assert (
        claim_payload[
            "tenant_id"
        ]
        == authoritative.tenant_id
    )

    assert (
        claim_payload[
            "execution_attempt_ref"
        ]
        == expected_ref
    )


    assert (
        winning_attempt
        not in str(
            claim_payload
        )
    )



def test_postgresql_reconciliation_mismatch_telemetry_uses_locked_current_attempt(
    monkeypatch,
):
    """
    Stale caller reconciliation evidence cannot become
    canonical execution-attempt correlation.

    EA1 must derive from PostgreSQL's locked current attempt.
    """

    import app.security_observability_integrations as integrations

    from app.security_observability import (
        build_execution_attempt_ref,
    )


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


    approver = context(
        role="APPROVER",
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
                approver,
        )
    )


    assert (
        claimed.execution_attempt_id
        is not None
    )


    review = (
        first
        .mark_workflow_needs_review(
            result.workflow_id,
            (
                "PostgreSQL telemetry "
                "correlation proof."
            ),
            expected_execution_attempt_id=
                claimed.execution_attempt_id,
            security_context=
                approver,
        )
    )


    assert (
        review.status
        == "NEEDS_REVIEW"
    )


    events = []


    def capture(
        event,
    ):
        events.append(
            event
        )

        return True


    monkeypatch.setattr(
        integrations,
        "_emit_best_effort",
        capture,
    )


    stale_attempt = (
        "EXEC-STALE508C"
    )


    assert (
        stale_attempt
        != review.execution_attempt_id
    )


    with pytest.raises(
        PermissionError
    ):

        second.authorize_reconciled_retry(
            result.workflow_id,
            expected_execution_attempt_id=
                stale_attempt,
            security_context=
                approver,
        )


    authoritative = (
        authoritative_store
        .get_workflow(
            result.workflow_id
        )
    )


    assert (
        authoritative.status
        == "NEEDS_REVIEW"
    )

    assert (
        authoritative
        .execution_attempt_id
        == review.execution_attempt_id
    )

    assert (
        authoritative.tenant_id
        is not None
    )

    assert (
        authoritative
        .execution_attempt_id
        is not None
    )


    denials = [
        event.to_dict()
        for event in events
        if (
            event.to_dict()[
                "event_type"
            ]
            ==
            (
                "security.provider."
                "reconciliation_denied"
            )
        )
    ]


    assert len(
        denials
    ) == 1


    denial = denials[
        0
    ]


    assert (
        denial[
            "reason_code"
        ]
        == "execution_attempt_mismatch"
    )

    assert (
        denial[
            "source_component"
        ]
        == "workflow_postgresql_store"
    )

    assert (
        denial[
            "workflow_id"
        ]
        == authoritative.workflow_id
    )

    assert (
        denial[
            "tenant_id"
        ]
        == authoritative.tenant_id
    )


    expected_ref = (
        build_execution_attempt_ref(
            tenant_id=
                authoritative.tenant_id,

            workflow_id=
                authoritative.workflow_id,

            execution_attempt_id=
                authoritative
                .execution_attempt_id,
        )
    )


    assert (
        denial[
            "execution_attempt_ref"
        ]
        == expected_ref
    )


    # Neither the stale caller evidence nor the raw current
    # execution-attempt authority may appear in canonical output.
    assert (
        stale_attempt
        not in str(
            denial
        )
    )

    assert (
        authoritative
        .execution_attempt_id
        not in str(
            denial
        )
    )

    assert (
        denial.get(
            "provider_correlation_id"
        )
        is None
    )



def test_postgresql_wrong_state_reconciliation_denial_does_not_promote_lookup(
    monkeypatch,
):
    """
    A workflow_id supplied as a lookup argument is not canonical
    correlation until persisted WorkflowResult authority has been
    parsed.

    PROCESSING -> authorize retry fails before that boundary.
    """

    import app.security_observability_integrations as integrations


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


    approver = context(
        role="APPROVER",
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
                approver,
        )
    )


    assert (
        claimed.status
        == "PROCESSING"
    )

    assert (
        claimed.execution_attempt_id
        is not None
    )


    events = []


    def capture(
        event,
    ):
        events.append(
            event
        )

        return True


    monkeypatch.setattr(
        integrations,
        "_emit_best_effort",
        capture,
    )


    with pytest.raises(
        PermissionError
    ):

        second.authorize_reconciled_retry(
            result.workflow_id,
            expected_execution_attempt_id=
                claimed.execution_attempt_id,
            security_context=
                approver,
        )


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
        == claimed.execution_attempt_id
    )


    denials = [
        event.to_dict()
        for event in events
        if (
            event.to_dict()[
                "event_type"
            ]
            ==
            (
                "security.provider."
                "reconciliation_denied"
            )
        )
    ]


    assert len(
        denials
    ) == 1


    denial = (
        denials[
            0
        ]
    )


    assert (
        denial[
            "reason_code"
        ]
        == "workflow_transition_not_allowed"
    )


    assert (
        denial.get(
            "workflow_id"
        )
        is None
    )

    assert (
        denial.get(
            "tenant_id"
        )
        is None
    )

    assert (
        denial.get(
            "execution_attempt_ref"
        )
        is None
    )

    assert (
        denial.get(
            "provider_correlation_id"
        )
        is None
    )



def test_postgresql_observer_failure_cannot_change_authoritative_claim(
    monkeypatch,
):
    """
    An observer failure during a PostgreSQL-backed denial must not
    change the already-authoritative winning claim.

    Metrics failure is intentionally injected inside
    _emit_best_effort's independent metrics boundary.
    """

    import app.security_observability_integrations as integrations


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


    approver = context(
        role="APPROVER",
    )

    result = bound()


    first.save_workflow(
        result
    )


    winner = (
        first
        .claim_workflow_for_execution(
            result.workflow_id,
            security_context=
                approver,
        )
    )


    assert (
        winner.execution_attempt_id
        is not None
    )


    class SuccessfulAuditEmitter:

        def __init__(
            self,
            sink,
        ):
            self.sink = sink


        def emit(
            self,
            event,
        ):
            return None


    class FailingMetricsRegistry:

        def observe(
            self,
            event,
        ):
            raise RuntimeError(
                "STEP508C_OBSERVER_FAILURE_CANARY"
            )


    monkeypatch.setattr(
        integrations,
        "build_existing_audit_security_event_sink",
        lambda:
            object(),
    )

    monkeypatch.setattr(
        integrations,
        "SecurityEventEmitter",
        SuccessfulAuditEmitter,
    )

    monkeypatch.setattr(
        integrations,
        "get_process_security_metrics_registry",
        lambda:
            FailingMetricsRegistry(),
    )

    monkeypatch.setattr(
        integrations,
        "evaluate_security_event",
        lambda event:
            None,
    )


    with pytest.raises(
        PermissionError
    ):

        second.claim_workflow_for_execution(
            result.workflow_id,
            security_context=
                approver,
        )


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
        == winner.execution_attempt_id
    )
