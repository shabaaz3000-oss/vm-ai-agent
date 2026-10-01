import inspect

import pytest

from app import workflow_store


def test_workflow_store_defaults_to_sqlite(
    monkeypatch,
):
    monkeypatch.delenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        raising=False,
    )

    assert (
        workflow_store
        .get_workflow_store_backend_name()
        == "sqlite"
    )

    assert isinstance(
        workflow_store.get_workflow_store(),
        workflow_store.SQLiteWorkflowStore,
    )


def test_explicit_sqlite_backend_is_selected(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "sqlite",
    )

    assert isinstance(
        workflow_store.get_workflow_store(),
        workflow_store.SQLiteWorkflowStore,
    )


def test_backend_name_is_normalized(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "  SQLITE  ",
    )

    assert (
        workflow_store
        .get_workflow_store_backend_name()
        == "sqlite"
    )


def test_blank_backend_fails_closed(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "   ",
    )

    with pytest.raises(
        RuntimeError,
        match="cannot be blank",
    ):
        workflow_store.get_workflow_store()


def test_postgresql_selection_fails_closed_until_installed(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "postgresql",
    )

    with pytest.raises(
        RuntimeError,
        match="PostgreSQL workflow store selected",
    ):
        workflow_store.get_workflow_store()


def test_unknown_backend_fails_closed(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "untrusted-backend",
    )

    with pytest.raises(
        RuntimeError,
        match="Unsupported workflow store backend",
    ):
        workflow_store.get_workflow_store()


def test_claim_public_signature_preserves_tenant_authority_boundary():
    signature = inspect.signature(
        workflow_store
        .claim_workflow_for_execution
    )

    assert set(
        signature.parameters
    ) == {
        "workflow_id",
        "security_context",
    }

    assert (
        signature.parameters[
            "security_context"
        ].kind
        is inspect.Parameter.KEYWORD_ONLY
    )

    for forbidden in (
        "tenant",
        "tenant_id",
        "principal",
        "provider",
        "assignment_group",
        "instance_url",
    ):
        assert (
            forbidden
            not in signature.parameters
        )


def test_reconciliation_public_signatures_preserve_authority_boundary():
    confirm_signature = (
        inspect.signature(
            workflow_store
            .confirm_reconciled_ticket_creation
        )
    )

    retry_signature = (
        inspect.signature(
            workflow_store
            .authorize_reconciled_retry
        )
    )

    assert set(
        confirm_signature.parameters
    ) == {
        "workflow_id",
        "expected_execution_attempt_id",
        "ticket_id",
        "security_context",
    }

    assert set(
        retry_signature.parameters
    ) == {
        "workflow_id",
        "expected_execution_attempt_id",
        "security_context",
    }

    for signature in (
        confirm_signature,
        retry_signature,
    ):
        assert (
            signature.parameters[
                "security_context"
            ].kind
            is inspect.Parameter.KEYWORD_ONLY
        )

        assert (
            signature.parameters[
                "expected_execution_attempt_id"
            ].kind
            is inspect.Parameter.KEYWORD_ONLY
        )
