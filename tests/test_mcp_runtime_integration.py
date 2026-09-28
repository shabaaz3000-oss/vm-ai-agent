from __future__ import annotations

import json
import os
import subprocess
import sys

from pathlib import Path

import pytest

from app.auth import Principal
from app.mcp_session_runtime import (
    build_mcp_session_manager,
)
from app.mcp_sqlite_session_store import (
    SQLiteSessionStore,
)


PROJECT_ROOT = (
    Path(__file__).resolve().parents[1]
)

RUNTIME_ENVIRONMENT_KEYS = (
    "VM_AI_ENV",
    "VM_AI_SESSION_STORE",
    "VM_AI_SESSION_DB_PATH",
    "VM_AI_SESSION_TTL_MINUTES",
    "VM_AI_MCP_TENANT_BINDINGS",
)


def _runtime_environment(
    database_path: Path,
    *,
    tenant_bindings: str | None,
) -> dict[str, str]:

    environment = os.environ.copy()

    for key in RUNTIME_ENVIRONMENT_KEYS:
        environment.pop(
            key,
            None,
        )

    environment.update(
        {
            "VM_AI_ENV":
                "production",

            "VM_AI_SESSION_STORE":
                "sqlite",

            "VM_AI_SESSION_DB_PATH":
                str(database_path),

            "VM_AI_SESSION_TTL_MINUTES":
                "30",
        }
    )

    if tenant_bindings is not None:
        environment[
            "VM_AI_MCP_TENANT_BINDINGS"
        ] = tenant_bindings

    return environment


def _manager_environment(
    database_path: Path,
) -> dict[str, str]:

    return {
        "VM_AI_ENV":
            "production",

        "VM_AI_SESSION_STORE":
            "sqlite",

        "VM_AI_SESSION_DB_PATH":
            str(database_path),

        "VM_AI_SESSION_TTL_MINUTES":
            "30",
    }


def _run_mcp_runtime(
    database_path: Path,
    *,
    tenant_bindings: str | None,
) -> subprocess.CompletedProcess[str]:

    code = r"""
import inspect
import json

from app import mcp_server as server


tool_functions = (
    server.mcp_get_finding,
    server.mcp_get_asset_details,
    server.mcp_get_threat_intel,
    server.mcp_search_knowledge,
)

payload = {
    "principal_id":
        server.LOCAL_MCP_PRINCIPAL.username,

    "tenant_id":
        server.LOCAL_MCP_TENANT_ID,

    "session_id":
        server.LOCAL_MCP_SESSION.session_id,

    "session_tenant_id":
        server.LOCAL_MCP_SESSION.tenant_id,

    "security_context_tenant_id":
        server.build_mcp_security_context().tenant_id,

    "tool_parameters": [
        list(
            inspect.signature(
                function
            ).parameters
        )
        for function in tool_functions
    ],
}

print(
    "MCP_RUNTIME_RESULT="
    + json.dumps(
        payload
    )
)
"""

    return subprocess.run(
        [
            sys.executable,
            "-c",
            code,
        ],
        cwd=PROJECT_ROOT,
        env=_runtime_environment(
            database_path,
            tenant_bindings=
                tenant_bindings,
        ),
        capture_output=True,
        text=True,
        check=False,
    )


def _runtime_payload(
    result: subprocess.CompletedProcess[str],
) -> dict[str, object]:

    prefix = "MCP_RUNTIME_RESULT="

    for line in reversed(
        result.stdout.splitlines()
    ):

        if line.startswith(
            prefix
        ):
            return json.loads(
                line[
                    len(prefix):
                ]
            )

    raise AssertionError(
        "MCP runtime result marker "
        "was not emitted.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def _assert_validation_denied(
    manager,
    principal: Principal,
    *,
    session_id: str,
    tenant_id: str,
) -> None:

    try:
        manager.validate_session(
            principal,
            session_id=session_id,
            tenant_id=tenant_id,
        )

    except Exception:
        return

    pytest.fail(
        "MCP session validation unexpectedly succeeded."
    )


def test_production_runtime_uses_durable_session_and_trusted_tenant(
    tmp_path,
):

    database_path = (
        tmp_path
        / "runtime.db"
    )

    result = _run_mcp_runtime(
        database_path,
        tenant_bindings=(
            '{"mcp-local-analyst": "tenant-prod"}'
        ),
    )

    assert result.returncode == 0, (
        result.stderr
    )

    payload = _runtime_payload(
        result
    )

    assert (
        payload["principal_id"]
        == "mcp-local-analyst"
    )

    assert (
        payload["tenant_id"]
        == "tenant-prod"
    )

    assert (
        payload["session_tenant_id"]
        == "tenant-prod"
    )

    assert (
        payload[
            "security_context_tenant_id"
        ]
        == "tenant-prod"
    )

    store = SQLiteSessionStore(
        database_path=database_path
    )

    persisted = store.get(
        str(
            payload["session_id"]
        )
    )

    assert persisted is not None

    assert (
        persisted.principal_id
        == "mcp-local-analyst"
    )

    assert (
        persisted.tenant_id
        == "tenant-prod"
    )


def test_production_runtime_fails_closed_without_tenant_bindings(
    tmp_path,
):

    result = _run_mcp_runtime(
        tmp_path / "runtime.db",
        tenant_bindings=None,
    )

    assert result.returncode != 0

    assert (
        "VM_AI_MCP_TENANT_BINDINGS"
        in result.stderr
    )


def test_production_runtime_rejects_unbound_server_identity(
    tmp_path,
):

    result = _run_mcp_runtime(
        tmp_path / "runtime.db",
        tenant_bindings=(
            '{"some-other-principal": "tenant-prod"}'
        ),
    )

    assert result.returncode != 0

    assert (
        "No trusted MCP tenant binding exists"
        in result.stderr
    )


def test_runtime_session_survives_manager_reconstruction(
    tmp_path,
):

    database_path = (
        tmp_path
        / "runtime.db"
    )

    result = _run_mcp_runtime(
        database_path,
        tenant_bindings=(
            '{"mcp-local-analyst": "tenant-prod"}'
        ),
    )

    assert result.returncode == 0, (
        result.stderr
    )

    payload = _runtime_payload(
        result
    )

    principal = Principal(
        username="mcp-local-analyst",
        role="ANALYST",
        retrieval_access="standard",
    )

    reconstructed_manager = (
        build_mcp_session_manager(
            _manager_environment(
                database_path
            )
        )
    )

    validated = (
        reconstructed_manager
        .validate_session(
            principal,
            session_id=str(
                payload["session_id"]
            ),
            tenant_id="tenant-prod",
        )
    )

    assert (
        validated.session_id
        == payload["session_id"]
    )


def test_runtime_session_rejects_cross_identity_and_cross_tenant_use(
    tmp_path,
):

    database_path = (
        tmp_path
        / "runtime.db"
    )

    result = _run_mcp_runtime(
        database_path,
        tenant_bindings=(
            '{"mcp-local-analyst": "tenant-prod"}'
        ),
    )

    assert result.returncode == 0, (
        result.stderr
    )

    payload = _runtime_payload(
        result
    )

    manager = (
        build_mcp_session_manager(
            _manager_environment(
                database_path
            )
        )
    )

    legitimate_principal = Principal(
        username="mcp-local-analyst",
        role="ANALYST",
        retrieval_access="standard",
    )

    attacker_principal = Principal(
        username="mallory",
        role="ANALYST",
        retrieval_access="standard",
    )

    session_id = str(
        payload["session_id"]
    )

    _assert_validation_denied(
        manager,
        attacker_principal,
        session_id=session_id,
        tenant_id="tenant-prod",
    )

    _assert_validation_denied(
        manager,
        legitimate_principal,
        session_id=session_id,
        tenant_id="attacker-tenant",
    )


def test_runtime_revocation_remains_authoritative_after_reconstruction(
    tmp_path,
):

    database_path = (
        tmp_path
        / "runtime.db"
    )

    result = _run_mcp_runtime(
        database_path,
        tenant_bindings=(
            '{"mcp-local-analyst": "tenant-prod"}'
        ),
    )

    assert result.returncode == 0, (
        result.stderr
    )

    payload = _runtime_payload(
        result
    )

    principal = Principal(
        username="mcp-local-analyst",
        role="ANALYST",
        retrieval_access="standard",
    )

    session_id = str(
        payload["session_id"]
    )

    first_manager = (
        build_mcp_session_manager(
            _manager_environment(
                database_path
            )
        )
    )

    revoked = (
        first_manager.revoke_session(
            principal,
            session_id=session_id,
            tenant_id="tenant-prod",
        )
    )

    assert revoked.revoked_at is not None

    second_manager = (
        build_mcp_session_manager(
            _manager_environment(
                database_path
            )
        )
    )

    _assert_validation_denied(
        second_manager,
        principal,
        session_id=session_id,
        tenant_id="tenant-prod",
    )

    authoritative_store = (
        SQLiteSessionStore(
            database_path=database_path
        )
    )

    authoritative_session = (
        authoritative_store.get(
            session_id
        )
    )

    assert authoritative_session is not None

    assert (
        authoritative_session.revoked_at
        is not None
    )


def test_mcp_tools_expose_no_tenant_selection_argument(
    tmp_path,
):

    result = _run_mcp_runtime(
        tmp_path / "runtime.db",
        tenant_bindings=(
            '{"mcp-local-analyst": "tenant-prod"}'
        ),
    )

    assert result.returncode == 0, (
        result.stderr
    )

    payload = _runtime_payload(
        result
    )

    for parameters in (
        payload["tool_parameters"]
    ):
        assert (
            "tenant_id"
            not in parameters
        )
