from __future__ import annotations

import asyncio
import json
import tempfile

from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path

from mcp import Client

from app.auth import Principal

from app.mcp_server import (
    LOCAL_MCP_SESSION,
    LOCAL_MCP_TENANT_ID,
    build_mcp_execution_context,
    mcp,
)

from app.mcp_session import (
    MCPSessionAccessDenied,
    MCPSessionExpired,
    MCPSessionManager,
    MCPSessionNotFound,
    MCPSessionRevoked,
)

from app.mcp_session_runtime import (
    MCPSessionRuntimeConfigurationError,
    build_mcp_session_manager,
    load_mcp_session_runtime_settings,
)

from app.mcp_tenant import (
    MCPTenantResolutionError,
    load_trusted_mcp_tenant_bindings,
    resolve_mcp_tenant,
)

from app.security_context import (
    SecurityContext,
)

from app.tools.dispatcher import (
    ToolExecutionContext,
)


# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


MCP_IDENTITY_SECURITY_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "mcp_identity_security_cases.json"
)


# -------------------------------------------------
# RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class MCPIdentitySecurityEvaluationResult:

    total_cases: int

    allowed_cases: int
    blocked_cases: int
    authority_protection_cases: int

    passed_cases: int
    failed_cases: int

    unexpected_allows: int
    unexpected_blocks: int

    passed: bool


# -------------------------------------------------
# LOAD CORPUS
# -------------------------------------------------


def load_mcp_identity_security_cases(
    path: Path = (
        MCP_IDENTITY_SECURITY_CORPUS_PATH
    ),
) -> list[dict]:

    cases = json.loads(
        path.read_text(
            encoding="utf-8-sig"
        )
    )

    if not isinstance(
        cases,
        list,
    ):
        raise ValueError(
            "MCP identity security corpus "
            "must contain a JSON list."
        )

    return cases


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def _principal(
    username: str,
) -> Principal:

    return Principal(
        username=username,
        role="ANALYST",
        retrieval_access="standard",
    )


def _fixed_time() -> datetime:

    return datetime(
        2026,
        9,
        26,
        12,
        0,
        tzinfo=timezone.utc,
    )


# -------------------------------------------------
# SESSION ATTACK OBSERVATION
# -------------------------------------------------


async def observe_mcp_identity_case(
    client: Client,
    case: dict,
) -> bool:

    attack = case[
        "attack"
    ]

    manager = MCPSessionManager(
        session_ttl=timedelta(
            minutes=30
        )
    )

    alice = _principal(
        "alice"
    )

    bob = _principal(
        "bob"
    )

    start = _fixed_time()

    session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    # -------------------------------------------------
    # LEGITIMATE OWNER
    # -------------------------------------------------

    if attack == "valid_owner":

        context = (
            manager.build_security_context(
                alice,
                session_id=
                    session.session_id,
                tenant_id="tenant-a",
                now=start,
            )
        )

        return (
            context.principal_id
            == "alice"
            and context.tenant_id
            == "tenant-a"
            and context.session_id
            == session.session_id
        )

    # -------------------------------------------------
    # CROSS USER
    # -------------------------------------------------

    if attack == "cross_user":

        try:
            manager.build_security_context(
                bob,
                session_id=
                    session.session_id,
                tenant_id="tenant-a",
                now=start,
            )

        except MCPSessionAccessDenied:
            return False

        return True

    # -------------------------------------------------
    # CROSS TENANT
    # -------------------------------------------------

    if attack == "cross_tenant":

        try:
            manager.build_security_context(
                alice,
                session_id=
                    session.session_id,
                tenant_id="tenant-b",
                now=start,
            )

        except MCPSessionAccessDenied:
            return False

        return True

    # -------------------------------------------------
    # EXPIRED SESSION
    # -------------------------------------------------

    if attack == "expired_session":

        try:
            manager.build_security_context(
                alice,
                session_id=
                    session.session_id,
                tenant_id="tenant-a",
                now=(
                    start
                    + timedelta(
                        minutes=30
                    )
                ),
            )

        except MCPSessionExpired:
            return False

        return True

    # -------------------------------------------------
    # UNKNOWN SESSION
    # -------------------------------------------------

    if attack == "unknown_session":

        try:
            manager.build_security_context(
                alice,
                session_id=
                    "attacker-controlled-session",
                tenant_id="tenant-a",
                now=start,
            )

        except MCPSessionNotFound:
            return False

        return True

    # -------------------------------------------------
    # MUTABLE CLAIM DRIFT
    # -------------------------------------------------

    if attack == "role_drift":

        security_context = (
            manager.build_security_context(
                alice,
                session_id=
                    session.session_id,
                tenant_id="tenant-a",
                now=start,
            )
        )

        tool_context = (
            ToolExecutionContext(
                principal=alice,
                security_context=
                    security_context,
            )
        )

        alice.role = "APPROVER"

        try:
            (
                tool_context
                .validate_security_binding()
            )

        except ValueError:
            return False

        return True

    # -------------------------------------------------
    # CLIENT SESSION ARGUMENT SPOOF
    # -------------------------------------------------

    if attack == "session_argument_injection":

        result = await client.call_tool(
            "get_finding",
            {
                "session_id":
                    "attacker-session"
            },
        )

        # A transport-level rejection is secure.
        if result.is_error:
            return False

        # Some MCP implementations may tolerate or
        # ignore unknown arguments. That is also secure
        # only if server-controlled authority remains
        # unchanged.
        context = (
            build_mcp_execution_context()
        )

        security_context = (
            context.security_context
        )

        if security_context is None:
            return True

        attacker_gained_authority = not (
            security_context.session_id
            == LOCAL_MCP_SESSION.session_id

            and security_context.tenant_id
            == LOCAL_MCP_TENANT_ID
        )

        return attacker_gained_authority

    # -------------------------------------------------
    # CLIENT TENANT ARGUMENT SPOOF
    # -------------------------------------------------

    if attack == "tenant_argument_injection":

        result = await client.call_tool(
            "get_finding",
            {
                "tenant_id":
                    "attacker-tenant"
            },
        )

        # Rejection is secure. If the MCP transport
        # tolerates the extra field, verify that it did
        # not replace server-controlled authority.
        if result.is_error:
            return False

        context = (
            build_mcp_execution_context()
        )

        security_context = (
            context.security_context
        )

        if security_context is None:
            return True

        attacker_gained_authority = not (
            security_context.session_id
            == LOCAL_MCP_SESSION.session_id

            and security_context.tenant_id
            == LOCAL_MCP_TENANT_ID
        )

        return attacker_gained_authority


    # -------------------------------------------------
    # PRODUCTION STORE CONFIGURATION MUST BE EXPLICIT
    # -------------------------------------------------

    if attack == "production_missing_store":

        try:
            load_mcp_session_runtime_settings(
                {
                    "VM_AI_ENV":
                        "production",
                }
            )

        except MCPSessionRuntimeConfigurationError:
            return False

        return True


    # -------------------------------------------------
    # PRODUCTION CANNOT USE EPHEMERAL SESSION STORAGE
    # -------------------------------------------------

    if attack == "production_memory_store":

        try:
            load_mcp_session_runtime_settings(
                {
                    "VM_AI_ENV":
                        "production",

                    "VM_AI_SESSION_STORE":
                        "memory",
                }
            )

        except MCPSessionRuntimeConfigurationError:
            return False

        return True


    # -------------------------------------------------
    # PRODUCTION TENANT BINDINGS MUST BE EXPLICIT
    # -------------------------------------------------

    if attack == "production_missing_tenant_binding":

        try:
            load_trusted_mcp_tenant_bindings(
                {
                    "VM_AI_ENV":
                        "production",
                }
            )

        except MCPTenantResolutionError:
            return False

        return True


    # -------------------------------------------------
    # UNBOUND PRINCIPAL CANNOT SELF-ESTABLISH TENANCY
    # -------------------------------------------------

    if attack == "unbound_principal_tenant":

        try:
            resolve_mcp_tenant(
                alice,
                environment={
                    "VM_AI_ENV":
                        "production",

                    "VM_AI_MCP_TENANT_BINDINGS":
                        (
                            '{"bob": "tenant-b"}'
                        ),
                },
            )

        except MCPTenantResolutionError:
            return False

        return True


    # -------------------------------------------------
    # REVOCATION SURVIVES MANAGER RECONSTRUCTION
    # -------------------------------------------------

    if attack == "durable_revocation_reconstruction":

        with tempfile.TemporaryDirectory() as temp_dir:

            database_path = (
                Path(temp_dir)
                / "mcp_sessions.db"
            )

            environment = {
                "VM_AI_ENV":
                    "production",

                "VM_AI_SESSION_STORE":
                    "sqlite",

                "VM_AI_SESSION_DB_PATH":
                    str(database_path),

                "VM_AI_SESSION_TTL_MINUTES":
                    "30",
            }

            first_manager = (
                build_mcp_session_manager(
                    environment
                )
            )

            durable_session = (
                first_manager.create_session(
                    alice,
                    tenant_id="tenant-a",
                    now=start,
                )
            )

            first_manager.revoke_session(
                alice,
                session_id=
                    durable_session.session_id,
                tenant_id="tenant-a",
                now=start,
            )

            reconstructed_manager = (
                build_mcp_session_manager(
                    environment
                )
            )

            try:
                reconstructed_manager.build_security_context(
                    alice,
                    session_id=
                        durable_session.session_id,
                    tenant_id="tenant-a",
                    now=start,
                )

            except MCPSessionRevoked:
                return False

            return True


    raise ValueError(
        "Unknown MCP identity attack: "
        f"{attack}"
    )


# -------------------------------------------------
# EVALUATOR
# -------------------------------------------------


async def run_mcp_identity_security_evaluation_async(
    path: Path = (
        MCP_IDENTITY_SECURITY_CORPUS_PATH
    ),
) -> MCPIdentitySecurityEvaluationResult:

    cases = (
        load_mcp_identity_security_cases(
            path
        )
    )

    allowed_cases = 0
    blocked_cases = 0
    authority_protection_cases = 0

    passed_cases = 0
    failed_cases = 0

    unexpected_allows = 0
    unexpected_blocks = 0

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        for case in cases:

            allowed = (
                await observe_mcp_identity_case(
                    client,
                    case,
                )
            )

            expected = case[
                "expected_behavior"
            ]

            case_passed = False

            if expected == "allow":

                allowed_cases += 1

                if allowed:
                    case_passed = True
                else:
                    unexpected_blocks += 1

            elif expected == "block":

                blocked_cases += 1

                if not allowed:
                    case_passed = True
                else:
                    unexpected_allows += 1

            elif (
                expected
                == "protect_authority"
            ):

                authority_protection_cases += 1

                # Secure outcomes:
                #
                # 1. MCP rejects the injected identity
                #    argument.
                #
                # 2. MCP tolerates/ignores the argument
                #    while preserving server-controlled
                #    session and tenant authority.
                #
                # For these cases, True means the
                # attacker successfully changed trusted
                # authority. False means authority was
                # protected.
                if not allowed:
                    case_passed = True
                else:
                    unexpected_allows += 1

            else:
                raise ValueError(
                    "Unknown expected behavior: "
                    f"{expected}"
                )

            if case_passed:
                passed_cases += 1
            else:
                failed_cases += 1

    return MCPIdentitySecurityEvaluationResult(
        total_cases=len(cases),

        allowed_cases=
            allowed_cases,

        blocked_cases=
            blocked_cases,

        authority_protection_cases=
            authority_protection_cases,

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        unexpected_allows=
            unexpected_allows,

        unexpected_blocks=
            unexpected_blocks,

        passed=(
            failed_cases == 0
        ),
    )


def run_mcp_identity_security_evaluation(
    path: Path = (
        MCP_IDENTITY_SECURITY_CORPUS_PATH
    ),
) -> MCPIdentitySecurityEvaluationResult:

    return asyncio.run(
        run_mcp_identity_security_evaluation_async(
            path
        )
    )
