from __future__ import annotations

from app.models import WorkflowResult
from app.security_context import SecurityContext


class WorkflowTenantBindingError(
    PermissionError
):
    """
    Raised when workflow tenant authority is missing,
    malformed, or inconsistent with trusted server-side
    SecurityContext authority.
    """


def _trusted_tenant_id(
    security_context: SecurityContext,
) -> str:
    """
    Return the internal application tenant carried by a
    trusted immutable SecurityContext.

    Tenant authority must never be accepted from workflow
    request bodies, ticket fields, model output, MCP
    arguments, asset ownership, or provider responses.
    """

    if not isinstance(
        security_context,
        SecurityContext,
    ):
        raise WorkflowTenantBindingError(
            "Trusted SecurityContext is required."
        )

    tenant_id = (
        security_context.tenant_id
    )

    if (
        not isinstance(
            tenant_id,
            str,
        )
        or not tenant_id.strip()
        or tenant_id != tenant_id.strip()
    ):
        raise WorkflowTenantBindingError(
            "Trusted workflow tenant authority is invalid."
        )

    return tenant_id


def bind_workflow_tenant(
    result: WorkflowResult,
    *,
    security_context: SecurityContext,
) -> WorkflowResult:
    """
    Bind an unbound workflow to the internal tenant carried
    by trusted SecurityContext authority.

    Binding is monotonic:

    - an unbound workflow may become bound;
    - an already-bound workflow may be revalidated against
      the same trusted tenant;
    - a workflow can never be rebound to another tenant.

    This prevents cross-tenant mutation after workflow
    creation.
    """

    if not isinstance(
        result,
        WorkflowResult,
    ):
        raise TypeError(
            "WorkflowResult is required."
        )

    tenant_id = _trusted_tenant_id(
        security_context
    )

    current_tenant = (
        result.tenant_id
    )

    if current_tenant is not None:

        if (
            not isinstance(
                current_tenant,
                str,
            )
            or not current_tenant.strip()
            or current_tenant
            != current_tenant.strip()
        ):
            raise WorkflowTenantBindingError(
                "Workflow tenant binding is invalid."
            )

        if current_tenant != tenant_id:

            raise WorkflowTenantBindingError(
                "Workflow belongs to a different tenant."
            )

        return result

    data = (
        result.model_dump()
    )

    data[
        "tenant_id"
    ] = tenant_id

    return WorkflowResult.model_validate(
        data
    )


def require_workflow_tenant(
    result: WorkflowResult,
    *,
    security_context: SecurityContext,
) -> str:
    """
    Require an existing workflow tenant binding to exactly
    match the trusted SecurityContext tenant.

    This function is intended for tenant-sensitive reads,
    approval/execution boundaries, and external routing.
    """

    if not isinstance(
        result,
        WorkflowResult,
    ):
        raise TypeError(
            "WorkflowResult is required."
        )

    trusted_tenant = (
        _trusted_tenant_id(
            security_context
        )
    )

    workflow_tenant = (
        result.tenant_id
    )

    if (
        not isinstance(
            workflow_tenant,
            str,
        )
        or not workflow_tenant.strip()
        or workflow_tenant
        != workflow_tenant.strip()
    ):
        raise WorkflowTenantBindingError(
            "Workflow does not contain trusted "
            "tenant authority."
        )

    if workflow_tenant != trusted_tenant:

        raise WorkflowTenantBindingError(
            "Workflow belongs to a different tenant."
        )

    return workflow_tenant
