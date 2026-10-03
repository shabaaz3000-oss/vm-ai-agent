from contextlib import asynccontextmanager

from fastapi import Depends
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import status

from app.auth import Principal
from app.auth import require_approver
from app.auth import require_authenticated_user

from app.execution import (
    claim_and_execute_workflow,
    reconcile_stale_workflow,
)

from app.models import WorkflowResult

from app.workflow import prepare_workflow

from app.workflow_store import (
    get_workflow,
    save_workflow,
    validate_workflow_store_readiness,
    reject_workflow_authoritatively,
)

from app.api_security_context import (
    APIContextConfigurationError,
    APITenantBindingError,
    build_api_security_context,
)
from app.audit import log_event
from app.providers.servicenow_client import (
    ServiceNowClientError,
)
from app.servicenow_reconciliation import (
    resolve_servicenow_workflow,
)
from app.legacy_audit_hygiene import build_legacy_execution_attempt_audit_fields


# -------------------------------------------------
# APPLICATION
# -------------------------------------------------


@asynccontextmanager
async def _lifespan(
    _app: FastAPI,
):

    validate_workflow_store_readiness()

    yield


app = FastAPI(
    title="VM AI Agent API",
    version="0.3.0",
    lifespan=_lifespan,
    description=(
        "Secure AI-assisted vulnerability management "
        "workflow API with authentication, RBAC, "
        "persistent state, and atomic execution claims."
    ),
)


# -------------------------------------------------
# HEALTH
# -------------------------------------------------


@app.get(
    "/health"
)
def health():

    return {
        "status": "ok"
    }


# -------------------------------------------------
# CREATE / PREPARE WORKFLOW
# -------------------------------------------------


@app.post(
    "/workflows",
    response_model=WorkflowResult,
    status_code=status.HTTP_201_CREATED,
)
def create_workflow(
    principal: Principal = Depends(
        require_authenticated_user
    )
):

    result = prepare_workflow()

    save_workflow(
        result
    )

    return result


# -------------------------------------------------
# GET WORKFLOW
# -------------------------------------------------


@app.get(
    "/workflows/{workflow_id}",
    response_model=WorkflowResult,
)
def read_workflow(
    workflow_id: str,

    principal: Principal = Depends(
        require_authenticated_user
    )
):

    try:

        return get_workflow(
            workflow_id
        )

    except KeyError:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workflow not found.",
        )


# -------------------------------------------------
# APPROVE + EXECUTE WORKFLOW
# -------------------------------------------------


@app.post(
    "/workflows/{workflow_id}/approve",
    response_model=WorkflowResult,
)
def approve_workflow(
    workflow_id: str,

    principal: Principal = Depends(
        require_approver
    )
):

    try:

        authoritative = (
            get_workflow(
                workflow_id
            )
        )

        if authoritative is None:

            raise KeyError(
                workflow_id
            )

        trusted_context = None

        if authoritative.tenant_id is not None:

            try:

                trusted_context = (
                    build_api_security_context(
                        principal
                    )
                )

            except APITenantBindingError:

                raise HTTPException(
                    status_code=
                        status.HTTP_403_FORBIDDEN,

                    detail=(
                        "Authenticated principal has no "
                        "trusted API tenant binding."
                    ),
                )

            except APIContextConfigurationError:

                raise HTTPException(
                    status_code=
                        status.HTTP_503_SERVICE_UNAVAILABLE,

                    detail=(
                        "Trusted API tenant authority "
                        "is unavailable."
                    ),
                )

        if trusted_context is None:

            completed_result = (
                claim_and_execute_workflow(
                    workflow_id=
                        workflow_id,

                    approved_by=
                        principal.username,
                )
            )

        else:

            completed_result = (
                claim_and_execute_workflow(
                    workflow_id=
                        workflow_id,

                    approved_by=
                        principal.username,

                    security_context=
                        trusted_context,
                )
            )

    except KeyError:

        raise HTTPException(
            status_code=
                status.HTTP_404_NOT_FOUND,

            detail=
                "Workflow not found.",
        )

    except PermissionError as error:

        raise HTTPException(
            status_code=
                status.HTTP_409_CONFLICT,

            detail=
                str(error),
        )

    return completed_result


# -------------------------------------------------
# REJECT WORKFLOW
# -------------------------------------------------


@app.post(
    "/workflows/{workflow_id}/reject",
    response_model=WorkflowResult,
)
def reject_workflow_endpoint(
    workflow_id: str,

    principal: Principal = Depends(
        require_approver
    )
):

    try:

        authoritative = (
            get_workflow(
                workflow_id
            )
        )

        if authoritative is None:

            raise KeyError(
                workflow_id
            )

        trusted_context = None

        if authoritative.tenant_id is not None:

            try:

                trusted_context = (
                    build_api_security_context(
                        principal
                    )
                )

            except APITenantBindingError:

                raise HTTPException(
                    status_code=
                        status.HTTP_403_FORBIDDEN,

                    detail=(
                        "Authenticated principal has no "
                        "trusted API tenant binding."
                    ),
                )

            except APIContextConfigurationError:

                raise HTTPException(
                    status_code=
                        status.HTTP_503_SERVICE_UNAVAILABLE,

                    detail=(
                        "Trusted API tenant authority "
                        "is unavailable."
                    ),
                )

        if trusted_context is None:

            rejected_result = (
                reject_workflow_authoritatively(
                    workflow_id
                )
            )

        else:

            rejected_result = (
                reject_workflow_authoritatively(
                    workflow_id,
                    security_context=
                        trusted_context,
                )
            )

    except KeyError:

        raise HTTPException(
            status_code=
                status.HTTP_404_NOT_FOUND,

            detail=
                "Workflow not found.",
        )

    except PermissionError as error:

        raise HTTPException(
            status_code=
                status.HTTP_409_CONFLICT,

            detail=
                str(error),
        )

    return rejected_result


# -------------------------------------------------
# RECONCILE STALE PROCESSING WORKFLOW
# -------------------------------------------------


@app.post(
    "/workflows/{workflow_id}/reconcile",
    response_model=WorkflowResult,
)
def reconcile_workflow(
    workflow_id: str,

    principal: Principal = Depends(
        require_approver
    )
):

    try:

        result = (
            reconcile_stale_workflow(
                workflow_id=workflow_id
            )
        )

    except KeyError:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workflow not found.",
        )

    except PermissionError as error:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )

    except ValueError as error:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    return result

# -------------------------------------------------
# SERVICENOW HUMAN RECONCILIATION CONTROL PLANE
# -------------------------------------------------


def _servicenow_resolution_audit_fields(
    workflow_id: str,
    principal: Principal,
    *,
    security_context: SecurityContext | None = None,
) -> dict[str, str]:
    """
    Return non-secret identity fields for operator audit events.

    Raw API session identifiers are deliberately excluded.
    """

    details = {
        "workflow_id":
            workflow_id,

        "principal_id":
            principal.username,

        "role":
            principal.role,
    }

    if security_context is not None:

        details.update(
            {
                "tenant_id":
                    security_context.tenant_id,

                "session_correlation_id":
                    security_context
                    .session_correlation_id,
            }
        )

    return details


@app.post(
    "/workflows/{workflow_id}/servicenow-resolution",
    response_model=WorkflowResult,
)
def resolve_servicenow_workflow_endpoint(
    workflow_id: str,

    principal: Principal = Depends(
        require_approver
    ),
):
    """
    Human-operator-only ServiceNow reconciliation resolution.

    The request supplies no reconciliation truth. The server
    derives tenant/session authority, performs a fresh read-only
    ServiceNow lookup, and applies the allowed atomic transition.
    """

    try:

        trusted_context = (
            build_api_security_context(
                principal
            )
        )

    except APITenantBindingError:

        log_event(
            "SERVICENOW_RECONCILIATION_DENIED",
            {
                **_servicenow_resolution_audit_fields(
                    workflow_id,
                    principal,
                ),

                "reason":
                    "principal_not_tenant_bound",
            },
        )

        raise HTTPException(
            status_code=
                status.HTTP_403_FORBIDDEN,

            detail=(
                "Authenticated principal has no "
                "trusted API tenant binding."
            ),
        )

    except APIContextConfigurationError:

        log_event(
            "SERVICENOW_RECONCILIATION_FAILED",
            {
                **_servicenow_resolution_audit_fields(
                    workflow_id,
                    principal,
                ),

                "reason":
                    "api_tenant_authority_unavailable",
            },
        )

        raise HTTPException(
            status_code=
                status.HTTP_503_SERVICE_UNAVAILABLE,

            detail=(
                "Trusted API tenant authority "
                "is unavailable."
            ),
        )

    audit_identity = (
        _servicenow_resolution_audit_fields(
            workflow_id,
            principal,
            security_context=
                trusted_context,
        )
    )

    log_event(
        "SERVICENOW_RECONCILIATION_REQUESTED",
        audit_identity,
    )

    try:

        resolved = (
            resolve_servicenow_workflow(
                workflow_id,
                security_context=
                    trusted_context,
            )
        )

    except KeyError:

        log_event(
            "SERVICENOW_RECONCILIATION_FAILED",
            {
                **audit_identity,
                "reason":
                    "workflow_not_found",
            },
        )

        raise HTTPException(
            status_code=
                status.HTTP_404_NOT_FOUND,

            detail=
                "Workflow not found.",
        )

    except PermissionError as error:

        log_event(
            "SERVICENOW_RECONCILIATION_DENIED",
            {
                **audit_identity,

                "reason":
                    error.__class__.__name__,
            },
        )

        raise HTTPException(
            status_code=
                status.HTTP_409_CONFLICT,

            detail=
                str(error),
        )

    except ServiceNowClientError:

        log_event(
            "SERVICENOW_RECONCILIATION_FAILED",
            {
                **audit_identity,

                "reason":
                    "servicenow_lookup_failed",
            },
        )

        raise HTTPException(
            status_code=
                status.HTTP_502_BAD_GATEWAY,

            detail=(
                "ServiceNow reconciliation "
                "lookup failed."
            ),
        )

    except ValueError as error:

        log_event(
            "SERVICENOW_RECONCILIATION_FAILED",
            {
                **audit_identity,

                "reason":
                    error.__class__.__name__,
            },
        )

        raise HTTPException(
            status_code=
                status.HTTP_400_BAD_REQUEST,

            detail=
                str(error),
        )

    resolution = (
        "CONFIRMED"
        if resolved.status
        == "TICKET_CREATED"

        else "RETRY_AUTHORIZED"
        if resolved.status
        == "AWAITING_APPROVAL"

        else "UNKNOWN"
    )

    log_event(
        "SERVICENOW_RECONCILIATION_RESOLVED",
        {
            **audit_identity,

            "resolution":
                resolution,

            "workflow_status":
                resolved.status,

            **build_legacy_execution_attempt_audit_fields(
                tenant_id=
                    trusted_context.tenant_id,
                workflow_id=
                    resolved.workflow_id,
                execution_attempt_id=
                    resolved.execution_attempt_id,
            ),
        },
    )

    return resolved
