from typing import Literal

from fastapi import HTTPException
from fastapi import status

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from app.auth import Principal

from app.security_context import (
    SecurityContext,
)


# -------------------------------------------------
# RETRIEVAL ACCESS
# -------------------------------------------------


RetrievalAccess = Literal[
    "standard",
    "restricted",
]


# -------------------------------------------------
# AUTHORITATIVE RETRIEVAL PRINCIPAL
# -------------------------------------------------


class RetrievalPrincipal(BaseModel):
    """
    Immutable identity used exclusively for knowledge
    retrieval authorization.

    This object is derived from trusted server-side
    SecurityContext state.

    It must never be populated from:

    - LLM-generated tool arguments
    - request-body authorization claims
    - query parameters
    - retrieved document metadata
    - MCP client-supplied authority claims

    Workflow role and approval authority are deliberately
    excluded from this model because those privileges must
    not implicitly grant knowledge access.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    principal_id: str = Field(
        min_length=1
    )

    tenant_id: str = Field(
        min_length=1
    )

    retrieval_access: RetrievalAccess


# -------------------------------------------------
# BUILD AUTHORITATIVE RETRIEVAL PRINCIPAL
# -------------------------------------------------


def build_retrieval_principal(
    security_context: SecurityContext,
) -> RetrievalPrincipal:
    """
    Derive retrieval identity only from trusted immutable
    server-side security context.

    The caller cannot independently choose principal,
    tenant, or retrieval-access authority here.
    """

    return RetrievalPrincipal(
        principal_id=
            security_context.principal_id,

        tenant_id=
            security_context.tenant_id,

        retrieval_access=
            security_context.retrieval_access,
    )


# -------------------------------------------------
# RESOLVE RETRIEVAL ACCESS
# -------------------------------------------------


def get_retrieval_access(
    principal: Principal,
) -> RetrievalAccess:

    # -------------------------------------------------
    # TRUST BOUNDARY
    # -------------------------------------------------
    #
    # Retrieval authority comes from the authenticated
    # Principal created by trusted application code.
    #
    # The LLM does not choose this value and tool
    # arguments cannot override it.
    # -------------------------------------------------

    access = principal.retrieval_access

    if access not in (
        "standard",
        "restricted",
    ):

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,

            detail=(
                "Principal does not have a valid "
                "retrieval-access authorization."
            ),
        )

    return access
