from typing import Literal

from fastapi import HTTPException
from fastapi import status

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from app.auth import Principal
from app.models import KnowledgeChunk

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
# DEFAULT-DENY KNOWLEDGE AUTHORIZATION
# -------------------------------------------------


RetrievalAuthorizationReason = Literal[
    "allowed",
    "missing_tenant_scope",
    "tenant_mismatch",
    "principal_acl_denied",
    "invalid_retrieval_access",
    "classification_denied",
    "invalid_authorization_metadata",
]


class RetrievalAuthorizationDecision(BaseModel):
    """
    Structured result for a knowledge authorization decision.

    The decision intentionally contains no document content,
    embedding data, session identifiers, or raw client input.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    allowed: bool

    reason: RetrievalAuthorizationReason


def evaluate_knowledge_chunk_authorization(
    *,
    chunk: KnowledgeChunk,
    caller_access: RetrievalAccess | None = None,
    retrieval_principal: RetrievalPrincipal | None = None,
) -> RetrievalAuthorizationDecision:
    """
    Evaluate whether a knowledge chunk is eligible for
    retrieval before semantic search.

    Principal-aware authorization evaluates:

    1. authoritative tenant membership
    2. document-level principal ACL
    3. standard/restricted knowledge classification

    The returned reason code is deterministic and safe for
    structured audit logging.
    """

    # -------------------------------------------------
    # PRINCIPAL-AWARE ENTERPRISE AUTHORIZATION
    # -------------------------------------------------

    if retrieval_principal is not None:

        # ---------------------------------------------
        # TENANT SCOPE ? DEFAULT DENY
        # ---------------------------------------------

        if chunk.tenant_id is None:

            return RetrievalAuthorizationDecision(
                allowed=False,
                reason=
                    "missing_tenant_scope",
            )

        if (
            chunk.tenant_id
            != retrieval_principal.tenant_id
        ):

            return RetrievalAuthorizationDecision(
                allowed=False,
                reason=
                    "tenant_mismatch",
            )

        # ---------------------------------------------
        # DOCUMENT ACL
        # ---------------------------------------------

        if (
            chunk.allowed_principal_ids
            is not None
            and
            retrieval_principal.principal_id
            not in chunk.allowed_principal_ids
        ):

            return RetrievalAuthorizationDecision(
                allowed=False,
                reason=
                    "principal_acl_denied",
            )

        effective_access = (
            retrieval_principal
            .retrieval_access
        )

    # -------------------------------------------------
    # LEGACY ACCESS-LEVEL AUTHORIZATION
    # -------------------------------------------------

    else:

        effective_access = (
            caller_access
            or "standard"
        )

    # -------------------------------------------------
    # RETRIEVAL AUTHORITY VALIDATION
    # -------------------------------------------------

    if effective_access not in (
        "standard",
        "restricted",
    ):

        return RetrievalAuthorizationDecision(
            allowed=False,
            reason=
                "invalid_retrieval_access",
        )

    # -------------------------------------------------
    # KNOWLEDGE CLASSIFICATION
    # -------------------------------------------------

    if chunk.access_level == "standard":

        return RetrievalAuthorizationDecision(
            allowed=True,
            reason="allowed",
        )

    if chunk.access_level == "restricted":

        if effective_access == "restricted":

            return RetrievalAuthorizationDecision(
                allowed=True,
                reason="allowed",
            )

        return RetrievalAuthorizationDecision(
            allowed=False,
            reason=
                "classification_denied",
        )

    # Unknown or malformed authorization metadata.
    return RetrievalAuthorizationDecision(
        allowed=False,
        reason=
            "invalid_authorization_metadata",
    )


def is_knowledge_chunk_authorized(
    *,
    chunk: KnowledgeChunk,
    caller_access: RetrievalAccess | None = None,
    retrieval_principal: RetrievalPrincipal | None = None,
) -> bool:
    """
    Backward-compatible boolean authorization helper.

    New authorization-aware code should prefer
    evaluate_knowledge_chunk_authorization() when the
    structured reason is required.
    """

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk,
            caller_access=caller_access,
            retrieval_principal=
                retrieval_principal,
        )
    )

    return decision.allowed


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
