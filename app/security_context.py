from hashlib import sha256

from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from app.auth import Principal


# -------------------------------------------------
# TRUSTED SECURITY CONTEXT
# -------------------------------------------------


class SecurityContext(BaseModel):
    """
    Immutable server-side execution context.

    SecurityContext binds authenticated identity claims
    to a specific enterprise tenant and application
    session.

    The context must be created by trusted application
    code. It must never be populated from LLM-generated
    arguments or caller-controlled tool parameters.
    """

    model_config = ConfigDict(
        frozen=True
    )

    principal_id: str = Field(
        min_length=1
    )

    role: Literal[
        "ANALYST",
        "APPROVER",
    ]

    retrieval_access: Literal[
        "standard",
        "restricted",
    ]

    session_revocation_access: Literal[
        "self",
        "tenant_admin",
    ] = "self"

    tenant_id: str = Field(
        min_length=1
    )

    session_id: str = Field(
        min_length=1
    )



    @property
    def session_correlation_id(
        self,
    ) -> str:
        """
        Return a stable non-secret identifier suitable
        for audit correlation.

        Raw session identifiers must not be written to
        audit logs.
        """

        return sha256(
            self.session_id.encode(
                "utf-8"
            )
        ).hexdigest()[:16]

    @classmethod
    def from_principal(
        cls,
        principal: Principal,
        *,
        tenant_id: str,
        session_id: str,
    ) -> "SecurityContext":

        return cls(
            principal_id=principal.username,
            role=principal.role,
            retrieval_access=(
                principal.retrieval_access
            ),
            session_revocation_access=(
                principal.session_revocation_access
            ),
            tenant_id=tenant_id,
            session_id=session_id,
        )