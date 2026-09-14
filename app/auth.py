import os
import secrets

from typing import Literal

from dotenv import load_dotenv

from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from pydantic import BaseModel


# -------------------------------------------------
# ENVIRONMENT
# -------------------------------------------------


load_dotenv()


# -------------------------------------------------
# AUTHENTICATED PRINCIPAL
# -------------------------------------------------


class Principal(BaseModel):
    username: str

    role: Literal[
        "ANALYST",
        "APPROVER",
    ]

    # -------------------------------------------------
    # RETRIEVAL AUTHORIZATION CLAIM
    # -------------------------------------------------
    #
    # This value is established by trusted application
    # authentication logic.
    #
    # It is not supplied by the LLM and is deliberately
    # independent from workflow approval authority.
    #
    # Existing principals default to the least-privileged
    # standard knowledge-access level.
    # -------------------------------------------------

    retrieval_access: Literal[
        "standard",
        "restricted",
    ] = "standard"


# -------------------------------------------------
# BEARER TOKEN SCHEME
# -------------------------------------------------


bearer_scheme = HTTPBearer(
    auto_error=False
)


# -------------------------------------------------
# AUTHENTICATION FAILURE
# -------------------------------------------------


def authentication_error():

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,

        detail=(
            "Valid API authentication "
            "is required."
        ),

        headers={
            "WWW-Authenticate": "Bearer"
        },
    )


# -------------------------------------------------
# READ CONFIGURED TOKENS
# -------------------------------------------------


def get_configured_tokens():

    return {
        "ANALYST":
            os.getenv(
                "VM_AI_ANALYST_TOKEN"
            ),

        "APPROVER":
            os.getenv(
                "VM_AI_APPROVER_TOKEN"
            ),

        "RESTRICTED_ANALYST":
            os.getenv(
                "VM_AI_RESTRICTED_ANALYST_TOKEN"
            ),
    }


# -------------------------------------------------
# AUTHENTICATE TOKEN
# -------------------------------------------------


def authenticate_token(
    token: str
) -> Principal:

    configured = (
        get_configured_tokens()
    )

    analyst_token = configured[
        "ANALYST"
    ]

    approver_token = configured[
        "APPROVER"
    ]

    restricted_analyst_token = configured[
        "RESTRICTED_ANALYST"
    ]

    # -------------------------------------------------
    # STANDARD ANALYST
    # -------------------------------------------------

    if (
        analyst_token
        and secrets.compare_digest(
            token,
            analyst_token
        )
    ):

        return Principal(
            username="api-analyst",
            role="ANALYST",
            retrieval_access="standard",
        )

    # -------------------------------------------------
    # APPROVER
    # -------------------------------------------------
    #
    # Approval authority does not automatically grant
    # access to restricted RAG evidence.
    # -------------------------------------------------

    if (
        approver_token
        and secrets.compare_digest(
            token,
            approver_token
        )
    ):

        return Principal(
            username="api-approver",
            role="APPROVER",
            retrieval_access="standard",
        )

    # -------------------------------------------------
    # RESTRICTED-KNOWLEDGE ANALYST
    # -------------------------------------------------
    #
    # This demo identity has ordinary ANALYST workflow
    # authority but an explicitly separate restricted
    # knowledge-access capability.
    # -------------------------------------------------

    if (
        restricted_analyst_token
        and secrets.compare_digest(
            token,
            restricted_analyst_token
        )
    ):

        return Principal(
            username="api-restricted-analyst",
            role="ANALYST",
            retrieval_access="restricted",
        )

    raise authentication_error()


# -------------------------------------------------
# REQUIRE AUTHENTICATED USER
# -------------------------------------------------


def require_authenticated_user(
    credentials:
        HTTPAuthorizationCredentials
        | None = Depends(
            bearer_scheme
        )
) -> Principal:

    if credentials is None:

        raise authentication_error()

    if (
        credentials.scheme.lower()
        != "bearer"
    ):

        raise authentication_error()

    return authenticate_token(
        credentials.credentials
    )


# -------------------------------------------------
# REQUIRE APPROVER ROLE
# -------------------------------------------------


def require_approver(
    principal: Principal = Depends(
        require_authenticated_user
    )
) -> Principal:

    if principal.role != "APPROVER":

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,

            detail=(
                "Approver role is required "
                "for this operation."
            ),
        )

    return principal