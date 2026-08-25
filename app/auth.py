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
        )

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