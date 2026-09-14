from fastapi import HTTPException
from fastapi import status

from app.auth import Principal

from app.retriever import (
    RetrievalAccess,
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