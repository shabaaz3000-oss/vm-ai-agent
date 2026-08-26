from pydantic import (
    BaseModel,
    ConfigDict,
)

from app.providers.tenable_client import (
    TenableApiClient,
    TenableApiError,
)

from app.providers.tenable_config import (
    TenableSettings,
)

from app.providers.tenable_factory import (
    create_tenable_client,
)


# -------------------------------------------------
# CONNECTIVITY RESULT
# -------------------------------------------------


class TenableConnectivityResult(
    BaseModel
):

    """
    Sanitized result of a Tenable connectivity test.

    This model deliberately contains no credentials
    and no raw Tenable response data.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    connected: bool

    endpoint: str

    message: str


# -------------------------------------------------
# CONNECTIVITY ENDPOINT
# -------------------------------------------------


CONNECTIVITY_ENDPOINT = (
    "/api/v3/access-control/"
    "permissions/users/me"
)


# -------------------------------------------------
# CHECK EXISTING CLIENT
# -------------------------------------------------


def check_tenable_connectivity(
    client: TenableApiClient,
) -> TenableConnectivityResult:

    """
    Perform one read-only authenticated request.

    The raw permissions response is used only to
    confirm authenticated Tenable connectivity.

    Raw response content is not returned to the
    caller.
    """

    if not isinstance(
        client,
        TenableApiClient
    ):

        raise TypeError(
            "client must be "
            "TenableApiClient."
        )

    response = client.request_json(
        "GET",
        CONNECTIVITY_ENDPOINT,
    )

    if not isinstance(
        response,
        dict
    ):

        raise TenableApiError(
            "Tenable connectivity check "
            "returned an unexpected response."
        )

    return TenableConnectivityResult(
        connected=True,

        endpoint=(
            CONNECTIVITY_ENDPOINT
        ),

        message=(
            "Authenticated Tenable "
            "connectivity confirmed."
        ),
    )


# -------------------------------------------------
# CHECK FROM SETTINGS
# -------------------------------------------------


def check_tenable_connectivity_from_settings(
    settings: TenableSettings,
    *,
    transport=None,
) -> TenableConnectivityResult:

    """
    Create a temporary authenticated client,
    perform the read-only connectivity check,
    and always close the HTTP client afterward.
    """

    if not isinstance(
        settings,
        TenableSettings
    ):

        raise TypeError(
            "settings must be "
            "TenableSettings."
        )

    client = create_tenable_client(
        settings,
        transport=transport,
    )

    try:

        return check_tenable_connectivity(
            client
        )

    finally:

        client.close()