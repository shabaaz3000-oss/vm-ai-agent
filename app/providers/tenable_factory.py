from time import sleep

from app.providers.tenable_client import (
    TenableApiClient,
)

from app.providers.tenable_config import (
    TenableSettings,
)

from app.providers.tenable_sync import (
    TenableExportSync,
)


# -------------------------------------------------
# CREATE TENABLE API CLIENT
# -------------------------------------------------


def create_tenable_client(
    settings: TenableSettings,
    *,
    transport=None,
) -> TenableApiClient:

    """
    Create a configured Tenable API client.

    Secret values are extracted from SecretStr only
    at this boundary because the HTTP client requires
    the real credential values for authentication.

    Credentials are not returned, logged, or exposed
    to the workflow or AI layers.
    """

    if not isinstance(
        settings,
        TenableSettings
    ):

        raise TypeError(
            "settings must be "
            "TenableSettings."
        )

    return TenableApiClient(
        access_key=(
            settings
            .access_key
            .get_secret_value()
        ),

        secret_key=(
            settings
            .secret_key
            .get_secret_value()
        ),

        base_url=(
            settings.base_url
        ),

        timeout_seconds=(
            settings.timeout_seconds
        ),

        transport=transport,
    )


# -------------------------------------------------
# CREATE TENABLE EXPORT SYNC
# -------------------------------------------------


def create_tenable_sync(
    settings: TenableSettings,
    client: TenableApiClient,
    *,
    sleep_function=sleep,
) -> TenableExportSync:

    """
    Create the asynchronous Tenable export
    synchronization service.

    Polling configuration comes from validated
    TenableSettings.
    """

    if not isinstance(
        settings,
        TenableSettings
    ):

        raise TypeError(
            "settings must be "
            "TenableSettings."
        )

    if not isinstance(
        client,
        TenableApiClient
    ):

        raise TypeError(
            "client must be "
            "TenableApiClient."
        )

    return TenableExportSync(
        client=client,

        poll_interval_seconds=(
            settings.poll_interval_seconds
        ),

        max_poll_attempts=(
            settings.max_poll_attempts
        ),

        sleep_function=(
            sleep_function
        ),
    )


# -------------------------------------------------
# CREATE BOTH COMPONENTS
# -------------------------------------------------


def create_tenable_components(
    settings: TenableSettings,
    *,
    transport=None,
    sleep_function=sleep,
) -> tuple[
    TenableApiClient,
    TenableExportSync,
]:

    """
    Create the Tenable HTTP and synchronization
    components from one validated settings object.

    This provides the application's controlled
    composition boundary for Tenable connectivity.
    """

    client = create_tenable_client(
        settings,
        transport=transport,
    )

    sync = create_tenable_sync(
        settings,
        client,
        sleep_function=sleep_function,
    )

    return (
        client,
        sync,
    )