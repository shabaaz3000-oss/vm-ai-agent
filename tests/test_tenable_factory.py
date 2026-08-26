import httpx
import pytest

from app.providers.tenable_client import (
    TenableApiClient,
)

from app.providers.tenable_config import (
    TenableSettings,
)

from app.providers.tenable_factory import (
    create_tenable_client,
    create_tenable_components,
    create_tenable_sync,
)

from app.providers.tenable_sync import (
    TenableExportSync,
)


# -------------------------------------------------
# TEST SETTINGS
# -------------------------------------------------


def make_settings():

    return TenableSettings(
        access_key=(
            "factory-test-access"
        ),

        secret_key=(
            "factory-test-secret"
        ),

        base_url=(
            "https://cloud.tenable.com"
        ),

        timeout_seconds=42,

        poll_interval_seconds=3,

        max_poll_attempts=77,

        vulnerability_num_assets=600,

        asset_chunk_size=7000,
    )


# -------------------------------------------------
# CLIENT CREATION
# -------------------------------------------------


def test_factory_creates_tenable_client():

    settings = make_settings()

    client = create_tenable_client(
        settings
    )

    assert isinstance(
        client,
        TenableApiClient
    )

    assert (
        client.base_url
        == "https://cloud.tenable.com"
    )

    assert (
        client.timeout_seconds
        == 42
    )

    client.close()


# -------------------------------------------------
# SECRET VALUES REACH ONLY HTTP AUTH BOUNDARY
# -------------------------------------------------


def test_factory_passes_credentials_to_http_client():

    captured = {}

    def handler(
        request
    ):

        captured[
            "api_keys"
        ] = request.headers.get(
            "X-ApiKeys"
        )

        return httpx.Response(
            status_code=200,

            json={
                "status":
                    "ok"
            },
        )

    settings = make_settings()

    client = create_tenable_client(
        settings,

        transport=httpx.MockTransport(
            handler
        ),
    )

    client.request_json(
        "GET",
        "/assets",
    )

    client.close()

    assert (
        captured["api_keys"]
        == (
            "accessKey=factory-test-access; "
            "secretKey=factory-test-secret;"
        )
    )


# -------------------------------------------------
# SYNC CREATION
# -------------------------------------------------


def test_factory_creates_configured_sync():

    settings = make_settings()

    client = create_tenable_client(
        settings
    )

    sync = create_tenable_sync(
        settings,
        client
    )

    assert isinstance(
        sync,
        TenableExportSync
    )

    assert (
        sync.client
        is client
    )

    assert (
        sync.poll_interval_seconds
        == 3
    )

    assert (
        sync.max_poll_attempts
        == 77
    )

    client.close()


# -------------------------------------------------
# COMPLETE COMPONENT CREATION
# -------------------------------------------------


def test_factory_creates_connected_components():

    settings = make_settings()

    client, sync = (
        create_tenable_components(
            settings
        )
    )

    assert isinstance(
        client,
        TenableApiClient
    )

    assert isinstance(
        sync,
        TenableExportSync
    )

    assert (
        sync.client
        is client
    )

    client.close()


# -------------------------------------------------
# INVALID SETTINGS FAIL CLOSED
# -------------------------------------------------


def test_client_factory_rejects_invalid_settings():

    with pytest.raises(
        TypeError,
        match="TenableSettings",
    ):

        create_tenable_client(
            {
                "access_key":
                    "fake"
            }
        )


# -------------------------------------------------
# INVALID CLIENT FAIL CLOSED
# -------------------------------------------------


def test_sync_factory_rejects_invalid_client():

    settings = make_settings()

    with pytest.raises(
        TypeError,
        match="TenableApiClient",
    ):

        create_tenable_sync(
            settings,
            object(),
        )