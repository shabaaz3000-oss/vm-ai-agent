import httpx
import pytest

from app.providers.tenable_client import (
    TenableApiClient,
    TenableApiError,
)

from app.providers.tenable_config import (
    TenableSettings,
)

from app.providers.tenable_connectivity import (
    CONNECTIVITY_ENDPOINT,
    TenableConnectivityResult,
    check_tenable_connectivity,
    check_tenable_connectivity_from_settings,
)


# -------------------------------------------------
# TEST SETTINGS
# -------------------------------------------------


def make_settings():

    return TenableSettings(
        access_key=(
            "connectivity-test-access"
        ),

        secret_key=(
            "connectivity-test-secret"
        ),
    )


# -------------------------------------------------
# SUCCESSFUL CONNECTIVITY
# -------------------------------------------------


def test_connectivity_check_returns_sanitized_success():

    def handler(
        request
    ):

        return httpx.Response(
            status_code=200,

            json={
                "permissions": [
                    {
                        "name":
                            "example"
                    }
                ]
            },
        )

    result = (
        check_tenable_connectivity_from_settings(
            make_settings(),

            transport=httpx.MockTransport(
                handler
            ),
        )
    )

    assert isinstance(
        result,
        TenableConnectivityResult
    )

    assert (
        result.connected
        is True
    )

    assert (
        result.endpoint
        == CONNECTIVITY_ENDPOINT
    )

    assert (
        result.message
        == (
            "Authenticated Tenable "
            "connectivity confirmed."
        )
    )


# -------------------------------------------------
# EXPECTED READ-ONLY ENDPOINT
# -------------------------------------------------


def test_connectivity_check_uses_expected_endpoint():

    captured = {}

    def handler(
        request
    ):

        captured[
            "method"
        ] = request.method

        captured[
            "url"
        ] = str(
            request.url
        )

        return httpx.Response(
            status_code=200,
            json={},
        )

    check_tenable_connectivity_from_settings(
        make_settings(),

        transport=httpx.MockTransport(
            handler
        ),
    )

    assert (
        captured["method"]
        == "GET"
    )

    assert (
        captured["url"]
        == (
            "https://cloud.tenable.com"
            "/api/v3/access-control/"
            "permissions/users/me"
        )
    )


# -------------------------------------------------
# RAW RESPONSE IS NOT RETURNED
# -------------------------------------------------


def test_connectivity_result_does_not_expose_raw_response():

    sensitive_remote_value = (
        "REMOTE-INTERNAL-VALUE"
    )

    def handler(
        request
    ):

        return httpx.Response(
            status_code=200,

            json={
                "internal_value":
                    sensitive_remote_value
            },
        )

    result = (
        check_tenable_connectivity_from_settings(
            make_settings(),

            transport=httpx.MockTransport(
                handler
            ),
        )
    )

    serialized = (
        result.model_dump_json()
    )

    assert (
        sensitive_remote_value
        not in serialized
    )


# -------------------------------------------------
# INVALID RESPONSE FAILS CLOSED
# -------------------------------------------------


def test_invalid_connectivity_response_fails_closed():

    def handler(
        request
    ):

        return httpx.Response(
            status_code=200,

            json=[
                "unexpected",
                "response",
            ],
        )

    with pytest.raises(
        TenableApiError,
        match="unexpected response",
    ):

        check_tenable_connectivity_from_settings(
            make_settings(),

            transport=httpx.MockTransport(
                handler
            ),
        )


# -------------------------------------------------
# AUTHENTICATION ERROR IS SANITIZED
# -------------------------------------------------


def test_authentication_failure_does_not_expose_secrets():

    access_key = (
        "VERY-SECRET-ACCESS"
    )

    secret_key = (
        "VERY-SECRET-SECRET"
    )

    settings = TenableSettings(
        access_key=
            access_key,

        secret_key=
            secret_key,
    )

    def handler(
        request
    ):

        return httpx.Response(
            status_code=401,

            json={
                "message":
                    "Remote authentication failure",

                "sensitive":
                    "REMOTE-SENSITIVE-VALUE",
            },
        )

    with pytest.raises(
        TenableApiError
    ) as error:

        check_tenable_connectivity_from_settings(
            settings,

            transport=httpx.MockTransport(
                handler
            ),
        )

    message = str(
        error.value
    )

    assert (
        "401"
        in message
    )

    assert (
        access_key
        not in message
    )

    assert (
        secret_key
        not in message
    )

    assert (
        "REMOTE-SENSITIVE-VALUE"
        not in message
    )


# -------------------------------------------------
# WRONG CLIENT TYPE FAILS CLOSED
# -------------------------------------------------


def test_connectivity_check_rejects_invalid_client():

    with pytest.raises(
        TypeError,
        match="TenableApiClient",
    ):

        check_tenable_connectivity(
            object()
        )