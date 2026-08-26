import httpx
import pytest

from app.providers.tenable_client import (
    TenableApiClient,
    TenableApiError,
)


# -------------------------------------------------
# BLANK CREDENTIALS
# -------------------------------------------------


def test_blank_access_key_is_rejected():

    with pytest.raises(
        ValueError,
        match="access key",
    ):

        TenableApiClient(
            access_key="",
            secret_key="secret",
        )


def test_blank_secret_key_is_rejected():

    with pytest.raises(
        ValueError,
        match="secret key",
    ):

        TenableApiClient(
            access_key="access",
            secret_key="",
        )


# -------------------------------------------------
# HTTPS REQUIRED
# -------------------------------------------------


def test_insecure_base_url_is_rejected():

    with pytest.raises(
        ValueError,
        match="HTTPS",
    ):

        TenableApiClient(
            access_key="access",
            secret_key="secret",

            base_url=(
                "http://cloud.tenable.com"
            ),
        )


# -------------------------------------------------
# AUTHENTICATION HEADER
# -------------------------------------------------


def test_request_uses_tenable_api_keys():

    captured = {}

    def handler(
        request
    ):

        captured[
            "url"
        ] = str(
            request.url
        )

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

    transport = (
        httpx.MockTransport(
            handler
        )
    )

    client = TenableApiClient(
        access_key="test-access-key",

        secret_key="test-secret-key",

        transport=transport,
    )

    result = client.request_json(
        "GET",
        "/assets",
    )

    client.close()

    assert (
        captured["url"]
        == (
            "https://cloud.tenable.com"
            "/assets"
        )
    )

    assert (
        captured["api_keys"]
        == (
            "accessKey=test-access-key; "
            "secretKey=test-secret-key;"
        )
    )

    assert result == {
        "status": "ok"
    }


# -------------------------------------------------
# SANITIZED HTTP ERROR
# -------------------------------------------------


def test_http_error_does_not_expose_credentials():

    access_key = (
        "SUPER-SECRET-ACCESS"
    )

    secret_key = (
        "SUPER-SECRET-SECRET"
    )

    def handler(
        request
    ):

        return httpx.Response(
            status_code=401,

            json={
                "message":
                    "Authentication failed",

                "debug_secret":
                    "server-sensitive-data",
            },
        )

    transport = (
        httpx.MockTransport(
            handler
        )
    )

    client = TenableApiClient(
        access_key=access_key,
        secret_key=secret_key,
        transport=transport,
    )

    with pytest.raises(
        TenableApiError
    ) as error:

        client.request_json(
            "GET",
            "/assets",
        )

    client.close()

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
        "server-sensitive-data"
        not in message
    )


# -------------------------------------------------
# INVALID JSON
# -------------------------------------------------


def test_invalid_json_response_is_rejected():

    def handler(
        request
    ):

        return httpx.Response(
            status_code=200,

            text=(
                "not-json"
            ),
        )

    transport = (
        httpx.MockTransport(
            handler
        )
    )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",
        transport=transport,
    )

    with pytest.raises(
        TenableApiError,
        match="invalid JSON",
    ):

        client.request_json(
            "GET",
            "/assets",
        )

    client.close()


# -------------------------------------------------
# INVALID TIMEOUT
# -------------------------------------------------


def test_invalid_timeout_is_rejected():

    with pytest.raises(
        ValueError,
        match="timeout",
    ):

        TenableApiClient(
            access_key="access",
            secret_key="secret",
            timeout_seconds=0,
        )