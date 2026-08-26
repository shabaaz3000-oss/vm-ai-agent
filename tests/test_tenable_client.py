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

            text="not-json",
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


# -------------------------------------------------
# START VULNERABILITY EXPORT
# -------------------------------------------------


def test_start_vulnerability_export_posts_expected_request():

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

        captured[
            "body"
        ] = request.read()

        return httpx.Response(
            status_code=200,

            json={
                "export_uuid":
                    "EXPORT-12345"
            },
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    export_uuid = (
        client
        .start_vulnerability_export(
            filters={
                "severity": [
                    "HIGH",
                    "CRITICAL",
                ]
            },

            num_assets=500,

            include_unlicensed=True,

            include_plugin_output=False,
        )
    )

    client.close()

    assert (
        captured["method"]
        == "POST"
    )

    assert (
        captured["url"]
        == (
            "https://cloud.tenable.com"
            "/vulns/export"
        )
    )

    assert (
        export_uuid
        == "EXPORT-12345"
    )

    body = (
        captured["body"]
        .decode(
            "utf-8"
        )
    )

    assert (
        '"num_assets":500'
        in body
    )

    assert (
        '"include_unlicensed":true'
        in body
    )

    assert (
        '"include_plugin_output":false'
        in body
    )

    assert (
        '"CRITICAL"'
        in body
    )


def test_start_vulnerability_export_requires_export_uuid():

    def handler(
        request
    ):

        return httpx.Response(
            status_code=200,

            json={
                "status":
                    "queued"
            },
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    with pytest.raises(
        TenableApiError,
        match="export UUID",
    ):

        client.start_vulnerability_export()

    client.close()


# -------------------------------------------------
# NUM ASSETS VALIDATION
# -------------------------------------------------


def test_num_assets_below_minimum_is_rejected():

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",
    )

    with pytest.raises(
        ValueError,
        match="50 and 5000",
    ):

        client.start_vulnerability_export(
            num_assets=49
        )

    client.close()


def test_num_assets_above_maximum_is_rejected():

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",
    )

    with pytest.raises(
        ValueError,
        match="50 and 5000",
    ):

        client.start_vulnerability_export(
            num_assets=5001
        )

    client.close()


# -------------------------------------------------
# EXPORT STATUS
# -------------------------------------------------


def test_export_status_uses_expected_endpoint():

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

            json={
                "status":
                    "PROCESSING",

                "chunks_available": [
                    1,
                    3,
                ],
            },
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    result = (
        client
        .get_vulnerability_export_status(
            "EXPORT-12345"
        )
    )

    client.close()

    assert (
        captured["method"]
        == "GET"
    )

    assert (
        captured["url"]
        == (
            "https://cloud.tenable.com"
            "/vulns/export/"
            "EXPORT-12345/status"
        )
    )

    assert (
        result["status"]
        == "PROCESSING"
    )


def test_blank_export_uuid_is_rejected():

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",
    )

    with pytest.raises(
        ValueError,
        match="export UUID",
    ):

        client.get_vulnerability_export_status(
            "   "
        )

    client.close()


# -------------------------------------------------
# AVAILABLE CHUNKS
# -------------------------------------------------


def test_available_chunk_ids_are_returned():

    def handler(
        request
    ):

        return httpx.Response(
            status_code=200,

            json={
                "status":
                    "PROCESSING",

                "chunks_available": [
                    2,
                    7,
                    4,
                ],
            },
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    chunks = (
        client
        .get_available_vulnerability_chunks(
            "EXPORT-12345"
        )
    )

    client.close()

    assert chunks == [
        2,
        7,
        4,
    ]


# -------------------------------------------------
# DOWNLOAD CHUNK
# -------------------------------------------------


def test_download_vulnerability_chunk_uses_expected_endpoint():

    captured = {}

    records = [
        {
            "asset": {
                "uuid":
                    "ASSET-123"
            },

            "plugin": {
                "id":
                    12345
            },
        }
    ]

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
            json=records,
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    result = (
        client
        .download_vulnerability_chunk(
            export_uuid=
                "EXPORT-12345",

            chunk_id=
                7,
        )
    )

    client.close()

    assert (
        captured["method"]
        == "GET"
    )

    assert (
        captured["url"]
        == (
            "https://cloud.tenable.com"
            "/vulns/export/"
            "EXPORT-12345/chunks/7"
        )
    )

    assert result == records


def test_download_chunk_rejects_invalid_payload():

    def handler(
        request
    ):

        return httpx.Response(
            status_code=200,

            json={
                "unexpected":
                    "object"
            },
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    with pytest.raises(
        TenableApiError,
        match="unexpected response",
    ):

        client.download_vulnerability_chunk(
            export_uuid=
                "EXPORT-12345",

            chunk_id=
                1,
        )

    client.close()

# -------------------------------------------------
# START ASSET EXPORT
# -------------------------------------------------


def test_start_asset_export_posts_expected_request():

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

        captured[
            "body"
        ] = request.read()

        return httpx.Response(
            status_code=200,

            json={
                "export_uuid":
                    "ASSET-EXPORT-123"
            },
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    export_uuid = (
        client.start_asset_export(
            chunk_size=5000,

            include_open_ports=False,

            filters={
                "types": [
                    "host"
                ]
            },
        )
    )

    client.close()

    assert (
        captured["method"]
        == "POST"
    )

    assert (
        captured["url"]
        == (
            "https://cloud.tenable.com"
            "/assets/v2/export"
        )
    )

    assert (
        export_uuid
        == "ASSET-EXPORT-123"
    )

    body = (
        captured["body"]
        .decode(
            "utf-8"
        )
    )

    assert (
        '"chunk_size":5000'
        in body
    )

    assert (
        '"include_open_ports":false'
        in body
    )


# -------------------------------------------------
# ASSET CHUNK SIZE VALIDATION
# -------------------------------------------------


def test_asset_chunk_size_below_minimum_is_rejected():

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",
    )

    with pytest.raises(
        ValueError,
        match="100 and 10000",
    ):

        client.start_asset_export(
            chunk_size=99
        )

    client.close()


def test_asset_chunk_size_above_maximum_is_rejected():

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",
    )

    with pytest.raises(
        ValueError,
        match="100 and 10000",
    ):

        client.start_asset_export(
            chunk_size=10001
        )

    client.close()


# -------------------------------------------------
# ASSET EXPORT STATUS
# -------------------------------------------------


def test_asset_export_status_uses_expected_endpoint():

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

            json={
                "status":
                    "PROCESSING",

                "chunks_available": [
                    0,
                    2,
                ],
            },
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    result = (
        client.get_asset_export_status(
            "ASSET-EXPORT-123"
        )
    )

    client.close()

    assert (
        captured["method"]
        == "GET"
    )

    assert (
        captured["url"]
        == (
            "https://cloud.tenable.com"
            "/assets/export/"
            "ASSET-EXPORT-123/status"
        )
    )

    assert (
        result["status"]
        == "PROCESSING"
    )


def test_blank_asset_export_uuid_is_rejected():

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",
    )

    with pytest.raises(
        ValueError,
        match="export UUID",
    ):

        client.get_asset_export_status(
            "   "
        )

    client.close()


# -------------------------------------------------
# AVAILABLE ASSET CHUNKS
# -------------------------------------------------


def test_available_asset_chunks_are_returned():

    def handler(
        request
    ):

        return httpx.Response(
            status_code=200,

            json={
                "status":
                    "PROCESSING",

                "chunks_available": [
                    4,
                    1,
                    7,
                ],
            },
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    chunks = (
        client.get_available_asset_chunks(
            "ASSET-EXPORT-123"
        )
    )

    client.close()

    assert chunks == [
        4,
        1,
        7,
    ]


# -------------------------------------------------
# DOWNLOAD ASSET CHUNK
# -------------------------------------------------


def test_download_asset_chunk_uses_expected_endpoint():

    captured = {}

    assets = [
        {
            "id":
                "ASSET-UUID-123",

            "name":
                "internet-web-01",
        }
    ]

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
            json=assets,
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    result = (
        client.download_asset_chunk(
            export_uuid=
                "ASSET-EXPORT-123",

            chunk_id=
                4,
        )
    )

    client.close()

    assert (
        captured["method"]
        == "GET"
    )

    assert (
        captured["url"]
        == (
            "https://cloud.tenable.com"
            "/assets/export/"
            "ASSET-EXPORT-123/chunks/4"
        )
    )

    assert result == assets


def test_download_asset_chunk_rejects_invalid_payload():

    def handler(
        request
    ):

        return httpx.Response(
            status_code=200,

            json={
                "unexpected":
                    "object"
            },
        )

    client = TenableApiClient(
        access_key="access",
        secret_key="secret",

        transport=httpx.MockTransport(
            handler
        ),
    )

    with pytest.raises(
        TenableApiError,
        match="unexpected response",
    ):

        client.download_asset_chunk(
            export_uuid=
                "ASSET-EXPORT-123",

            chunk_id=
                1,
        )

    client.close()