from __future__ import annotations

import httpx
import pytest

from app.providers.servicenow_client import (
    ServiceNowClient,
    ServiceNowResponseError,
    ServiceNowTransportError,
)
from app.providers.servicenow_config import (
    ServiceNowSettings,
)


def settings() -> ServiceNowSettings:

    return ServiceNowSettings(
        instance_url=
            "https://example.service-now.com",

        username=
            "vm.integration",

        password=
            "test-secret",

        table=
            "incident",

        timeout_seconds=
            5,
    )


def test_create_record_uses_fixed_trusted_endpoint():

    observed = {}

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        observed["method"] = request.method
        observed["url"] = str(
            request.url
        )

        return httpx.Response(
            201,
            json={
                "result": {
                    "sys_id":
                        "abc123",

                    "number":
                        "INC0012345",
                }
            },
        )

    transport = httpx.MockTransport(
        handler
    )

    with ServiceNowClient(
        settings(),
        transport=transport,
    ) as client:

        result = client.create_record(
            {
                "short_description":
                    "Security remediation",
            }
        )

    assert observed["method"] == "POST"

    assert (
        observed["url"]
        == (
            "https://example.service-now.com"
            "/api/now/table/incident"
        )
    )

    assert result["sys_id"] == "abc123"
    assert result["number"] == "INC0012345"


def test_client_does_not_follow_redirects():

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        return httpx.Response(
            302,
            headers={
                "Location":
                    "https://attacker.example/ticket"
            },
        )

    with ServiceNowClient(
        settings(),
        transport=httpx.MockTransport(
            handler
        ),
    ) as client:

        with pytest.raises(
            ServiceNowResponseError
        ):
            client.create_record(
                {
                    "short_description":
                        "Security remediation",
                }
            )


@pytest.mark.parametrize(
    "status_code",
    [
        400,
        401,
        403,
        404,
        409,
        429,
        500,
        503,
    ],
)
def test_unsuccessful_response_fails_closed(
    status_code,
):

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        return httpx.Response(
            status_code,
            json={
                "error": {
                    "message":
                        "request rejected",
                }
            },
        )

    with ServiceNowClient(
        settings(),
        transport=httpx.MockTransport(
            handler
        ),
    ) as client:

        with pytest.raises(
            ServiceNowResponseError
        ):
            client.create_record(
                {
                    "short_description":
                        "Security remediation",
                }
            )


def test_transport_failure_has_uncertain_outcome():

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        raise httpx.ReadTimeout(
            "timeout",
            request=request,
        )

    with ServiceNowClient(
        settings(),
        transport=httpx.MockTransport(
            handler
        ),
    ) as client:

        with pytest.raises(
            ServiceNowTransportError,
            match="reconciled before retry",
        ):
            client.create_record(
                {
                    "short_description":
                        "Security remediation",
                }
            )


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"result": None},
        {"result": {}},
        {
            "result": {
                "sys_id": "",
                "number": "INC1",
            }
        },
        {
            "result": {
                "sys_id": "abc",
                "number": "",
            }
        },
    ],
)
def test_invalid_response_schema_is_rejected(
    body,
):

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        return httpx.Response(
            201,
            json=body,
        )

    with ServiceNowClient(
        settings(),
        transport=httpx.MockTransport(
            handler
        ),
    ) as client:

        with pytest.raises(
            ServiceNowResponseError
        ):
            client.create_record(
                {
                    "short_description":
                        "Security remediation",
                }
            )


def test_empty_payload_is_rejected_before_http():

    called = False

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        nonlocal called
        called = True

        return httpx.Response(
            500
        )

    with ServiceNowClient(
        settings(),
        transport=httpx.MockTransport(
            handler
        ),
    ) as client:

        with pytest.raises(
            ValueError
        ):
            client.create_record(
                {}
            )

    assert called is False
