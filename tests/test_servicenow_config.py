from __future__ import annotations

import pytest

from app.providers.servicenow_config import (
    ServiceNowConfigurationError,
    ServiceNowSettings,
)


VALID_ENV = {
    "SERVICENOW_INSTANCE_URL":
        "https://example.service-now.com",

    "SERVICENOW_USERNAME":
        "vm.integration",

    "SERVICENOW_PASSWORD":
        "test-secret",

    "SERVICENOW_TABLE":
        "incident",

    "SERVICENOW_TIMEOUT_SECONDS":
        "10",
}


def test_valid_settings_load_from_environment():

    settings = ServiceNowSettings.from_environment(
        VALID_ENV
    )

    assert (
        settings.instance_url
        == "https://example.service-now.com"
    )

    assert settings.table == "incident"

    assert (
        settings.table_endpoint
        == (
            "https://example.service-now.com"
            "/api/now/table/incident"
        )
    )


def test_http_instance_url_is_rejected():

    environ = dict(
        VALID_ENV
    )

    environ[
        "SERVICENOW_INSTANCE_URL"
    ] = "http://example.service-now.com"

    with pytest.raises(
        ServiceNowConfigurationError
    ):
        ServiceNowSettings.from_environment(
            environ
        )


@pytest.mark.parametrize(
    "instance_url",
    [
        "https://user:pass@example.service-now.com",
        (
            "https://example.service-now.com/"
            "api/now/table/problem"
        ),
        "https://example.service-now.com?table=problem",
        "https://example.service-now.com#problem",
    ],
)
def test_instance_url_injection_is_rejected(
    instance_url,
):

    environ = dict(
        VALID_ENV
    )

    environ[
        "SERVICENOW_INSTANCE_URL"
    ] = instance_url

    with pytest.raises(
        ServiceNowConfigurationError
    ):
        ServiceNowSettings.from_environment(
            environ
        )


@pytest.mark.parametrize(
    "table",
    [
        "problem",
        "change_request",
        "sys_user",
        "sys_user_group",
        "../incident",
        "incident?sysparm_query=active=true",
        "",
    ],
)
def test_non_allowlisted_table_is_rejected(
    table,
):

    environ = dict(
        VALID_ENV
    )

    environ[
        "SERVICENOW_TABLE"
    ] = table

    with pytest.raises(
        ServiceNowConfigurationError
    ):
        ServiceNowSettings.from_environment(
            environ
        )


@pytest.mark.parametrize(
    "timeout",
    [
        "0",
        "-1",
        "31",
        "not-a-number",
    ],
)
def test_invalid_timeout_is_rejected(
    timeout,
):

    environ = dict(
        VALID_ENV
    )

    environ[
        "SERVICENOW_TIMEOUT_SECONDS"
    ] = timeout

    with pytest.raises(
        ServiceNowConfigurationError
    ):
        ServiceNowSettings.from_environment(
            environ
        )


def test_password_is_redacted_from_repr():

    settings = ServiceNowSettings.from_environment(
        VALID_ENV
    )

    rendered = repr(
        settings
    )

    assert "test-secret" not in rendered
    assert "<redacted>" in rendered


def test_missing_credentials_fail_closed():

    environ = dict(
        VALID_ENV
    )

    environ[
        "SERVICENOW_PASSWORD"
    ] = ""

    with pytest.raises(
        ServiceNowConfigurationError
    ):
        ServiceNowSettings.from_environment(
            environ
        )
