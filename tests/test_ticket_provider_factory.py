from __future__ import annotations

import pytest

from app.providers.mock_ticket_provider import (
    MockTicketProvider,
)
from app.providers.servicenow_ticket_provider import (
    ServiceNowTicketProvider,
)
from app.providers.ticket_provider import (
    TicketProvider,
)
from app.providers.ticket_provider_factory import (
    TicketProviderConfigurationError,
    build_ticket_provider,
)


def servicenow_environment():
    return {
        "TICKET_PROVIDER":
            "servicenow",

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


def test_default_provider_is_mock():

    provider = build_ticket_provider(
        {}
    )

    assert isinstance(
        provider,
        MockTicketProvider,
    )

    assert isinstance(
        provider,
        TicketProvider,
    )


@pytest.mark.parametrize(
    "configured_value",
    [
        "mock",
        "MOCK",
        " mock ",
    ],
)
def test_mock_provider_selection_is_normalized(
    configured_value,
):

    provider = build_ticket_provider(
        {
            "TICKET_PROVIDER":
                configured_value,
        }
    )

    assert isinstance(
        provider,
        MockTicketProvider,
    )


def test_servicenow_provider_can_be_selected():

    provider = build_ticket_provider(
        servicenow_environment()
    )

    try:

        assert isinstance(
            provider,
            ServiceNowTicketProvider,
        )

        assert isinstance(
            provider,
            TicketProvider,
        )

        assert (
            provider.provider_name
            == "servicenow"
        )

    finally:

        provider._client.close()


@pytest.mark.parametrize(
    "provider_name",
    [
        "",
        "jira",
        "zendesk",
        "http",
        "https://attacker.example",
        "../servicenow",
        "servicenow?table=sys_user",
        "mock;servicenow",
    ],
)
def test_unknown_provider_fails_closed(
    provider_name,
):

    with pytest.raises(
        TicketProviderConfigurationError,
        match="Unsupported ticket provider",
    ):

        build_ticket_provider(
            {
                "TICKET_PROVIDER":
                    provider_name,
            }
        )


def test_servicenow_requires_complete_server_configuration():

    with pytest.raises(
        ValueError
    ):

        build_ticket_provider(
            {
                "TICKET_PROVIDER":
                    "servicenow",
            }
        )


def test_mock_does_not_require_servicenow_credentials():

    provider = build_ticket_provider(
        {
            "TICKET_PROVIDER":
                "mock",

            "SERVICENOW_INSTANCE_URL":
                "https://attacker.example",

            "SERVICENOW_USERNAME":
                "attacker",

            "SERVICENOW_PASSWORD":
                "attacker-secret",

            "SERVICENOW_TABLE":
                "sys_user",
        }
    )

    assert isinstance(
        provider,
        MockTicketProvider,
    )


@pytest.mark.parametrize(
    "untrusted_field",
    [
        {
            "provider":
                "servicenow",
        },
        {
            "ticket_provider":
                "servicenow",
        },
        {
            "provider_name":
                "servicenow",
        },
        {
            "table":
                "sys_user",
        },
        {
            "instance_url":
                "https://attacker.example",
        },
    ],
)
def test_non_configuration_keys_cannot_select_provider(
    untrusted_field,
):

    provider = build_ticket_provider(
        untrusted_field
    )

    assert isinstance(
        provider,
        MockTicketProvider,
    )


def test_servicenow_provider_uses_hardened_settings():

    environ = servicenow_environment()

    environ[
        "SERVICENOW_TABLE"
    ] = "sys_user"

    with pytest.raises(
        ValueError
    ):

        build_ticket_provider(
            environ
        )


def test_servicenow_http_destination_cannot_be_smuggled_in_provider_name():

    environ = servicenow_environment()

    environ[
        "TICKET_PROVIDER"
    ] = (
        "servicenow:"
        "https://attacker.example"
    )

    with pytest.raises(
        TicketProviderConfigurationError
    ):

        build_ticket_provider(
            environ
        )


def test_provider_selection_does_not_accept_runtime_ticket_arguments():

    import inspect

    signature = inspect.signature(
        build_ticket_provider
    )

    assert set(
        signature.parameters
    ) == {
        "environ",
    }

    for forbidden_name in (
        "ticket",
        "approval",
        "workflow_id",
        "principal",
        "tenant_id",
        "provider_name",
        "url",
        "table",
    ):

        assert (
            forbidden_name
            not in signature.parameters
        )
