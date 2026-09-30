from __future__ import annotations

import os
from typing import Mapping

from app.providers.mock_ticket_provider import (
    MockTicketProvider,
)
from app.providers.servicenow_client import (
    ServiceNowClient,
)
from app.providers.servicenow_config import (
    ServiceNowSettings,
)
from app.providers.servicenow_ticket_provider import (
    ServiceNowTicketProvider,
)
from app.providers.ticket_provider import (
    TicketProvider,
)


class TicketProviderConfigurationError(
    ValueError
):
    """
    Raised when server-side ticket-provider configuration
    is missing, unsupported, or unsafe.
    """


_ALLOWED_PROVIDERS = frozenset(
    {
        "mock",
        "servicenow",
    }
)


def _provider_name_from_environment(
    environ: Mapping[str, str],
) -> str:
    """
    Read provider selection from server-owned configuration.

    No ticket field, workflow input, MCP argument, model output,
    approval payload, or caller parameter is accepted here.
    """

    provider_name = (
        environ.get(
            "TICKET_PROVIDER",
            "mock",
        )
        .strip()
        .lower()
    )

    if provider_name not in _ALLOWED_PROVIDERS:

        raise TicketProviderConfigurationError(
            "Unsupported ticket provider."
        )

    return provider_name


def build_ticket_provider(
    environ: Mapping[str, str] | None = None,
) -> TicketProvider:
    """
    Construct the server-selected ticket provider.

    Runtime callers should omit `environ`, causing the process
    environment to be used.

    The optional mapping exists only to make configuration
    behavior deterministic and testable without mutating the
    process environment.

    Provider selection remains allowlisted and never derives
    from workflow, ticket, principal, approval, model, or MCP
    data.
    """

    source = (
        os.environ
        if environ is None
        else environ
    )

    provider_name = (
        _provider_name_from_environment(
            source
        )
    )

    if provider_name == "mock":

        return MockTicketProvider()

    if provider_name == "servicenow":

        settings = (
            ServiceNowSettings
            .from_environment(
                source
            )
        )

        client = ServiceNowClient(
            settings
        )

        return ServiceNowTicketProvider(
            client
        )

    # Defense in depth. The allowlist above should make this
    # branch unreachable.
    raise TicketProviderConfigurationError(
        "Ticket provider selection failed closed."
    )
