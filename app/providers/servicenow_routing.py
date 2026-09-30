from __future__ import annotations

import json
import re

from collections.abc import Mapping
from types import MappingProxyType


ROUTING_ENVIRONMENT_VARIABLE = (
    "SERVICENOW_TENANT_ASSIGNMENT_GROUPS"
)


_SYS_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{32}$"
)


class ServiceNowRoutingConfigurationError(
    ValueError
):
    """
    Raised when server-owned tenant routing configuration is
    malformed or unsafe.
    """


class ServiceNowRoutingError(
    PermissionError
):
    """
    Raised when a trusted tenant has no authorized ServiceNow
    assignment-group route.
    """


def normalize_assignment_group_sys_id(
    value: str,
) -> str:
    """
    Validate the narrow sys_id representation accepted by this
    integration.

    ServiceNow identifies records with 32-character sys_id
    values. This integration intentionally uses a stricter
    application profile of exactly 32 hexadecimal characters.
    """

    if not isinstance(
        value,
        str,
    ):

        raise ServiceNowRoutingConfigurationError(
            "ServiceNow assignment-group sys_id "
            "must be a string."
        )

    if (
        not value
        or value != value.strip()
        or _SYS_ID_PATTERN.fullmatch(
            value
        )
        is None
    ):

        raise ServiceNowRoutingConfigurationError(
            "ServiceNow assignment-group sys_id "
            "must contain exactly 32 hexadecimal "
            "characters."
        )

    return value.lower()


def _unique_object_pairs(
    pairs,
):
    """
    Reject duplicate JSON object keys instead of silently using
    the final value.
    """

    result = {}

    for key, value in pairs:

        if key in result:

            raise (
                ServiceNowRoutingConfigurationError(
                    "Duplicate tenant routing key "
                    "is not allowed."
                )
            )

        result[
            key
        ] = value

    return result


class ServiceNowRoutingPolicy:
    """
    Immutable mapping from internal application tenant IDs to
    trusted ServiceNow sys_user_group sys_id values.

    Routing authority comes only from server configuration.
    Ticket fields, model output, approval dictionaries, asset
    owners, MCP arguments, and HTTP request data are never
    routing authorities.
    """

    def __init__(
        self,
        routes: Mapping[str, str],
    ) -> None:

        if not isinstance(
            routes,
            Mapping,
        ):

            raise (
                ServiceNowRoutingConfigurationError(
                    "ServiceNow tenant routing "
                    "must be a mapping."
                )
            )

        validated = {}

        for (
            tenant_id,
            group_sys_id,
        ) in routes.items():

            if (
                not isinstance(
                    tenant_id,
                    str,
                )
                or not tenant_id.strip()
                or tenant_id
                != tenant_id.strip()
            ):

                raise (
                    ServiceNowRoutingConfigurationError(
                        "ServiceNow routing tenant IDs "
                        "must be non-blank normalized "
                        "strings."
                    )
                )

            validated[
                tenant_id
            ] = (
                normalize_assignment_group_sys_id(
                    group_sys_id
                )
            )

        self._routes = (
            MappingProxyType(
                validated
            )
        )

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str],
    ) -> ServiceNowRoutingPolicy:

        raw = environ.get(
            ROUTING_ENVIRONMENT_VARIABLE
        )

        if raw is None:

            return cls(
                {}
            )

        if not isinstance(
            raw,
            str,
        ):

            raise (
                ServiceNowRoutingConfigurationError(
                    "ServiceNow tenant routing "
                    "configuration must be a JSON string."
                )
            )

        if not raw.strip():

            return cls(
                {}
            )

        try:

            decoded = json.loads(
                raw,
                object_pairs_hook=
                    _unique_object_pairs,
            )

        except (
            json.JSONDecodeError,
            ServiceNowRoutingConfigurationError,
        ) as error:

            raise (
                ServiceNowRoutingConfigurationError(
                    "ServiceNow tenant routing "
                    "configuration is invalid."
                )
            ) from error

        if not isinstance(
            decoded,
            dict,
        ):

            raise (
                ServiceNowRoutingConfigurationError(
                    "ServiceNow tenant routing "
                    "configuration must be "
                    "a JSON object."
                )
            )

        return cls(
            decoded
        )

    @property
    def configured_tenants(
        self,
    ) -> tuple[str, ...]:

        return tuple(
            sorted(
                self._routes
            )
        )

    def resolve_assignment_group(
        self,
        tenant_id: str,
    ) -> str:
        """
        Resolve an exact trusted tenant to its configured group.

        There is intentionally no default route.
        """

        if (
            not isinstance(
                tenant_id,
                str,
            )
            or not tenant_id.strip()
            or tenant_id
            != tenant_id.strip()
        ):

            raise ServiceNowRoutingError(
                "Trusted tenant routing authority "
                "is invalid."
            )

        try:

            return self._routes[
                tenant_id
            ]

        except KeyError as error:

            raise ServiceNowRoutingError(
                "No ServiceNow assignment-group "
                "route is configured for this tenant."
            ) from error
