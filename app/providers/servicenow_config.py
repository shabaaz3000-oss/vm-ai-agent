from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse


class ServiceNowConfigurationError(ValueError):
    """
    Raised when ServiceNow production configuration violates
    the application's trusted outbound boundary.
    """


@dataclass(frozen=True)
class ServiceNowSettings:
    """
    Server-owned ServiceNow connection settings.

    No caller, LLM, MCP tool argument, vulnerability record,
    asset metadata, or ticket draft may choose the outbound
    ServiceNow host or table.

    Credentials are intentionally omitted from repr output.
    """

    instance_url: str
    username: str
    password: str
    table: str = "incident"
    timeout_seconds: float = 10.0

    ALLOWED_TABLES = frozenset(
        {
            "incident",
        }
    )

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> "ServiceNowSettings":

        source = (
            os.environ
            if environ is None
            else environ
        )

        instance_url = (
            source.get(
                "SERVICENOW_INSTANCE_URL",
                "",
            )
            .strip()
            .rstrip("/")
        )

        username = source.get(
            "SERVICENOW_USERNAME",
            "",
        ).strip()

        password = source.get(
            "SERVICENOW_PASSWORD",
            "",
        )

        table = (
            source.get(
                "SERVICENOW_TABLE",
                "incident",
            )
            .strip()
            .lower()
        )

        raw_timeout = source.get(
            "SERVICENOW_TIMEOUT_SECONDS",
            "10",
        )

        try:
            timeout_seconds = float(
                raw_timeout
            )
        except (
            TypeError,
            ValueError,
        ) as error:
            raise ServiceNowConfigurationError(
                "ServiceNow timeout must be numeric."
            ) from error

        settings = cls(
            instance_url=instance_url,
            username=username,
            password=password,
            table=table,
            timeout_seconds=timeout_seconds,
        )

        settings.validate()

        return settings

    def validate(self) -> None:

        if not self.instance_url:
            raise ServiceNowConfigurationError(
                "ServiceNow instance URL is required."
            )

        parsed = urlparse(
            self.instance_url
        )

        if parsed.scheme != "https":
            raise ServiceNowConfigurationError(
                "ServiceNow instance URL must use HTTPS."
            )

        if not parsed.hostname:
            raise ServiceNowConfigurationError(
                "ServiceNow instance URL must contain a host."
            )

        if parsed.username or parsed.password:
            raise ServiceNowConfigurationError(
                "Credentials must not be embedded in the "
                "ServiceNow instance URL."
            )

        if parsed.query or parsed.fragment:
            raise ServiceNowConfigurationError(
                "ServiceNow instance URL must not contain "
                "a query string or fragment."
            )

        if parsed.path not in (
            "",
            "/",
        ):
            raise ServiceNowConfigurationError(
                "ServiceNow instance URL must identify only "
                "the trusted instance origin."
            )

        if self.table not in self.ALLOWED_TABLES:
            raise ServiceNowConfigurationError(
                "ServiceNow table is not allowlisted."
            )

        if not self.username:
            raise ServiceNowConfigurationError(
                "ServiceNow username is required."
            )

        if not self.password:
            raise ServiceNowConfigurationError(
                "ServiceNow password is required."
            )

        if (
            self.timeout_seconds <= 0
            or self.timeout_seconds > 30
        ):
            raise ServiceNowConfigurationError(
                "ServiceNow timeout must be greater than "
                "0 and no more than 30 seconds."
            )

    @property
    def table_endpoint(self) -> str:

        return (
            f"{self.instance_url}"
            f"/api/now/table/"
            f"{self.table}"
        )

    def __repr__(self) -> str:

        return (
            "ServiceNowSettings("
            f"instance_url={self.instance_url!r}, "
            f"username={self.username!r}, "
            "password='<redacted>', "
            f"table={self.table!r}, "
            f"timeout_seconds={self.timeout_seconds!r}"
            ")"
        )
