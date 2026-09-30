from __future__ import annotations

from typing import Any

import httpx

from app.providers.servicenow_config import (
    ServiceNowSettings,
)


class ServiceNowClientError(RuntimeError):
    """
    Base exception for controlled ServiceNow client failures.
    """


class ServiceNowTransportError(
    ServiceNowClientError
):
    """
    Raised when the HTTP outcome is uncertain because transport
    failed before a trustworthy response was processed.

    Callers MUST NOT blindly retry ticket creation.
    """


class ServiceNowResponseError(
    ServiceNowClientError
):
    """
    Raised when ServiceNow returns an invalid or unsuccessful
    response.
    """


class ServiceNowClient:
    """
    Minimal hardened ServiceNow Table API client.

    Security properties:

    - destination URL comes only from trusted settings
    - HTTPS is enforced by configuration validation
    - table selection is allowlisted
    - caller cannot supply arbitrary URLs
    - caller cannot supply arbitrary headers
    - bounded request timeout
    - no automatic POST retry
    - unsuccessful responses fail closed
    - response schema is validated before use
    """

    def __init__(
        self,
        settings: ServiceNowSettings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:

        settings.validate()

        self._settings = settings

        self._client = httpx.Client(
            auth=(
                settings.username,
                settings.password,
            ),
            headers={
                "Accept":
                    "application/json",
                "Content-Type":
                    "application/json",
            },
            timeout=settings.timeout_seconds,
            transport=transport,
            follow_redirects=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(
        self,
    ) -> "ServiceNowClient":
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        self.close()

    def create_record(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:

        if not isinstance(
            payload,
            dict,
        ):
            raise TypeError(
                "ServiceNow payload must be a dictionary."
            )

        if not payload:
            raise ValueError(
                "ServiceNow payload cannot be empty."
            )

        try:
            response = self._client.post(
                self._settings.table_endpoint,
                json=payload,
            )
        except httpx.HTTPError as error:
            raise ServiceNowTransportError(
                "ServiceNow ticket creation has an "
                "uncertain external outcome and must "
                "be reconciled before retry."
            ) from error

        if (
            response.status_code < 200
            or response.status_code >= 300
        ):
            raise ServiceNowResponseError(
                "ServiceNow rejected ticket creation "
                f"with HTTP {response.status_code}."
            )

        try:
            body = response.json()
        except ValueError as error:
            raise ServiceNowResponseError(
                "ServiceNow returned invalid JSON."
            ) from error

        if not isinstance(
            body,
            dict,
        ):
            raise ServiceNowResponseError(
                "ServiceNow response must be an object."
            )

        result = body.get(
            "result"
        )

        if not isinstance(
            result,
            dict,
        ):
            raise ServiceNowResponseError(
                "ServiceNow response is missing result."
            )

        sys_id = result.get(
            "sys_id"
        )

        number = result.get(
            "number"
        )

        if (
            not isinstance(
                sys_id,
                str,
            )
            or not sys_id.strip()
        ):
            raise ServiceNowResponseError(
                "ServiceNow response is missing sys_id."
            )

        if (
            not isinstance(
                number,
                str,
            )
            or not number.strip()
        ):
            raise ServiceNowResponseError(
                "ServiceNow response is missing number."
            )

        return dict(
            result
        )
