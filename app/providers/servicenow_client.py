from __future__ import annotations

from typing import Any

import httpx

from app.providers.servicenow_correlation import (
    validate_servicenow_correlation_id,
)

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


class ServiceNowLookupError(
    ServiceNowClientError
):
    """
    Raised when a read-only ServiceNow reconciliation lookup
    cannot produce a trustworthy result.

    The lookup performs no external mutation. The workflow must
    remain NEEDS_REVIEW until a later lookup succeeds.
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

    def find_records_by_correlation_id(
        self,
        correlation_id: str,
    ) -> list[dict[str, str]]:
        """
        Retrieve at most two records matching one trusted
        application-derived correlation identifier.

        Query authority is deliberately fixed here:

        - table comes from validated ServiceNowSettings
        - field is always correlation_id
        - returned fields are fixed
        - result limit is always 2
        - no raw sysparm_query is accepted from any caller
        """

        trusted_correlation_id = (
            validate_servicenow_correlation_id(
                correlation_id
            )
        )

        params = {
            "sysparm_query":
                (
                    "correlation_id="
                    + trusted_correlation_id
                ),

            "sysparm_fields":
                "sys_id,number,correlation_id",

            "sysparm_limit":
                "2",
        }

        try:

            response = self._client.get(
                self._settings.table_endpoint,
                params=params,
            )

        except httpx.HTTPError as error:

            raise ServiceNowLookupError(
                "ServiceNow reconciliation lookup "
                "failed before a trustworthy response "
                "was processed."
            ) from error

        if (
            response.status_code < 200
            or response.status_code >= 300
        ):

            raise ServiceNowLookupError(
                "ServiceNow reconciliation lookup "
                f"failed with HTTP "
                f"{response.status_code}."
            )

        try:

            body = response.json()

        except ValueError as error:

            raise ServiceNowLookupError(
                "ServiceNow reconciliation lookup "
                "returned invalid JSON."
            ) from error

        if not isinstance(
            body,
            dict,
        ):

            raise ServiceNowLookupError(
                "ServiceNow reconciliation response "
                "must be an object."
            )

        result = body.get(
            "result"
        )

        if not isinstance(
            result,
            list,
        ):

            raise ServiceNowLookupError(
                "ServiceNow reconciliation response "
                "is missing the result list."
            )

        if len(
            result
        ) > 2:

            raise ServiceNowLookupError(
                "ServiceNow reconciliation returned "
                "more records than the fixed limit."
            )

        normalized = []

        allowed_fields = {
            "sys_id",
            "number",
            "correlation_id",
        }

        for record in result:

            if not isinstance(
                record,
                dict,
            ):

                raise ServiceNowLookupError(
                    "ServiceNow reconciliation record "
                    "must be an object."
                )

            if (
                set(
                    record
                )
                - allowed_fields
            ):

                raise ServiceNowLookupError(
                    "ServiceNow reconciliation record "
                    "contains unexpected fields."
                )

            sys_id = record.get(
                "sys_id"
            )

            number = record.get(
                "number"
            )

            observed_correlation = (
                record.get(
                    "correlation_id"
                )
            )

            if (
                not isinstance(
                    sys_id,
                    str,
                )
                or len(
                    sys_id
                ) != 32
                or any(
                    character
                    not in (
                        "0123456789"
                        "abcdefABCDEF"
                    )
                    for character
                    in sys_id
                )
            ):

                raise ServiceNowLookupError(
                    "ServiceNow reconciliation record "
                    "contains an invalid sys_id."
                )

            if (
                not isinstance(
                    number,
                    str,
                )
                or not number.strip()
                or number
                != number.strip()
            ):

                raise ServiceNowLookupError(
                    "ServiceNow reconciliation record "
                    "contains an invalid number."
                )

            if (
                observed_correlation
                != trusted_correlation_id
            ):

                raise ServiceNowLookupError(
                    "ServiceNow reconciliation record "
                    "does not match the requested "
                    "correlation_id."
                )

            normalized.append(
                {
                    "sys_id":
                        sys_id.lower(),

                    "number":
                        number,

                    "correlation_id":
                        trusted_correlation_id,
                }
            )

        return normalized


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
