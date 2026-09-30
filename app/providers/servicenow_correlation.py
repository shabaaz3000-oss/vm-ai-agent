from __future__ import annotations

from hashlib import sha256

from app.ticket_execution_context import (
    TicketExecutionContext,
)


_CORRELATION_PREFIX = "VMAI-"


class ServiceNowCorrelationError(
    PermissionError
):
    """
    Raised when trusted execution metadata is insufficient to
    establish a stable external ServiceNow correlation key.
    """


def validate_servicenow_correlation_id(
    value: str,
) -> str:
    """
    Validate the exact application-owned correlation format.

    The restricted alphabet prevents encoded-query operators,
    separators, scripting fragments, or caller-controlled query
    structure from entering the ServiceNow lookup boundary.
    """

    if not isinstance(
        value,
        str,
    ):

        raise ServiceNowCorrelationError(
            "ServiceNow correlation_id "
            "must be a string."
        )

    if (
        len(value) != 69
        or not value.startswith(
            "VMAI-"
        )
        or any(
            character
            not in "0123456789abcdef"
            for character
            in value[
                5:
            ]
        )
    ):

        raise ServiceNowCorrelationError(
            "ServiceNow correlation_id "
            "has an invalid format."
        )

    return value


def build_servicenow_correlation_id(
    execution_context: TicketExecutionContext,
) -> str:
    """
    Derive a deterministic external correlation identifier from
    trusted, server-controlled execution state.

    The value deliberately excludes approval IDs, ticket fields,
    model output, MCP arguments, and caller-controlled data.

    SHA-256 keeps the external identifier fixed length while
    avoiding disclosure of internal tenant/workflow identifiers.
    """

    if not isinstance(
        execution_context,
        TicketExecutionContext,
    ):

        raise ServiceNowCorrelationError(
            "Trusted TicketExecutionContext is required "
            "for ServiceNow correlation."
        )

    execution_attempt_id = (
        execution_context
        .execution_attempt_id
    )

    if (
        not isinstance(
            execution_attempt_id,
            str,
        )
        or not execution_attempt_id.strip()
        or execution_attempt_id
        != execution_attempt_id.strip()
    ):

        raise ServiceNowCorrelationError(
            "A trusted execution_attempt_id is required "
            "for ServiceNow correlation."
        )

    material = "\x1f".join(
        (
            execution_context.tenant_id,
            execution_context.workflow_id,
            execution_attempt_id,
        )
    ).encode(
        "utf-8"
    )

    digest = sha256(
        material
    ).hexdigest()

    correlation_id = (
        _CORRELATION_PREFIX
        + digest
    )

    # ServiceNow correlation fields are bounded strings.
    # Keep the application profile well below 100 characters.

    if len(
        correlation_id
    ) > 100:

        raise ServiceNowCorrelationError(
            "Derived ServiceNow correlation_id "
            "exceeds the supported length."
        )

    return validate_servicenow_correlation_id(
        correlation_id
    )
