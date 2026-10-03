from __future__ import annotations

from hashlib import sha256


_EXECUTION_ATTEMPT_REF_PREFIX = "EA1-"

_EXECUTION_ATTEMPT_REF_DIGEST_LENGTH = 64

_EXECUTION_ATTEMPT_REF_LENGTH = (
    len(_EXECUTION_ATTEMPT_REF_PREFIX)
    + _EXECUTION_ATTEMPT_REF_DIGEST_LENGTH
)

_EXECUTION_ATTEMPT_REF_DOMAIN = (
    "vm-ai-security-observability:"
    "execution-attempt-ref:v1"
)


class SecurityCorrelationError(
    ValueError
):
    """
    Raised when trusted security-correlation material is invalid.
    """


def _require_trusted_correlation_value(
    *,
    field_name: str,
    value: str,
) -> str:
    """
    Require a normalized, bounded server-side correlation input.

    Validation does not establish authority. Callers remain
    responsible for supplying values obtained from authoritative
    runtime state.
    """

    if not isinstance(
        value,
        str,
    ):
        raise SecurityCorrelationError(
            f"{field_name} must be a string."
        )

    if (
        not value
        or not value.strip()
        or value != value.strip()
    ):
        raise SecurityCorrelationError(
            f"{field_name} must be a non-blank "
            "normalized string."
        )

    if len(value) > 512:
        raise SecurityCorrelationError(
            f"{field_name} exceeds the supported "
            "correlation length."
        )

    if any(
        ord(character) < 32
        or ord(character) == 127
        for character in value
    ):
        raise SecurityCorrelationError(
            f"{field_name} contains control characters."
        )

    return value


def validate_execution_attempt_ref(
    value: str,
) -> str:
    """
    Validate the canonical execution-attempt reference format.

    The reference is correlation metadata only and is never an
    execution authorization value.
    """

    if not isinstance(
        value,
        str,
    ):
        raise SecurityCorrelationError(
            "execution_attempt_ref must be a string."
        )

    if (
        len(value)
        != _EXECUTION_ATTEMPT_REF_LENGTH
        or not value.startswith(
            _EXECUTION_ATTEMPT_REF_PREFIX
        )
        or any(
            character
            not in "0123456789abcdef"
            for character in value[
                len(
                    _EXECUTION_ATTEMPT_REF_PREFIX
                ):
            ]
        )
    ):
        raise SecurityCorrelationError(
            "execution_attempt_ref has an invalid format."
        )

    return value


def build_execution_attempt_ref(
    *,
    tenant_id: str,
    workflow_id: str,
    execution_attempt_id: str,
) -> str:
    """
    Derive a deterministic pseudonymous reference from trusted
    workflow execution state.

    The raw execution_attempt_id participates in exact execution
    authority and MUST NOT be replaced by this reference in any
    compare-and-swap, transition, reconciliation, or authorization
    decision.

    This function only derives observability correlation.
    """

    trusted_tenant_id = (
        _require_trusted_correlation_value(
            field_name="tenant_id",
            value=tenant_id,
        )
    )

    trusted_workflow_id = (
        _require_trusted_correlation_value(
            field_name="workflow_id",
            value=workflow_id,
        )
    )

    trusted_execution_attempt_id = (
        _require_trusted_correlation_value(
            field_name="execution_attempt_id",
            value=execution_attempt_id,
        )
    )

    material = "\x1f".join(
        (
            _EXECUTION_ATTEMPT_REF_DOMAIN,
            trusted_tenant_id,
            trusted_workflow_id,
            trusted_execution_attempt_id,
        )
    ).encode(
        "utf-8"
    )

    digest = sha256(
        material
    ).hexdigest()

    reference = (
        _EXECUTION_ATTEMPT_REF_PREFIX
        + digest
    )

    return validate_execution_attempt_ref(
        reference
    )
