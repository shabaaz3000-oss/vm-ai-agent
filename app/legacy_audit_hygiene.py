"""
Legacy audit confidentiality and correlation helpers.

This module is observational only. It does not authenticate,
authorize, establish workflow authority, select authoritative state,
or participate in CAS/reconciliation.
"""

from __future__ import annotations

from app.security_observability_correlation import (
    SecurityCorrelationError,
    build_execution_attempt_ref,
)


def build_legacy_execution_attempt_audit_fields(
    *,
    tenant_id: str | None,
    workflow_id: str,
    execution_attempt_id: str | None,
) -> dict[str, str]:
    """
    Return optional EA1 correlation fields for legacy audit.

    Callers must supply trusted authoritative workflow state.

    Missing tenant or execution-attempt authority produces no
    execution-attempt audit correlation. The raw exact attempt is
    never returned.
    """

    if (
        tenant_id is None
        or execution_attempt_id is None
    ):
        return {}


    try:

        execution_attempt_ref = (
            build_execution_attempt_ref(
                tenant_id=
                    tenant_id,

                workflow_id=
                    workflow_id,

                execution_attempt_id=
                    execution_attempt_id,
            )
        )

    except SecurityCorrelationError:

        # Optional legacy audit correlation must not interfere with
        # the underlying workflow security operation.
        return {}


    return {
        "execution_attempt_ref":
            execution_attempt_ref,
    }
