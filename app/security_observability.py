"""
Canonical production security-event model.

This module implements the Step 50 security observability contract.

Security telemetry observes authority; it is not authority. Nothing in
this module grants access, selects a tenant, establishes a principal,
approves a workflow, creates an execution claim, or changes provider /
reconciliation authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import UUID, uuid4


SECURITY_EVENT_SCHEMA_VERSION = "1.0"


class SecurityEventValidationError(ValueError):
    """Raised when security-event input violates the v1 contract."""


class SecurityEventType(str, Enum):
    """Canonical bounded security-event taxonomy."""

    # Identity / authentication.
    IDENTITY_AUTHENTICATION_SUCCEEDED = (
        "security.identity.authentication_succeeded"
    )
    IDENTITY_AUTHENTICATION_FAILED = (
        "security.identity.authentication_failed"
    )
    IDENTITY_PRINCIPAL_BINDING_FAILED = (
        "security.identity.principal_binding_failed"
    )
    IDENTITY_TENANT_BINDING_DENIED = (
        "security.identity.tenant_binding_denied"
    )

    # Authorization.
    AUTHORIZATION_ALLOWED = (
        "security.authorization.allowed"
    )
    AUTHORIZATION_DENIED = (
        "security.authorization.denied"
    )
    AUTHORIZATION_CROSS_TENANT_DENIED = (
        "security.authorization.cross_tenant_denied"
    )

    # RAG.
    RAG_RETRIEVAL_ALLOWED = (
        "security.rag.retrieval_allowed"
    )
    RAG_RETRIEVAL_DENIED = (
        "security.rag.retrieval_denied"
    )
    RAG_DOCUMENT_ACL_DENIED = (
        "security.rag.document_acl_denied"
    )
    RAG_PROMPT_INJECTION_BLOCKED = (
        "security.rag.prompt_injection_blocked"
    )

    # MCP / tooling.
    MCP_SESSION_CREATED = (
        "security.mcp.session_created"
    )
    MCP_SESSION_VALIDATION_FAILED = (
        "security.mcp.session_validation_failed"
    )
    MCP_SESSION_REVOKED = (
        "security.mcp.session_revoked"
    )
    MCP_TOOL_INVOCATION_ALLOWED = (
        "security.mcp.tool_invocation_allowed"
    )
    MCP_TOOL_INVOCATION_DENIED = (
        "security.mcp.tool_invocation_denied"
    )
    MCP_TOOL_OUTPUT_INJECTION_BLOCKED = (
        "security.mcp.tool_output_injection_blocked"
    )

    # Workflow / approval.
    WORKFLOW_CREATED = (
        "security.workflow.created"
    )
    WORKFLOW_APPROVAL_GRANTED = (
        "security.workflow.approval_granted"
    )
    WORKFLOW_APPROVAL_REJECTED = (
        "security.workflow.approval_rejected"
    )
    WORKFLOW_TRANSITION_DENIED = (
        "security.workflow.transition_denied"
    )
    WORKFLOW_EXECUTION_CLAIMED = (
        "security.workflow.execution_claimed"
    )
    WORKFLOW_EXECUTION_CLAIM_DENIED = (
        "security.workflow.execution_claim_denied"
    )
    WORKFLOW_STALE_PROCESSING_DETECTED = (
        "security.workflow.stale_processing_detected"
    )
    WORKFLOW_RECONCILIATION_STARTED = (
        "security.workflow.reconciliation_started"
    )
    WORKFLOW_RECONCILIATION_RESOLVED = (
        "security.workflow.reconciliation_resolved"
    )
    WORKFLOW_NEEDS_REVIEW = (
        "security.workflow.needs_review"
    )

    # Provider / ServiceNow.
    PROVIDER_REQUEST_STARTED = (
        "security.provider.request_started"
    )
    PROVIDER_REQUEST_COMPLETED = (
        "security.provider.request_completed"
    )
    PROVIDER_RESULT_CORRELATED = (
        "security.provider.result_correlated"
    )
    PROVIDER_RESULT_AMBIGUOUS = (
        "security.provider.result_ambiguous"
    )
    PROVIDER_RECONCILIATION_DENIED = (
        "security.provider.reconciliation_denied"
    )

    # AI security.
    AI_DIRECT_PROMPT_INJECTION_BLOCKED = (
        "security.ai.direct_prompt_injection_blocked"
    )
    AI_TOOL_OUTPUT_PROMPT_INJECTION_BLOCKED = (
        "security.ai.tool_output_prompt_injection_blocked"
    )


class SecuritySeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityOutcome(str, Enum):
    SUCCESS = "success"
    ALLOWED = "allowed"
    DENIED = "denied"
    BLOCKED = "blocked"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"
    REVOKED = "revoked"
    REVIEW_REQUIRED = "review_required"


class SecuritySourceComponent(str, Enum):
    API = "api"
    AUTH = "auth"
    AGENT = "agent"
    RETRIEVAL_AUTHORIZATION = "retrieval_authorization"
    RETRIEVER = "retriever"
    MCP_SESSION = "mcp_session"
    MCP_SERVER = "mcp_server"
    WORKFLOW = "workflow"
    EXECUTION = "execution"
    WORKFLOW_STORE = "workflow_store"
    WORKFLOW_POSTGRESQL_STORE = "workflow_postgresql_store"
    TICKETING = "ticketing"
    SERVICENOW_PROVIDER = "servicenow_provider"
    SERVICENOW_RECONCILIATION = "servicenow_reconciliation"


class SecurityReasonCode(str, Enum):
    INVALID_CREDENTIALS = "invalid_credentials"
    PRINCIPAL_UNBOUND = "principal_unbound"
    TENANT_UNBOUND = "tenant_unbound"
    CROSS_TENANT = "cross_tenant"
    INSUFFICIENT_ROLE = "insufficient_role"
    RETRIEVAL_ACL_DENIED = "retrieval_acl_denied"
    DOCUMENT_ACL_DENIED = "document_acl_denied"
    SESSION_MISSING = "session_missing"
    SESSION_EXPIRED = "session_expired"
    SESSION_REVOKED = "session_revoked"
    SECURITY_BINDING_MISMATCH = "security_binding_mismatch"
    PROMPT_INJECTION_DETECTED = "prompt_injection_detected"
    TOOL_NOT_AUTHORIZED = "tool_not_authorized"
    WORKFLOW_TRANSITION_NOT_ALLOWED = (
        "workflow_transition_not_allowed"
    )
    EXECUTION_ALREADY_CLAIMED = "execution_already_claimed"
    EXECUTION_ATTEMPT_MISMATCH = "execution_attempt_mismatch"
    STALE_EXECUTION_ATTEMPT = "stale_execution_attempt"
    PROVIDER_CORRELATION_MISMATCH = (
        "provider_correlation_mismatch"
    )
    PROVIDER_AMBIGUOUS = "provider_ambiguous"
    RECONCILIATION_DENIED = "reconciliation_denied"
    NEEDS_REVIEW = "needs_review"


class SecurityResourceType(str, Enum):
    IDENTITY = "identity"
    TENANT = "tenant"
    RAG_DOCUMENT = "rag_document"
    RETRIEVAL = "retrieval"
    MCP_SESSION = "mcp_session"
    MCP_TOOL = "mcp_tool"
    WORKFLOW = "workflow"
    APPROVAL = "approval"
    EXECUTION_ATTEMPT = "execution_attempt"
    PROVIDER_REQUEST = "provider_request"
    PROVIDER_RESULT = "provider_result"
    RECONCILIATION = "reconciliation"


class SecurityAction(str, Enum):
    AUTHENTICATE = "authenticate"
    AUTHORIZE = "authorize"
    BIND_PRINCIPAL = "bind_principal"
    BIND_TENANT = "bind_tenant"
    RETRIEVE = "retrieve"
    CREATE_SESSION = "create_session"
    VALIDATE_SESSION = "validate_session"
    REVOKE_SESSION = "revoke_session"
    INVOKE_TOOL = "invoke_tool"
    CREATE_WORKFLOW = "create_workflow"
    APPROVE_WORKFLOW = "approve_workflow"
    REJECT_WORKFLOW = "reject_workflow"
    TRANSITION_WORKFLOW = "transition_workflow"
    CLAIM_EXECUTION = "claim_execution"
    RECONCILE = "reconcile"
    CALL_PROVIDER = "call_provider"
    CORRELATE_PROVIDER_RESULT = "correlate_provider_result"
    INSPECT_PROMPT_INJECTION = "inspect_prompt_injection"


_OUTPUT_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "event_type",
        "occurred_at",
        "severity",
        "outcome",
        "source_component",
        "request_id",
        "principal_ref",
        "tenant_id",
        "session_ref",
        "workflow_id",
        "execution_attempt_ref",
        "provider_correlation_id",
        "resource_type",
        "action",
        "reason_code",
    }
)

_SERVER_OWNED_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "occurred_at",
    }
)

_INPUT_FIELDS = _OUTPUT_FIELDS - _SERVER_OWNED_FIELDS

_REQUIRED_INPUT_FIELDS = frozenset(
    {
        "event_type",
        "severity",
        "outcome",
        "source_component",
    }
)

_OPTIONAL_TEXT_FIELDS = (
    "request_id",
    "principal_ref",
    "tenant_id",
    "session_ref",
    "workflow_id",
    "execution_attempt_ref",
    "provider_correlation_id",
)

_FORBIDDEN_FIELD_FRAGMENTS = frozenset(
    {
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "authorization",
        "bearer",
        "cookie",
        "api_key",
        "apikey",
        "access_key",
        "secret_key",
        "private_key",
        "client_secret",
        "raw_prompt",
        "prompt_text",
        "model_prompt",
        "model_response",
        "document_content",
        "rag_document_body",
        "retrieved_evidence",
        "raw_content",
        "tool_output",
        "request_body",
        "response_body",
    }
)

_CONTROL_CHAR_PATTERN = re.compile(
    r"[\x00-\x1f\x7f]"
)

_SAFE_REFERENCE_MAX_LENGTH = 512


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_field_name(value: object) -> str:
    text = str(value).strip().lower()

    return re.sub(
        r"[^a-z0-9]+",
        "_",
        text,
    ).strip("_")


def _find_forbidden_field_path(
    value: object,
    *,
    path: str = "$",
) -> str | None:
    """
    Recursively inspect mapping keys for sensitive field names.

    The canonical v1 event does not support arbitrary nested metadata,
    but recursive inspection ensures a future adapter cannot hide a
    credential inside a nested object before unknown-field validation.
    """

    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = _normalize_field_name(key)

            if any(
                fragment in normalized
                for fragment in _FORBIDDEN_FIELD_FRAGMENTS
            ):
                return f"{path}.{key}"

            nested_path = _find_forbidden_field_path(
                nested,
                path=f"{path}.{key}",
            )

            if nested_path is not None:
                return nested_path

    elif isinstance(value, (list, tuple, set)):
        for index, nested in enumerate(value):
            nested_path = _find_forbidden_field_path(
                nested,
                path=f"{path}[{index}]",
            )

            if nested_path is not None:
                return nested_path

    return None


def _validate_reference(
    name: str,
    value: str | None,
) -> None:
    if value is None:
        return

    if not isinstance(value, str):
        raise SecurityEventValidationError(
            f"{name} must be a string or None."
        )

    if not value.strip():
        raise SecurityEventValidationError(
            f"{name} must not be blank."
        )

    if len(value) > _SAFE_REFERENCE_MAX_LENGTH:
        raise SecurityEventValidationError(
            f"{name} exceeds the maximum safe length."
        )

    if _CONTROL_CHAR_PATTERN.search(value):
        raise SecurityEventValidationError(
            f"{name} contains control characters."
        )


def _coerce_enum(
    enum_type: type[Enum],
    value: object,
    *,
    field_name: str,
) -> Enum:
    if isinstance(value, enum_type):
        return value

    if not isinstance(value, str):
        raise SecurityEventValidationError(
            f"{field_name} must be a bounded string value."
        )

    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(
            sorted(str(item.value) for item in enum_type)
        )

        raise SecurityEventValidationError(
            f"Unsupported {field_name}: {value!r}. "
            f"Allowed values: {allowed}"
        ) from exc


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise SecurityEventValidationError(
            "occurred_at must be timezone-aware."
        )

    normalized = value.astimezone(timezone.utc)

    return normalized.isoformat().replace(
        "+00:00",
        "Z",
    )


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """
    Immutable schema-v1 production security event.

    Server-owned fields are intentionally not constructor parameters.
    """

    event_type: SecurityEventType
    severity: SecuritySeverity
    outcome: SecurityOutcome
    source_component: SecuritySourceComponent

    request_id: str | None = None
    principal_ref: str | None = None
    tenant_id: str | None = None
    session_ref: str | None = None
    workflow_id: str | None = None
    execution_attempt_ref: str | None = None
    provider_correlation_id: str | None = None

    resource_type: SecurityResourceType | None = None
    action: SecurityAction | None = None
    reason_code: SecurityReasonCode | None = None

    schema_version: str = field(
        default=SECURITY_EVENT_SCHEMA_VERSION,
        init=False,
    )
    event_id: str = field(
        default_factory=lambda: str(uuid4()),
        init=False,
    )
    occurred_at: datetime = field(
        default_factory=_utc_now,
        init=False,
    )

    def __post_init__(self) -> None:
        required_enums = (
            (
                "event_type",
                self.event_type,
                SecurityEventType,
            ),
            (
                "severity",
                self.severity,
                SecuritySeverity,
            ),
            (
                "outcome",
                self.outcome,
                SecurityOutcome,
            ),
            (
                "source_component",
                self.source_component,
                SecuritySourceComponent,
            ),
        )

        for name, value, enum_type in required_enums:
            if not isinstance(value, enum_type):
                raise SecurityEventValidationError(
                    f"{name} must be a {enum_type.__name__}."
                )

        optional_enums = (
            (
                "resource_type",
                self.resource_type,
                SecurityResourceType,
            ),
            (
                "action",
                self.action,
                SecurityAction,
            ),
            (
                "reason_code",
                self.reason_code,
                SecurityReasonCode,
            ),
        )

        for name, value, enum_type in optional_enums:
            if value is not None and not isinstance(
                value,
                enum_type,
            ):
                raise SecurityEventValidationError(
                    f"{name} must be a {enum_type.__name__} "
                    "or None."
                )

        for name in _OPTIONAL_TEXT_FIELDS:
            _validate_reference(
                name,
                getattr(self, name),
            )

        try:
            UUID(self.event_id)
        except ValueError as exc:
            raise SecurityEventValidationError(
                "event_id must be a valid UUID."
            ) from exc

        if self.occurred_at.tzinfo is None:
            raise SecurityEventValidationError(
                "occurred_at must be timezone-aware."
            )

    def to_dict(self) -> dict[str, object]:
        """
        Return the explicit allowlisted schema-v1 event payload.

        None-valued optional fields are omitted.
        """

        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "occurred_at": _format_timestamp(
                self.occurred_at
            ),
            "severity": self.severity.value,
            "outcome": self.outcome.value,
            "source_component": (
                self.source_component.value
            ),
        }

        optional_values: tuple[
            tuple[str, object | None],
            ...,
        ] = (
            ("request_id", self.request_id),
            ("principal_ref", self.principal_ref),
            ("tenant_id", self.tenant_id),
            ("session_ref", self.session_ref),
            ("workflow_id", self.workflow_id),
            (
                "execution_attempt_ref",
                self.execution_attempt_ref,
            ),
            (
                "provider_correlation_id",
                self.provider_correlation_id,
            ),
            (
                "resource_type",
                (
                    self.resource_type.value
                    if self.resource_type
                    else None
                ),
            ),
            (
                "action",
                self.action.value
                if self.action
                else None,
            ),
            (
                "reason_code",
                (
                    self.reason_code.value
                    if self.reason_code
                    else None
                ),
            ),
        )

        for name, value in optional_values:
            if value is not None:
                payload[name] = value

        unexpected = (
            set(payload)
            - _OUTPUT_FIELDS
        )

        if unexpected:
            raise SecurityEventValidationError(
                "Security event contains non-allowlisted "
                f"fields: {sorted(unexpected)}"
            )

        return payload


def security_event_from_mapping(
    values: Mapping[str, Any],
) -> SecurityEvent:
    """
    Build a canonical event from trusted adapter input.

    Server-owned fields cannot be supplied by the adapter.
    Unknown and sensitive field names are rejected.
    """

    if not isinstance(values, Mapping):
        raise SecurityEventValidationError(
            "Security event input must be a mapping."
        )

    forbidden_path = _find_forbidden_field_path(
        values
    )

    if forbidden_path is not None:
        raise SecurityEventValidationError(
            "Sensitive field is forbidden in security "
            f"telemetry: {forbidden_path}"
        )

    supplied_fields = set(values)

    server_owned = (
        supplied_fields
        & _SERVER_OWNED_FIELDS
    )

    if server_owned:
        raise SecurityEventValidationError(
            "Server-owned fields cannot be supplied: "
            f"{sorted(server_owned)}"
        )

    unknown = supplied_fields - _INPUT_FIELDS

    if unknown:
        raise SecurityEventValidationError(
            "Unknown security-event fields: "
            f"{sorted(unknown)}"
        )

    missing = (
        _REQUIRED_INPUT_FIELDS
        - supplied_fields
    )

    if missing:
        raise SecurityEventValidationError(
            "Missing required security-event fields: "
            f"{sorted(missing)}"
        )

    event_type = _coerce_enum(
        SecurityEventType,
        values["event_type"],
        field_name="event_type",
    )
    severity = _coerce_enum(
        SecuritySeverity,
        values["severity"],
        field_name="severity",
    )
    outcome = _coerce_enum(
        SecurityOutcome,
        values["outcome"],
        field_name="outcome",
    )
    source_component = _coerce_enum(
        SecuritySourceComponent,
        values["source_component"],
        field_name="source_component",
    )

    resource_type_raw = values.get(
        "resource_type"
    )
    action_raw = values.get("action")
    reason_code_raw = values.get(
        "reason_code"
    )

    resource_type = (
        None
        if resource_type_raw is None
        else _coerce_enum(
            SecurityResourceType,
            resource_type_raw,
            field_name="resource_type",
        )
    )

    action = (
        None
        if action_raw is None
        else _coerce_enum(
            SecurityAction,
            action_raw,
            field_name="action",
        )
    )

    reason_code = (
        None
        if reason_code_raw is None
        else _coerce_enum(
            SecurityReasonCode,
            reason_code_raw,
            field_name="reason_code",
        )
    )

    text_values: dict[str, str | None] = {}

    for name in _OPTIONAL_TEXT_FIELDS:
        value = values.get(name)

        if value is not None and not isinstance(
            value,
            str,
        ):
            raise SecurityEventValidationError(
                f"{name} must be a string or None."
            )

        text_values[name] = value

    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        outcome=outcome,
        source_component=source_component,
        request_id=text_values["request_id"],
        principal_ref=text_values[
            "principal_ref"
        ],
        tenant_id=text_values["tenant_id"],
        session_ref=text_values["session_ref"],
        workflow_id=text_values["workflow_id"],
        execution_attempt_ref=text_values[
            "execution_attempt_ref"
        ],
        provider_correlation_id=text_values[
            "provider_correlation_id"
        ],
        resource_type=resource_type,
        action=action,
        reason_code=reason_code,
    )


def serialize_security_event(
    event: SecurityEvent,
) -> str:
    """
    Serialize one normalized security event as compact JSON.

    The serializer only accepts SecurityEvent instances so arbitrary
    dictionaries cannot bypass the allowlist.
    """

    if not isinstance(event, SecurityEvent):
        raise SecurityEventValidationError(
            "serialize_security_event requires "
            "a SecurityEvent instance."
        )

    payload = event.to_dict()

    forbidden_path = _find_forbidden_field_path(
        payload
    )

    if forbidden_path is not None:
        raise SecurityEventValidationError(
            "Sensitive field reached the security-event "
            f"serializer: {forbidden_path}"
        )

    if set(payload) - _OUTPUT_FIELDS:
        raise SecurityEventValidationError(
            "Security-event serializer encountered "
            "a non-allowlisted field."
        )

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
