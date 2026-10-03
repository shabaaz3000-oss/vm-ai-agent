from __future__ import annotations

import pytest

from app.security_event_emitter import (
    InMemorySecurityEventSink,
    LegacyAuditInvocationMode,
    LegacyAuditSecurityEventSink,
    SecurityEventEmissionError,
    SecurityEventEmitter,
    build_existing_audit_security_event_sink,
    detect_legacy_audit_invocation_mode,
    emit_security_event,
)
from app.security_observability import (
    SecurityAction,
    SecurityEvent,
    SecurityEventType,
    SecurityEventValidationError,
    SecurityOutcome,
    SecurityReasonCode,
    SecurityResourceType,
    SecuritySeverity,
    SecuritySourceComponent,
)


def _event() -> SecurityEvent:
    return SecurityEvent(
        event_type=(
            SecurityEventType
            .AUTHORIZATION_CROSS_TENANT_DENIED
        ),
        severity=SecuritySeverity.HIGH,
        outcome=SecurityOutcome.DENIED,
        source_component=(
            SecuritySourceComponent.AUTH
        ),
        principal_ref="principal-ref-001",
        tenant_id="tenant-alpha",
        workflow_id="WF-OBS-002",
        resource_type=(
            SecurityResourceType.TENANT
        ),
        action=SecurityAction.AUTHORIZE,
        reason_code=(
            SecurityReasonCode.CROSS_TENANT
        ),
    )


def test_in_memory_sink_records_exact_event():
    sink = InMemorySecurityEventSink()

    event = _event()

    sink.emit(event)

    assert sink.events == (event,)


def test_in_memory_sink_exposes_immutable_snapshot():
    sink = InMemorySecurityEventSink()

    sink.emit(_event())

    observed = sink.events

    assert isinstance(observed, tuple)


def test_emitter_delivers_event_to_sink():
    sink = InMemorySecurityEventSink()

    emitter = SecurityEventEmitter(sink)

    event = _event()

    emitter.emit(event)

    assert sink.events == (event,)


def test_convenience_emit_security_event():
    sink = InMemorySecurityEventSink()

    event = _event()

    emit_security_event(
        event,
        sink=sink,
    )

    assert sink.events == (event,)


def test_emitter_rejects_non_event_input():
    sink = InMemorySecurityEventSink()

    emitter = SecurityEventEmitter(sink)

    with pytest.raises(
        SecurityEventValidationError,
        match="requires a SecurityEvent",
    ):
        emitter.emit(
            {
                "event_type":
                "security.authorization.denied"
            }
        )


class _FailingSink:
    def emit(
        self,
        event: SecurityEvent,
    ) -> None:
        del event

        raise RuntimeError(
            "provider-password=DO-NOT-SURFACE"
        )


def test_emitter_wraps_sink_failure_without_raw_error():
    emitter = SecurityEventEmitter(
        _FailingSink()
    )

    with pytest.raises(
        SecurityEventEmissionError,
        match="Security event emission failed",
    ) as caught:
        emitter.emit(
            _event()
        )

    assert "DO-NOT-SURFACE" not in str(
        caught.value
    )


def test_detects_event_type_mapping_signature():
    def legacy(
        event_type,
        details,
    ):
        del event_type, details

    mode = detect_legacy_audit_invocation_mode(
        legacy
    )

    assert (
        mode
        is LegacyAuditInvocationMode
        .EVENT_TYPE_MAPPING
    )


def test_detects_event_type_kwargs_signature():
    def legacy(
        event_type,
        **details,
    ):
        del event_type, details

    mode = detect_legacy_audit_invocation_mode(
        legacy
    )

    assert (
        mode
        is LegacyAuditInvocationMode
        .EVENT_TYPE_KWARGS
    )


def test_detects_keyword_mapping_signature():
    def legacy(
        event_type,
        *,
        details,
    ):
        del event_type, details

    mode = detect_legacy_audit_invocation_mode(
        legacy
    )

    assert (
        mode
        is LegacyAuditInvocationMode
        .EVENT_TYPE_KEYWORD_MAPPING
    )


def test_rejects_legacy_var_positional_signature():
    def legacy(
        *args,
    ):
        del args

    with pytest.raises(
        SecurityEventEmissionError,
        match=r"\*args",
    ):
        detect_legacy_audit_invocation_mode(
            legacy
        )


def test_rejects_unknown_legacy_signature():
    def legacy():
        return None

    with pytest.raises(
        SecurityEventEmissionError,
        match="Unsupported legacy",
    ):
        detect_legacy_audit_invocation_mode(
            legacy
        )


def test_legacy_mapping_adapter_receives_safe_payload():
    observed = {}

    def legacy(
        event_type,
        details,
    ):
        observed["event_type"] = event_type
        observed["details"] = details

    sink = LegacyAuditSecurityEventSink(
        legacy
    )

    event = _event()

    sink.emit(event)

    assert (
        observed["event_type"]
        == "security.authorization."
        "cross_tenant_denied"
    )

    details = observed["details"]

    assert details["schema_version"] == "1.0"
    assert details["tenant_id"] == "tenant-alpha"
    assert (
        details["reason_code"]
        == "cross_tenant"
    )

    # event_type is supplied exactly once to the legacy API.
    assert "event_type" not in details

    # Sensitive/raw fields are not part of the schema.
    assert "token" not in details
    assert "password" not in details
    assert "request_body" not in details
    assert "response_body" not in details


def test_legacy_kwargs_adapter_receives_safe_payload():
    observed = {}

    def legacy(
        event_type,
        **details,
    ):
        observed["event_type"] = event_type
        observed["details"] = details

    sink = LegacyAuditSecurityEventSink(
        legacy
    )

    sink.emit(
        _event()
    )

    assert (
        observed["event_type"]
        == "security.authorization."
        "cross_tenant_denied"
    )

    assert (
        observed["details"]["workflow_id"]
        == "WF-OBS-002"
    )


def test_legacy_keyword_mapping_adapter():
    observed = {}

    def legacy(
        event_type,
        *,
        payload,
    ):
        observed["event_type"] = event_type
        observed["payload"] = payload

    sink = LegacyAuditSecurityEventSink(
        legacy
    )

    sink.emit(
        _event()
    )

    assert (
        observed["payload"]["tenant_id"]
        == "tenant-alpha"
    )


def test_legacy_adapter_rejects_arbitrary_mapping():
    observed = []

    def legacy(
        event_type,
        details,
    ):
        observed.append(
            (event_type, details)
        )

    sink = LegacyAuditSecurityEventSink(
        legacy
    )

    with pytest.raises(
        SecurityEventValidationError,
        match="requires a SecurityEvent",
    ):
        sink.emit(
            {
                "event_type":
                "security.authorization.denied",
                "access_token":
                "DO-NOT-LOG",
            }
        )

    assert observed == []


def test_existing_repository_audit_signature_supported():
    sink = (
        build_existing_audit_security_event_sink()
    )

    assert isinstance(
        sink,
        LegacyAuditSecurityEventSink,
    )

    assert sink.invocation_mode in {
        LegacyAuditInvocationMode
        .EVENT_TYPE_MAPPING,
        LegacyAuditInvocationMode
        .EVENT_TYPE_KWARGS,
        LegacyAuditInvocationMode
        .EVENT_TYPE_KEYWORD_MAPPING,
    }


def test_adapter_does_not_modify_security_event():
    event = _event()

    before = event.to_dict()

    def legacy(
        event_type,
        details,
    ):
        del event_type, details

    sink = LegacyAuditSecurityEventSink(
        legacy
    )

    sink.emit(event)

    assert event.to_dict() == before


def test_sink_failure_does_not_retain_secret_exception_context():
    import traceback

    import pytest

    from app.security_event_emitter import (
        SecurityEventEmissionError,
        SecurityEventEmitter,
    )
    from app.security_observability import (
        SecurityEvent,
        SecurityEventType,
        SecurityOutcome,
        SecuritySeverity,
        SecuritySourceComponent,
    )


    secret = (
        "SUPER-SECRET-SINK-CREDENTIAL"
    )


    class SecretBearingSink:

        def emit(
            self,
            event,
        ) -> None:

            raise RuntimeError(
                "Authorization: Bearer "
                + secret
            )


    event = SecurityEvent(
        event_type=(
            SecurityEventType
            .AUTHORIZATION_DENIED
        ),
        severity=(
            SecuritySeverity.HIGH
        ),
        outcome=(
            SecurityOutcome.DENIED
        ),
        source_component=(
            SecuritySourceComponent.AUTH
        ),
    )


    with pytest.raises(
        SecurityEventEmissionError
    ) as captured:

        SecurityEventEmitter(
            SecretBearingSink()
        ).emit(
            event
        )


    error = (
        captured.value
    )


    assert (
        secret
        not in str(
            error
        )
    )

    assert (
        "Authorization: Bearer"
        not in str(
            error
        )
    )


    assert (
        error.__cause__
        is None
    )

    assert (
        error.__context__
        is None
    )

    assert (
        error.__suppress_context__
        is True
    )


    rendered = "".join(
        traceback.format_exception(
            type(
                error
            ),
            error,
            error.__traceback__,
        )
    )


    assert (
        secret
        not in rendered
    )

    assert (
        "Authorization: Bearer"
        not in rendered
    )

    assert (
        "RuntimeError"
        not in rendered
    )
