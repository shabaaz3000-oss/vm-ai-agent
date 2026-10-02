from __future__ import annotations

import pytest

from app.security_observability_correlation import (
    SecurityCorrelationError,
    build_execution_attempt_ref,
    validate_execution_attempt_ref,
)


def _build(
    *,
    tenant_id: str = "tenant-alpha",
    workflow_id: str = "WF-1234ABCD",
    execution_attempt_id: str = "EXEC-ABCDEF12",
) -> str:

    return build_execution_attempt_ref(
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        execution_attempt_id=execution_attempt_id,
    )


def test_execution_attempt_ref_is_deterministic():
    first = _build()
    second = _build()

    assert first == second


def test_execution_attempt_ref_has_bounded_format():
    reference = _build()

    assert reference.startswith(
        "EA1-"
    )

    assert len(reference) == 68

    digest = reference[4:]

    assert len(digest) == 64

    int(
        digest,
        16,
    )

    assert (
        validate_execution_attempt_ref(
            reference
        )
        == reference
    )


def test_execution_attempt_ref_does_not_disclose_raw_attempt():
    raw_attempt = (
        "EXEC-ABCDEF12"
    )

    reference = _build(
        execution_attempt_id=raw_attempt,
    )

    assert raw_attempt not in reference

    assert (
        reference
        != raw_attempt
    )


@pytest.mark.parametrize(
    (
        "changed_field",
        "kwargs",
    ),
    [
        (
            "tenant",
            {
                "tenant_id":
                    "tenant-beta",
            },
        ),
        (
            "workflow",
            {
                "workflow_id":
                    "WF-AAAAAAAA",
            },
        ),
        (
            "attempt",
            {
                "execution_attempt_id":
                    "EXEC-11111111",
            },
        ),
    ],
)
def test_execution_attempt_ref_changes_with_authority_tuple(
    changed_field: str,
    kwargs: dict[str, str],
):
    del changed_field

    baseline = _build()

    changed = _build(
        **kwargs
    )

    assert changed != baseline


@pytest.mark.parametrize(
    (
        "field",
        "kwargs",
    ),
    [
        (
            "tenant_id",
            {
                "tenant_id":
                    "",
            },
        ),
        (
            "tenant_id",
            {
                "tenant_id":
                    " tenant-alpha",
            },
        ),
        (
            "workflow_id",
            {
                "workflow_id":
                    " ",
            },
        ),
        (
            "workflow_id",
            {
                "workflow_id":
                    "WF-1234ABCD ",
            },
        ),
        (
            "execution_attempt_id",
            {
                "execution_attempt_id":
                    "",
            },
        ),
        (
            "execution_attempt_id",
            {
                "execution_attempt_id":
                    "EXEC-ABCDEF12\n",
            },
        ),
    ],
)
def test_execution_attempt_ref_rejects_invalid_material(
    field: str,
    kwargs: dict[str, str],
):
    with pytest.raises(
        SecurityCorrelationError,
        match=field,
    ):
        _build(
            **kwargs
        )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "EA1-",
        "EXEC-ABCDEF12",
        "EA1-" + ("g" * 64),
        "EA1-" + ("a" * 63),
        "EA2-" + ("a" * 64),
        " ea1-" + ("a" * 64),
    ],
)
def test_execution_attempt_ref_validator_rejects_wrong_format(
    value: str,
):
    with pytest.raises(
        SecurityCorrelationError,
        match="invalid format",
    ):
        validate_execution_attempt_ref(
            value
        )


def test_execution_attempt_ref_is_not_raw_authority():
    raw_attempt = (
        "EXEC-DEADBEEF"
    )

    reference = (
        build_execution_attempt_ref(
            tenant_id="tenant-alpha",
            workflow_id="WF-12345678",
            execution_attempt_id=raw_attempt,
        )
    )

    assert (
        reference
        != raw_attempt
    )

    assert (
        raw_attempt
        not in reference
    )
