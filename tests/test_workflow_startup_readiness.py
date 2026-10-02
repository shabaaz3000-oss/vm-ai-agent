from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from app import api


def test_api_lifespan_validates_workflow_store_readiness(
    monkeypatch,
):
    calls = []

    def validate() -> None:
        calls.append(
            "validated"
        )

    monkeypatch.setattr(
        api,
        "validate_workflow_store_readiness",
        validate,
    )

    with TestClient(
        api.app
    ) as client:

        response = client.get(
            "/health"
        )

        assert (
            response.status_code
            == 200
        )

    assert calls == [
        "validated"
    ]


def test_api_startup_fails_closed_when_workflow_schema_invalid(
    monkeypatch,
):
    def fail_validation() -> None:
        raise RuntimeError(
            "workflow schema incompatible"
        )

    monkeypatch.setattr(
        api,
        "validate_workflow_store_readiness",
        fail_validation,
    )

    with pytest.raises(
        RuntimeError,
        match="workflow schema incompatible",
    ):

        with TestClient(
            api.app
        ):
            pass
