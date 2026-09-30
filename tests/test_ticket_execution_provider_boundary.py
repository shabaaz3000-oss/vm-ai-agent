from __future__ import annotations

import inspect

import pytest

import app.execution as execution


class FakeProvider:

    provider_name = "fake"

    def __init__(
        self,
        *,
        result=None,
        error=None,
    ):
        self.result = (
            {
                "ticket_id":
                    "EXT-123",

                "status":
                    "OPEN",
            }
            if result is None
            else result
        )

        self.error = error
        self.calls = []
        self.closed = False

    def create_ticket(
        self,
        *,
        ticket,
        approval,
    ):
        self.calls.append(
            (
                ticket,
                approval,
            )
        )

        if self.error is not None:
            raise self.error

        return self.result

    def close(
        self,
    ):
        self.closed = True


def test_execution_uses_server_selected_provider(
    monkeypatch,
):

    provider = FakeProvider()

    monkeypatch.setattr(
        execution,
        "build_ticket_provider",
        lambda:
            provider,
    )

    ticket = object()

    approval = {
        "approval_id":
            "APR-TEST",
    }

    result = (
        execution
        ._create_ticket_with_selected_provider(
            ticket=ticket,
            approval=approval,
        )
    )

    assert (
        result["ticket_id"]
        == "EXT-123"
    )

    assert provider.calls == [
        (
            ticket,
            approval,
        )
    ]

    assert provider.closed is True


def test_execution_closes_provider_when_external_action_fails(
    monkeypatch,
):

    provider = FakeProvider(
        error=RuntimeError(
            "external provider failure"
        )
    )

    monkeypatch.setattr(
        execution,
        "build_ticket_provider",
        lambda:
            provider,
    )

    with pytest.raises(
        RuntimeError,
        match="external provider failure",
    ):

        execution \
            ._create_ticket_with_selected_provider(
                ticket=object(),
                approval={
                    "approval_id":
                        "APR-TEST",
                },
            )

    assert provider.closed is True


def test_execution_helper_cannot_accept_provider_selection():

    signature = inspect.signature(
        execution
        ._create_ticket_with_selected_provider
    )

    assert set(
        signature.parameters
    ) == {
        "ticket",
        "approval",
    }

    for forbidden in (
        "provider",
        "provider_name",
        "url",
        "table",
        "instance_url",
        "credentials",
    ):

        assert (
            forbidden
            not in signature.parameters
        )
