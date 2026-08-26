import pytest

import tenable_check

from app.providers.tenable_client import (
    TenableApiError,
)

from app.providers.tenable_config import (
    TenableConfigurationError,
    TenableSettings,
)

from app.providers.tenable_connectivity import (
    CONNECTIVITY_ENDPOINT,
    TenableConnectivityResult,
)


# -------------------------------------------------
# SUCCESS
# -------------------------------------------------


def test_cli_reports_success(
    monkeypatch,
    capsys,
):

    fake_settings = object()

    monkeypatch.setattr(
        tenable_check.TenableSettings,
        "from_env",
        lambda:
            fake_settings,
    )

    monkeypatch.setattr(
        tenable_check,
        "check_tenable_connectivity_from_settings",
        lambda settings:
            TenableConnectivityResult(
                connected=True,

                endpoint=
                    CONNECTIVITY_ENDPOINT,

                message=(
                    "Authenticated Tenable "
                    "connectivity confirmed."
                ),
            ),
    )

    exit_code = (
        tenable_check.main()
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 0

    assert (
        "TENABLE CONNECTIVITY CHECK"
        in output
    )

    assert (
        "Connected: True"
        in output
    )

    assert (
        "Authenticated Tenable "
        "connectivity confirmed."
        in output
    )


# -------------------------------------------------
# MISSING CONFIGURATION
# -------------------------------------------------


def test_cli_handles_missing_configuration_safely(
    monkeypatch,
    capsys,
):

    monkeypatch.setattr(
        tenable_check.TenableSettings,
        "from_env",
        lambda:
            (
                _raise(
                    TenableConfigurationError(
                        "Tenable access key "
                        "is not configured."
                    )
                )
            ),
    )

    exit_code = (
        tenable_check.main()
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 2

    assert (
        "FAILED"
        in output
    )

    assert (
        "credentials are not configured"
        in output
    )


# -------------------------------------------------
# VALIDATION FAILURE
# -------------------------------------------------


def test_cli_handles_validation_error_safely(
    monkeypatch,
    capsys,
):

    try:

        TenableSettings(
            access_key="",
            secret_key="secret",
        )

    except Exception as error:

        validation_error = error

    monkeypatch.setattr(
        tenable_check.TenableSettings,
        "from_env",
        lambda:
            _raise(
                validation_error
            ),
    )

    exit_code = (
        tenable_check.main()
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 2

    assert (
        "configuration validation "
        "failed"
        in output
    )

    assert (
        "secret"
        not in output
    )


# -------------------------------------------------
# API FAILURE
# -------------------------------------------------


def test_cli_reports_sanitized_api_failure(
    monkeypatch,
    capsys,
):

    fake_settings = object()

    monkeypatch.setattr(
        tenable_check.TenableSettings,
        "from_env",
        lambda:
            fake_settings,
    )

    monkeypatch.setattr(
        tenable_check,
        "check_tenable_connectivity_from_settings",
        lambda settings:
            _raise(
                TenableApiError(
                    "Tenable API request failed "
                    "with HTTP 401."
                )
            ),
    )

    exit_code = (
        tenable_check.main()
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 3

    assert (
        "401"
        in output
    )


# -------------------------------------------------
# UNEXPECTED FAILURE
# -------------------------------------------------


def test_cli_hides_unexpected_exception_details(
    monkeypatch,
    capsys,
):

    sensitive_value = (
        "DO-NOT-PRINT-THIS-SECRET"
    )

    monkeypatch.setattr(
        tenable_check.TenableSettings,
        "from_env",
        lambda:
            _raise(
                RuntimeError(
                    sensitive_value
                )
            ),
    )

    exit_code = (
        tenable_check.main()
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 4

    assert (
        "unexpected error"
        in output
    )

    assert (
        sensitive_value
        not in output
    )


# -------------------------------------------------
# TEST HELPER
# -------------------------------------------------


def _raise(
    error
):

    raise error