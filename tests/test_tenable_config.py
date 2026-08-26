import pytest

from pydantic import ValidationError

from app.providers.tenable_config import (
    TenableConfigurationError,
    TenableSettings,
)


# -------------------------------------------------
# TEST ENVIRONMENT
# -------------------------------------------------


def make_environment():

    return {
        "TENABLE_ACCESS_KEY":
            "test-access-key",

        "TENABLE_SECRET_KEY":
            "test-secret-key",

        "TENABLE_BASE_URL":
            "https://cloud.tenable.com",

        "TENABLE_TIMEOUT_SECONDS":
            "45",

        "TENABLE_POLL_INTERVAL_SECONDS":
            "2",

        "TENABLE_MAX_POLL_ATTEMPTS":
            "100",

        "TENABLE_VULNERABILITY_NUM_ASSETS":
            "750",

        "TENABLE_ASSET_CHUNK_SIZE":
            "8000",
    }


# -------------------------------------------------
# ENVIRONMENT LOADING
# -------------------------------------------------


def test_settings_are_loaded_from_environment():

    settings = (
        TenableSettings.from_env(
            make_environment()
        )
    )

    assert (
        settings
        .access_key
        .get_secret_value()
        == "test-access-key"
    )

    assert (
        settings
        .secret_key
        .get_secret_value()
        == "test-secret-key"
    )

    assert (
        settings.base_url
        == "https://cloud.tenable.com"
    )

    assert (
        settings.timeout_seconds
        == 45
    )

    assert (
        settings.poll_interval_seconds
        == 2
    )

    assert (
        settings.max_poll_attempts
        == 100
    )

    assert (
        settings.vulnerability_num_assets
        == 750
    )

    assert (
        settings.asset_chunk_size
        == 8000
    )


# -------------------------------------------------
# DEFAULTS
# -------------------------------------------------


def test_safe_defaults_are_used():

    settings = (
        TenableSettings.from_env(
            {
                "TENABLE_ACCESS_KEY":
                    "access",

                "TENABLE_SECRET_KEY":
                    "secret",
            }
        )
    )

    assert (
        settings.base_url
        == "https://cloud.tenable.com"
    )

    assert (
        settings.timeout_seconds
        == 30
    )

    assert (
        settings.poll_interval_seconds
        == 1
    )

    assert (
        settings.max_poll_attempts
        == 60
    )

    assert (
        settings.vulnerability_num_assets
        == 500
    )

    assert (
        settings.asset_chunk_size
        == 5000
    )


# -------------------------------------------------
# MISSING ACCESS KEY
# -------------------------------------------------


def test_missing_access_key_fails_closed():

    environment = (
        make_environment()
    )

    environment.pop(
        "TENABLE_ACCESS_KEY"
    )

    with pytest.raises(
        TenableConfigurationError,
        match="access key",
    ):

        TenableSettings.from_env(
            environment
        )


# -------------------------------------------------
# MISSING SECRET KEY
# -------------------------------------------------


def test_missing_secret_key_fails_closed():

    environment = (
        make_environment()
    )

    environment.pop(
        "TENABLE_SECRET_KEY"
    )

    with pytest.raises(
        TenableConfigurationError,
        match="secret key",
    ):

        TenableSettings.from_env(
            environment
        )


# -------------------------------------------------
# HTTPS REQUIRED
# -------------------------------------------------


def test_insecure_base_url_is_rejected():

    environment = (
        make_environment()
    )

    environment[
        "TENABLE_BASE_URL"
    ] = (
        "http://cloud.tenable.com"
    )

    with pytest.raises(
        ValidationError,
        match="HTTPS",
    ):

        TenableSettings.from_env(
            environment
        )


# -------------------------------------------------
# SECRETS MUST BE REDACTED
# -------------------------------------------------


def test_secrets_are_not_exposed_by_model_output():

    access_key = (
        "VERY-SENSITIVE-ACCESS-KEY"
    )

    secret_key = (
        "VERY-SENSITIVE-SECRET-KEY"
    )

    settings = TenableSettings(
        access_key=
            access_key,

        secret_key=
            secret_key,
    )

    outputs = [
        str(
            settings
        ),

        repr(
            settings
        ),

        settings.model_dump_json(),
    ]

    for output in outputs:

        assert (
            access_key
            not in output
        )

        assert (
            secret_key
            not in output
        )


# -------------------------------------------------
# INVALID EXPORT LIMITS
# -------------------------------------------------


@pytest.mark.parametrize(
    (
        "field_name",
        "value",
    ),
    [
        (
            "timeout_seconds",
            0,
        ),

        (
            "poll_interval_seconds",
            -1,
        ),

        (
            "max_poll_attempts",
            0,
        ),

        (
            "vulnerability_num_assets",
            49,
        ),

        (
            "vulnerability_num_assets",
            5001,
        ),

        (
            "asset_chunk_size",
            99,
        ),

        (
            "asset_chunk_size",
            10001,
        ),
    ],
)
def test_invalid_tuning_values_are_rejected(
    field_name,
    value
):

    settings = {
        "access_key":
            "access",

        "secret_key":
            "secret",

        field_name:
            value,
    }

    with pytest.raises(
        ValidationError
    ):

        TenableSettings(
            **settings
        )


# -------------------------------------------------
# SETTINGS ARE IMMUTABLE
# -------------------------------------------------


def test_settings_cannot_be_modified_after_creation():

    settings = TenableSettings(
        access_key="access",
        secret_key="secret",
    )

    with pytest.raises(
        ValidationError
    ):

        settings.base_url = (
            "https://attacker.example"
        )