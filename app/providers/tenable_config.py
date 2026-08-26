import os

from collections.abc import Mapping

from dotenv import load_dotenv

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
)


# -------------------------------------------------
# CONFIGURATION ERROR
# -------------------------------------------------


class TenableConfigurationError(
    RuntimeError
):

    """
    Sanitized Tenable configuration error.

    Configuration errors deliberately avoid
    including secret values.
    """

    pass


# -------------------------------------------------
# TENABLE SETTINGS
# -------------------------------------------------


class TenableSettings(
    BaseModel
):

    """
    Validated configuration for the Tenable
    integration.

    Secrets use Pydantic SecretStr so accidental
    repr(), str(), and JSON serialization do not
    expose their raw values.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    access_key: SecretStr

    secret_key: SecretStr

    base_url: str = (
        "https://cloud.tenable.com"
    )

    timeout_seconds: float = Field(
        default=30.0,
        gt=0,
    )

    poll_interval_seconds: float = Field(
        default=1.0,
        ge=0,
    )

    max_poll_attempts: int = Field(
        default=60,
        gt=0,
    )

    vulnerability_num_assets: int = Field(
        default=500,
        ge=50,
        le=5000,
    )

    asset_chunk_size: int = Field(
        default=5000,
        ge=100,
        le=10000,
    )


    # -------------------------------------------------
    # SECRET VALIDATION
    # -------------------------------------------------


    @field_validator(
        "access_key",
        "secret_key",
        mode="before",
    )
    @classmethod
    def validate_secret(
        cls,
        value
    ):

        if not isinstance(
            value,
            str
        ):

            raise ValueError(
                "Tenable credential must "
                "be a string."
            )

        value = value.strip()

        if not value:

            raise ValueError(
                "Tenable credential "
                "cannot be blank."
            )

        return value


    # -------------------------------------------------
    # BASE URL VALIDATION
    # -------------------------------------------------


    @field_validator(
        "base_url"
    )
    @classmethod
    def validate_base_url(
        cls,
        value: str
    ) -> str:

        value = value.strip()

        if not value.startswith(
            "https://"
        ):

            raise ValueError(
                "Tenable base URL "
                "must use HTTPS."
            )

        return value.rstrip(
            "/"
        )


    # -------------------------------------------------
    # LOAD FROM ENVIRONMENT
    # -------------------------------------------------


    @classmethod
    def from_env(
        cls,
        environ: Mapping[
            str,
            str
        ] | None = None,
    ):

        """
        Build Tenable settings from environment
        variables.

        A mapping can be injected during testing
        so tests never depend on real credentials.
        """

        if environ is None:

            load_dotenv()

            source = os.environ

        else:

            source = environ

        access_key = source.get(
            "TENABLE_ACCESS_KEY"
        )

        secret_key = source.get(
            "TENABLE_SECRET_KEY"
        )

        if (
            access_key is None
            or not access_key.strip()
        ):

            raise TenableConfigurationError(
                "Tenable access key "
                "is not configured."
            )

        if (
            secret_key is None
            or not secret_key.strip()
        ):

            raise TenableConfigurationError(
                "Tenable secret key "
                "is not configured."
            )

        return cls(
            access_key=
                access_key,

            secret_key=
                secret_key,

            base_url=source.get(
                "TENABLE_BASE_URL",
                "https://cloud.tenable.com",
            ),

            timeout_seconds=source.get(
                "TENABLE_TIMEOUT_SECONDS",
                "30",
            ),

            poll_interval_seconds=source.get(
                "TENABLE_POLL_INTERVAL_SECONDS",
                "1",
            ),

            max_poll_attempts=source.get(
                "TENABLE_MAX_POLL_ATTEMPTS",
                "60",
            ),

            vulnerability_num_assets=source.get(
                "TENABLE_VULNERABILITY_NUM_ASSETS",
                "500",
            ),

            asset_chunk_size=source.get(
                "TENABLE_ASSET_CHUNK_SIZE",
                "5000",
            ),
        )