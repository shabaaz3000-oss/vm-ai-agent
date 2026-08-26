from pydantic import ValidationError

from app.providers.tenable_client import (
    TenableApiError,
)

from app.providers.tenable_config import (
    TenableConfigurationError,
    TenableSettings,
)

from app.providers.tenable_connectivity import (
    check_tenable_connectivity_from_settings,
)


# -------------------------------------------------
# RUN CONNECTIVITY CHECK
# -------------------------------------------------


def run_connectivity_check() -> int:

    """
    Perform a read-only authenticated Tenable
    connectivity check.

    This command deliberately does not:

    - export vulnerability data
    - export asset data
    - invoke AI
    - calculate risk
    - approve workflows
    - create tickets
    """

    settings = (
        TenableSettings.from_env()
    )

    result = (
        check_tenable_connectivity_from_settings(
            settings
        )
    )

    print(
        "TENABLE CONNECTIVITY CHECK"
    )

    print(
        "--------------------------"
    )

    print(
        f"Connected: {result.connected}"
    )

    print(
        f"Endpoint: {result.endpoint}"
    )

    print(
        f"Result: {result.message}"
    )

    return 0


# -------------------------------------------------
# SAFE ENTRY POINT
# -------------------------------------------------


def main() -> int:

    try:

        return run_connectivity_check()

    except TenableConfigurationError:

        print(
            "TENABLE CONNECTIVITY CHECK FAILED"
        )

        print(
            "Tenable credentials are not "
            "configured."
        )

        return 2

    except ValidationError:

        print(
            "TENABLE CONNECTIVITY CHECK FAILED"
        )

        print(
            "Tenable configuration validation "
            "failed."
        )

        return 2

    except TenableApiError as error:

        print(
            "TENABLE CONNECTIVITY CHECK FAILED"
        )

        print(
            str(
                error
            )
        )

        return 3

    except Exception:

        # Deliberately do not print the exception.
        #
        # Unexpected exceptions may contain internal
        # implementation details or sensitive data.

        print(
            "TENABLE CONNECTIVITY CHECK FAILED"
        )

        print(
            "An unexpected error occurred."
        )

        return 4


# -------------------------------------------------
# COMMAND-LINE ENTRY POINT
# -------------------------------------------------


if __name__ == "__main__":

    raise SystemExit(
        main()
    )