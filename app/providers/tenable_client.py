import httpx


# -------------------------------------------------
# TENABLE API ERROR
# -------------------------------------------------


class TenableApiError(
    RuntimeError
):

    """
    Sanitized Tenable API error.

    API keys and remote response bodies are
    deliberately excluded from error messages.
    """

    pass


# -------------------------------------------------
# TENABLE API CLIENT
# -------------------------------------------------


class TenableApiClient:

    """
    Minimal secure HTTP client for Tenable
    Vulnerability Management.

    This class is responsible only for:

    - API authentication
    - HTTPS communication
    - timeouts
    - sanitized HTTP error handling
    - JSON response parsing

    It does NOT:

    - calculate vulnerability risk
    - invoke the AI analyzer
    - approve workflows
    - create remediation tickets
    """

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        base_url: str = (
            "https://cloud.tenable.com"
        ),
        timeout_seconds: float = 30.0,
        transport=None,
    ):

        access_key = (
            access_key.strip()
        )

        secret_key = (
            secret_key.strip()
        )

        base_url = (
            base_url.rstrip("/")
        )

        if not access_key:

            raise ValueError(
                "Tenable access key "
                "cannot be blank."
            )

        if not secret_key:

            raise ValueError(
                "Tenable secret key "
                "cannot be blank."
            )

        if not base_url.startswith(
            "https://"
        ):

            raise ValueError(
                "Tenable API base URL "
                "must use HTTPS."
            )

        if timeout_seconds <= 0:

            raise ValueError(
                "Tenable API timeout "
                "must be greater than zero."
            )

        self.base_url = (
            base_url
        )

        self.timeout_seconds = (
            timeout_seconds
        )

        self._client = httpx.Client(
            base_url=self.base_url,

            timeout=self.timeout_seconds,

            transport=transport,

            headers={
                "Accept":
                    "application/json",

                "X-ApiKeys": (
                    f"accessKey={access_key}; "
                    f"secretKey={secret_key};"
                ),
            },
        )


    # -------------------------------------------------
    # REQUEST JSON
    # -------------------------------------------------


    def request_json(
        self,
        method: str,
        path: str,
        *,
        params=None,
        json=None,
    ):

        try:

            response = (
                self._client.request(
                    method=method,
                    url=path,
                    params=params,
                    json=json,
                )
            )

        except httpx.HTTPError as error:

            raise TenableApiError(
                "Tenable API request failed "
                "before a valid response "
                "was received."
            ) from error

        if response.status_code >= 400:

            raise TenableApiError(
                "Tenable API request failed "
                f"with HTTP "
                f"{response.status_code}."
            )

        if response.status_code == 204:

            return {}

        try:

            return response.json()

        except ValueError as error:

            raise TenableApiError(
                "Tenable API returned an "
                "invalid JSON response."
            ) from error


    # -------------------------------------------------
    # CLOSE
    # -------------------------------------------------


    def close(
        self
    ) -> None:

        self._client.close()


    # -------------------------------------------------
    # CONTEXT MANAGER
    # -------------------------------------------------


    def __enter__(
        self
    ):

        return self


    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):

        self.close()