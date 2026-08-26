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

    This class is responsible for:

    - API authentication
    - HTTPS communication
    - request timeouts
    - sanitized HTTP errors
    - JSON parsing
    - vulnerability export operations

    It does NOT:

    - calculate authoritative vulnerability risk
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
    # START VULNERABILITY EXPORT
    # -------------------------------------------------


    def start_vulnerability_export(
        self,
        *,
        filters: dict | None = None,
        num_assets: int = 50,
        include_unlicensed: bool = False,
        include_plugin_output: bool = False,
    ) -> str:

        """
        Queue an asynchronous Tenable vulnerability
        export and return its export UUID.

        Tenable supports num_assets values between
        50 and 5000. This client rejects values
        outside that range instead of silently
        changing caller intent.
        """

        if (
            isinstance(
                num_assets,
                bool
            )
            or not isinstance(
                num_assets,
                int
            )
        ):

            raise ValueError(
                "num_assets must be an integer."
            )

        if (
            num_assets < 50
            or num_assets > 5000
        ):

            raise ValueError(
                "num_assets must be between "
                "50 and 5000."
            )

        if (
            filters is not None
            and not isinstance(
                filters,
                dict
            )
        ):

            raise ValueError(
                "Tenable vulnerability export "
                "filters must be a dictionary."
            )

        request_body = {
            "num_assets":
                num_assets,

            "include_unlicensed":
                include_unlicensed,

            "include_plugin_output":
                include_plugin_output,
        }

        if filters is not None:

            request_body[
                "filters"
            ] = filters

        response = self.request_json(
            "POST",
            "/vulns/export",
            json=request_body,
        )

        if not isinstance(
            response,
            dict
        ):

            raise TenableApiError(
                "Tenable vulnerability export "
                "returned an unexpected response."
            )

        export_uuid = (
            response.get(
                "export_uuid"
            )
        )

        if (
            not isinstance(
                export_uuid,
                str
            )
            or not export_uuid.strip()
        ):

            raise TenableApiError(
                "Tenable vulnerability export "
                "did not return an export UUID."
            )

        return export_uuid


    # -------------------------------------------------
    # GET VULNERABILITY EXPORT STATUS
    # -------------------------------------------------


    def get_vulnerability_export_status(
        self,
        export_uuid: str
    ) -> dict:

        export_uuid = (
            export_uuid.strip()
        )

        if not export_uuid:

            raise ValueError(
                "Tenable export UUID "
                "cannot be blank."
            )

        response = self.request_json(
            "GET",
            (
                "/vulns/export/"
                f"{export_uuid}/status"
            ),
        )

        if not isinstance(
            response,
            dict
        ):

            raise TenableApiError(
                "Tenable vulnerability export "
                "status returned an unexpected "
                "response."
            )

        return response


    # -------------------------------------------------
    # GET AVAILABLE CHUNK IDS
    # -------------------------------------------------


    def get_available_vulnerability_chunks(
        self,
        export_uuid: str
    ) -> list[int]:

        status = (
            self
            .get_vulnerability_export_status(
                export_uuid
            )
        )

        chunks = status.get(
            "chunks_available",
            []
        )

        if not isinstance(
            chunks,
            list
        ):

            raise TenableApiError(
                "Tenable vulnerability export "
                "returned invalid chunk metadata."
            )

        validated_chunks = []

        for chunk_id in chunks:

            if (
                isinstance(
                    chunk_id,
                    bool
                )
                or not isinstance(
                    chunk_id,
                    int
                )
                or chunk_id < 0
            ):

                raise TenableApiError(
                    "Tenable vulnerability export "
                    "returned an invalid chunk ID."
                )

            validated_chunks.append(
                chunk_id
            )

        return validated_chunks


    # -------------------------------------------------
    # DOWNLOAD VULNERABILITY CHUNK
    # -------------------------------------------------


    def download_vulnerability_chunk(
        self,
        export_uuid: str,
        chunk_id: int
    ) -> list[dict]:

        export_uuid = (
            export_uuid.strip()
        )

        if not export_uuid:

            raise ValueError(
                "Tenable export UUID "
                "cannot be blank."
            )

        if (
            isinstance(
                chunk_id,
                bool
            )
            or not isinstance(
                chunk_id,
                int
            )
            or chunk_id < 0
        ):

            raise ValueError(
                "Tenable chunk ID must be "
                "a non-negative integer."
            )

        response = self.request_json(
            "GET",
            (
                "/vulns/export/"
                f"{export_uuid}/chunks/"
                f"{chunk_id}"
            ),
        )

        if not isinstance(
            response,
            list
        ):

            raise TenableApiError(
                "Tenable vulnerability chunk "
                "returned an unexpected response."
            )

        for record in response:

            if not isinstance(
                record,
                dict
            ):

                raise TenableApiError(
                    "Tenable vulnerability chunk "
                    "contains an invalid record."
                )

        return response


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