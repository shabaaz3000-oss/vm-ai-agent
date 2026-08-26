from time import sleep

from app.providers.tenable import TenableProvider

from app.providers.tenable_client import (
    TenableApiClient,
    TenableApiError,
)


# -------------------------------------------------
# TENABLE EXPORT SYNCHRONIZATION
# -------------------------------------------------


class TenableExportSync:

    """
    Orchestrate Tenable VM asynchronous exports.

    Responsibilities:

    - start vulnerability exports
    - start asset exports
    - poll export status
    - download chunks as they become available
    - avoid downloading the same chunk twice
    - fail closed on export errors
    - build a normalized TenableProvider

    This layer does NOT:

    - calculate authoritative risk
    - invoke the AI analyzer
    - approve workflows
    - create remediation tickets
    """


    def __init__(
        self,
        client: TenableApiClient,
        poll_interval_seconds: float = 1.0,
        max_poll_attempts: int = 60,
        sleep_function=sleep,
    ):

        if (
            isinstance(
                poll_interval_seconds,
                bool
            )
            or not isinstance(
                poll_interval_seconds,
                (
                    int,
                    float,
                )
            )
            or poll_interval_seconds < 0
        ):

            raise ValueError(
                "poll_interval_seconds must be "
                "zero or greater."
            )

        if (
            isinstance(
                max_poll_attempts,
                bool
            )
            or not isinstance(
                max_poll_attempts,
                int
            )
            or max_poll_attempts <= 0
        ):

            raise ValueError(
                "max_poll_attempts must be "
                "a positive integer."
            )

        self.client = client

        self.poll_interval_seconds = float(
            poll_interval_seconds
        )

        self.max_poll_attempts = (
            max_poll_attempts
        )

        self.sleep_function = (
            sleep_function
        )


    # -------------------------------------------------
    # STATUS VALIDATION
    # -------------------------------------------------


    @staticmethod
    def _validate_status(
        response,
        export_type: str
    ) -> tuple[str, list[int]]:

        if not isinstance(
            response,
            dict
        ):

            raise TenableApiError(
                f"Tenable {export_type} export "
                "returned invalid status data."
            )

        export_status = response.get(
            "status"
        )

        if (
            not isinstance(
                export_status,
                str
            )
            or not export_status.strip()
        ):

            raise TenableApiError(
                f"Tenable {export_type} export "
                "status is missing."
            )

        chunks = response.get(
            "chunks_available",
            []
        )

        if not isinstance(
            chunks,
            list
        ):

            raise TenableApiError(
                f"Tenable {export_type} export "
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
                    f"Tenable {export_type} export "
                    "returned an invalid chunk ID."
                )

            validated_chunks.append(
                chunk_id
            )

        return (
            export_status
            .strip()
            .upper(),

            validated_chunks,
        )


    # -------------------------------------------------
    # COLLECT EXPORT
    # -------------------------------------------------


    def _collect_export(
        self,
        *,
        export_uuid: str,
        export_type: str,
        status_getter,
        chunk_downloader,
    ) -> list[dict]:

        processed_chunks = set()

        records = []

        for attempt in range(
            self.max_poll_attempts
        ):

            status_response = (
                status_getter(
                    export_uuid
                )
            )

            (
                export_status,
                available_chunks,
            ) = self._validate_status(
                status_response,
                export_type
            )

            # -------------------------------------------------
            # DOWNLOAD NEWLY AVAILABLE CHUNKS
            # -------------------------------------------------

            for chunk_id in available_chunks:

                if (
                    chunk_id
                    in processed_chunks
                ):

                    continue

                chunk_records = (
                    chunk_downloader(
                        export_uuid,
                        chunk_id
                    )
                )

                if not isinstance(
                    chunk_records,
                    list
                ):

                    raise TenableApiError(
                        f"Tenable {export_type} "
                        "chunk returned invalid data."
                    )

                for record in chunk_records:

                    if not isinstance(
                        record,
                        dict
                    ):

                        raise TenableApiError(
                            f"Tenable {export_type} "
                            "chunk contains an "
                            "invalid record."
                        )

                records.extend(
                    chunk_records
                )

                processed_chunks.add(
                    chunk_id
                )

            # -------------------------------------------------
            # SUCCESS
            # -------------------------------------------------

            if (
                export_status
                == "FINISHED"
            ):

                return records

            # -------------------------------------------------
            # TERMINAL FAILURE
            # -------------------------------------------------

            if export_status in {
                "ERROR",
                "CANCELLED",
            }:

                raise TenableApiError(
                    f"Tenable {export_type} export "
                    f"ended with status "
                    f"{export_status}."
                )

            # -------------------------------------------------
            # POLL AGAIN
            # -------------------------------------------------

            if (
                attempt
                < self.max_poll_attempts - 1
                and
                self.poll_interval_seconds > 0
            ):

                self.sleep_function(
                    self.poll_interval_seconds
                )

        raise TenableApiError(
            f"Tenable {export_type} export "
            "did not finish within the "
            "configured polling limit."
        )


    # -------------------------------------------------
    # LOAD VULNERABILITIES
    # -------------------------------------------------


    def load_vulnerability_records(
        self,
        *,
        filters: dict | None = None,
        num_assets: int = 500,
    ) -> list[dict]:

        export_uuid = (
            self.client
            .start_vulnerability_export(
                filters=filters,

                num_assets=
                    num_assets,

                include_unlicensed=
                    False,

                include_plugin_output=
                    False,
            )
        )

        return self._collect_export(
            export_uuid=
                export_uuid,

            export_type=
                "vulnerability",

            status_getter=
                self.client
                .get_vulnerability_export_status,

            chunk_downloader=
                self.client
                .download_vulnerability_chunk,
        )


    # -------------------------------------------------
    # LOAD ASSETS
    # -------------------------------------------------


    def load_asset_records(
        self,
        *,
        filters: dict | None = None,
        chunk_size: int = 5000,
    ) -> list[dict]:

        export_uuid = (
            self.client
            .start_asset_export(
                filters=filters,

                chunk_size=
                    chunk_size,

                include_open_ports=
                    False,
            )
        )

        return self._collect_export(
            export_uuid=
                export_uuid,

            export_type=
                "asset",

            status_getter=
                self.client
                .get_asset_export_status,

            chunk_downloader=
                self.client
                .download_asset_chunk,
        )


    # -------------------------------------------------
    # BUILD PROVIDER
    # -------------------------------------------------


    def build_provider(
        self,
        *,
        asset_context_by_uuid: dict,
        vulnerability_filters: dict | None = None,
        asset_filters: dict | None = None,
        num_assets: int = 500,
        asset_chunk_size: int = 5000,
    ) -> TenableProvider:

        vulnerability_records = (
            self.load_vulnerability_records(
                filters=
                    vulnerability_filters,

                num_assets=
                    num_assets,
            )
        )

        asset_records = (
            self.load_asset_records(
                filters=
                    asset_filters,

                chunk_size=
                    asset_chunk_size,
            )
        )

        return TenableProvider(
            vulnerability_records=
                vulnerability_records,

            asset_records=
                asset_records,

            asset_context_by_uuid=
                asset_context_by_uuid,
        )