import pytest

from app.models import AssetContext

from app.providers.tenable import (
    TenableProvider,
)

from app.providers.tenable_client import (
    TenableApiError,
)

from app.providers.tenable_sync import (
    TenableExportSync,
)


# -------------------------------------------------
# TEST DATA
# -------------------------------------------------


def make_vulnerability_record():

    return {
        "finding_id":
            "FIND-TENABLE-0001",

        "asset": {
            "uuid":
                "ASSET-UUID-123",
        },

        "plugin": {
            "id":
                12345,

            "name":
                "Critical Remote Code Execution",

            "description":
                (
                    "A remote code execution "
                    "vulnerability was detected."
                ),

            "cve": [
                "CVE-2026-12345"
            ],

            "cvss3_base_score":
                9.8,

            "epss_score":
                94.0,

            "has_patch":
                True,

            "vpr": {
                "on_cisa_kev":
                    True,
            },
        },
    }


def make_asset_record():

    return {
        "id":
            "ASSET-UUID-123",

        "types": [
            "host"
        ],

        "timestamps": {
            "updated_at":
                "2026-08-25T00:00:00Z",
        },
    }


def make_asset_context():

    return AssetContext(
        asset_name=
            "internet-web-01",

        owner=
            "Web Platform Team",

        application=
            "Customer Portal",

        environment=
            "production",

        business_criticality=
            "critical",

        internet_exposed=
            True,

        data_classification=
            "confidential",

        current_controls=[
            "WAF",
            "EDR",
        ],
    )


# -------------------------------------------------
# FAKE TENABLE CLIENT
# -------------------------------------------------


class FakeTenableClient:

    def __init__(
        self,
        vulnerability_statuses=None,
        asset_statuses=None,
    ):

        self.vulnerability_statuses = (
            vulnerability_statuses
            or [
                {
                    "status":
                        "FINISHED",

                    "chunks_available": [
                        0
                    ],
                }
            ]
        )

        self.asset_statuses = (
            asset_statuses
            or [
                {
                    "status":
                        "FINISHED",

                    "chunks_available": [
                        0
                    ],
                }
            ]
        )

        self.vulnerability_status_index = 0

        self.asset_status_index = 0

        self.downloaded_vulnerability_chunks = []

        self.downloaded_asset_chunks = []


    def start_vulnerability_export(
        self,
        **kwargs
    ):

        return (
            "VULN-EXPORT-123"
        )


    def start_asset_export(
        self,
        **kwargs
    ):

        return (
            "ASSET-EXPORT-123"
        )


    def get_vulnerability_export_status(
        self,
        export_uuid
    ):

        index = min(
            self.vulnerability_status_index,

            len(
                self.vulnerability_statuses
            ) - 1
        )

        status = (
            self.vulnerability_statuses[
                index
            ]
        )

        self.vulnerability_status_index += 1

        return status


    def get_asset_export_status(
        self,
        export_uuid
    ):

        index = min(
            self.asset_status_index,

            len(
                self.asset_statuses
            ) - 1
        )

        status = (
            self.asset_statuses[
                index
            ]
        )

        self.asset_status_index += 1

        return status


    def download_vulnerability_chunk(
        self,
        export_uuid,
        chunk_id
    ):

        self.downloaded_vulnerability_chunks.append(
            chunk_id
        )

        return [
            make_vulnerability_record()
        ]


    def download_asset_chunk(
        self,
        export_uuid,
        chunk_id
    ):

        self.downloaded_asset_chunks.append(
            chunk_id
        )

        return [
            make_asset_record()
        ]


# -------------------------------------------------
# BUILD PROVIDER
# -------------------------------------------------


def test_sync_builds_normalized_tenable_provider():

    client = FakeTenableClient()

    sync = TenableExportSync(
        client=client,

        poll_interval_seconds=0,
    )

    provider = sync.build_provider(
        asset_context_by_uuid={
            "ASSET-UUID-123":
                make_asset_context()
        }
    )

    assert isinstance(
        provider,
        TenableProvider
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    threat = provider.get_threat_intel(
        finding.cve
    )

    assert (
        finding.asset_name
        == "internet-web-01"
    )

    assert (
        finding.cvss
        == 9.8
    )

    assert (
        threat.epss
        == pytest.approx(
            0.94
        )
    )

    assert (
        threat.kev
        is True
    )


# -------------------------------------------------
# OUT-OF-ORDER CHUNKS
# -------------------------------------------------


def test_sync_downloads_out_of_order_chunks():

    client = FakeTenableClient(
        vulnerability_statuses=[
            {
                "status":
                    "PROCESSING",

                "chunks_available": [
                    7
                ],
            },

            {
                "status":
                    "FINISHED",

                "chunks_available": [
                    7,
                    2,
                    5,
                ],
            },
        ]
    )

    sync = TenableExportSync(
        client=client,
        poll_interval_seconds=0,
    )

    records = (
        sync.load_vulnerability_records()
    )

    assert (
        client
        .downloaded_vulnerability_chunks
        == [
            7,
            2,
            5,
        ]
    )

    assert len(
        records
    ) == 3


# -------------------------------------------------
# CHUNKS DOWNLOADED ONCE
# -------------------------------------------------


def test_available_chunk_is_not_downloaded_twice():

    client = FakeTenableClient(
        vulnerability_statuses=[
            {
                "status":
                    "PROCESSING",

                "chunks_available": [
                    4
                ],
            },

            {
                "status":
                    "PROCESSING",

                "chunks_available": [
                    4
                ],
            },

            {
                "status":
                    "FINISHED",

                "chunks_available": [
                    4
                ],
            },
        ]
    )

    sync = TenableExportSync(
        client=client,
        poll_interval_seconds=0,
    )

    sync.load_vulnerability_records()

    assert (
        client
        .downloaded_vulnerability_chunks
        == [
            4
        ]
    )


# -------------------------------------------------
# ERROR FAILS CLOSED
# -------------------------------------------------


def test_export_error_fails_closed():

    client = FakeTenableClient(
        vulnerability_statuses=[
            {
                "status":
                    "ERROR",

                "chunks_available":
                    [],
            }
        ]
    )

    sync = TenableExportSync(
        client=client,
        poll_interval_seconds=0,
    )

    with pytest.raises(
        TenableApiError,
        match="ERROR",
    ):

        sync.load_vulnerability_records()


# -------------------------------------------------
# CANCELLED FAILS CLOSED
# -------------------------------------------------


def test_cancelled_export_fails_closed():

    client = FakeTenableClient(
        vulnerability_statuses=[
            {
                "status":
                    "CANCELLED",

                "chunks_available":
                    [],
            }
        ]
    )

    sync = TenableExportSync(
        client=client,
        poll_interval_seconds=0,
    )

    with pytest.raises(
        TenableApiError,
        match="CANCELLED",
    ):

        sync.load_vulnerability_records()


# -------------------------------------------------
# POLLING LIMIT
# -------------------------------------------------


def test_export_polling_limit_fails_closed():

    client = FakeTenableClient(
        vulnerability_statuses=[
            {
                "status":
                    "PROCESSING",

                "chunks_available":
                    [],
            }
        ]
    )

    sync = TenableExportSync(
        client=client,

        poll_interval_seconds=0,

        max_poll_attempts=3,
    )

    with pytest.raises(
        TenableApiError,
        match="polling limit",
    ):

        sync.load_vulnerability_records()

    assert (
        client.vulnerability_status_index
        == 3
    )


# -------------------------------------------------
# INVALID STATUS DATA
# -------------------------------------------------


def test_invalid_chunk_metadata_fails_closed():

    client = FakeTenableClient(
        vulnerability_statuses=[
            {
                "status":
                    "PROCESSING",

                "chunks_available":
                    "not-a-list",
            }
        ]
    )

    sync = TenableExportSync(
        client=client,
        poll_interval_seconds=0,
    )

    with pytest.raises(
        TenableApiError,
        match="chunk metadata",
    ):

        sync.load_vulnerability_records()


# -------------------------------------------------
# INVALID POLLING CONFIGURATION
# -------------------------------------------------


def test_invalid_polling_configuration_is_rejected():

    client = FakeTenableClient()

    with pytest.raises(
        ValueError,
        match="max_poll_attempts",
    ):

        TenableExportSync(
            client=client,
            max_poll_attempts=0,
        )

    with pytest.raises(
        ValueError,
        match="poll_interval_seconds",
    ):

        TenableExportSync(
            client=client,
            poll_interval_seconds=-1,
        )