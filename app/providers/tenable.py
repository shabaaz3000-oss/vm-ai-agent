from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.providers.base import VulnerabilityProvider


# -------------------------------------------------
# TENABLE VULNERABILITY PROVIDER
# -------------------------------------------------


class TenableProvider(
    VulnerabilityProvider
):

    """
    Normalize Tenable Vulnerability Management
    export records into the application's trusted
    Pydantic models.

    Raw Tenable data is treated as untrusted input.

    Asset correlation uses the Tenable asset UUID.

    Enterprise business context is supplied
    separately because Tenable is not authoritative
    for fields such as:

    - application owner
    - business criticality
    - environment
    - data classification
    - compensating controls
    """

    def __init__(
        self,
        vulnerability_records: list[dict],
        asset_records: list[dict],
        asset_context_by_uuid: dict,
    ):

        self.vulnerability_records = (
            self._validate_record_list(
                vulnerability_records,
                "vulnerability"
            )
        )

        self.asset_records = (
            self._validate_record_list(
                asset_records,
                "asset"
            )
        )

        self._vulnerabilities_by_id = {}

        for record in self.vulnerability_records:

            finding_id = record.get(
                "finding_id"
            )

            if (
                not isinstance(
                    finding_id,
                    str
                )
                or not finding_id.strip()
            ):

                raise ValueError(
                    "Tenable vulnerability record "
                    "is missing finding_id."
                )

            if (
                finding_id
                in self._vulnerabilities_by_id
            ):

                raise ValueError(
                    "Duplicate Tenable finding_id "
                    f"detected: {finding_id}"
                )

            self._vulnerabilities_by_id[
                finding_id
            ] = record

        self._assets_by_uuid = {}

        for record in self.asset_records:

            asset_uuid = record.get(
                "id"
            )

            if (
                not isinstance(
                    asset_uuid,
                    str
                )
                or not asset_uuid.strip()
            ):

                raise ValueError(
                    "Tenable asset record "
                    "is missing id."
                )

            if (
                asset_uuid
                in self._assets_by_uuid
            ):

                raise ValueError(
                    "Duplicate Tenable asset UUID "
                    f"detected: {asset_uuid}"
                )

            self._assets_by_uuid[
                asset_uuid
            ] = record

        if not isinstance(
            asset_context_by_uuid,
            dict
        ):

            raise ValueError(
                "asset_context_by_uuid must "
                "be a dictionary."
            )

        self._asset_context_by_uuid = {}

        for (
            asset_uuid,
            context
        ) in asset_context_by_uuid.items():

            if (
                not isinstance(
                    asset_uuid,
                    str
                )
                or not asset_uuid.strip()
            ):

                raise ValueError(
                    "Asset enrichment UUID "
                    "cannot be blank."
                )

            normalized_context = (
                context
                if isinstance(
                    context,
                    AssetContext
                )
                else AssetContext.model_validate(
                    context
                )
            )

            self._asset_context_by_uuid[
                asset_uuid
            ] = normalized_context


    # -------------------------------------------------
    # RAW RECORD VALIDATION
    # -------------------------------------------------


    @staticmethod
    def _validate_record_list(
        records,
        record_type: str
    ) -> list[dict]:

        if not isinstance(
            records,
            list
        ):

            raise ValueError(
                f"Tenable {record_type} records "
                "must be a list."
            )

        for record in records:

            if not isinstance(
                record,
                dict
            ):

                raise ValueError(
                    f"Tenable {record_type} record "
                    "must be a dictionary."
                )

        return records


    # -------------------------------------------------
    # FIND RAW VULNERABILITY
    # -------------------------------------------------


    def _get_vulnerability_record(
        self,
        finding_id: str
    ) -> dict:

        record = (
            self._vulnerabilities_by_id.get(
                finding_id
            )
        )

        if record is None:

            raise KeyError(
                "Tenable finding not found: "
                f"{finding_id}"
            )

        return record


    # -------------------------------------------------
    # ASSET UUID CORRELATION
    # -------------------------------------------------


    @staticmethod
    def _get_finding_asset_uuid(
        record: dict
    ) -> str:

        asset = record.get(
            "asset"
        )

        if not isinstance(
            asset,
            dict
        ):

            raise ValueError(
                "Tenable finding is missing "
                "its asset object."
            )

        legacy_uuid = asset.get(
            "uuid"
        )

        current_id = asset.get(
            "id"
        )

        if (
            legacy_uuid
            and current_id
            and legacy_uuid != current_id
        ):

            raise ValueError(
                "Tenable finding contains "
                "conflicting asset identifiers."
            )

        asset_uuid = (
            legacy_uuid
            or current_id
        )

        if (
            not isinstance(
                asset_uuid,
                str
            )
            or not asset_uuid.strip()
        ):

            raise ValueError(
                "Tenable finding is missing "
                "its asset UUID."
            )

        return asset_uuid


    # -------------------------------------------------
    # CURRENT ASSET
    # -------------------------------------------------


    def _get_current_asset(
        self,
        asset_uuid: str
    ) -> dict:

        asset = (
            self._assets_by_uuid.get(
                asset_uuid
            )
        )

        if asset is None:

            raise KeyError(
                "Current Tenable asset not found "
                f"for UUID: {asset_uuid}"
            )

        timestamps = asset.get(
            "timestamps",
            {}
        )

        if timestamps is None:

            timestamps = {}

        if not isinstance(
            timestamps,
            dict
        ):

            raise ValueError(
                "Tenable asset timestamps "
                "must be an object."
            )

        if (
            timestamps.get(
                "deleted_at"
            )
            or timestamps.get(
                "terminated_at"
            )
        ):

            raise ValueError(
                "Tenable asset is deleted or "
                "terminated and cannot be used "
                "for a new workflow."
            )

        return asset


    # -------------------------------------------------
    # ENTERPRISE ASSET CONTEXT
    # -------------------------------------------------


    def _get_context_by_uuid(
        self,
        asset_uuid: str
    ) -> AssetContext:

        context = (
            self._asset_context_by_uuid.get(
                asset_uuid
            )
        )

        if context is None:

            raise KeyError(
                "Enterprise asset context "
                "not found for Tenable asset "
                f"UUID: {asset_uuid}"
            )

        return context


    # -------------------------------------------------
    # PLUGIN OBJECT
    # -------------------------------------------------


    @staticmethod
    def _get_plugin(
        record: dict
    ) -> dict:

        plugin = record.get(
            "plugin"
        )

        if not isinstance(
            plugin,
            dict
        ):

            raise ValueError(
                "Tenable finding is missing "
                "its plugin object."
            )

        return plugin


    # -------------------------------------------------
    # SINGLE CVE
    # -------------------------------------------------


    @staticmethod
    def _get_single_cve(
        plugin: dict
    ) -> str:

        cves = plugin.get(
            "cve"
        )

        if isinstance(
            cves,
            str
        ):

            cves = [
                cves
            ]

        if not isinstance(
            cves,
            list
        ):

            raise ValueError(
                "Tenable plugin CVE data "
                "must be a list."
            )

        normalized = []

        for cve in cves:

            if (
                not isinstance(
                    cve,
                    str
                )
                or not cve.strip()
            ):

                raise ValueError(
                    "Tenable plugin contains "
                    "an invalid CVE."
                )

            normalized.append(
                cve.strip()
            )

        if len(
            normalized
        ) != 1:

            raise ValueError(
                "This workflow currently requires "
                "exactly one CVE per Tenable "
                "finding."
            )

        return normalized[0]


    # -------------------------------------------------
    # CVSS NORMALIZATION
    # -------------------------------------------------


    @staticmethod
    def _get_cvss(
        plugin: dict
    ) -> float:

        candidates = [
            plugin.get(
                "cvss4_base_score"
            ),

            plugin.get(
                "cvss3_base_score"
            ),

            plugin.get(
                "cvss_base_score"
            ),
        ]

        for value in candidates:

            if value is None:

                continue

            if (
                isinstance(
                    value,
                    bool
                )
                or not isinstance(
                    value,
                    (
                        int,
                        float,
                    )
                )
            ):

                raise ValueError(
                    "Tenable CVSS score "
                    "must be numeric."
                )

            score = float(
                value
            )

            if (
                score < 0
                or score > 10
            ):

                raise ValueError(
                    "Tenable CVSS score "
                    "must be between 0 and 10."
                )

            return score

        raise ValueError(
            "Tenable finding does not contain "
            "a supported CVSS base score."
        )


    # -------------------------------------------------
    # PATCH AVAILABILITY
    # -------------------------------------------------


    @staticmethod
    def _get_patch_available(
        record: dict,
        plugin: dict
    ) -> bool:

        value = plugin.get(
            "has_patch"
        )

        if value is None:

            value = record.get(
                "has_patch"
            )

        if not isinstance(
            value,
            bool
        ):

            raise ValueError(
                "Tenable finding does not contain "
                "explicit patch availability."
            )

        return value


    # -------------------------------------------------
    # EPSS NORMALIZATION
    # -------------------------------------------------


    @staticmethod
    def _get_epss(
        plugin: dict
    ) -> float | None:

        value = plugin.get(
            "epss_score"
        )

        if value is None:

            return None

        if (
            isinstance(
                value,
                bool
            )
            or not isinstance(
                value,
                (
                    int,
                    float,
                )
            )
        ):

            raise ValueError(
                "Tenable EPSS score "
                "must be numeric."
            )

        percentage = float(
            value
        )

        if (
            percentage < 0
            or percentage > 100
        ):

            raise ValueError(
                "Tenable EPSS score "
                "must be between 0 and 100."
            )

        return (
            percentage
            / 100
        )


    # -------------------------------------------------
    # CISA KEV
    # -------------------------------------------------


    @staticmethod
    def _get_kev(
        plugin: dict
    ) -> bool:

        vpr = plugin.get(
            "vpr"
        )

        if isinstance(
            vpr,
            dict
        ):

            value = vpr.get(
                "on_cisa_kev"
            )

            if isinstance(
                value,
                bool
            ):

                return value

        # Compatibility with exports created before
        # Tenable's VPR v2 transition completed.

        vpr_v2 = plugin.get(
            "vpr_v2"
        )

        if isinstance(
            vpr_v2,
            dict
        ):

            value = vpr_v2.get(
                "on_cisa_kev"
            )

            if isinstance(
                value,
                bool
            ):

                return value

        # Our RiskResult treats KEV as an
        # authoritative deterministic factor.
        #
        # Missing KEV data must therefore NOT
        # silently become False.

        raise ValueError(
            "Tenable finding does not contain "
            "explicit CISA KEV status."
        )


    # -------------------------------------------------
    # FINDING
    # -------------------------------------------------


    def get_finding(
        self,
        finding_id: str
    ) -> VulnerabilityFinding:

        record = (
            self._get_vulnerability_record(
                finding_id
            )
        )

        asset_uuid = (
            self._get_finding_asset_uuid(
                record
            )
        )

        # Verify the finding still maps to a
        # current Tenable asset.

        self._get_current_asset(
            asset_uuid
        )

        context = (
            self._get_context_by_uuid(
                asset_uuid
            )
        )

        plugin = (
            self._get_plugin(
                record
            )
        )

        cve = (
            self._get_single_cve(
                plugin
            )
        )

        name = plugin.get(
            "name"
        )

        if (
            not isinstance(
                name,
                str
            )
            or not name.strip()
        ):

            raise ValueError(
                "Tenable plugin name "
                "cannot be blank."
            )

        description = plugin.get(
            "description"
        )

        if (
            not isinstance(
                description,
                str
            )
            or not description.strip()
        ):

            raise ValueError(
                "Tenable plugin description "
                "cannot be blank."
            )

        return VulnerabilityFinding(
            finding_id=
                finding_id,

            asset_name=
                context.asset_name,

            cve=
                cve,

            title=
                name.strip(),

            description=
                description.strip(),

            cvss=
                self._get_cvss(
                    plugin
                ),

            patch_available=
                self._get_patch_available(
                    record,
                    plugin
                ),
        )


    # -------------------------------------------------
    # ASSET CONTEXT
    # -------------------------------------------------


    def get_asset_context(
        self,
        asset_name: str
    ) -> AssetContext:

        matches = []

        for (
            asset_uuid,
            context
        ) in (
            self
            ._asset_context_by_uuid
            .items()
        ):

            if (
                context.asset_name
                == asset_name
            ):

                matches.append(
                    (
                        asset_uuid,
                        context,
                    )
                )

        if not matches:

            raise KeyError(
                "Enterprise asset context "
                f"not found: {asset_name}"
            )

        if len(
            matches
        ) != 1:

            raise ValueError(
                "Asset name maps to multiple "
                "Tenable asset UUIDs."
            )

        (
            asset_uuid,
            context,
        ) = matches[0]

        self._get_current_asset(
            asset_uuid
        )

        return context


    # -------------------------------------------------
    # THREAT INTELLIGENCE
    # -------------------------------------------------


    def get_threat_intel(
        self,
        cve: str
    ) -> ThreatIntel:

        epss_values = []
        kev_values = []

        for record in (
            self.vulnerability_records
        ):

            plugin = (
                self._get_plugin(
                    record
                )
            )

            record_cve = (
                self._get_single_cve(
                    plugin
                )
            )

            if (
                record_cve
                != cve
            ):

                continue

            epss = (
                self._get_epss(
                    plugin
                )
            )

            if epss is not None:

                epss_values.append(
                    epss
                )

            kev_values.append(
                self._get_kev(
                    plugin
                )
            )

        if not kev_values:

            raise KeyError(
                "Tenable threat intelligence "
                f"not found for CVE: {cve}"
            )

        # CVE-level metadata should normally agree
        # across findings. If stale finding records
        # disagree, use the conservative values:
        #
        # - highest EPSS
        # - KEV True if any record reports True

        epss = (
            max(
                epss_values
            )
            if epss_values
            else None
        )

        kev = any(
            kev_values
        )

        return ThreatIntel(
            cve=
                cve,

            epss=
                epss,

            kev=
                kev,

            data_source=(
                "Tenable Vulnerability Management"
            ),
        )