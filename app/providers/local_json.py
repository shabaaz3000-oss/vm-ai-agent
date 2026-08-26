import json

from pathlib import Path

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.providers.base import VulnerabilityProvider


# -------------------------------------------------
# LOCAL JSON VULNERABILITY PROVIDER
# -------------------------------------------------


class LocalJsonProvider(VulnerabilityProvider):

    """
    Vulnerability provider backed by local JSON files.

    This provider is intended for:

    - local development
    - testing
    - demonstrations
    - offline portfolio use

    The provider retrieves and normalizes security
    data only.

    It does NOT:

    - calculate risk
    - call the AI analyzer
    - approve workflows
    - create tickets
    - execute remediation actions
    """

    def __init__(
        self,
        finding_path: str | Path = "data/finding.json",
        asset_path: str | Path = "data/asset.json",
        threat_intel_path: str | Path = "data/threat_intel.json",
    ):

        self.finding_path = Path(
            finding_path
        )

        self.asset_path = Path(
            asset_path
        )

        self.threat_intel_path = Path(
            threat_intel_path
        )


    # -------------------------------------------------
    # INTERNAL JSON LOADER
    # -------------------------------------------------


    @staticmethod
    def _load_json(
        path: Path
    ) -> dict:

        with path.open(
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(
                file
            )

        if not isinstance(
            data,
            dict
        ):

            raise ValueError(
                "Provider JSON data must contain "
                "a JSON object."
            )

        return data


    # -------------------------------------------------
    # FINDING
    # -------------------------------------------------


    def get_finding(
        self,
        finding_id: str
    ) -> VulnerabilityFinding:

        data = self._load_json(
            self.finding_path
        )

        finding = (
            VulnerabilityFinding
            .model_validate(
                data
            )
        )

        if (
            finding.finding_id
            != finding_id
        ):

            raise KeyError(
                "Requested finding does not match "
                f"provider data: {finding_id}"
            )

        return finding


    # -------------------------------------------------
    # ASSET CONTEXT
    # -------------------------------------------------


    def get_asset_context(
        self,
        asset_name: str
    ) -> AssetContext:

        data = self._load_json(
            self.asset_path
        )

        asset = (
            AssetContext
            .model_validate(
                data
            )
        )

        if (
            asset.asset_name
            != asset_name
        ):

            raise KeyError(
                "Requested asset does not match "
                f"provider data: {asset_name}"
            )

        return asset


    # -------------------------------------------------
    # THREAT INTELLIGENCE
    # -------------------------------------------------


    def get_threat_intel(
        self,
        cve: str
    ) -> ThreatIntel:

        data = self._load_json(
            self.threat_intel_path
        )

        threat = (
            ThreatIntel
            .model_validate(
                data
            )
        )

        if (
            threat.cve
            != cve
        ):

            raise KeyError(
                "Requested CVE does not match "
                f"provider data: {cve}"
            )

        return threat