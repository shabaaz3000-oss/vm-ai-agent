from abc import ABC
from abc import abstractmethod

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding


# -------------------------------------------------
# VULNERABILITY PROVIDER CONTRACT
# -------------------------------------------------


class VulnerabilityProvider(ABC):

    """
    Base contract for vulnerability data providers.

    Providers are responsible only for retrieving
    and normalizing security data.

    Providers do NOT:
    - calculate authoritative risk
    - call the AI analyzer
    - approve workflows
    - create tickets
    - perform external remediation actions
    """

    @abstractmethod
    def get_finding(
        self,
        finding_id: str
    ) -> VulnerabilityFinding:

        """
        Retrieve and normalize one vulnerability
        finding.
        """

        raise NotImplementedError


    @abstractmethod
    def get_asset_context(
        self,
        asset_name: str
    ) -> AssetContext:

        """
        Retrieve and normalize context for the
        affected asset.
        """

        raise NotImplementedError


    @abstractmethod
    def get_threat_intel(
        self,
        cve: str
    ) -> ThreatIntel:

        """
        Retrieve and normalize threat intelligence
        for the vulnerability.
        """

        raise NotImplementedError