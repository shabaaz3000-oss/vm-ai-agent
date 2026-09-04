from app.models import AssetContext
from app.models import RiskResult
from app.models import VulnerabilityFinding


def build_retrieval_query(
    finding: VulnerabilityFinding,
    asset: AssetContext,
    risk: RiskResult,
) -> str:

    """
    Build a constrained retrieval query for
    vulnerability-management reference material.

    Free-form vulnerability description text is
    deliberately excluded from the initial RAG
    retrieval query because it is untrusted and
    may contain retrieval-manipulation content.
    """

    patch_status = (
        "patch available"
        if finding.patch_available
        else "patch unavailable"
    )

    exposure = (
        "internet exposed"
        if asset.internet_exposed
        else "not internet exposed"
    )

    query_parts = [
        "enterprise vulnerability remediation",
        "compensating controls",
        "remediation validation",
        f"CVE {finding.cve}",
        patch_status,
        f"{asset.environment} environment",
        f"{asset.business_criticality} business criticality",
        exposure,
        f"{risk.rating} authoritative risk rating",
    ]

    return "; ".join(
        query_parts
    )