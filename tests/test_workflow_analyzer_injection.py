import app.ai_analyzer as ai_analyzer
import app.workflow as workflow

from app.models import AIAnalysis
from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.providers.base import VulnerabilityProvider


# -------------------------------------------------
# TEST PROVIDER
# -------------------------------------------------


class AnalyzerTestProvider(
    VulnerabilityProvider
):

    def get_finding(
        self,
        finding_id: str
    ) -> VulnerabilityFinding:

        return VulnerabilityFinding(
            finding_id=
                finding_id,

            asset_name=
                "internet-web-01",

            cve=
                "CVE-2026-12345",

            title=
                "Remote Code Execution",

            description=(
                "A remote code execution "
                "vulnerability was detected."
            ),

            cvss=
                9.8,

            patch_available=
                True,
        )


    def get_asset_context(
        self,
        asset_name: str
    ) -> AssetContext:

        return AssetContext(
            asset_name=
                asset_name,

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


    def get_threat_intel(
        self,
        cve: str
    ) -> ThreatIntel:

        return ThreatIntel(
            cve=
                cve,

            epss=
                0.94,

            kev=
                True,

            data_source=
                "test",
        )


# -------------------------------------------------
# TEST ANALYSIS
# -------------------------------------------------


def make_analysis(
    *,
    requires_human_review: bool = True,
) -> AIAnalysis:

    return AIAnalysis(
        executive_summary=(
            "Controlled local analysis."
        ),

        rationale=[
            "Deterministic test rationale."
        ],

        remediation=(
            "Apply the approved patch."
        ),

        compensating_controls=[
            "Maintain existing controls."
        ],

        validation_steps=[
            "Run an authenticated rescan."
        ],

        confidence=
            "HIGH",

        requires_human_review=
            requires_human_review,

        ticket_summary=(
            "Remediate vulnerability"
        ),

        ticket_description=(
            "Controlled test ticket."
        ),
    )


# -------------------------------------------------
# INJECTED ANALYZER
# -------------------------------------------------


def test_prepare_workflow_uses_supplied_analyzer(
    monkeypatch,
) -> None:

    calls = {}

    def custom_analyzer(
        finding,
        asset,
        threat,
        risk,
    ):

        calls["finding"] = finding
        calls["asset"] = asset
        calls["threat"] = threat
        calls["risk"] = risk

        return make_analysis()

    def default_analyzer_must_not_run(
        **kwargs,
    ):

        raise AssertionError(
            "Default analyzer was called."
        )

    monkeypatch.setattr(
        workflow,
        "analyze_vulnerability",
        default_analyzer_must_not_run,
    )

    monkeypatch.setattr(
        workflow,
        "log_event",
        lambda *args, **kwargs:
            None,
    )

    result = workflow.prepare_workflow(
        provider=AnalyzerTestProvider(),
        finding_id="FIND-0001",
        analyzer=custom_analyzer,
    )

    assert (
        result.analysis.executive_summary
        == "Controlled local analysis."
    )

    assert (
        calls["finding"].finding_id
        == "FIND-0001"
    )

    assert (
        calls["asset"].asset_name
        == "internet-web-01"
    )

    assert (
        calls["threat"].cve
        == "CVE-2026-12345"
    )

    assert calls["risk"].score == 100

    assert (
        calls["risk"].rating
        == "CRITICAL"
    )


# -------------------------------------------------
# DEFAULT ANALYZER REMAINS DEFAULT
# -------------------------------------------------


def test_prepare_workflow_uses_default_analyzer_when_not_supplied(
    monkeypatch,
) -> None:

    called = False

    def fake_default_analyzer(
        **kwargs,
    ):

        nonlocal called

        called = True

        return make_analysis()

    monkeypatch.setattr(
        workflow,
        "analyze_vulnerability",
        fake_default_analyzer,
    )

    monkeypatch.setattr(
        workflow,
        "log_event",
        lambda *args, **kwargs:
            None,
    )

    result = workflow.prepare_workflow(
        provider=AnalyzerTestProvider(),
        finding_id="FIND-0001",
    )

    assert called is True

    assert (
        result.analysis.executive_summary
        == "Controlled local analysis."
    )


# -------------------------------------------------
# OPENAI CLIENT IS LAZY
# -------------------------------------------------


def test_openai_client_is_created_lazily_and_reused(
    monkeypatch,
) -> None:

    fake_client = object()

    calls = 0

    def fake_openai():

        nonlocal calls

        calls += 1

        return fake_client

    monkeypatch.setattr(
        ai_analyzer,
        "client",
        None,
    )

    monkeypatch.setattr(
        ai_analyzer,
        "OpenAI",
        fake_openai,
    )

    first = (
        ai_analyzer
        ._get_client()
    )

    second = (
        ai_analyzer
        ._get_client()
    )

    assert first is fake_client

    assert second is fake_client

    assert calls == 1

# -------------------------------------------------
# HUMAN REVIEW POLICY IS AUTHORITATIVE
# -------------------------------------------------


def test_analyzer_cannot_disable_human_review_requirement(
    monkeypatch,
) -> None:

    """
    A model or analyzer may claim that human review
    is unnecessary.

    That advisory value must not weaken the
    workflow's authoritative approval policy.
    """

    def malicious_analyzer(
        finding,
        asset,
        threat,
        risk,
    ):

        return make_analysis(
            requires_human_review=False,
        )

    monkeypatch.setattr(
        workflow,
        "log_event",
        lambda *args, **kwargs:
            None,
    )

    result = workflow.prepare_workflow(
        provider=AnalyzerTestProvider(),
        finding_id="FIND-0001",
        analyzer=malicious_analyzer,
    )

    # The analyzer is allowed to express its
    # advisory opinion.

    assert (
        result.analysis.requires_human_review
        is False
    )

    # But authoritative workflow security policy
    # must still require human review.

    assert (
        result.security.human_review_required
        is True
    )

    assert (
        result.status
        == "AWAITING_APPROVAL"
    )
