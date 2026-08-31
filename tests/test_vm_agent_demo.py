from types import SimpleNamespace

import app.ai_analyzer as ai_analyzer
import app.workflow as workflow_module

import vm_agent

from app.providers.tenable_csv import (
    TenableCsvProvider,
)


# -------------------------------------------------
# TEST RESULT
# -------------------------------------------------


def make_result():

    return SimpleNamespace(
        workflow_id=
            "WF-DEMO0001",

        finding_id=
            "FIND-DEMO-0001",

        asset_name=
            "demo-web-01",

        cve=
            "CVE-2026-12345",

        status=
            "AWAITING_APPROVAL",

        risk=
            SimpleNamespace(
                score=100,
                rating="CRITICAL",
                sla_hours=24,
            ),

        security=
            SimpleNamespace(
                prompt_injection_detected=
                    False,

                prompt_injection_matches=
                    [],

                human_review_required=
                    True,
            ),

        analysis=
            SimpleNamespace(
                executive_summary=(
                    "Controlled local demo "
                    "analysis."
                ),

                remediation=(
                    "Apply the approved patch."
                ),

                confidence=
                    "HIGH",
            ),

        ticket=
            SimpleNamespace(
                priority="P1",
                risk_rating="CRITICAL",
                risk_score=100,
                sla_hours=24,
            ),
    )


# -------------------------------------------------
# REAL CREDENTIAL-FREE DEMO
# -------------------------------------------------


def test_demo_command_runs_with_real_sample_files(
    monkeypatch,
    capsys,
) -> None:

    # Prevent tests from writing portfolio-demo
    # events into the normal audit log.

    monkeypatch.setattr(
        workflow_module,
        "log_event",
        lambda *args, **kwargs:
            None,
    )

    exit_code = vm_agent.main(
        [
            "demo"
        ]
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 0

    assert (
        "VM AI AGENT - PORTFOLIO DEMO"
        in output
    )

    assert (
        "FIND-DEMO-0001"
        in output
    )

    assert (
        "demo-web-01"
        in output
    )

    assert (
        "CVE-2026-12345"
        in output
    )

    assert (
        "Score: 100"
        in output
    )

    assert (
        "Rating: CRITICAL"
        in output
    )

    assert (
        "Priority: P1"
        in output
    )

    assert (
        "AWAITING_APPROVAL"
        in output
    )

    assert (
        "No ticket has been approved "
        "or created."
        in output
    )


# -------------------------------------------------
# NO OPENAI CALL
# -------------------------------------------------


def test_demo_does_not_call_openai(
    monkeypatch,
    capsys,
) -> None:

    monkeypatch.setattr(
        workflow_module,
        "log_event",
        lambda *args, **kwargs:
            None,
    )

    def forbidden_openai_client():

        raise AssertionError(
            "The portfolio demo attempted "
            "to create an OpenAI client."
        )

    monkeypatch.setattr(
        ai_analyzer,
        "_get_client",
        forbidden_openai_client,
    )

    exit_code = vm_agent.main(
        [
            "demo"
        ]
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 0

    assert (
        "No OpenAI API credentials "
        "are required."
        in output
    )

    assert (
        "AWAITING_APPROVAL"
        in output
    )


# -------------------------------------------------
# EXPLICIT LOCAL ANALYZER
# -------------------------------------------------


def test_demo_explicitly_injects_local_analyzer(
    monkeypatch,
    capsys,
) -> None:

    calls = {}

    provider = object()

    class FakeTenableCsvProvider:

        @classmethod
        def from_files(
            cls,
            **kwargs,
        ):

            calls[
                "provider_kwargs"
            ] = kwargs

            return provider

    def fake_prepare_workflow(
        *,
        provider,
        finding_id,
        analyzer,
    ):

        calls[
            "workflow_provider"
        ] = provider

        calls[
            "finding_id"
        ] = finding_id

        calls[
            "analyzer"
        ] = analyzer

        return make_result()

    monkeypatch.setattr(
        vm_agent,
        "TenableCsvProvider",
        FakeTenableCsvProvider,
    )

    monkeypatch.setattr(
        vm_agent,
        "prepare_workflow",
        fake_prepare_workflow,
    )

    exit_code = vm_agent.main(
        [
            "demo"
        ]
    )

    capsys.readouterr()

    assert exit_code == 0

    assert (
        calls[
            "workflow_provider"
        ]
        is provider
    )

    assert (
        calls[
            "finding_id"
        ]
        == "FIND-DEMO-0001"
    )

    assert (
        calls[
            "analyzer"
        ]
        is vm_agent
        .analyze_demo_vulnerability
    )

    assert (
        calls[
            "provider_kwargs"
        ][
            "vulnerability_csv_path"
        ]
        == vm_agent
        .DEMO_FINDINGS_PATH
    )

    assert (
        calls[
            "provider_kwargs"
        ][
            "asset_csv_path"
        ]
        == vm_agent
        .DEMO_ASSETS_PATH
    )

    assert (
        calls[
            "provider_kwargs"
        ][
            "asset_context_csv_path"
        ]
        == vm_agent
        .DEMO_CONTEXT_PATH
    )


# -------------------------------------------------
# NO EXECUTION AUTHORITY
# -------------------------------------------------


def test_demo_cli_has_no_ticket_execution_authority() -> None:

    # vm_agent.py intentionally imports no approval
    # or ticket-execution functions.
    #
    # The analysis CLI therefore cannot directly
    # cross the workflow's human approval boundary.

    assert not hasattr(
        vm_agent,
        "approve_and_execute_workflow",
    )

    assert not hasattr(
        vm_agent,
        "reject_workflow",
    )

    assert not hasattr(
        vm_agent,
        "display_created_ticket",
    )


# -------------------------------------------------
# DEMO DATA CORRELATION
# -------------------------------------------------


def test_demo_files_form_valid_correlated_tenable_dataset() -> None:

    assert (
        vm_agent
        .DEMO_FINDINGS_PATH
        .is_file()
    )

    assert (
        vm_agent
        .DEMO_ASSETS_PATH
        .is_file()
    )

    assert (
        vm_agent
        .DEMO_CONTEXT_PATH
        .is_file()
    )

    provider = (
        TenableCsvProvider
        .from_files(
            vulnerability_csv_path=
                vm_agent
                .DEMO_FINDINGS_PATH,

            asset_csv_path=
                vm_agent
                .DEMO_ASSETS_PATH,

            asset_context_csv_path=
                vm_agent
                .DEMO_CONTEXT_PATH,
        )
    )

    finding = provider.get_finding(
        "FIND-DEMO-0001"
    )

    asset = provider.get_asset_context(
        "demo-web-01"
    )

    threat = provider.get_threat_intel(
        "CVE-2026-12345"
    )

    assert (
        finding.finding_id
        == "FIND-DEMO-0001"
    )

    assert (
        finding.asset_name
        == "demo-web-01"
    )

    assert (
        asset.asset_name
        == finding.asset_name
    )

    assert (
        threat.cve
        == finding.cve
    )

    assert finding.cvss == 9.8

    assert (
        finding.patch_available
        is True
    )

    assert threat.epss == 0.94

    assert threat.kev is True

    assert (
        asset.business_criticality
        == "critical"
    )

    assert (
        asset.internet_exposed
        is True
    )