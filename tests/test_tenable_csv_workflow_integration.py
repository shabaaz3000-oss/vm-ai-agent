import csv

from pathlib import Path

import app.workflow as workflow

from app.models import AIAnalysis

from app.providers.asset_context_csv import (
    ASSET_CONTEXT_CSV_COLUMNS,
)

from app.providers.tenable_csv import (
    TenableCsvProvider,
)


ASSET_UUID = (
    "11111111-1111-1111-1111-111111111111"
)


# -------------------------------------------------
# TEST DATA
# -------------------------------------------------


def finding_row() -> dict[str, str]:

    return {
        "id":
            "FIND-TENABLE-0001",

        "asset.id":
            ASSET_UUID,

        "asset.name":
            "internet-web-01",

        "definition.cve":
            "CVE-2026-12345",

        "definition.name":
            "Remote Code Execution Vulnerability",

        "definition.description":
            (
                "A remote code execution "
                "vulnerability was detected "
                "on the affected system."
            ),

        "definition.cvss4.base_score":
            "9.8",

        "definition.cvss3.base_score":
            "9.1",

        "definition.cvss2.base_score":
            "7.5",

        "definition.epss.score":
            "94",

        "definition.vpr.drivers_on_cisa_kev":
            "true",

        "definition.patch_published":
            "2026-08-01T00:00:00Z",

        "severity":
            "critical",
    }


def asset_row() -> dict[str, str]:

    return {
        "id":
            ASSET_UUID,

        "name":
            "internet-web-01",

        "terminated_at":
            "",

        "display_fqdn":
            "internet-web-01.example.test",
    }


def context_row() -> dict[str, str]:

    return {
        "asset_uuid":
            ASSET_UUID,

        "asset_name":
            "internet-web-01",

        "owner":
            "Web Platform Team",

        "application":
            "Customer Portal",

        "environment":
            "production",

        "business_criticality":
            "critical",

        "internet_exposed":
            "true",

        "data_classification":
            "confidential",

        "current_controls":
            (
                "WAF enabled;"
                "EDR installed;"
                "SIEM logging enabled"
            ),
    }


# -------------------------------------------------
# CSV WRITER
# -------------------------------------------------


def write_csv(
    path: Path,
    row: dict[str, str],
    *,
    fieldnames: list[str],
) -> Path:

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerow(
            {
                field:
                    row.get(
                        field,
                        "",
                    )
                for field
                in fieldnames
            }
        )

    return path


# -------------------------------------------------
# FILE SETUP
# -------------------------------------------------


def build_files(
    tmp_path: Path,
) -> tuple[
    Path,
    Path,
    Path,
]:

    finding = finding_row()

    asset = asset_row()

    context = context_row()

    finding_csv = write_csv(
        tmp_path / "tenable-findings.csv",
        finding,
        fieldnames=list(
            finding.keys()
        ),
    )

    asset_csv = write_csv(
        tmp_path / "tenable-assets.csv",
        asset,
        fieldnames=list(
            asset.keys()
        ),
    )

    context_csv = write_csv(
        tmp_path / "asset-context.csv",
        context,
        fieldnames=list(
            ASSET_CONTEXT_CSV_COLUMNS
        ),
    )

    return (
        finding_csv,
        asset_csv,
        context_csv,
    )


# -------------------------------------------------
# CONTROLLED AI RESPONSE
# -------------------------------------------------


def make_analysis() -> AIAnalysis:

    return AIAnalysis(
        executive_summary=(
            "Critical vulnerability requiring "
            "expedited remediation."
        ),

        rationale=[
            "Internet exposed.",
            "Listed in CISA KEV.",
        ],

        remediation=(
            "Deploy the approved vendor patch."
        ),

        compensating_controls=[
            "Maintain WAF protection.",
            "Increase EDR monitoring.",
        ],

        validation_steps=[
            "Verify fixed version.",
            "Run authenticated rescan.",
        ],

        confidence=
            "HIGH",

        requires_human_review=
            True,

        ticket_summary=(
            "CRITICAL: Remediate "
            "CVE-2026-12345"
        ),

        ticket_description=(
            "Validated vulnerability ticket."
        ),
    )


def configure_workflow(
    monkeypatch,
    events: list[dict],
) -> None:

    monkeypatch.setattr(
        workflow,
        "analyze_vulnerability",
        lambda **kwargs:
            make_analysis(),
    )

    monkeypatch.setattr(
        workflow,
        "generate_workflow_id",
        lambda:
            "WF-TENABLECSV1",
    )

    monkeypatch.setattr(
        workflow,
        "log_event",
        lambda event_type, details=None:
            events.append(
                {
                    "event_type":
                        event_type,

                    "details":
                        details or {},
                }
            ),
    )


# -------------------------------------------------
# FROM FILES
# -------------------------------------------------


def test_tenable_csv_provider_from_files(
    tmp_path: Path,
) -> None:

    (
        finding_csv,
        asset_csv,
        context_csv,
    ) = build_files(
        tmp_path
    )

    provider = (
        TenableCsvProvider
        .from_files(
            vulnerability_csv_path=
                finding_csv,

            asset_csv_path=
                asset_csv,

            asset_context_csv_path=
                context_csv,
        )
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    asset = provider.get_asset_context(
        "internet-web-01"
    )

    threat = provider.get_threat_intel(
        "CVE-2026-12345"
    )

    assert finding.asset_name == (
        "internet-web-01"
    )

    assert finding.cvss == 9.8

    assert finding.patch_available is True

    assert asset.owner == (
        "Web Platform Team"
    )

    assert asset.application == (
        "Customer Portal"
    )

    assert (
        asset.business_criticality
        == "critical"
    )

    assert (
        asset.internet_exposed
        is True
    )

    assert threat.epss == 0.94

    assert threat.kev is True


# -------------------------------------------------
# COMPLETE THREE-FILE WORKFLOW
# -------------------------------------------------


def test_three_file_tenable_csv_runs_complete_workflow(
    tmp_path: Path,
    monkeypatch,
) -> None:

    events: list[dict] = []

    configure_workflow(
        monkeypatch,
        events,
    )

    (
        finding_csv,
        asset_csv,
        context_csv,
    ) = build_files(
        tmp_path
    )

    provider = (
        TenableCsvProvider
        .from_files(
            vulnerability_csv_path=
                finding_csv,

            asset_csv_path=
                asset_csv,

            asset_context_csv_path=
                context_csv,
        )
    )

    result = workflow.prepare_workflow(
        provider=provider,
        finding_id=
            "FIND-TENABLE-0001",
    )

    assert (
        result.workflow_id
        == "WF-TENABLECSV1"
    )

    assert (
        result.status
        == "AWAITING_APPROVAL"
    )

    assert (
        result.finding_id
        == "FIND-TENABLE-0001"
    )

    assert (
        result.asset_name
        == "internet-web-01"
    )

    assert (
        result.cve
        == "CVE-2026-12345"
    )


# -------------------------------------------------
# AUTHORITATIVE RISK
# -------------------------------------------------


def test_three_file_tenable_csv_produces_authoritative_risk(
    tmp_path: Path,
    monkeypatch,
) -> None:

    events: list[dict] = []

    configure_workflow(
        monkeypatch,
        events,
    )

    (
        finding_csv,
        asset_csv,
        context_csv,
    ) = build_files(
        tmp_path
    )

    provider = (
        TenableCsvProvider
        .from_files(
            vulnerability_csv_path=
                finding_csv,

            asset_csv_path=
                asset_csv,

            asset_context_csv_path=
                context_csv,
        )
    )

    result = workflow.prepare_workflow(
        provider=provider,
        finding_id=
            "FIND-TENABLE-0001",
    )

    assert result.risk.score == 100

    assert (
        result.risk.rating
        == "CRITICAL"
    )

    assert (
        result.risk.sla_hours
        == 24
    )

    assert (
        result.ticket.priority
        == "P1"
    )

    assert (
        result.ticket.risk_rating
        == "CRITICAL"
    )

    assert (
        result.ticket.risk_score
        == 100
    )

    assert (
        result.ticket.sla_hours
        == 24
    )


# -------------------------------------------------
# AUDIT SOURCE
# -------------------------------------------------


def test_three_file_workflow_audit_identifies_provider(
    tmp_path: Path,
    monkeypatch,
) -> None:

    events: list[dict] = []

    configure_workflow(
        monkeypatch,
        events,
    )

    (
        finding_csv,
        asset_csv,
        context_csv,
    ) = build_files(
        tmp_path
    )

    provider = (
        TenableCsvProvider
        .from_files(
            vulnerability_csv_path=
                finding_csv,

            asset_csv_path=
                asset_csv,

            asset_context_csv_path=
                context_csv,
        )
    )

    workflow.prepare_workflow(
        provider=provider,
        finding_id=
            "FIND-TENABLE-0001",
    )

    started = next(
        event
        for event
        in events
        if event["event_type"]
        == "WORKFLOW_STARTED"
    )

    validated = next(
        event
        for event
        in events
        if event["event_type"]
        == "SECURITY_DATA_VALIDATED"
    )

    assert (
        started["details"]["provider"]
        == "TenableCsvProvider"
    )

    assert (
        validated["details"]["provider"]
        == "TenableCsvProvider"
    )


# -------------------------------------------------
# HUMAN APPROVAL BOUNDARY
# -------------------------------------------------


def test_three_file_workflow_stops_before_execution(
    tmp_path: Path,
    monkeypatch,
) -> None:

    events: list[dict] = []

    configure_workflow(
        monkeypatch,
        events,
    )

    (
        finding_csv,
        asset_csv,
        context_csv,
    ) = build_files(
        tmp_path
    )

    provider = (
        TenableCsvProvider
        .from_files(
            vulnerability_csv_path=
                finding_csv,

            asset_csv_path=
                asset_csv,

            asset_context_csv_path=
                context_csv,
        )
    )

    result = workflow.prepare_workflow(
        provider=provider,
        finding_id=
            "FIND-TENABLE-0001",
    )

    event_types = [
        event["event_type"]
        for event
        in events
    ]

    assert (
        result.status
        == "AWAITING_APPROVAL"
    )

    assert result.approval_id is None

    assert result.ticket_id is None

    assert (
        "TICKET_APPROVED"
        not in event_types
    )

    assert (
        "MOCK_TICKET_CREATED"
        not in event_types
    )