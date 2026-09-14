from pathlib import Path
from types import SimpleNamespace

import vm_agent

from app.providers.tenable_csv import (
    TenableCsvImportError,
)


# -------------------------------------------------
# TEST RESULT
# -------------------------------------------------


def make_result(
    *,
    prompt_injection_detected: bool = False,
):

    matches = (
        [
            "ignore previous instructions"
        ]
        if prompt_injection_detected
        else []
    )

    return SimpleNamespace(
        workflow_id=
            "WF-CLI0001",

        finding_id=
            "FIND-TENABLE-0001",

        asset_name=
            "internet-web-01",

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
                    prompt_injection_detected,

                prompt_injection_matches=
                    matches,

                human_review_required=
                    True,
            ),

        analysis=
            SimpleNamespace(
                executive_summary=(
                    "Critical vulnerability "
                    "requiring remediation."
                ),

                remediation=(
                    "Deploy the approved patch."
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
# SUCCESSFUL COMMAND
# -------------------------------------------------


def test_cli_analyzes_three_file_tenable_workflow(
    monkeypatch,
    capsys,
    tmp_path: Path,
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
    ):

        calls[
            "workflow_provider"
        ] = provider

        calls[
            "finding_id"
        ] = finding_id

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

    findings = (
        tmp_path
        / "findings.csv"
    )

    assets = (
        tmp_path
        / "assets.csv"
    )

    context = (
        tmp_path
        / "context.csv"
    )

    exit_code = vm_agent.main(
        [
            "analyze-tenable-csv",

            "--findings",
            str(findings),

            "--assets",
            str(assets),

            "--context",
            str(context),

            "--finding-id",
            "FIND-TENABLE-0001",
        ]
    )

    output = (
        capsys
        .readouterr()
        .out
    )

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
        == "FIND-TENABLE-0001"
    )

    assert (
        calls[
            "provider_kwargs"
        ][
            "vulnerability_csv_path"
        ]
        == findings
    )

    assert (
        calls[
            "provider_kwargs"
        ][
            "asset_csv_path"
        ]
        == assets
    )

    assert (
        calls[
            "provider_kwargs"
        ][
            "asset_context_csv_path"
        ]
        == context
    )

    assert (
        "CRITICAL"
        in output
    )

    assert (
        "P1"
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
# SECURITY EVALUATION COMMAND
# -------------------------------------------------


def make_prompt_security_eval_result(
    *,
    passed: bool = True,
):

    return SimpleNamespace(
        total_cases=20,
        adversarial_cases=15,
        benign_cases=5,
        passed_cases=(20 if passed else 19),
        failed_cases=(0 if passed else 1),
        false_negatives=(0 if passed else 1),
        false_positives=0,
        category_mismatches=0,
        passed=passed,
    )


def make_rag_security_eval_result(
    *,
    passed: bool = True,
):

    return SimpleNamespace(
        total_cases=20,
        malicious_cases=14,
        benign_cases=6,
        passed_cases=(20 if passed else 19),
        failed_cases=(0 if passed else 1),
        missed_quarantines=(0 if passed else 1),
        false_quarantines=0,
        category_mismatches=0,
        passed=passed,
    )


def make_tool_security_eval_result(
    *,
    passed: bool = True,
):

    return SimpleNamespace(
        total_cases=16,
        allowed_cases=8,
        blocked_cases=8,
        passed_cases=(16 if passed else 15),
        failed_cases=(0 if passed else 1),
        unexpected_allows=(0 if passed else 1),
        unexpected_blocks=0,
        error_mismatches=0,
        passed=passed,
    )


def make_authorization_security_eval_result(
    *,
    passed: bool = True,
):

    return SimpleNamespace(
        total_cases=8,
        allowed_cases=4,
        blocked_cases=4,
        passed_cases=(8 if passed else 7),
        failed_cases=(0 if passed else 1),
        unexpected_allows=(0 if passed else 1),
        unexpected_blocks=0,
        status_mismatches=0,
        role_mismatches=0,
        exception_mismatches=0,
        passed=passed,
    )


def make_data_leakage_security_eval_result(
    *,
    passed: bool = True,
):

    return SimpleNamespace(
        total_cases=8,
        passed_cases=(8 if passed else 7),
        failed_cases=(0 if passed else 1),
        unexpected_exposures=(0 if passed else 1),
        result_mismatches=0,
        access_mismatches=0,
        error_mismatches=0,
        passed=passed,
    )


def make_excessive_agency_security_eval_result(
    *,
    passed: bool = True,
):

    return SimpleNamespace(
        total_cases=12,
        permitted_cases=3,
        blocked_cases=9,
        passed_cases=(12 if passed else 11),
        failed_cases=(0 if passed else 1),
        unexpected_allows=(0 if passed else 1),
        unexpected_blocks=0,
        error_mismatches=0,
        message_mismatches=0,
        scope_mismatches=0,
        passed=passed,
    )


def make_attack_security_eval_results(
    *,
    passed: bool = True,
):

    attack_names = [
        "Direct Prompt Injection",
        "Indirect Prompt Injection",
        "Unauthorized Tool Execution",
        "Privilege Escalation",
        "RAG Poisoning",
        "Data Exfiltration",
        "System Prompt Leakage",
    ]

    return [
        SimpleNamespace(
            attack_name=attack_name,
            category="security_eval",
            severity="critical",
            passed=passed,
            expected_behavior=(
                "Security control blocks attack."
            ),
            observed_behavior=(
                "Attack blocked."
                if passed
                else "Attack succeeded."
            ),
            evidence=[],
        )
        for attack_name in attack_names
    ]


def patch_security_eval_suites(
    monkeypatch,
    *,
    prompt_passed: bool = True,
    rag_passed: bool = True,
    tool_passed: bool = True,
    authorization_passed: bool = True,
    leakage_passed: bool = True,
    agency_passed: bool = True,
    attack_results=None,
) -> None:

    monkeypatch.setattr(
        vm_agent,
        "run_security_evaluation",
        lambda: make_prompt_security_eval_result(
            passed=prompt_passed
        ),
    )

    monkeypatch.setattr(
        vm_agent,
        "run_rag_security_evaluation",
        lambda: make_rag_security_eval_result(
            passed=rag_passed
        ),
    )

    monkeypatch.setattr(
        vm_agent,
        "run_tool_security_evaluation",
        lambda: make_tool_security_eval_result(
            passed=tool_passed
        ),
    )

    monkeypatch.setattr(
        vm_agent,
        "run_authorization_security_evaluation",
        lambda: make_authorization_security_eval_result(
            passed=authorization_passed
        ),
    )

    monkeypatch.setattr(
        vm_agent,
        "run_data_leakage_security_evaluation",
        lambda: make_data_leakage_security_eval_result(
            passed=leakage_passed
        ),
    )

    monkeypatch.setattr(
        vm_agent,
        "run_excessive_agency_security_evaluation",
        lambda: make_excessive_agency_security_eval_result(
            passed=agency_passed
        ),
    )

    if attack_results is None:
        attack_results = (
            make_attack_security_eval_results(
                passed=True
            )
        )

    monkeypatch.setattr(
        vm_agent,
        "run_security_evaluations",
        lambda: attack_results,
    )


def test_security_eval_command_returns_zero_when_all_suites_pass(
    monkeypatch,
    capsys,
) -> None:

    patch_security_eval_suites(
        monkeypatch
    )

    exit_code = vm_agent.main(
        ["security-eval"]
    )

    output = capsys.readouterr().out

    assert exit_code == 0

    assert (
        "VM AI AGENT - SECURITY EVALUATION"
        in output
    )

    for heading in [
        "PROMPT-INJECTION DETECTION",
        "RAG QUARANTINE ENFORCEMENT",
        "TOOL SECURITY",
        "AUTHORIZATION SECURITY",
        "DATA LEAKAGE SECURITY",
        "EXCESSIVE AGENCY",
        "STANDARDIZED ATTACK HARNESS",
    ]:
        assert heading in output

    assert "Adversarial Cases: 15" in output
    assert "Malicious Cases: 14" in output
    assert "Allowed Cases: 8" in output
    assert "Allowed Cases: 4" in output
    assert "Permitted Cases: 3" in output
    assert "Unexpected Exposures: 0" in output
    assert "Status Mismatches: 0" in output
    assert "Role Mismatches: 0" in output
    assert "Exception Mismatches: 0" in output
    assert "Message Mismatches: 0" in output
    assert "Scope Mismatches: 0" in output

    assert (
        "Prompt-Injection Result: PASS"
        in output
    )
    assert (
        "RAG Quarantine Result: PASS"
        in output
    )
    assert (
        "Tool Security Result: PASS"
        in output
    )
    assert (
        "Authorization Security Result: PASS"
        in output
    )
    assert (
        "Data Leakage Security Result: PASS"
        in output
    )
    assert (
        "Excessive Agency Result: PASS"
        in output
    )

    assert "Direct Prompt Injection" in output
    assert "System Prompt Leakage" in output
    assert "Passed: 7" in output
    assert "Failed: 0" in output
    assert "Security Score: 100.0%" in output

    assert (
        "OVERALL SECURITY EVALUATION: PASS"
        in output
    )

    assert (
        "no approval, ticket creation, "
        "or external execution"
        in output
    )


def test_security_eval_command_fails_when_prompt_suite_fails(
    monkeypatch,
    capsys,
) -> None:

    patch_security_eval_suites(
        monkeypatch,
        prompt_passed=False,
    )

    exit_code = vm_agent.main(
        ["security-eval"]
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "False Negatives: 1" in output
    assert "Prompt-Injection Result: FAIL" in output
    assert "RAG Quarantine Result: PASS" in output
    assert "Tool Security Result: PASS" in output
    assert "Authorization Security Result: PASS" in output
    assert "Data Leakage Security Result: PASS" in output
    assert "Excessive Agency Result: PASS" in output
    assert "OVERALL SECURITY EVALUATION: FAIL" in output


def test_security_eval_command_fails_when_rag_suite_fails(
    monkeypatch,
    capsys,
) -> None:

    patch_security_eval_suites(
        monkeypatch,
        rag_passed=False,
    )

    exit_code = vm_agent.main(
        ["security-eval"]
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Missed Quarantines: 1" in output
    assert "Prompt-Injection Result: PASS" in output
    assert "RAG Quarantine Result: FAIL" in output
    assert "Tool Security Result: PASS" in output
    assert "Authorization Security Result: PASS" in output
    assert "Data Leakage Security Result: PASS" in output
    assert "Excessive Agency Result: PASS" in output
    assert "OVERALL SECURITY EVALUATION: FAIL" in output


def test_security_eval_command_fails_when_tool_suite_fails(
    monkeypatch,
    capsys,
) -> None:

    patch_security_eval_suites(
        monkeypatch,
        tool_passed=False,
    )

    exit_code = vm_agent.main(
        ["security-eval"]
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Unexpected Allows: 1" in output
    assert "Tool Security Result: FAIL" in output
    assert "Authorization Security Result: PASS" in output
    assert "Data Leakage Security Result: PASS" in output
    assert "Excessive Agency Result: PASS" in output
    assert "OVERALL SECURITY EVALUATION: FAIL" in output


def test_security_eval_command_fails_when_authorization_suite_fails(
    monkeypatch,
    capsys,
) -> None:

    patch_security_eval_suites(
        monkeypatch,
        authorization_passed=False,
    )

    exit_code = vm_agent.main(
        ["security-eval"]
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Authorization Security Result: FAIL" in output
    assert "Unexpected Allows: 1" in output
    assert "Data Leakage Security Result: PASS" in output
    assert "Excessive Agency Result: PASS" in output
    assert "OVERALL SECURITY EVALUATION: FAIL" in output


def test_security_eval_command_fails_when_data_leakage_suite_fails(
    monkeypatch,
    capsys,
) -> None:

    patch_security_eval_suites(
        monkeypatch,
        leakage_passed=False,
    )

    exit_code = vm_agent.main(
        ["security-eval"]
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Unexpected Exposures: 1" in output
    assert "Data Leakage Security Result: FAIL" in output
    assert "Authorization Security Result: PASS" in output
    assert "Excessive Agency Result: PASS" in output
    assert "OVERALL SECURITY EVALUATION: FAIL" in output


def test_security_eval_command_fails_when_excessive_agency_suite_fails(
    monkeypatch,
    capsys,
) -> None:

    patch_security_eval_suites(
        monkeypatch,
        agency_passed=False,
    )

    exit_code = vm_agent.main(
        ["security-eval"]
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Unexpected Allows: 1" in output
    assert "Excessive Agency Result: FAIL" in output
    assert "Authorization Security Result: PASS" in output
    assert "Data Leakage Security Result: PASS" in output
    assert "OVERALL SECURITY EVALUATION: FAIL" in output


def test_security_eval_command_fails_when_attack_harness_fails(
    monkeypatch,
    capsys,
) -> None:

    attack_results = (
        make_attack_security_eval_results(
            passed=True
        )
    )

    attack_results[-1].passed = False
    attack_results[-1].observed_behavior = (
        "Protected system prompt was exposed."
    )

    patch_security_eval_suites(
        monkeypatch,
        attack_results=attack_results,
    )

    exit_code = vm_agent.main(
        ["security-eval"]
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "System Prompt Leakage" in output
    assert "FAIL" in output
    assert "Tool Security Result: PASS" in output
    assert "Authorization Security Result: PASS" in output
    assert "Data Leakage Security Result: PASS" in output
    assert "Excessive Agency Result: PASS" in output
    assert "OVERALL SECURITY EVALUATION: FAIL" in output


# -------------------------------------------------
# PROMPT INJECTION WARNING
# -------------------------------------------------


def test_cli_displays_prompt_injection_warning(
    monkeypatch,
    capsys,
) -> None:

    provider = object()

    class FakeTenableCsvProvider:

        @classmethod
        def from_files(
            cls,
            **kwargs,
        ):

            return provider

    monkeypatch.setattr(
        vm_agent,
        "TenableCsvProvider",
        FakeTenableCsvProvider,
    )

    monkeypatch.setattr(
        vm_agent,
        "prepare_workflow",
        lambda **kwargs:
            make_result(
                prompt_injection_detected=True
            ),
    )

    exit_code = vm_agent.main(
        [
            "analyze-tenable-csv",

            "--findings",
            "findings.csv",

            "--assets",
            "assets.csv",

            "--context",
            "context.csv",

            "--finding-id",
            "FIND-TENABLE-0001",
        ]
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 0

    assert (
        "SECURITY WARNING"
        in output
    )

    assert (
        "Prompt Injection Detected: True"
        in output
    )

    assert (
        "Authoritative risk remains "
        "controlled by deterministic policy."
        in output
    )


# -------------------------------------------------
# INPUT VALIDATION ERROR
# -------------------------------------------------


def test_cli_sanitizes_input_validation_error(
    monkeypatch,
    capsys,
) -> None:

    secret_marker = (
        "DO_NOT_LEAK_THIS_VALUE"
    )

    class FakeTenableCsvProvider:

        @classmethod
        def from_files(
            cls,
            **kwargs,
        ):

            raise TenableCsvImportError(
                secret_marker
            )

    monkeypatch.setattr(
        vm_agent,
        "TenableCsvProvider",
        FakeTenableCsvProvider,
    )

    exit_code = vm_agent.main(
        [
            "analyze-tenable-csv",

            "--findings",
            "findings.csv",

            "--assets",
            "assets.csv",

            "--context",
            "context.csv",

            "--finding-id",
            "FIND-TENABLE-0001",
        ]
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 2

    assert (
        "failed security validation"
        in output
    )

    assert (
        secret_marker
        not in output
    )


# -------------------------------------------------
# UNKNOWN FINDING
# -------------------------------------------------


def test_cli_handles_unknown_finding_safely(
    monkeypatch,
    capsys,
) -> None:

    provider = object()

    class FakeTenableCsvProvider:

        @classmethod
        def from_files(
            cls,
            **kwargs,
        ):

            return provider

    monkeypatch.setattr(
        vm_agent,
        "TenableCsvProvider",
        FakeTenableCsvProvider,
    )

    monkeypatch.setattr(
        vm_agent,
        "prepare_workflow",
        lambda **kwargs:
            (_ for _ in ())
            .throw(
                KeyError(
                    "SENSITIVE_FINDING_VALUE"
                )
            ),
    )

    exit_code = vm_agent.main(
        [
            "analyze-tenable-csv",

            "--findings",
            "findings.csv",

            "--assets",
            "assets.csv",

            "--context",
            "context.csv",

            "--finding-id",
            "FIND-9999",
        ]
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 3

    assert (
        "was not found"
        in output
    )

    assert (
        "SENSITIVE_FINDING_VALUE"
        not in output
    )


# -------------------------------------------------
# UNEXPECTED ERROR
# -------------------------------------------------


def test_cli_hides_unexpected_exception_details(
    monkeypatch,
    capsys,
) -> None:

    secret_marker = (
        "SECRET_INTERNAL_DETAIL"
    )

    class FakeTenableCsvProvider:

        @classmethod
        def from_files(
            cls,
            **kwargs,
        ):

            raise RuntimeError(
                secret_marker
            )

    monkeypatch.setattr(
        vm_agent,
        "TenableCsvProvider",
        FakeTenableCsvProvider,
    )

    exit_code = vm_agent.main(
        [
            "analyze-tenable-csv",

            "--findings",
            "findings.csv",

            "--assets",
            "assets.csv",

            "--context",
            "context.csv",

            "--finding-id",
            "FIND-TENABLE-0001",
        ]
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert exit_code == 4

    assert (
        "unexpected error"
        in output
    )

    assert (
        secret_marker
        not in output
    )

    assert (
        "No ticket was approved or created."
        in output
    )


# -------------------------------------------------
# TERMINAL CONTROL CHARACTERS
# -------------------------------------------------


def test_safe_text_removes_terminal_control_characters() -> None:

    malicious_text = (
        "Critical\x1b[31mInjected"
    )

    safe = (
        vm_agent._safe_text(
            malicious_text
        )
    )

    assert "\x1b" not in safe

    assert "Critical" in safe

    assert "Injected" in safe