from types import SimpleNamespace

import vm_agent


def make_enterprise_identity_result(
    *,
    passed: bool = True,
):

    return SimpleNamespace(
        total_cases=16,
        allowed_cases=2,
        blocked_cases=8,
        authority_protection_cases=6,

        passed_cases=(
            16 if passed else 15
        ),

        failed_cases=(
            0 if passed else 1
        ),

        unexpected_allows=(
            0 if passed else 1
        ),

        unexpected_blocks=0,

        authority_failures=(
            0 if passed else 1
        ),

        execution_errors=0,

        passed=passed,
    )


def patch_security_eval_dependencies(
    monkeypatch,
    *,
    enterprise_passed: bool,
):

    passed_result = (
        SimpleNamespace(
            passed=True
        )
    )

    for name in [
        "run_security_evaluation",
        "run_rag_security_evaluation",
        "run_tool_security_evaluation",
        "run_authorization_security_evaluation",
        "run_data_leakage_security_evaluation",
        "run_excessive_agency_security_evaluation",
        "run_mcp_identity_security_evaluation",
        "run_identity_aware_rag_security_evaluation",
    ]:

        monkeypatch.setattr(
            vm_agent,
            name,
            lambda: passed_result,
        )

    monkeypatch.setattr(
        vm_agent,
        "run_enterprise_identity_security_evaluation",
        lambda:
            make_enterprise_identity_result(
                passed=
                    enterprise_passed
            ),
    )

    monkeypatch.setattr(
        vm_agent,
        "run_security_evaluations",
        lambda: [
            SimpleNamespace(
                passed=True
            )
        ],
    )

    monkeypatch.setattr(
        vm_agent,
        "display_security_evaluation",
        lambda *args, **kwargs:
            None,
    )


def test_enterprise_identity_security_display_reports_pass(
    capsys,
):

    vm_agent.display_enterprise_identity_security_evaluation(
        make_enterprise_identity_result(
            passed=True
        )
    )

    output = (
        capsys.readouterr().out
    )

    assert (
        "ENTERPRISE IDENTITY AUTHORITY"
        in output
    )

    assert (
        "Total Cases: 16"
        in output
    )

    assert (
        "Authority Protection Cases: 6"
        in output
    )

    assert (
        "Authority Failures: 0"
        in output
    )

    assert (
        "Enterprise Identity Authority "
        "Result: PASS"
        in output
    )


def test_security_eval_passes_when_enterprise_identity_passes(
    monkeypatch,
):

    patch_security_eval_dependencies(
        monkeypatch,
        enterprise_passed=True,
    )

    assert (
        vm_agent.run_security_eval()
        == 0
    )


def test_security_eval_fails_when_enterprise_identity_fails(
    monkeypatch,
):

    patch_security_eval_dependencies(
        monkeypatch,
        enterprise_passed=False,
    )

    assert (
        vm_agent.run_security_eval()
        == 1
    )
