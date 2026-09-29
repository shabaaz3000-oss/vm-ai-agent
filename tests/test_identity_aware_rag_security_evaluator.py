from types import SimpleNamespace

import vm_agent

from app.identity_aware_rag_security_evaluator import (
    run_identity_aware_rag_security_evaluation,
)


def test_identity_aware_rag_security_evaluator_passes():

    result = (
        run_identity_aware_rag_security_evaluation()
    )

    assert result.total_cases == 6

    assert result.authorized_cases == 1
    assert result.blocked_cases == 5

    assert result.cross_tenant_cases == 1
    assert result.cross_user_acl_cases == 1
    assert result.classification_cases == 1
    assert result.fail_closed_cases == 1
    assert result.backend_injection_cases == 1

    assert result.passed_cases == 6
    assert result.failed_cases == 0

    assert result.unauthorized_exposures == 0

    assert (
        result.pre_search_boundary_failures
        == 0
    )

    assert result.audit_failures == 0

    assert result.passed is True


def test_identity_aware_rag_security_display_reports_pass(
    capsys,
):

    result = (
        run_identity_aware_rag_security_evaluation()
    )

    vm_agent.display_identity_aware_rag_security_evaluation(
        result
    )

    output = capsys.readouterr().out

    assert (
        "IDENTITY-AWARE RAG AUTHORIZATION"
        in output
    )

    assert "Total Cases: 6" in output

    assert "Unauthorized Exposures: 0" in output

    assert (
        "Pre-Search Boundary Failures: 0"
        in output
    )

    assert "Audit Failures: 0" in output

    assert (
        "Identity-Aware RAG Authorization "
        "Result: PASS"
        in output
    )


def patch_security_eval_dependencies(
    monkeypatch,
    *,
    identity_rag_passed: bool,
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
    ]:

        monkeypatch.setattr(
            vm_agent,
            name,
            lambda: passed_result,
        )

    monkeypatch.setattr(
        vm_agent,
        "run_identity_aware_rag_security_evaluation",
        lambda:
            SimpleNamespace(
                passed=
                    identity_rag_passed
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


def test_security_eval_passes_when_identity_rag_passes(
    monkeypatch,
):

    patch_security_eval_dependencies(
        monkeypatch,
        identity_rag_passed=True,
    )

    assert (
        vm_agent.run_security_eval()
        == 0
    )


def test_security_eval_fails_when_identity_rag_fails(
    monkeypatch,
):

    patch_security_eval_dependencies(
        monkeypatch,
        identity_rag_passed=False,
    )

    assert (
        vm_agent.run_security_eval()
        == 1
    )