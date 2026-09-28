from types import SimpleNamespace

import vm_agent


def make_mcp_result(
    *,
    passed: bool = True,
):

    return SimpleNamespace(
        total_cases=20,
        allowed_cases=2,
        blocked_cases=15,
        authority_protection_cases=3,
        passed_cases=(
            20 if passed else 19
        ),
        failed_cases=(
            0 if passed else 1
        ),
        unexpected_allows=(
            0 if passed else 1
        ),
        unexpected_blocks=0,
        passed=passed,
    )


def patch_security_eval_dependencies(
    monkeypatch,
    *,
    mcp_passed: bool,
):

    passed_result = (
        SimpleNamespace(
            passed=True
        )
    )

    monkeypatch.setattr(
        vm_agent,
        "run_security_evaluation",
        lambda: passed_result,
    )

    monkeypatch.setattr(
        vm_agent,
        "run_rag_security_evaluation",
        lambda: passed_result,
    )

    monkeypatch.setattr(
        vm_agent,
        "run_tool_security_evaluation",
        lambda: passed_result,
    )

    monkeypatch.setattr(
        vm_agent,
        "run_authorization_security_evaluation",
        lambda: passed_result,
    )

    monkeypatch.setattr(
        vm_agent,
        "run_data_leakage_security_evaluation",
        lambda: passed_result,
    )

    monkeypatch.setattr(
        vm_agent,
        "run_excessive_agency_security_evaluation",
        lambda: passed_result,
    )

    monkeypatch.setattr(
        vm_agent,
        "run_mcp_identity_security_evaluation",
        lambda: make_mcp_result(
            passed=mcp_passed
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
        lambda *args, **kwargs: None,
    )


def test_mcp_identity_security_display_reports_pass(
    capsys,
):

    vm_agent.display_mcp_identity_security_evaluation(
        make_mcp_result(
            passed=True
        )
    )

    output = capsys.readouterr().out

    assert (
        "MCP IDENTITY / SESSION ISOLATION"
        in output
    )

    assert "Total Cases: 20" in output

    assert (
        "Authority Protection Cases: 3"
        in output
    )

    assert (
        "MCP Identity / Session "
        "Isolation Result: PASS"
        in output
    )


def test_security_eval_passes_when_mcp_identity_passes(
    monkeypatch,
):

    patch_security_eval_dependencies(
        monkeypatch,
        mcp_passed=True,
    )

    assert (
        vm_agent.run_security_eval()
        == 0
    )


def test_security_eval_fails_when_mcp_identity_fails(
    monkeypatch,
):

    patch_security_eval_dependencies(
        monkeypatch,
        mcp_passed=False,
    )

    assert (
        vm_agent.run_security_eval()
        == 1
    )
