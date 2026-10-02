from __future__ import annotations

import ast
from pathlib import Path


EXECUTION_PATH = Path(
    "app/execution.py"
)


def _source() -> str:
    return EXECUTION_PATH.read_text(
        encoding="utf-8-sig"
    )


def _tree() -> ast.AST:
    return ast.parse(
        _source(),
        filename=str(
            EXECUTION_PATH
        ),
    )


def _call_name(
    node: ast.AST,
) -> str | None:

    if isinstance(
        node,
        ast.Name,
    ):
        return node.id

    if isinstance(
        node,
        ast.Attribute,
    ):
        return node.attr

    return None


def test_successful_claim_uses_claimed_result_correlation():
    text = _source()

    assert (
        "emit_workflow_execution_claimed_security_event("
        in text
    )

    index = text.index(
        "emit_workflow_execution_claimed_security_event("
    )

    region = text[
        index:
        index + 700
    ]

    assert (
        "tenant_id=claimed_result.tenant_id"
        in region
    )

    assert (
        "workflow_id=claimed_result.workflow_id"
        in region
    )

    assert (
        "claimed_result"
        in region
    )

    assert (
        ".execution_attempt_id"
        in region
    )


def test_needs_review_uses_returned_review_result():
    text = _source()

    assert (
        text.count(
            "emit_workflow_needs_review_security_event("
        )
        == 2
    )

    first = text.index(
        "emit_workflow_needs_review_security_event("
    )

    region = text[
        first:
        first + 800
    ]

    assert (
        "tenant_id=review_result.tenant_id"
        in region
    )

    assert (
        "workflow_id=review_result.workflow_id"
        in region
    )


def test_stale_path_uses_authoritative_result():
    text = _source()

    index = text.index(
        "emit_workflow_stale_processing_detected_security_event("
    )

    region = text[
        index:
        index + 1200
    ]

    assert (
        "tenant_id=result.tenant_id"
        in region
    )

    assert (
        "workflow_id=result.workflow_id"
        in region
    )

    assert (
        "result.execution_attempt_id"
        in region
    )

    assert (
        "emit_workflow_needs_review_security_event("
        in region
    )


def test_generic_claim_denial_does_not_emit_canonical_correlation():
    source = _source()

    tree = _tree()

    targets = [
        node
        for node in tree.body
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            == "claim_and_execute_workflow"
        )
    ]

    assert len(targets) == 1

    function = targets[0]

    segment = (
        ast.get_source_segment(
            source,
            function,
        )
        or ""
    )

    blocked = segment.index(
        '"WORKFLOW_EXECUTION_CLAIM_BLOCKED"'
    )

    claimed = segment.index(
        '"WORKFLOW_EXECUTION_CLAIMED"'
    )

    blocked_region = segment[
        blocked:
        claimed
    ]

    assert (
        "emit_workflow_execution_claim_denied"
        not in blocked_region
    )

    assert (
        "build_execution_attempt_ref"
        not in blocked_region
    )


def test_canonical_wiring_never_passes_raw_attempt_as_reference():
    text = _source()

    assert (
        "execution_attempt_ref="
        not in text
    )

    assert (
        "build_execution_attempt_ref("
        not in text
    )


def test_expected_execution_attempt_authority_remains_present():
    text = _source()

    assert (
        "expected_execution_attempt_id="
        in text
    )

    assert (
        "claimed_result"
        in text
    )

    assert (
        ".execution_attempt_id"
        in text
    )
