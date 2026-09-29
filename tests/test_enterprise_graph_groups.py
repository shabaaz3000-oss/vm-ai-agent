import json

from urllib.error import URLError

import pytest

from app.enterprise_authorization_evidence import (
    EnterpriseAuthorizationEvidence,
    EnterpriseGroupMembershipUnavailable,
    ValidatedEnterpriseToken,
    require_authoritative_group_ids,
)

from app.enterprise_graph_groups import (
    MICROSOFT_GRAPH_V1,
    GraphHttpResult,
    MicrosoftGraphGroupResolutionError,
    MicrosoftGraphGroupResolver,
    resolve_authoritative_group_membership,
    resolve_validated_token_group_membership,
)

from app.enterprise_identity import (
    EnterpriseIdentity,
)


OID = (
    "33333333-3333-3333-3333-333333333333"
)

GROUP_ONE = (
    "44444444-4444-4444-4444-444444444444"
)

GROUP_TWO = (
    "55555555-5555-5555-5555-555555555555"
)

GRAPH_TOKEN = (
    "server-acquired-graph-access-token"
)


# -------------------------------------------------
# TEST HELPERS
# -------------------------------------------------


class RecordingExecutor:

    def __init__(
        self,
        result,
    ):

        self.result = result

        self.requests = []

    def __call__(
        self,
        request,
        timeout,
    ):

        self.requests.append(
            (
                request,
                timeout,
            )
        )

        return self.result


class RecordingResolver:

    def __init__(
        self,
        group_ids,
    ):

        self.group_ids = group_ids

        self.calls = []

    def resolve_group_ids(
        self,
        directory_object_id,
    ):

        self.calls.append(
            directory_object_id
        )

        return self.group_ids


def graph_result(
    value,
    *,
    status_code=200,
):

    return GraphHttpResult(
        status_code=
            status_code,
        body=
            json.dumps(
                {
                    "value": value
                }
            ).encode(
                "utf-8"
            ),
    )


def overage_evidence():

    return EnterpriseAuthorizationEvidence(
        app_roles=(
            "VM.Reader",
        ),
        group_ids=(),
        group_membership_state=
            "overage",
        directory_object_id=
            OID,
    )


# -------------------------------------------------
# FIXED GRAPH AUTHORITY
# -------------------------------------------------


def test_graph_resolver_constructs_server_owned_url_from_oid():

    executor = RecordingExecutor(
        graph_result(
            [
                GROUP_ONE
            ]
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    result = resolver.resolve_group_ids(
        OID
    )

    assert result == (
        GROUP_ONE,
    )

    request, timeout = (
        executor.requests[0]
    )

    assert request.full_url == (
        f"{MICROSOFT_GRAPH_V1}"
        f"/users/{OID}"
        f"/getMemberGroups"
    )

    assert request.method == "POST"

    assert timeout == 5.0


def test_graph_request_uses_separate_server_graph_token():

    executor = RecordingExecutor(
        graph_result(
            []
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    resolver.resolve_group_ids(
        OID
    )

    request, _ = executor.requests[0]

    assert request.get_header(
        "Authorization"
    ) == (
        f"Bearer {GRAPH_TOKEN}"
    )


def test_graph_request_asks_for_transitive_membership_set():

    executor = RecordingExecutor(
        graph_result(
            []
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    resolver.resolve_group_ids(
        OID
    )

    request, _ = executor.requests[0]

    assert json.loads(
        request.data.decode(
            "utf-8"
        )
    ) == {
        "securityEnabledOnly": False
    }


# -------------------------------------------------
# GRAPH RESPONSE VALIDATION
# -------------------------------------------------


def test_graph_group_ids_are_canonicalized_and_deduplicated():

    executor = RecordingExecutor(
        graph_result(
            [
                GROUP_TWO,
                GROUP_ONE.upper(),
                GROUP_ONE,
            ]
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    assert resolver.resolve_group_ids(
        OID
    ) == (
        GROUP_ONE,
        GROUP_TWO,
    )


@pytest.mark.parametrize(
    "invalid_value",
    [
        "not-a-list",
        None,
        {},
        123,
    ],
)
def test_invalid_graph_value_shape_fails_closed(
    invalid_value,
):

    executor = RecordingExecutor(
        graph_result(
            invalid_value
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    with pytest.raises(
        MicrosoftGraphGroupResolutionError
    ):

        resolver.resolve_group_ids(
            OID
        )


@pytest.mark.parametrize(
    "invalid_group",
    [
        "",
        "not-a-guid",
        123,
        None,
    ],
)
def test_invalid_graph_group_ids_fail_closed(
    invalid_group,
):

    executor = RecordingExecutor(
        graph_result(
            [
                invalid_group
            ]
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    with pytest.raises(
        MicrosoftGraphGroupResolutionError
    ):

        resolver.resolve_group_ids(
            OID
        )


def test_non_200_graph_response_fails_closed():

    executor = RecordingExecutor(
        graph_result(
            [],
            status_code=403,
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    with pytest.raises(
        MicrosoftGraphGroupResolutionError
    ):

        resolver.resolve_group_ids(
            OID
        )


def test_malformed_graph_json_fails_closed():

    executor = RecordingExecutor(
        GraphHttpResult(
            status_code=200,
            body=b"{not-json",
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    with pytest.raises(
        MicrosoftGraphGroupResolutionError
    ):

        resolver.resolve_group_ids(
            OID
        )


def test_graph_network_failure_fails_closed():

    def failing_executor(
        request,
        timeout,
    ):

        raise URLError(
            "network unavailable"
        )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            failing_executor,
    )

    with pytest.raises(
        MicrosoftGraphGroupResolutionError
    ):

        resolver.resolve_group_ids(
            OID
        )


def test_graph_result_size_over_limit_fails_closed():

    executor = RecordingExecutor(
        graph_result(
            [
                GROUP_ONE
            ]
            * 11001
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    with pytest.raises(
        MicrosoftGraphGroupResolutionError
    ):

        resolver.resolve_group_ids(
            OID
        )


# -------------------------------------------------
# TOKEN / INPUT HYGIENE
# -------------------------------------------------


@pytest.mark.parametrize(
    "invalid_token",
    [
        "",
        "   ",
        " token",
        "token ",
        None,
        123,
    ],
)
def test_invalid_graph_access_token_fails_before_request(
    invalid_token,
):

    executor = RecordingExecutor(
        graph_result(
            []
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda:
            invalid_token,
        request_executor=
            executor,
    )

    with pytest.raises(
        MicrosoftGraphGroupResolutionError
    ):

        resolver.resolve_group_ids(
            OID
        )

    assert executor.requests == []


@pytest.mark.parametrize(
    "invalid_oid",
    [
        "",
        "not-a-guid",
        None,
        123,
    ],
)
def test_invalid_directory_object_id_fails_before_graph_request(
    invalid_oid,
):

    executor = RecordingExecutor(
        graph_result(
            []
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    with pytest.raises(
        MicrosoftGraphGroupResolutionError
    ):

        resolver.resolve_group_ids(
            invalid_oid
        )

    assert executor.requests == []


def test_graph_error_does_not_echo_access_token():

    executor = RecordingExecutor(
        graph_result(
            [],
            status_code=500,
        )
    )

    resolver = MicrosoftGraphGroupResolver(
        lambda: GRAPH_TOKEN,
        request_executor=
            executor,
    )

    with pytest.raises(
        MicrosoftGraphGroupResolutionError
    ) as captured:

        resolver.resolve_group_ids(
            OID
        )

    assert GRAPH_TOKEN not in str(
        captured.value
    )


# -------------------------------------------------
# OVERAGE RESOLUTION
# -------------------------------------------------


def test_group_overage_resolves_to_authoritative_state():

    resolver = RecordingResolver(
        (
            GROUP_TWO,
            GROUP_ONE,
        )
    )

    resolved = (
        resolve_authoritative_group_membership(
            overage_evidence(),
            resolver=resolver,
        )
    )

    assert (
        resolved.group_membership_state
        == "resolved"
    )

    assert resolved.group_ids == (
        GROUP_ONE,
        GROUP_TWO,
    )

    assert (
        require_authoritative_group_ids(
            resolved
        )
        == (
            GROUP_ONE,
            GROUP_TWO,
        )
    )

    assert resolver.calls == [
        OID
    ]


def test_graph_resolution_preserves_app_roles():

    resolver = RecordingResolver(
        (
            GROUP_ONE,
        )
    )

    resolved = (
        resolve_authoritative_group_membership(
            overage_evidence(),
            resolver=resolver,
        )
    )

    assert resolved.app_roles == (
        "VM.Reader",
    )


def test_complete_inline_groups_do_not_call_graph():

    evidence = EnterpriseAuthorizationEvidence(
        app_roles=(),
        group_ids=(
            GROUP_ONE,
        ),
        group_membership_state=
            "complete",
    )

    resolver = RecordingResolver(
        (
            GROUP_TWO,
        )
    )

    result = (
        resolve_authoritative_group_membership(
            evidence,
            resolver=resolver,
        )
    )

    assert result is evidence

    assert resolver.calls == []


def test_already_resolved_groups_do_not_call_graph_again():

    evidence = EnterpriseAuthorizationEvidence(
        app_roles=(),
        group_ids=(
            GROUP_ONE,
        ),
        group_membership_state=
            "resolved",
        directory_object_id=
            OID,
    )

    resolver = RecordingResolver(
        (
            GROUP_TWO,
        )
    )

    result = (
        resolve_authoritative_group_membership(
            evidence,
            resolver=resolver,
        )
    )

    assert result is evidence

    assert resolver.calls == []


def test_missing_group_claim_fails_closed_without_graph():

    evidence = EnterpriseAuthorizationEvidence(
        app_roles=(),
        group_ids=(),
        group_membership_state=
            "not_present",
    )

    resolver = RecordingResolver(
        (
            GROUP_ONE,
        )
    )

    with pytest.raises(
        EnterpriseGroupMembershipUnavailable
    ):

        resolve_authoritative_group_membership(
            evidence,
            resolver=resolver,
        )

    assert resolver.calls == []


# -------------------------------------------------
# VALIDATED TOKEN PRESERVATION
# -------------------------------------------------


def test_resolving_groups_preserves_authenticated_identity():

    identity = EnterpriseIdentity(
        issuer=(
            "https://login.microsoftonline.com/"
            "11111111-1111-1111-1111-111111111111/"
            "v2.0"
        ),
        subject=
            "subject-123",
        identity_provider_tenant_id=(
            "11111111-1111-1111-1111-111111111111"
        ),
    )

    token = ValidatedEnterpriseToken(
        identity=identity,
        authorization=
            overage_evidence(),
    )

    resolved = (
        resolve_validated_token_group_membership(
            token,
            resolver=
                RecordingResolver(
                    (
                        GROUP_ONE,
                    )
                ),
        )
    )

    assert resolved.identity == (
        identity
    )

    assert (
        resolved.authorization
        .group_membership_state
        == "resolved"
    )

    assert (
        resolved.authorization.group_ids
        == (
            GROUP_ONE,
        )
    )
