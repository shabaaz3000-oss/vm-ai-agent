from __future__ import annotations

from dataclasses import dataclass

import json

from typing import Callable
from typing import Protocol

from urllib.error import HTTPError
from urllib.error import URLError

from urllib.request import Request
from urllib.request import urlopen

from uuid import UUID

from pydantic import ValidationError

from app.enterprise_authorization_evidence import (
    EnterpriseAuthorizationEvidence,
    EnterpriseGroupMembershipUnavailable,
    ValidatedEnterpriseToken,
)


# -------------------------------------------------
# FIXED GRAPH AUTHORITY
# -------------------------------------------------


MICROSOFT_GRAPH_V1 = (
    "https://graph.microsoft.com/v1.0"
)

MAX_GRAPH_GROUP_IDS = 11000


# -------------------------------------------------
# GRAPH FAILURE
# -------------------------------------------------


class MicrosoftGraphGroupResolutionError(
    RuntimeError
):
    """
    Raised when complete group membership cannot be obtained
    from the trusted Microsoft Graph resolution path.

    Access tokens, object IDs, HTTP response bodies, and Graph
    internals are intentionally excluded from public errors.
    """


# -------------------------------------------------
# HTTP RESULT
# -------------------------------------------------


@dataclass(
    frozen=True
)
class GraphHttpResult:

    status_code: int

    body: bytes


# -------------------------------------------------
# RESOLVER CONTRACT
# -------------------------------------------------


class EnterpriseGroupResolver(
    Protocol
):

    def resolve_group_ids(
        self,
        directory_object_id: str,
    ) -> tuple[str, ...]:
        ...


GraphAccessTokenProvider = Callable[
    [],
    str,
]

GraphRequestExecutor = Callable[
    [
        Request,
        float,
    ],
    GraphHttpResult,
]


# -------------------------------------------------
# DEFAULT HTTP EXECUTOR
# -------------------------------------------------


def _execute_graph_request(
    request: Request,
    timeout_seconds: float,
) -> GraphHttpResult:

    with urlopen(
        request,
        timeout=timeout_seconds,
    ) as response:

        return GraphHttpResult(
            status_code=
                response.status,
            body=
                response.read(),
        )


# -------------------------------------------------
# MICROSOFT GRAPH GROUP RESOLVER
# -------------------------------------------------


class MicrosoftGraphGroupResolver:
    """
    Resolve Entra group overage using a trusted Microsoft
    Graph access token supplied by server-side authentication.

    Security properties:

    - Graph URL is fixed server-side
    - user object is identified by validated oid
    - token-supplied distributed-claim URLs are never used
    - VM API access tokens are not accepted as input here
    - Graph bearer token comes only from a server token provider
    - network and response failures fail closed
    - returned group IDs must be canonical GUIDs
    """

    def __init__(
        self,
        graph_access_token_provider:
            GraphAccessTokenProvider,
        *,
        request_executor:
            GraphRequestExecutor
            | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:

        if (
            not isinstance(
                timeout_seconds,
                (
                    int,
                    float,
                ),
            )
            or timeout_seconds <= 0
            or timeout_seconds > 30
        ):
            raise ValueError(
                "Microsoft Graph timeout must be "
                "between 0 and 30 seconds."
            )

        self._graph_access_token_provider = (
            graph_access_token_provider
        )

        self._request_executor = (
            request_executor
            if request_executor is not None
            else _execute_graph_request
        )

        self._timeout_seconds = float(
            timeout_seconds
        )

    def resolve_group_ids(
        self,
        directory_object_id: str,
    ) -> tuple[str, ...]:
        """
        Return complete transitive group membership for one
        validated Entra directory object ID.
        """

        try:

            canonical_oid = str(
                UUID(
                    directory_object_id
                )
            )

        except (
            ValueError,
            TypeError,
            AttributeError,
        ) as exc:

            raise MicrosoftGraphGroupResolutionError(
                "Microsoft Graph group resolution failed."
            ) from exc

        graph_token = (
            self._graph_access_token_provider()
        )

        if (
            not isinstance(
                graph_token,
                str,
            )
            or not graph_token.strip()
            or graph_token != graph_token.strip()
        ):
            raise MicrosoftGraphGroupResolutionError(
                "Microsoft Graph group resolution failed."
            )

        url = (
            f"{MICROSOFT_GRAPH_V1}"
            f"/users/{canonical_oid}"
            f"/getMemberGroups"
        )

        request_body = json.dumps(
            {
                "securityEnabledOnly": False
            }
        ).encode(
            "utf-8"
        )

        request = Request(
            url=url,
            data=request_body,
            headers={
                "Authorization":
                    f"Bearer {graph_token}",
                "Content-Type":
                    "application/json",
                "Accept":
                    "application/json",
            },
            method="POST",
        )

        try:

            result = (
                self._request_executor(
                    request,
                    self._timeout_seconds,
                )
            )

        except (
            HTTPError,
            URLError,
            OSError,
            TimeoutError,
        ) as exc:

            raise MicrosoftGraphGroupResolutionError(
                "Microsoft Graph group resolution failed."
            ) from exc

        if not isinstance(
            result,
            GraphHttpResult,
        ):
            raise MicrosoftGraphGroupResolutionError(
                "Microsoft Graph group resolution failed."
            )

        if result.status_code != 200:
            raise MicrosoftGraphGroupResolutionError(
                "Microsoft Graph group resolution failed."
            )

        try:

            payload = json.loads(
                result.body.decode(
                    "utf-8"
                )
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:

            raise MicrosoftGraphGroupResolutionError(
                "Microsoft Graph group resolution failed."
            ) from exc

        if not isinstance(
            payload,
            dict,
        ):
            raise MicrosoftGraphGroupResolutionError(
                "Microsoft Graph group resolution failed."
            )

        raw_group_ids = payload.get(
            "value"
        )

        if not isinstance(
            raw_group_ids,
            list,
        ):
            raise MicrosoftGraphGroupResolutionError(
                "Microsoft Graph group resolution failed."
            )

        if len(
            raw_group_ids
        ) > MAX_GRAPH_GROUP_IDS:
            raise MicrosoftGraphGroupResolutionError(
                "Microsoft Graph group resolution failed."
            )

        canonical_groups: set[str] = set()

        for item in raw_group_ids:

            if not isinstance(
                item,
                str,
            ):
                raise MicrosoftGraphGroupResolutionError(
                    "Microsoft Graph group resolution failed."
                )

            try:

                canonical_groups.add(
                    str(
                        UUID(
                            item.strip()
                        )
                    )
                )

            except ValueError as exc:

                raise MicrosoftGraphGroupResolutionError(
                    "Microsoft Graph group resolution failed."
                ) from exc

        return tuple(
            sorted(
                canonical_groups
            )
        )


# -------------------------------------------------
# AUTHORITATIVE MEMBERSHIP RESOLUTION
# -------------------------------------------------


def resolve_authoritative_group_membership(
    evidence: EnterpriseAuthorizationEvidence,
    *,
    resolver: EnterpriseGroupResolver,
) -> EnterpriseAuthorizationEvidence:
    """
    Guarantee complete group authority or fail closed.

    complete:
        Already authoritative from validated inline claim.

    resolved:
        Already authoritative from trusted Graph resolution.

    overage:
        Resolve using validated oid and trusted Graph client.

    not_present:
        No complete group authority is available.
    """

    if (
        evidence.group_membership_state
        in (
            "complete",
            "resolved",
        )
    ):
        return evidence

    if (
        evidence.group_membership_state
        == "not_present"
    ):
        raise EnterpriseGroupMembershipUnavailable(
            "Complete enterprise group membership "
            "is not available."
        )

    if (
        evidence.group_membership_state
        != "overage"
        or evidence.directory_object_id is None
    ):
        raise EnterpriseGroupMembershipUnavailable(
            "Complete enterprise group membership "
            "is not available."
        )

    resolved_group_ids = (
        resolver.resolve_group_ids(
            evidence.directory_object_id
        )
    )

    try:

        return EnterpriseAuthorizationEvidence(
            app_roles=
                evidence.app_roles,
            group_ids=
                resolved_group_ids,
            group_membership_state=
                "resolved",
            directory_object_id=
                evidence.directory_object_id,
        )

    except ValidationError as exc:

        raise MicrosoftGraphGroupResolutionError(
            "Microsoft Graph group resolution failed."
        ) from exc


def resolve_validated_token_group_membership(
    validated_token: ValidatedEnterpriseToken,
    *,
    resolver: EnterpriseGroupResolver,
) -> ValidatedEnterpriseToken:
    """
    Preserve the authenticated identity while replacing an
    overage authorization state with complete trusted group
    membership.
    """

    authorization = (
        resolve_authoritative_group_membership(
            validated_token.authorization,
            resolver=resolver,
        )
    )

    return ValidatedEnterpriseToken(
        identity=
            validated_token.identity,
        authorization=
            authorization,
    )
