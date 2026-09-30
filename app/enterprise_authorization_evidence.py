from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import ValidationError
from pydantic import field_validator
from pydantic import model_validator

from app.enterprise_identity import EnterpriseIdentity


GroupMembershipState = Literal[
    "not_present",
    "complete",
    "overage",
    "resolved",
]


class EnterpriseGroupMembershipUnavailable(
    RuntimeError
):
    """
    Raised when complete authoritative group membership
    is not available for a security decision.
    """


# -------------------------------------------------
# AUTHORIZATION EVIDENCE
# -------------------------------------------------


class EnterpriseAuthorizationEvidence(BaseModel):
    """
    Immutable authorization evidence extracted only after
    successful cryptographic validation of an enterprise
    access token.

    This object contains IdP evidence, not application
    authorization decisions.

    app_roles:
        Microsoft Entra app-role values from the validated
        roles claim.

    group_ids:
        Canonical Microsoft Entra group object IDs only when
        the token contains a complete groups claim.

    group_membership_state:
        not_present
            The token did not contain group membership data.
            This MUST NOT be interpreted as zero membership.

        complete
            The token contained the complete inline groups
            claim available to this application.

        overage
            Microsoft Entra indicated that group memberships
            exceeded the token limit. Group-based decisions
            must fail closed until an authoritative resolver
            obtains the full membership set.

        resolved
            Complete group membership was retrieved through
            a trusted Microsoft Graph resolution path after
            token group overage.

    directory_object_id:
        Validated oid claim when available. It is required
        for the overage state so a later trusted Graph
        resolver can identify the subject without relying
        on mutable names or email addresses.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    app_roles: tuple[
        str,
        ...,
    ] = ()

    group_ids: tuple[
        str,
        ...,
    ] = ()

    group_membership_state: (
        GroupMembershipState
    ) = "not_present"

    directory_object_id: str | None = None

    @field_validator(
        "app_roles",
        mode="before",
    )
    @classmethod
    def normalize_app_roles(
        cls,
        value,
    ) -> tuple[str, ...]:

        if not isinstance(
            value,
            (
                list,
                tuple,
            ),
        ):
            raise ValueError(
                "Enterprise app roles must be "
                "a sequence."
            )

        normalized: list[str] = []

        for item in value:

            if (
                not isinstance(
                    item,
                    str,
                )
                or not item.strip()
            ):
                raise ValueError(
                    "Enterprise app roles must "
                    "contain non-empty strings."
                )

            normalized.append(
                item.strip()
            )

        return tuple(
            sorted(
                set(
                    normalized
                )
            )
        )

    @field_validator(
        "group_ids",
        mode="before",
    )
    @classmethod
    def normalize_group_ids(
        cls,
        value,
    ) -> tuple[str, ...]:

        if not isinstance(
            value,
            (
                list,
                tuple,
            ),
        ):
            raise ValueError(
                "Enterprise group IDs must be "
                "a sequence."
            )

        normalized: list[str] = []

        for item in value:

            if (
                not isinstance(
                    item,
                    str,
                )
                or not item.strip()
            ):
                raise ValueError(
                    "Enterprise group IDs must "
                    "contain GUID strings."
                )

            try:

                canonical = str(
                    UUID(
                        item.strip()
                    )
                )

            except ValueError as exc:

                raise ValueError(
                    "Enterprise group IDs must "
                    "contain valid GUIDs."
                ) from exc

            normalized.append(
                canonical
            )

        return tuple(
            sorted(
                set(
                    normalized
                )
            )
        )

    @field_validator(
        "directory_object_id",
        mode="before",
    )
    @classmethod
    def normalize_directory_object_id(
        cls,
        value,
    ) -> str | None:

        if value is None:
            return None

        if (
            not isinstance(
                value,
                str,
            )
            or not value.strip()
        ):
            raise ValueError(
                "Directory object ID must be "
                "a valid GUID."
            )

        try:

            return str(
                UUID(
                    value.strip()
                )
            )

        except ValueError as exc:

            raise ValueError(
                "Directory object ID must be "
                "a valid GUID."
            ) from exc

    @model_validator(
        mode="after"
    )
    def validate_group_state(
        self,
    ) -> "EnterpriseAuthorizationEvidence":

        if (
            self.group_membership_state
            not in (
                "complete",
                "resolved",
            )
            and self.group_ids
        ):
            raise ValueError(
                "Group IDs require complete "
                "group membership state."
            )

        if (
            self.group_membership_state
            == "overage"
            and self.directory_object_id is None
        ):
            raise ValueError(
                "Group overage requires an "
                "authoritative directory object ID."
            )

        return self


# -------------------------------------------------
# VALIDATED TOKEN RESULT
# -------------------------------------------------


class ValidatedEnterpriseToken(BaseModel):
    """
    Result of cryptographic token validation.

    Raw token material is intentionally excluded.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    identity: EnterpriseIdentity

    authorization: (
        EnterpriseAuthorizationEvidence
    )


# -------------------------------------------------
# REQUIRE COMPLETE GROUP AUTHORITY
# -------------------------------------------------


def require_authoritative_group_ids(
    evidence: EnterpriseAuthorizationEvidence,
) -> tuple[str, ...]:
    """
    Return group membership only when the validator proved
    that the token carried a complete groups claim.

    Missing claims and group overage both fail closed.
    """

    if (
        evidence.group_membership_state
        not in (
            "complete",
            "resolved",
        )
    ):
        raise EnterpriseGroupMembershipUnavailable(
            "Complete enterprise group membership "
            "is not available."
        )

    return evidence.group_ids
