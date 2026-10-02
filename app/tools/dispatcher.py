from dataclasses import dataclass
from enum import Enum

from app.auth import Principal
from app.security_context import SecurityContext
from app.audit import log_event
from app.security_observability_integrations import (
    emit_mcp_tool_invocation_allowed_security_event,
    emit_mcp_tool_invocation_denied_security_event,
)

from app.models import (
    AssetContext,
    RiskResult,
    VulnerabilityFinding,
)

from app.retriever import KnowledgeRetriever

from app.tools.assets import (
    get_asset_details,
)

from app.tools.findings import (
    get_finding,
)

from app.tools.knowledge import (
    search_knowledge,
)

from app.tools.registry import (
    get_tool_spec,
)

from app.tools.threat_intel import (
    get_threat_intel,
)


# -------------------------------------------------
# TRUSTED TOOL EXECUTION CONTEXT
# -------------------------------------------------




class ToolInvocationTelemetryOrigin(str, Enum):
    """Bounded observability provenance; never authorization."""

    MCP = "mcp"

@dataclass(
    frozen=True
)
class ToolExecutionContext:

    principal: Principal

    security_context: SecurityContext | None = None
    telemetry_origin: ToolInvocationTelemetryOrigin | None = None

    finding: VulnerabilityFinding | None = None

    asset: AssetContext | None = None

    risk: RiskResult | None = None

    retriever: KnowledgeRetriever | None = None


    def __post_init__(
        self,
    ) -> None:

        self.validate_security_binding()




    def audit_identity_fields(
        self,
    ) -> dict[str, str]:
        """
        Return trusted identity metadata for security
        audit events.

        Raw MCP session identifiers are deliberately
        excluded.
        """

        fields = {
            "username":
                self.principal.username,

            "role":
                self.principal.role,
        }

        security_context = (
            self.security_context
        )

        if security_context is None:
            return fields

        fields.update(
            {
                "principal_id":
                    security_context.principal_id,

                "tenant_id":
                    security_context.tenant_id,

                "retrieval_access":
                    security_context.retrieval_access,

                "session_correlation_id":
                    security_context
                    .session_correlation_id,
            }
        )

        return fields

    def validate_security_binding(
        self,
    ) -> None:
        """
        Fail closed if authenticated Principal claims
        diverge from the trusted immutable security
        context.

        Validation occurs both at context creation and
        again immediately before dispatch because the
        Principal object itself is mutable.
        """

        security_context = (
            self.security_context
        )

        # Legacy/non-MCP contexts remain supported while
        # MCP session isolation is introduced
        # incrementally.
        if security_context is None:
            return

        if (
            security_context.principal_id
            != self.principal.username
        ):
            raise ValueError(
                "Tool execution security context "
                "principal mismatch."
            )

        if (
            security_context.role
            != self.principal.role
        ):
            raise ValueError(
                "Tool execution security context "
                "role mismatch."
            )

        if (
            security_context.retrieval_access
            != self.principal.retrieval_access
        ):
            raise ValueError(
                "Tool execution security context "
                "retrieval access mismatch."
            )



def _trusted_mcp_telemetry_tenant_id(
    context: ToolExecutionContext,
) -> str | None:
    """
    Return trusted tenant correlation only for an explicitly
    server-marked MCP telemetry context.

    This function is observability-only and is never consulted by
    authorization.
    """

    if (
        context.telemetry_origin
        is not ToolInvocationTelemetryOrigin.MCP
    ):
        return None

    security_context = (
        context.security_context
    )

    if security_context is None:
        return None

    return security_context.tenant_id


def _emit_mcp_tool_allowed_if_trusted(
    context: ToolExecutionContext,
) -> None:

    tenant_id = (
        _trusted_mcp_telemetry_tenant_id(
            context
        )
    )

    if tenant_id is None:
        return

    emit_mcp_tool_invocation_allowed_security_event(
        tenant_id=tenant_id,
    )


def _emit_mcp_tool_denied_if_trusted(
    context: ToolExecutionContext,
    *,
    reason: str,
) -> None:

    tenant_id = (
        _trusted_mcp_telemetry_tenant_id(
            context
        )
    )

    if tenant_id is None:
        return

    emit_mcp_tool_invocation_denied_security_event(
        tenant_id=tenant_id,
        reason=reason,
    )


# -------------------------------------------------
# LLM TOOL DISPATCHER
# -------------------------------------------------


def dispatch_llm_tool(
    tool_name: str,
    context: ToolExecutionContext,
):

    # Security-significant identity claims are checked
    # again at execution time so mutable Principal state
    # cannot drift from the trusted session context.
    try:
        context.validate_security_binding()

    except ValueError:
        _emit_mcp_tool_denied_if_trusted(
            context,
            reason="security_binding_mismatch",
        )

        raise

    log_event(
        "LLM_TOOL_DISPATCH_REQUESTED",
        {
            "tool": tool_name,
            **context.audit_identity_fields(),
        },
    )

    # -------------------------------------------------
    # 1. REQUIRE REGISTERED TOOL
    # -------------------------------------------------

    try:

        spec = get_tool_spec(
            tool_name
        )

    except KeyError:

        log_event(
            "LLM_TOOL_DISPATCH_BLOCKED",
            {
                "tool": tool_name,
                **context.audit_identity_fields(),
                "reason":
                    "unknown_tool",
            },
        )

        _emit_mcp_tool_denied_if_trusted(
            context,
            reason="tool_not_authorized",
        )

        raise

    # -------------------------------------------------
    # 2. REQUIRE LLM VISIBILITY
    # -------------------------------------------------

    if not spec.llm_visible:

        log_event(
            "LLM_TOOL_DISPATCH_BLOCKED",
            {
                "tool": tool_name,
                **context.audit_identity_fields(),
                "reason":
                    "tool_not_llm_visible",
            },
        )

        _emit_mcp_tool_denied_if_trusted(
            context,
            reason="tool_not_authorized",
        )

        raise PermissionError(
            "Tool is not available "
            "to the LLM."
        )

    # -------------------------------------------------
    # 3. LLM MAY ONLY DISPATCH READ TOOLS
    # -------------------------------------------------

    if spec.kind != "read":

        log_event(
            "LLM_TOOL_DISPATCH_BLOCKED",
            {
                "tool": tool_name,
                **context.audit_identity_fields(),
                "reason":
                    "non_read_tool",
            },
        )

        _emit_mcp_tool_denied_if_trusted(
            context,
            reason="tool_not_authorized",
        )

        raise PermissionError(
            "LLM tool dispatch is restricted "
            "to read-only tools."
        )

    _emit_mcp_tool_allowed_if_trusted(
        context
    )

    # -------------------------------------------------
    # 4. DISPATCH ALLOWLISTED TOOL
    # -------------------------------------------------

    if tool_name == "get_finding":

        result = get_finding(
            principal=
                context.principal,
        )

    elif tool_name == "get_asset_details":

        result = get_asset_details(
            principal=
                context.principal,
        )

    elif tool_name == "get_threat_intel":

        result = get_threat_intel(
            principal=
                context.principal,
        )

    elif tool_name == "search_knowledge":

        if (
            context.finding is None
            or context.asset is None
            or context.risk is None
            or context.retriever is None
        ):

            raise ValueError(
                "search_knowledge requires "
                "server-controlled finding, "
                "asset, risk, and retriever "
                "context."
            )

        result = search_knowledge(
            principal=
                context.principal,

            finding=
                context.finding,

            asset=
                context.asset,

            risk=
                context.risk,

            retriever=
                context.retriever,

            security_context=
                context.security_context,
        )

    else:

        # Defense in depth.
        #
        # Registry entries must also have an
        # explicit dispatcher implementation.

        raise KeyError(
            f"No dispatcher implementation "
            f"for tool: {tool_name}"
        )

    # -------------------------------------------------
    # 5. AUDIT SUCCESSFUL DISPATCH
    # -------------------------------------------------

    log_event(
        "LLM_TOOL_DISPATCHED",
        {
            "tool": tool_name,
            **context.audit_identity_fields(),
        },
    )

    return result
