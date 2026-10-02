# Production Security Observability Contract

## Status

This document defines the version 1 security observability contract for the
VM AI Agent.

It is the design authority for Step 50: Production Security Observability,
Audit Telemetry, and Detection.

The contract governs how existing security decisions are represented as
production telemetry. It does not create, replace, or weaken any
authorization boundary.

---

## 1. Purpose

The VM AI Agent already enforces security controls across enterprise identity,
tenant isolation, retrieval authorization, MCP sessions, human approval,
workflow execution, exact execution attempts, provider operations, and
reconciliation.

Step 50 makes those controls operationally observable.

The security observability layer must allow operators and detection systems
to answer questions such as:

- Which principal attempted an operation?
- Which authoritative tenant applied?
- Which MCP session was involved?
- Which workflow was affected?
- Which exact execution attempt was involved?
- Which provider correlation identifier was used?
- Was the operation allowed, denied, blocked, failed, ambiguous, or placed
  into review?
- Which security control produced the decision?
- Can related events be correlated across application instances?
- Can this evidence be produced without exposing secrets, sensitive prompts,
  or raw retrieved content?

---

## 2. Security Invariant

Security telemetry observes authority.

Security telemetry is not authority.

No audit event, event field, metric, trace identifier, request identifier,
log record, or telemetry sink may grant access, select a tenant, establish a
principal, authorize a workflow transition, authorize retrieval, authorize an
MCP operation, approve consequential action, or authorize provider execution.

All security authority continues to originate from the existing trusted
server-side security and workflow controls.

---

## 3. Existing Foundation

Step 50 builds on the repository's existing audit and security decision
surfaces rather than creating a parallel authorization system.

Existing code already contains:

- `log_event(...)` audit call sites;
- security event vocabulary;
- tenant-aware retrieval decisions;
- MCP session security decisions;
- workflow and approval decisions;
- exact workflow execution attempts;
- ServiceNow correlation identifiers;
- reconciliation decisions;
- prompt-injection security decisions;
- adversarial security evaluators.

Step 50.2 will introduce a normalized production security-event layer that
can receive events from these existing decision points.

Existing security controls remain authoritative.

---

## 4. Trust Boundary

### 4.1 Trusted telemetry context

A field may be treated as authoritative telemetry context only when its value
was obtained from trusted server-side state or from a security control that
already validated the value.

Examples include:

- authenticated server-derived principal context;
- server-derived tenant binding;
- server-created MCP session state;
- authoritative workflow state;
- authoritative execution-attempt state;
- validated ServiceNow correlation state;
- server-generated request/event identifiers.

### 4.2 Untrusted context

The following must never become authoritative merely because they appear in
an HTTP request, tool argument, model output, retrieved document, external
provider response, or caller-supplied payload:

- principal identifiers;
- tenant identifiers;
- session identifiers;
- workflow identifiers;
- execution-attempt identifiers;
- authorization results;
- approval state;
- roles;
- permissions;
- telemetry severity;
- telemetry outcome;
- telemetry reason codes.

Caller-controlled identifiers may be inspected or compared when necessary,
but authoritative telemetry correlation must use the server-owned value.

---

## 5. Threat Model

The production observability layer must address the following threats.

### OBS-01 ? Caller-controlled correlation spoofing

An attacker supplies a tenant, principal, session, workflow, execution, or
correlation identifier intended to make an event appear associated with
another security context.

Control:

Telemetry correlation uses trusted server-side context only.

### OBS-02 ? Secret leakage

Tokens, API keys, passwords, approval secrets, credentials, or provider
secrets are accidentally serialized into audit events.

Control:

The security-event serializer uses an explicit allowlist and rejects
forbidden sensitive fields.

### OBS-03 ? Sensitive AI-data leakage

Raw prompts, retrieved RAG document bodies, model output, or tool output are
written into operational security logs.

Control:

Only normalized event, decision, classification, count, and reason data may
be emitted.

### OBS-04 ? Log injection

Attacker-controlled strings inject newlines, fake event structures, terminal
control data, or misleading log records.

Control:

Production events are structured records. Free-form untrusted text is not
part of the v1 event contract.

### OBS-05 ? Telemetry as a confused deputy

The telemetry system accidentally becomes an alternate authorization or
tenant-selection mechanism.

Control:

No security decision may read authorization state back from telemetry.

### OBS-06 ? Audit suppression

An attacker or software failure prevents an event from reaching the primary
telemetry sink.

Control:

Event-emission failures are operational failures and must be observable.
They do not change the underlying authorization decision.

### OBS-07 ? Metric-cardinality exhaustion

Attacker-controlled or high-cardinality identifiers create unbounded metric
label cardinality.

Control:

Tenant IDs, principal references, session references, workflow IDs,
execution-attempt references, event IDs, ticket IDs, and provider correlation
IDs must never be metric labels.

### OBS-08 ? Cross-instance ambiguity

Events from different application instances cannot be reliably correlated.

Control:

All instances use the same schema version, canonical event names, UTC time,
server-generated event IDs, and authoritative domain correlation identifiers.

### OBS-09 ? Event replay or duplication

A sink, retry, or distributed execution path produces duplicate security
events.

Control:

Every event has a server-generated unique `event_id`. Consumers must be able
to deduplicate by `event_id`.

### OBS-10 ? False security evidence

A success event is emitted before the authoritative operation actually
succeeds, or a denial event misrepresents the control that produced it.

Control:

Events are emitted at explicit security decision points and carry normalized
outcomes and bounded reason codes.

---

## 6. Canonical Event Envelope ? Schema v1

Every production security event must conform to the following logical
envelope.

### 6.1 Required fields

| Field | Requirement |
| --- | --- |
| `schema_version` | Must be `1.0` for this contract |
| `event_id` | Server-generated unique event identifier |
| `event_type` | Canonical bounded event name |
| `occurred_at` | UTC timestamp |
| `severity` | Bounded security severity |
| `outcome` | Bounded normalized result |
| `source_component` | Bounded emitting component |

### 6.2 Optional trusted correlation fields

| Field | Meaning |
| --- | --- |
| `request_id` | Server-generated request correlation identifier |
| `principal_ref` | Non-secret/pseudonymous principal reference |
| `tenant_id` | Authoritative server-derived tenant identifier |
| `session_ref` | Non-secret MCP session correlation reference |
| `workflow_id` | Authoritative workflow identifier |
| `execution_attempt_ref` | Correlation reference derived from the authoritative exact execution attempt |
| `provider_correlation_id` | Validated non-secret provider correlation identifier |
| `resource_type` | Bounded target resource classification |
| `action` | Bounded attempted security action |
| `reason_code` | Bounded normalized reason |

The v1 envelope does not permit arbitrary free-form metadata or arbitrary
nested request/response payloads.

---

## 7. Server-Owned Event Identifiers

### `event_id`

`event_id` is generated by the application when the normalized security
event is created.

It must not be supplied by the caller.

### `request_id`

The current repository does not rely on a general request ID as security
authority.

Step 50 may introduce a server-generated request correlation ID for
observability.

An incoming request header must not become trusted authorization or tenant
context.

### `principal_ref`

Production telemetry should not require a raw username, email address, token
subject, or other directly identifying value when a stable correlation
reference is sufficient.

The exact derivation mechanism will be implemented in Step 50.2/50.3.

### `session_ref`

Where possible, session telemetry should use an existing non-secret session
correlation identifier rather than exposing a credential-like session value.

### `execution_attempt_ref`

The workflow system already maintains an authoritative
`execution_attempt_id`.

Telemetry may correlate to that exact authoritative attempt when the value is
non-secret.

The telemetry field is called `execution_attempt_ref` to make clear that the
value is correlation evidence and never execution authority.

### `provider_correlation_id`

Provider correlation values may be recorded only after they have passed the
existing trusted provider correlation validation.

---

## 8. Bounded Severity

Schema v1 supports:

- `info`
- `low`
- `medium`
- `high`
- `critical`

Severity describes the security significance of the individual event.

Detection rules may produce a higher-level alert severity from multiple
events later in Step 50.5.

---

## 9. Bounded Outcome

Schema v1 supports:

- `success`
- `allowed`
- `denied`
- `blocked`
- `failed`
- `ambiguous`
- `revoked`
- `review_required`

Event producers must not invent arbitrary outcome strings.

---

## 10. Canonical Event Taxonomy ? Schema v1

### 10.1 Identity and authentication

- `security.identity.authentication_succeeded`
- `security.identity.authentication_failed`
- `security.identity.principal_binding_failed`
- `security.identity.tenant_binding_denied`

### 10.2 Authorization

- `security.authorization.allowed`
- `security.authorization.denied`
- `security.authorization.cross_tenant_denied`

### 10.3 RAG

- `security.rag.retrieval_allowed`
- `security.rag.retrieval_denied`
- `security.rag.document_acl_denied`
- `security.rag.prompt_injection_blocked`

### 10.4 MCP and tooling

- `security.mcp.session_created`
- `security.mcp.session_validation_failed`
- `security.mcp.session_revoked`
- `security.mcp.tool_invocation_allowed`
- `security.mcp.tool_invocation_denied`
- `security.mcp.tool_output_injection_blocked`

### 10.5 Workflow and approval

- `security.workflow.created`
- `security.workflow.approval_granted`
- `security.workflow.approval_rejected`
- `security.workflow.transition_denied`
- `security.workflow.execution_claimed`
- `security.workflow.execution_claim_denied`
- `security.workflow.stale_processing_detected`
- `security.workflow.reconciliation_started`
- `security.workflow.reconciliation_resolved`
- `security.workflow.needs_review`

### 10.6 Provider and ServiceNow

- `security.provider.request_started`
- `security.provider.request_completed`
- `security.provider.result_correlated`
- `security.provider.result_ambiguous`
- `security.provider.reconciliation_denied`

### 10.7 AI security

- `security.ai.direct_prompt_injection_blocked`
- `security.ai.tool_output_prompt_injection_suspected`
- `security.ai.tool_output_prompt_injection_blocked`

The `security.ai.tool_output_prompt_injection_suspected` event
represents detection of prompt-injection-like content in a tool result
when the runtime records suspicion but does not block that result at the
same decision point. Its v1 `outcome` is `ambiguous`.

The `security.ai.tool_output_prompt_injection_blocked` event is reserved
for an enforcement point that actually blocks tool-output propagation.
A detector-only or suspicion-only path MUST NOT emit the blocked event.


---

## 11. Reason Codes

Reason codes are machine-readable bounded identifiers.

They must use lowercase snake case.

Initial reason vocabulary includes:

- `invalid_credentials`
- `principal_unbound`
- `tenant_unbound`
- `cross_tenant`
- `insufficient_role`
- `retrieval_acl_denied`
- `document_acl_denied`
- `session_missing`
- `session_expired`
- `session_revoked`
- `security_binding_mismatch`
- `prompt_injection_detected`
- `tool_not_authorized`
- `workflow_transition_not_allowed`
- `execution_already_claimed`
- `execution_attempt_mismatch`
- `stale_execution_attempt`
- `provider_correlation_mismatch`
- `provider_ambiguous`
- `reconciliation_denied`
- `needs_review`

New reason codes require an intentional schema-compatible change rather than
emission of arbitrary exception text.

---

## 12. Source Components

`source_component` is bounded.

Initial components include:

- `api`
- `auth`
- `agent`
- `retrieval_authorization`
- `retriever`
- `mcp_session`
- `mcp_server`
- `tool_dispatcher`
- `workflow`
- `execution`
- `workflow_store`
- `workflow_postgresql_store`
- `ticketing`
- `servicenow_provider`
- `servicenow_reconciliation`

This list may be extended intentionally as additional trusted emission points
are integrated.

---

## 13. Sensitive-Data Policy

### 13.1 Never record

The production security-event payload must never contain:

- bearer tokens;
- access tokens;
- refresh tokens;
- ID tokens;
- API keys;
- Tenable access keys;
- Tenable secret keys;
- passwords;
- client secrets;
- ServiceNow credentials;
- authorization headers;
- cookies;
- session credentials;
- one-time approval secrets;
- execution claim secrets;
- private keys;
- raw RAG document bodies;
- raw retrieved evidence;
- raw model prompts;
- raw model responses;
- raw tool output;
- arbitrary HTTP request bodies;
- arbitrary HTTP response bodies;
- arbitrary provider request bodies;
- arbitrary provider response bodies.

### 13.2 Do not treat caller claims as authority

Caller-supplied values describing:

- identity;
- principal;
- tenant;
- role;
- permission;
- workflow authority;
- approval authority;
- execution authority;

must never be recorded as though they were authoritative security context.

### 13.3 Normalize before recording

The following may be recorded only as bounded normalized values:

- exception/error category;
- denial reason;
- authorization result;
- provider result;
- prompt-injection result;
- reconciliation result;
- workflow state.

Raw exception text is not part of the v1 security-event contract.

---

## 14. Metrics Contract

Metrics summarize security behavior but are not audit records.

Allowed examples include counters such as:

- authentication failures;
- authorization denials;
- cross-tenant denials;
- retrieval denials;
- prompt-injection blocks;
- MCP validation failures;
- session revocations;
- workflow transition denials;
- execution claim denials;
- stale-processing detections;
- reconciliation operations;
- `NEEDS_REVIEW` transitions;
- provider ambiguous outcomes.

### 14.1 Metric labels

Metric labels must be low-cardinality bounded values such as:

- event type;
- outcome;
- reason code;
- source component;
- provider type.

The following must never be metric labels:

- `event_id`;
- `request_id`;
- `principal_ref`;
- `tenant_id`;
- `session_ref`;
- `workflow_id`;
- `execution_attempt_ref`;
- ticket identifiers;
- `provider_correlation_id`;
- usernames;
- email addresses.

---

## 15. Event Emission Semantics

Security events are emitted after or at the authoritative decision point they
describe.

Examples:

- an authorization-denied event follows an actual authorization denial;
- an execution-claimed event represents a successful authoritative claim;
- an execution-claim-denied event represents a rejected claim;
- a session-revoked event represents authoritative revocation;
- a provider-result-correlated event represents validated correlation;
- a provider-result-ambiguous event represents an actual ambiguous provider
  result;
- a `needs_review` event represents an authoritative transition to review.

Telemetry must never predict a state transition that has not occurred.

---

## 16. Emission-Failure Semantics

Telemetry failure must not create authority.

A security-event sink failure:

- must not convert a deny into an allow;
- must not select a tenant;
- must not approve a workflow;
- must not create an execution claim;
- must not rotate an execution attempt;
- must not change reconciliation state.

The underlying security decision remains authoritative.

Step 50.2 will define a safe local fallback/failure reporting mechanism so
that telemetry failures themselves remain operationally visible.

---

## 17. Distributed and Multi-Instance Semantics

All application instances must emit schema-compatible records.

The system does not assume total event ordering across instances.

Correlation relies on:

- unique `event_id`;
- UTC `occurred_at`;
- authoritative tenant context;
- session correlation;
- workflow ID;
- exact execution-attempt correlation;
- provider correlation.

Consumers must tolerate events arriving late or out of order.

Duplicate delivery must be deduplicable by `event_id`.

---

## 18. Audit Integrity

The application must not permit a remote caller or model-generated payload to
modify an event after normalization.

Production telemetry sinks should support append-oriented or otherwise
tamper-resistant storage appropriate to the deployment.

Audit-integrity implementation and validation are part of Step 50.6.

---

## 19. Relationship to Existing `log_event(...)`

Existing `log_event(...)` calls are security evidence already distributed
through important code paths.

Step 50 does not require immediate replacement of those call sites.

Step 50.2 will introduce a normalized structured security-event API and then
adapt existing audit emission points incrementally.

The adapter must:

1. preserve existing security behavior;
2. map bounded existing events into the canonical taxonomy where applicable;
3. derive correlation only from trusted server-owned state;
4. enforce the sensitive-data allowlist before serialization;
5. reject unsafe telemetry payload fields;
6. remain independent from authorization decisions.

---

## 20. Compatibility

Schema version `1.0` is the initial production event contract.

Compatible changes may add optional bounded fields or new documented event
types.

Breaking changes include:

- removing required fields;
- changing the meaning of an existing event type;
- changing authority semantics;
- permitting previously prohibited sensitive content;
- changing an identifier from correlation-only into authorization authority.

Breaking changes require a new schema version.

---

## 21. Step 50 Implementation Sequence

This contract governs the following implementation sequence:

### 50.2 ? Structured security audit events

Implement the canonical event model, serializer, sensitive-field enforcement,
and adapters for selected existing security decision points.

### 50.3 ? Correlation and traceability

Implement server-generated request correlation and trusted correlation across
principal, tenant, session, workflow, exact execution attempt, and provider
result.

### 50.4 ? Security metrics

Derive bounded low-cardinality security metrics.

### 50.5 ? Detection rules and alerting

Detect attack patterns and suspicious control failures from structured
events.

### 50.6 ? Audit integrity and sensitive-data controls

Strengthen telemetry integrity, redaction/rejection behavior, and sink
failure handling.

### 50.7 ? Adversarial observability evaluation

Verify hostile activity produces expected telemetry without misleading benign
alerts.

### 50.8 ? PostgreSQL and multi-instance telemetry testing

Verify distributed instances preserve event schema and correlation
semantics.

### 50.9 ? Architecture, NIST AI RMF, README, CI, PR, and merge

Document and validate the completed production observability capability.

---

## 22. Acceptance Criteria for Step 50

Step 50 is complete only when:

- production security events use a canonical schema;
- security event fields are allowlisted;
- forbidden sensitive fields cannot be serialized;
- correlation is derived from trusted server-owned context;
- existing security authority remains unchanged;
- exact workflow execution attempts are observable;
- MCP security decisions are observable;
- RAG authorization decisions are observable;
- provider and reconciliation decisions are observable;
- prompt-injection blocks are observable;
- low-cardinality metrics are available;
- detection rules cover priority attack patterns;
- adversarial tests validate expected events;
- benign tests validate acceptable false-positive behavior;
- PostgreSQL-backed multi-instance tests validate correlation;
- architecture and NIST AI RMF documentation describe the controls.

---

## 23. Core Principle

The objective of Step 50 is not to create more authority.

The objective is to make existing authority observable, measurable,
correlatable, detectable, and defensible in production without exposing the
sensitive information those controls are designed to protect.

### MCP tool-dispatch observability provenance

Canonical `security.mcp.tool_invocation_allowed` and
`security.mcp.tool_invocation_denied` events emitted by the shared tool
dispatcher require an explicit server-controlled MCP telemetry-origin
marker on `ToolExecutionContext`.

The telemetry-origin marker is observability metadata only. It MUST NOT
grant tool access, change tool visibility, select a tenant, establish a
principal, validate a session, or otherwise participate in an
authorization decision.

The presence of `SecurityContext` alone MUST NOT be treated as proof of
MCP provenance. Ordinary or future non-MCP execution paths may also use
trusted security context.

Raw tool names, raw MCP session identifiers, credentials, tokens, and
caller-supplied provenance values MUST NOT be copied into canonical MCP
tool-invocation events.

### Canonical session correlation

Canonical `session_ref` is a non-secret observability reference derived
only from an authoritative server-side session identifier.

For the current v1 runtime, the canonical derivation is:

`sha256(session_id).hexdigest()[:16]`

This is the same stable correlation derivation already used by
`SecurityContext.session_correlation_id` and the MCP session manager.

`session_ref` MUST NOT contain a raw session identifier.

`session_ref` MUST NOT be derived from an attempted session identifier
when no authoritative session record exists. Therefore a
`session_not_found` event omits `session_ref`.

For an existing authoritative MCP session, validation failures and
successful revocation MAY include the derived `session_ref`.

For MCP tool dispatch, `session_ref` MAY be populated from the immutable
trusted `SecurityContext.session_correlation_id`.

`session_ref` is observability metadata only. It MUST NOT establish,
validate, restore, revoke, or otherwise influence session authority.
Exact session authority continues to depend on the underlying
server-controlled session state and validation logic.

### Workflow and execution-attempt correlation

Canonical workflow telemetry distinguishes the persisted workflow
identifier from the exact execution-attempt authority value.

#### `workflow_id`

Canonical `workflow_id` MAY contain the exact workflow identifier only
after that value has been obtained from authoritative server-side
workflow state, such as a persisted `WorkflowResult` returned by the
workflow store.

An HTTP path value, request parameter, model-generated value, provider
response, or other caller-supplied string MUST NOT become authoritative
canonical workflow correlation merely because it resembles a workflow
identifier.

#### `execution_attempt_ref`

The exact `execution_attempt_id` participates in execution authority,
including exact-attempt equality checks, compare-and-swap transitions,
completion, recovery, and reconciliation.

Canonical security telemetry therefore MUST NOT copy the raw
`execution_attempt_id` into `execution_attempt_ref`.

The v1 canonical execution-attempt reference is derived as:

`EA1-` + SHA-256(
`vm-ai-security-observability:execution-attempt-ref:v1`
+ trusted `tenant_id`
+ authoritative `workflow_id`
+ authoritative `execution_attempt_id`
)

The inputs are separated with the application correlation delimiter
before hashing.

The reference is deterministic for the same authoritative execution
attempt and changes if the tenant, workflow, or execution-attempt value
changes.

`execution_attempt_ref` is pseudonymous observability metadata. It is
not an execution credential, capability, approval token, workflow
transition token, or substitute for the exact execution-attempt ID.

All existing checks involving `expected_execution_attempt_id` MUST
continue to compare against the exact authoritative
`execution_attempt_id`.

No metric label may contain `workflow_id`, `execution_attempt_ref`, or
the raw `execution_attempt_id`.

Correlation observes authority. Correlation is never authority.

### Authoritative workflow execution event correlation

Canonical workflow execution events MUST be emitted only after the
corresponding authoritative workflow decision or state transition has
occurred.

For `security.workflow.execution_claimed`, correlation is taken from the
`WorkflowResult` returned by the authoritative claim operation.

For `security.workflow.needs_review`, correlation is taken from the
authoritative `WorkflowResult` returned after the NEEDS_REVIEW transition
has succeeded.

For stale PROCESSING recovery, the successful recovery result establishes
both that stale processing was detected and that the workflow was moved to
NEEDS_REVIEW. The runtime MAY therefore emit both
`security.workflow.stale_processing_detected` and
`security.workflow.needs_review` after that operation returns.

Legacy tenant-unbound workflows MAY emit authoritative `workflow_id` but
MUST omit `execution_attempt_ref`, because the v1 attempt-reference
derivation requires an authoritative tenant binding.

The generic execution-layer claim-denial handler does not possess an
authoritative returned workflow object. It MUST NOT copy its incoming
`workflow_id` argument into canonical `workflow_id` or derive
`execution_attempt_ref` from that caller-facing value.

Canonical claim-denial correlation should instead be emitted at a deeper
workflow-store authority point where the persisted workflow state and
specific denial reason are known.

Existing raw `execution_attempt_id` values in legacy audit records remain
a migration concern for the sensitive-data-control phase. New canonical
security events MUST NOT copy that raw authority value.

Correlation observes authority. Correlation is never authority.
