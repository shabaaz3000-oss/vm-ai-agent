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

### Authoritative execution-claim denial telemetry

SQLite and PostgreSQL workflow stores emit
`security.workflow.execution_claim_denied` only beside existing
authoritative execution-claim denial decisions.

Telemetry remains observational and best-effort. It MUST NOT participate
in workflow lookup, execution eligibility, tenant validation,
execution-attempt generation, locking, compare-and-swap behavior,
winner selection, or any later workflow transition.

When authoritative persisted status is not `AWAITING_APPROVAL`, the
canonical denial reason is:

- `execution_already_claimed` when persisted status is `PROCESSING`;
- otherwise `workflow_transition_not_allowed`.

That decision occurs before an authoritative `WorkflowResult` has been
parsed. The canonical event therefore omits `workflow_id`, `tenant_id`,
and `execution_attempt_ref` rather than promoting the incoming lookup
identifier into trusted correlation.

For a tenant-bound workflow with no trusted `SecurityContext`,
`security_binding_mismatch` is emitted using only the already parsed
authoritative workflow's `workflow_id` and persisted tenant binding.

When the existing tenant-authority check raises
`WorkflowTenantBindingError`, canonical telemetry is emitted before the
same exception is re-raised unchanged.

If the normalized persisted workflow tenant differs from the trusted
security-context tenant, the reason is `cross_tenant`. Canonical
`tenant_id` is the persisted authoritative workflow tenant, never the
mismatching caller tenant.

If persisted tenant authority cannot safely be used as normalized
canonical correlation, the reason is `security_binding_mismatch` and the
invalid tenant value is omitted.

A failed execution-claim compare-and-swap is reported as
`execution_already_claimed`. The freshly generated candidate
`execution_attempt_id` MUST NOT be emitted, hashed, or converted into
`execution_attempt_ref`, because the losing claimant did not establish
that candidate attempt as persisted execution authority.

The current SQLite and PostgreSQL claim implementations do not re-read
the winning workflow after a failed claim CAS. Consequently a CAS-loser
event contains only authoritative workflow and tenant correlation that
was already available before the attempted mutation, and contains no
execution-attempt correlation.

Unknown-workflow lookup failures remain outside canonical claim-denial
telemetry in this tranche. No authoritative workflow object exists at
that point, and canonical telemetry MUST NOT copy the caller-facing
lookup argument into `workflow_id`.

Existing execution-claim exceptions, authorization decisions, transaction
semantics, and winner-selection behavior remain unchanged.

Correlation observes authority. Correlation is never authority.

### ServiceNow provider correlation telemetry

ServiceNow observability uses the existing application-owned
`VMAI-<sha256>` correlation scheme. No second provider correlation
identifier is introduced.

Canonical `provider_correlation_id` is accepted only when the
observability adapter can independently rebuild the expected VMAI value
from the same trusted tenant, workflow, and exact execution-attempt
identity and the supplied value is equal to that server-derived result.

`validate_servicenow_correlation_id()` establishes safe syntax only. A
string does not become authoritative merely because it matches the VMAI
format.

The raw exact `execution_attempt_id` remains workflow and reconciliation
authority. It may be used by observability only to derive the
pseudonymous `EA1-...` reference and to bind the expected VMAI value. It
MUST NOT be serialized into the canonical event.

For read-only ServiceNow reconciliation, canonical ordering is:

1. retrieve authoritative workflow state;
2. establish `NEEDS_REVIEW`;
3. establish tenant authority;
4. construct trusted `TicketExecutionContext`;
5. derive the server-owned VMAI correlation;
6. emit `security.workflow.reconciliation_started`;
7. emit `security.provider.request_started`;
8. perform the fixed correlation lookup;
9. after a successfully returned and validated lookup, emit
   `security.provider.request_completed`;
10. classify the normalized result.

A zero-record `NOT_FOUND` lookup is not ambiguity and emits neither
`security.provider.result_correlated` nor
`security.provider.result_ambiguous`.

Exactly one normalized matching record emits
`security.provider.result_correlated`.

Multiple normalized matching records emit
`security.provider.result_ambiguous` with reason
`provider_ambiguous`, while workflow authority remains unchanged.

`security.workflow.reconciliation_resolved` is emitted only after the
authoritative workflow-store reconciliation transition returns
successfully. Telemetry does not authorize the transition and does not
replace exact execution-attempt, tenant, state, locking, or CAS checks.

Ticket numbers and ServiceNow `sys_id` values are reconciliation evidence;
they are not canonical provider-correlation authority.

Provider request or response bodies, ticket descriptions, comments,
credentials, authorization headers, cookies, tokens, passwords, and
arbitrary provider records MUST NOT be copied into canonical telemetry.

Provider correlation observes authority. Provider correlation is never
authority.

Security telemetry observes authority. Security telemetry is not
authority.

### ServiceNow provider failure telemetry

ServiceNow lookup failures use bounded machine-readable classification.
Telemetry MUST NOT determine failure semantics by parsing exception text,
exception causes, provider bodies, or arbitrary records.

The internal lookup classifications are:

- `transport`
- `http_status`
- `invalid_response`
- `correlation_mismatch`

Transport, non-success HTTP status, and invalid/untrustworthy response
failures emit `security.provider.reconciliation_denied` with outcome
`failed` and reason `reconciliation_denied`.

A returned provider record whose `correlation_id` does not match the
server-requested VMAI correlation emits the same canonical event with
outcome `denied` and reason `provider_correlation_mismatch`.

For correlation mismatch, canonical `provider_correlation_id` is the
server-built expected VMAI value. The mismatching provider-returned value
MUST NOT be copied into canonical telemetry.

`security.provider.request_started` remains before the lookup.
`security.provider.request_completed` is emitted only after a successful,
validated lookup return. A `ServiceNowLookupError` failure emits bounded
failure telemetry and then re-raises the same exception. The existing
client `finally` cleanup remains authoritative for closing the provider
client.

A multiple-result lookup is already observed as
`security.provider.result_ambiguous`. When resolution subsequently refuses
workflow mutation because the evidence outcome is `CONFLICT`, the actual
refusal additionally emits `security.provider.reconciliation_denied` with
outcome `denied` and reason `provider_ambiguous`.

This layer does not observe store-owned cross-tenant, stale exact-attempt,
workflow-state, existing-ticket, or reconciliation-CAS denials. Those
remain separate workflow-store authority decisions.

The failure-kind value is bounded classification metadata only. It is not
authorization or workflow authority.

Provider response bodies, raw HTTP payloads, arbitrary records, exception
causes, credentials, authorization headers, cookies, tokens, passwords,
ticket descriptions, comments, raw mismatching provider correlations, and
raw execution-attempt identifiers MUST NOT be serialized into canonical
telemetry.

Provider correlation observes authority. Provider correlation is never
authority.

Security telemetry observes authority. Security telemetry is not
authority.

### Workflow-store reconciliation denial telemetry

SQLite and PostgreSQL workflow stores emit
`security.provider.reconciliation_denied` only as observations of
existing store-owned authorization, state, locking, and CAS decisions.

Store telemetry does not construct or accept ServiceNow provider
correlation. `provider_correlation_id` remains absent from this generic
workflow-store boundary.

Invalid workflow identifiers, invalid ticket identifiers, and unknown
workflow lookups remain outside correlated canonical store-denial
telemetry.

Both backends test persisted workflow status before parsing the
authoritative `WorkflowResult`. A wrong-state denial therefore emits an
uncorrelated canonical event with reason
`workflow_transition_not_allowed`; it MUST NOT copy the caller lookup
`workflow_id` into canonical correlation fields.

After an authoritative `WorkflowResult` has been parsed, persisted
`workflow_id`, normalized persisted tenant identity, and the persisted
current execution attempt may be used as observability correlation.

Missing or invalid trusted `SecurityContext` emits reason
`security_binding_mismatch`.

Wrong reconciliation role emits reason `reconciliation_denied`.

`require_workflow_tenant()` remains tenant authority. A
`WorkflowTenantBindingError` is classified as `cross_tenant` only when a
normalized persisted tenant and normalized trusted context tenant both
exist and differ. Otherwise it is observed as
`security_binding_mismatch`. The original tenant exception is re-raised.

Malformed expected execution-attempt evidence emits
`reconciliation_denied` without deriving EA1 from the malformed expected
value.

An exact mismatch between authoritative
`current.execution_attempt_id` and the expected reconciliation attempt
emits `execution_attempt_mismatch`. Any EA1 correlation is derived only
from the persisted current attempt, never from the stale or mismatching
expected attempt.

A `NEEDS_REVIEW` workflow that already contains a ticket emits
`reconciliation_denied`.

SQLite acquires `BEGIN IMMEDIATE` before authoritative reconciliation
state is read. PostgreSQL performs `SELECT ... FOR UPDATE`. In both
backends the authoritative persisted snapshot remains protected through
tenant validation, exact-attempt validation, UPDATE, and rowcount/CAS
verification.

Therefore reconciliation CAS denial may correlate with the already
parsed persisted `workflow_id`, tenant, and EA1 derived from
`current.execution_attempt_id`. Candidate or newly constructed
execution-attempt identifiers MUST NOT be emitted.

The telemetry path does not change or replace the exact attempt
comparison, tenant helper, database locking, workflow-state predicates,
or rowcount/CAS decision.

Correlation observes authority. Correlation is never authority.

Security telemetry observes authority. Security telemetry is not
authority.

### Canonical bounded security metrics registry

The initial production security-metrics boundary is framework-independent.
It consumes only validated canonical `SecurityEvent` objects and does not
accept caller-defined metric names or arbitrary label mappings.

The v1 counters are:

- `security_events_total`
- `security_denials_total`
- `security_review_required_total`

`security_events_total` uses only:

- `event_type`
- `severity`
- `outcome`
- `source_component`

`security_denials_total` and
`security_review_required_total` use only:

- `event_type`
- `reason_code`
- `source_component`

When a qualifying event has no canonical `reason_code`, the fixed literal
`none` is used. This is one bounded synthetic value and does not introduce
attacker-controlled cardinality.

The registry exposes no generic arbitrary-label increment operation.
Metrics are derived from canonical event enums inside the metrics boundary.

The following security-event correlation fields are never metric labels:

- `event_id`
- `request_id`
- `principal_ref`
- `tenant_id`
- `session_ref`
- `workflow_id`
- `execution_attempt_ref`
- `provider_correlation_id`

Raw execution-attempt IDs, raw session IDs, usernames, email addresses,
ticket identifiers, ServiceNow `sys_id` values, exception text, provider
response text, and other arbitrary strings are also prohibited.

Theoretical series cardinality is explicitly bounded by the finite
canonical enum vocabularies. The general event counter is bounded by:

`|event_type| ? |severity| ? |outcome| ? |source_component|`

The denial and review-required counters are each bounded by:

`|event_type| ? (|reason_code| + 1) ? |source_component|`

where the additional reason-code value is the fixed `none` label.

The first registry is process-local, thread-safe, counter-only, and
framework-independent. It does not add Prometheus, OpenTelemetry, StatsD,
Datadog, or another exporter dependency.

Exporter and canonical-event-delivery integration are separate steps.
The metrics registry does not replace the existing audit sink and does not
change `SecurityEventEmitter` delivery semantics in this tranche.

Metrics observe authority. Metrics are never authority.

A metrics observation or exporter failure MUST NOT alter authentication,
authorization, tenant binding, session validity, retrieval authorization,
workflow state, exact execution-attempt authority, provider reconciliation,
or an API response.

### Canonical security metrics delivery integration

Canonical production security events are observed through the existing
`_emit_best_effort` integration seam. Individual event producers do not
implement separate metrics calls.

One already-constructed canonical `SecurityEvent` is offered to two
independent observational paths:

1. the existing audit sink;
2. the bounded process-local security metrics registry.

Audit delivery is attempted first. Metrics observation is then attempted
exactly once regardless of whether audit delivery succeeded or failed.

The two observer failure paths are isolated.

A metrics observation failure MUST NOT suppress the audit attempt, alter
the existing `_emit_best_effort` audit-success return value, or propagate
into the security decision.

An audit delivery failure MUST NOT prevent bounded metrics observation.

If both observational paths fail, neither failure changes authentication,
authorization, tenant binding, session validity, retrieval authorization,
workflow state, exact execution-attempt authority, provider reconciliation,
or an API response.

The `_emit_best_effort` boolean contract remains backward compatible:

- `True` means the existing audit delivery succeeded.
- `False` means the existing audit delivery failed.

Metrics success or failure does not alter that boolean.

The metrics registry is explicitly process-local observability state and
is accessed through `get_process_security_metrics_registry()`. It is not
authorization, configuration, tenant, session, workflow, or execution
authority.

Metric observation continues to derive labels only from the bounded
canonical enum fields defined by the security metrics registry. Event
correlation identifiers remain prohibited as metric labels.

Metrics observation failures are logged using only a bounded exception
type name. Raw exception messages are not copied to logs.

The existing `SecurityEventEmitter` exception-chain behavior is unchanged
by this integration and remains a separate sensitive-data hardening item.

Metrics observe authority. Metrics are never authority.

Security telemetry observes authority. Security telemetry is not
authority.

### Deterministic single-event security detections

The first Step 50.5 detection boundary is framework-independent and
evaluates one already-normalized canonical `SecurityEvent` at a time.

The deterministic rule boundary does not reconstruct, replace, or modify
security authority.

A rule may match only bounded canonical dimensions:

- `event_type`
- `outcome`
- `reason_code`

The v1 rule vocabulary is explicit and immutable. Arbitrary predicates,
callbacks, free-form rule IDs, and free-form alert types are not accepted.

The initial high-confidence rules detect:

- cross-tenant activity;
- security-binding mismatch;
- ServiceNow/provider correlation mismatch;
- provider ambiguity;
- workflow execution-attempt mismatch;
- stale workflow processing;
- blocked direct prompt injection;
- suspected tool-output prompt injection;
- unauthorized MCP tool invocation;
- workflow `NEEDS_REVIEW`.

Authority-boundary violations take precedence over lower-severity
operational signals when more than one conceptual category could apply to
the same source event.

Each source event produces at most one v1 `SecurityAlert`.

A `SecurityAlert` is immutable responder-facing observability data. It
contains a server-generated alert ID, detection timestamp, bounded rule
ID, bounded alert type, alert severity, the source event identity/type,
source outcome/component, canonical reason code when present, and selected
canonical correlation context.

Canonical correlation fields may be copied from the already-validated
source event for investigation:

- `request_id`
- `principal_ref`
- `tenant_id`
- `session_ref`
- `workflow_id`
- `execution_attempt_ref`
- `provider_correlation_id`

Those values are alert context only. They are not detection authority and
must not become aggregate metric labels merely because they are present
on an alert.

Alerts do not include raw access tokens, refresh tokens, ID tokens,
passwords, client secrets, raw prompts, raw RAG content, raw tool output,
provider response bodies, raw execution secrets, arbitrary exception
messages, ServiceNow `sys_id` values, or other uncontrolled sensitive
payloads.

The first detection tranche intentionally contains no sliding-window,
threshold, rate, grouping, or expiration state.

Aggregate/rate detections require a separate explicit contract defining:

- observation window;
- threshold;
- grouping dimension;
- state lifetime;
- expiration/reset behavior;
- false-positive expectations.

A detection result does not authenticate a principal, select a tenant,
authorize retrieval, validate an MCP session, authorize a tool invocation,
approve workflow execution, establish exact execution-attempt authority,
change workflow state, or resolve provider reconciliation.

An alert record is not authorization state.

Detection observes authority. Detection is never authority.

Metrics observe authority. Metrics are never authority.

Security telemetry observes authority. Security telemetry is not
authority.

### Deterministic detection and structured alert delivery

The canonical best-effort observability flow contains three sibling
observers:

1. existing audit delivery;
2. bounded metrics observation;
3. deterministic single-event detection.

When deterministic detection produces a `SecurityAlert`, the alert is
offered to a fourth independently isolated structured alert-delivery
boundary.

The processing order is:

1. audit attempt;
2. metrics attempt;
3. deterministic detection evaluation;
4. alert delivery when and only when a rule matches.

Each observational failure domain is isolated.

Audit failure does not prevent metrics, detection, or alert delivery.

Metrics failure does not prevent detection or alert delivery.

Detection evaluation failure does not alter audit delivery, metrics,
security authority, or the `_emit_best_effort` return value. Because no
valid alert exists in that case, alert delivery is not attempted.

Alert-delivery failure does not alter audit delivery, metrics, the source
security event, the detection result, security authority, or the
`_emit_best_effort` return value.

`evaluate_security_event(event)` returning `None` is a normal no-match
result and produces no alert-delivery attempt.

The `_emit_best_effort` boolean remains backward compatible:

- `True` means existing audit delivery succeeded.
- `False` means existing audit delivery failed.

Metrics, detection, and alert-delivery outcomes do not modify this
boolean.

The alert-delivery boundary is framework-independent and exposes a
`SecurityAlertSink` protocol.

The v1 process-local implementation is `InMemorySecurityAlertSink`.
It is thread-safe and exposes an immutable tuple snapshot through its
`alerts` property.

Process-local alerts are available only through the explicit
`get_process_security_alert_sink()` observability boundary. A private
reset helper exists only for deterministic test isolation.

Process-local alert state is observability state only. It MUST NOT be
consulted to authenticate, authorize, select a tenant, validate a
session, transition a workflow, establish execution-attempt authority,
or resolve provider state.

Detection and alert-delivery failures are logged using only bounded
exception type names. Raw exception messages are not copied to logs.

Structured alert delivery serializes only fields already permitted by the
`SecurityAlert` model. It does not copy raw prompts, RAG content, tool
output, provider bodies, credentials, raw execution secrets, ServiceNow
`sys_id` values, or arbitrary exception messages.

No external SIEM, notification, Prometheus, OpenTelemetry, or vendor
alerting dependency is introduced by this tranche.

No sliding-window, threshold, rate, or grouping state is introduced.

Detection observes authority. Detection is never authority.

Alerts describe observed security conditions. Alerts are never authority.

Metrics observe authority. Metrics are never authority.

Security telemetry observes authority. Security telemetry is not
authority.

### Security event sink exception confidentiality

A canonical security-event sink may fail with an exception whose message
contains provider, transport, credential, token, or other sensitive
material.

`SecurityEventEmitter` preserves canonical
`SecurityEventValidationError` propagation, but generic sink failures are
converted to a bounded `SecurityEventEmissionError` only after the generic
sink exception scope has ended.

The generic sink exception is not retained in a local exception binding
when the sanitized emission error is raised.

The sanitized emission error uses explicit `from None` chaining
suppression.

For a generic sink failure:

- the outward `SecurityEventEmissionError` contains no raw sink exception
  text;
- `__cause__` is `None`;
- `__context__` is `None`;
- formatted traceback output does not expose the underlying generic sink
  exception type or message;
- the original generic sink exception cannot become an observability
  payload;
- `_emit_best_effort` continues to treat the failure as best-effort
  telemetry failure;
- the underlying security decision remains unchanged.

Canonical `SecurityEventValidationError` continues to propagate directly
and is not converted to a sink-emission error.

This confidentiality control does not make audit delivery authoritative.

Audit observes authority. Audit is not authority.

Security telemetry observes authority. Security telemetry is not
authority.

### Legacy audit exception-message confidentiality

Legacy `log_event` records must not serialize arbitrary exception
messages.

Exception strings may contain credentials, bearer tokens, provider
responses, transport details, identifiers, or other sensitive
operational content that is not required for audit correlation.

The legacy execution events:

- `TICKET_EXECUTION_BLOCKED`
- `WORKFLOW_EXECUTION_CLAIM_BLOCKED`

therefore retain bounded `error_type` metadata but do not persist
`str(error)` or another free-form message equivalent.

The legacy audit boundary must not replace removed exception strings with
fields such as:

- `error_message`
- `exception_message`
- `sanitized_message`

unless a future contract defines a bounded vocabulary for such a field.

Removing exception text does not alter exception propagation. The
underlying `PermissionError` is still re-raised through the existing
execution control flow.

This tranche does not modify raw `execution_attempt_id` handling. Exact
execution-attempt audit hygiene is handled separately so that its
authoritative tenant/workflow/attempt derivation can be evaluated at each
call site.

Audit observes authority. Audit is not authority.

Exception text is not authority and is not required audit data.

Security telemetry observes authority. Security telemetry is not
authority.

### Legacy execution-attempt audit confidentiality

The raw exact `execution_attempt_id` participates in workflow execution,
compare-and-swap, recovery, and reconciliation authority.

It remains available internally wherever those authority checks require
it, but legacy `log_event` records do not persist the raw exact value.

For legacy audit correlation, trusted authoritative workflow state
supplies the workflow and execution-attempt values.

For the authenticated ServiceNow reconciliation endpoint, tenant
correlation comes from the server-built trusted security context while
workflow and execution-attempt correlation come from the authoritative
resolved workflow result. The caller-supplied endpoint workflow
identifier is not used as EA1 workflow correlation merely because it
matches authoritative state.

For other migrated workflow audit events, the authoritative returned
`WorkflowResult` supplies tenant, workflow, and execution-attempt
correlation.

When all required trusted values are present, the audit record contains
the pseudonymous `execution_attempt_ref` derived through the canonical
EA1 correlation function.

When authoritative tenant or execution-attempt correlation is absent,
the legacy audit record omits execution-attempt correlation rather than
persisting raw execution authority.

The legacy audit helper does not establish trust. Call sites remain
responsible for supplying trusted authoritative state.

Optional audit-correlation failure does not establish, alter, or replace
workflow authority.

This tranche does not change:

- `expected_execution_attempt_id` comparisons;
- workflow claim semantics;
- compare-and-swap behavior;
- stale-processing authority;
- ServiceNow reconciliation authority;
- workflow state transitions.

Correlation observes authority. Correlation is never authority.

Audit observes authority. Audit is not authority.

EA1 is observational only.

Security telemetry observes authority. Security telemetry is not
authority.

### Legacy audit identity purpose limitation

Raw identity is treated differently from credentials, bearer tokens,
provider response bodies, free-form exception text, and exact execution
authority.

For the current legacy audit boundary, trusted identity may be retained
when it is materially necessary for actor accountability, administrative
action reconstruction, access-control review, or security investigation.

Current examples include:

- MCP session validation and revocation audit;
- privileged actor/target principal revocation audit;
- agent activity attribution;
- tool request, denial, execution, and failure audit;
- authorized retrieval activity.

This retention is purpose-limited. Raw identity is legacy audit context,
not canonical security telemetry authority.

Canonical `SecurityEvent` records do not add ad hoc `username`,
`principal_id`, `actor_principal_id`, or `target_principal_id` fields.

The canonical schema supports `principal_ref`, but this version does not
define or invent a principal pseudonymization algorithm or stable
principal-reference lifecycle. Raw identity must not be mechanically
hashed merely to populate `principal_ref`.

Until such a lifecycle is explicitly designed, raw legacy audit identity
may be retained where removing it would materially reduce attribution or
incident-response usefulness.

Identity retained for legacy audit must come from the applicable trusted
principal, authenticated session context, or the explicitly recorded
target of a security-relevant administrative action.

For actor/target administrative records, the target identity describes
the object of the attempted or completed action. It does not establish
the target's authority.

Raw identity must not be used as a security-metric label. High-cardinality
audit correlation and bounded metric dimensions remain separate
concerns.

This policy does not make identity a credential secret, and it does not
permit unrestricted identity collection. Identity remains subject to
data minimization and purpose limitation.

A future migration from raw identity to `principal_ref` requires an
approved derivation and lifecycle that defines stability, collision
properties, tenant scoping, rotation/versioning where applicable, and
multi-instance consistency.

Audit observes authority. Audit is not authority.

Identity retained for accountability does not establish authorization.

Canonical security telemetry must not gain ad hoc raw identity fields.

Do not invent `principal_ref`.

Security telemetry observes authority. Security telemetry is not
authority.

### Legacy audit ticket identity purpose limitation

Legacy `ticket_id` is treated as operational work-item correlation, not
as a credential, authentication secret, workflow authority, or provider
request-correlation value.

The current legacy audit boundary retains `ticket_id` only where the
identifier originates from trusted returned ticket/workflow state and
materially supports workflow-to-ticket traceability or incident-response
reconstruction.

There are two currently approved legacy audit provenance shapes.

For the ticket-creation audit record, `MOCK_TICKET_CREATED` consumes
`created_ticket["ticket_id"]`.

`created_ticket` is produced only by
`_create_ticket_with_selected_provider(...)`. Both control-flow branches
invoke that same server-selected provider path, differing only in whether
an already validated `TicketExecutionContext` is supplied.

The provider selector does not accept a caller-supplied `ticket_id`. Its
successful value is the return from `provider.create_ticket(...)`.

The completed workflow result is populated from that same
`created_ticket["ticket_id"]`.

For the successful `execute_ticket_workflow` tool audit record,
`TOOL_EXECUTED` consumes `result.ticket_id` from the completed
authoritative `WorkflowResult`.

For the production ServiceNow provider, `ticket_id` represents the
provider-returned human-facing ticket number, while `external_sys_id`
represents the provider-returned ServiceNow record identifier.

These identifiers are distinct from the server-built ServiceNow
`correlation_id` and canonical `provider_correlation_id`.

`provider_correlation_id` correlates the trusted provider interaction.
It must not be substituted for `ticket_id` merely to remove an
operational identifier, because provider-call correlation and
operational ticket identity have different semantics.

Retaining `ticket_id` in purpose-limited legacy audit does not authorize
adding `ticket_id`, `ticket_number`, `external_sys_id`, or `sys_id` to
the canonical `SecurityEvent` schema.

No ad hoc ticket pseudonymization or ticket-reference algorithm is
introduced in this version.

Ticket and provider identifiers are high-cardinality values and must not
be used as security-metric labels.

New audit records must not add ticket identity merely because it is
available. Ticket identity should be retained only where operational
reconstruction materially requires it and its provenance is trusted
returned provider or workflow state.

Audit observes authority. Audit is not authority.

Ticket identity used for audit correlation does not establish workflow,
approval, provider-selection, or execution authority.

Provider correlation observes provider activity.

Provider correlation is not ticket identity.

Security telemetry observes authority. Security telemetry is not
authority.

### Legacy audit content minimization

Legacy audit records must not preserve raw prompt text, retrieved document
content, tool output bodies, provider request or response bodies, or the
attacker-controlled content that caused a security detector to fire.

Prompt-injection detection metadata is permitted only when it remains
non-reflective.

The current detector returns bounded category identifiers from the
server-defined suspicious-pattern taxonomy. It does not return the text
that matched a pattern.

Structured `field_matches` records field paths mapped to those detector
categories. It does not record the corresponding field values.

Accordingly, the legacy `PROMPT_INJECTION_SUSPECTED` audit event may
retain:

- affected structural field paths;
- bounded detector categories;
- the de-duplicated bounded category list.

It must not add the inspected provider payload, matched substring, prompt
text, or other attacker-controlled value merely to explain the
detection.

The `RISK_CALCULATED` audit event may retain deterministic `factors`
because the current factor vocabulary consists only of fixed
server-defined labels generated by the authoritative deterministic risk
engine. Risk factors must not be changed to arbitrary free-form model,
provider, or user text.

`RAG_EVIDENCE_RETRIEVED` may retain purpose-limited source attribution
metadata consisting of source identifier, source name, chunk identifier,
similarity score, trust tier, and access level. Retrieved chunk `content`
must not be placed in this audit event.

Source identifiers, names, chunk identifiers, finding identifiers, and
asset names are high-cardinality operational metadata. Their presence in
purpose-limited audit does not make them acceptable security-metric
labels.

RAG quarantine audit may retain quarantined chunk identifiers, bounded
detector categories, and aggregate retrieved/safe counts. It must not
retain the quarantined malicious payload.

`retrieval_access` may be retained where it records server-resolved
retrieval authorization context. The audit copy observes that resolved
decision; it does not become an authorization source.

The local legacy audit may therefore contain operational identifiers and
source attribution metadata that can itself be sensitive in some
deployments. Access controls, retention periods, and transport/storage
protections for the audit sink remain deployment responsibilities unless
explicitly implemented elsewhere.

Canonical `SecurityEvent` must not be expanded with these legacy content
structures merely because the local audit retains their minimized
metadata form.

Audit observes authority. Audit is not authority.

Detection observes authority. Detection is never authority.

Detection metadata must not preserve the dangerous content it detected.

Security telemetry observes authority. Security telemetry is not
authority.

### Adversarial observability evaluation

The observability boundary is evaluated adversarially rather than relying
only on nominal telemetry tests.

The adversarial evaluation injects unique canary values through sensitive
or forbidden field names, raw authority identifiers, observer exception
messages, malicious prompt-like content, and large sets of unique
correlation identifiers.

Canonical security telemetry must reject sensitive or unknown fields
without reflecting their values into validation errors.

Raw `session_id` and `execution_attempt_id` values must not enter the
canonical event schema. Server-generated observational references remain
separate from raw authority identifiers.

Canonical serialization remains an explicit allowlist.

Metric-cardinality evaluation submits many distinct principal, tenant,
session, workflow, execution-attempt, and provider-correlation values.
Those values must not become metric-label keys or values. Metric series
remain bounded by the registered enum-like label dimensions.

Detection is evaluated from canonical structured events only. A generated
`SecurityAlert` may carry approved canonical correlation fields for
investigation, but must not grow raw prompt, RAG content, request or
response bodies, credentials, or raw authority identifiers.

Prompt-injection adversarial canaries may cause bounded detector
categories and structural field paths to be retained. The original
malicious value must not be reflected in that detector metadata.

Audit, metrics, detection, and alert delivery remain independent
observers. Adversarial failure of one observer must not grant authority,
change the existing security decision, or suppress later independent
observers except where the failed detection itself means there is no
alert object to deliver.

Observer failure reporting must not copy the raw exception message.
Bounded exception type is sufficient for operational diagnosis.

The return contract of `_emit_best_effort` remains intentionally narrow:
its boolean reports audit-delivery success only. Metrics, detection, and
alert-delivery outcomes do not redefine that result.

The adversarial evaluation does not make audit, metrics, detection,
alerts, or correlation authoritative.

Audit observes authority. Audit is not authority.

Metrics observe authority. Metrics are not authority.

Detection observes authority. Detection is never authority.

Alerts describe observed conditions. Alerts are never authority.

Correlation observes authority. Correlation is never authority.

Security telemetry observes authority. Security telemetry is not
authority.

### PostgreSQL multi-instance telemetry proof

Production PostgreSQL integration is runtime-tested rather than inferred
from collected or skipped integration tests.

The PostgreSQL workflow store remains the sole shared workflow-state
authority. `SELECT ... FOR UPDATE`, workflow-state predicates, exact
execution-attempt comparison, and conditional update/CAS semantics decide
the authoritative outcome before telemetry is interpreted.

A two-instance PostgreSQL execution-claim race produces exactly one
persisted winning execution attempt.

A losing claim must not promote a candidate or uncommitted execution
attempt into canonical telemetry. When the persisted row is already
`PROCESSING`, claim-denial telemetry is intentionally uncorrelated because
the wrong-state decision occurs before authoritative `WorkflowResult`
correlation is parsed.

The successful execution-claim adapter may derive EA1 only from the
`WorkflowResult` returned by the authoritative claim operation. Runtime
PostgreSQL validation re-reads the persisted winning attempt and verifies
that canonical EA1 is derived from that winning value while the raw
execution-attempt identifier remains absent.

For reconciliation, PostgreSQL keeps `SELECT ... FOR UPDATE` authority
through persisted workflow parsing, tenant validation, exact
execution-attempt comparison, mutation, and CAS verification.

When stale reconciliation evidence does not match
`current.execution_attempt_id`, canonical denial correlation uses only the
persisted current workflow, persisted tenant, and EA1 derived from the
persisted current execution attempt. The stale caller attempt and the raw
current execution attempt are not emitted.

A wrong-state reconciliation denial that occurs before authoritative
`WorkflowResult` parsing must not promote the caller lookup `workflow_id`,
tenant, or execution attempt into canonical correlation.

Observer failure remains independent from PostgreSQL authority. A failure
inside audit, metrics, detection, or alert delivery cannot select a
workflow winner, roll back an already committed winner, authorize a
loser, or replace PostgreSQL state.

The built-in security metrics registry and in-memory security-alert sink
remain process-local. They do not provide globally aggregated
multi-instance metrics, distributed alert durability, or distributed
workflow coordination. Production aggregation/export is a deployment
concern unless a distributed telemetry backend is explicitly configured.

PostgreSQL test database URLs and credentials are test/runtime secrets.
Validation evidence must report execution results without printing or
persisting those values.

PostgreSQL owns shared workflow authority.

Correlation observes PostgreSQL-backed authority. Correlation is never
authority.

Telemetry observes PostgreSQL-backed authority. Telemetry is not
PostgreSQL authority.
