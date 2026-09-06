# NIST AI Risk Management Framework Assessment

## Project

VM AI Agent

## Purpose

This document evaluates the VM AI Agent using the NIST AI Risk Management Framework (AI RMF).

The assessment is organized around the four core AI RMF functions:

1. GOVERN
2. MAP
3. MEASURE
4. MANAGE

### How the AI RMF Functions Work Together

The four AI RMF functions are not intended to operate as a one-time sequential checklist.

GOVERN is a cross-cutting function that establishes the policies, responsibilities, processes, and organizational risk-management practices that support the other functions.

MAP identifies the context of the AI system and the risks that arise from that context.

MEASURE evaluates, analyzes, and tracks identified risks and the effectiveness of controls.

MANAGE prioritizes and responds to identified risks based on their potential impact.

AI risk management is iterative. As the system, data sources, models, tools, threats, or deployment environment change, risks should be mapped, measured, and managed again under the organization's governance structure.

---

## 1. GOVERN

### What GOVERN Means

GOVERN establishes the policies, responsibilities, processes, and oversight used to manage AI risk throughout the system lifecycle.

### VM AI Agent Controls

The VM AI Agent implements several technical and procedural controls that support the GOVERN function of the NIST AI RMF. Because this is a portfolio-scale application rather than an organizational AI program, some governance outcomes are only partially implemented or remain future work.

#### Existing Governance Controls

- **Authentication and role-based access control (RBAC):** Access to protected workflow operations is restricted to authenticated users and authorized roles.
- **Human approval before execution:** AI-generated analysis and recommendations do not independently authorize sensitive workflow actions. An authorized human approver must approve execution.
- **Separation of AI recommendation from authoritative decision logic:** Deterministic application logic is used for authoritative security decisions where appropriate rather than allowing the language model to act as the sole decision-maker.
- **Audit logging:** Security-relevant workflow events are recorded to support accountability and investigation.
- **Audit trace reconstruction:** Workflow activity can be reconstructed to review execution order, tool usage, and RAG activity.
- **AI security evaluations:** Expected and adversarial AI behavior is evaluated through repeatable security test cases.
- **Automated testing and Security CI:** Application tests, dependency checks, and secret scanning provide ongoing validation of security requirements.
- **Controlled tool execution:** AI-assisted workflows operate through defined application functions rather than unrestricted access to external systems.

#### Human-AI Responsibilities

The application intentionally separates AI assistance from execution authority.

The AI component may:

- analyze vulnerability information;
- retrieve relevant contextual information;
- generate recommendations; and
- prepare proposed workflow actions.

The AI component is not trusted to independently authorize sensitive actions.

Human approvers are responsible for reviewing and approving or rejecting actions that require elevated authority.

This design provides a human oversight boundary between AI-generated recommendations and security-impacting execution.

#### Current Governance Gaps

The project does not yet implement all organizational governance outcomes described by the NIST AI RMF. Areas for additional development or documentation include:

- formal AI risk tolerance criteria;
- legal and regulatory applicability documentation;
- a formal AI system inventory;
- defined periodic governance review intervals;
- AI system decommissioning procedures;
- formal stakeholder feedback processes;
- documented third-party AI provider risk assessments;
- contingency procedures for third-party AI or data-source failures; and
- organization-level AI roles, training, and executive accountability.

These gaps do not necessarily indicate application vulnerabilities. They identify governance capabilities that would be required if the VM AI Agent were developed or deployed as part of a production organizational AI program.

---

## 2. MAP

### What MAP Means

MAP establishes the context in which the AI system operates, including its purpose, users, components, data sources, dependencies, and potential risks.

### VM AI Agent Architecture

#### System Purpose

The VM AI Agent is a security-focused application that assists with vulnerability management workflows.

The system combines deterministic security logic, AI-assisted analysis, retrieval-augmented generation (RAG), human approval, controlled tool execution, and audit logging.

Its intended purpose is to assist security personnel with analyzing vulnerability findings, incorporating relevant security context, recommending remediation actions, and preparing controlled workflow actions without allowing the language model to independently authorize sensitive execution.

#### Intended Users

The primary intended users are:

- vulnerability management analysts;
- security engineers;
- authorized workflow approvers; and
- security administrators responsible for reviewing workflow and audit activity.

The application is not designed to provide unrestricted autonomous access to security tools or enterprise systems.

#### Major System Components

The VM AI Agent includes the following major components:

- **FastAPI application layer:** exposes application workflow endpoints.
- **Authentication system:** establishes the identity of users interacting with protected operations.
- **Role-based access control:** restricts operations based on authorization level.
- **Workflow engine:** coordinates preparation, approval, execution, rejection, and reconciliation of vulnerability workflows.
- **Deterministic risk engine:** calculates authoritative vulnerability risk using structured security data.
- **AI analyzer:** generates AI-assisted vulnerability analysis and recommendations.
- **RAG subsystem:** retrieves relevant security knowledge for use as additional model context.
- **Human approval boundary:** separates AI-generated recommendations from execution authority.
- **Controlled tool layer:** performs explicitly defined workflow operations.
- **Ticketing integration:** represents downstream remediation-ticket creation through controlled application logic.
- **Workflow store:** maintains persistent workflow state.
- **Audit logging and trace reconstruction:** records security-relevant activity and allows workflow behavior to be reconstructed.
- **Evaluation framework:** tests expected and adversarial AI security behavior.
- **Security CI:** validates application tests and selected software-development security controls.

#### Key Inputs

The system processes several types of information:

- vulnerability finding data;
- asset information;
- threat intelligence;
- user requests;
- retrieved RAG content;
- workflow state;
- approval or rejection decisions; and
- application configuration.

These inputs do not necessarily have the same level of trust.

#### Key Outputs

The application may produce:

- calculated vulnerability risk;
- AI-generated vulnerability analysis;
- remediation recommendations;
- proposed workflow actions;
- workflow state transitions;
- mock remediation tickets;
- audit events; and
- reconstructed execution traces.

#### Trust Boundaries

Important trust boundaries include:

1. **User to application boundary**
   User requests enter the FastAPI application and must be subject to authentication, authorization, and input validation.

2. **Application to AI model boundary**
   Structured security information is provided to an AI model that may produce probabilistic or incorrect output. Model output must therefore not automatically be treated as authoritative.

3. **RAG data to AI model boundary**
   Retrieved content may originate from sources that contain inaccurate, outdated, or malicious information. Retrieved text must be treated as data rather than trusted instructions.

4. **AI output to tool-execution boundary**
   AI-generated recommendations may influence proposed actions, but authorization controls and human approval must prevent model output from independently triggering sensitive operations.

5. **Application to downstream-system boundary**
   Tool and ticketing operations represent interactions with systems outside the AI reasoning process and therefore require explicit authorization and controlled interfaces.

6. **Persistent state and audit boundary**
   Workflow state and audit records must remain reliable enough to support authorization decisions, recovery, accountability, and investigation.

#### Initial Risk Scenarios

The system context creates several important AI and security risk scenarios, including:

- prompt injection through user-controlled or retrieved content;
- inaccurate or fabricated AI analysis;
- poisoned or misleading RAG content;
- unauthorized workflow execution;
- excessive tool permissions;
- bypass of the human approval boundary;
- incorrect vulnerability prioritization;
- manipulation of workflow state;
- exposure of sensitive information through prompts, outputs, or logs;
- incomplete or misleading audit records;
- dependency or third-party AI service failure; and
- unexpected interaction between deterministic application logic and probabilistic AI output.

These risks will be evaluated in greater detail through the MEASURE and MANAGE functions.

---

## 3. MEASURE

### What MEASURE Means

MEASURE evaluates identified AI risks and determines whether security, safety, reliability, and other controls are operating as intended.

### VM AI Agent Measurements and Evaluations

#### Measurement Approach

The VM AI Agent uses software tests, AI security evaluations, audit evidence, and CI checks to assess risks identified during the MAP function.

The project does not assume that the presence of a security control proves that the control is effective. Where practical, expected behavior is validated through repeatable tests and observable application evidence.

#### Existing Measurement Capabilities

The project currently includes the following measurement and evaluation mechanisms:

- **Automated application testing:** pytest is used to validate deterministic application behavior and security-relevant workflow requirements.
- **AI security evaluations:** repeatable evaluation cases exercise expected and adversarial AI-assisted behavior.
- **RAG evaluations:** retrieval behavior can be evaluated to determine whether relevant context is used and whether retrieved content creates unsafe behavior.
- **Authorization testing:** tests validate that protected workflow operations cannot be performed without the required authentication, role, or approval state.
- **Workflow-state testing:** workflow transitions and execution claims are tested to reduce the likelihood of invalid, duplicate, or conflicting execution.
- **Audit-trace testing:** recorded events can be reconstructed and checked for expected ordering and relevant workflow evidence.
- **Tool-use observation:** tool activity can be identified through application and audit evidence rather than relying solely on model-generated descriptions.
- **Security CI:** automated checks execute on repository changes to identify application test failures, exposed secrets, and selected dependency risks.

#### Example Risk-to-Measurement Mapping

| Risk identified during MAP | Measurement approach |
| --- | --- |
| Prompt injection through retrieved content | Execute adversarial RAG evaluation cases and observe model behavior, tool requests, and audit evidence |
| Inaccurate AI analysis | Compare AI output against structured security inputs and deterministic application results |
| Unauthorized workflow execution | Attempt protected operations without required authorization or approval and verify rejection |
| Bypass of human approval | Test workflow transitions to confirm execution cannot occur from an unapproved state |
| Duplicate or conflicting execution | Test atomic execution claims and stale-workflow reconciliation behavior |
| Excessive or unexpected tool use | Inspect audit traces and evaluation results for tool invocation order and frequency |
| Incomplete audit evidence | Reconstruct workflows from recorded events and verify expected security-relevant activity is present |
| Software dependency or secret exposure | Run dependency and secret-scanning checks through Security CI |

#### Measurement Limitations

The current measurement program has limitations that would need to be addressed for a production deployment.

Examples include:

- no large-scale statistical benchmark of AI response quality;
- limited model-to-model comparison;
- limited measurement of false-positive and false-negative AI recommendations;
- no production telemetry or long-term behavioral monitoring;
- no independent third-party assessment;
- limited evaluation of privacy impacts;
- limited testing against a broad corpus of adversarial prompt-injection techniques;
- no formal measurement thresholds for acceptable AI performance degradation;
- no formal business-impact metrics tied to AI failures; and
- no continuous evaluation against changes in an external model provider.

These limitations should be considered when interpreting evaluation results.

#### Measurement Principle

A security control is not considered effective solely because it exists in the architecture.

Where practical, the project attempts to produce evidence that the control operates as intended.

For example:

- RBAC should be tested by attempting unauthorized access.
- Human approval should be tested by attempting execution before approval.
- RAG controls should be tested using adversarial retrieved content.
- Audit logging should be tested by reconstructing security-relevant workflow activity.
- Tool restrictions should be evaluated by observing what actions the AI-assisted workflow can actually initiate.

This evidence-based approach supports the transition from assumed security to measured security.

---

## 4. MANAGE

### What MANAGE Means

MANAGE prioritizes identified risks and determines how those risks should be mitigated, accepted, transferred, avoided, or monitored.

### VM AI Agent Risk Treatments

#### Risk Management Approach

The VM AI Agent uses a defense-in-depth approach to manage AI and application risks.

Risk treatment decisions are based on the potential impact of a failure, the trustworthiness of the component involved, and whether a deterministic or human-controlled mechanism can reduce reliance on probabilistic AI behavior.

The project generally favors preventing or limiting high-impact AI actions rather than assuming that model output will always be correct.

#### Existing Risk Treatments

| Risk | Existing Treatment |
| --- | --- |
| Inaccurate or fabricated AI analysis | Deterministic security logic remains authoritative where appropriate, and AI output is treated as advisory |
| Prompt injection through retrieved content | Retrieved information is treated as contextual data rather than trusted execution authority, with downstream authorization controls limiting impact |
| Unauthorized workflow execution | Authentication, RBAC, workflow-state validation, and human approval restrict execution |
| Human approval bypass | Execution requires an approved workflow state and appropriate authorization |
| Duplicate execution | Atomic execution claims reduce the likelihood that the same workflow is executed multiple times |
| Stale or interrupted workflows | Reconciliation logic supports recovery of workflows left in an inconsistent execution state |
| Excessive tool authority | Tool operations are exposed through explicitly defined application functions rather than unrestricted system access |
| Unexpected AI tool behavior | Tool activity is observable through audit events and execution traces |
| Manipulation of workflow state | Persistent workflow state is validated before protected transitions and execution |
| Incomplete accountability | Audit logging and trace reconstruction provide evidence of important workflow activity |
| Software dependency risk | Dependency checks are included in Security CI |
| Exposed credentials or secrets | Secret scanning is included in Security CI |
| AI or RAG behavioral regression | Repeatable security evaluations can detect changes in expected behavior |

#### Defense-in-Depth Example

A potentially unsafe AI recommendation is not controlled through a single protection.

The application uses multiple layers:

1. the AI produces an analysis or recommendation;
2. deterministic application logic remains authoritative for selected security decisions;
3. workflow rules constrain available state transitions;
4. authorization checks restrict who may perform protected operations;
5. human approval is required before sensitive execution;
6. tool access is limited to defined application operations; and
7. audit events record relevant workflow behavior.

This design reduces dependence on any single AI security control.

#### Risk Treatment Decisions

The project uses several general risk-treatment strategies.

**Mitigate**

Risks are reduced through technical or procedural controls.

Examples include:

- requiring human approval;
- enforcing RBAC;
- restricting tool access;
- validating workflow state;
- maintaining deterministic security logic; and
- testing adversarial behavior.

**Avoid**

Some risk is avoided by deliberately not granting the AI certain capabilities.

For example, the language model is not granted unrestricted authority to execute arbitrary security operations.

**Accept**

Some residual risk is accepted because this is a portfolio-scale demonstration system.

Examples include:

- limited adversarial evaluation coverage;
- reliance on mock downstream systems;
- limited production telemetry; and
- lack of large-scale AI performance benchmarking.

Accepted risks should be reconsidered before production deployment.

**Monitor**

Risks that may change over time should be monitored through:

- automated tests;
- AI security evaluations;
- audit traces;
- dependency scanning;
- secret scanning; and
- future production telemetry.

#### Residual Risks and Future Improvements

Several risks remain after the current controls are applied.

Future improvements could include:

- formal classification of trusted and untrusted RAG data sources;
- stronger controls for indirect prompt injection;
- model-output schema and semantic validation;
- formal tool allowlists and argument validation;
- detection of abnormal tool-use patterns;
- sensitive-data filtering for AI prompts and responses;
- formal AI-provider risk assessments;
- model-version change testing;
- expanded adversarial evaluation datasets;
- defined AI risk-acceptance thresholds;
- production monitoring and alerting;
- documented AI incident-response procedures; and
- periodic reassessment of residual AI risk.

#### Risk Management Principle

AI-generated output should not receive authority simply because it was produced confidently or appears plausible.

The level of authority granted to an AI-assisted decision should be proportional to the potential impact of an incorrect result.

Higher-impact actions should therefore receive stronger deterministic controls, authorization checks, human oversight, validation, logging, and testing.

---

## 5. NIST AI 600-1 Generative AI Profile

### Purpose

NIST AI 600-1 extends the AI Risk Management Framework by identifying risks that are unique to or intensified by generative AI systems.

Not every Generative AI Profile risk has the same relevance to the VM AI Agent. Risk relevance depends on the system's intended use, architecture, data, external dependencies, and potential impact.

### GenAI Risk Prioritization

| NIST AI 600-1 Risk | Relevance to VM AI Agent | Rationale |
| --- | --- | --- |
| Confabulation | High | Incorrect or fabricated vulnerability analysis could mislead analysts or influence remediation decisions |
| Information Security | High | The application processes vulnerability information and integrates AI, RAG, authorization, workflow state, and controlled tools |
| Human-AI Configuration | High | Users may over-trust confident AI recommendations, making clear human oversight boundaries important |
| Information Integrity | High | Incorrect, outdated, poisoned, or manipulated RAG content could influence AI analysis |
| Value Chain and Component Integration | High | The system depends on model providers, software dependencies, data sources, APIs, and downstream integrations |
| Data Privacy | Medium; potentially High in production | Production vulnerability, asset, user, or enterprise data could contain sensitive information exposed through prompts, retrieval, outputs, or logs |
| Intellectual Property | Context-dependent | Risk depends on the provenance, licensing, and permitted use of RAG content and other information supplied to AI services |
| Harmful Bias or Homogenization | Lower for the current use case | The application is not primarily designed for decisions about individuals or demographic groups, although systematic model bias may still affect analysis quality |
| Environmental Impacts | Low for the current assessment | The application consumes an external model and does not train a large foundation model |
| CBRN Information or Capabilities | Not materially applicable to the intended use case | The application's intended purpose is vulnerability management rather than chemical, biological, radiological, or nuclear analysis |
| Dangerous, Violent, or Hateful Content | Not a primary risk in the intended workflow | This content is outside the normal purpose and expected output of the application |
| Obscene, Degrading, and/or Abusive Content | Not a primary risk in the intended workflow | This content is outside the normal purpose and expected output of the application |

### Priority GenAI Risks

The following risks receive the greatest attention in the current VM AI Agent assessment because they are most closely connected to the application's architecture and intended use.

#### Confabulation

**Risk**

The language model may confidently generate vulnerability statements, technical explanations, remediation recommendations, or supporting claims that are incorrect, unsupported, or inconsistent with authoritative security data.

**Potential Impact**

If users or downstream systems treat generated content as authoritative, incorrect AI analysis could result in:

- incorrect vulnerability prioritization;
- unnecessary remediation activity;
- failure to remediate an important vulnerability;
- inaccurate remediation tickets;
- loss of analyst trust; or
- unsafe automated action.

**Existing Controls**

- deterministic security logic remains authoritative where appropriate;
- structured vulnerability, asset, and threat-intelligence inputs provide grounding;
- RAG can provide additional security context;
- AI output is treated as advisory rather than execution authority;
- human approval separates recommendations from sensitive execution;
- controlled tool interfaces limit downstream actions;
- audit logging provides evidence of AI-assisted workflow activity; and
- AI security evaluations provide repeatable testing of expected behavior.

**Measurement Approach**

Confabulation risk can be evaluated by comparing AI-generated claims against known structured inputs and expected security conclusions.

Evaluation cases should include situations where:

- relevant information is missing;
- conflicting information is presented;
- retrieved information is irrelevant;
- the model is encouraged to make unsupported conclusions; and
- authoritative deterministic results conflict with AI-generated recommendations.

**Residual Risk**

These controls reduce the impact of incorrect AI output but do not eliminate the possibility that the model will generate plausible but incorrect information.

Human reviewers may also exhibit automation bias and accept incorrect recommendations without sufficient verification.

**Future Improvements**

Potential improvements include:

- requiring citations or evidence for security claims;
- validating generated claims against authoritative sources;
- confidence or uncertainty signaling;
- stronger output-schema and semantic validation;
- broader adversarial evaluation coverage; and
- explicit UI indicators distinguishing deterministic results from AI-generated recommendations.

#### Information Security

**Risk**

The integration of a generative AI model with RAG, workflow state, application logic, and tools creates opportunities for attackers to influence model behavior or cause unauthorized actions.

Relevant attack paths include:

- direct prompt injection through user-controlled input;
- indirect prompt injection through retrieved RAG content;
- malicious or manipulated context supplied to the model;
- attempts to bypass workflow authorization;
- attempts to cause unintended tool use;
- exploitation of excessive tool permissions; and
- manipulation of AI-generated arguments passed to downstream operations.

**Potential Impact**

Successful exploitation could result in:

- unauthorized workflow actions;
- incorrect remediation activity;
- exposure of sensitive vulnerability or asset information;
- manipulation of remediation tickets;
- bypass of intended human oversight;
- misuse of downstream tools or integrations; or
- misleading audit or workflow results.

**Existing Controls**

The VM AI Agent implements several layers intended to reduce information-security risk:

- authentication protects restricted application operations;
- RBAC limits protected actions to authorized roles;
- human approval is required before sensitive workflow execution;
- workflow-state validation prevents invalid execution paths;
- deterministic application logic limits dependence on model-generated decisions;
- tool operations are exposed through controlled application functions;
- atomic execution claims reduce duplicate or conflicting execution;
- audit logging records security-relevant workflow activity;
- audit traces provide visibility into tool and RAG behavior;
- adversarial evaluations exercise security-sensitive AI behavior; and
- Security CI performs automated application, dependency, and secret checks.

**Measurement Approach**

Information-security risk should be evaluated using adversarial scenarios that attempt to cross system trust boundaries.

Evaluation cases should include:

- direct prompt-injection attempts;
- indirect prompt injection embedded in retrieved documents;
- requests for unauthorized tool actions;
- attempts to execute workflows without required approval;
- attempts to bypass RBAC;
- malformed or unexpected tool arguments;
- conflicting or malicious RAG context; and
- attempts to trigger multiple executions of the same workflow.

Expected results should verify that unauthorized or unsafe operations are blocked and that relevant activity is observable through audit evidence.

**Residual Risk**

Prompt injection and model manipulation cannot be assumed to be completely preventable.

A sufficiently persuasive malicious input may still influence AI-generated recommendations even when downstream execution controls prevent direct impact.

Risk also increases if future versions of the application grant the model additional tools, broader data access, or greater execution authority.

**Future Improvements**

Potential improvements include:

- explicit trust classification for model inputs and RAG sources;
- stronger separation of retrieved data from application instructions;
- formal tool allowlists;
- strict tool-argument schema validation;
- runtime policy enforcement before tool execution;
- prompt-injection detection and alerting;
- sensitive-data egress controls;
- rate and action limits for tools;
- additional adversarial evaluation corpora; and
- documented AI-specific incident-response procedures.

---

#### Human-AI Configuration

**Risk**

Users may place inappropriate trust in AI-generated analysis because model responses can appear confident, detailed, and technically plausible.

This creates the possibility of automation bias, where a human reviewer accepts an AI recommendation without performing sufficient independent validation.

**Potential Impact**

Over-reliance on AI-generated recommendations could result in:

- incorrect vulnerability prioritization;
- approval of unnecessary remediation actions;
- failure to challenge fabricated or unsupported technical claims;
- inappropriate escalation of low-risk findings;
- insufficient attention to high-risk findings; or
- gradual transfer of decision authority from humans to the model without an explicit governance decision.

**Existing Controls**

The application establishes a deliberate separation between AI assistance and human authority.

Existing controls include:

- AI-generated analysis is advisory;
- deterministic logic remains authoritative for selected security decisions;
- human approval is required before sensitive workflow execution;
- approver permissions are enforced through RBAC;
- workflow states distinguish preparation from approval and execution;
- audit events record approval and execution activity; and
- evaluation cases can test whether the approval boundary remains effective.

**Measurement Approach**

Human-AI configuration should be evaluated by testing scenarios where AI output appears convincing but conflicts with authoritative information.

Examples include:

- AI recommendations that conflict with deterministic risk results;
- unsupported high-confidence technical claims;
- remediation recommendations based on incomplete evidence;
- retrieved content containing misleading technical guidance; and
- attempts by AI-generated content to persuade the approver to bypass normal controls.

Measurement should determine whether system design makes authoritative and AI-generated information clearly distinguishable.

**Residual Risk**

Human approval does not eliminate risk if reviewers routinely accept recommendations without meaningful review.

The effectiveness of the human oversight control therefore depends on the quality of the information presented to the approver and the organization's review practices.

**Future Improvements**

Potential improvements include:

- visually distinguishing deterministic results from AI-generated content;
- displaying evidence used to support AI recommendations;
- requiring justification for high-impact approvals;
- presenting uncertainty or conflicting evidence to reviewers;
- reviewer training on automation bias;
- periodic review of approval behavior; and
- measuring whether human reviewers detect intentionally incorrect AI recommendations.

---

#### Information Integrity

**Risk**

The AI component may rely on information that is inaccurate, outdated, incomplete, manipulated, or malicious.

RAG increases this risk because external documents can influence generated analysis without becoming part of authoritative application logic.

A malicious or compromised knowledge source could intentionally introduce incorrect security guidance or embedded instructions.

**Potential Impact**

Compromised information integrity could result in:

- incorrect vulnerability analysis;
- misleading remediation guidance;
- incorrect claims about exploitability;
- inappropriate risk prioritization;
- propagation of outdated security recommendations;
- indirect prompt injection; or
- reduced trust in AI-assisted analysis.

**Existing Controls**

Current controls include:

- deterministic security logic remains separate from retrieved narrative context;
- structured vulnerability, asset, and threat-intelligence data provide authoritative inputs;
- RAG content is used to supplement rather than replace deterministic decision logic;
- human approval limits the impact of misleading AI output;
- audit traces expose RAG activity;
- evaluation cases can test retrieval behavior; and
- controlled tool execution limits the ability of compromised information to directly cause sensitive actions.

**Measurement Approach**

Information-integrity testing should include retrieval scenarios involving:

- outdated documents;
- conflicting documents;
- irrelevant documents;
- intentionally incorrect security guidance;
- documents containing embedded instructions;
- duplicate or misleading knowledge entries; and
- authoritative data that conflicts with retrieved content.

Tests should verify whether the application continues to preserve the distinction between retrieved context and authoritative security data.

**Residual Risk**

The system cannot guarantee that all retrieved information is correct.

A trusted repository may also become outdated or compromised, and a model may combine valid and invalid information into a plausible response.

**Future Improvements**

Potential improvements include:

- document-source trust classification;
- provenance metadata for retrieved information;
- document versioning and expiration;
- integrity validation for approved knowledge sources;
- access controls around knowledge ingestion;
- explicit citation of retrieved sources;
- detection of conflicting retrieved evidence;
- review workflows for new RAG content; and
- continuous testing of retrieval quality.

---

#### Value Chain and Component Integration

**Risk**

The VM AI Agent depends on multiple software, data, and service components that may fail, change, or introduce vulnerabilities outside the application's direct control.

Relevant dependencies may include:

- external AI model providers;
- Python packages and frameworks;
- RAG data sources;
- APIs;
- ticketing or downstream systems;
- authentication components; and
- CI and development dependencies.

Changes to one component may alter the security behavior of the overall AI system.

**Potential Impact**

Component or supply-chain failures could result in:

- unexpected model behavior;
- degraded security controls;
- unavailable AI functionality;
- compromised dependencies;
- changes in model output after provider updates;
- inaccurate retrieval results;
- downstream API failures;
- incompatible application behavior; or
- exposure of information to third-party services.

**Existing Controls**

Current controls include:

- dependency scanning through Security CI;
- automated application testing;
- AI security evaluations;
- controlled interfaces between AI output and tool execution;
- audit logging;
- persistent workflow state;
- deterministic logic that does not depend entirely on the AI provider; and
- mock downstream integrations that limit the current project's external impact.

**Measurement Approach**

Component-integration risk can be evaluated through:

- dependency vulnerability scanning;
- application regression testing;
- model-behavior regression evaluations;
- simulated downstream service failure;
- malformed API responses;
- unavailable RAG sources;
- unexpected or incomplete model output; and
- changes in dependency or model versions.

Testing should determine whether failures remain contained and whether the application fails safely.

**Residual Risk**

External model providers and software dependencies can change outside the application's release cycle.

An upstream provider change may alter model behavior without any application-code change.

Open-source or third-party dependencies may also introduce vulnerabilities that are not immediately detectable.

**Future Improvements**

Potential improvements include:

- formal third-party AI provider assessments;
- model-version pinning where supported;
- regression testing before model upgrades;
- software bill of materials generation;
- stronger dependency version controls;
- documented provider outage procedures;
- fallback behavior when AI services are unavailable;
- RAG source availability monitoring;
- service-level and security requirements for production integrations; and
- periodic reassessment of third-party risk.

---

#### Data Privacy

**Risk**

A production implementation of the VM AI Agent may process sensitive enterprise information through prompts, retrieved documents, workflow records, AI outputs, and audit logs.

Relevant information could include:

- internal hostnames;
- IP addresses;
- vulnerability findings;
- system configurations;
- asset ownership information;
- remediation details;
- user identities;
- internal security procedures; or
- proprietary RAG documents.

Sending or storing this information through AI-related components may create privacy or confidentiality risks.

**Potential Impact**

Improper handling of sensitive information could result in:

- exposure of internal security information;
- disclosure to unauthorized users;
- unnecessary transmission to an external AI provider;
- sensitive information appearing in generated output;
- excessive retention in logs;
- accidental inclusion of credentials or secrets; or
- violation of organizational data-handling requirements.

**Existing Controls**

Relevant existing controls include:

- authentication and RBAC;
- controlled application workflows;
- defined RAG access paths;
- auditability;
- secret scanning in Security CI; and
- separation between AI recommendations and unrestricted system access.

Because the current project uses demonstration data and mock integrations, production privacy requirements have not yet been fully implemented.

**Measurement Approach**

Privacy testing should include:

- attempts to expose sensitive information through prompts;
- testing whether unauthorized users can access protected workflow data;
- review of audit logs for unnecessary sensitive-data retention;
- secret-leakage evaluations;
- attempts to cause the model to repeat unrelated retrieved information; and
- inspection of information transmitted to external AI services.

**Residual Risk**

Application-level access controls do not fully address privacy risk if sensitive information is unnecessarily transmitted to external services or retained longer than required.

Production deployment would require explicit organizational decisions about which data may be provided to the AI system.

**Future Improvements**

Potential improvements include:

- formal data classification;
- prompt and response data-loss-prevention controls;
- sensitive-data redaction;
- minimum-necessary data transmission;
- defined retention requirements;
- log sanitization;
- provider data-use and retention review;
- restrictions on which data classifications may enter RAG;
- privacy impact assessment; and
- documented deletion and data-lifecycle procedures.

---

## 6. Risk Register

Priority risks identified through this assessment are tracked in the project AI Risk Register:

[`ai-risk-register.md`](ai-risk-register.md)

The risk register documents qualitative likelihood and impact, existing controls, residual risk, treatment decisions, and recommended future actions.