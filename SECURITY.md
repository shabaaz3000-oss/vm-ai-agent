# Security Policy

## Supported Versions

VM AI Agent is a portfolio and engineering demonstration rather than a production service.

Security fixes are applied to the current `main` branch.

| Version | Supported |
| --- | --- |
| Current `main` branch | Yes |
| Older commits or forks | No |

## Reporting a Vulnerability

Please do not disclose suspected vulnerabilities through a public GitHub issue.

If private vulnerability reporting is available for this repository, use GitHub's private security reporting mechanism.

When reporting a security issue, include enough information to reproduce and understand the problem when it is safe to do so.

Useful information may include:

- affected component or file
- vulnerability type
- reproduction steps
- expected security boundary
- observed behavior
- potential impact
- suggested remediation, if known

Do not include real API keys, bearer tokens, passwords, production vulnerability data, customer information, or other sensitive information in a report.

## Security Scope

Security-sensitive areas of this project include:

- vulnerability and scanner input validation
- prompt-injection handling
- deterministic risk authority
- AI advisory boundaries
- human-review enforcement
- approval fingerprinting
- authentication and RBAC
- server-controlled ticket routing
- workflow-state integrity
- atomic execution claims
- uncertain-execution recovery
- secret handling
- CI/CD and software-supply-chain security

## AI Security Boundary

The core security principle of the project is:

> **AI may recommend. Deterministic policy decides. Humans authorize. Controlled code executes.**

A language model must not be able to:

- authoritatively change risk score or rating
- change remediation SLA
- change deterministic ticket priority
- remove required human review
- approve its own proposed action
- control authoritative ticket routing
- directly execute ticket creation or remediation

Reports that demonstrate a violation of one of these authority boundaries are considered security relevant.

## Sensitive Data

This public repository should contain only synthetic, sanitized, or otherwise non-sensitive demonstration data.

Do not submit:

- real vulnerability exports containing sensitive asset data
- Tenable API credentials
- OpenAI API credentials
- authentication bearer tokens
- ServiceNow credentials
- private customer or enterprise information

## Disclosure

Please allow time for investigation and remediation before publishing vulnerability details.

This project favors coordinated disclosure of security issues.
