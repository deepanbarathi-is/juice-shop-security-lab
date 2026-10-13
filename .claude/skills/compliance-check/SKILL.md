---
name: compliance-check
description: Performs a compliance gap analysis against PCI-DSS and ISO 27001 by mapping the current codebase to specific control requirements and outputs a compliance-report.md file. Use when asked to check compliance, audit against a standard/framework, or produce a gap analysis.
---

When performing a compliance check, always include:

1. **Define scope**: Identify what's in scope — components that handle cardholder/payment data (PCI-DSS) or fall under the ISMS (ISO 27001): auth, session/token handling, data storage, encryption, logging/audit, input validation, third-party/dependency exposure, secrets management, network/config boundaries. Note any explicit out-of-scope areas (e.g. no real payment processor integrated).

2. **Inventory relevant code**: Search the codebase for evidence tied to each control area below. Cite concrete `file:line` evidence — never assert a status without a code reference (or explicit absence of one).
   - Authentication & session management (password hashing, token signing/storage, session expiry, MFA)
   - Cryptography (algorithms/key lengths in use, key storage/rotation, data at rest & in transit)
   - Access control (authorization checks, role/privilege enforcement, least privilege, IDOR potential)
   - Logging & monitoring (what's logged, whether logs capture auth events/access to sensitive data, log protection, retention)
   - Input validation & injection defenses (SQL/NoSQL/XML/command injection surfaces, sanitization)
   - Secrets management (hardcoded keys/credentials, env var usage, secret rotation)
   - Data handling (what sensitive/cardholder/PII data is stored, retention, masking/truncation, deletion)
   - Dependency & vulnerability management (lockfiles, known-vulnerable packages, patching cadence if evident)
   - Network/config exposure (default configs, exposed admin/debug endpoints, directory listing, CORS/headers)

3. **Map each finding to specific control IDs** from both standards — do not summarize generically:
   - **PCI-DSS v4.0**: cite requirement numbers, e.g. Req 3 (protect stored account data), Req 4 (encrypt transmission), Req 6 (secure systems/software development), Req 7 (restrict access by need-to-know), Req 8 (identify users & authenticate access), Req 10 (log and monitor access), Req 11 (test security regularly).
   - **ISO/IEC 27001:2022 Annex A**: cite control numbers, e.g. A.5.15 (access control), A.5.17 (authentication information), A.8.3 (information access restriction), A.8.9 (configuration management), A.8.15 (logging), A.8.24 (use of cryptography), A.8.25 (secure development lifecycle), A.8.28 (secure coding).
   - If a control has no applicable code evidence either way, mark it **Not Applicable** rather than guessing.

4. **Assess each mapped control** with a status:
   - `Compliant` — control is implemented correctly in code
   - `Partial` — control exists but has gaps (weak algorithm, incomplete coverage, missing edge cases)
   - `Non-Compliant` — control is absent or actively violated
   - `Not Applicable` — out of scope for this codebase

5. **Generate a compliance-report.md file**:

# Compliance Gap Analysis: <System Name>

## Executive Summary
<2-4 sentences: overall posture, count of critical gaps, headline risk>

## Scope & Methodology
<what was reviewed, what standards/versions, what's out of scope, how evidence was gathered>

## Compliance Matrix
| Control Area | PCI-DSS v4.0 | ISO 27001:2022 Annex A | Status | Evidence (file:line) |

## Gap Analysis
| ID | Standard(s) | Requirement | Status | Gap Description | Risk | Remediation |

## Critical Findings
- Top gaps ranked by risk, each tied back to its control ID(s)

## Remediation Roadmap
- Prioritized (Critical/High/Medium/Low), with effort estimate if determinable

## Appendix: Full Control Coverage
<every control area assessed, including Compliant and Not Applicable ones, for audit completeness>

Keep it evidence-based and specific to this codebase — never assert a compliance status without a code citation, and flag explicitly when insufficient information exists to assess a control rather than assuming compliance.
