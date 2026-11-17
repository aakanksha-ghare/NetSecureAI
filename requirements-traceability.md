
# NetSecureAI — Requirements Traceability

Last updated: 2026-10-16

## Project objective

Build a multi-vendor network configuration compliance and risk
assessment platform. The application will normalize network
configurations into a common security baseline, evaluate controls
deterministically, produce evidence-based findings, and provide
audit-ready reporting and integrity verification.

## Status definitions

- [ ] Planned: not implemented yet.
- [x] Implemented: code exists; this does not automatically mean
      every scenario has been tested.
- [x] Tested: use this label in the status column only after relevant
      automated or integration tests pass.
- Partial: some required functionality exists, but the full requirement
  is not complete.

A requirement is complete only when its implementation and relevant
tests have been verified. Do not claim full framework compliance merely
because a control mapping exists.

## 1. Core application and API

| ID | Requirement | Status | Verification / notes |
|---|---|---|---|
| CORE-01 | Python application structure | Implemented and tested | Flask application and app factory |
| CORE-02 | Health endpoint | Implemented; test coverage to verify | `GET /health` |
| CORE-03 | REST API for configuration audits | Implemented and tested | `POST /api/audit/cisco` |
| CORE-04 | Request validation and meaningful HTTP errors | Implemented and tested | Invalid bodies and risk inputs |
| CORE-05 | JSON findings response | Implemented and tested | Status, severity, evidence, remediation |
| CORE-06 | Clear rule source metadata | Implemented and tested | API field `rule_source` |
| CORE-07 | Requirement traceability | In progress | This document |
| CORE-08 | Project-specific Copilot instructions | Planned | `.github/copilot-instructions.md` |
| CORE-09 | Git commits and reproducible setup documentation | Partial | Verify milestones and setup instructions |

## 2. Configuration parsing and normalization

| ID | Requirement | Status | Verification / notes |
|---|---|---|---|
| PARSE-01 | Cisco IOS-style configuration parser | Implemented; initial tests pass | Selected SSH, HTTP, and logging settings |
| PARSE-02 | Common vendor-independent security baseline | Partial | Initial `SecurityBaseline` model exists; generalize it |
| PARSE-03 | Preserve source evidence and line numbers | Partial | Initial source-line tracking exists |
| PARSE-04 | Distinguish configured, explicitly absent, and unknown settings | Partial | Improve handling of command order, negation, and ambiguity |
| PARSE-05 | Support configuration syntax variations | Planned | Add parser fixtures and edge-case tests |
| PARSE-06 | Reject or report unsupported syntax safely | Planned | Avoid interpreting missing evidence as a confirmed failure |
| PARSE-07 | Parser unit tests and synthetic test configurations | Partial | Expand coverage per vendor |

### Multi-vendor requirement

The final platform must support nine network vendors. A vendor counts
as supported only after its parser, normalized settings, evidence
handling, and relevant tests are implemented.

| Vendor slot | Vendor | Status |
|---|---|---|
| 1 | Cisco | Partial — initial parser and three rules |
| 2 | Fortinet | Planned |
| 3 | Palo Alto Networks | Planned |
| 4 | Juniper Networks | Planned |
| 5 | To be selected | Pending selection |
| 6 | To be selected | Pending selection |
| 7 | To be selected | Pending selection |
| 8 | To be selected | Pending selection |
| 9 | To be selected | Pending selection |

Do not count a vendor as supported solely because its name appears
in documentation. Select the remaining vendors before implementing
their parsers and record the final list here.

## 3. Compliance framework coverage

Required framework families:

- CIS Benchmarks
- NIST SP 800-53
- DISA Security Technical Implementation Guides (STIGs)
- ISO/IEC 27001

| ID | Requirement | Status | Verification / notes |
|---|---|---|---|
| COMP-01 | Deterministic compliance rule engine | Implemented; initial tests pass | `app/rules/compliance_engine.py` |
| COMP-02 | PASS, FAIL, and UNKNOWN outcomes | Implemented; initial tests pass | Preserve inconclusive evidence |
| COMP-03 | NOT EVALUATED where a control is not applicable or not assessed | Planned | Define explicit semantics and API representation |
| COMP-04 | Evidence attached to each finding | Partial | Initial evidence strings and source lines |
| COMP-05 | Severity classification | Implemented; initial rules tested | LOW, MEDIUM, HIGH, CRITICAL |
| COMP-06 | CIS control mappings | Partial | Initial related mapping; validate exact release and applicability |
| COMP-07 | NIST SP 800-53 mappings | Partial | Initial related mapping; not full control assessment |
| COMP-08 | DISA STIG mappings | Partial | Initial related mapping; validate exact STIG version and identifiers |
| COMP-09 | ISO/IEC 27001 mappings | Partial | Initial related mapping; validate control references |
| COMP-10 | Broader control catalog and rule coverage | Planned | Add tested rules for all supported vendors |
| COMP-11 | Traceable mapping rationale and applicability | Partial | Rationale fields exist; expand validation |
| COMP-12 | Avoid claiming full compliance from a single setting | Required design constraint | Keep explicit limitations in findings and reports |

Framework mappings are candidate relationships until their control
references, versions, applicability, and evaluation conditions have
been validated. A mapping alone does not prove control compliance.

## 4. Risk assessment and remediation

| ID | Requirement | Status | Verification / notes |
|---|---|---|---|
| RISK-01 | Explicit likelihood and impact inputs on a 1–5 scale | Implemented and tested | `app/models/risk_assessment.py` |
| RISK-02 | Calculate risk score | Implemented and tested | Likelihood × impact |
| RISK-03 | Configurable project risk thresholds | Implemented and tested | LOW 1–7, MEDIUM 8–14, HIGH 15–19, CRITICAL 20–25 |
| RISK-04 | Record rationale for risk assessment | Implemented and tested | Non-empty rationale required |
| RISK-05 | Do not invent risk ratings from severity | Implemented in current design | Risk requires explicit inputs |
| RISK-06 | Keep inconclusive risk as NOT_ASSESSED | Implemented and tested | No fabricated score |
| RISK-07 | Risk prioritization across findings | Planned | Dashboard and report integration |
| RISK-08 | Actionable remediation guidance | Partial | Initial static remediation guidance exists |
| RISK-09 | Remediation verification and reassessment workflow | Planned | Define evidence needed to close a finding |

The risk thresholds are NetSecureAI's initial project policy, not a
universal standard. Make them configurable and document their use.

## 5. Dashboard and audit reporting

| ID | Requirement | Status | Verification / notes |
|---|---|---|---|
| UI-01 | Dashboard | Planned | Build after API and finding schema stabilize |
| UI-02 | Findings register with filtering and sorting | Planned | Include status, severity, vendor, and rule |
| UI-03 | Show evidence and source lines | Planned | Link displayed findings to evidence |
| UI-04 | Show framework mappings and rationale | Planned | Distinguish related mappings from verified compliance |
| UI-05 | Show risk scores and priorities | Planned | Do not display fabricated scores |
| REPORT-01 | PDF report export | Planned | Audit-ready report |
| REPORT-02 | PDF includes scope, timestamp, device/vendor, and summary | Planned | Record the actual audit inputs |
| REPORT-03 | PDF includes findings, evidence, mappings, risk, and remediation | Planned | Respect UNKNOWN and NOT EVALUATED |
| REPORT-04 | Report reproducibility and error handling | Planned | Test empty results and report-generation failures |

## 6. LLM-assisted explanations

| ID | Requirement | Status | Verification / notes |
|---|---|---|---|
| LLM-01 | Generate plain-language finding explanations | Planned | LLM is an explanatory layer |
| LLM-02 | Suggest remediation based on rule and evidence | Planned | Ground suggestions in available context |
| LLM-03 | Keep compliance decisions deterministic | Required design constraint | LLM must never determine PASS or FAIL |
| LLM-04 | Do not treat unsupported LLM claims as evidence | Required design constraint | Separate verified evidence from generated text |
| LLM-05 | Handle unavailable models, timeouts, and malformed responses | Planned | Graceful failure |
| LLM-06 | Protect sensitive configuration data | Planned | Minimize exposure and document model/privacy settings |
| LLM-07 | Test generated output for grounding and safe fallback | Planned | Include misleading and insufficient-evidence cases |

## 7. Evidence integrity and Hyperledger Fabric

| ID | Requirement | Status | Verification / notes |
|---|---|---|---|
| INT-01 | Calculate SHA-256 hashes of evidence artifacts | Planned | Define canonical evidence representation |
| INT-02 | Store hashes with finding/audit metadata | Planned | Define schema and provenance |
| INT-03 | Verify evidence against recorded hashes | Planned | Detect modified evidence |
| INT-04 | Integrate Hyperledger Fabric | Planned | Define network, identity, and transaction workflow |
| INT-05 | Record evidence hash or integrity metadata on the ledger | Planned | Avoid placing secrets or raw sensitive configs on-chain |
| INT-06 | Verify ledger-recorded integrity data | Planned | Test matching, missing, and mismatching records |
| INT-07 | Handle ledger/network failures safely | Planned | Report verification unavailable separately from tampering |
| INT-08 | Test tampering and audit traceability | Planned | Reproducible integration tests |

A hash mismatch indicates that the artifact differs from the version
represented by the recorded hash. It does not independently prove
malicious intent. A ledger outage must not be reported as confirmed
tampering.

## 8. Quality, security, and documentation

| ID | Requirement | Status | Verification / notes |
|---|---|---|---|
| QA-01 | Automated regression suite | Implemented | Latest recorded result: 31 passed |
| QA-02 | Unit tests for every parser and rule | Partial | Expand with each implementation |
| QA-03 | API validation tests | Implemented; initial coverage passes | Expand as request schema evolves |
| QA-04 | Integration tests for full audit workflow | Partial | Add dashboard, PDF, LLM, and ledger workflows |
| QA-05 | Synthetic fixtures and repeatable examples | Partial | Expand for all nine vendors |
| QA-06 | Safe handling of malformed and ambiguous configurations | Partial | Add adversarial test cases |
| DOC-01 | README with installation and usage | Planned / verify current file | Include setup and example requests |
| DOC-02 | Architecture and data-flow documentation | Planned | Document parser, engine, evidence, LLM, and ledger boundaries |
| DOC-03 | Framework and risk-policy limitations | Required | Document mapping scope and risk thresholds |
| DOC-04 | Git milestones and reproducible tests | Ongoing | Commit verified changes |

## 9. Definition of done

A requirement can be marked complete only when:

1. Its implementation exists.
2. Relevant unit or integration tests pass.
3. Evidence and error handling are verified where applicable.
4. Documentation is updated.
5. No unsupported claims are made about framework compliance or vendor support.

Before final release, run the full regression suite and validate an
end-to-end audit through the supported interface.

## Current verified checkpoint

- Cisco parser: initial implementation.
- Compliance rules: SSH version, HTTP management server, logging destination.
- Risk model: explicit likelihood and impact, validated input, documented thresholds.
- API: framework mappings, rule source, risk serialization, request validation.
- Latest recorded automated test result: 31 passed.
- Manual API smoke test: SSH failure and risk score 20 / CRITICAL verified.
- All remaining planned features must be implemented and tested before the project is described as complete.
