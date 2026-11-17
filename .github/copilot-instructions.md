
# NetSecureAI — GitHub Copilot Instructions

## 1. Project purpose

NetSecureAI is a multi-vendor network configuration compliance and
risk assessment platform.

The intended capabilities include:

- Configuration parsing for nine network vendors.
- Vendor-independent security configuration normalization.
- Compliance evaluation against CIS, NIST SP 800-53, DISA STIGs,
  and ISO/IEC 27001.
- Evidence-based findings, severity, framework mappings, risk
  assessments, and remediation guidance.
- A dashboard and PDF audit reports.
- LLM-assisted explanations and remediation suggestions.
- SHA-256 evidence hashing and Hyperledger Fabric integrity
  verification.

These are project requirements, not claims that all features exist.
Consult `requirements-traceability.md` for current implementation
and testing status.

## 2. Architecture principles

Keep responsibilities separated:

- `app/models/`: data structures and domain models.
- `app/parsers/`: vendor-specific configuration parsing.
- `app/rules/`: deterministic compliance rules and evaluation.
- `app/services/`: application workflows and orchestration.
- `app/routes/`: HTTP request validation and response serialization.
- `tests/`: unit, API, regression, and integration tests.

Avoid placing compliance logic in Flask routes or vendor-specific
syntax handling in the compliance engine.

Prefer reusable, typed, testable functions and small modules.
Do not introduce unnecessary dependencies or duplicate existing logic.

## 3. Common security baseline

Vendor parsers must normalize supported settings into a shared
representation so that common compliance rules can evaluate them
consistently.

Preserve:

- Vendor and device identity where available.
- The normalized setting name and value.
- Evidence status and uncertainty.
- Source lines or other traceable source references.
- Relevant parsing limitations.

Do not assume that syntactically different vendor commands have
identical semantics without verifying them.

Distinguish an explicitly configured value, an explicitly disabled
setting, missing evidence, unsupported syntax, and ambiguous evidence.
Do not silently convert missing or ambiguous evidence into failure.

## 4. Compliance decisions

Compliance status must be determined by deterministic code, not by an
LLM.

Preserve these distinct outcomes:

- `PASS`: sufficient evidence satisfies the evaluated rule.
- `FAIL`: sufficient evidence demonstrates that the rule is violated.
- `UNKNOWN`: evidence is inconclusive.
- `NOT EVALUATED`: the rule was not evaluated, such as when it is
  unsupported or not applicable under defined evaluation conditions.

Use only the outcomes defined by the current domain model and extend
it deliberately when adding new outcomes.

Each finding should retain its rule ID, title, status, severity,
description, evidence, source references, remediation, rule source,
framework mappings, and risk assessment where applicable.

Never claim full framework compliance from one setting or a related
control mapping. Validate framework versions, control identifiers,
applicability, and evaluation requirements before making stronger
claims.

## 5. Risk assessment

The initial NetSecureAI risk policy uses:

- Likelihood: 1–5.
- Impact: 1–5.
- Score: likelihood multiplied by impact.
- 1–7: LOW.
- 8–14: MEDIUM.
- 15–19: HIGH.
- 20–25: CRITICAL.

These are the project's configurable initial thresholds, not a
universal standard.

Require explicit ratings and a rationale. Never infer likelihood,
impact, or a numeric risk score from finding severity alone.

Do not assign a confirmed risk score when evidence is inconclusive.
Validate input types and bounds, including rejecting booleans where
integers are expected.

## 6. Framework mappings

Keep the rule's origin separate from external framework mappings.

The API field `rule_source` identifies the source of the rule.
`framework_mappings` contains related framework and control references,
including the framework name, control ID, control title, and rationale.

A mapping must not imply that the complete external control has been
evaluated. Document the scope and limitations of each mapping.

## 7. LLM integration

LLMs may explain findings or suggest remediation based on verified
rules and evidence.

LLMs must not:

- Decide compliance status.
- Invent configuration evidence or source lines.
- Fabricate framework control references.
- Invent risk scores or silently change risk ratings.
- Present unverified suggestions as confirmed facts.

Handle model errors, unavailable models, timeouts, and malformed
responses safely. Keep generated explanations distinguishable from
deterministic findings and verified evidence.

Minimize exposure of sensitive configuration data and document
privacy implications of external model calls.

## 8. Evidence integrity

Use SHA-256 to identify evidence artifacts and verify their integrity.

Define a consistent evidence representation before hashing it.
Keep hashes associated with the correct audit and finding metadata.

Hyperledger Fabric integration must verify ledger records and report
verification failures accurately.

A hash mismatch indicates a difference from the artifact represented
by the recorded hash; it does not independently prove malicious intent.
A ledger outage must not be reported as confirmed tampering.

Never put secrets or raw sensitive configurations on a ledger merely
to prove integrity.

## 9. Security and input handling

Treat uploaded or submitted configuration text as untrusted input.

- Validate request structure and data types.
- Handle malformed and unsupported configurations safely.
- Avoid executing configuration content.
- Do not expose API keys, secrets, or sensitive configuration data
  in logs or error responses.
- Use parameterized database operations where applicable.
- Keep error responses informative without leaking internals.

## 10. Testing and completion criteria

Whenever code changes, identify and update relevant tests.

Test normal cases, invalid input, boundary conditions, missing
evidence, ambiguous evidence, and failure paths where applicable.

Run the project tests using the project's active Python environment.
For this development setup, use `.venv314`, not `.venv`.

Do not claim tests passed unless the actual test output confirms it.
Do not mark a requirement complete until its implementation and
relevant tests have been verified.

Update `requirements-traceability.md` as requirements are implemented
and tested. Keep documentation consistent with actual behavior.

## 11. Development workflow

The developer prefers a controlled, step-by-step workflow.

When asked to inspect or diagnose code:

- Explain the cause of the issue.
- Identify the affected files and relevant tests.
- Suggest focused changes.
- Do not rewrite or modify unrelated functionality.

When a complete file replacement is requested, provide a coherent,
ready-to-copy-paste version and preserve existing behavior unless a
change is intentional.

Do not skip agreed project requirements or claim that planned features
already exist. Prefer small, verifiable milestones over large,
untested rewrites.
