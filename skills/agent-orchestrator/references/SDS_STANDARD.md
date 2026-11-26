# SDS — system design specification standard

The SDS converts an **auto-frozen or approved high-level plan** into an **implementable, reviewable contract**. It describes **what must hold**, not detailed task sequencing. It must not add significant product scope on its own.

## Required SDS structure

1. Header: project, owner, state `DRAFT | FROZEN`, revision, date, approved plan reference, change log.
2. Problem and scope: objectives, non-goals, user roles, scenarios, constraints, environment and assumptions.
3. Traceability: each requirement/`AC-...` mapped to components, interfaces and verification.
4. Architecture: component boundaries, dependency rules, ownership and extension points. Prefer text diagrams where portability matters.
5. Data models: schema, validation, identifiers, persistence, retention, migrations and backward compatibility.
6. API and module contracts: method, input/output types, error codes, sync/async, versioning, security checks, resource ownership.
7. Runtime flows: happy path, degraded path, retries, timeouts, cancellation, idempotency, transaction boundaries, concurrency and recovery.
8. Threat and reliability model: trust boundaries, attack surfaces, least privilege, secrets, logging redaction, availability, resource limits, failure domains.
9. Operational design: deployment requirements, configuration defaults, observability, troubleshooting, backups and rollbacks.
10. Tests: unit/integration/contract/end-to-end/security/performance checks tied to acceptance criteria; explicit measurable pass/fail rules.
11. Alternatives and trade-offs: why the chosen architecture fits and what is sacrificed.
12. Open issues and change control: unknowns with owner, severity and resolved status; revision rules.

## Freeze gates

- Each major requirement points to a component contract and to at least one verifiable check.
- Names/units/versions/protocols are consistent across diagrams, tables and examples.
- No unresolved Critical or High severity issue; Medium items have explicit disposition and owner.
- Designs are consistent with actual project platform and dependency constraints.
- Rollback and failure modes are not hand-waved for durable state migrations or external APIs.
- Independently reviewed if reviewers exist; otherwise the report explicitly states NOT_INDEPENDENT.
- `AUTO_FIRST`: record `AUTO_FROZEN` on exact revision (never claim human approval). `HUMAN_GATE`: human approves exact reviewed revision. Record SDS hash (e.g., SHA-256) where available.

## Drift policy

After SDS freeze, changes to scope, public API, data semantics, security boundaries or acceptance criteria require a change proposal, impact assessment, version bump, targeted re-review, and renewed targeted independent review and `AUTO_FROZEN` if in-scope/reversible in `AUTO_FIRST`, or renewed human SDS approval in `HUMAN_GATE`. Unauthorized scope expansion always needs explicit user authorization. Ordinary internal implementation detail within frozen contracts may change without refreezing.
