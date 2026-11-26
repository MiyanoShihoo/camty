# Autonomy policy — default AUTO_FIRST

Autonomous execution is a **work-flow default**, not a blanket authorization to use credentials, deploy, or act beyond the requested repository.

## Mode matrix

| Event | AUTO_FIRST (default) | HUMAN_GATE (opt-in) |
| --- | --- | --- |
| Repository discovery, plan draft | Continue | Continue |
| Built-in grill | Internal challenge + evidence-backed auto decision | Internal challenge + evidence-backed auto decision |
| Independent PLAN review | Continue, up to 3 rounds | Same |
| PLAN freeze | `AUTO_FROZEN` with revision and evidence | `AUTO_FROZEN` with revision and evidence |
| Independent SDS review | Continue, up to 3 rounds | Same |
| SDS freeze | `AUTO_FROZEN` after gates pass | Pause for exact-revision human approval |
| Implementation + code review + regression | Continue while authorized/in-scope | Continue after SDS gate |
| Package local deliverable | Auto | Auto |
| Publish/deploy external system | Only with specific prior authorization | Specific authorization + final human approval |
| Scope/permission/irreversible change | Ask for explicit authorization | Ask for explicit authorization |

## Internal grill transaction (one decision at a time)

For each decision `D-...`:

1. Form **one** sharp question as a skeptical reviewer would. Do not send it to the user by default.
2. Inspect facts already available in code/tests/config/requirements; avoid unrelated secrets and unapproved external access.
3. Evaluate alternatives, reversibility, blast radius, maintenance burden and verification cost.
4. Choose the **lowest-risk defensible in-scope** option. Record `status=AUTO_SELECTED`, a confidence label (high/medium/low), evidence paths, rejected alternative, failure hypothesis, test and downstream dependencies. **Never write `USER_CONFIRMED` without an actual user answer.**
5. Follow depth-first into dependencies; return to the next branch only when current branch has testable consequences.
6. When no defensible reversible choice exists, either run a bounded local falsifying experiment or mark `NEEDS_USER_DECISION` and ask exactly one concise question with a suggested answer. Lack of a user answer is **not** approval.

Other decision sources: `USER_CONFIRMED`, `REPO_EVIDENCE`, `AUTO_SELECTED`, `BLOCKED`. Record provenance.

## Default autonomy boundaries

Allowed without repeated approval when explicitly within user's requested repository/project: inspect nonsecret project files, create/edit project code and docs, use an isolated branch/worktree, run project-local tests/builds/lint, create local artifacts, review diffs, update internal ledgers. Respect user-provided restrictions and resource budgets.

Not implied by autonomous preference: production deployments, external publication, paid calls, account creation, contacting third parties, altering external accounts, uploading source to third-party services, reading/exfiltrating secrets, destructive database/filesystem changes, disabling safeguards, high-privilege installs, or new legal/safety/security scope. Each requires prior explicit *action-specific* authorization. Where authorization is absent, stage a dry run or local artifact and escalate only that action.

## Review, limits, and escalation

- Default review cap: **3 rounds per artifact**; failing implementation tasks: **2 repair cycles** before marking blocked. These are defaults, overridable by the user or project policy.
- **BLOCK** a freeze for open Critical/High review findings, missing core requirement traceability or failed required tests; never label a review independent if only self-review happened.
- On nonblocking Medium findings, record owner, residual risk, and verification condition; do not loop forever over Low cosmetic issues.
- If autonomous progress is blocked: report what was attempted, exact failure/test output path, recommended bounded option, and ask **one** user decision only when necessary.
- If tool calls, run time, tokens or session lifetime prevent continuation: checkpoint `STATE.md`, `TASKS.md`, `HANDOFF.md`, then state the interruption plainly; do not promise background execution.
- Scope changes that alter user-visible outcomes, public contract or security boundary need risk assessment and targeted re-review; if still inside authorized scope and reversible, `AUTO_FIRST` may automatically re-freeze, otherwise require authorization.

## Checkpoint discipline

Persist `STATE.md`, `AUTONOMY.md`, `DECISIONS.md`, `REVIEW_LEDGER.md`, `TASKS.md`, and `HANDOFF.md` at phase transitions. Child agents return only the minimal evidence summary/path. The primary session holds orchestration, not every source excerpt. On resume, trust git/diffs/test evidence over stale model recollections.
