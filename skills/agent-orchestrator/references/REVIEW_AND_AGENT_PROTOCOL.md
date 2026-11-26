# Reviewer and subagent protocols

## Discover capabilities; never fabricate them

Before dispatch, inspect the actual host tool list for a subagent/task spawn facility. Distinguish (a) genuine fresh-context subagent, (b) a distinct tool-backed reviewer, and (c) single-chat self-critique. Record which exists. Superpowers is optional and its skill commands/tool names are host/version dependent; inspect locally instead of assuming paths or slash commands.

## Independent review contract (plan or SDS)

- **Role:** sceptical outside reviewer. You did NOT author the artifact; your goal is to falsify it rather than endorse it.
- **Input:** exact artifact path + revision, scope/acceptance constraints, targeted codebase evidence. Do not ingest the author's defense/summary as ground truth.
- **Questions:** contradictions, missing user journeys, hidden dependency, untestable assumption, trust boundary, rollback, under/over-engineering, implementation risk, impossible resource requirements.
- **Output:** file with one record per finding: ID; severity `Critical | High | Medium | Low`; location; concrete scenario/evidence; consequence; recommended resolution; validation approach; status.
- **Verdict:** `BLOCKED` if Critical/High unresolved, `CONDITIONAL` for accepted Medium with owner, `PASS` if all blocking findings resolved. A verdict is not a substitute for listed evidence.
- **No reviewer edits to approved artifacts** without orchestrator decision. Distinct reviewers work independently before comparing findings.

Use iterative rounds max 3 per artifact, not endless debate. Deduplicate findings and maintain `REVIEW_LEDGER.md` with resolution evidence. If no independent agent is possible, label review `SINGLE_AGENT_SELF_REVIEW` and explicitly note it does not provide independence.

## Implementer dispatch contract

Each implementer receives a **single bounded task** with:

- Task ID and `IMPLEMENTATION_PLAN.md` exact task section / separate extracted brief path.
- Exact relevant frozen SDS sections/revision and any accepted interface decision.
- Working branch/worktree, base commit, allowed files, explicit out-of-scope files.
- Test-first commands, acceptance checks, error cases, safety/secret boundaries.
- One path for report and a request for only a compact completion reply.

Implementer must not self-authorize architectural changes, modify unrelated files, or declare itself independently reviewed. It implements a failing test first when feasible, demonstrates red then green, refactors, runs focused tests and writes: files/commits, tests and exit codes, deviation requests, risks, report path. Only the orchestrator dispatches reviewers. Avoid parallel changes to overlapping files.

## Task review contract

The reviewer gets the **same brief**, pinned SDS revision, implementer report and **full diff against recorded pre-task BASE**, plus test evidence. Do not use `HEAD~1` if a task used several commits. Reviewer checks in this order:

1. **Spec compliance:** required behavior implemented? unwanted behavior added? API/invariants/acceptance violated? tests cover edge cases?
2. **Engineering quality:** security, maintainability, data race/state, error handling, build compatibility, test reliability, no unnecessary side effects.

Record separately `SPEC_PASS | SPEC_FAIL` and `QUALITY_PASS | QUALITY_FAIL` plus findings. If either fails, orchestrator sends only actionable findings back to implementer, then requests a **fresh or clearly tracked** independent re-review after changes. Block progression on Critical/High findings and failing required tests.

## Long-session context discipline

- Main agent maintains a simple ledger, not massive chat transcripts. Children write long outputs to disk and return <= 8 lines containing status, paths, commits, tests, blockers.
- Reuse exact file paths and revision IDs. Feed child only what it must know (task brief, interfaces, relevant SDS excerpts).
- After each task, update task and review ledger; maintain a handoff readable by a completely new agent.
- If time/context/service limits interrupt execution, stop cleanly with persisted state. Never promise automatic continuous background operation.
- No production changes, destructive cleanup, credential access, paid transactions or external publications without appropriately scoped explicit authorization.

## Release gate

After task reviews, run cross-module integration review and actual regression/acceptance commands. Distinguish observed from assumed. Prepare a changelog, risk register and rollback. Mark local deliverable `RELEASE_READY` and `ACCEPTED` once required test/review gates pass. An external deploy/publication requires specific prior authorization in all modes, and `HUMAN_GATE` additionally requires final human release approval. No automatic production publish from generic autonomous preference.
