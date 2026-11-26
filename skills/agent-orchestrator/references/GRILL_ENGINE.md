# Built-in GRILL engine — decision-tree pressure test

## Intent

This is an integral part of `agent-orchestrator`, not a dependency on any external skill. The goal is **shared, testable understanding**, not maximizing question count or simply agreeing with the user.

## Preparation

1. Write draft plan before questions. Enumerate assumptions as `[A-...]`, decision nodes `[D-...]`, and acceptance tests `[AC-...]`.
2. Extract a decision DAG: `D-01 platform` → `D-04 deployment`, `D-02 user roles` → `D-06 access control`, etc. Unknown nodes are not user-approved; autonomous mode may select a logged, reviewable provisional answer with evidence.
3. Prioritize highest-impact irreversible/risk-bearing nodes. Run cheap factual inspection first: repo structure, existing APIs, configuration, tests, logs, product docs. Cite filenames/symbols as evidence; never read unrelated secrets.
4. If requirements are already explicit in user text, record as confirmed; do not ask to repeat.

## Interactive grill transaction (`INTERACTIVE_GRILL` or hard blocker only)

Only **one question per assistant message**. Format naturally in the user's language:

> **Grill Q[D-03] — <topic>**
> Context: <one short repo fact, prior decision or trade-off>.
> **My recommendation:** <specific default> because <one or two concise reasons>.
> **Question:** <single sharply framed question>?
> Alternative: <other option and cost>.

Wait for an answer. A refusal to choose means the branch is BLOCKED, or adopt a clearly labeled reversible provisional decision only within existing authorization. Never bundle follow-ups in the same turn. Prefer one actual product decision over generic preference surveys.

## Default autonomous transaction (`AUTO_FIRST` / `HUMAN_GATE`)

Do **not** send a question to the user merely because a design choice exists. Apply the internal-grill protocol from `references/AUTONOMY_PROTOCOL.md`: one critical question at a time → evidence → lowest-risk reversible option → failure test → log `AUTO_SELECTED` with provenance → follow dependencies. Only ask the user if there is no defensible in-scope choice or authorization is missing. **Do not invent a user reply** or mark an autonomous choice as human-approved.

## Follow-up logic

After every internal selection or actual human answer:

- Write `DECISIONS.md` row: ID, question, source (`USER_CONFIRMED` or `AUTO_SELECTED`), recommendation, decision, alternative rejected, rationale, status (`confirmed`/`provisional`/`blocked`), confidence, date, evidence/owner, downstream effects.
- Challenge vague values ("fast", "secure", "same as original") into measurable constraints, not arbitrary invented metrics.
- Explore a branch depth-first: identify dependencies, failure cases, second-order impacts and reversibility; only then move laterally.
- Adapt the next question based on the user's actual answer. Do not pre-batch questions that depend on unknown answers.
- If conflict with previous answer, present exact contradiction and ask user to resolve it.

## Lenses to cover (not a user-facing checklist)

- What is the primary user outcome? Who is excluded? What does "done" mean?
- What must remain identical or backwards compatible? What can be deliberately dropped?
- What alternative would deliver most value with less work? What is explicitly out of scope?
- What fails with invalid input, offline mode, timeouts, duplicated events, concurrent edits, retries, partial state, process termination?
- What assumptions can we test rather than debate? What is the cheapest falsifying experiment?
- What does the system need to protect? What crosses a trust boundary? What credentials/logs are prohibited?
- What scale, platform, resource, latency and operating-system constraints apply?
- What is the upgrade, migration and rollback plan? How will actual behavior be verified?
- If this fails in production, which earlier decision was probably wrong? What warning signal catches it?

## Termination

A branch is resolved when it has an explicit decision, implications, and at least one testable consequence, OR a clearly designated nonblocking deferral with owner. Grilling as a whole ends when no blocking design decision remains and critical behavior is covered by acceptance criteria. Summarize `decided / deferred / blocked` with references. **Do not request preliminary plan approval** by default. Record reviewed plan `AUTO_FROZEN`; in interactive mode, ask only if a genuinely unresolved user decision blocks progress. Do not interpret silence or an agent verdict as human approval.

Avoid repeating already settled questions unless new evidence invalidates them. Only reopen affected branches after a review finding.
