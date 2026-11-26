# HANDOFF — <project title>

Purpose: reconstruct project state in a **fresh-context implementation session if supported**, or continue automatically in the same session with bounded context.

Phase: HANDOFF_READY
Repo absolute path:
Base commit / branch:
Mode / policy file: AUTO_FIRST / docs/agent-orchestrator/AUTONOMY.md
Plan file / auto-frozen or approved revision:
SDS file / auto-frozen or human-approved revision / hash:
Implementation plan path:
Decision log / review ledger / task ledger paths:
Open nonblocking risks:
Platform, available tools and permissions:
Baseline test command/results:
Scope/deployment restrictions:

## Bootstrap prompt (fresh session when supported, or current main session)

You are the main orchestrator for the project at <repo-path>. Activate the `agent-orchestrator` skill in RESUME/IMPLEMENT mode. Read `docs/agent-orchestrator/HANDOFF.md`, `STATE.md`, the frozen PLAN, frozen SDS, detailed implementation plan and task ledger. Verify revisions/hashes and Git state. If Superpowers is **actually** installed, use its supported planning, worktree, TDD, subagent development and review mechanisms; otherwise use the skill's built-in implementation fallback. Delegate one bounded task at a time, use a distinct independent review agent if supported, gate on tests/spec compliance, persist reports to disk and keep main context small. Respect AUTONOMY.md: proceed without routine approvals; do not expand scope or externally deploy without action-specific authorization. If HUMAN_GATE, check SDS and external-release approvals. Begin with environment and baseline verification, then next unblocked task.
