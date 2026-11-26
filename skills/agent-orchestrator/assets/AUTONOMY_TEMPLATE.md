# AUTONOMY — <project>

Execution policy: AUTO_FIRST   # AUTO_FIRST (default) | HUMAN_GATE
Scope level: FULL             # FULL | LITE | REVIEW_ONLY | RESUME
Grill mode: INTERNAL         # INTERNAL (default) | INTERACTIVE_GRILL
Authorized project/repo path:
Allowed local side effects: project files, branch/worktree, local tests/builds, local artifacts
Restrictions inherited from user:
Explicitly authorized external actions (describe exact targets, otherwise NONE): NONE
Credential access: NONE unless separately authorized
Production deployment/publication: NOT AUTHORIZED by mode alone
Review rounds per artifact: 3
Repair cycles per task: 2
Time/token/budget constraints: host limits; avoid long raw tool output
Auto-freeze after passing gates: PLAN and SDS (AUTO_FIRST only)
Optional HUMAN_GATE checkpoints: reviewed SDS exact revision; final external release
Escalation: absent action-specific permission, blocking High/Critical, irreducible decision, failed retries, scope drift
Last policy update / source:
