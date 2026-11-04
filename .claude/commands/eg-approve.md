---
description: Exception Guardian step 3 - the approval plan and ticket text for every REVOKE. Never applies anything.
argument-hint: "<run dir>"
---

Run: $ARGUMENTS

Follow Step 3 of the repo-root `SKILL.md`: run `exception-guardian approve --run <run>` and present `<run>/approval-plan.md`:
which rules apply mode could disable (auto) and which need a ticket (manual), and what each disable re-surfaces.
Never run `--apply`. If I ask to disable rules, give me the exact command to run in my own terminal, and say that
it refuses a partial run and asks before each rule.
