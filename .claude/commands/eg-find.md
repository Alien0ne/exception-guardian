---
description: Exception Guardian step 1 - re-grade every risk exception against today's KEV, EPSS and asset exposure.
argument-hint: "<config> <out dir> [previous run]"
---

Arguments: $ARGUMENTS (config file, output directory, and optionally an earlier run to compare with).

Follow Step 1 of the repo-root `SKILL.md`: run `exception-guardian find --config <config> --out <out>` (add `--previous <run>` if
given). Then read `<out>/handoff-find.md` and tell me the counts, whether the run is partial and why, the exception
to revoke first with its evidence (then vs now, with sources), and every warning. If find warned that no asset is
marked internet-facing, offer Step 1b (map exposure). Never compute or change a grade yourself.
