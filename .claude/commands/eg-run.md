---
description: Exception Guardian end to end on your config - find, guard (drafts and samples), approve - and a report. Never applies anything.
argument-hint: "<config> <out dir> [previous run]"
---

Arguments: $ARGUMENTS (config file, output directory, and optionally an earlier run to compare with).

Run the playbook in the repo-root `SKILL.md` from Step 1 to Step 3, then finish as it says. Stop for one question
only:

1. `/eg-find` with the config and output directory (and the earlier run if given). Then, on a live config, run
   `exception-guardian dcs --run <out dir>` (SKILL.md Step 1c, read-only). Your one question to the human covers
   both of these, asked together:
   - if find warned that no asset is marked internet-facing: map exposure now (Step 1b, passive public records
     only) or go on without it. Do Step 1b only on a yes. If the `exposure` command verified any claim, run `find`
     again into the same output directory with `--exposure-claims <out dir>/exposure-evidence.json` before guard,
     so the grades and the report use it;
   - if `dcs` listed proven DCs for placeholders the config leaves unset: show the list and ask whether these are
     their DCs. Only on a yes run `exception-guardian dcs --run <out dir> --use`.
   Either way, go on to guard, and say in the finish which it was.
2. `/eg-guard` on the output directory: drafts or not-loggable reasons for every missing CVE, samples for every
   brief, rerun guard until nothing is left (at most twice per problem).
3. `/eg-approve` on the output directory.

Live Tenable calls stay read-only: only `exception-guardian` talks to Tenable. Never run `--apply`.
