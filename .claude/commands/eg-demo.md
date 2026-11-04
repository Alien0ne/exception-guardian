---
description: Exception Guardian on the sample data, offline - find, guard (drafts and samples), approve - and a report.
argument-hint: "[out dir, default out/demo]"
---

Run the whole Exception Guardian playbook on the sample data, offline, into the directory given here ($ARGUMENTS),
or `out/demo` if none is given.

1. Run `exception-guardian demo --out <dir>`.
2. Do the agent part of Step 2 in the repo-root `SKILL.md`: for every CVE in `guard.json` `missing_drafts`, draft a rule or record
   it in `<dir>/drafts/not-loggable.json`. For every brief in `<dir>/sample-briefs/`, write samples. Then run
   `exception-guardian guard --run <dir> --drafts <dir>/drafts`. Follow `skills/exception-guardian-guard/SKILL.md`.
3. Run `exception-guardian approve --run <dir>` and read `approval-plan.md`.

Finish as `SKILL.md` says: the counts, the exception to revoke first and why, what has no rule or no samples, and
the path to `<dir>/report.html`.
