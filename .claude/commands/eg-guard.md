---
description: Exception Guardian step 2 - detections for each REVOKE - draft missing rules, write sample logs from briefs, test and convert.
argument-hint: "<run dir>"
---

Run: $ARGUMENTS

Follow Step 2 of the repo-root `SKILL.md` and `skills/exception-guardian-guard/SKILL.md` exactly:

1. `exception-guardian guard --run <run>`, then read `<run>/handoff-guard.md` and `<run>/guard.json`.
2. Each CVE under `missing_drafts`: draft one rule into `<run>/drafts/<CVE>.yml`, or, if no log can show it, add it to
   `<run>/drafts/not-loggable.json` with the reason.
3. Each brief in `<run>/sample-briefs/`: write the samples file it names from the CVE's public write-up. Do not open
   the rule's detection logic first.
4. Rerun `exception-guardian guard --run <run> --drafts <run>/drafts`. Fix rejected drafts or samples, at most twice.

Report per REVOKE: rules, their scores (say which used agent-written samples), benign hits, and targets with no query.
