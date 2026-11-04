# Exception Guardian in Claude Code: screenshots

Back to the [README](/README.md).

**What `/eg-demo` looks like** (a fresh clone, 4 Nov 2026, sample data, offline, 44 seconds):

![/eg-demo in Claude Code: the demo grades REVOKE 6, REVIEW 3, OK 4, shows what changed since last week's run and the evidence for R-HERO-001, then guard writes 12 rules with 0 drafts dropped and approve writes the plan](/docs/media/claude-code/demo-start.png)

The demo itself exits 0 (`EXIT 0` in the full output). The red "Exit code 2" belongs to the `ls` Claude chained
after it, which looked for a `sample-briefs/` folder the demo does not need: it ships reviewed drafts and
labelled sample logs.

![The /eg-demo summary: what was not covered and why, the counts and changes since last week, and the exception to revoke first with its KEV, EPSS and exposure evidence](/docs/media/claude-code/demo-summary.png)

![The rules and test scores for each REVOKE exception, the injected justification treated as data, and next steps for the vulnerability manager and the SOC](/docs/media/claude-code/demo-scores.png)

Claude reports the gaps first (the generic web-shell rule caught 0 of 7 attacks), then the exception to revoke
first, each REVOKE's rules and scores, and who does what next. `R-INJECT-007`'s justification is a prompt
injection; Claude treats it as data and no grade changes.

**What the live run looks like.** Screenshots from the live run on the Tenable Partner Lab (4 Nov 2026), with
the lab's names blurred:

| | |
|---|---|
| ![/skills in the repo folder: the playbook skill, its find and guard skills, and the five /eg commands, each a few dozen tokens](/docs/media/claude-code/skills.png) | ![/context at the start of a session: the skills take 2.8k tokens, 0.3% of the context](/docs/media/claude-code/context.png) |
| `/skills`: the playbook, its two step skills and the five commands | `/context`: the skills take 2.8k tokens (0.3%) until a step loads one |

![The start of /eg-run guardian.live.yaml out/live: Claude finds no Tenable keys in its shell, runs find (1,399 assets read, in the background), then dcs, which proves 4 domain controllers](/docs/media/claude-code/run-start.png)

Step 1: `/eg-run guardian.live.yaml out/live`. Claude looks for the Tenable keys and finds none in its shell, as
intended: the CLI reads them from a file Claude never sees, so `find` still reads the lab (1,399 assets). Then
`dcs` proves 4 domain controllers from the scan evidence.

![During /eg-run, Claude drafts a Sigma rule for each CVE that SigmaHQ does not cover: Internet Explorer, GlueBall, AD FS and Remote Desktop exploitation](/docs/media/claude-code/drafts.png)

Step 2: Claude drafts a Sigma rule for each CVE no SigmaHQ rule covers. The CLI then tests and converts them.

![The end of /eg-run: REVOKE 7, REVIEW 316, OK 1, 25 rules with 6 drafts that each caught 2 of 2 attack samples, the exception to revoke first and its evidence, the one question, and next steps for the vulnerability manager, the AD admin and the SOC](/docs/media/claude-code/run-summary.png)

The end of `/eg-run`: the grades, the exception to revoke first and why, the one question, and what each team
does next. The `approve --apply` command is handed to you; Claude never runs it.

Apply mode runs outside Claude Code, in your own terminal. Lab rule ids and host names are blurred:

![approve --apply in a terminal: for each REVOKE rule it shows the live rule, the graded CVEs, enabled to disabled, how many findings come back and the triggers, then asks Disable this rule? y/N](/docs/media/claude-code/apply-confirm.png)

![The end of approve --apply: the last rules asked about, then the result per rule, 2 disabled (verified) and 5 declined](/docs/media/claude-code/apply-result.png)

Each rule is shown as it is live in Tenable, with what changes and how many findings come back, and nothing
happens until you type `y`. At the end, every change is read back from Tenable before it says "verified".
