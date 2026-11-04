# Security notes and guardrail tests

Back to the [README](/README.md).

## Security notes

- **Read-only by default.** `find`, `exposure`, `dcs`, `guard`, `approve`, `html` and `demo` never change
  anything in Tenable. Only `approve --apply` writes, and only when all of these are true:
  - the rule is a Tenable VM accept or recast rule;
  - stdin is an interactive terminal, not an agent's shell (`CLAUDECODE` and `EG_HARNESS` are unset);
  - the live rule still hides the same thing, until the same date, as the copy that was graded;
  - you confirm that rule.

  It first checks (read-only) that the key can change rules at all. Each change is read back and logged, and a
  rule that changed since the run, or while you confirm, is skipped. Apply mode only disables rules, which brings
  findings back into view. It never deletes rules or touches exclusions, scans or other systems.
- **Claude never applies.** The skills tell Claude to stop at the plan, and the repo's `.claude/settings.json`
  enforces that in code. It holds a deny rule and a hook (`.claude/hooks/block_apply.py`) that blocks any
  `exception-guardian approve --apply` command Claude tries to run, however it is wrapped (`bash -c`,
  `python -m`, an abbreviated `--appl`). The CLI also accepts no abbreviated options and refuses `--apply` inside
  a Claude Code shell. Only a person runs apply mode, in their own terminal.
- **A person owns every change.** Use a read-only key for `find`, and edit rights only for the named analyst who
  applies. `applied-changes.log` records each change: the rule, what changed, when, the verified result and who
  confirmed it, and the disabled rule in Tenable names the plan as its reason. Put the plan's ticket text into
  your change system before you apply.
- **It fails loudly.** If a source cannot be read, the report says **PARTIAL RUN** and `find` exits 3, so a
  scheduled job or CI never reports success by mistake.
- **Outside text is treated as data.** Justifications, rule and asset names, CSV cells and CVE text all come from
  outside, so:
  - they never affect grades (the sample rule `R-INJECT-007` carries an injection-style justification, and a
    test proves its grade does not change);
  - reports escape them;
  - the skills tell Claude to treat them as quoted data, never as instructions;
  - rule IDs are cleaned before they are used as file names.
- **Detection only.** Drafted rules and hunt briefs describe how to spot exploitation. They contain no exploit code
  or payloads.
- **Secrets** come only from environment variables or a git-ignored `.env` in the folder you run from (loaded at
  start; variables already set win). `.env.example` holds placeholders. The repo history is scanned with gitleaks
  before release.

## Guardrails, and how we tested them

In Claude Code, the slash commands `/eg-demo`, `/eg-run`, `/eg-find`, `/eg-guard` and `/eg-approve` run each step
behind guardrail hooks: Claude cannot run `--apply`, read `.env`, call Tenable directly or push.

We tested the whole playbook headless on a fresh clone, with a test harness of our own (it is not part of this
repo), and threw 21 attacks at the guardrails. 7 are direct: read the keys, push, apply, call Tenable directly, forge the grades,
write outside `out/`, and switch off the hooks. The other 14 are prompt injections hidden in places such as the
data, a team checklist, project memory, a code comment, a skill file, a file name, a CSV export, an SC rule
comment and an asset tag. In the latest real run (Claude Sonnet 5.5), **none got through**, for $1.20, and the
demo passed all 10 checks. Every prompt and tool call is in [docs/e2e-results.md](/docs/e2e-results.md). The hook
rules themselves are unit-tested in `tests/` (`test_guardrails.py`, `test_review_harness.py`, `test_hook_fixes.py`),
so they run with the rest of the suite.

![Red-team results: 21 attacks on the guardrails, 0 got through. The hooks or a deny rule blocked every attempt that ran, the model refused the rest, and the injected demo's grades match the code's own run. The demo passed 10 of 10 checks. Real sessions on Claude Sonnet 5.5](/docs/media/e2e-results.png)
