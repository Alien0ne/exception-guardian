# Every file a run writes

Back to the [README](/README.md).

## What you get (in `out/<run>/`)

| File | What it is |
|---|---|
| `report.md` | the ranked report: REVOKE and REVIEW with then-and-now evidence, then the OK list |
| `changes.md`, `changes.json` | with `--previous`: what got worse, gained evidence, appeared, eased or went away since that run |
| `findings.json` | the same data for machines; `partial: true` if a source failed |
| `handoff-find.md`, `handoff-guard.md` | short summaries that the next step (and Claude) reads |
| `rules/<rule id>/` | each Sigma rule (`.yml`) and its converted queries (`.<target>.txt`) |
| `guard.json` | for each REVOKE: rules, conversions, test results, dropped drafts, CVEs still missing a rule, and gaps SigmaHQ leaves |
| `hunt-briefs/<rule id>.md` | the hypothesis, hosts, evidence, a "Known infrastructure" section naming the DCs its detections rely on (and where those values came from), the look-back window, the detections, and a starting prompt for SOC-Hunter |
| `approval-plan.md` | for each REVOKE: automatic or manual, what disabling it brings back into view, and ticket text |
| `report.html` | rewritten by every step (`find`, `guard`, `approve`, `demo`, `html`) in the same format: the whole run so far on one self-contained page (lead exception, changes, every exception, hunt queries with test results, the plan) |
| `applied-changes.log` | apply mode only: timestamp, rule, result, and who confirmed it |
| `exposure-candidates.json` | from `find`: assets whose internet exposure is unknown, for the exposure step |
| `exposure-claims.json`, `exposure-evidence.json`, `exposure-drafted-hosts.csv` | from `exposure`: Claude's claims, what the code re-checked, and a draft host list for you to review |
| `dc-candidates.json` | from `dcs`: every Windows server that looked like a DC, its evidence, and whether it is proven |
| `placeholders.found.yaml` | from `dcs --use`: the proven DCs as placeholder values, used by `guard` for this run only |
| `drafts/<CVE>.yml`, `drafts/not-loggable.json` | Claude's drafted rules, and the CVEs no log can show, with the reason (input to `guard`) |
| `sample-briefs/<log>.md` | from `guard`: which sample logs Claude should write for a rule with nothing to test against |
| `samples/<log>.jsonl` | Claude's sample logs from public write-ups, marked as agent-written in every score (input to `guard`) |
| `previous/` | `demo` only: the earlier run that `changes.md` compares with |
