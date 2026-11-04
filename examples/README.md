# Example run

`demo-run/` is the full output of one demo run, checked in so you can read the results before installing
anything. It was made from the sample data in [`../samples/`](../samples), not from a real tenant. The sample
exceptions, hosts and owners are made up, every public address is in a documentation range
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and the sample logs are synthetic. The KEV and EPSS values are the real ones, from a dated
snapshot (2026-11-02).

It grades 13 exceptions: REVOKE 6, REVIEW 3, OK 4.

## Start here

| File | What it is |
|---|---|
| `demo-run/report.html` | the whole run on one page: [open it in your browser](https://alien0ne.github.io/exception-guardian/examples/demo-run/report.html) (GitHub Pages). It loads nothing from the network |
| `demo-run/report.md` | the same grades as text, with each exception's evidence |
| `demo-run/hunt-briefs/R-HERO-001.md` | the hunt brief for the exception to revoke first: evidence, look-back window, queries |
| `demo-run/rules/R-HERO-001/` | its Sigma rules, each with a Splunk, Sentinel and Defender query where one converts |
| `demo-run/approval-plan.md` | what to revoke, how, and the ticket text. Nothing was changed |
| `demo-run/changes.md` | what got worse since last week's run |

## Everything else

| Path | What it is |
|---|---|
| `demo-run/findings.json` | every grade with its triggers (then, now, source), for scripts |
| `demo-run/guard.json` | per REVOKE exception: its rules, conversions and test scores |
| `demo-run/drafts/` | the three rules drafted where SigmaHQ had none (reviewed copies from `samples/golden/drafts/`) |
| `demo-run/previous/` | last week's run (2026-10-26), which `changes.md` compares against |
| `demo-run/exposure-candidates.json` | the covered assets with no exposure evidence yet |
| `demo-run/changes.json` | `changes.md` as JSON |
| `demo-run/handoff-find.md`, `demo-run/handoff-guard.md` | the notes each step leaves for Claude's next step |

## Make it yourself

```bash
exception-guardian demo --out examples/demo-run
```

The demo is offline and needs no keys. Your copy differs only in the timestamps. A test
(`tests/test_demo.py`) checks that this folder still matches a fresh run.
