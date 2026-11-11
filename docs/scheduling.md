# Run it on a schedule

The grades change when the world does: a CVE joins KEV, exploit code is published, a host gets a public address. One
pass a week catches that. `recheck` is the whole pass in one command, and it only reads.

```bash
exception-guardian recheck --config guardian.live.yaml --runs out/
exception-guardian notify --run "out/$(date +%F)"
```

`recheck` writes `out/<today>/`, compares it with the newest earlier dated folder in `out/` and writes
`changes.md` (what got worse, what is new). `notify` posts the short result to the webhook in `EG_WEBHOOK_URL`.
Nothing is disabled from a schedule: `approve --apply` needs a person at a terminal.

## cron

```cron
# Mondays 07:00: grade, then tell the channel. Keys and EG_WEBHOOK_URL are in the repo's git-ignored .env.
0 7 * * 1  cd /opt/exception-guardian && .venv/bin/exception-guardian recheck --config guardian.live.yaml --runs out/ ; .venv/bin/exception-guardian notify --run "out/$(date +\%F)"
```

`recheck` exits `3` on a partial run (a source failed). The line above still notifies, and the message says
PARTIAL RUN, so a failed source is seen the same morning.

## GitHub Actions

Keep the run folders between jobs (an artifact or a cache), or every pass is a first pass with nothing to compare.

```yaml
name: exception-guardian weekly
on:
  schedule: [{cron: "0 7 * * 1"}]
  workflow_dispatch:
permissions: {contents: read}
jobs:
  recheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install .
      - uses: actions/cache@v4
        with: {path: out, key: "eg-runs-${{ github.run_id }}", restore-keys: "eg-runs-"}
      - run: exception-guardian recheck --config guardian.live.yaml --runs out/ || [ $? -eq 3 ]
        env:
          TENABLE_ACCESS_KEY: ${{ secrets.TENABLE_ACCESS_KEY }}
          TENABLE_SECRET_KEY: ${{ secrets.TENABLE_SECRET_KEY }}
      - run: exception-guardian notify --run "out/$(date +%F)"
        env: {EG_WEBHOOK_URL: "${{ secrets.EG_WEBHOOK_URL }}"}
      - uses: actions/upload-artifact@v4
        with: {name: "exception-guardian-run", path: "out/", retention-days: 30}
```

Use a read-only Tenable key here. The run folder holds rule ids, owners and host names from your tenant: keep the
artifact private and the repository that runs this private too.

## Tickets

`approve` (and so `recheck`) writes `tickets.json`: one entry per REVOKE rule and one per owner with REVIEW rules,
each with `kind`, `title`, `owner`, `rule_ids`, `mode` and `body`. A short script of your own can file them in Jira
or ServiceNow; Exception Guardian does not call a ticketing system itself.
