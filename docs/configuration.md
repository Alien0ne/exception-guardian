# Exit codes, settings and the mock API

Back to the [README](../README.md).

## Exit codes and errors

Exit codes: 0 means done. 2 is a usage error (a missing file, a bad option, `dcs --use` with no proven DC, or
`--apply` refused). 3 means `find` wrote a PARTIAL RUN because a source could not be read. `approve --apply` exits
1 when a change did not verify and 2 when the run was partial. Errors print one line; set `EG_DEBUG=1` to see the
traceback. `EG_ENV_FILE` points the CLI at a `.env` somewhere else, so a test harness can keep the keys out of
the agent's folder.

## Settings

You can tune these settings in the config:

| Key | Default | Meaning |
|---|---|---|
| `revoke_epss` | 0.5 | an EPSS score at or above this grades REVOKE |
| `review_epss_delta` | 0.1 | an EPSS rise of this much since acceptance grades REVIEW |
| `review_max_age_days` | 365 | an exception older than this grades REVIEW |
| `internal_keywords` | internal, isolated, … | words in a justification that an internet-facing asset contradicts |
| `siem_targets` | splunk, sentinel, defender | the query languages to convert to |
| `sample_logs_dir` | none (demo: samples/logs) | labelled logs every rule is tested against (point it at your own) |
| `critical_acr` | 9 | a Tenable One ACR at or above this marks a critical asset (grades REVOKE) |
| `max_context_lookups` | 1500 | Tenable One asset lookups per run, two requests each. The report says when the cap was reached. Lookups run 8 at a time, and a long run prints its progress |
| `placeholders` | none | your own values for SigmaHQ placeholders, e.g. `{DC-MACHINE-NAME: [DC01$, DC02$], dc_ip_addresses: [10.0.0.10]}`. If unset, a placeholder in a match accepts any value, and one in a filter gets the stand-in `SET_<name>`: the query still runs but excludes nothing, so it is noisy, and the brief says so. Each IPv4 DC address also matches its `::ffff:` form, as Kerberos events log it. `dcs --use` fills the ones you leave unset, for one run |
| `placeholders_file` | none (live sample: `placeholders.local.yaml`) | the same map in a git-ignored file next to the config, so your DC names stay out of git; it wins over `placeholders` |
| `offline`, `intel_snapshot_dir` | false, samples/intel | use the KEV and EPSS snapshot instead of fetching |
| `exposure.*` | none (demo: tag `Exposure:Internet`) | what counts as internet-facing: tags, ranges, a host list, verified claims ([grades.md](../references/grades.md)) |

## Trying apply mode without a tenant

To try apply mode without a real tenant, start the local mock and point `--base-url` at it. Any key values work
against the mock.

```bash
.venv/bin/exception-guardian mock-tenable --fixtures samples/tenable_vm --port 8765
```
