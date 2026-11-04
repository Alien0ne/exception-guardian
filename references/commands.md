# Commands, outputs and settings

Every step reads and writes one run folder, `out/<run>/`. Each step also rewrites `out/<run>/report.html`, so the
page always shows everything the run has so far.

## Commands

### `find`

Grade every exception and write the report.

| Flag | Meaning |
|---|---|
| `--config <file>` | settings file (default `guardian.yaml`) |
| `--out <dir>` | the run folder to create (required) |
| `--today <YYYY-MM-DD>` | grade as of this date (default: today) |
| `--offline` | no network: KEV and EPSS come from the dated snapshot in `intel_snapshot_dir`; sources that need the network are skipped and the run is marked partial |
| `--previous <dir>` | an earlier run folder: also write `changes.md` / `changes.json` (what got worse since) |
| `--exposure-claims <file>` | an `exposure-evidence.json` from the `exposure` command: grade with its verified claims (overrides `exposure.claims_file`) |

Writes: `findings.json`, `report.md`, `handoff-find.md`, `report.html`, `exposure-candidates.json`, and with `--previous` `changes.md` and
`changes.json`.

Exit code: `0` when every source was read; `3` for a **PARTIAL RUN** (a source failed: the report is still written,
and stderr names the failed source); `2` for a usage error.

### `exposure`

Check Claude's exposure claims for a run (see `exposure.md`).

| Flag | Meaning |
|---|---|
| `--run <dir>` | a `find` run folder (required) |
| `--claims <file>` | claims file (default `<run>/exposure-claims.json`) |

Writes: `exposure-evidence.json` (verified and rejected claims), `exposure-drafted-hosts.csv` (for a person to
review). Every `find` run also writes `exposure-candidates.json`, the covered assets with no exposure evidence.
Exit code `2` if the claims file is missing.

### `dcs`

Find the domain controllers in the Tenable VM scan evidence (read-only GETs), for the SigmaHQ DC placeholders. A
host counts as a DC only on proof: Kerberos (plugin 43829) and LDAP (20870) answer, and the LDAP root entry (25701)
names its server object in the domain's Sites, or the AD plugin (170631) reports a domain controller role.

| Flag | Meaning |
|---|---|
| `--run <dir>` | a `find` run folder (required); the lookup uses the config `find` used |
| `--use` | after a person's yes: write `placeholders.found.yaml` in the run from the proven DCs. Guard uses it for any placeholder the config leaves unset (the config wins) |

Writes: `dc-candidates.json` (every Windows server with Kerberos and LDAP, its evidence, proven or not). Nothing
is looked up for a config with no live `tenable-vm` source. `--use` exits `2` and writes nothing when no DC is
proven. To keep the values for later runs, copy `placeholders.found.yaml` to `placeholders.local.yaml` (git-ignored).

### `guard`

Detections, SIEM queries and hunt briefs for every REVOKE exception.

| Flag | Meaning |
|---|---|
| `--run <dir>` | a `find` run folder (required) |
| `--drafts <dir>` | drafted Sigma rules (default `<run>/drafts`) |
| `--config <file>` | settings file, for `siem_targets`, `sample_logs_dir` and placeholders (default: the config `find` used for this run) |

Writes: `guard.json`, `rules/<rule id>/` (each Sigma rule as `.yml` plus one `.splunk.txt` / `.sentinel.txt` /
`.defender.txt` per target it converts to), `hunt-briefs/<rule id>.md`, `handoff-guard.md`, `report.html`, and
`sample-briefs/<log>.md` for each log source a rule has no sample logs for.

Reads, besides the run: `<drafts>/*.yml` (Claude's drafts), `<drafts>/not-loggable.json` (CVEs no log can show,
with the reason) and `<run>/samples/*.jsonl` (Claude's sample logs, checked and marked agent-written).

In `guard.json`, per REVOKE exception: `rules` (each with `origin`, `conversions` and `tested`: attack and benign
hits on the sample logs), `missing_drafts` (CVEs with no SigmaHQ rule and no draft yet), `dropped` (drafts that
failed validation, with errors), `no_valid_draft` (CVEs that still have none; generic behaviour rules are attached
instead), `not_drafted` (CVEs left to the generic rules), `not_loggable` (CVE and reason), `needs_samples` (log
sources with no sample logs, and their brief) and `conversions` (per target, how many rules converted and how many
were `unsupported`).

### `approve`

Write the approval plan; with `--apply`, disable confirmed Tenable VM rules.

| Flag | Meaning |
|---|---|
| `--run <dir>` | a run folder (required) |
| `--apply` | opt-in: disable each auto rule after a per-rule confirmation. Needs an interactive terminal; refuses otherwise |
| `--base-url <url>` | Tenable VM API base URL for `--apply`, e.g. `https://cloud.tenable.com` |

Writes: `approval-plan.md` (per REVOKE exception: mode auto or manual, how many findings disabling re-surfaces,
and ready ticket text), `report.html`; with `--apply`, `applied-changes.log`.

Exit code with `--apply`: `2` when it refuses before changing anything (no `--base-url`, no interactive terminal,
an agent's shell, a key that cannot change rules, or a partial run), `1` when a rule changed while you were
confirming, or a disabled rule does not read back as disabled or cannot be read back (it stops there, and the log
says what was done). Rules that changed since the run are skipped and logged.

Keys: the CLI reads `TENABLE_*` keys from the environment, then from `.env` in the working directory, or from the
file `EG_ENV_FILE` names.

### `html`

| Flag | Meaning |
|---|---|
| `--run <dir>` | a run folder (required) |

Rewrites `report.html` from whatever the run folder holds. Every step already does this, so you need it only for a
run made by an older version, or to rebuild a page that was deleted.

### `demo`

| Flag | Meaning |
|---|---|
| `--out <dir>` | run folder (default `out/demo`) |
| `--config <file>` | settings file (default `guardian.yaml`) |

Offline, on the samples: last week's run (2026-10-26) into `<out>/previous`, then this week's `find --previous`,
`guard` with the reviewed drafts from `samples/golden/drafts/`, and `approve` (plan only). Prints the lead
exception's evidence table.

### `mock-tenable`

| Flag | Meaning |
|---|---|
| `--fixtures <dir>` | fixture folder to serve (default `samples/tenable_vm`) |
| `--port <n>` | port to listen on (default 8765) |

Serves a local mock of the Tenable VM API, for trying `--apply` without a tenant.

## Settings (`guardian.yaml`)

An unknown key, an empty `sources` list or a value of the wrong kind stops the run with `error: …` (exit 2), so a
typo can never quietly fall back to a default.

| Setting | Default | Effect |
|---|---|---|
| `sources` | | each source: `name` (`tenable-vm`, `tenable-sc` or `csv`), then `fixture_dir` (samples) or `base_url` / `host` (live); `csv` takes `path` (a `.csv` or `.json` export) and `map` (its column map, like `maps/other-scanner.yaml`) |
| `assets` | | asset inventory: `fixture` (a JSON file) or `base_url` (live Tenable VM: hosts from `/assets`, which lists at most 5,000 licensed hosts seen in 90 days; any other host from the v3 host search, without tags; web apps from the v3 web app search). A live Tenable VM list is not used for Tenable SC rules; `for_sources: [tenable-vm, csv]` names the sources it covers. With `base_url`, Tenable One attack paths are read too; `attack_paths: <file>` reads them from a sample file instead |
| `revoke_epss` | 0.5 | EPSS at or above this is `EPSS_HIGH` (REVOKE) |
| `review_epss_delta` | 0.1 | an EPSS rise of at least this since acceptance is `EPSS_ROSE` (REVIEW) |
| `review_max_age_days` | 365 | older exceptions are `TOO_OLD` (REVIEW) |
| `internal_keywords` | internal, not internet, … | words in a justification that claim the asset is internal |
| `siem_targets` | splunk, sentinel, defender | which query languages `guard` writes |
| `sample_logs_dir` | none (the demo config sets `samples/logs`) | labelled logs the rules are tested against; point it at your own |
| `offline` | false | same as `--offline` |
| `intel_snapshot_dir` | `samples/intel` | the dated KEV/EPSS snapshot used offline or when a fetch fails. An online run works without it |
| `max_context_lookups` | 1500 | Tenable One asset lookups per run (two requests each, 8 at a time); the report says when the cap was reached |
| `critical_acr` | 9 | a covered asset whose Tenable ACR (1-10) is at least this is critical (`ATTACK_PATH`, REVOKE) |
| `exposure.internet_tags` | none | your tag names that mark an asset internet-facing (REVOKE), e.g. `[Exposure:Internet]`. With none set and no range or host list, the report says INTERNET_FACING cannot fire |
| `exposure.internet_ranges` | none | CIDR ranges whose assets are internet-facing |
| `exposure.internet_hosts_file` | none | CSV (`host`, optional `source`) of internet-facing names, FQDNs or IPs; relative to the config file |
| `exposure.claims_file` | none | an `exposure-evidence.json` written by the `exposure` command: its verified claims are used (open ports seen from the internet → internet-facing; public DNS → `PUBLIC_IP` hint) |
| `placeholders` | none | your values for SigmaHQ placeholders (`DC-MACHINE-NAME: [DC01$]`); unset ones in a filter get the stand-in `SET_<name>` (a noisy query) |
| `placeholders_file` | none | a git-ignored YAML file with the same map (for example `placeholders.local.yaml`), for values that must stay out of the repo; it wins over `placeholders`, and a missing file is skipped |

Keys come only from environment variables, the git-ignored `.env`, or the file `EG_ENV_FILE` names: `TENABLE_ACCESS_KEY`,
`TENABLE_SECRET_KEY` (VM); `TENABLE_SC_HOST`, `TENABLE_SC_ACCESS_KEY`, `TENABLE_SC_SECRET_KEY` (SC);
`SHODAN_API_KEY` (optional, for the `exposure` command's internet-scan checks).
