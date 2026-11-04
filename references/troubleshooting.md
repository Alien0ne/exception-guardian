# Troubleshooting

Report each of these to the human as it is, with the exact message from `report.md` or the command's output.
Never work around one by grading or writing queries yourself.

## Find

| You see | What it means | What to do |
|---|---|---|
| **PARTIAL RUN** at the top of the report, `find` exits 3; a warning `source <name> failed: …` | one source could not be read, so its exceptions are missing from every count | say so first; fix the cause (keys, `base_url`, host, file path) and rerun |
| `error: …` and exit 2 (a missing file, broken YAML, an unknown config key, a folder that is not a run) | a mistake in the command or the config; nothing was graded | do what the line says; `EG_DEBUG=1` shows the traceback |
| `source csv failed: <file> is missing the mapped column …; it has: …` (or `has no rows`) | the export is from another tool, or the map is wrong; the run is partial and exits 3 | fix `columns` in the map so each names a header the file has |
| `source csv failed: <map>.yaml: unknown column keys …` (or `unknown keys`, `unknown type_values`, `unknown status_values`) | a typo in the column map; nothing from that source was graded and the run is partial | fix the name the message gives (it lists the known ones) and rerun |
| `warning: N rows skipped` on the terminal | rows the map could not read (bad CVE id, date format, unknown type); each is listed under Warnings in `report.md` | fix `date_format`, `type_values` or the rows |
| `source <name> failed: skipped because of --offline (it needs the network)` | a live source in an `--offline` run | expected; drop `--offline` for a full run |
| `source assets failed: …` | no asset inventory, so exposure and attack-path triggers cannot fire | the run is partial; INTERNET_FACING and ATTACK_PATH are unknown, not absent |
| `refusing --apply: cannot change rules: …` | the API key's role can only read rules | nothing was changed; ask the tenant admin for a role that can manage recast and accept rules, or file the tickets from the plan |
| `refusing to apply: this run is partial` | a source failed in that run, so its grades may be incomplete | nothing was changed; fix the source, run `find` again, then apply from the new run |
| `environment variable TENABLE_… is not set` | a live source has no key | the human sets it in the environment or `.env`; never ask for the value in chat |
| `source KEV/EPSS failed: live fetch failed (…), so the snapshot from <date> is used` | intel came from the dated snapshot, and the run is marked partial | grades stand, but say which date they reflect. `approve --apply` refuses a partial run |
| `<source>: row <n> (<id>) skipped: …` | a CSV/JSON row was unreadable (unknown type, bad CVE id, missing date) | name the rows; the rest of the file was graded. Fix the export or its column map in `maps/` |
| `<source>: plugin <id> CVE lookup failed: …` | a plugin-only rule's CVEs are unknown | that exception is graded without CVE intel |
| `source assets (tags) failed: the asset list stops at 5,000; …` | the tenant has more hosts than `/assets` lists | the run is partial; hosts past the cap were read by name and IP only, so `INTERNET_FACING` cannot fire for them, `PUBLIC_IP` still can |
| `source assets failed: the asset list stops at 5,000 and the host search failed …` | over 5,000 hosts and the v3 host search did not answer | the run is partial; rules on the missing hosts show `ASSET_UNKNOWN` |
| `asset host search failed (hosts not seen in 90 days were not read): …` | the v3 host search did not answer; `/assets` was complete | not partial; only rules on hosts unseen for 90 days may show `ASSET_UNKNOWN` |
| `source assets (web apps) failed: …` | hosts were read, the web app list was not | the run is partial; rules on web apps may show `ASSET_UNKNOWN` and miss `PUBLIC_IP` |
| `finding count for rule … failed: …` | the findings search did not answer for that rule | its approval plan says the number of findings it re-surfaces is unknown; grades are not affected |
| note `ASSET_UNKNOWN` | the exception's targets match nothing in the inventory | its exposure is unknown; check the target names or tags |
| `--previous` gives nothing new | the earlier run graded the same | normal; say "no change since <date>" |

## Guard

| You see | What it means | What to do |
|---|---|---|
| CVE under `missing_drafts` | SigmaHQ has no rule and there is no draft | draft one (`skills/exception-guardian-guard/SKILL.md`) and rerun `guard` |
| CVEs under `not_drafted` | the rule covers CVEs with no KEV listing, EPSS below the line and no attack path | nothing: they are skipped on purpose; report the count |
| a conversion `note` about a placeholder | a SigmaHQ rule names a value only you know (`%DC-MACHINE-NAME%`) | the query matches any value there. Set your own values under `placeholders:` in the config and run guard again |
| note: "%dc_ip_addresses% is not set, so the filter uses the stand-in" | the placeholder sits in a filter; the stand-in `SET_<name>` makes the filter exclude nothing, so the query also returns the events it was meant to drop | set it under `placeholders:` in the config, or in a git-ignored `placeholders_file:`, and run guard again |
| Sentinel note: "uses Defender XDR's … table" | ASIM has no table for that log (image load, antivirus) | the query needs the Microsoft Defender XDR connector streaming that table into Sentinel |
| no query: "has no table for application/rpc_firewall logs" (or zeek) | neither Sentinel nor Defender XDR stores that log with its fields | use the Splunk query, or convert the rule against the custom table you ingest it into |
| draft under `dropped`, with errors | it failed Sigma validation and was not written | fix it from the errors and rerun, at most twice; then report it as not covered |
| CVE under `no_valid_draft` | still no rule of its own; generic behaviour rules are attached | say the coverage is generic only |
| a target `unsupported` in `conversions` | that rule has no query in that language (e.g. webserver rules on Defender) | say so; never hand-write the query |
| `tested: false` with a reason | no sample logs for its log source, or the rule uses Sigma features the tester does not cover | say "not tested"; point `sample_logs_dir` at real labelled logs to test it |
| a drafted rule misses its own CVE's attack samples | the draft does not detect what it claims | revise it before handing it on |
| a benign hit | a false positive on the sample logs | it should match a `falsepositives` line; if not, add one |

## Approve

| You see | What it means | What to do |
|---|---|---|
| `refusing --apply: … needs an interactive TTY` | `--apply` was run from a non-interactive shell (e.g. by an agent) | by design; the human runs it in their own terminal |
| `refusing --apply: this shell belongs to an agent session` | `--apply` was run from a Claude Code shell or a harness run | by design; run it in your own terminal |
| `skipped: the live rule changed since the run …` | the rule's filter, action, severity or expiry is not what was graded | run `find` again, then plan and apply from the new run |
| `the rule changed while you were confirming, so it was not disabled` | someone edited the rule between the check and the disable | nothing was changed; grade it again |
| `disabled, not verified (could not read it back …)` | the disable was sent but the check-back read failed | check the rule in Tenable; apply stopped there |
| `--apply needs --base-url` | no API address given | add `--base-url https://cloud.tenable.com` (or their region's URL) |
| mode **manual** | the rule is not a Tenable VM rule (SC, CSV) | the human raises the ticket text; there is no API change |
| `<rule>: already disabled` | someone disabled it since the run | nothing to do; it is logged |
| `verify failed for <rule>` | after the change, re-reading the rule did not show it disabled | stop; tell the human to check the rule in Tenable by hand |

## The page

`report.html` is rewritten by every step. If it is missing or stale (a run made by an older version), run
`exception-guardian html --run out/<run>`.
