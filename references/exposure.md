# Map exposure: Claude proposes, the code checks

Most companies do not tag which hosts face the internet. Without that, `INTERNET_FACING` can never fire, and the
report says so. This step lets Claude look for the evidence, and lets code decide what counts.

## When

`find` printed `exposure: no asset is marked internet-facing…`, or the human asks which covered assets are
exposed. Each run writes `out/<run>/exposure-candidates.json`: the assets the exceptions cover that have no
exposure evidence yet, with their names, IPs and FQDNs. Only these assets are looked into.

## What Claude may do (passive only)

- Read public DNS and certificate transparency records for the asset's names and FQDNs.
- Read an internet-scan service's **existing** records for the asset's public IPs (for example Shodan), if the
  human has an account.
- For Shodan, just write `internet_scan` claims: `exception-guardian exposure` reads `SHODAN_API_KEY` from `.env` itself
  and fetches each record. Never check whether the key is set (no `grep`, `cat` or `test` on `.env`); without a
  key the command rejects those claims and says why.
- Read exports the human gives: firewall NAT rules, load balancer pools, a CMDB, an attack-surface tool.

What Claude never does: scan, probe, ping, port-check, fetch a web page from, or otherwise connect to the hosts.
They may not be the human's to test, and the step must leave no trace on them.

## The claims file

`out/<run>/exposure-claims.json` is a JSON list. Each claim:

```json
{"asset_id": "<id from exposure-candidates.json>", "kind": "dns", "value": "shop.example.net",
 "source": "crt.sh certificate, 2026-09-01"}
```

| Kind | Value | How the code checks it | If it holds |
|---|---|---|---|
| `dns` | a DNS name | resolves the name itself; it must point at one of the asset's own IPs, and that IP must be public | the asset gets the public DNS name: `PUBLIC_IP` (REVIEW) |
| `internet_scan` | one of the asset's public IPs | fetches the internet-scan record itself (needs `SHODAN_API_KEY`); it must show open ports, seen within 90 days | the asset is internet-facing: `INTERNET_FACING` (REVOKE), source "seen open from the internet on <date>: ports … (agent-found, verified <date>)" |
| `document` | a host name, FQDN or IP | cannot be checked by code | a row in the draft host list, with its source line, for a person to review |

A claim for an asset that is not a candidate, of another kind, or whose check fails is **rejected** with the
reason. Claims are untrusted: Claude made them after reading outside text, so nothing in a claim is believed
until the code has re-derived it.

## Run it

```bash
exception-guardian exposure --run out/<run>
```

It writes:

- `exposure-evidence.json`: the verified claims and the rejected ones, each with its reason.
- `exposure-drafted-hosts.csv`: `host,source` rows from document claims. A person checks each row; the approved
  file becomes `exposure.internet_hosts_file`.

Then run `find` again with `--exposure-claims out/<run>/exposure-evidence.json` (or set `exposure.claims_file` to it in the config). Only then do grades change. A verified public DNS name stays a hint; open ports seen
from the internet (an `internet_scan` claim) mark the asset internet-facing.

## Report to the human

The printed counts (verified, drafted, rejected), each rejection's reason, and that the draft host list waits for
their review. Never say an asset is exposed unless the command verified it.
