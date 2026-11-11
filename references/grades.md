# Grades and triggers

An exception's grade is the highest grade among its triggers: REVOKE beats REVIEW beats OK. No trigger means OK.
Every trigger carries **then** (the state when the exception was accepted, blank if unknown), **now** and
**source**. Quote all three as written; never re-derive them.

## Grades

| Grade | Meaning | What the human does |
|---|---|---|
| **REVOKE** | the reason it was safe to accept no longer holds: the CVE is exploited, very likely to be, or the asset became reachable | revoke it (approval plan), and hunt for past exploitation (hunt brief) |
| **REVIEW** | nothing proves it is dangerous yet, but the decision has gone stale or contradicts itself | the owner re-confirms or retires it |
| **OK** | no trigger fired | nothing; it is graded again on the next run |

### REVIEW comes in two tiers

A large tenant grades most rules REVIEW (316 of 324 on the live run), so REVIEW is split by what fired:

| Tier | Fires when | What it means |
|---|---|---|
| **now** | any of `JUSTIFICATION_CONTRADICTED`, `EXPLOIT_PUBLIC`, `EPSS_ROSE`, `PUBLIC_IP`, `PATH_CVE_ELSEWHERE`, `EXPIRED_STILL_ENABLED`, `NEW_ASSETS` (unless the rule is also `BLANKET`, where new assets are expected) | there is evidence the risk changed, or the rule outlived its own expiry: the owner looks at it first |
| **housekeeping** | only `NO_EXPIRY`, `TOO_OLD`, `NO_JUSTIFICATION`, `BLANKET` | paperwork gaps: set an expiry, write the reason, narrow the scope |

The tier is `review_tier` in `findings.json` (`null` for REVOKE and OK). `report.md` counts both tiers, labels each
REVIEW heading, and lists the review work per owner. The tier is fixed by the trigger codes; it is never a judgment.

## Triggers

| Code | Grade | Fires when | Then → now (as written) | Source |
|---|---|---|---|---|
| `KEV` | REVOKE | a CVE is in CISA KEV | "not in KEV" (added after acceptance) or "already in KEV when accepted" → "in KEV since <date>", plus ", ransomware use" if flagged | CISA KEV (live or snapshot:<date>) |
| `EPSS_HIGH` | REVOKE | EPSS now ≥ `revoke_epss` (0.5) | EPSS at acceptance → EPSS now | FIRST EPSS |
| `INTERNET_FACING` | REVOKE | a matched asset is marked internet-facing: one of `exposure.internet_tags` (none by default), an address in `exposure.internet_ranges`, or a name, FQDN or IP in `exposure.internet_hosts_file` | "internal" if every such asset became exposed after acceptance; "not tagged internet-facing until <date>" if Tenable shows the exposure tag was added to every such asset after acceptance; else blank → "internet-facing" | the reason: `tag Zone:DMZ: <names>`, `internet range <cidr>: <names>`, `host list <file> (<source>): <names>` |
| `ATTACK_PATH` | REVOKE | a matched asset is on a Tenable One attack path, or its ACR is at least `critical_acr` (9) | blank → "on 3 attack paths (1 critical), ACR 9 of 10" (live) or "on attack path" / "critical asset" (asset list flags) | `Tenable One inventory: <asset>` or `Tenable VM asset: <asset>` (live), `asset inventory: <asset>` |
| `ATTACK_PATH_CVE` | REVOKE | a Tenable One attack path uses one of the exception's CVEs and reaches a covered asset, or crosses a network (CIDR node) a covered asset's IP is in | blank → "<CVE> is used in an attack path: a → 10.1.48.0/22 → b (priority 6.26), and host (10.1.48.38) is on 10.1.48.0/22" (or "…, and the path reaches host"); up to 3 paths, the rest counted in a note | `Tenable One attack paths: <path name>` |
| `EXPLOIT_PUBLIC` | REVIEW | exploit code for a CVE is public: a Metasploit exploit module, an Exploit-DB entry or a Nuclei template (`exploit_feeds`) | "no Exploit-DB entry yet" when the earliest Exploit-DB entry is dated after acceptance, else blank → "public exploit: Metasploit module exploit/…, Exploit-DB 52295 (published 2025-05-18), Nuclei template http/cves/…" | the feeds that list it, e.g. `Exploit-DB, Nuclei (live)` or `(snapshot:<date>)` |
| `NEW_ASSETS` | REVIEW | Tenable first saw a matched asset after the rule was created, so nobody accepted the risk for that host. Needs the asset's first-seen date: Tenable VM's host search (`first_observed`) and bulk export carry it, and Security Center's hosts list (`firstSeen`, joined to the host summary); a Security Center too old to have a hosts list gives none, and the run says so | "covered <n> assets", or "covered no asset Tenable had seen yet" (blank if any matched asset has no date) → "covers <n>: <m> first seen since (latest <date>)", plus ", <k> with no first-seen date" | Tenable first-seen date, naming the new assets |
| `EPSS_ROSE` | REVIEW | EPSS rose by ≥ `review_epss_delta` (0.1) since acceptance | EPSS at acceptance → EPSS now | FIRST EPSS |
| `PUBLIC_IP` | REVIEW | a matched asset has a public IP, or Tenable's `is_public` flag, but is not marked internet-facing (and no matched asset is) | blank → "has a public IP (<ips>), but it is not marked internet-facing" (past 3 IPs or names: "a, b, c and 17 more"), with "and Tenable marks it public" when the flag is set | asset inventory: <asset names> |
| `PATH_CVE_ELSEWHERE` | REVIEW | a Tenable One attack path uses one of the CVEs, but touches none of the covered assets or their networks | blank → "<CVE> is used in <n> attack paths elsewhere, e.g. a → b (priority 7.2)" | `Tenable One attack paths: <path name>` |
| `NO_EXPIRY` | REVIEW | the exception never expires | blank → "no expiry" | rule metadata |
| `TOO_OLD` | REVIEW | older than `review_max_age_days` (365) | the acceptance date → "<n> days old" | rule metadata |
| `EXPIRED_STILL_ENABLED` | REVIEW | past its expiry date but still enabled | blank → "expired <date>, still enabled" | rule metadata |
| `NO_JUSTIFICATION` | REVIEW | the rule gives no reason: the justification (VM comment or description, SC comment, CSV column) is empty, punctuation only, or a placeholder such as "n/a", "TBD" or "test" | blank → "no reason given" | rule metadata |
| `BLANKET` | REVIEW | the rule has no asset filter, so it covers every asset, including ones added later (assets carved out with a negated filter do not change that) | blank → "every asset (<n> today)", or "every asset" when the asset list is not checked for this source | rule metadata |
| `JUSTIFICATION_CONTRADICTED` | REVIEW | the justification claims the asset is internal (`internal_keywords`) but a matched asset is internet-facing or has a public IP | "says internal" → "says internal, but the asset is internet-facing" (or "…, but the asset has a public IP"); also when an `ATTACK_PATH_CVE` path starts from the internet → "says internal, but an attack path from the internet uses this CVE" | justification vs asset inventory (or vs Tenable One attack paths) |

A public IP is a hint, not proof, so it asks for a review and never revokes: network gear can report an
internal routing range that counts as public (Juniper switches use 128.0.0.x), and some assets carry placeholder
addresses. Say what really faces the internet and those assets grade REVOKE:

- `internet_tags`: your own tag names (`Zone: DMZ`, `Environment: External`); case and spaces around `:` are ignored.
- `internet_ranges`: CIDR ranges you publish (a DMZ, an edge range).
- `internet_hosts_file`: a CSV with a `host` column (name, FQDN or IP) and an optional `source` column, exported
  from a firewall, load balancer, CMDB or attack-surface tool. This is the only way to catch hosts behind NAT or a
  load balancer, which carry only a private IP.

- `claims_file`: evidence from the map-exposure step (`exposure.md`): Claude proposes, the `exposure` command
  checks. An IP seen open from the internet by a scan service makes the asset internet-facing; a public DNS name
  that resolves to the asset is a `PUBLIC_IP` hint.

When none of these marks any asset, the report says so (`exposure: no asset is marked internet-facing…`), so a run
with no INTERNET_FACING is not read as "nothing is exposed". Tenable's `CloudScan` asset source is cloud workload
discovery, not a scan from the internet, so it is not used as exposure evidence.

Live, `find` looks up each asset an exception covers in the Tenable One inventory: its Asset Criticality Rating
(ACR, 1-10), Asset Exposure Score (AES, 0-1000) and attack-path counts. Without Tenable One it reads ACR and AES
from the VM asset. When nothing triggers, the finding still notes what was checked, for example
"ACR 5 of 10, AES 707 of 1000, no attack paths (Tenable One inventory)".

The justification is read for two things only: the `internal_keywords` claim, and whether it says anything at all
(`NO_JUSTIFICATION`). Nothing else in a justification can change a grade. A short real reason ("Lab", "Accepted by
CAB") is not flagged: the grader cannot judge whether a reason is good, only whether one was given.

Public exploit code is REVIEW, not REVOKE: it shows an attack is easy to run, not that anyone ran it (that is
`KEV`). Only Exploit-DB dates its entries, so "then" is filled only from that date. A feed that cannot be read is a
note in the report (`exploit feeds: …`), not a failed source, because it can only cost REVIEW evidence. The feeds are
fetched once a day and kept in `intel_cache_dir`.

## Special cases

- **Exclusions** (scan exclusions hide assets, not CVEs) are graded only on `INTERNET_FACING`, `PUBLIC_IP`,
  `ATTACK_PATH`, `NO_EXPIRY`, `TOO_OLD`, `NO_JUSTIFICATION` and `BLANKET`.
- **A disabled rule** is OK, with the note "rule disabled": it hides nothing.
- **A recast that raises severity** is OK, with the note "recast raises severity, so it hides nothing".
- **Notes** that are not triggers: `ASSET_UNKNOWN` (its
  targets match no asset in the inventory), "no CVE intel" (no CVE to look up; graded on age, expiry and exposure
  only). Mention them; they lower confidence, not the grade.

## Order in the report

REVOKE first, then REVIEW, then OK. Within REVIEW: a contradicted justification first, then the most risk triggers (the "now" tier), then housekeeping. Within a grade: the strongest single REVOKE reason first (`KEV`, then
`ATTACK_PATH_CVE`, `INTERNET_FACING`, `EPSS_HIGH`, `ATTACK_PATH`), then the most REVOKE triggers, then the oldest
exception, then by rule id. So a CVE exploited in the wild leads a rule with several weaker reasons.

In the HTML report, eight or more REVIEW or OK rules from one source with the same triggers are shown as one
group row (with a table of the rules); every rule is still listed in `findings.json` and `report.md`.
