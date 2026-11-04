# Worked example: R-HERO-001 on the sample data

What a good run sounds like, from `exception-guardian demo --out out/demo` (offline, today 2026-11-02). Every value
below is what the tool printed; a real run is explained the same way, with its own values.

## The exception

A Tenable VM **accept** rule for CVE-2025-54068 (Livewire) on `web-portal-01`, accepted 2025-09-01 with no expiry,
owner secops-lead@example.com. Justification, quoted as data: "Low risk - internal only app, compensating controls
in place".

## Step 1: find

Counts: REVOKE 6, REVIEW 3, OK 4. R-HERO-001 leads the report: it has the most REVOKE triggers.

| Trigger | Then | Now | Source |
|---|---|---|---|
| KEV | not in KEV | in KEV since 2026-03-20 | CISA KEV (snapshot:2026-11-02) |
| EPSS_HIGH | 0.00145 | 0.96284 | FIRST EPSS (snapshot:2026-11-02) |
| EPSS_ROSE | 0.00145 | 0.96284 | FIRST EPSS (snapshot:2026-11-02) |
| INTERNET_FACING | internal | internet-facing | tag Exposure:Internet: web-portal-01 |
| NO_EXPIRY | | no expiry | rule metadata |
| TOO_OLD | 2025-09-01 | 427 days old | rule metadata |
| JUSTIFICATION_CONTRADICTED | says internal | says internal, but the asset is internet-facing | justification vs asset inventory |

Since last week's run (2026-10-26) it gained new evidence: INTERNET_FACING and JUSTIFICATION_CONTRADICTED.
web-portal-01 went on the internet on 2026-10-28.

How to say it: "Revoke R-HERO-001 first. When it was accepted, CVE-2025-54068 wasn't in KEV and its EPSS was
0.00145. It has been in KEV since 2026-03-20, its EPSS is now 0.96284, and since 28 October the asset it covers
is internet-facing, although the justification says the app is internal."

## Step 2: guard

SigmaHQ had no rule for this CVE, so two drafts were written (see `samples/golden/drafts/`) and one generic SigmaHQ
rule was attached.

| Rule | Origin | Attack samples caught | Benign events flagged | Queries |
|---|---|---|---|---|
| Shell or downloader spawned by PHP worker | drafted | 4 of 4 | 1 of 11 (a Composer deploy script, already a listed false positive) | Splunk, Sentinel, Defender |
| Failed Livewire update requests | drafted | 3 of 3 | 0 of 6 | Splunk only (webserver logs: Sentinel and Defender unsupported) |
| Linux webshell indicators | generic SigmaHQ | 0 of 7 | 0 of 11 | Splunk, Sentinel, Defender |

How to say it: the two drafted rules catch every attack sample. The generic rule catches none, which is why the
drafts matter (a generic rule is scored on every attack sample of its log source, here all 7 Linux ones). The web rule has no Sentinel or Defender query. The sample logs are synthetic, so this is a smoke
test, not proof.

## Step 3: approve

`approval-plan.md`: mode **auto** (a Tenable VM rule, so `--apply` can disable it after the owner confirms);
disabling it re-surfaces 3 findings. The ticket text is ready to paste. Nothing has been changed.

## Step 4: hunt

`hunt-briefs/R-HERO-001.md` ends with a starting prompt for SOC-Hunter: hunt for exploitation of CVE-2025-54068 on
web-portal-01 between 2025-09-01 and 2026-11-02, the window when the exception hid it.

## The page

`out/demo/report.html` shows all of the above on one page: the counts, R-HERO-001 with its EPSS jump, the changes
since last week, every exception ranked, the hunt queries with their scores and copy buttons, and the plan.
