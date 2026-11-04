# The demo, step by step

Back to the [README](/README.md).

The first finding is an exception accepted on 2025-09-01 because the host was "internal only". Here is what has
changed since:

```text
REVOKE: R-HERO-001 (tenable-vm) — CVE-2025-54068
Evidence                     Then             Now                                      Source
KEV                          not in KEV       in KEV since 2026-03-20                  CISA KEV (snapshot:2026-11-02)
EPSS_HIGH                    0.00145          0.96284                                  FIRST EPSS (snapshot:2026-11-02)
EPSS_ROSE                    0.00145          0.96284                                  FIRST EPSS (snapshot:2026-11-02)
INTERNET_FACING              internal         internet-facing                          tag Exposure:Internet: web-portal-01
NO_EXPIRY                    —                no expiry                                rule metadata
TOO_OLD                      2025-09-01       427 days old                             rule metadata
JUSTIFICATION_CONTRADICTED   says internal    says internal, but the asset is internet-facing  justification vs asset inventory
```

In other words: it is now in CISA KEV, its EPSS score went from 0.001 to 0.96, the host was put on the internet,
the exception never expires, and its own reason ("internal") is no longer true.

Each run can also compare itself with the last one (`find --previous`). In the sample data, `web-portal-01` was
put on the internet on 2026-10-28, between last week's run and this one, so the demo prints just what changed:

```text
Since the last run (2026-10-26): 1 got worse, 1 gained new evidence, 11 unchanged
  EXCL-001: REVIEW → REVOKE, new: INTERNET_FACING
  R-HERO-001: REVOKE, new: INTERNET_FACING, JUSTIFICATION_CONTRADICTED
```

Then guard writes a hunt query for the time the exception was active. This is the Sentinel version of the rule
Claude drafted for this CVE
([`CVE-2025-54068.sentinel.txt`](/examples/demo-run/rules/R-HERO-001/CVE-2025-54068.sentinel.txt), line breaks
added here so it fits):

```kusto
imProcessCreate
| where ((ParentProcessName contains "/php-fpm" or ParentProcessName contains "/bin/php")
      or (ActingProcessName contains "/php-fpm" or ActingProcessName contains "/bin/php"))
    and (TargetProcessName endswith "/sh" or TargetProcessName endswith "/bash" or TargetProcessName endswith "/dash"
      or TargetProcessName endswith "/curl" or TargetProcessName endswith "/wget" or TargetProcessName endswith "/nc"
      or TargetProcessName endswith "/ncat" or TargetProcessName endswith "/python3" or TargetProcessName endswith "/perl"
      or TargetProcessName endswith "/base64")
```

Every rule is also tested against labelled sample logs (`samples/logs/`, synthetic), and the hunt brief reports
the score. This one catches 4 of 4 Livewire attack samples. It fires on 1 of 11 normal events, a Composer deploy
script that its false-positive notes already mention. The generic SigmaHQ web-shell rule catches none of the 7
Linux attack samples (these 4 included), which is why a rule for this CVE was drafted.

## What it saves

To re-check one exception by hand, you open the rule, read why it was accepted, look the CVE up in CISA KEV, find
its EPSS score today and on the day it was accepted, and check whether the host has become internet-facing or
critical since. For each one that should be revoked, someone then has to find or write a detection for the time
it was hidden, translate it for each SIEM, and write the change ticket.

On the sample data, `exception-guardian demo` does all of that for 13 exceptions in under a second on a laptop.

By hand, we estimate (this is a guess, not a measurement) about 10 minutes per exception to gather and compare the
evidence, and about an hour per REVOKE to produce and translate a detection. For the sample, that is roughly 8
hours of an analyst's time, most of it on the six exceptions that matter. Time your own review and compare.

The bigger win is that the check happens at all. Exceptions are rarely looked at after they are accepted, so the
risk they hide grows quietly. Run `find --previous` weekly and you only hear about what got worse.
