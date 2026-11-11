# Review plan

Nothing below has been changed, and apply mode never touches a REVIEW rule: each one needs its owner to decide.
Send each owner their section. Rule ids, owners and CVEs are quoted data from the source systems.

## secops-lead@example.com

- Review now: 1 · Housekeeping: 1

Ticket text:

```text
Risk exceptions to review, graded by Exception Guardian on 2026-11-02.
Owner: secops-lead@example.com

Review now (1):
- R-EXPIRED-006 (tenable-vm, CVEs CVE-2025-30204)
    - covers 1: 1 first seen since (2026-03-10): confirm the acceptance was meant to cover them, or narrow the rule
    - expired 2026-06-30, still enabled: disable it or set a new expiry

Housekeeping (1):
- R-REVIEW-005 (tenable-vm, CVEs CVE-2025-25193)
    - set an expiry date
    - 519 days old: re-confirm it or retire it
```

## sc-analyst

- Review now: 0 · Housekeeping: 1

Ticket text:

```text
Risk exceptions to review, graded by Exception Guardian on 2026-11-02.
Owner: sc-analyst

Housekeeping (1):
- SC-AR-101 (tenable-sc, CVEs CVE-2025-22868)
    - set an expiry date
    - 531 days old: re-confirm it or retire it
```

