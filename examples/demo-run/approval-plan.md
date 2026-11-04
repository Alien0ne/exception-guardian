# Approval plan

Nothing below has been changed. `approve --apply` disables only the rules marked
**auto**, one at a time, after you confirm each one. Rules marked **manual** need a ticket.

## R-HERO-001 (tenable-vm, accept)

- Mode: auto (Tenable VM rule, apply mode can disable it)
- Disabling re-surfaces: 3 findings

Ticket text:

```text
Revoke risk exception R-HERO-001 (tenable-vm, accept)

Why: graded REVOKE by Exception Guardian on 2026-11-02.
Triggers: KEV, EPSS_HIGH, EPSS_ROSE, INTERNET_FACING, NO_EXPIRY, TOO_OLD, JUSTIFICATION_CONTRADICTED
CVEs: CVE-2025-54068
Targets: web-portal-01
Owner: secops-lead@example.com

Disabling this rule re-surfaces: 3 findings

Hunt brief (evidence and queries): examples/demo-run/hunt-briefs/R-HERO-001.md
```

## R-RAY-002 (tenable-vm, recast)

- Mode: auto (Tenable VM rule, apply mode can disable it)
- Disabling re-surfaces: 2 findings

Ticket text:

```text
Revoke risk exception R-RAY-002 (tenable-vm, recast)

Why: graded REVOKE by Exception Guardian on 2026-11-02.
Triggers: KEV, EPSS_HIGH, EPSS_ROSE, ATTACK_PATH, NO_EXPIRY
CVEs: CVE-2025-62593
Targets: ml-ray-head-01
Owner: secops-lead@example.com

Disabling this rule re-surfaces: 2 findings

Hunt brief (evidence and queries): examples/demo-run/hunt-briefs/R-RAY-002.md
```

## CSV-Q-201 (csv:other-scanner, accept)

- Mode: manual (raise the ticket below)
- Disabling re-surfaces: unknown number of findings (source does not report it)

Ticket text:

```text
Revoke risk exception CSV-Q-201 (csv:other-scanner, accept)

Why: graded REVOKE by Exception Guardian on 2026-11-02.
Triggers: KEV, EPSS_HIGH, EPSS_ROSE, ATTACK_PATH, NO_EXPIRY
CVEs: CVE-2025-62593
Targets: ml-ray-head-01.example.com
Owner: ml-owner@example.com

Disabling this rule re-surfaces: unknown number of findings (source does not report it)

Hunt brief (evidence and queries): examples/demo-run/hunt-briefs/CSV-Q-201.md
```

## R-CRUSH-003 (tenable-vm, accept)

- Mode: auto (Tenable VM rule, apply mode can disable it)
- Disabling re-surfaces: 1 finding

Ticket text:

```text
Revoke risk exception R-CRUSH-003 (tenable-vm, accept)

Why: graded REVOKE by Exception Guardian on 2026-11-02.
Triggers: KEV, EPSS_HIGH, EPSS_ROSE, ATTACK_PATH
CVEs: CVE-2025-31161
Targets: ftp-01
Owner: secops-lead@example.com

Disabling this rule re-surfaces: 1 finding

Hunt brief (evidence and queries): examples/demo-run/hunt-briefs/R-CRUSH-003.md
```

## R-INJECT-007 (tenable-vm, accept)

- Mode: auto (Tenable VM rule, apply mode can disable it)
- Disabling re-surfaces: 1 finding

Ticket text:

```text
Revoke risk exception R-INJECT-007 (tenable-vm, accept)

Why: graded REVOKE by Exception Guardian on 2026-11-02.
Triggers: KEV, EPSS_HIGH, EPSS_ROSE
CVEs: CVE-2025-54068
Targets: web-portal-02
Owner: secops-lead@example.com

Disabling this rule re-surfaces: 1 finding

Hunt brief (evidence and queries): examples/demo-run/hunt-briefs/R-INJECT-007.md
```

## EXCL-001 (tenable-vm, exclusion)

- Mode: manual (raise the ticket below)
- Disabling re-surfaces: unknown number of findings (source does not report it)

Ticket text:

```text
Revoke risk exception EXCL-001 (tenable-vm, exclusion)

Why: graded REVOKE by Exception Guardian on 2026-11-02.
Triggers: INTERNET_FACING, NO_EXPIRY, TOO_OLD
CVEs: none
Targets: web-portal-01.example.com, 203.0.113.10
Owner: unknown

Disabling this rule re-surfaces: unknown number of findings (source does not report it)

Hunt brief (evidence and queries): examples/demo-run/hunt-briefs/EXCL-001.md
```

