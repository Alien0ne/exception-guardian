# Hunt brief: EXCL-001

Exception `EXCL-001` (tenable-vm, exclusion) suppressed no CVE (exclusion) on web-portal-01. It now grades **REVOKE**. Before the
exception is revoked, hunt for signs that the suppressed weakness was already used.

## Hypothesis

While exception EXCL-001 was active (2025-03-01 → 2026-11-02), an attacker exploited no CVE (exclusion) on web-portal-01 and the
finding stayed hidden from the vulnerability queue.

## Affected hosts

- web-portal-01 (Linux Ubuntu 22.04, IPs 203.0.113.10)

## CVEs and evidence

| Evidence | Then | Now | Source |
|---|---|---|---|
| INTERNET_FACING | internal | internet-facing | tag Exposure:Internet: web-portal-01 |
| NO_EXPIRY | — | no expiry | rule metadata |
| TOO_OLD | 2025-03-01 | 611 days old | rule metadata |

## Look-back window

From **2025-03-01** (exception created) to **2026-11-02** (today).

## Detections

- Linux Webshell Indicators (generic SigmaHQ rule, tested on synthetic sample logs: fires on 0 of 7 attack samples, 0 of 11 benign, https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml)
  - defender: `proc_creation_lnx_webshell_detection.defender.txt`
  - sentinel: `proc_creation_lnx_webshell_detection.sentinel.txt`
  - splunk: `proc_creation_lnx_webshell_detection.splunk.txt`

## Suggested SOC-Hunter starting prompt

> Hunt for exploitation of no CVE (exclusion) on web-portal-01 between 2025-03-01 and 2026-11-02. The exception EXCL-001 hid this
> exposure from the vulnerability queue. Start with the detections listed in this brief, run each query over the
> window, and report any hit with its host, time and process tree.

Quoted fields (names, CVEs, hosts) come from the source system and are shown escaped.
