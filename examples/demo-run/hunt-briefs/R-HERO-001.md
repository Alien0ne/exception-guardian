# Hunt brief: R-HERO-001

Exception `R-HERO-001` (tenable-vm, accept) suppressed CVE-2025-54068 on web-portal-01. It now grades **REVOKE**. Before the
exception is revoked, hunt for signs that the suppressed weakness was already used.

## Hypothesis

While exception R-HERO-001 was active (2025-09-01 → 2026-11-02), an attacker exploited CVE-2025-54068 on web-portal-01 and the
finding stayed hidden from the vulnerability queue.

## Affected hosts

- web-portal-01 (Linux Ubuntu 22.04, IPs 203.0.113.10)

## CVEs and evidence

| Evidence | Then | Now | Source |
|---|---|---|---|
| KEV | not in KEV | in KEV since 2026-03-20 | CISA KEV (snapshot:2026-11-02) |
| EPSS_HIGH | 0.00145 | 0.96284 | FIRST EPSS (snapshot:2026-11-02) |
| EPSS_ROSE | 0.00145 | 0.96284 | FIRST EPSS (snapshot:2026-11-02) |
| INTERNET_FACING | internal | internet-facing | tag Exposure:Internet: web-portal-01 |
| NO_EXPIRY | — | no expiry | rule metadata |
| TOO_OLD | 2025-09-01 | 427 days old | rule metadata |
| JUSTIFICATION_CONTRADICTED | says internal | says internal, but the asset is internet-facing | justification vs asset inventory |

## Look-back window

From **2025-09-01** (exception created) to **2026-11-02** (today).

## Detections

- Failed Livewire Update Requests - Possible CVE-2025-54068 Exploitation Attempts (drafted, tested on synthetic sample logs: fires on 3 of 3 attack samples, 0 of 6 benign)
  - defender: unsupported: Defender XDR has no table for webserver logs
  - sentinel: unsupported: Sentinel (ASIM) has no field for cs
  - splunk: `CVE-2025-54068-web.splunk.txt`
- Shell Or Downloader Spawned By PHP Worker - Possible Livewire CVE-2025-54068 Exploitation (drafted, tested on synthetic sample logs: fires on 4 of 4 attack samples, 1 of 11 benign (Composer post-install script shells out from PHP during a deploy, a listed false positive))
  - defender: `CVE-2025-54068.defender.txt`
  - sentinel: `CVE-2025-54068.sentinel.txt`
  - splunk: `CVE-2025-54068.splunk.txt`
- Linux Webshell Indicators (generic SigmaHQ rule, tested on synthetic sample logs: fires on 0 of 7 attack samples, 0 of 11 benign, https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml)
  - defender: `proc_creation_lnx_webshell_detection.defender.txt`
  - sentinel: `proc_creation_lnx_webshell_detection.sentinel.txt`
  - splunk: `proc_creation_lnx_webshell_detection.splunk.txt`

## Suggested SOC-Hunter starting prompt

> Hunt for exploitation of CVE-2025-54068 on web-portal-01 between 2025-09-01 and 2026-11-02. The exception R-HERO-001 hid this
> exposure from the vulnerability queue. Start with the detections listed in this brief, run each query over the
> window, and report any hit with its host, time and process tree.

Quoted fields (names, CVEs, hosts) come from the source system and are shown escaped.
