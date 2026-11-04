# Hunt brief: R-INJECT-007

Exception `R-INJECT-007` (tenable-vm, accept) suppressed CVE-2025-54068 on web-portal-02. It now grades **REVOKE**. Before the
exception is revoked, hunt for signs that the suppressed weakness was already used.

## Hypothesis

While exception R-INJECT-007 was active (2026-04-01 → 2026-11-02), an attacker exploited CVE-2025-54068 on web-portal-02 and the
finding stayed hidden from the vulnerability queue.

## Affected hosts

- web-portal-02 (Linux Ubuntu 22.04, IPs 192.0.2.11)

## CVEs and evidence

| Evidence | Then | Now | Source |
|---|---|---|---|
| KEV | already in KEV when accepted | in KEV since 2026-03-20 | CISA KEV (snapshot:2026-11-02) |
| EPSS_HIGH | 0.48851 | 0.96284 | FIRST EPSS (snapshot:2026-11-02) |
| EPSS_ROSE | 0.48851 | 0.96284 | FIRST EPSS (snapshot:2026-11-02) |

## Look-back window

From **2026-04-01** (exception created) to **2026-11-02** (today).

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

> Hunt for exploitation of CVE-2025-54068 on web-portal-02 between 2026-04-01 and 2026-11-02. The exception R-INJECT-007 hid this
> exposure from the vulnerability queue. Start with the detections listed in this brief, run each query over the
> window, and report any hit with its host, time and process tree.

Quoted fields (names, CVEs, hosts) come from the source system and are shown escaped.
