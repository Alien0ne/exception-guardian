# Hunt brief: R-RAY-002

Exception `R-RAY-002` (tenable-vm, recast) suppressed CVE-2025-62593 on ml-ray-head-01. It now grades **REVOKE**. Before the
exception is revoked, hunt for signs that the suppressed weakness was already used.

## Hypothesis

While exception R-RAY-002 was active (2025-12-01 → 2026-11-02), an attacker exploited CVE-2025-62593 on ml-ray-head-01 and the
finding stayed hidden from the vulnerability queue.

## Affected hosts

- ml-ray-head-01 (Linux Rocky 9, IPs 192.0.2.21)

## CVEs and evidence

| Evidence | Then | Now | Source |
|---|---|---|---|
| KEV | not in KEV | in KEV since 2026-08-17 | CISA KEV (snapshot:2026-11-02) |
| EPSS_HIGH | 0.00021 | 0.6015 | FIRST EPSS (snapshot:2026-11-02) |
| EPSS_ROSE | 0.00021 | 0.6015 | FIRST EPSS (snapshot:2026-11-02) |
| ATTACK_PATH | — | on attack path | asset inventory: ml-ray-head-01 |
| NO_EXPIRY | — | no expiry | rule metadata |

## Look-back window

From **2025-12-01** (exception created) to **2026-11-02** (today).

## Detections

- Shell Or Downloader Spawned By Ray Process - Possible CVE-2025-62593 Exploitation (drafted, tested on synthetic sample logs: fires on 3 of 3 attack samples, 0 of 11 benign)
  - defender: `CVE-2025-62593.defender.txt`
  - sentinel: `CVE-2025-62593.sentinel.txt`
  - splunk: `CVE-2025-62593.splunk.txt`
- Linux Webshell Indicators (generic SigmaHQ rule, tested on synthetic sample logs: fires on 0 of 7 attack samples, 0 of 11 benign, https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml)
  - defender: `proc_creation_lnx_webshell_detection.defender.txt`
  - sentinel: `proc_creation_lnx_webshell_detection.sentinel.txt`
  - splunk: `proc_creation_lnx_webshell_detection.splunk.txt`

## Suggested SOC-Hunter starting prompt

> Hunt for exploitation of CVE-2025-62593 on ml-ray-head-01 between 2025-12-01 and 2026-11-02. The exception R-RAY-002 hid this
> exposure from the vulnerability queue. Start with the detections listed in this brief, run each query over the
> window, and report any hit with its host, time and process tree.

Quoted fields (names, CVEs, hosts) come from the source system and are shown escaped.
