# Hunt brief: R-CRUSH-003

Exception `R-CRUSH-003` (tenable-vm, accept) suppressed CVE-2025-31161 on ftp-01. It now grades **REVOKE**. Before the
exception is revoked, hunt for signs that the suppressed weakness was already used.

## Hypothesis

While exception R-CRUSH-003 was active (2026-02-10 → 2026-11-02), an attacker exploited CVE-2025-31161 on ftp-01 and the
finding stayed hidden from the vulnerability queue.

## Affected hosts

- ftp-01 (Microsoft Windows Server 2022, IPs 192.0.2.30)

## CVEs and evidence

| Evidence | Then | Now | Source |
|---|---|---|---|
| KEV | already in KEV when accepted | in KEV since 2025-04-07, ransomware use | CISA KEV (snapshot:2026-11-02) |
| EPSS_HIGH | 0.87967 | 0.99969 | FIRST EPSS (snapshot:2026-11-02) |
| EPSS_ROSE | 0.87967 | 0.99969 | FIRST EPSS (snapshot:2026-11-02) |
| ATTACK_PATH | — | critical asset | asset inventory: ftp-01 |

## Look-back window

From **2026-02-10** (exception created) to **2026-11-02** (today).

## Detections

- Suspicious CrushFTP Child Process (SigmaHQ rule, tested on synthetic sample logs: fires on 2 of 2 attack samples, 1 of 4 benign (CrushFTP runs its own update script through cmd), https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2025/Exploits/CVE-2025-31161/proc_creation_win_crushftp_susp_child_processes.yml)
  - defender: `proc_creation_win_crushftp_susp_child_processes.defender.txt`
  - sentinel: `proc_creation_win_crushftp_susp_child_processes.sentinel.txt`
  - splunk: `proc_creation_win_crushftp_susp_child_processes.splunk.txt`

## Suggested SOC-Hunter starting prompt

> Hunt for exploitation of CVE-2025-31161 on ftp-01 between 2026-02-10 and 2026-11-02. The exception R-CRUSH-003 hid this
> exposure from the vulnerability queue. Start with the detections listed in this brief, run each query over the
> window, and report any hit with its host, time and process tree.

Quoted fields (names, CVEs, hosts) come from the source system and are shown escaped.
