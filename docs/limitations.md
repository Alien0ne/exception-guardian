# Known limitations, in full

Back to the [README](/README.md).

- **Drafted Sigma rules are drafts.** They are checked for syntax and conversion and tested against the labelled
  sample logs, which are synthetic. A rule that catches every sample attack has passed a smoke test, not proof
  against real traffic (on the live lab run, the Kerberos TGS rule missed one sample whose ticket type it does not
  watch). The samples cover Linux and Windows process creation, Windows image loads and registry events, and web
  server logs; where none exist for a rule's log source, the hunt brief says it was not tested. DC rules are scored
  against stand-in DCs (`DC-01$`, `DC-02$`), while the SIEM queries keep your real values. Review drafts before you
  rely on them, and test them against your own logs by pointing `sample_logs_dir` at them.
- **Some Sentinel queries need the Defender XDR connector.** ASIM has no table for antivirus detections or image
  loads, so those rules use Defender XDR's `DeviceEvents` and `DeviceImageLoadEvents` tables. Sentinel only has
  them when the Microsoft Defender XDR connector streams them in. The antivirus query notes say so.
- **The log tester does not judge time parts or correlations.** It evaluates field matches (contains, startswith,
  endswith, all, regular expressions, CIDR, null, `windash`), field references, number comparisons, `exists`,
  booleans, keywords, and `and`, `or`, `not`, `1 of` and `all of` conditions. A rule that uses a time part
  (`|hour`, `|day`) or is a correlation rule is reported as not tested, never guessed.
- **A public IP is a hint, not proof.** An asset counts as internet-facing (REVOKE) only when your own evidence
  says so: tags, internet ranges, or an exported host list (`exposure` settings, `references/grades.md`). A public
  IP on its own only asks for a review (`PUBLIC_IP`). If nothing marks any asset, the playbook offers a passive
  exposure search, and the CLI re-checks every claim; Claude never scans the hosts (`references/exposure.md`).
- **Very large tenants.** `GET /assets` lists at most 5,000 assets, and only licensed hosts seen in the last 90
  days. When that cap is reached, the hosts are read from the bulk asset export instead, which returns every host
  with its tags, so `INTERNET_FACING` still works. The export needs the Basic role or the export privilege; if it
  fails, the extra hosts come from the v3 host search without tags, and the report says so and is marked partial.
  Set `assets.export: always` to use the export on every run (it also brings tags for hosts the list leaves out),
  or `false` to never start one. Tenable One context is looked up for at most `max_context_lookups` assets (1,500).
- **"Then" exposure comes from the tag's own date.** Tenable records the day each tag was added to an asset. When
  the tag that marks an asset internet-facing was added after the rule was created, the *then* side reads "not
  tagged internet-facing until <date>". That is when the tag was added, not proof of when the host was exposed.
  Exposure taken from a range, a host list or a verified claim has no date, so *then* stays blank there.
- **Some rules don't convert to every target.** Microsoft Defender has no web server log table, so web server rules
  are reported as `unsupported` there. Sentinel's ASIM web schema does not map IIS-style fields either. The
  `process_creation` rules convert to all three targets.
- **Qualys, Rapid7 and other scanners are supported through CSV or JSON export only.**
- **Security Center rules are never changed by apply mode.** Security Center can delete a rule but not disable
  it, and a delete cannot be undone, so it stays a person's step: the plan says so and `sc-rule-backups.json`
  keeps a copy of each REVOKE rule to create it again from.
- **`NEW_ASSETS` goes by the day Tenable first saw a host,** not the day the host was built. A long-running
  server that was scanned for the first time last month reads as new. On a blanket rule new
  hosts are expected, so there it does not move the rule to "review now".
- **Public exploit feeds are a signal, not proof of attack.** `EXPLOIT_PUBLIC` (REVIEW) means Metasploit,
  Exploit-DB or Nuclei lists the CVE. Tenable VPR and VulnCheck KEV are not read.
- **Notifications and tickets.** `notify` posts to one chat webhook. No ticketing system is called:
  `tickets.json` is for a script of your own. Queries are written to files, never run in your SIEM.
- **The Elastic target is opt-in and was checked on sample rules only**, not in a live Elastic stack.
- **Seen live on one lab only.** The
  lab's rules filter by plugin, so a rule that filters by CVE (`definition.cve`) has not been seen live. Apply mode
  itself has run live once, on Tenable VM rules (see "Does it work?").
- **CVEs.** Rules filtered by plugin get their CVEs from the plugin details in your own tenant. A plugin with no
  CVE leaves the rule with "no CVE intel": it is still graded on age, expiry and exposure.
- **Targets.** A rule with no asset filter is treated as covering every asset. Tag filters, IP ranges and CIDR
  members are matched against the asset inventory. Other filter properties are ignored.
- **Offline runs use a dated snapshot.** The bundled one is a small sample dated 2026-11-02, for the demo. For
  your own offline runs, save a fresh one from an online run (`find --save-intel <dir>`) and point
  `intel_snapshot_dir` at it. The report names the snapshot's date either way.
