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
- **The log tester covers the common Sigma subset:** field matches with contains, startswith, endswith, all,
  regular expressions, CIDR and null; keywords; and `and`, `or`, `not`, `1 of` and `all of` conditions. A rule that
  uses anything else (field references, aggregations, correlations) is reported as not tested.
- **A public IP is a hint, not proof.** An asset counts as internet-facing (REVOKE) only when your own evidence
  says so: tags, internet ranges, or an exported host list (`exposure` settings, `references/grades.md`). A public
  IP on its own only asks for a review (`PUBLIC_IP`). If nothing marks any asset, the playbook offers a passive
  exposure search, and the CLI re-checks every claim; Claude never scans the hosts (`references/exposure.md`).
- **Very large tenants.** `GET /assets` lists at most 5,000 assets, and only licensed hosts seen in the last 90
  days. Every other host is read from the v3 host search, which returns no tags, so `INTERNET_FACING` cannot fire
  for it. When the 5,000 cap is reached, the report says so and is marked partial. The bulk asset export would
  include tags but needs more than a read-only role.
- **"Then" exposure is known only where there is history.** The *then* side of `INTERNET_FACING` comes from an
  exposure-since date on the asset (`x_exposure_since` in the samples). Without one, *then* is left blank.
- **Some rules don't convert to every target.** Microsoft Defender has no web server log table, so web server rules
  are reported as `unsupported` there. Sentinel's ASIM web schema does not map IIS-style fields either. The
  `process_creation` rules convert to all three targets.
- **Qualys, Rapid7 and other scanners are supported through CSV or JSON export only.**
- **Not yet run against a real tenant.** SC assets are not read, and apply mode does not change SC rules. The
  lab's rules filter by plugin, so a rule that filters by CVE (`definition.cve`) has not been seen live. Apply mode
  itself has run live once, on Tenable VM rules (see "Does it work?").
- **CVEs.** Rules filtered by plugin get their CVEs from the plugin details in your own tenant. A plugin with no
  CVE leaves the rule with "no CVE intel": it is still graded on age, expiry and exposure.
- **Targets.** A rule with no asset filter is treated as covering every asset. Tag filters, IP ranges and CIDR
  members are matched against the asset inventory. Other filter properties are ignored.
- **Offline runs use a dated snapshot.** The bundled KEV and EPSS snapshot is dated 2026-11-02. Offline runs grade
  on it, and the report says so.
