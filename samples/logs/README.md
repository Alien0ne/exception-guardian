# Sample logs (synthetic)

Labelled events written for Exception Guardian's rule tests, in Sigma field names. Nothing here is a real log:
hosts, users and addresses come from the sample tenant and documentation ranges (192.0.2.0/24, 198.51.100.0/24).
The Windows files cover CrushFTP (CVE-2025-31161), PrintNightmare (CVE-2021-34527) and Zerologon (CVE-2020-1472);
some attacks are written to slip past the SigmaHQ rules and some benign events to trip them, so the scores show
what a rule misses as well as what it catches.

- `_logsource`: `<category>/<product>` (or just `<category>`), matched against each rule's logsource.
- `_label`: `attack` or `benign`. Attack events name the CVEs they exploit in `_attack`.
- `_note`: what the event is.

`guard` runs every rule it writes against these events and records how many attack samples it caught and how many
benign events it fired on. Point `sample_logs_dir` in guardian.yaml at your own labelled logs to test against those.
