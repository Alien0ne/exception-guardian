# Adding a source

Exception Guardian reads exceptions through small reader functions. Each one turns a source's data into
`RiskException` records. The grading, report, guard and approval steps only ever see `RiskException`.

You can add a source in one of two ways:

- **No code.** Export the exceptions to CSV or JSON and write a column map (see [below](#a-new-csv-map)).
- **A reader.** Write a module, if the source has an API you want to call directly.

## The reader contract

```python
from exception_guardian.models import RiskException, RuleType
from exception_guardian.readers import register

@register("my-source")              # the name used in guardian.yaml `sources[].name`
def read(params: dict) -> list[RiskException]:
    ...
```

- `params` is the source's entry in `guardian.yaml`, minus `name`.
- Raise an exception on failure. `read_all` catches it, records `source my-source failed: ...`, and marks the run
  **PARTIAL RUN**, so one bad source never sinks the others.
- To report skipped rows without failing, expose a module-level `LAST_WARNINGS: list[str]`. Clear it at the start
  of `read`; `read_all` collects it after the call.
- Built-in readers are imported lazily. Add your module's name to `_BUILTIN` in
  `src/exception_guardian/readers/__init__.py`.
- Credentials come only from environment variables (the CLI loads the git-ignored `.env` into them at start),
  never from `params` or files in the repo.

### `RiskException` fields

| Field | Type | Notes |
|---|---|---|
| `source` | str | the reader name, e.g. `qualys` |
| `rule_id` | str | the source's id for the exception |
| `rule_type` | `RuleType` | `ACCEPT`, `RECAST` or `EXCLUSION` |
| `cves` | tuple[str, ...] | upper-case `CVE-YYYY-NNNN`; empty for plugin-only rules and exclusions |
| `plugin_ids` | tuple[str, ...] | scanner check ids, if any |
| `targets` | tuple[str, ...] | host names, FQDNs, IPs or asset ids; matched case-insensitively against the asset inventory |
| `original_severity`, `new_severity` | str \| None | for recasts; a recast that raises severity is graded OK |
| `owner` | str \| None | who approved it |
| `created` | date | **required**; the look-back window and the EPSS "then" value use it |
| `updated`, `expires` | date \| None | `expires=None` means never, which grades REVIEW |
| `justification` | str | free text, treated as untrusted data |
| `status` | str | `"enabled"` or `"disabled"`; disabled rules are graded OK |
| `revised_findings` | int \| None | how many findings the exception hides, if the source reports it |
| `revised_findings_capped` | bool | default `False`; `True` when the count stopped at a page cap, so it means "at least" |
| `raw` | dict | the original record, kept for reference; not compared |

## Worked example: a `qualys` reader

Qualys VMDR has no single "exceptions" export in this tool. The simplest path is a CSV map, described below. If
you want an API reader, it looks like this:

```python
# src/exception_guardian/readers/qualys.py
"""Qualys VMDR exceptions via its API (example)."""
from __future__ import annotations

import os
from datetime import date

import requests

from ..models import RiskException, RuleType
from . import register

LAST_WARNINGS: list[str] = []


@register("qualys")
def read(params: dict) -> list[RiskException]:
    LAST_WARNINGS.clear()
    auth = (os.environ["QUALYS_USERNAME"], os.environ["QUALYS_PASSWORD"])
    resp = requests.get(params["base_url"] + params.get("path", "/exceptions"), auth=auth, timeout=30)
    resp.raise_for_status()
    out = []
    for n, row in enumerate(resp.json(), start=1):
        try:
            created = date.fromisoformat(row["created"][:10])
        except (KeyError, ValueError):
            LAST_WARNINGS.append(f"qualys: record {n} skipped: bad created date")
            continue
        out.append(RiskException(
            source="qualys", rule_id=str(row["id"]), rule_type=RuleType.ACCEPT,
            cves=tuple(c.upper() for c in row.get("cves", [])), plugin_ids=(str(row["qid"]),),
            targets=tuple(row.get("hosts", [])), original_severity=None, new_severity=None,
            owner=row.get("approver"), created=created, updated=None,
            expires=date.fromisoformat(row["expires"][:10]) if row.get("expires") else None,
            justification=row.get("comment", ""), status="enabled" if row.get("active", True) else "disabled",
            revised_findings=None, raw=row))
    return out
```

The field names in `row[...]` are placeholders: map them to what your Qualys API version returns. Then:

1. Add `"qualys"` to `_BUILTIN` in `readers/__init__.py`.
2. Add the source to your config:

   ```yaml
   sources:
     - name: qualys
       base_url: https://qualysapi.qualys.com
   ```

3. Add a fixture and a test: copy `tests/test_reader_csv.py` as a pattern. Assert the ids, the `rule_type`, the
   dates, and that a bad record lands in `LAST_WARNINGS`.

## A new CSV map

Any scanner that can export exceptions works with the built-in `csv` reader and a YAML column map. Copy
`maps/other-scanner.yaml`:

```yaml
columns:              # our field: "their column header"
  rule_id: "Exception ID"
  cve: "CVE"          # one or more CVE ids, split on commas, semicolons or spaces
  target: "Host"      # comma-separated for several hosts
  created: "Created On"
  expires: "Expires On"
  justification: "Reason"
  owner: "Approved By"
  status: "State"
  type: "Exception Type"
date_format: "%Y-%m-%d"    # Python strptime format of their dates
type_values:               # their value: accept | recast | exclusion
  "Risk Accepted": accept
  "Severity Changed": recast
  "Excluded": exclusion
status_values:             # their value: enabled | disabled (missing = enabled)
  "Active": enabled
  "Inactive": disabled
```

Then add the source:

```yaml
sources:
  - name: csv
    path: exports/qualys-exceptions.csv     # or a .json list of objects with the same keys
    map: maps/qualys.yaml
```

The source shows as `csv:<map file name>` (here `csv:qualys`). An unknown key or value in the map (a misspelled
column key, a status other than `enabled` / `disabled`, a type other than `accept` / `recast` / `exclusion`) stops
that source with a message naming it, and the run is marked partial. The reader skips some rows and lists each one as a
warning in the report, with its file line number. A row is skipped when:
- it has an unknown type;
- it has no CVE (unless it is an exclusion);
- its created date is missing or bad.
