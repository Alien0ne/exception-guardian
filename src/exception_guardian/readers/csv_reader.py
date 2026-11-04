"""Generic CSV/JSON exception export + YAML column map (any scanner)."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path

import yaml

from ..cves import split_cves
from ..models import RiskException, RuleType
from . import register

#: Warnings from the last read (malformed rows); read_all collects them.
LAST_WARNINGS: list[str] = []


def _rows(path: Path, cols: dict):
    """Yield (line_number, row). CSV line numbers count the header as line 1."""
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(data, list):
            raise ValueError(f"{path.name}: a JSON export must be a list of exception objects, "
                             f"not a {type(data).__name__}")
        for i, row in enumerate(data, start=1):
            if not isinstance(row, dict):
                LAST_WARNINGS.append(f"{path.name}: row {i} skipped: it is not an object ({type(row).__name__})")
                continue
            yield i, row
    else:
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8-sig")  # -sig drops the byte-order mark Excel writes
        except UnicodeDecodeError:
            text = raw.decode("cp1252", errors="replace")
            LAST_WARNINGS.append(f"{path.name}: not UTF-8, read as Windows-1252")
        reader = csv.DictReader(io.StringIO(text, newline=""))
        _check_header(path, reader.fieldnames or [], cols)
        for i, row in enumerate(reader, start=2):
            yield i, row


#: columns a row cannot be read without; the rest are optional
REQUIRED = ("type", "created", "cve")


def _check_header(path: Path, header: list[str], cols: dict) -> None:
    """A file from another tool, or the wrong map: say which columns are missing and what the file has, instead
    of skipping every row (which reads as "0 exceptions", a clean run)."""
    if not header:
        raise ValueError(f"{path.name} has no rows (not even a header line)")
    have = [h.strip() for h in header]
    missing = [f"{cols[k]!r} ({k})" for k in REQUIRED if k in cols and cols[k] not in have]
    if missing:
        raise ValueError(f"{path.name} is missing the mapped column{'s' if len(missing) > 1 else ''} "
                         f"{', '.join(missing)}; it has: {', '.join(have)}. Fix the columns in the map file")


MAP_KEYS = ("columns", "date_format", "type_values", "status_values")
FIELDS = ("rule_id", "cve", "target", "created", "expires", "justification", "owner", "status", "type")
STATUSES = ("enabled", "disabled")


def _check_map(map_path: Path, m) -> None:
    """Like guardian.yaml, a map with an unknown key or value stops the source: a misspelled column key would
    drop that field from every row, and a misspelled status would grade a disabled rule as live."""
    def bad(what: str, got, known) -> ValueError:
        return ValueError(f"{map_path.name}: {what} {got}; known: {', '.join(known)}")
    if not isinstance(m, dict):
        raise ValueError(f"{map_path.name}: a column map must be a YAML mapping with a columns block")
    if unknown := sorted(str(k) for k in m if k not in MAP_KEYS):
        raise bad("unknown keys", unknown, MAP_KEYS)
    if not isinstance(m.get("columns"), dict) or not m["columns"]:
        raise ValueError(f"{map_path.name}: no columns block (our field: \"their column header\")")
    for key in ("type_values", "status_values"):
        if not isinstance(m.get(key) or {}, dict):
            raise ValueError(f"{map_path.name}: {key} must map their value to ours (\"Accepted\": accept), "
                             f"not a {type(m[key]).__name__}")
    if unknown := sorted(str(k) for k in m["columns"] if k not in FIELDS):
        raise bad("unknown column keys", unknown, FIELDS)
    if unknown := sorted(str(v) for v in (m.get("type_values") or {}).values()
                         if v not in {t.value for t in RuleType}):
        raise bad("unknown type_values", unknown, [t.value for t in RuleType])
    if unknown := sorted(str(v) for v in (m.get("status_values") or {}).values() if v not in STATUSES):
        raise bad("unknown status_values", unknown, STATUSES)


@register("csv")
def read(params: dict) -> list[RiskException]:
    LAST_WARNINGS.clear()
    path, map_path = Path(params["path"]), Path(params["map"])
    m = yaml.safe_load(map_path.read_text())
    _check_map(map_path, m)
    cols, fmt = m["columns"], m.get("date_format", "%Y-%m-%d")
    types, statuses = m.get("type_values", {}), m.get("status_values", {})
    source = "csv:" + map_path.stem

    def cell(row, key):
        return str(row.get(cols[key], "") or "").strip() if key in cols else ""

    def parse_date(s):
        return datetime.strptime(s, fmt).date() if s else None

    status_map = {str(k).strip().lower(): v for k, v in statuses.items()}
    seen: set[str] = set()
    out = []
    n = 0
    for n, row in _rows(path, cols):
        rid = cell(row, "rule_id") or f"{path.name}:{n}"
        if rid in seen:
            LAST_WARNINGS.append(f"{source}: duplicate rule id {rid[:40]!r} at row {n}, kept as {rid[:40]!r} (row {n})")
            rid = f"{rid} (row {n})"
        seen.add(rid)
        try:
            if cell(row, "type") not in types:
                raise ValueError(f"unknown exception type {cell(row, 'type')[:40]!r}")
            rtype = RuleType(types[cell(row, "type")])
            cves, bad = split_cves(cell(row, "cve"))
            if bad:
                raise ValueError(f"not a CVE id: {bad[0][:40]!r}")
            if not cves and rtype is not RuleType.EXCLUSION:
                raise ValueError("missing CVE")
            created = parse_date(cell(row, "created"))
            if created is None:
                raise ValueError("missing created date")
            expires = parse_date(cell(row, "expires"))
        except (KeyError, ValueError) as exc:
            LAST_WARNINGS.append(f"{source}: row {n} ({rid}) skipped: {exc}")
            continue
        st = cell(row, "status")
        if st and st.lower() not in status_map:
            LAST_WARNINGS.append(f"{source}: row {n} ({rid}) has unknown status {st[:30]!r}, so it is read as "
                                 "enabled. Add it to status_values.")
        out.append(RiskException(
            source=source, rule_id=rid, rule_type=rtype, cves=cves, plugin_ids=(),
            targets=tuple(t.strip() for t in cell(row, "target").split(",") if t.strip()),
            original_severity=None, new_severity=None, owner=cell(row, "owner") or None,
            created=created, updated=None, expires=expires, justification=cell(row, "justification"),
            status=status_map.get(st.lower(), "enabled") if st else "enabled", revised_findings=None, raw=dict(row)))
    if n == 0:
        raise ValueError(f"{path.name} has no rows")
    return out
