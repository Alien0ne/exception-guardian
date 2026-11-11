"""Assets from any scanner: a CSV or JSON asset export plus a YAML column map (`assets: {path, map}`)."""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime
from pathlib import Path

import yaml

from .models import Asset

MAP_KEYS = ("columns", "tag_columns", "date_format", "list_separator", "true_values")
FIELDS = ("id", "name", "ips", "fqdns", "os", "tags", "first_seen", "internet_facing", "critical")
#: one of these must be mapped, or a row cannot be matched to an exception target
IDENTITY = ("name", "id", "ips")
TRUE = ("yes", "true", "1", "y")


def _check_map(map_path: Path, m) -> None:
    """An unknown key stops the read, like the exception map: a misspelled column key would drop that field from
    every asset, and a dropped internet_facing column reads as "nothing is exposed"."""
    def bad(what: str, got, known) -> ValueError:
        return ValueError(f"{map_path.name}: {what} {got}; known: {', '.join(known)}")
    if not isinstance(m, dict) or not isinstance(m.get("columns"), dict) or not m["columns"]:
        raise ValueError(f"{map_path.name}: an asset map needs a columns block (our field: \"their column header\")")
    if unknown := sorted(str(k) for k in m if k not in MAP_KEYS):
        raise bad("unknown keys", unknown, MAP_KEYS)
    if unknown := sorted(str(k) for k in m["columns"] if k not in FIELDS):
        raise bad("unknown column keys", unknown, FIELDS)
    if not any(k in m["columns"] for k in IDENTITY):
        raise ValueError(f"{map_path.name}: an asset map needs a name, id or ips column, or no exception target "
                         "can be matched to an asset")
    if not isinstance(m.get("tag_columns") or {}, dict):
        raise ValueError(f"{map_path.name}: tag_columns must map a tag key to a column (site: \"Sites\")")


def _rows(path: Path, wanted: dict[str, str], warnings: list[str]):
    """Yield (row number, row). CSV row numbers count the header as row 1."""
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, dict) and isinstance(data.get("assets"), list):
            data = data["assets"]
        if not isinstance(data, list):
            raise ValueError(f"{path.name}: a JSON asset export must be a list of asset objects")
        for i, row in enumerate(data, start=1):
            if isinstance(row, dict):
                yield i, row
            else:
                warnings.append(f"{path.name}: row {i} skipped: it is not an object ({type(row).__name__})")
        return
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8-sig")  # -sig drops the byte-order mark Excel writes
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="replace")
        warnings.append(f"{path.name}: not UTF-8, read as Windows-1252")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    have = [h.strip() for h in reader.fieldnames or []]
    if not have:
        raise ValueError(f"{path.name} has no rows (not even a header line)")
    missing = [f"{col!r} ({key})" for key, col in wanted.items() if col not in have]
    if missing:
        raise ValueError(f"{path.name} is missing the mapped column{'s' if len(missing) > 1 else ''} "
                         f"{', '.join(missing)}; it has: {', '.join(have)}. Fix the columns in the map file")
    yield from enumerate(reader, start=2)


def read_asset_file(params: dict, warnings: list[str]) -> list[Asset]:
    from .assets import _public
    if "map" not in params:
        raise ValueError("assets: path needs map, the column map for that file (like maps/other-scanner-assets.yaml)")
    path, map_path = Path(params["path"]), Path(params["map"])
    m = yaml.safe_load(map_path.read_text())
    _check_map(map_path, m)
    cols, tag_cols = m["columns"], m.get("tag_columns") or {}
    fmt = m.get("date_format", "%Y-%m-%d")
    sep = re.compile("|".join(re.escape(s) for s in str(m.get("list_separator", ";,|"))))
    true = {str(v).strip().lower() for v in m.get("true_values", TRUE)}

    def items(row, col) -> tuple[str, ...]:
        v = row.get(col)
        parts = v if isinstance(v, list) else sep.split(str(v or ""))
        return tuple(dict.fromkeys(p for p in (str(x).strip() for x in parts) if p))

    def text(row, key) -> str:
        return str(row.get(cols[key], "") or "").strip() if key in cols else ""

    def flag(row, key) -> bool:
        v = row.get(cols[key]) if key in cols else None
        return v is True or str(v or "").strip().lower() in true

    out, n = [], 0
    wanted = {k: c for k, c in cols.items()} | {f"tag_columns.{k}": c for k, c in tag_cols.items()}
    for n, row in _rows(path, wanted, warnings):
        ips = items(row, cols["ips"]) if "ips" in cols else ()
        ident = text(row, "id") or text(row, "name") or (ips[0] if ips else "")
        if not ident:
            warnings.append(f"{path.name}: row {n} skipped: it has no id, name or address")
            continue
        name = text(row, "name") or ident
        seen, day = text(row, "first_seen"), None
        if seen:
            try:
                day = datetime.strptime(seen, fmt).date()
            except ValueError:
                warnings.append(f"{path.name}: row {n} ({name}): first-seen date {seen[:30]!r} does not fit "
                                f"date_format {fmt!r}, so it has no first-seen date")
        tags = (items(row, cols["tags"]) if "tags" in cols else ()) + tuple(
            f"{key}:{v}" for key, col in tag_cols.items() for v in items(row, col))
        facing = flag(row, "internet_facing")
        out.append(Asset(
            id=ident, name=name, os=text(row, "os") or None, ips=ips,
            fqdns=items(row, cols["fqdns"]) if "fqdns" in cols else (), tags=tags, internet_facing=facing,
            exposure_since=None, critical=True if flag(row, "critical") else None, on_attack_path=None,
            public_ips=_public(ips), origin="asset-file", first_seen=day,
            exposure_reason=f"column {cols['internet_facing']!r} in {path.name}" if facing else ""))
    if n == 0:
        raise ValueError(f"{path.name} has no rows")
    return out
