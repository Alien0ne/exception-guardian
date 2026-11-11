"""Assets from any scanner: a CSV or JSON asset export plus a YAML column map (`assets: {path, map}`), the same
way exceptions from another scanner are read. Without it, a rule from another scanner gets no exposure,
unknown-host or new-asset grading, because the only asset list the tool could read was Tenable's."""
import json
from datetime import date

import pytest

from exception_guardian import assets as m
from exception_guardian.cli import main
from exception_guardian.config import ExposureConfig
from exception_guardian.exposure import apply_exposure

MAP = """columns:
  id: "Asset ID"
  name: "Host Name"
  ips: "IP Addresses"
  fqdns: "DNS Names"
  os: "Operating System"
  tags: "Labels"
  first_seen: "First Seen"
  internet_facing: "Internet Facing"
  critical: "Business Critical"
tag_columns:
  site: "Sites"
date_format: "%d/%m/%Y"
"""
HEAD = ("Asset ID,Host Name,IP Addresses,DNS Names,Operating System,Labels,Sites,First Seen,Internet Facing,"
        "Business Critical\n")
ROWS = ("A1,web-01,10.0.0.5;192.88.99.7,web-01.example.com,Ubuntu 24.04,env:prod;zone:dmz,London;Paris,"
        "01/06/2026,Yes,yes\n"
        "A2,db-01,10.0.0.9,,Windows Server 2022,env:prod,London,10/01/2025,no,\n")


def _files(tmp_path, body=HEAD + ROWS, mapping=MAP, name="assets.csv"):
    f, mp = tmp_path / name, tmp_path / "scanner-assets.yaml"
    f.write_text(body, encoding="utf-8")
    mp.write_text(mapping, encoding="utf-8")
    return {"path": str(f), "map": str(mp)}


def test_a_csv_asset_export_becomes_assets(tmp_path):
    web, db = m.load_assets(_files(tmp_path))
    assert (web.id, web.name, web.os) == ("A1", "web-01", "Ubuntu 24.04")
    assert web.ips == ("10.0.0.5", "192.88.99.7") and web.public_ips == ("192.88.99.7",)
    assert web.fqdns == ("web-01.example.com",)
    assert web.tags == ("env:prod", "zone:dmz", "site:London", "site:Paris")
    assert web.first_seen == date(2026, 6, 1) and db.first_seen == date(2025, 1, 10)
    assert web.critical is True and db.critical is None
    assert db.fqdns == () and db.tags == ("env:prod", "site:London")
    assert web.origin == "asset-file"
    assert m.LAST_WARNINGS == []


def test_the_internet_facing_column_survives_the_exposure_step(tmp_path):
    out, _ = apply_exposure(m.load_assets(_files(tmp_path)), ExposureConfig())
    web, db = out
    assert web.internet_facing and web.exposure_reason == "column 'Internet Facing' in assets.csv"
    assert not db.internet_facing and db.exposure_reason == ""


def test_a_configured_tag_still_wins_over_the_column(tmp_path):
    out, _ = apply_exposure(m.load_assets(_files(tmp_path)), ExposureConfig(internet_tags=("zone:dmz",)))
    assert out[0].exposure_reason == "tag zone:dmz"


def test_targets_match_file_assets_by_name_address_and_tag(tmp_path):
    hosts = m.load_assets(_files(tmp_path))
    assert [a.name for a in m.match(("web-01.example.com",), hosts)] == ["web-01"]
    assert [a.name for a in m.match(("10.0.0.0/24",), hosts)] == ["web-01", "db-01"]
    assert [a.name for a in m.match(("tag:site:paris",), hosts)] == ["web-01"]


def test_a_json_asset_export_is_read_too(tmp_path):
    rows = [{"Asset ID": "A1", "Host Name": "web-01", "IP Addresses": ["10.0.0.5", "192.88.99.7"],
             "Labels": ["env:prod"], "First Seen": "01/06/2026", "Internet Facing": True}]
    web, = m.load_assets(_files(tmp_path, json.dumps(rows), name="assets.json"))
    assert web.ips == ("10.0.0.5", "192.88.99.7") and web.tags == ("env:prod",)
    assert web.first_seen == date(2026, 6, 1) and web.internet_facing


def test_only_a_name_or_an_address_is_needed(tmp_path):
    cfg = _files(tmp_path, "Host,Addr\nweb-01,10.0.0.5\n,10.0.0.6\n",
                 'columns:\n  name: "Host"\n  ips: "Addr"\n')
    a, b = m.load_assets(cfg)
    assert (a.id, a.name) == ("web-01", "web-01") and (b.id, b.name) == ("10.0.0.6", "10.0.0.6")


def test_a_row_with_no_name_id_or_address_is_skipped_with_a_warning(tmp_path):
    cfg = _files(tmp_path, HEAD + ROWS + ",,,,,,,,,\n")
    assert len(m.load_assets(cfg)) == 2
    assert m.LAST_WARNINGS == ["assets.csv: row 4 skipped: it has no id, name or address"]


def test_a_date_that_does_not_fit_the_format_is_a_warning_not_a_guess(tmp_path):
    cfg = _files(tmp_path, HEAD + ROWS.replace("01/06/2026", "2026-06-01"))
    web = m.load_assets(cfg)[0]
    assert web.first_seen is None
    assert m.LAST_WARNINGS == ["assets.csv: row 2 (web-01): first-seen date '2026-06-01' does not fit "
                               "date_format '%d/%m/%Y', so it has no first-seen date"]


def test_a_missing_mapped_column_stops_the_read_and_names_it(tmp_path):
    cfg = _files(tmp_path, HEAD.replace("Host Name", "Hostname") + ROWS)
    with pytest.raises(ValueError, match=r"assets.csv is missing the mapped column 'Host Name' \(name\); it has: "
                                         r"Asset ID, Hostname"):
        m.load_assets(cfg)


def test_a_map_with_an_unknown_key_stops_the_read(tmp_path):
    with pytest.raises(ValueError, match=r"scanner-assets.yaml: unknown column keys \['hostname'\]; known: id, name"):
        m.load_assets(_files(tmp_path, mapping='columns:\n  hostname: "Host Name"\n'))
    with pytest.raises(ValueError, match=r"scanner-assets.yaml: unknown keys \['dates'\]"):
        m.load_assets(_files(tmp_path, mapping='columns:\n  name: "Host Name"\ndates: "%Y"\n'))
    with pytest.raises(ValueError, match="needs a name, id or ips column"):
        m.load_assets(_files(tmp_path, mapping='columns:\n  os: "Operating System"\n'))


def test_an_empty_asset_file_is_an_error_not_an_empty_estate(tmp_path):
    with pytest.raises(ValueError, match="assets.csv has no rows"):
        m.load_assets(_files(tmp_path, HEAD))


def test_path_without_a_map_says_what_is_missing(tmp_path):
    with pytest.raises(ValueError, match="assets: path needs map"):
        m.load_assets({"path": _files(tmp_path)["path"]})


def test_find_grades_another_scanners_rule_against_another_scanners_assets(tmp_path, capsys):
    """End to end, no Tenable anywhere: a rule and an asset list from files. The rule was accepted in March; the
    host it names was first seen in June and the file says it faces the internet."""
    a = _files(tmp_path)
    (tmp_path / "ex.csv").write_text(
        "Exception ID,CVE,Host,Created On,Expires On,Reason,Approved By,State,Exception Type\n"
        "X-1,CVE-2025-27152,web-01,2026-03-01,2027-03-01,Internal only,o@example.com,Active,Risk Accepted\n"
        "X-2,CVE-2025-27152,gone-01,2026-03-01,2027-03-01,Lab box,o@example.com,Active,Risk Accepted\n")
    cfg = tmp_path / "g.yaml"
    cfg.write_text(f"sources:\n  - name: csv\n    path: {tmp_path / 'ex.csv'}\n    map: maps/other-scanner.yaml\n"
                   f"assets:\n  path: {a['path']}\n  map: {a['map']}\n"
                   "intel_snapshot_dir: samples/intel\n")
    out = tmp_path / "out"
    assert main(["find", "--config", str(cfg), "--out", str(out), "--offline", "--today", "2026-11-02"]) in (0, 1)
    report = json.loads((out / "findings.json").read_text())
    by_id = {f["exception"]["rule_id"]: {t["code"] for t in f["triggers"]} | set(f["notes"])
             for f in report["findings"]}
    assert {"INTERNET_FACING", "NEW_ASSETS"} <= by_id["X-1"]
    assert "ASSET_UNKNOWN" in by_id["X-2"]
