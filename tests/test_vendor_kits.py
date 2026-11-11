"""Ready-made kits for scanners other than Tenable: a column map, the export query where the vendor has one, and
a sample export. Each kit must read cleanly and grade end to end with no Tenable source in the config."""
import json
import re
from datetime import date
from pathlib import Path

import yaml

from exception_guardian import assets as m
from exception_guardian.cli import main
from exception_guardian.readers import get_reader

R7 = {"path": "samples/rapid7/exceptions.csv", "map": "maps/rapid7-insightvm.yaml"}
R7_ASSETS = {"path": "samples/rapid7/assets.csv", "map": "maps/rapid7-insightvm-assets.yaml"}
MDE_ASSETS = {"path": "samples/defender/devices.csv", "map": "maps/defender-assets.yaml"}


def test_the_rapid7_exception_sample_reads_with_no_warnings():
    reader = get_reader("csv")
    rules = {e.rule_id: e for e in reader(R7)}
    assert len(rules) == 6 and reader.__module__ and not __import__(reader.__module__, fromlist=["x"]).LAST_WARNINGS
    assert rules["101"].targets == ("*",) and rules["102"].targets == ("tag:site:London DC",)
    assert rules["103"].targets == ("tag:group:Payments",) and rules["104"].targets == ("app-01.example.com",)
    assert rules["101"].created == date(2025, 2, 10) and rules["102"].expires == date(2027, 3, 1)
    # Rapid7 applies only an approved exception: the other states grade as not live
    assert {i: e.status for i, e in rules.items()} == {"101": "enabled", "102": "enabled", "103": "enabled",
                                                       "104": "enabled", "105": "disabled", "106": "disabled"}
    assert rules["102"].justification.startswith("Compensating Control: ")
    assert all(e.source == "csv:rapid7-insightvm" for e in rules.values())


def test_the_rapid7_asset_sample_reads_sites_groups_and_first_seen():
    hosts = {a.name: a for a in m.load_assets(R7_ASSETS)}
    assert m.LAST_WARNINGS == [] and len(hosts) == 5
    web = hosts["web-01.example.com"]
    assert web.tags == ("site:London DC", "group:Payments", "group:Internet Facing")
    assert web.first_seen == date(2026, 6, 14) and web.ips == ("10.20.0.11", "192.88.99.21")
    assert web.os == "Ubuntu Linux 24.04"


def test_each_export_query_returns_every_column_its_map_reads():
    """The map and the query ship together: a column renamed in one and not the other reads as a missing column."""
    for sql, mapping in (("maps/rapid7-insightvm-exceptions.sql", "maps/rapid7-insightvm.yaml"),
                         ("maps/rapid7-insightvm-assets.sql", "maps/rapid7-insightvm-assets.yaml")):
        mp = yaml.safe_load(Path(mapping).read_text())
        aliases = set(re.findall(r"\bAS (\w+)\s*(?:,|\n)", Path(sql).read_text()))
        wanted = set(mp["columns"].values()) | set((mp.get("tag_columns") or {}).values())
        assert wanted <= aliases, (sql, wanted - aliases)


def test_the_defender_device_sample_reads_tags_criticality_and_first_seen():
    hosts = {a.name: a for a in m.load_assets(MDE_ASSETS)}
    assert m.LAST_WARNINGS == [] and len(hosts) == 4
    web = hosts["srv-web-01"]
    assert "tag:internet-facing" in web.tags and web.first_seen == date(2026, 6, 14) and web.critical is True
    assert hosts["wks-hr-07"].critical is None and hosts["wks-hr-07"].fqdns == ()


def _find(tmp_path, config):
    out = tmp_path / "out"
    assert main(["find", "--config", config, "--out", str(out), "--offline", "--today", "2026-11-02"]) in (0, 1)
    report = json.loads((out / "findings.json").read_text())
    return report, {f["exception"]["rule_id"]: f for f in report["findings"]}


def _codes(f):
    return {t["code"] for t in f["triggers"]} | set(f["notes"])


def test_the_rapid7_kit_grades_end_to_end_without_tenable(tmp_path):
    report, by_id = _find(tmp_path, "samples/rapid7/guardian.yaml")
    assert not report["partial"] and not report["warnings"]
    assert {f["exception"]["source"] for f in report["findings"]} == {"csv:rapid7-insightvm"}
    # 102 is scoped to a site: one of the site's hosts is tagged internet-facing and joined after the acceptance
    assert {"INTERNET_FACING", "NEW_ASSETS"} <= _codes(by_id["102"]) and by_id["102"]["grade"] == "REVOKE"
    assert {a["name"] for a in by_id["102"]["assets"]} == {"web-01.example.com", "db-01.example.com"}
    assert "BLANKET" in _codes(by_id["101"])                      # a global exception covers every asset
    assert "ASSET_UNKNOWN" in _codes(by_id["104"])                # the named host is not in the asset export
    assert {a["name"] for a in by_id["103"]["assets"]} == {"web-01.example.com", "pay-01.example.com"}


def test_the_defender_device_list_gives_exposure_to_rules_from_a_file(tmp_path):
    cfg = tmp_path / "g.yaml"
    (tmp_path / "ex.csv").write_text(
        "Exception ID,CVE,Host,Created On,Expires On,Reason,Approved By,State,Exception Type\n"
        "D-1,CVE-2025-27152,srv-web-01,2026-03-01,2027-03-01,Internal only,o@example.com,Active,Risk Accepted\n")
    cfg.write_text(f"sources:\n  - name: csv\n    path: {tmp_path / 'ex.csv'}\n    map: maps/other-scanner.yaml\n"
                   "assets:\n  path: samples/defender/devices.csv\n  map: maps/defender-assets.yaml\n"
                   "exposure:\n  internet_tags: ['tag:internet-facing']\nintel_snapshot_dir: samples/intel\n")
    _, by_id = _find(tmp_path, str(cfg))
    assert {"INTERNET_FACING", "NEW_ASSETS"} <= _codes(by_id["D-1"])
