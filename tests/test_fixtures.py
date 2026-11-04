import csv
import json
from pathlib import Path

VM = Path("samples/tenable_vm")
VM_RULES = {"R-HERO-001", "R-RAY-002", "R-CRUSH-003", "R-OK-004", "R-REVIEW-005",
            "R-EXPIRED-006", "R-INJECT-007", "R-RAISE-008"}


def _load(p):
    return json.loads(Path(p).read_text())


def test_all_json_fixtures_parse():
    for p in list(Path("samples").rglob("*.json")):
        _load(p)


def test_vm_recast_rules_ids():
    data = _load(VM / "recast_rules.json")
    assert "_source_doc" in data
    assert {r["rule_id"] for r in data["rules"]} == VM_RULES


def test_vm_exclusions_has_excl_001():
    data = _load(VM / "exclusions.json")
    assert "EXCL-001" in {e["name"] for e in data["exclusions"]}


def test_epss_snapshot_hero_values():
    e = _load("samples/intel/epss.json")
    assert e["snapshot_date"] == "2026-11-02"
    assert e["now"]["CVE-2025-54068"] == 0.96284
    assert e["history"]["CVE-2025-54068"]["2025-09-01"] == 0.00145
    assert e["now"]["CVE-2025-62593"] == 0.6015


def test_csv_has_three_rows():
    with open("samples/csv/other_scanner_exceptions.csv", newline="") as fh:
        assert len(list(csv.DictReader(fh))) == 3
