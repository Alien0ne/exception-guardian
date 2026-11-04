"""Edge cases found by an independent review (3 Nov 2026): the readers."""
from datetime import date

import pytest

from exception_guardian.assets import match
from exception_guardian.models import Asset
from exception_guardian.readers import tenable_sc, tenable_vm


def _rule(flt, **kw):
    return {"rule_id": "r1", "rule_value": {"action": "ACCEPT"}, "filter": flt,
            "created_at": "2026-10-01T00:00:00Z", **kw}


def _a(name, ip="10.0.0.1"):
    return Asset(id=name, name=name, os=None, ips=(ip,), fqdns=(), tags=(), internet_facing=False, exposure_since=None,
                 critical=None, on_attack_path=None)


def test_neq_asset_filter_means_every_asset_except():
    r = tenable_vm.parse_rules([_rule({"and": [{"property": "asset.name", "operator": "neq",
                                                "value": ["web-portal-01"]}]})])[0]
    assert r.targets == ("!web-portal-01",)
    assert [a.name for a in match(r.targets, [_a("web-portal-01"), _a("db-01", "10.0.0.2")])] == ["db-01"]


def test_negated_cve_filter_is_not_read_as_the_rule_cves():
    r = tenable_vm.parse_rules([_rule({"and": [{"property": "definition.cve", "operator": "nmatch",
                                                "value": ["CVE-2021-44228"]}]})])[0]
    assert r.cves == () and r.raw["x_excluded_cves"] == ["CVE-2021-44228"]


def test_unknown_asset_property_matches_nothing_instead_of_everything():
    r = tenable_vm.parse_rules([_rule({"and": [{"property": "asset.hostname", "operator": "eq",
                                                "value": ["db-01"]}]})])[0]
    assert r.targets == ("?asset.hostname=db-01",)
    assert match(r.targets, [_a("db-01")]) == []


def test_one_malformed_rule_is_skipped_not_the_whole_source():
    good = _rule({}, rule_id="ok")
    epoch = _rule({}, rule_id="epoch", created_at=1759276800)
    bad = {"rule_id": "bad", "rule_value": {"action": "ACCEPT"}, "filter": {}}
    tenable_vm.LAST_WARNINGS.clear()
    out = tenable_vm.parse_rules([good, epoch, bad])
    assert [r.rule_id for r in out] == ["ok", "epoch"] and out[1].created == date(2025, 10, 1)
    assert tenable_vm.LAST_WARNINGS == ["source tenable-vm failed: rule bad skipped (KeyError: 'created_at')"]


def test_offset_timestamps_become_utc_dates():
    r = tenable_vm.parse_rules([_rule({}, created_at="2026-10-01T22:30:00-05:00")])[0]
    assert r.created == date(2026, 10, 2)


def test_exclusion_one_off_schedule_sets_expiry_and_duplicate_names_get_ids():
    ex = [{"id": 1, "name": "X", "creation_date": 1740787200, "members": "a",
           "schedule": {"enabled": True, "starttime": "2026-11-01 00:00:00", "endtime": "2026-11-20 00:00:00",
                        "rrules": {"freq": "ONETIME"}}},
          {"id": 2, "name": "X", "creation_date": 1740787200, "members": "b", "schedule": {"enabled": False}},
          {"id": 3, "name": "Y", "members": "c"}]
    tenable_vm.LAST_WARNINGS.clear()
    out = tenable_vm.parse_exclusions(ex)
    assert [(e.rule_id, e.expires) for e in out] == [("X (1)", date(2026, 11, 20)), ("X (2)", None)]
    assert tenable_vm.LAST_WARNINGS[0].startswith("source tenable-vm failed: exclusion Y skipped")


def test_sc_float_epoch_and_a_bad_rule():
    ok = {"id": 1, "createdTime": "1759276800.0", "hostType": "all"}
    tenable_sc.LAST_WARNINGS.clear()
    out = tenable_sc.parse([ok, {"id": 2, "hostType": "all"}], tenable_sc.RuleType.ACCEPT)
    assert [r.rule_id for r in out] == ["1"] and out[0].created == date(2025, 10, 1)
    assert tenable_sc.LAST_WARNINGS[0].startswith("source tenable-sc failed: rule 2 skipped")


def _csv(tmp_path, body, enc="utf-8"):
    import yaml
    (tmp_path / "e.csv").write_bytes(body.encode(enc))
    (tmp_path / "m.yaml").write_text(yaml.safe_dump({"columns": {"rule_id": "id", "type": "type", "cve": "cve",
                                                                 "created": "created", "status": "state"},
                                                     "type_values": {"accept": "accept"},
                                                     "status_values": {"Inactive": "disabled", "Active": "enabled"}}))
    from exception_guardian.readers import csv_reader
    return csv_reader.read({"path": str(tmp_path / "e.csv"), "map": str(tmp_path / "m.yaml")}), csv_reader.LAST_WARNINGS


def test_csv_bom_status_case_unknown_status_and_duplicate_ids(tmp_path):
    out, warn = _csv(tmp_path, "\ufeffid,type,cve,created,state\n"
                                "a,accept,CVE-2021-0001,2026-01-01,inactive\n"
                                "b,accept,CVE-2021-0002,2026-01-01,Revoked\n"
                                "b,accept,CVE-2021-0003,2026-01-01,Active\n")
    assert [(r.rule_id, r.status) for r in out] == [("a", "disabled"), ("b", "enabled"), ("b (row 4)", "enabled")]
    assert any("unknown status 'Revoked'" in w for w in warn) and any("duplicate rule id 'b'" in w for w in warn)


def test_csv_in_windows_1252_is_read(tmp_path):
    out, warn = _csv(tmp_path, "id,type,cve,created,state\ncé,accept,CVE-2021-0001,2026-01-01,Active\n", "cp1252")
    assert [r.rule_id for r in out] == ["cé"] and any("not UTF-8" in w for w in warn)


def _json(tmp_path, data):
    import json
    import yaml
    (tmp_path / "e.json").write_text(json.dumps(data))
    (tmp_path / "m.yaml").write_text(yaml.safe_dump({"columns": {"rule_id": "id", "type": "type", "cve": "cve",
                                                                 "created": "created"},
                                                     "type_values": {"accept": "accept"}}))
    from exception_guardian.readers import csv_reader
    return csv_reader.read({"path": str(tmp_path / "e.json"), "map": str(tmp_path / "m.yaml")}), csv_reader.LAST_WARNINGS


def test_json_row_that_is_not_an_object_is_skipped_not_the_whole_source(tmp_path):
    good = {"id": "J1", "type": "accept", "cve": "CVE-2021-44228", "created": "2025-01-01"}
    out, warn = _json(tmp_path, [good, ["J2", "accept"], "J3", None])
    assert [e.rule_id for e in out] == ["J1"]
    assert sum("is not an object" in w for w in warn) == 3


def test_json_export_that_is_not_a_list_says_what_it_needs(tmp_path):
    import pytest
    with pytest.raises(ValueError, match="list of exception objects"):
        _json(tmp_path, {"exceptions": []})


def test_demo_runs_from_any_folder(tmp_path, monkeypatch, capsys):
    from exception_guardian.cli import main
    monkeypatch.chdir(tmp_path)
    assert main(["demo", "--out", "d"]) == 0
    assert (tmp_path / "d" / "report.html").is_file() and (tmp_path / "d" / "approval-plan.md").is_file()
    import os
    assert os.getcwd() == str(tmp_path)  # the folder is restored afterwards


@pytest.mark.parametrize("key", ["type_values", "status_values", "columns"])
def test_a_map_block_given_as_a_list_names_the_key(tmp_path, key):
    from exception_guardian.readers.csv_reader import _check_map
    m = {"columns": {"type": "Type", "created": "Created", "cve": "CVE"}, key: ["accept", "recast"]}
    with pytest.raises(ValueError, match=key):
        _check_map(tmp_path / "map.yaml", m)
