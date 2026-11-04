from datetime import date

import pytest

from exception_guardian.config import SourceConfig
from exception_guardian.models import RuleType
from exception_guardian.readers import get_reader, read_all


def test_vm_reader_reads_all_rules_and_exclusions():
    ex = get_reader("tenable-vm")({"fixture_dir": "samples/tenable_vm"})
    ids = {e.rule_id for e in ex}
    assert {"R-HERO-001", "R-RAISE-008", "EXCL-001"} <= ids and len(ex) == 9


def test_vm_reader_maps_hero_fields():
    hero = next(e for e in get_reader("tenable-vm")({"fixture_dir": "samples/tenable_vm"}) if e.rule_id == "R-HERO-001")
    assert hero.rule_type is RuleType.ACCEPT and hero.cves == ("CVE-2025-54068",)
    assert hero.created == date(2025, 9, 1) and hero.expires is None and hero.source == "tenable-vm"


def test_vm_reader_maps_recast_and_exclusion():
    ex = {e.rule_id: e for e in get_reader("tenable-vm")({"fixture_dir": "samples/tenable_vm"})}
    ray = ex["R-RAY-002"]
    assert ray.rule_type is RuleType.RECAST and (ray.original_severity, ray.new_severity) == ("CRITICAL", "LOW")
    excl = ex["EXCL-001"]
    assert excl.rule_type is RuleType.EXCLUSION and excl.targets == ("web-portal-01.example.com", "203.0.113.10")
    assert excl.created == date(2025, 3, 1) and excl.cves == ()


def test_unknown_reader_lists_known():
    with pytest.raises(KeyError, match="tenable-vm"):
        get_reader("qualys")


def test_read_all_reports_failing_source():
    ex, warn = read_all((SourceConfig("tenable-vm", {"fixture_dir": "nope/"}),))
    assert ex == [] and "source tenable-vm failed" in warn[0]


def test_read_all_explains_a_403(monkeypatch):
    import requests
    from exception_guardian import readers

    def forbidden(params):
        resp = requests.Response(); resp.status_code = 403; resp.url = "https://cloud.tenable.com/v1/recast/rules/search"
        raise requests.HTTPError("403 Client Error: Forbidden", response=resp)
    monkeypatch.setattr(readers, "get_reader", lambda name: forbidden)
    _, warn = read_all((SourceConfig("tenable-vm", {"base_url": "https://cloud.tenable.com"}),))
    assert "source tenable-vm failed" in warn[0]
    assert "the API user's role is not allowed to read this" in warn[0]
