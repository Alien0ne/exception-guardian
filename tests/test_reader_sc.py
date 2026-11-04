from datetime import date

from exception_guardian.models import RuleType
from exception_guardian.readers import get_reader


def test_sc_reader():
    ex = get_reader("tenable-sc")({"fixture_dir": "samples/tenable_sc"})
    assert {e.rule_id for e in ex} == {"SC-AR-101", "SC-RR-102"}
    ar = next(e for e in ex if e.rule_id == "SC-AR-101")
    assert ar.expires is None and ar.rule_type is RuleType.ACCEPT and ar.created == date(2025, 5, 20)
    assert ar.targets == ("192.0.2.50",) and ar.cves == ("CVE-2025-22868",) and ar.source == "tenable-sc"


def test_sc_recast_severities_and_expiry():
    rr = next(e for e in get_reader("tenable-sc")({"fixture_dir": "samples/tenable_sc"}) if e.rule_id == "SC-RR-102")
    assert rr.rule_type is RuleType.RECAST and rr.new_severity == "Medium" and rr.expires == date(2027, 10, 1)
