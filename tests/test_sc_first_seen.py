"""Security Center's host summary (sumip) carries no first-seen date; its hosts list does. The live read joins the
two (hosts.uuid = sumip.hostUUID, else by address) so NEW_ASSETS can fire for Security Center rules too."""
import sys
import types
from datetime import date

from exception_guardian.config import Config
from exception_guardian.grading import grade, review_tier
from exception_guardian.models import RiskException, RuleType
from exception_guardian.readers import tenable_sc
from exception_guardian.report import is_partial

DAY = 1780000000  # 2026-05-28 UTC
SUMIP = [{"ip": "10.0.0.1", "dnsName": "a.corp.example", "hostUUID": "u-1", "uuid": "", "repository": {"id": "1"}},
         {"ip": "10.0.0.2", "dnsName": "b.corp.example", "hostUUID": "", "uuid": "", "repository": {"id": "1"}},
         {"ip": "10.0.0.3", "dnsName": "c.corp.example", "hostUUID": "u-3", "uuid": "", "repository": {"id": "1"}}]


def _read(monkeypatch, hosts):
    class FakeSC:
        def __init__(self, host=None, **kw):
            self.accept_risks = self.recast_risks = types.SimpleNamespace(list=lambda **kw: [])
            self.analysis = types.SimpleNamespace(vulns=lambda **kw: iter([dict(r) for r in SUMIP]))
            self.hosts = types.SimpleNamespace(list=hosts)

    monkeypatch.setitem(sys.modules, "tenable.sc", types.SimpleNamespace(TenableSC=FakeSC))
    for k, v in (("TENABLE_SC_HOST", "h"), ("TENABLE_SC_ACCESS_KEY", "ak"), ("TENABLE_SC_SECRET_KEY", "sk")):
        monkeypatch.setenv(k, v)
    tenable_sc.read({})
    return {a.name.split(".")[0]: a for a in tenable_sc.parse_hosts(tenable_sc.LAST_HOSTS)}


def test_parse_hosts_reads_the_first_seen_day():
    a, b, c = tenable_sc.parse_hosts([{"ip": "10.0.0.1", "firstSeen": str(DAY)}, {"ip": "10.0.0.2", "firstSeen": DAY},
                                      {"ip": "10.0.0.3", "firstSeen": "soon"}])
    assert a.first_seen == b.first_seen == date(2026, 5, 28) and c.first_seen is None


def test_the_live_read_joins_first_seen_by_host_id_then_by_address(monkeypatch):
    asked = {}

    def hosts(**kw):
        asked.update(kw)
        return [{"uuid": "u-1", "ipAddress": "10.9.9.9", "firstSeen": str(DAY)},
                {"uuid": "u-2", "ipAddress": "10.0.0.2", "firstSeen": str(DAY + 86400)}]
    got = _read(monkeypatch, hosts)
    assert {"uuid", "ipAddress", "firstSeen"} <= set(asked["fields"])
    assert got["a"].first_seen == date(2026, 5, 28) and got["b"].first_seen == date(2026, 5, 29)
    assert got["c"].first_seen is None and tenable_sc.LAST_WARNINGS == []


def test_an_address_shared_by_two_hosts_is_not_used_to_join(monkeypatch):
    got = _read(monkeypatch, lambda **kw: [{"uuid": "x", "ipAddress": "10.0.0.2", "firstSeen": str(DAY)},
                                           {"uuid": "y", "ipAddress": "10.0.0.2", "firstSeen": str(DAY + 86400)}])
    assert got["b"].first_seen is None


def test_a_security_center_without_the_hosts_list_still_reads_its_hosts(monkeypatch):
    def hosts(**kw):
        raise RuntimeError("404 hosts")
    got = _read(monkeypatch, hosts)
    assert len(got) == 3 and all(a.first_seen is None for a in got.values())
    assert tenable_sc.LAST_WARNINGS == ["tenable-sc first-seen dates were not read (RuntimeError: 404 hosts), so "
                                        "NEW_ASSETS cannot fire for Security Center rules"]
    assert not is_partial(tenable_sc.LAST_WARNINGS)


def test_an_old_blanket_sc_rule_names_the_hosts_first_seen_since():
    rule = RiskException(source="tenable-sc", rule_id="7", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=("1",),
                         targets=("*",), original_severity=None, new_severity=None, owner=None,
                         created=date(2020, 2, 1), updated=None, expires=date(2027, 1, 1), justification="Accepted",
                         status="enabled", revised_findings=None, raw={"repository": {"id": "1"}})
    hosts = tenable_sc.parse_hosts([{"ip": "10.0.0.1", "dnsName": "a", "firstSeen": str(DAY), "repository": {"id": "1"}}])
    g = grade(rule, hosts, {}, Config(), date(2026, 11, 2), sc_hosts=True)
    t = next(t for t in g.triggers if t.code == "NEW_ASSETS")
    assert t.now == "covers 1: 1 first seen since (2026-05-28)" and review_tier(g) == "housekeeping"
