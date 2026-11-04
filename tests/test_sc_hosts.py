"""Security Center rules are matched to SC's own hosts (analysis tool sumip), not to the Tenable VM asset list.
Shape as Security Center returns it: each host with ip, dnsName, acrScore, assetExposureScore."""
from dataclasses import replace
from datetime import date

import pytest

from exception_guardian.config import Config
from exception_guardian.grading import grade
from exception_guardian.models import RiskException, RuleType
from exception_guardian.readers.tenable_sc import parse_hosts

ROWS = [{"ip": "10.20.0.5", "dnsName": "db01.corp.example", "netbiosName": "", "acrScore": "9", "assetExposureScore": "802",
         "repository": {"id": "1", "name": "Live"}},
        {"ip": "8.8.4.4", "dnsName": "", "netbiosName": "EDGE01", "acrScore": "", "assetExposureScore": "",
         "repository": {"id": "2", "name": "DMZ"}}]


def _rule(targets=("*",), repo="1"):
    return RiskException(source="tenable-sc", rule_id="7", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=("1",),
                         targets=targets, original_severity=None, new_severity=None, owner=None,
                         created=date(2026, 10, 1), updated=None, expires=date(2027, 1, 1), justification="",
                         status="enabled", revised_findings=None, raw={"repository": {"id": repo}})


def test_parse_hosts_keeps_name_ip_scores_and_repository():
    a, b = parse_hosts(ROWS, critical_acr=9)
    assert (a.name, a.ips, a.fqdns, a.acr, a.aes, a.critical) == ("db01.corp.example", ("10.20.0.5",),
                                                                ("db01.corp.example",), 9.0, 802.0, True)
    assert a.context_source == "Tenable SC host summary" and a.origin == "sc" and a.id == "sc:1:10.20.0.5"
    assert (b.name, b.acr, b.critical, b.public_ips) == ("EDGE01", None, None, ("8.8.4.4",))


def test_sc_rule_graded_on_sc_hosts_of_its_repository():
    hosts = parse_hosts(ROWS, critical_acr=9)
    vm = Config(offline=True, assets={"base_url": "https://cloud.tenable.com"})
    g = grade(_rule(), hosts, {}, vm, date(2026, 11, 3), sc_hosts=True)
    assert [a.name for a in g.assets] == ["db01.corp.example"]  # repository 1 only
    t = {x.code: x for x in g.triggers}
    assert t["ATTACK_PATH"].now == "ACR 9 of 10" and t["ATTACK_PATH"].source == "Tenable SC host summary: db01.corp.example"
    g2 = grade(_rule(repo="2"), hosts, {}, vm, date(2026, 11, 3), sc_hosts=True)
    assert "PUBLIC_IP" in {x.code for x in g2.triggers}
    assert not [n for n in g.notes if n.startswith("assets not checked")]


def test_compliance_check_rules_say_why_there_is_no_cve():
    r = replace(_rule(), raw={"plugin": {"id": "1003092", "name": "<agent>unix</agent> <compliance>true</compliance>"}})
    g = grade(r, [], {}, Config(offline=True), date(2026, 11, 3))
    assert "compliance check (an audit result, not a vulnerability), so there is no CVE to look up" in g.notes
    assert "no CVE intel" not in g.notes


def test_find_grades_sc_rules_on_sc_hosts_and_says_how_many(tmp_path, monkeypatch):
    import json
    import shutil
    from exception_guardian import find as find_mod
    from exception_guardian.config import load_config
    from exception_guardian.find import run_find
    from exception_guardian.report import read_line
    monkeypatch.setattr(find_mod, "build_intel", lambda wanted, cfg: ({}, []))
    d = tmp_path / "sc"
    shutil.copytree("samples/tenable_sc", d)
    app = {"ip": "192.0.2.50", "dnsName": "app07.corp.example", "acrScore": "4", "repository": {"id": "1"}}
    (d / "hosts.json").write_text(json.dumps({"hosts": ROWS + [app]}))
    base = load_config("guardian.yaml")
    src = next(s for s in base.sources if s.name == "tenable-sc")
    cfg = replace(base, sources=(replace(src, params={"fixture_dir": str(d)}),))
    run_find(cfg, tmp_path / "r", date(2026, 11, 3))
    data = json.loads((tmp_path / "r/findings.json").read_text())
    assert data["read"]["sc_hosts"] == 3
    assert read_line(data["read"]).count("3 Security Center hosts") == 1
    by_ip = {f["exception"]["targets"][0]: [a["name"] for a in f["assets"]] for f in data["findings"]}
    assert by_ip["192.0.2.50"] == ["app07.corp.example"]
    assert by_ip["192.0.2.42"] == []  # not an SC host: ASSET_UNKNOWN, not a VM asset


@pytest.mark.parametrize("missing", ["TENABLE_SC_HOST", "TENABLE_SC_ACCESS_KEY", "TENABLE_SC_SECRET_KEY"])
def test_a_missing_sc_variable_is_named_like_the_vm_one(monkeypatch, missing):
    """Review of src, 4 Nov 2026: a missing SC key showed only as "source tenable-sc failed: 'TENABLE_SC_ACCESS_KEY'"."""
    from exception_guardian.config import SourceConfig
    from exception_guardian.readers import read_all
    for v in ("TENABLE_SC_HOST", "TENABLE_SC_ACCESS_KEY", "TENABLE_SC_SECRET_KEY"):
        monkeypatch.setenv(v, "x")
    monkeypatch.delenv(missing)
    _, warnings = read_all((SourceConfig("tenable-sc", {}),))
    assert warnings == [f"source tenable-sc failed: environment variable {missing} is not set"]
