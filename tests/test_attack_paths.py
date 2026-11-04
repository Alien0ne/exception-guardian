"""Tenable One attack paths that use an exception's CVE (sample data shaped like Tenable One's)."""
import json
import shutil
from datetime import date
from pathlib import Path

import pytest

from exception_guardian.attack_paths import parse_paths
from exception_guardian.config import Config
from exception_guardian.grading import grade
from exception_guardian.mock_tenable import serve
from exception_guardian.models import Asset, RiskException, RuleType
from exception_guardian.tenable_client import TenableVMClient

TODAY = date(2026, 11, 3)


def raw_path(cve="CVE-2021-34527", first="ws11", net="10.1.48.0/22", last="dc9", internet=False, last_id="", prio=6.26):
    tech = json.dumps([{"provider_detection_id": cve, "id": cve, "type": "CVE"}])
    nodes = ([{"name": "Public Internet", "asset_id": "", "labels": ["Internet", "InternetInfiltration"]}] if internet
             else [{"name": first, "asset_id": "id-ws11", "labels": ["Asset", "Computer"]}])
    nodes += [{"name": net, "asset_id": "", "labels": ["Network"]}, {"name": last, "asset_id": last_id,
                                                                      "labels": ["Asset"]}]
    return {"priority": prio, "name": f"{nodes[0]['name']} to {last} via Exploitation of Remote Services",
            "nodes": nodes, "techniques": [{"source_information": tech, "name": "Exploitation of Remote Services"}]}


def asset(ip="10.1.48.38", aid="id-host"):
    return Asset(id=aid, name="host7", os=None, ips=(ip,), fqdns=(), tags=(), internet_facing=False,
                 exposure_since=None, critical=False, on_attack_path=False)


def exc(cves=("CVE-2021-34527",), just="internal only, not reachable from the internet"):
    return RiskException(source="tenable-vm", rule_id="R1", rule_type=RuleType.ACCEPT, cves=cves, plugin_ids=(),
                         targets=("host7",), original_severity=None, new_severity=None, owner=None,
                         created=date(2026, 10, 1), updated=None, expires=date(2027, 1, 1), justification=just,
                         status="enabled", revised_findings=None)


def codes(g):
    return {t.code: t for t in g.triggers}


def test_parse_keeps_steps_cves_networks_and_origin():
    p = parse_paths([raw_path(internet=True)])[0]
    assert p.steps == ("Public Internet", "10.1.48.0/22", "dc9") and p.cves == ("CVE-2021-34527",)
    assert p.networks == ("10.1.48.0/22",) and p.from_internet and p.priority == 6.26


def test_accepted_cve_used_in_a_path_across_the_assets_network_revokes():
    g = grade(exc(), [asset()], {}, Config(offline=True), TODAY, paths=parse_paths([raw_path()]))
    t = codes(g)["ATTACK_PATH_CVE"]
    assert t.grade.value == "REVOKE"
    assert t.now == ("CVE-2021-34527 is used in an attack path: ws11 → 10.1.48.0/22 → dc9 (priority 6.26), and "
                     "host7 (10.1.48.38) is on 10.1.48.0/22")
    assert t.source == "Tenable One attack paths: ws11 to dc9 via Exploitation of Remote Services"
    assert "JUSTIFICATION_CONTRADICTED" not in codes(g)  # an internal path does not contradict "not from internet"


def test_path_through_the_asset_itself_revokes():
    g = grade(exc(), [asset(ip="192.0.2.9")], {}, Config(offline=True), TODAY,
              paths=parse_paths([raw_path(net="172.16.0.0/16", last="host7", last_id="id-host")]))
    assert codes(g)["ATTACK_PATH_CVE"].now.endswith(", and the path reaches host7")


def test_path_from_the_internet_contradicts_an_internal_justification():
    g = grade(exc(), [asset()], {}, Config(offline=True), TODAY, paths=parse_paths([raw_path(internet=True)]))
    assert codes(g)["JUSTIFICATION_CONTRADICTED"].now == "says internal, but an attack path from the internet uses this CVE"


def test_same_cve_on_an_unrelated_network_is_a_review_hint():
    g = grade(exc(), [asset(ip="192.0.2.9")], {}, Config(offline=True), TODAY,
              paths=parse_paths([raw_path(net="172.16.0.0/16")]))
    t = codes(g)
    assert "ATTACK_PATH_CVE" not in t and t["PATH_CVE_ELSEWHERE"].grade.value == "REVIEW"
    assert t["PATH_CVE_ELSEWHERE"].now == ("CVE-2021-34527 is used in 1 attack path elsewhere, e.g. "
                                           "ws11 → 172.16.0.0/16 → dc9 (priority 6.26)")


def test_no_shared_cve_no_trigger():
    g = grade(exc(cves=("CVE-2020-1472",)), [asset()], {}, Config(offline=True), TODAY, paths=parse_paths([raw_path()]))
    assert not {"ATTACK_PATH_CVE", "PATH_CVE_ELSEWHERE"} & codes(g).keys()


def _samples(d):
    for f in Path("samples/tenable_vm").glob("*.json"):
        shutil.copy(f, d / f.name)


@pytest.fixture
def mock(tmp_path, monkeypatch):
    _samples(tmp_path)
    (tmp_path / "attack_paths.json").write_text(json.dumps({"paths": [raw_path(prio=9 - i / 100) for i in range(150)]}))
    srv, url = serve(tmp_path)
    yield url, tmp_path
    srv.shutdown()


def test_client_reads_every_page_of_attack_paths(mock):
    url, _ = mock
    raw, capped = TenableVMClient(url, "a", "s").attack_paths()
    assert len(raw) == 150 and not capped
    raw, capped = TenableVMClient(url, "a", "s").attack_paths(max_pages=1)
    assert len(raw) == 100 and capped


def test_client_without_tenable_one_returns_none(tmp_path):
    _samples(tmp_path)
    srv, url = serve(tmp_path)  # no attack_paths.json: the mock refuses (403), like a tenant without Tenable One
    try:
        assert TenableVMClient(url, "a", "s").attack_paths() is None
    finally:
        srv.shutdown()


def test_find_reads_paths_from_a_sample_file_and_grades_with_them(tmp_path):
    """The demo has no Tenable One, so `assets.attack_paths` can name a sample file of paths."""
    from exception_guardian.attack_paths import load_paths
    f = tmp_path / "paths.json"
    f.write_text(json.dumps({"paths": [raw_path()]}))
    paths, notes = load_paths({"fixture": "x.json", "attack_paths": str(f)}, client=None)
    assert [p.cves for p in paths] == [("CVE-2021-34527",)] and notes == []
    assert load_paths({"fixture": "x.json"}, client=None) == ([], [])


def test_live_paths_without_tenable_one_is_a_note_not_a_failure():
    class NoT1:
        def attack_paths(self):
            return None
    paths, notes = load_paths_live()(NoT1())
    assert paths == [] and notes == ["attack paths: not read (no Tenable One on this tenant)"]


def load_paths_live():
    from exception_guardian.attack_paths import load_paths
    return lambda client: load_paths({"base_url": "https://cloud.tenable.com"}, client=client)
