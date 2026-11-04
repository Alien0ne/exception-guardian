"""Gaps a live run showed (3 Nov 2026): the re-surfaces count, the public-IP exposure signal, and web
app targets that are not in the host asset list."""
import json
import shutil
from datetime import date
from pathlib import Path

import pytest

from exception_guardian.approval import _resurfaces
from exception_guardian.mock_tenable import serve
from exception_guardian.models import RiskException, RuleType
from exception_guardian.tenable_client import TenableVMClient

TODAY = date(2026, 11, 2)
HOST_RULE = {"rule_id": "r-host", "resource_type": "HOST", "rule_value": {"action": "RECAST"},
             "filter": {"and": [{"value": "app-host-01", "operator": "eq", "property": "asset.name"},
                                {"value": "123456", "operator": "eq", "property": "definition.id"}]}}
WEB_RULE = {"rule_id": "r-web", "resource_type": "WEBAPP", "rule_value": {"action": "ACCEPT"},
            "filter": {"and": [{"or": [{"value": ["shop.example.com"], "operator": "eq", "property": "asset.name"}]},
                               {"value": "654321", "operator": "eq", "property": "definition.id"}]}}


def _finding(i, kind, plugin, asset, risk):
    return {"id": f"f{i}", "kind": kind, "definition": {"id": plugin}, "asset": {"name": asset}, "risk_modified": risk}


@pytest.fixture
def lab(tmp_path):
    for f in Path("samples/tenable_vm").glob("*.json"):
        shutil.copy(f, tmp_path / f.name)
    findings = [_finding(i, "host", 123456, "app-host-01", "RECASTED") for i in range(450)]
    findings += [_finding(1000, "host", 123456, "app-host-01", "NONE"),       # same plugin and asset, not recast
                 _finding(1001, "host", 123456, "other-host", "RECASTED"),  # another asset
                 _finding(1002, "webapp", 654321, "shop.example.com", "ACCEPTED"),
                 _finding(1003, "webapp", 654321, "shop.example.com", "ACCEPTED"),
                 _finding(1004, "host", 654321, "shop.example.com", "ACCEPTED")]  # host side must not count for WEBAPP
    (tmp_path / "findings.json").write_text(json.dumps({"findings": findings}))
    srv, url = serve(tmp_path)
    yield tmp_path, url
    srv.shutdown()


def test_count_rule_findings_pages_through_the_host_search(lab):
    _, url = lab
    assert TenableVMClient(url, "a", "s").count_rule_findings(HOST_RULE) == (450, False)


def test_count_rule_findings_stops_at_the_page_cap(lab):
    _, url = lab
    assert TenableVMClient(url, "a", "s").count_rule_findings(HOST_RULE, max_pages=2) == (400, True)


def test_count_rule_findings_uses_the_webapp_search_for_webapp_rules(lab):
    _, url = lab
    assert TenableVMClient(url, "a", "s").count_rule_findings(WEB_RULE) == (2, False)


def test_live_reader_fills_the_count_when_the_rule_has_none(lab):
    from exception_guardian.readers.tenable_vm import read
    d, url = lab
    rules = json.loads((d / "recast_rules.json").read_text())
    for r in rules["rules"]:
        r.pop("x_revised_findings", None)
    rules["rules"].append({**HOST_RULE, "created_at": "2026-01-01T00:00:00Z",
                           "rule_value": {"action": "RECAST", "severity": "LOW", "original_severity": "HIGH"}})
    (d / "recast_rules.json").write_text(json.dumps(rules))
    srv, url2 = serve(d)  # reload the edited rules
    try:
        import os
        os.environ.setdefault("TENABLE_ACCESS_KEY", "a"); os.environ.setdefault("TENABLE_SECRET_KEY", "s")
        out = {e.rule_id: e for e in read({"base_url": url2})}
    finally:
        srv.shutdown()
    assert out["r-host"].revised_findings == 450 and out["r-host"].revised_findings_capped is False
    assert all(e.revised_findings is not None for e in out.values() if e.rule_type in (RuleType.ACCEPT, RuleType.RECAST)
               and e.status == "enabled")


def _exc(**kw):
    base = dict(source="tenable-vm", rule_id="x", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=("1",), targets=("h",),
                original_severity=None, new_severity=None, owner=None, created=TODAY, updated=None, expires=None,
                justification="", status="enabled", revised_findings=None, raw={"rule_id": "x"})
    return RiskException(**{**base, **kw})


def test_count_findings_failure_is_a_warning_and_leaves_the_count_unknown():
    from exception_guardian.readers import count_rule_findings

    def boom(rule):
        raise RuntimeError("HTTP 403")
    out, warn = count_rule_findings([_exc()], boom)
    assert out[0].revised_findings is None
    assert warn == ["tenable-vm: finding count for rule x failed: HTTP 403"]


def test_count_findings_skips_rules_that_already_have_a_count_and_disabled_or_exclusion_rules():
    from exception_guardian.readers import count_rule_findings
    calls = []
    rules = [_exc(rule_id="has", revised_findings=3), _exc(rule_id="off", status="disabled"),
             _exc(rule_id="ex", rule_type=RuleType.EXCLUSION), _exc(rule_id="todo")]
    out, warn = count_rule_findings(rules, lambda r: calls.append(r) or (7, False))
    assert [e.revised_findings for e in out] == [3, None, None, 7] and len(calls) == 1 and warn == []


def test_resurfaces_says_at_least_when_the_count_was_capped():
    assert _resurfaces({"revised_findings": 5000, "revised_findings_capped": True}) == "at least 5000 findings"
    assert _resurfaces({"revised_findings": 0}) == "0 findings (the rule matches nothing today)"
    assert _resurfaces({"revised_findings": 1}) == "1 finding"


# a public IP is a REVIEW signal, never a REVOKE; only a configured tag (here Exposure:Internet) says internet-facing
def _asset_rows(*rows):
    from exception_guardian.assets import parse_assets
    from exception_guardian.config import ExposureConfig
    from exception_guardian.exposure import apply_exposure
    out, _ = apply_exposure(parse_assets([{"id": n, "hostname": [n], "ipv4": ips, "tags": tags} for n, ips, tags in rows]),
                            ExposureConfig(internet_tags=("Exposure:Internet",)))
    return out


def test_public_ip_alone_does_not_mark_an_asset_internet_facing():
    (sw,) = _asset_rows(("switch-01", ["128.0.0.1", "10.0.0.5"], []))
    assert sw.internet_facing is False and sw.public_ips == ("128.0.0.1",)


def _graded(assets, justification="", rule_type=RuleType.ACCEPT):
    from exception_guardian.config import Config
    from exception_guardian.grading import grade
    exc = _exc(targets=tuple(a.name for a in assets), justification=justification, rule_type=rule_type,
               expires=date(2027, 1, 1), created=date(2026, 10, 1))
    return grade(exc, assets, {}, Config(offline=True), TODAY)


def test_public_ip_without_the_tag_grades_review_with_the_ip_as_evidence():
    g = _graded(_asset_rows(("switch-01", ["128.0.0.1"], [])))
    t = {x.code: x for x in g.triggers}
    assert g.grade.value == "REVIEW" and "INTERNET_FACING" not in t
    assert t["PUBLIC_IP"].now == "has a public IP (128.0.0.1), but it is not marked internet-facing"
    assert t["PUBLIC_IP"].source == "asset inventory: switch-01"


def test_tagged_asset_is_still_internet_facing_and_revoke_without_a_public_ip_trigger():
    g = _graded(_asset_rows(("web", ["203.0.113.10"], [{"tag_key": "Exposure", "tag_value": "Internet"}])))
    codes = {x.code for x in g.triggers}
    assert g.grade.value == "REVOKE" and "INTERNET_FACING" in codes and "PUBLIC_IP" not in codes


def test_internal_justification_on_a_public_ip_asset_is_contradicted_softly():
    g = _graded(_asset_rows(("switch-01", ["128.0.0.1"], [])), justification="internal only, behind the firewall")
    t = {x.code: x for x in g.triggers}
    assert t["JUSTIFICATION_CONTRADICTED"].now == "says internal, but the asset has a public IP"


def test_exclusions_keep_the_public_ip_trigger():
    g = _graded(_asset_rows(("switch-01", ["128.0.0.1"], [])), rule_type=RuleType.EXCLUSION)
    assert "PUBLIC_IP" in {x.code for x in g.triggers}


# web apps are assets too (POST /api/v3/assets/webapp/search), so web app rule targets match
WEBAPPS = [{"id": "wa-1", "name": "shop.example.com ", "url": None, "domain": "shop.example.com",
            "ipv4_addresses": ["203.0.113.80"], "types": ["webapp"]},
           {"id": "wa-2", "name": "Portal", "url": "https://portal.example.com/app", "domain": None,
            "ipv4_addresses": None, "types": ["webapp"]}]


def test_parse_webapps_names_addresses_and_public_ips():
    from exception_guardian.assets import parse_webapps
    shop, portal = parse_webapps(WEBAPPS)
    assert (shop.name, shop.ips, shop.fqdns, shop.public_ips) == ("shop.example.com", ("203.0.113.80",),
                                                                  ("shop.example.com",), ())
    assert (portal.name, portal.fqdns, portal.internet_facing) == ("Portal", ("portal.example.com",), False)


def test_parse_webapps_flags_a_global_ip():
    from exception_guardian.assets import parse_webapps
    (g,) = parse_webapps([{"id": "g", "name": "shop.example.net", "ipv4_addresses": ["9.9.9.9"]}])
    assert g.public_ips == ("9.9.9.9",)


def test_live_assets_include_web_apps(tmp_path):
    from exception_guardian.assets import load_assets, match
    for f in Path("samples/tenable_vm").glob("*.json"):
        shutil.copy(f, tmp_path / f.name)
    (tmp_path / "webapps.json").write_text(json.dumps({"assets": WEBAPPS}))
    srv, url = serve(tmp_path)
    try:
        import os
        os.environ.setdefault("TENABLE_ACCESS_KEY", "a"); os.environ.setdefault("TENABLE_SECRET_KEY", "s")
        assets = load_assets({"base_url": url})
    finally:
        srv.shutdown()
    names = {a.name for a in assets}
    assert {"web-portal-01", "shop.example.com", "Portal"} <= names
    assert [a.name for a in match(("shop.example.com",), assets)] == ["shop.example.com"]


def test_web_app_list_failure_keeps_hosts_and_marks_the_run_partial(tmp_path, monkeypatch):
    from exception_guardian import assets as assets_mod
    from exception_guardian.report import is_partial
    from exception_guardian.tenable_client import TenableVMClient as C
    for f in Path("samples/tenable_vm").glob("*.json"):
        shutil.copy(f, tmp_path / f.name)
    srv, url = serve(tmp_path)

    def boom(self):
        raise RuntimeError("HTTP 403")
    monkeypatch.setattr(C, "list_webapps", boom)
    try:
        import os
        os.environ.setdefault("TENABLE_ACCESS_KEY", "a"); os.environ.setdefault("TENABLE_SECRET_KEY", "s")
        got = assets_mod.load_assets({"base_url": url})
    finally:
        srv.shutdown()
    assert "web-portal-01" in {a.name for a in got}
    assert assets_mod.LAST_WARNINGS == ["source assets (web apps) failed: HTTP 403"]
    assert is_partial(assets_mod.LAST_WARNINGS)


def test_find_reports_the_asset_warnings(tmp_path, monkeypatch):
    from dataclasses import replace
    from exception_guardian import assets as assets_mod, find as find_mod
    from exception_guardian.config import load_config

    def fake_load(params):
        assets_mod.LAST_WARNINGS[:] = ["source assets (web apps) failed: HTTP 403"]
        return []
    monkeypatch.setattr(find_mod, "load_assets", fake_load)
    find_mod.run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, TODAY)
    d = json.loads((tmp_path / "findings.json").read_text())
    assert "source assets (web apps) failed: HTTP 403" in d["warnings"] and d["partial"] is True


# /assets lists at most 5,000 licensed hosts seen in 90 days; the v3 host search fills the gaps (no tags)
def _v3(i, name, ips):
    return {"id": i, "name": name, "host_name": name, "ipv4_addresses": ips, "ipv6_addresses": [], "types": ["host"]}


def test_parse_v3_hosts_keeps_name_ips_and_public_ips_without_tags():
    from exception_guardian.assets import parse_v3_hosts
    (a,) = parse_v3_hosts([_v3("h1", "old-box", ["10.0.0.9", "198.51.100.7", "8.8.4.4"])])
    assert (a.id, a.name, a.ips, a.tags, a.internet_facing, a.public_ips) == (
        "h1", "old-box", ("10.0.0.9", "198.51.100.7", "8.8.4.4"), (), False, ("8.8.4.4",))


@pytest.fixture
def v3lab(tmp_path):
    for f in Path("samples/tenable_vm").glob("*.json"):
        shutil.copy(f, tmp_path / f.name)
    known = json.loads((tmp_path / "assets.json").read_text())["assets"][0]
    rows = [_v3(known["id"], "dup", ["10.9.9.9"])] + [_v3(f"s{i}", f"stale-{i}", [f"10.1.{i // 250}.{i % 250}"])
                                                       for i in range(450)]
    (tmp_path / "v3_hosts.json").write_text(json.dumps({"assets": rows}))
    srv, url = serve(tmp_path)
    import os
    os.environ.setdefault("TENABLE_ACCESS_KEY", "a"); os.environ.setdefault("TENABLE_SECRET_KEY", "s")
    yield url
    srv.shutdown()


def test_list_hosts_v3_pages_and_caps(v3lab):
    c = TenableVMClient(v3lab, "a", "s")
    rows, capped = c.list_hosts_v3()
    assert len(rows) == 451 and capped is False
    rows, capped = c.list_hosts_v3(max_pages=2)
    assert len(rows) == 400 and capped is True


def test_live_assets_add_hosts_missing_from_the_asset_list_once(v3lab):
    from exception_guardian import assets as m
    got = m.load_assets({"base_url": v3lab})
    names = [a.name for a in got]
    assert "stale-7" in names and "dup" not in names and len(names) == len(set(a.id for a in got))
    assert m.LAST_WARNINGS == []


def test_asset_list_at_its_cap_marks_the_run_partial(v3lab, monkeypatch):
    from exception_guardian import assets as m
    from exception_guardian.report import is_partial
    monkeypatch.setattr(TenableVMClient, "list_assets_with_total",
                        lambda self: ([{"id": f"a{i}", "hostname": [f"h{i}"]} for i in range(5000)], 5000))
    m.load_assets({"base_url": v3lab})
    assert is_partial(m.LAST_WARNINGS)
    assert m.LAST_WARNINGS[0].startswith("source assets (tags) failed: the asset list stops at 5,000, so 451 more hosts")


def _fail_v3(monkeypatch):
    def boom(self, max_pages=250):
        raise RuntimeError("HTTP 403")
    monkeypatch.setattr(TenableVMClient, "list_hosts_v3", boom)


def test_host_search_failure_under_the_cap_is_a_plain_warning(v3lab, monkeypatch):
    from exception_guardian import assets as m
    from exception_guardian.report import is_partial
    _fail_v3(monkeypatch)
    got = m.load_assets({"base_url": v3lab})
    assert "web-portal-01" in {a.name for a in got}
    assert m.LAST_WARNINGS == ["asset host search failed (hosts not seen in 90 days were not read): HTTP 403"]
    assert not is_partial(m.LAST_WARNINGS)


def test_host_search_failure_at_the_cap_is_partial(v3lab, monkeypatch):
    from exception_guardian import assets as m
    from exception_guardian.report import is_partial
    _fail_v3(monkeypatch)
    monkeypatch.setattr(TenableVMClient, "list_assets_with_total",
                        lambda self: ([{"id": f"a{i}", "hostname": [f"h{i}"]} for i in range(5000)], 5000))
    m.load_assets({"base_url": v3lab})
    assert is_partial(m.LAST_WARNINGS) and "HTTP 403" in m.LAST_WARNINGS[0]


# "What was read": one line of counts at the top of every report
LIVE_READ = {"exceptions": 2, "accept": 1, "recast": 1, "exclusion": 0, "assets": 1154,
             "hosts": 150, "host_search": 1000, "webapps": 4, "public_ip": 9, "tagged": 0,
             "covered_assets": 2, "covered_findings": 1, "uncounted_rules": 0}


def test_read_line_for_a_live_run():
    from exception_guardian.report import read_line
    assert read_line(LIVE_READ) == (
        "Read 2 exceptions (1 accept rule, 1 recast rule, 0 exclusions) and 1,154 assets (150 hosts from the "
        "asset list, 1,000 more from the host search without tags, 4 web apps: 9 with a public IP, 0 marked "
        "internet-facing). The exceptions cover 2 of those assets and 1 finding.")


def test_read_line_without_an_inventory_and_with_uncounted_rules():
    from exception_guardian.report import read_line
    r = {**LIVE_READ, "exceptions": 1, "accept": 1, "recast": 0, "assets": 0, "hosts": 0, "host_search": 0,
         "webapps": 0, "public_ip": 0, "covered_assets": 0, "covered_findings": 0, "uncounted_rules": 1}
    assert read_line(r) == ("Read 1 exception (1 accept rule, 0 recast rules, 0 exclusions) and no asset inventory. "
                            "The exception covers 0 assets. 1 rule does not report how many findings it changes.")


def test_asset_origins():
    from exception_guardian.assets import parse_assets, parse_v3_hosts, parse_webapps
    assert parse_assets([{"id": "a"}])[0].origin == "hosts"
    assert parse_v3_hosts([_v3("b", "b", [])])[0].origin == "host-search"
    assert parse_webapps([{"id": "c", "name": "c"}])[0].origin == "webapp"


def test_demo_run_records_and_prints_what_was_read(tmp_path):
    from dataclasses import replace
    from exception_guardian.config import load_config
    from exception_guardian.find import run_find
    from exception_guardian.html_report import render_html
    from exception_guardian.report import read_line
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, TODAY)
    read = json.loads((tmp_path / "findings.json").read_text())["read"]
    assert read["exceptions"] == 13 and read["assets"] == read["hosts"] > 0 and read["host_search"] == 0
    line = read_line(read)
    assert line in (tmp_path / "report.md").read_text()
    assert line in (tmp_path / "handoff-find.md").read_text()
    assert line.replace("&", "&amp;") in render_html(tmp_path)


def test_read_line_plural_uncounted_rules():
    from exception_guardian.report import read_line
    r = {**LIVE_READ, "uncounted_rules": 4, "covered_findings": 14}
    assert read_line(r).endswith(". 4 rules do not report how many findings they change (the others change 14 findings).")
