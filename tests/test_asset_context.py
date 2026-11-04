"""Tenable One context for the assets an exception covers: ACR, AES and attack paths drive ATTACK_PATH live.
Shapes as a live tenant returns them: the inventory id is the VM asset id; a text query finds it."""
import json
import shutil
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from exception_guardian.assets import parse_assets
from exception_guardian.config import Config, load_config
from exception_guardian.context import enrich_context
from exception_guardian.grading import grade
from exception_guardian.mock_tenable import serve
from exception_guardian.models import RiskException, RuleType
from exception_guardian.tenable_client import TenableVMClient

TODAY = date(2026, 11, 2)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    for f in Path("samples/tenable_vm").glob("*.json"):
        shutil.copy(f, tmp_path / f.name)
    ids = [a["id"] for a in json.loads((tmp_path / "assets.json").read_text())["assets"]]
    (tmp_path / "inventory.json").write_text(json.dumps({"assets": [
        {"id": ids[0], "asset_class": "DEVICE", "acr": 9, "aes": 812,
         "extra_properties": {"apa_asset_total_paths_count": 3, "apa_asset_critical_paths_count": 1}},
        {"id": ids[1], "asset_class": "DEVICE", "acr": 5, "aes": 707,
         "extra_properties": {"apa_asset_total_paths_count": 0, "apa_asset_critical_paths_count": 0}}]}))
    srv, url = serve(tmp_path)
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "a")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    yield url, ids, tmp_path
    srv.shutdown()


def test_client_reads_inventory_context(lab):
    url, ids, _ = lab
    c = TenableVMClient(url, "a", "s")
    assert c.asset_context(ids[0]) == {"acr": 9, "aes": 812, "paths": 3, "critical_paths": 1,
                                       "source": "Tenable One inventory"}
    assert c.asset_context("not-there") is None


def test_client_falls_back_to_the_vm_asset_when_inventory_is_refused(lab):
    url, ids, d = lab
    (d / "inventory.json").unlink()   # the mock then answers the inventory search with 403, like an unlicensed tenant
    srv, url2 = serve(d)
    try:
        assert TenableVMClient(url2, "a", "s").asset_context(ids[2]) == {
            "acr": None, "aes": None, "paths": None, "critical_paths": None, "source": "Tenable VM asset"}
    finally:
        srv.shutdown()


def _exc(targets):
    return RiskException(source="t", rule_id="R1", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=(), targets=targets,
                         original_severity=None, new_severity=None, owner=None, created=date(2026, 10, 1),
                         updated=None, expires=date(2027, 1, 1), justification="", status="enabled",
                         revised_findings=None)


def test_enrich_only_covered_assets_and_grade_attack_path(lab):
    url, ids, d = lab
    assets = parse_assets(json.loads((d / "assets.json").read_text())["assets"])
    a0, a1 = assets[0], assets[1]
    calls = []
    client = TenableVMClient(url, "a", "s")
    real = client.asset_context
    client.asset_context = lambda u: calls.append(u) or real(u)
    out, notes = enrich_context(assets, [_exc((a0.name,)), _exc((a1.name,))], client, critical_acr=9)
    assert sorted(calls) == sorted([a0.id, a1.id]) and notes == []
    t = {x.code: x for x in grade(_exc((a0.name,)), out, {}, Config(offline=True), TODAY).triggers}
    assert t["ATTACK_PATH"].now == "on 3 attack paths (1 critical), ACR 9 of 10"
    assert t["ATTACK_PATH"].source == f"Tenable One inventory: {a0.name}"
    g = grade(_exc((a1.name,)), out, {}, Config(offline=True), TODAY)
    assert "ATTACK_PATH" not in {x.code for x in g.triggers}
    assert f"{a1.name}: ACR 5 of 10, AES 707 of 1000, not itself on an attack path (Tenable One inventory)" in g.notes


def test_context_failure_is_a_note_not_a_crash(lab):
    url, ids, d = lab
    assets = parse_assets(json.loads((d / "assets.json").read_text())["assets"])
    client = TenableVMClient(url, "a", "s")
    client.asset_context = lambda u: (_ for _ in ()).throw(RuntimeError("HTTP 500"))
    out, notes = enrich_context(assets, [_exc((assets[0].name,))], client, critical_acr=9)
    assert out == assets and notes and notes[0].startswith("source asset context failed: all 1 lookups") and "HTTP 500" in notes[0]


def test_critical_acr_from_config(tmp_path):
    f = tmp_path / "g.yaml"
    f.write_text("critical_acr: 8\n")
    assert load_config(f).critical_acr == 8 and Config().critical_acr == 9


def test_live_find_uses_context(lab, tmp_path, monkeypatch):
    from exception_guardian import find as find_mod
    from exception_guardian.find import run_find
    monkeypatch.setattr(find_mod, "build_intel", lambda wanted, cfg: ({}, []))  # no KEV/EPSS fetch in tests
    url, ids, d = lab
    cfg = replace(load_config("guardian.yaml"), offline=False, assets={"base_url": url},
                  sources=(replace(load_config("guardian.yaml").sources[0], params={"base_url": url}),))
    run_find(replace(cfg, offline=False), tmp_path / "r", TODAY)
    data = json.loads((tmp_path / "r/findings.json").read_text())
    trig = [t for f in data["findings"] for t in f["triggers"] if t["code"] == "ATTACK_PATH"]
    assert any(t["source"].startswith("Tenable One inventory") for t in trig)


def test_html_ledger_shows_what_was_checked(tmp_path):
    from exception_guardian.html_report import _ledger
    f = {"grade": "REVIEW", "triggers": [], "notes": ["app-host-01: ACR 5 of 10, AES 707 of 1000, no attack paths "
                                                      "(Tenable One inventory)"],
         "exception": {"rule_id": "R1", "source": "tenable-vm", "rule_type": "accept", "cves": [], "targets": []}}
    html = _ledger([f])
    assert "Checked: app-host-01: ACR 5 of 10, AES 707 of 1000, no attack paths (Tenable One inventory)" in html


def test_html_shows_asset_context_table_outside_the_closed_rows():
    from exception_guardian.html_report import _context
    a = {"id": "a1", "name": "app-host-01", "acr": 5, "aes": 707, "attack_paths": 0, "critical_paths": 0,
         "context_source": "Tenable One inventory"}
    b = {"id": "a2", "name": "shop", "acr": None, "aes": None, "attack_paths": None, "critical_paths": None,
         "context_source": "Tenable One inventory"}
    html = _context([{"assets": [a, b], "exception": {"rule_id": "R1"}}, {"assets": [a], "exception": {"rule_id": "R2"}}])
    assert 'id="ctx-h"' in html and "<details" not in html
    assert html.count("app-host-01") == 1
    for cell in ('<td data-label="ACR">5 of 10</td>', '<td data-label="AES">707 of 1000</td>',
                 '<td data-label="Attack paths">none</td>', '<td data-label="Attack paths">not scored</td>'):
        assert cell in html
    assert _context([{"assets": [{"id": "x", "name": "n", "context_source": ""}], "exception": {}}]) == ""


def test_many_assets_on_attack_paths_become_one_trigger():
    from exception_guardian.models import Asset
    assets = [Asset(id=f"a{i}", name=f"h{i}", os=None, ips=(), fqdns=(), tags=(), internet_facing=False,
                    exposure_since=None, attack_paths=n, critical_paths=c, on_attack_path=True,
                    context_source="Tenable One inventory", acr=a, critical=bool(a and a >= 9))
              for i, (n, c, a) in enumerate([(2, 0, 5), (237, 0, 6), (148, 3, 7), (47, 0, 9), (65, 20, 4)])]
    t = [x for x in grade(_exc(("*",)), assets, {}, Config(offline=True), TODAY).triggers if x.code == "ATTACK_PATH"]
    assert len(t) == 1
    assert t[0].now == ("5 covered assets are on attack paths or critical. Most paths: h1 (237), h2 (148, 3 critical), "
                        "h4 (65, 20 critical)")
    assert t[0].source == "Tenable One inventory: 5 assets"


def test_sc_rules_are_not_matched_to_the_tenable_vm_asset_list():
    """Security Center rules cover SC repository hosts. Matching an SC 'all hosts' rule to the Tenable VM asset
    list graded hundreds of rules REVOKE on VM attack paths (live run, 3 Nov 2026)."""
    from exception_guardian.assets import covers
    from exception_guardian.models import Asset
    vm = Config(offline=True, assets={"base_url": "https://cloud.tenable.com"})
    a = Asset(id="a1", name="dc9", os=None, ips=(), fqdns=(), tags=(), internet_facing=False, exposure_since=None,
              attack_paths=148, on_attack_path=True, critical=False, context_source="Tenable One inventory")
    sc_rule = replace(_exc(("*",)), source="tenable-sc")
    g = grade(sc_rule, [a], {}, vm, TODAY)
    assert not g.assets and not [t for t in g.triggers if t.code == "ATTACK_PATH"]
    assert any(n.startswith("assets not checked: the configured asset list does not cover tenable-sc rules")
               for n in g.notes)
    assert covers(vm.assets, "tenable-vm") and not covers(vm.assets, "tenable-sc")
    assert covers({"fixture": "samples/tenable_vm/assets.json"}, "tenable-sc")  # sample data: unchanged
    assert covers({"base_url": "x", "for_sources": ["tenable-sc"]}, "tenable-sc")


class _TagsOnlyClient:
    """A tenant's asset list may carry no tags. The single-asset record does."""
    def asset_context(self, aid):
        return None

    def asset_tags(self, aid):
        return ["Exposure:Internet", "Owner:IT"] if aid == "a1" else []


def test_tags_missing_from_the_asset_list_are_read_per_covered_asset():
    assets = parse_assets([{"id": "a1", "hostname": ["web"], "ipv4": ["10.0.0.5"]},
                           {"id": "a2", "hostname": ["db"], "ipv4": ["10.0.0.6"]}])
    exc = RiskException(source="tenable-vm", rule_id="r1", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=(),
                        targets=("web",), original_severity=None, new_severity=None, owner=None, created=TODAY,
                        updated=None, expires=date(2026, 11, 11), justification="Internal only, not internet facing",
                        status="enabled", revised_findings=None)
    out, notes = enrich_context(assets, [exc], _TagsOnlyClient(), critical_acr=9, internet_tags=("Exposure:Internet",))
    web = next(a for a in out if a.id == "a1")
    assert web.internet_facing and web.exposure_reason == "tag Exposure:Internet" and "Owner:IT" in web.tags
    assert not next(a for a in out if a.id == "a2").internet_facing and notes == []
    codes = {t.code for t in grade(exc, out, {}, Config(), TODAY).triggers}
    assert {"INTERNET_FACING", "JUSTIFICATION_CONTRADICTED"} <= codes


def test_vm_client_reads_tags_from_the_single_asset_record():
    c = TenableVMClient("https://x", "a", "s")
    c._call = lambda method, path, **k: {"/assets/a1": {"info": {"tags": [
        {"tag_key": "Exposure", "tag_value": "Internet"}]}}}[path]
    assert c.asset_tags("a1") == ["Exposure:Internet"]


def test_vm_asset_fallback_quotes_the_asset_id(monkeypatch):
    """Review of src, 4 Nov 2026: the VM asset fallback put the id in the path unquoted (every other call quotes it),
    so an id holding / or ? would read a different endpoint."""
    import requests
    from exception_guardian.tenable_client import TenableVMClient
    c = TenableVMClient("https://example.invalid", "a", "s")
    paths = []

    def call(method, path, **kw):
        paths.append(path)
        if "/t1/" in path:
            r = requests.Response()
            r.status_code = 404
            raise requests.HTTPError(response=r)
        return {}
    monkeypatch.setattr(c, "_call", call)
    c.asset_context("a/../../session?x=1")
    assert paths[-1] == "/assets/a%2F..%2F..%2Fsession%3Fx%3D1"
