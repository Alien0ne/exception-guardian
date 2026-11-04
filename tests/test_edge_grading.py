"""Edge cases found by an independent review (3 Nov 2026): grading, attack paths, find, intel."""
import json
from datetime import date

from exception_guardian.attack_paths import links, parse_paths
from exception_guardian.config import Config
from exception_guardian.grading import grade
from exception_guardian.models import Asset, CveIntel, RiskException, RuleType

TODAY = date(2026, 11, 3)


def _exc(**kw):
    base = dict(source="tenable-vm", rule_id="R1", rule_type=RuleType.ACCEPT, cves=("CVE-2021-44228",), plugin_ids=(),
                targets=("h1",), original_severity=None, new_severity=None, owner=None, created=date(2026, 10, 1),
                updated=None, expires=date(2027, 1, 1), justification="", status="enabled", revised_findings=None)
    return RiskException(**{**base, **kw})


def _a(name="h1", ip="10.1.1.1", **kw):
    return Asset(id=name, name=name, os=None, ips=(ip,), fqdns=(), tags=(), internet_facing=False,
                 exposure_since=None, critical=None, on_attack_path=None, **kw)


def test_unmatched_scope_and_excluded_cves_are_noted():
    g = grade(_exc(targets=("?asset.hostname=db-01",)), [_a()], {}, Config(offline=True), TODAY)
    assert "scope not checked: the rule filters on asset.hostname, which assets are not matched on" in g.notes
    g = grade(_exc(cves=(), raw={"x_excluded_cves": ["CVE-2021-44228"]}), [_a()], {}, Config(offline=True), TODAY)
    assert ("the rule covers every CVE except CVE-2021-44228, so there is no CVE list to look up" in g.notes)


def test_negated_internal_wording_does_not_count_as_a_claim():
    pub = _a(public_ips=("8.8.8.8",))
    for just in ("NOT internal, exposed to the internet", "non-internal host", "not isolated"):
        g = grade(_exc(justification=just), [pub], {}, Config(offline=True), TODAY)
        assert "JUSTIFICATION_CONTRADICTED" not in {t.code for t in g.triggers}, just
    g = grade(_exc(justification="internal only"), [pub], {}, Config(offline=True), TODAY)
    assert "JUSTIFICATION_CONTRADICTED" in {t.code for t in g.triggers}


def test_kev_added_on_the_acceptance_day_says_so():
    i = {("CVE-2021-44228", date(2026, 10, 1)): CveIntel("CVE-2021-44228", True, date(2026, 10, 1), False, None,
                                                            None, "live")}
    t = next(t for t in grade(_exc(), [], i, Config(offline=True), TODAY).triggers if t.code == "KEV")
    assert t.then == "added to KEV the day the rule was accepted"


def test_recast_to_the_same_severity_is_not_called_a_raise():
    g = grade(_exc(rule_type=RuleType.RECAST, original_severity="high", new_severity="high"), [], {},
              Config(offline=True), TODAY)
    assert "recast keeps the same severity, so it hides nothing" in g.notes


def _path(cve="cve-2021-44228", net="10.1.0.0/16", prio=6.0):
    tech = json.dumps([{"id": cve}])
    return {"priority": prio, "name": "p", "techniques": [{"source_information": tech}],
            "nodes": [{"name": "x", "labels": ["Asset"]}, {"name": net, "labels": ["Network"]}, {"name": "y"}]}


def test_path_cves_are_read_in_any_case():
    assert parse_paths([_path()])[0].cves == ("CVE-2021-44228",)


def test_very_broad_networks_do_not_put_every_asset_on_a_path():
    for net in ("0.0.0.0/0", "10.0.0.0/8"):
        assert links(parse_paths([_path(net=net)])[0], [_a()]) == []
    assert links(parse_paths([_path(net="10.1.0.0/16")])[0], [_a()]) == ["h1 (10.1.1.1) is on 10.1.0.0/16"]


def test_a_bad_path_is_skipped_not_the_whole_list():
    from exception_guardian import attack_paths
    out = parse_paths([_path(prio="high"), _path()])
    assert len(out) == 1 and attack_paths.LAST_SKIPPED == 1


def test_intel_fallback_marks_the_run_partial():
    from exception_guardian.intel import build_intel
    from exception_guardian.report import is_partial

    def down(url):
        raise TimeoutError("down")
    _, warn = build_intel({"CVE-2021-44228": [date(2026, 10, 1)]}, Config(offline=False), fetch=down)
    assert warn and warn[0].startswith("source KEV/EPSS failed: ") and is_partial(warn)


def test_epss_before_its_history_starts_is_not_fetched():
    from exception_guardian.intel import build_intel
    calls = []

    def fetch(url):
        calls.append(url)
        return {"vulnerabilities": [], "data": [{"cve": "CVE-2019-0708", "epss": "0.9"}]}
    intel, _ = build_intel({"CVE-2019-0708": [date(2020, 2, 11)]}, Config(offline=False), fetch=fetch)
    assert intel[("CVE-2019-0708", date(2020, 2, 11))].epss_at_created is None
    assert not [u for u in calls if "date=" in u]  # FIRST has no EPSS before 2021-04-14


def test_one_failed_context_lookup_does_not_stop_the_rest():
    from exception_guardian.context import enrich_context

    class C:
        def asset_context(self, aid):
            if aid == "h1":
                raise RuntimeError("HTTP 500")
            return {"acr": 9, "aes": 1, "paths": 0, "critical_paths": 0, "source": "Tenable One inventory"}
    out, notes = enrich_context([_a("h1"), _a("h2", "10.1.1.2")], [_exc(targets=("*",))], C(), critical_acr=9)
    assert [a.acr for a in out] == [None, 9]
    assert notes == ["asset context: 1 of 2 lookups failed (RuntimeError: HTTP 500), so those assets use the asset "
                     "list's flags only"]


def test_a_failing_attack_path_read_keeps_the_assets(monkeypatch, tmp_path):
    from exception_guardian import find as find_mod
    from exception_guardian.config import load_config
    from exception_guardian.find import run_find
    monkeypatch.setattr(find_mod, "build_intel", lambda wanted, cfg: ({}, []))
    import exception_guardian.attack_paths as ap
    monkeypatch.setattr(ap, "load_paths", lambda cfg, client: (_ for _ in ()).throw(ValueError("bad path")))
    run_find(load_config("guardian.yaml"), tmp_path / "r", TODAY)
    data = json.loads((tmp_path / "r/findings.json").read_text())
    assert data["read"]["assets"] > 0
    assert any(w.startswith("source attack paths failed: bad path") for w in data["warnings"])


def test_rule_search_stops_on_a_repeating_page_token():
    from exception_guardian.tenable_client import TenableVMClient
    c = TenableVMClient("https://x", "a", "s")
    calls = []

    def page(*a, **k):  # bounded: a regression must fail here, not fill memory
        calls.append(1)
        if len(calls) > 100:
            raise AssertionError("no guard: still paging after 100 calls")
        return {"rules": [{"rule_id": "1"}], "pagination": {"next": "same"}}
    c._call = page
    import pytest
    with pytest.raises(RuntimeError, match="same page token twice"):
        c.search_rules()
