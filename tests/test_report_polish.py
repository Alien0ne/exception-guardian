"""Report fixes found on the first live run with hundreds of rules (3 Nov 2026)."""
import re
from datetime import date

from exception_guardian.config import Config
from exception_guardian.find import _sort_key
from exception_guardian.grading import grade
from exception_guardian.html_report import _context, _facts, _lead, _ledger, _measure, owner_name, rule_title
from exception_guardian.models import Asset, CveIntel, Grade, GradedException, RiskException, RuleType, Trigger

UUID = "3f6c1e2a-8b4d-4c7e-9a10-5d2e7b8c9f01"


def _exc(**kw):
    base = dict(source="tenable-vm", rule_id="R1", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=(), targets=("h",),
                original_severity=None, new_severity=None, owner=None, created=date(2026, 10, 1), updated=None,
                expires=None, justification="", status="enabled", revised_findings=None)
    return RiskException(**{**base, **kw})


def _g(rid, *codes):
    return GradedException(_exc(rule_id=rid), Grade.REVOKE,
                           tuple(Trigger(c, Grade.REVOKE, None, "x", "s") for c in codes), (), (), ())


def _f(rid=UUID, grade="REVIEW", source="tenable-sc", codes=("NO_EXPIRY", "TOO_OLD"), cves=(), **x):
    ex = {"source": source, "rule_id": rid, "rule_type": "accept", "cves": list(cves), "plugin_ids": ["1003092"],
          "targets": ["*"], "owner": None, "created": "2020-02-11", "justification": "", "raw": {}, **x}
    return {"exception": ex, "grade": grade, "assets": [], "intel": [], "notes": [],
            "triggers": [{"code": c, "grade": "REVIEW", "then": None, "now": "n", "source": "rule metadata"}
                         for c in codes]}


def test_2_lead_is_the_strongest_reason_not_the_most_reasons():
    many_small = _g("spectre", "EPSS_HIGH", "EPSS_HIGH", "EPSS_HIGH", "EPSS_HIGH", "ATTACK_PATH")
    kev = _g("printnightmare", "KEV", "EPSS_HIGH")
    assert sorted([many_small, kev], key=_sort_key)[0].exception.rule_id == "printnightmare"


def test_3_hero_shows_kev_when_epss_did_not_change():
    f = _f(grade="REVOKE", source="tenable-vm", cves=["CVE-2021-34527"], codes=())
    f["triggers"] = [{"code": "KEV", "grade": "REVOKE", "then": "already in KEV when accepted",
                      "now": "in KEV since 2021-11-03, ransomware use", "source": "CISA KEV (live)"},
                     {"code": "EPSS_HIGH", "grade": "REVOKE", "then": "0.99792", "now": "0.99792", "source": "e"}]
    f["intel"] = [{"cve": "CVE-2021-34527", "in_kev": True, "kev_date_added": "2021-11-03", "kev_ransomware": True}]
    f["exception"]["created"] = "2026-11-03"
    html = _measure(f)
    assert '<p class="figure">3 Nov 2021</p>' in html and "0.99792" not in html
    assert "Known Exploited Vulnerabilities" in html and "ransomware" in html


def test_3_hero_keeps_the_epss_jump_when_it_changed():
    f = _f(grade="REVOKE", cves=["CVE-2025-1"], codes=())
    f["triggers"] = [{"code": "EPSS_HIGH", "grade": "REVOKE", "then": "0.00145", "now": "0.96284", "source": "e"}]
    assert '<p class="figure">0.96284</p>' in _measure(f)


def test_4_unreadable_ids_get_a_title_and_owners_a_short_name():
    assert rule_title(_f(raw={"rule_name": "Accepting CVE-2021-34527"})["exception"]) == "Accepting CVE-2021-34527"
    sc = _f(rid="1", raw={"plugin": {"name": "<agent>unix</agent>"}})["exception"]
    assert rule_title(sc) == "accept plugin 1003092 on all assets"
    one = _f(cves=["CVE-2021-1"], **{"targets": ["win-srv-01"]})["exception"]
    assert rule_title(one) == "accept CVE-2021-1 on win-srv-01"
    assert rule_title(_f(rid="R-HERO-001", raw={"rule_name": "x"})["exception"]) == "R-HERO-001"
    assert owner_name("abcd1234-0000-4000-8000-000000000001") == "user abcd1234"
    assert owner_name("analyst@example.com") == "analyst@example.com" and owner_name(None) == "an unknown owner"


def test_4_titles_show_in_the_lead_and_ledger_with_the_id_kept_in_the_facts():
    f = _f(grade="REVOKE", raw={"rule_name": "Accepting CVE-2021-34527"})
    assert "Accepting CVE-2021-34527" in _lead(f) and "Accepting CVE-2021-34527" in _ledger([f])
    assert UUID in _facts(f["exception"])


def test_5_no_justification_says_so_instead_of_empty_quotes():
    f = _f(grade="REVOKE")
    for html in (_lead(f), _facts(f["exception"])):
        assert "&ldquo;&rdquo;" not in html and "No reason was given" in html


def test_6_many_rules_with_the_same_evidence_become_one_group():
    same = [_f(rid=str(i)) for i in range(40)]
    other = _f(rid="99", codes=("NO_EXPIRY",), source="tenable-vm")
    html = _ledger(same + [other])
    assert html.count('class="group"') == 1 and "40 Tenable SC rules with the same evidence" in html
    assert html.count("<details") == 2  # the group and the one different rule


def test_6_small_runs_are_not_grouped():
    html = _ledger([_f(rid=str(i)) for i in range(4)])
    assert 'class="group"' not in html and html.count("<details") == 4


def _asset(i, paths, acr):
    return {"id": f"a{i}", "name": f"h{i}", "context_source": "Tenable One inventory", "attack_paths": paths,
            "critical_paths": 0, "acr": acr, "aes": 100}


def test_7_asset_table_worst_first_one_table_with_a_show_all_button():
    f = _f()
    f["assets"] = [_asset(i, 0, 3) for i in range(30)] + [_asset(98, 237, 6), _asset(99, 0, 9)]
    html = _context([f])
    rows = re.findall(r'<th scope="row">(h\d+)</th>', html)
    assert rows[:2] == ["h98", "h99"] and len(rows) == 32
    assert html.count("<table") == 1 and "<details" not in html  # one table: the columns line up
    assert html.count('<tr class="extra">') == 22  # visible without script; script hides them behind the button
    assert '<button type="button" class="btn btn--quiet show-all" hidden>Show all 32 assets</button>' in html


def test_8_public_ip_lists_three_and_counts_the_rest():
    assets = [Asset(id=f"a{i}", name=f"h{i}", os=None, ips=(f"203.0.113.{i}",), fqdns=(), tags=(),
                    internet_facing=False, exposure_since=None, critical=False, on_attack_path=False,
                    public_ips=(f"203.0.113.{i}",)) for i in range(20)]
    t = next(t for t in grade(_exc(targets=("*",)), assets, {}, Config(offline=True), date(2026, 11, 3)).triggers
             if t.code == "PUBLIC_IP")
    assert t.now.startswith("has a public IP (203.0.113.0, 203.0.113.1, 203.0.113.2 and 17 more)")
    assert t.source == "asset inventory: h0, h1, h2 and 17 more"


def test_9_multi_cve_rules_name_the_cve_in_kev_and_epss_rows():
    intel = {(c, date(2026, 10, 1)): CveIntel(c, True, date(2021, 11, 3), False, 0.9, 0.9, "live")
             for c in ("CVE-2020-1472", "CVE-2020-1380")}
    t = grade(_exc(cves=("CVE-2020-1472", "CVE-2020-1380")), [], intel, Config(offline=True), date(2026, 11, 3)).triggers
    assert [x.now for x in t if x.code == "KEV"] == ["CVE-2020-1472 in KEV since 2021-11-03",
                                                     "CVE-2020-1380 in KEV since 2021-11-03"]
    assert [x.now for x in t if x.code == "EPSS_HIGH"][0] == "CVE-2020-1472: 0.9"
    one = grade(_exc(cves=("CVE-2020-1472",)), [], intel, Config(offline=True), date(2026, 11, 3)).triggers
    assert [x.now for x in one if x.code == "KEV"] == ["in KEV since 2021-11-03"]  # one CVE: unchanged


def test_9_hero_figure_and_label_use_the_cve_of_the_epss_row():
    f = _f(grade="REVOKE", cves=["CVE-1", "CVE-2"], codes=())
    f["triggers"] = [{"code": "EPSS_HIGH", "grade": "REVOKE", "then": "CVE-2: 0.001", "now": "CVE-2: 0.9", "source": "e"}]
    html = _measure(f)
    assert '<p class="figure">0.9</p>' in html and "<code>CVE-2</code>" in html and "0.001 when" in html


def test_9_long_cve_lists_are_cut_in_the_lead_and_ledger():
    f = _f(grade="REVOKE", cves=[f"CVE-2020-{1000 + i}" for i in range(78)])
    for html in (_lead(f), _ledger([f]).split('<div class="body">')[0]):
        assert "CVE-2020-1006" not in html and "and 72 more" in html
    assert "CVE-2020-1077" in _facts(f["exception"])  # the full list stays in the row's facts


def test_10_hero_says_what_the_rule_hides():
    f = _f(grade="REVOKE", source="tenable-vm", cves=["CVE-2021-34527"], codes=())
    f["exception"].update(targets=["win-srv-01"], revised_findings=1, expires=None, created="2026-11-03")
    f["intel"] = [{"cve": "CVE-2021-34527", "in_kev": True, "kev_date_added": "2021-11-03", "kev_ransomware": True}]
    f["triggers"] = [{"code": "KEV", "grade": "REVOKE", "then": "x", "now": "in KEV since 2021-11-03", "source": "k"},
                     {"code": "ATTACK_PATH_CVE", "grade": "REVOKE", "then": None, "source": "t",
                      "now": "CVE-2021-34527 is used in an attack path: ws11 → 10.1.48.0/22 → dc9 (priority 6.26), and "
                             "win-srv-01 (10.1.48.38) is on 10.1.48.0/22"}]
    html = _measure(f)
    assert ('<p class="impact">This rule hides 1 finding on win-srv-01 from the queue, and it never expires. '
            'Tenable One shows an attack path using CVE-2021-34527: ws11 → 10.1.48.0/22 → dc9.</p>') in html


def test_10_impact_for_a_rule_on_all_assets_that_is_internet_facing():
    f = _f(grade="REVOKE", source="tenable-vm", codes=())
    f["exception"].update(targets=["*"], revised_findings=None, expires="2027-01-01")
    f["triggers"] = [{"code": "INTERNET_FACING", "grade": "REVOKE", "then": "internal", "now": "internet-facing",
                      "source": "asset inventory: web-01"}]
    assert ('<p class="impact">This rule hides its findings on all assets from the queue. '
            'A covered asset is internet-facing now (asset inventory: web-01).</p>') in _measure(f)


def test_11_report_prose_uses_sentences_not_semicolons(tmp_path):
    """Review, 3 Nov 2026: 'why does it use ; everywhere'. Evidence and prose read as sentences."""
    import html as h
    from exception_guardian.cli import main
    main(["demo", "--out", str(tmp_path / "d")])
    page = (tmp_path / "d/report.html").read_text()
    page = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", page, flags=re.S)
    text = h.unescape(re.sub(r"<[^>]+>", " ", page))
    assert "; " not in text, [m for m in re.findall(r".{40}; .{40}", text)][:5]
