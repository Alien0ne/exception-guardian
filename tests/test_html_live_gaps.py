"""Manual live test (4 Nov 2026), report.html against report.md on a live tenant: the page dropped the run's
warnings unless a source had failed, the lead card said an attack path used "it" when the path used another of the
rule's CVEs, and grouped rows put trigger codes under the CVEs column."""
import json
import re
from datetime import date

from exception_guardian.html_report import render_html


def _f(rid, grade="REVIEW", cves=(), triggers=(), source="tenable-sc"):
    return {"exception": {"source": source, "rule_id": rid, "rule_type": "accept", "cves": list(cves),
                          "plugin_ids": [], "targets": ["*"], "created": "2020-02-11", "expires": None,
                          "justification": "", "status": "enabled", "revised_findings": None, "owner": None},
            "grade": grade, "triggers": [dict(t) for t in triggers], "assets": [], "intel": [], "notes": []}


def _page(tmp_path, findings, warnings=(), partial=False):
    (tmp_path / "findings.json").write_text(json.dumps(
        {"today": str(date(2026, 11, 4)), "partial": partial, "warnings": list(warnings), "findings": findings}))
    return render_html(tmp_path)


def test_warnings_show_when_no_source_failed(tmp_path):
    w = "asset context: 1200 covered assets, but only the first 200 were looked up"
    page = _page(tmp_path, [_f("r1")], warnings=[w])
    assert w in page and "Partial run" not in page


def test_no_warnings_no_notice(tmp_path):
    page = _page(tmp_path, [_f("r1")])
    assert 'class="notice"' not in page


def test_lead_card_names_the_cve_the_attack_path_uses(tmp_path):
    path = {"code": "ATTACK_PATH_CVE", "then": None, "source": "Tenable One attack paths",
            "now": "CVE-2020-1380 is used in an attack path: ws11 → 10.0.0.0/22 → dc9 (priority 6.26), and h is on 10.0.0.0/22"}
    lead = _f("lead", grade="REVOKE", cves=("CVE-2020-1472", "CVE-2020-1380"), source="tenable-vm", triggers=[path])
    page = _page(tmp_path, [lead])
    impact = re.search(r'<p class="impact">(.*?)</p>', page).group(1)
    assert "attack path using CVE-2020-1380: ws11" in impact and "using it" not in impact


def test_grouped_rows_put_cves_under_the_cves_column(tmp_path):
    trig = [{"code": "BLANKET", "then": None, "now": "every asset (27 today)", "source": "rule metadata"},
            {"code": "NO_EXPIRY", "then": None, "now": "no expiry", "source": "rule metadata"}]
    page = _page(tmp_path, [_f(f"r{i}", cves=(f"CVE-2020-{1000 + i}",), triggers=trig) for i in range(9)])
    summary = re.search(r'<details class="group"[^>]*><summary>(.*?)</summary>', page, re.S).group(1)
    cells = re.findall(r'<span class="hide-s">(.*?)</span>', summary)
    assert "CVE-2020-1000" in cells[1] and "BLANKET" not in cells[1]
