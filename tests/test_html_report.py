import json
import re
from dataclasses import replace
from datetime import date
from pathlib import Path

from exception_guardian.cli import main
from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.html_report import render_html, write_html


def _demo(tmp_path):
    assert main(["demo", "--out", str(tmp_path)]) == 0
    return (tmp_path / "report.html").read_text()


def test_demo_writes_html_with_hero_counts_changes_and_tests(tmp_path, capsys):
    page = _demo(tmp_path)
    assert page.startswith("<!DOCTYPE html>") and "<title>Exception Guardian report" in page
    assert "R-HERO-001" in page and "0.96284" in page and "0.00145" in page
    assert re.search(r'data-count="REVOKE"[^>]*>6<', page) and re.search(r'data-count="OK"[^>]*>4<', page)
    assert "EXCL-001" in page and "Since the last run" in page        # changes panel
    assert "caught 4 of 4 attack samples" in page                     # sample-log test results
    assert "nothing has been changed" in page.lower()                  # approval plan section
    assert "report.html" in capsys.readouterr().out


def test_untrusted_text_is_escaped(tmp_path):
    page = _demo(tmp_path)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in page  # shown, as quoted data


def test_untrusted_rule_ids_never_reach_attributes_raw(tmp_path):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    data = json.loads((tmp_path / "findings.json").read_text())
    data["findings"][0]["exception"]["rule_id"] = 'x" onmouseover="alert(1)'
    (tmp_path / "findings.json").write_text(json.dumps(data))
    page = render_html(tmp_path)
    assert 'onmouseover="alert(1)' not in page
    for attr in re.findall(r'\sid="([^"]*)"', page):
        assert re.fullmatch(r"[A-Za-z0-9_-]+", attr), attr


def test_find_only_run_renders_without_guard_or_changes(tmp_path):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    path = write_html(tmp_path)
    page = path.read_text()
    assert path.name == "report.html" and "R-HERO-001" in page
    assert "Since the last run" not in page and "Hunt queries" not in page
    assert "exception-guardian guard --run" in page   # tells the reader the next step


def test_empty_run_says_what_belongs_here(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps(
        {"today": "2026-11-02", "partial": False, "warnings": [], "findings": []}))
    page = render_html(tmp_path)
    assert "No risk exceptions were found" in page


def test_partial_run_is_flagged_first(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps(
        {"today": "2026-11-02", "partial": True, "warnings": ["source tenable-sc failed: timeout"], "findings": []}))
    page = render_html(tmp_path)
    assert "Partial run" in page and "source tenable-sc failed: timeout" in page
    assert page.index("Partial run") < page.index("No risk exceptions could be read")


def test_page_is_self_contained(tmp_path):
    page = _demo(tmp_path)
    assert "<script src" not in page and "<link rel=\"stylesheet\" href=\"./" not in page
    for url in re.findall(r'(?:src|href)="(https?://[^"]+)"', page):
        assert url.startswith(("https://github.com/", "https://nvd.nist.gov/", "https://www.cisa.gov/")), url
    # opening the page makes no request: the font is inside it (links above are only followed when clicked)
    assert "fonts.googleapis" not in page and "fonts.gstatic" not in page and "preconnect" not in page
    assert re.search(r'@font-face\s*\{[^}]*font-family:\s*"Geologica"[^}]*url\(data:font/woff2;base64,', page)


def test_html_cli(tmp_path, capsys):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    assert main(["html", "--run", str(tmp_path)]) == 0
    assert (tmp_path / "report.html").exists() and "report.html" in capsys.readouterr().out


def test_headings_highlight_the_finding(tmp_path):
    page = _demo(tmp_path)
    # one span per word, numbered, so the words light up one after another
    assert '13 risk exceptions, <mark class="hl"><span class="w" style="--i: 0">6 </span><span class="w" style="--i: 1">to </span><span class="w" style="--i: 2">revoke</span></mark>' in page
    assert 'Since the last run, <mark class="hl"><span class="w" style="--i: 0">1 </span><span class="w" style="--i: 1">got </span><span class="w" style="--i: 2">worse</span></mark>' in page
    assert page.count('<mark class="hl"') == 6
    assert "IntersectionObserver" in page and "prefers-reduced-motion" in page


def test_heading_highlight_when_nothing_to_revoke(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps(
        {"today": "2026-11-02", "partial": False, "warnings": [], "findings": []}))
    assert '<mark class="hl"><span class="w" style="--i: 0">none </span><span class="w" style="--i: 1">to </span><span class="w" style="--i: 2">revoke</span></mark>' in render_html(tmp_path)


def test_hunt_rules_show_verdict_score_and_origin(tmp_path):
    page = _demo(tmp_path)
    assert '<p class="verdict catch">Catches all</p>' in page          # drafted rules catch every attack sample
    assert '<p class="verdict watch">Fired on no attack sample</p>' in page   # generic rules: a watch, not a miss
    assert '<dt>Attack samples caught (any CVE)</dt>' in page   # generic rules: every attack on their log source
    assert '<p class="verdict none">' not in page                 # EXCL-001 (no CVE) was 0 of 0 before
    assert '<dd><b>4</b>/4</dd>' in page and '<dd class="warn"><b>1</b>/11</dd>' in page
    assert '<span class="origin drafted">Drafted for this CVE</span>' in page
    assert '<span class="origin">Generic SigmaHQ</span>' in page
    assert 'aria-label="caught 4 of 4 attack samples"' in page


def test_hunt_query_rows_name_the_siem_and_language(tmp_path):
    page = _demo(tmp_path)
    assert '<summary><span>Splunk</span><span class="lang">SPL</span>' in page
    assert '<span>Microsoft Sentinel</span><span class="lang">KQL</span>' in page
    assert re.search(r'<div class="target off"><span>Microsoft Sentinel</span><span class="lang">no query: [^<]+</span></div>', page)


def test_hunt_exceptions_open_with_a_numbered_header_and_jump_links(tmp_path):
    page = _demo(tmp_path)
    assert page.count('<header class="hunt-head" data-theme="dark">') == 6
    assert '<p class="pos">1 of 6</p>' in page and '<p class="pos">6 of 6</p>' in page
    assert re.search(r'<article id="hunt-1" aria-labelledby="hunt-1-h"><header class="hunt-head" data-theme="dark">'
                     r'<p class="pos">1 of 6</p><h3 id="hunt-1-h"><code>R-HERO-001</code></h3>', page)
    assert '<p class="sum">3 rules, 2 catch all attack samples</p>' in page
    assert re.search(r'<nav class="jump" aria-label="Exceptions with hunt queries">.*?<a href="#hunt-1">'
                     r'<code>R-HERO-001</code>', page)
    assert "id=\"hunt-R" not in page                                   # ids never carry source text


def test_top_bar_links_each_section_and_names_sources_and_intel(tmp_path):
    page = _demo(tmp_path)
    nav = re.search(r'<nav class="sections" aria-label="Report sections"><ul>(.*?)</ul></nav>', page).group(1)
    assert re.findall(r'href="#([a-z]+-h)"', nav) == ["lead-h", "changes-h", "all-h", "hunt-h", "plan-h"]
    assert '<a href="#lead-h">Revoke first</a>' in nav
    strip = re.search(r'<div class="runstrip">(.*?)</div></div>', page, re.S).group(1)
    assert "<dd>2 Nov 2026</dd>" in strip
    assert all(f'<li class="chip">{n}</li>' in strip for n in ("CSV: other-scanner", "Tenable SC", "Tenable VM"))
    assert '<li class="chip">CISA KEV <span>snapshot 2 Nov 2026</span></li>' in strip
    assert "aria-current" in page                                       # scroll-spy marks the section in view


def test_top_bar_nav_lists_only_sections_present(tmp_path):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    page = render_html(tmp_path)                                        # find-only: no hunt, no plan
    nav = re.search(r'<nav class="sections"[^>]*><ul>(.*?)</ul></nav>', page).group(1)
    assert "#hunt-h" not in nav and "#plan-h" not in nav and "#next-h" in nav


def test_every_step_of_a_real_run_refreshes_the_same_report(tmp_path, capsys):
    # find -> guard -> approve without `html` or `demo`: each step rewrites report.html, so any run ends with the page
    run = tmp_path / "run"
    assert main(["find", "--config", "guardian.yaml", "--out", str(run), "--offline", "--today", "2026-11-02"]) == 0
    page = (run / "report.html").read_text()
    assert "R-HERO-001" in page and "Hunt queries" not in page and f"report.html: {run / 'report.html'}" in capsys.readouterr().out
    import shutil
    shutil.copytree("samples/golden/drafts", run / "drafts")
    assert main(["guard", "--run", str(run)]) == 0
    assert 'id="hunt-h"' in (run / "report.html").read_text() and "report.html" in capsys.readouterr().out
    assert main(["approve", "--run", str(run)]) == 0
    assert 'id="plan-h"' in (run / "report.html").read_text() and "report.html" in capsys.readouterr().out


def test_partial_run_never_claims_all_clear(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps(
        {"today": "2026-11-03", "partial": True, "warnings": ["source tenable-vm failed: 403"], "findings": []}))
    page = render_html(tmp_path)
    h1 = page[page.index('<h1 id="top-h">'):page.index("</h1>")]
    assert "none to revoke" not in page and "<mark" not in h1
    assert "1 source could not be read" in h1
    assert "No risk exceptions could be read" in page and "No risk exceptions were found" not in page


def test_zero_revoke_count_is_not_highlighted(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps(
        {"today": "2026-11-03", "partial": True, "warnings": ["source tenable-vm failed: 403"], "findings": []}))
    assert 'data-count="REVOKE" class="revoke"' not in render_html(tmp_path)


def test_opening_one_exception_closes_the_open_one(tmp_path):
    """Every exception row and group is in one exclusive set (details name=...), so rows do not stack open. The
    queries inside a rule have a set of their own, per rule, so opening one never closes the rule around it."""
    import re
    page = _demo(tmp_path)
    rows = re.findall(r'<details( class="group")? name="([^"]+)"><summary>', page)
    assert len(rows) > 3 and {n for _, n in rows} == {"exceptions"}
    assert re.findall(r"<details(?![^>]*name=)", page) == []  # no row left outside a set
    targets = set(re.findall(r'<details class="target" name="([^"]+)"', page))
    assert targets and "exceptions" not in targets
    assert "ACCORDION_FALLBACK" in page and "scrollIntoView" in page


def test_reasons_no_log_can_show_are_a_spaced_list(tmp_path):
    """A hunt card with only CVEs no log can show (CPU side channels) was a run of bare lines under the header."""
    import re
    _demo(tmp_path)
    g = json.loads((tmp_path / "guard.json").read_text())
    rid = next(iter(g))
    g[rid]["not_loggable"] = [{"cve": "CVE-2017-5715", "reason": "CPU side channel: it writes no log."},
                              {"cve": "CVE-2017-5754", "reason": "CPU side channel (Meltdown): it writes no log."}]
    (tmp_path / "guard.json").write_text(json.dumps(g))
    page = write_html(tmp_path).read_text()
    lists = re.findall(r'<ul class="nolog">(.*?)</ul>', page, re.S)
    assert len(lists) == 1 and lists[0].count("<li>") == 2
    assert "No log can show <code>" in lists[0] and '<p class="muted">No log can show' not in page
    css = (Path("src/exception_guardian/templates/report.css")).read_text()
    assert re.search(r"\.nolog\s*\{[^}]*gap:", css) and re.search(r"\.hunt-body > p[^{]*\{[^}]*margin", css)
