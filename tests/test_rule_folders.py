"""Two rule ids can make the same folder name (R/1 and R_1 both become R_1), and one id can repeat across
sources. guard gives each its own folder and records it; the page and the plan read that record, so neither
shows one exception's queries or brief under another."""
import json
from dataclasses import replace
from datetime import date
from html import escape

from exception_guardian.approval import write_plan
from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.guard.run import run_guard
from exception_guardian.html_report import render_html


def _run(tmp_path, rename: dict, source=None):
    """rename: {demo rule id: new id}. R-CRUSH-003 and R-RAY-002 share no rule, so their queries differ."""
    cfg = replace(load_config("guardian.yaml"), offline=True)
    run_find(cfg, tmp_path, date(2026, 11, 2))
    p = tmp_path / "findings.json"
    data = json.loads(p.read_text())
    picked = [f for f in data["findings"] if f["exception"]["rule_id"] in rename]
    for f in picked:
        f["exception"]["rule_id"] = rename[f["exception"]["rule_id"]]
    if source:
        picked[1]["exception"]["source"] = source
    p.write_text(json.dumps(data))
    return run_guard(tmp_path, tmp_path / "drafts", cfg)


PAIR = {"R-CRUSH-003": "R/1", "R-RAY-002": "R_1"}


def test_colliding_folder_names_keep_their_own_queries_on_the_page(tmp_path):
    guard = _run(tmp_path, PAIR)
    assert sorted(guard[r]["dir"] for r in ("R/1", "R_1")) == ["R_1", "R_1-2"]
    page = render_html(tmp_path)
    queries = {rid: {q.read_text().strip() for q in (tmp_path / "rules" / guard[rid]["dir"]).glob("*.splunk.txt")}
               for rid in ("R/1", "R_1")}
    assert queries["R/1"] and queries["R_1"] and not queries["R/1"] & queries["R_1"]
    for qs in queries.values():  # each exception's own queries are on the page, not only the first folder's
        for q in qs:
            assert escape(q) in page


def test_the_plan_links_each_exception_to_its_own_brief(tmp_path):
    _run(tmp_path, PAIR)
    plan = write_plan(tmp_path).read_text()
    assert "hunt-briefs/R_1.md" in plan and "hunt-briefs/R_1-2.md" in plan


def test_an_id_repeated_across_sources_keeps_its_title_on_the_page(tmp_path):
    guard = _run(tmp_path, {"R-CRUSH-003": "DUP-1", "R-RAY-002": "DUP-1"}, source="tenable-sc")
    keys = sorted(k for k in guard if "DUP-1" in k)
    assert len(keys) == 2 and all(k.endswith(":DUP-1") for k in keys)
    page = render_html(tmp_path)
    hunt = page.split('id="hunt-h"', 1)[1]
    assert ":DUP-1" not in hunt.split("</h3>")[0]  # the card is titled as the exception, not by the guard key


def test_the_page_never_prints_the_run_folder_as_an_absolute_path(tmp_path):
    """The page is shared like the plan, so its commands name the run folder the way the plan does."""
    _run(tmp_path, PAIR)
    write_plan(tmp_path)
    assert str(tmp_path) not in render_html(tmp_path)
