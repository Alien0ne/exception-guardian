"""A run with no REVOKE (the usual live case) says so in the plan and on the page, instead of empty sections
and an --apply command with nothing to apply."""
import json

from exception_guardian.cli import main
from exception_guardian.html_report import render_html


def _review_only(tmp_path):
    assert main(["find", "--offline", "--out", str(tmp_path), "--today", "2026-11-02"]) == 0
    p = tmp_path / "findings.json"
    d = json.loads(p.read_text())
    d["findings"] = [f for f in d["findings"] if f["grade"] == "REVIEW"]
    p.write_text(json.dumps(d))
    assert main(["guard", "--run", str(tmp_path)]) == 0
    assert main(["approve", "--run", str(tmp_path)]) == 0
    return len(d["findings"])


def test_plan_says_nothing_to_disable(tmp_path):
    n = _review_only(tmp_path)
    plan = (tmp_path / "approval-plan.md").read_text()
    assert "No exception is graded REVOKE, so there is nothing to disable." in plan
    assert f"{n} graded REVIEW" in plan


def test_page_says_nothing_to_hunt_or_apply(tmp_path):
    n = _review_only(tmp_path)
    page = render_html(tmp_path)
    assert "Nothing to revoke, so nothing to hunt or apply" in page
    assert f"{n} exceptions graded REVIEW" in page
    assert "--apply" not in page
    assert 'id="hunt-h"' not in page and 'id="plan-h"' not in page


def test_page_with_revokes_keeps_hunt_and_plan(tmp_path):
    assert main(["demo", "--out", str(tmp_path)]) == 0
    page = render_html(tmp_path)
    assert 'id="hunt-h"' in page and 'id="plan-h"' in page and "Nothing to revoke" not in page
    assert "nothing to disable" not in (tmp_path / "approval-plan.md").read_text()
