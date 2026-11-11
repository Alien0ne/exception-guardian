"""REVIEW is split in two: rules with risk evidence ("now") and rules with paperwork gaps only ("housekeeping").
The live run (4 Nov 2026) graded 316 of 324 rules REVIEW; a flat pile that size is not read."""
import json
from datetime import date

from exception_guardian.find import _sort_key, to_dict
from exception_guardian.grading import review_tier
from exception_guardian.models import Grade, GradedException, RiskException, RuleType, Trigger
from exception_guardian.report import render_report


def _g(rule_id, codes, grade=Grade.REVIEW, owner="alice", created=date(2025, 1, 1)):
    e = RiskException(source="tenable-vm", rule_id=rule_id, rule_type=RuleType.ACCEPT, cves=("CVE-2024-0001",),
                      plugin_ids=(), targets=("*",), original_severity=None, new_severity=None, owner=owner,
                      created=created, updated=None, expires=None, justification="Accepted by CAB", status="enabled",
                      revised_findings=1)
    trig = tuple(Trigger(c, Grade.REVOKE if c == "KEV" else Grade.REVIEW, None, "now", "src") for c in codes)
    return GradedException(e, grade, trig, (), (), ())


def test_paperwork_only_is_housekeeping():
    assert review_tier(_g("A", ["NO_EXPIRY", "TOO_OLD", "NO_JUSTIFICATION", "BLANKET"])) == "housekeeping"


def test_risk_evidence_is_now():
    for code in ("EPSS_ROSE", "PUBLIC_IP", "PATH_CVE_ELSEWHERE", "JUSTIFICATION_CONTRADICTED",
                 "EXPIRED_STILL_ENABLED"):
        assert review_tier(_g("A", ["NO_EXPIRY", code])) == "now", code


def test_other_grades_have_no_tier():
    assert review_tier(_g("A", ["KEV"], grade=Grade.REVOKE)) is None
    assert review_tier(_g("A", [], grade=Grade.OK)) is None


def test_now_sorts_before_housekeeping_even_when_newer():
    old_paper = _g("OLD", ["NO_EXPIRY", "TOO_OLD"], created=date(2020, 1, 1))
    new_risk = _g("NEW", ["EPSS_ROSE"], created=date(2026, 1, 1))
    two_risks = _g("TWO", ["EPSS_ROSE", "PUBLIC_IP"], created=date(2026, 6, 1))
    order = [g.exception.rule_id for g in sorted([old_paper, new_risk, two_risks], key=_sort_key)]
    assert order == ["TWO", "NEW", "OLD"]


def test_findings_json_carries_the_tier():
    assert to_dict(_g("A", ["EPSS_ROSE"]))["review_tier"] == "now"
    assert to_dict(_g("A", ["TOO_OLD"]))["review_tier"] == "housekeeping"
    assert to_dict(_g("A", ["KEV"], grade=Grade.REVOKE))["review_tier"] is None
    json.dumps(to_dict(_g("A", ["EPSS_ROSE"])))


def test_report_counts_tiers_and_labels_headings():
    md = render_report([_g("R1", ["EPSS_ROSE"]), _g("R2", ["TOO_OLD"]), _g("R3", ["NO_EXPIRY"])], [], date(2026, 11, 2))
    assert "| REVIEW | 3 (1 to review now, 2 housekeeping) |" in md
    assert "## REVIEW (now): R1" in md and "## REVIEW (housekeeping): R2" in md


def test_report_lists_review_work_by_owner():
    md = render_report([_g("R1", ["EPSS_ROSE"], owner="alice"), _g("R2", ["TOO_OLD"], owner="alice"),
                        _g("R3", ["NO_EXPIRY"], owner=None), _g("R4", ["KEV"], grade=Grade.REVOKE, owner="bob")],
                       [], date(2026, 11, 2))
    assert "## Review work by owner" in md
    assert "| alice | 1 | 1 |" in md and "| unknown | 0 | 1 |" in md
    assert "| bob |" not in md


def test_html_shows_tier_on_each_review_row_and_in_the_count(tmp_path):
    from exception_guardian.html_report import render_html
    fs = [to_dict(_g("R1", ["EPSS_ROSE"])), to_dict(_g("R2", ["TOO_OLD"])), to_dict(_g("R3", ["NO_EXPIRY"]))]
    (tmp_path / "findings.json").write_text(json.dumps({"today": "2026-11-02", "warnings": [], "findings": fs}))
    html = render_html(tmp_path)
    assert html.count('<span class="grade review">Review now</span>') == 1
    assert html.count('<span class="grade review housekeeping">Housekeeping</span>') == 2
    assert "1 now, 2 housekeeping" in html


def test_html_reads_an_older_findings_file_without_tiers(tmp_path):
    from exception_guardian.html_report import render_html
    f = to_dict(_g("R1", ["EPSS_ROSE"]))
    del f["review_tier"]
    (tmp_path / "findings.json").write_text(json.dumps({"today": "2026-11-02", "warnings": [], "findings": [f]}))
    assert '<span class="grade review">Review</span>' in render_html(tmp_path)
