"""approve also writes review-plan.md: what each owner has to do about their REVIEW rules. Before this, approve
handled REVOKE only and a REVIEW rule had no next step (the commonest fix is an expiry or a reason, not a disable)."""
import json
from datetime import date

from exception_guardian.approval import write_plan, write_review_plan
from exception_guardian.find import to_dict
from exception_guardian.models import Grade, GradedException, RiskException, RuleType, Trigger


def _g(rule_id, codes, grade=Grade.REVIEW, owner="alice", justification="Accepted by CAB", source="tenable-vm"):
    e = RiskException(source=source, rule_id=rule_id, rule_type=RuleType.ACCEPT, cves=("CVE-2024-0001",),
                      plugin_ids=(), targets=("*",), original_severity=None, new_severity=None, owner=owner,
                      created=date(2025, 1, 1), updated=None, expires=None, justification=justification,
                      status="enabled", revised_findings=1)
    trig = tuple(Trigger(c, Grade.REVOKE if c == "KEV" else Grade.REVIEW, "0.01" if c == "EPSS_ROSE" else None,
                         "0.2" if c == "EPSS_ROSE" else "now", "src") for c in codes)
    return GradedException(e, grade, trig, (), (), ())


def _run(tmp_path, graded):
    (tmp_path / "findings.json").write_text(json.dumps(
        {"today": "2026-11-02", "warnings": [], "findings": [to_dict(g) for g in graded]}))
    return tmp_path


def test_one_section_per_owner_with_review_now_first(tmp_path):
    run = _run(tmp_path, [_g("R1", ["EPSS_ROSE", "NO_EXPIRY"]), _g("R2", ["TOO_OLD"]),
                          _g("R3", ["NO_EXPIRY"], owner="bob"), _g("R4", ["KEV"], grade=Grade.REVOKE, owner="carol")])
    text = write_review_plan(run).read_text()
    assert text.index("## alice") < text.index("## bob") and "carol" not in text
    alice = text.split("## alice")[1].split("## bob")[0]
    assert alice.index("Review now (1)") < alice.index("Housekeeping (1)")
    assert alice.index("R1") < alice.index("R2")


def test_each_trigger_names_its_action(tmp_path):
    run = _run(tmp_path, [_g("R1", ["EPSS_ROSE", "NO_EXPIRY", "NO_JUSTIFICATION", "BLANKET", "EXPIRED_STILL_ENABLED"])])
    text = write_review_plan(run).read_text()
    for want in ("EPSS rose from 0.01 to 0.2", "set an expiry date", "write the reason", "narrow it",
                 "disable it or set a new expiry"):
        assert want in text, want


def test_nothing_is_changed_and_it_says_so(tmp_path):
    text = write_review_plan(_run(tmp_path, [_g("R1", ["TOO_OLD"])])).read_text()
    assert "Nothing below has been changed" in text and "apply mode never touches" in text


def test_long_housekeeping_lists_are_capped_and_counted(tmp_path):
    run = _run(tmp_path, [_g(f"R{i:03}", ["TOO_OLD"]) for i in range(60)])
    text = write_review_plan(run).read_text()
    assert "R000" in text and "R059" not in text and "and 35 more" in text


def test_no_review_rules_means_no_file(tmp_path):
    run = _run(tmp_path, [_g("R4", ["KEV"], grade=Grade.REVOKE)])
    assert write_review_plan(run) is None and not (run / "review-plan.md").exists()


def test_hostile_owner_and_rule_id_cannot_add_lines_or_close_the_block(tmp_path):
    run = _run(tmp_path, [_g("R1\n## injected\n```", ["TOO_OLD"], owner="eve\n# heading")])
    text = write_review_plan(run).read_text()
    assert "\n## injected" not in text and "\n# heading" not in text
    assert text.count("```") % 2 == 0 and text.count("```text") == text.count("```") // 2


def test_approve_writes_both_plans(tmp_path):
    run = _run(tmp_path, [_g("R1", ["TOO_OLD"]), _g("R4", ["KEV"], grade=Grade.REVOKE)])
    write_plan(run)
    assert (run / "approval-plan.md").is_file() and (run / "review-plan.md").is_file()
    assert "review-plan.md" in (run / "approval-plan.md").read_text()
