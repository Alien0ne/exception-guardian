"""Manual live test (4 Nov 2026), every file of a live /eg-run read back. The report led with a rule whose KEV
trigger was counted once per CVE, over a never-expiring PrintNightmare rule with the same reasons; tickets listed
"KEV, KEV, KEV"; a hunt brief for CPU side channels listed every host three times and asked for a hunt no log can
support; the look-back window was one day with no warning; the lead card said "accepted on the reasoning below"
with no reason given; a note said "no attack paths" under evidence that the host's subnet is on one; report.md
showed escaped backticks; the coverage sentence left Security Center hosts out of the total; a group row showed one CVE for 14 rules
when 13 had none; tickets pointed at the run folder, not the brief; and a widened placeholder was flagged on the
page but not in the brief."""
import json
from datetime import date

from exception_guardian.approval import write_plan
from exception_guardian.find import _sort_key
from exception_guardian.guard.hunt import render_hunt_brief
from exception_guardian.html_report import render_html
from exception_guardian.models import GradedException, Grade, RiskException, RuleType, Trigger
from exception_guardian.report import read_line, render_report


def _exc(rid, cves=("CVE-2020-1472",), expires=date(2026, 11, 11), justification="", created=date(2026, 11, 3)):
    return RiskException(source="tenable-vm", rule_id=rid, rule_type=RuleType.ACCEPT, cves=tuple(cves), plugin_ids=(),
                         targets=("web-host-01",), original_severity=None, new_severity=None, owner=None, created=created,
                         updated=None, expires=expires, justification=justification, status="enabled",
                         revised_findings=None)


def _t(code, grade=Grade.REVOKE):
    return Trigger(code, grade, None, "x", "s")


def test_a_never_expiring_rule_leads_when_the_reasons_tie():
    zerologon = GradedException(_exc("zerologon", ("CVE-2020-1472", "CVE-2020-1380", "CVE-2021-1678")), Grade.REVOKE,
                                (_t("KEV"), _t("KEV"), _t("KEV"), _t("EPSS_HIGH"), _t("ATTACK_PATH_CVE"),
                                 _t("NO_JUSTIFICATION", Grade.REVIEW)), (), (), ())
    nightmare = GradedException(_exc("printnightmare", ("CVE-2021-34527",), expires=None,
                                     justification="internal only"), Grade.REVOKE,
                                (_t("KEV"), _t("EPSS_HIGH"), _t("ATTACK_PATH_CVE"), _t("NO_EXPIRY", Grade.REVIEW)),
                                (), (), ())
    assert sorted([zerologon, nightmare], key=_sort_key)[0] is nightmare


def test_more_distinct_reasons_still_lead_over_no_expiry():
    many = GradedException(_exc("many"), Grade.REVOKE, (_t("KEV"), _t("EPSS_HIGH"), _t("ATTACK_PATH_CVE")), (), (), ())
    fewer = GradedException(_exc("fewer", expires=None), Grade.REVOKE, (_t("KEV"), _t("NO_EXPIRY", Grade.REVIEW)),
                            (), (), ())
    assert sorted([fewer, many], key=_sort_key)[0] is many


def _f(rid="b2c3d4e5", cves=("CVE-2020-1472",), triggers=("KEV", "KEV", "EPSS_HIGH"), justification="", **kw):
    return {"exception": {"source": "tenable-vm", "rule_id": rid, "rule_type": "accept", "cves": list(cves),
                          "plugin_ids": [], "targets": ["web-host-01"], "created": "2026-11-03", "expires": None,
                          "justification": justification, "status": "enabled", "revised_findings": 1,
                          "owner": None, **kw},
            "grade": "REVOKE", "triggers": [{"code": c, "grade": "REVOKE", "then": None, "now": "x", "source": "s"}
                                            for c in triggers], "assets": [], "intel": [], "notes": []}


def _run(tmp_path, findings, warnings=()):
    (tmp_path / "findings.json").write_text(json.dumps(
        {"today": "2026-11-04", "partial": False, "warnings": list(warnings), "findings": findings}))
    return tmp_path


def test_ticket_lists_each_trigger_once_and_points_at_the_brief(tmp_path):
    run = _run(tmp_path, [_f()])
    (run / "hunt-briefs").mkdir()
    (run / "hunt-briefs" / "b2c3d4e5.md").write_text("# brief")
    plan = write_plan(run).read_text()
    assert "Triggers: KEV, EPSS_HIGH\n" in plan and "KEV, KEV" not in plan
    assert "hunt-briefs/b2c3d4e5.md" in plan


def _asset(i):
    return {"name": f"host{i}", "os": "Linux", "ips": [f"192.0.2.{i % 250}"]}


def test_a_brief_where_no_log_can_show_the_cves_asks_for_a_patch_not_a_hunt():
    f = _f(cves=("CVE-2017-5715", "CVE-2017-5753"), assets=None)
    f["assets"] = [_asset(i) for i in range(1200)]
    notes = ["CVE-2017-5715: no log can show it (CPU side channel). Patch or mitigate it instead.",
             "CVE-2017-5753: no log can show it (CPU side channel). Patch or mitigate it instead."]
    brief = render_hunt_brief(f, [], date(2026, 11, 3), date(2026, 11, 4), notes, unloggable=True)
    assert "No hunt" in brief and "Patch or mitigate" in brief
    assert "Start with the detections" not in brief and "an attacker exploited" not in brief
    assert brief.count("host1199") == 0 and "1,190 more" in brief
    assert len(brief) < 8000


def test_long_host_lists_are_shortened_in_every_brief():
    f = _f()
    f["assets"] = [_asset(i) for i in range(300)]
    brief = render_hunt_brief(f, [], date(2026, 11, 3), date(2026, 11, 4))
    assert "host299" not in brief and "290 more" in brief and len(brief) < 8000


def test_a_short_window_says_it_only_covers_the_exception_s_age():
    brief = render_hunt_brief(_f(), [], date(2026, 11, 3), date(2026, 11, 4))
    assert "only the exception's age" in brief


def test_a_long_window_has_no_such_note():
    brief = render_hunt_brief(_f(), [], date(2025, 1, 3), date(2026, 11, 4))
    assert "only the exception's age" not in brief


def test_a_widened_placeholder_is_named_in_the_brief():
    rules = [{"file": "r.yml", "origin": "sigmahq", "title": "Zerologon", "url": None, "tested": {},
              "conversions": {"sentinel": {"ok": True, "file": "r.sentinel.txt", "error": None,
                                           "note": "Placeholder %DC-MACHINE-NAME% matches any value"}}}]
    brief = render_hunt_brief(_f(), rules, date(2026, 11, 3), date(2026, 11, 4))
    assert "%DC-MACHINE-NAME%" in brief.replace("\\", "")


def test_lead_card_without_a_reason_does_not_point_at_reasoning(tmp_path):
    page = render_html(_run(tmp_path, [_f()]))
    assert "on the reasoning below" not in page and "No reason was given" in page


def test_lead_card_with_a_reason_still_points_at_it(tmp_path):
    page = render_html(_run(tmp_path, [_f(justification="internal only")]))
    assert "on the reasoning below" in page


def test_report_md_keeps_config_names_as_code():
    md = render_report([], ["exposure: nothing is internet-facing. Set `exposure` in the config"], date(2026, 11, 4))
    assert "Set `exposure` in the config" in md and "\\`" not in md


def test_coverage_counts_security_center_hosts_in_the_total():
    r = {"exceptions": 250, "accept": 246, "recast": 3, "exclusion": 1, "assets": 1100, "hosts": 150,
         "host_search": 1000, "webapps": 4, "public_ip": 9, "tagged": 0, "covered_assets": 1110,
         "covered_findings": 0, "uncounted_rules": 0, "sc_hosts": 20}
    line = read_line(r)
    assert "cover 1,110 of those 1,120 assets and hosts" in line


def test_group_row_does_not_show_one_cve_for_rules_that_have_none(tmp_path):
    trig = ("BLANKET", "NO_EXPIRY")
    fs = [dict(_f(f"r{i}", cves=("CVE-2018-10115",) if i == 0 else (), triggers=trig), grade="REVIEW")
          for i in range(14)]
    for f in fs:
        f["exception"]["source"] = "tenable-sc"
        for t in f["triggers"]:
            t["grade"] = "REVIEW"
    page = render_html(_run(tmp_path, fs))
    import re
    summary = re.search(r'<details class="group"[^>]*><summary>(.*?)</summary>', page, re.S).group(1)
    assert "1 of 14 rules" in summary, summary


def test_asset_note_does_not_deny_a_path_through_its_subnet():
    from exception_guardian import grading
    import inspect
    src = inspect.getsource(grading)
    assert '"no attack paths"' not in src and "not itself on an attack path" in src
