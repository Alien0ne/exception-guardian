"""Manual live test (4 Nov 2026), every file of a live /eg-run read back: guard left the first pass's web-shell
rules in rules/ after the second pass dropped them; the Sentinel and Defender queries of a SigmaHQ PrintNightmare rule
could never match (a value ending in a backslash came out as `endswith "...*"`); and a rule was marked as missing
attack samples written for another stage of the same CVE (a 4741 sample scored against a 4662 rule)."""
from dataclasses import replace
from datetime import date

from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.guard.convert import convert_rule
from exception_guardian.guard.logtest import score_rule
from exception_guardian.guard.run import run_guard

RULE = """title: t
id: 3b1b6b4e-0000-4000-8000-000000000001
status: test
logsource: {category: registry_event, product: windows}
detection:
  sel:
    TargetObject|contains: '\\Drivers\\Version-3\\QMS 810\\'
  condition: sel
"""


def test_a_contains_value_ending_in_a_backslash_stays_contains_in_kql():
    out = convert_rule(RULE, ("sentinel", "defender", "splunk"), {})
    for target in ("sentinel", "defender"):
        q = out[target].query
        assert "endswith" not in q and "810*" not in q, q
        assert 'contains "\\\\Drivers\\\\Version-3\\\\QMS 810\\\\"' in q, q


def test_hklm_is_still_spelled_out_for_sentinel():
    rule = RULE.replace("TargetObject|contains: '\\Drivers\\Version-3\\QMS 810\\'",
                        "TargetObject|startswith: 'HKLM\\SOFTWARE\\Foo'")
    q = convert_rule(rule, ("sentinel",), {})["sentinel"].query
    assert "HKEY_LOCAL_MACHINE" in q, q


STAGE_RULE = """title: replication
id: 3b1b6b4e-0000-4000-8000-000000000002
status: test
tags: [cve.2026-54121]
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4662
    SubjectUserName|endswith: '$'
  filter_main_system:
    EventID: 4741
  condition: selection and not filter_main_system
"""


def _ev(eid, label="attack", note="", user="GHOST01$"):
    return {"_logsource": "windows/security", "_label": label, "_attack": ["CVE-2026-54121"] if label == "attack" else [],
            "_note": note, "EventID": eid, "SubjectUserName": user}


def test_attack_samples_of_another_event_id_do_not_count_as_misses():
    events = [_ev(4741, note="staging: computer account created"), _ev(4662, note="DCSync"),
              _ev(4662, "benign", user="alice")]
    s = score_rule(STAGE_RULE, events, ("CVE-2026-54121",), own_cves_only=True)
    assert (s["attack_hits"], s["attack_total"]) == (1, 1), s
    assert "attack_missed_notes" not in s and s["other_stage"] == 1


def test_a_miss_on_the_rule_s_own_event_id_still_counts():
    events = [_ev(4662, note="DCSync by a user account", user="bob"), _ev(4662, "benign", user="alice")]
    s = score_rule(STAGE_RULE, events, ("CVE-2026-54121",), own_cves_only=True)
    assert (s["attack_hits"], s["attack_total"]) == (0, 1) and s["attack_missed_notes"] == ["DCSync by a user account"]


def test_a_rule_without_an_event_id_scores_every_attack_sample():
    rule = STAGE_RULE.replace("    EventID: 4662\n", "", 1)
    events = [_ev(4741, note="a"), _ev(4662, note="b")]
    s = score_rule(rule, events, ("CVE-2026-54121",), own_cves_only=True)
    assert s["attack_total"] == 2 and "other_stage" not in s


def test_guard_clears_rules_a_previous_pass_wrote(tmp_path):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    stale = tmp_path / "rules" / "R-HERO-001" / "proc_creation_old_pass.splunk.txt"
    stale.parent.mkdir(parents=True)
    stale.write_text("old")
    gone = tmp_path / "rules" / "R-NOT-REVOKE-ANY-MORE"
    gone.mkdir()
    (gone / "x.yml").write_text("old")
    run_guard(tmp_path, tmp_path / "nodrafts", load_config("guardian.yaml"))
    assert not stale.exists() and not gone.exists()
    assert any((tmp_path / "rules" / "R-HERO-001").iterdir())  # this pass's rules are written


def test_guard_never_follows_a_rules_link_out_of_the_run(tmp_path):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path / "run", date(2026, 11, 2))
    outside = tmp_path / "keep"
    outside.mkdir()
    (outside / "precious.txt").write_text("keep me")
    (tmp_path / "run" / "rules").symlink_to(outside, target_is_directory=True)
    run_guard(tmp_path / "run", tmp_path / "nodrafts", load_config("guardian.yaml"))
    assert (outside / "precious.txt").read_text() == "keep me"
