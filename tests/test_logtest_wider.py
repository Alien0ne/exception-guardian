"""The log tester used to stop at field references, number comparisons, |exists and booleans, and report such a
rule as not tested. It now evaluates them, so more SigmaHQ rules ship with a score. What it still cannot judge
(time parts, correlation rules) stays "not tested", never a guess."""
import pytest

from exception_guardian.guard.logtest import rule_matches, score_rule

HEAD = """title: t
id: 22222222-2222-4222-8222-222222222222
logsource: {category: process_creation, product: linux}
detection:
"""


def _rule(sel: str, condition: str = "sel") -> str:
    return HEAD + f"    sel: {sel}\n    condition: {condition}\n"


def _ev(**kw):
    return {"_logsource": "process_creation/linux", **kw}


def test_field_reference_compares_two_fields_of_one_event():
    r = _rule("{Image|fieldref: ParentImage}")
    assert rule_matches(r, _ev(Image="/bin/sh", ParentImage="/BIN/SH")) is True
    assert rule_matches(r, _ev(Image="/bin/sh", ParentImage="/bin/bash")) is False
    assert rule_matches(r, _ev(Image="/bin/sh")) is False


def test_field_reference_with_endswith_and_startswith():
    assert rule_matches(_rule("{CommandLine|fieldref|endswith: User}"), _ev(CommandLine="su - root", User="root"))
    assert not rule_matches(_rule("{CommandLine|fieldref|endswith: User}"), _ev(CommandLine="su - root", User="bob"))
    assert rule_matches(_rule("{CommandLine|fieldref|startswith: Image}"), _ev(CommandLine="/bin/sh -c x", Image="/bin/sh"))


@pytest.mark.parametrize("mod,value,yes,no", [("gte", 5, 5, 4), ("gt", 5, 6, 5), ("lte", 5, 5, 6), ("lt", 5, 4, 5)])
def test_number_comparisons(mod, value, yes, no):
    r = _rule(f"{{Count|{mod}: {value}}}")
    assert rule_matches(r, _ev(Count=yes)) and rule_matches(r, _ev(Count=str(yes)))
    assert not rule_matches(r, _ev(Count=no)) and not rule_matches(r, _ev(Count="many")) and not rule_matches(r, _ev())


def test_exists_true_and_false():
    assert rule_matches(_rule("{ParentImage|exists: true}"), _ev(ParentImage="/bin/sh"))
    assert not rule_matches(_rule("{ParentImage|exists: true}"), _ev(Image="/bin/sh"))
    assert rule_matches(_rule("{ParentImage|exists: false}"), _ev(Image="/bin/sh"))
    assert not rule_matches(_rule("{ParentImage|exists: false}"), _ev(ParentImage=""))


def test_booleans_match_json_booleans_and_their_text():
    r = _rule("{Elevated: true}")
    assert rule_matches(r, _ev(Elevated=True)) and rule_matches(r, _ev(Elevated="True"))
    assert not rule_matches(r, _ev(Elevated=False)) and not rule_matches(r, _ev(Elevated="yes")) and not rule_matches(r, _ev())


def test_windash_matches_either_dash():
    r = _rule("{CommandLine|windash|contains: ' -enc '}")
    assert rule_matches(r, _ev(CommandLine="powershell -enc AAAA")) and rule_matches(r, _ev(CommandLine="powershell /enc AAAA"))
    assert not rule_matches(r, _ev(CommandLine="powershell enc AAAA"))


def test_a_scored_rule_with_the_new_constructs_counts_as_tested():
    r = _rule("{Image|fieldref: ParentImage, Count|gte: 2}")
    s = score_rule(r, [_ev(Image="/bin/sh", ParentImage="/bin/sh", Count=3, _label="attack", _attack=["CVE-2025-54068"]),
                       _ev(Image="/bin/sh", ParentImage="/bin/sh", Count=1, _label="benign")], ("CVE-2025-54068",))
    assert s["tested"] is True and s["attack_hits"] == 1 and s["benign_hits"] == 0


def test_what_it_cannot_judge_is_still_reported_not_guessed():
    s = score_rule(_rule("{UtcTime|hour: 3}"), [_ev(UtcTime="2026-01-01 03:00:00", _label="benign")], ("CVE-2025-54068",))
    assert s["tested"] is False and "unsupported" in s["reason"]
