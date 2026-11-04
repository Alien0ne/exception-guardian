"""Review of the live run (4 Nov 2026): the Zerologon rule's %DC-MACHINE-NAME% became "any value" (TargetUserName="*"), and
the only way to narrow it was to edit the query by hand. The config's placeholders key now fills it: the SIEM
queries and the log test both use your own names, and an unset placeholder still widens and says so."""
from pathlib import Path

import pytest

from exception_guardian.config import load_config
from exception_guardian.guard.convert import convert_rule
from exception_guardian.guard.logtest import score_rule

RULE = Path("src/exception_guardian/data/sigmahq/win_security_exploit_cve_2020_1472.yml").read_text()
FILL = {"DC-MACHINE-NAME": ["DC01$", "DC02$"]}


def _ev(target, label="attack"):
    return {"_logsource": "windows/security", "_label": label, "_attack": ["CVE-2020-1472"], "EventID": 4742,
            "SubjectUserName": "ANONYMOUS LOGON", "TargetUserName": target, "PasswordLastSet": "2026-11-01"}


def test_config_reads_placeholders(tmp_path):
    p = tmp_path / "g.yaml"
    p.write_text("sources: [{name: csv, path: x.csv}]\nplaceholders:\n  DC-MACHINE-NAME: [DC01$, DC02$]\n"
                 "  ADMIN: root\n")
    assert load_config(p).placeholders == {"DC-MACHINE-NAME": ("DC01$", "DC02$"), "ADMIN": ("root",)}


def test_a_bad_placeholders_value_names_the_key(tmp_path):
    p = tmp_path / "g.yaml"
    p.write_text("sources: [{name: csv, path: x.csv}]\nplaceholders: [DC01$]\n")
    with pytest.raises(ValueError, match="placeholders"):
        load_config(p)


def test_filled_placeholders_go_into_every_query():
    out = convert_rule(RULE, ("splunk", "sentinel"), FILL)
    for t in ("splunk", "sentinel"):
        assert out[t].ok and "DC01$" in out[t].query and "DC02$" in out[t].query, t
        assert "matches any value" not in (out[t].note or "")
        assert "%DC-MACHINE-NAME% is set from your config" in out[t].note


def test_unset_placeholders_still_widen_and_name_the_config_key():
    note = convert_rule(RULE, ("splunk",))["splunk"].note
    assert "matches any value" in note and "placeholders:" in note


def test_the_log_test_uses_the_filled_names():
    events = [_ev("DC01$"), _ev("WS07$", "benign")]
    wide = score_rule(RULE, events, ("CVE-2020-1472",))
    filled = score_rule(RULE, events, ("CVE-2020-1472",), placeholders=FILL)
    assert wide["benign_hits"] == 1 and filled["benign_hits"] == 0 and filled["attack_hits"] == 1


DEAD = Path("src/exception_guardian/data/sigmahq/win_security_dc_machine_account_logon_non_dc_ip.yml").read_text()


def test_an_unset_placeholder_in_a_not_filter_gets_a_stand_in_not_a_wildcard():
    """NOT IpAddress="*" excludes every event: the query looked fine and could never fire. A stand-in excludes
    nothing instead, and the note says so (the live run of 4 Nov 2026 showed no query at all was worse)."""
    out = convert_rule(DEAD, ("splunk", "sentinel"))
    for t in ("splunk", "sentinel"):
        assert out[t].ok and 'IpAddress="*"' not in out[t].query and "SET_dc_ip_addresses" in out[t].query
        assert "%dc_ip_addresses%" in out[t].note and "placeholders:" in out[t].note


def test_setting_it_brings_the_query_back():
    out = convert_rule(DEAD, ("splunk",), {"dc_ip_addresses": ["10.0.0.10"], "dc_machine_accounts": ["DC01$"]})
    assert out["splunk"].ok and "10.0.0.10" in out["splunk"].query


def test_the_log_test_scores_with_the_stand_in():
    ev = {"_logsource": "windows/security", "_label": "attack", "_attack": ["CVE-2020-1472"], "EventID": 4624,
          "TargetUserName": "DC01$", "IpAddress": "10.9.9.9"}
    res = score_rule(DEAD, [ev], ("CVE-2020-1472",), any_attack=True)
    assert res["tested"] is True and "reason" not in res


def test_a_miss_names_the_missed_sample_and_says_it_may_be_the_sample():
    """Zerologon, 4 Nov: the vetted rule 'missed' because the drafted attack event had PasswordLastSet "-"."""
    from exception_guardian.html_report import _tested
    bad = {**_ev("DC01$"), "PasswordLastSet": "-", "_note": "Zerologon: DC account changed", "_origin": "agent"}
    t = score_rule(RULE, [bad], ("CVE-2020-1472",))
    assert t["attack_hits"] == 0 and t["attack_missed_notes"] == ["Zerologon: DC account changed"]
    html = _tested(t)
    assert "Missed: Zerologon: DC account changed" in html and "check the sample against" in html and "its write-up" in html
