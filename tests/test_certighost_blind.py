"""Live run of 5 Nov 2026: after `dcs --use`, two SigmaHQ CertiGhost rules scored 0/1 on their attack samples.
Each drops any event whose Attributes contain a known DC name or address, but in the attack the same Attributes
also hold `rmd:<the DC being attacked>`, so the real DC values filtered out every real attack. For those rules
the DC values are left out (the stand-in excludes nothing) and the note says why."""
from pathlib import Path

import pytest

from exception_guardian.guard.convert import convert_rule
from exception_guardian.guard.logtest import score_rule

SIGMAHQ = Path("src/exception_guardian/data/sigmahq")
BLINDED = ["win_security_adcs_certighost_cdc_chase_request.yml",
           "win_security_adcs_certighost_cert_issued_via_chase.yml"]
FILL = {"known_cdcs": ["dc1.corp.example.com", "10.0.0.10"]}


def _attack(event_id):
    return {"_logsource": "windows/security", "_label": "attack", "_attack": ["CVE-2026-54121"],
            "EventID": event_id, "Attributes": "cdc:ghost.evil.example\nrmd:dc1.corp.example.com\nccm:ghost"}


@pytest.mark.parametrize("name,event_id", list(zip(BLINDED, (4886, 4887))))
def test_an_attack_naming_a_real_dc_in_rmd_is_still_caught(name, event_id):
    res = score_rule((SIGMAHQ / name).read_text(), [_attack(event_id)], ("CVE-2026-54121",),
                     any_attack=True, placeholders=FILL)
    assert res["tested"] is True and res["attack_hits"] == 1


@pytest.mark.parametrize("name", BLINDED)
def test_the_query_leaves_the_dc_values_out_and_says_why(name):
    out = convert_rule((SIGMAHQ / name).read_text(), ("splunk", "sentinel"), FILL)
    for t in ("splunk", "sentinel"):
        assert out[t].ok, t
        assert "dc1.corp.example.com" not in out[t].query and "10.0.0.10" not in out[t].query, t
        assert "rmd:" in out[t].note and "%known_cdcs%" in out[t].note, t


def test_other_dc_rules_still_use_the_dc_values():
    rule = (SIGMAHQ / "win_security_dc_machine_account_logon_non_dc_ip.yml").read_text()
    out = convert_rule(rule, ("splunk",), {"dc_ip_addresses": ["10.0.0.10"], "dc_machine_accounts": ["DC01$"]})
    assert "10.0.0.10" in out["splunk"].query and "rmd:" not in (out["splunk"].note or "")
