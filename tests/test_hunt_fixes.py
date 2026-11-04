"""Hunt fixes from the live run (3 Nov 2026): a rollup rule of dozens of CVEs asked for a draft per CVE, and the SigmaHQ
Zerologon rule (windows/security, a %DC-MACHINE-NAME% placeholder) converted to no query at all."""
from pathlib import Path

from exception_guardian.guard.convert import convert_rule
from exception_guardian.guard.run import needs_rule

ZEROLOGON = Path("src/exception_guardian/data/sigmahq/win_security_exploit_cve_2020_1472.yml").read_text()


def test_splunk_widens_a_placeholder_and_says_so():
    r = convert_rule(ZEROLOGON, ("splunk",))["splunk"]
    assert r.ok and 'EventCode=4742' in r.query and 'TargetUserName="*"' in r.query
    assert r.note == ("Placeholder %DC-MACHINE-NAME% matches any value. Set it under placeholders: in the config to "
                      "narrow the query.")


def test_sentinel_uses_the_security_event_table_for_windows_security():
    r = convert_rule(ZEROLOGON, ("sentinel",))["sentinel"]
    assert r.ok and r.query.startswith("SecurityEvent\n") and "EventID == 4742" in r.query
    assert "SecurityEvent table" in r.note


def test_defender_says_why_there_is_no_query():
    r = convert_rule(ZEROLOGON, ("defender",))["defender"]
    assert not r.ok and r.error == "unsupported: Defender XDR has no table for the Windows security event log"


def _f(cves, triggers):
    return {"exception": {"cves": cves}, "triggers": [{"code": c, "now": n} for c, n in triggers]}


def test_drafts_only_for_the_cves_behind_the_revoke():
    f = _f([f"CVE-2020-{1000 + i}" for i in range(60)] + ["CVE-2020-1472"],
           [("KEV", "CVE-2020-1472 in KEV since 2021-11-03"), ("EPSS_HIGH", "CVE-2020-1001: 0.9"),
            ("ATTACK_PATH_CVE", "CVE-2020-1002 is used in an attack path: a → b"), ("NO_EXPIRY", "no expiry")])
    assert needs_rule(f) == {"CVE-2020-1472", "CVE-2020-1001", "CVE-2020-1002"}


def test_one_cve_or_no_cve_signal_keeps_every_cve():
    assert needs_rule(_f(["CVE-1"], [("INTERNET_FACING", "internet-facing")])) == {"CVE-1"}
    assert needs_rule(_f(["CVE-1", "CVE-2"], [("INTERNET_FACING", "x")])) == {"CVE-1", "CVE-2"}


def test_no_table_says_which_log_has_no_table():
    zeek = Path("src/exception_guardian/data/sigmahq/"
                "zeek_dce_rpc_exploit_cve_2021_1675_printnightmare_print_driver_install.yml").read_text()
    r = convert_rule(zeek, ("sentinel", "defender"))
    assert r["sentinel"].error == "unsupported: Sentinel (ASIM) has no table for zeek/dce_rpc logs"
    assert r["defender"].error == "unsupported: Defender XDR has no table for zeek/dce_rpc logs"


def test_hunt_header_lists_the_cves_behind_the_revoke_first(tmp_path):
    from exception_guardian.html_report import _hunt
    cves = [f"CVE-2020-{1000 + i}" for i in range(60)] + ["CVE-2020-1472"]
    f = {"exception": {"rule_id": "R1", "cves": cves, "rule_type": "accept", "targets": ["h"], "raw": {}},
         "grade": "REVOKE", "triggers": [{"code": "KEV", "now": "CVE-2020-1472 in KEV since 2021-11-03"}]}
    head = _hunt(tmp_path, {"R1": {"rules": []}}, [f]).split("</header>")[0]
    assert "<code>CVE-2020-1472</code>" in head and "CVE-2020-1005" not in head and "and 55 more" in head
