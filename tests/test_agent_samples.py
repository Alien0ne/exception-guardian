"""Rules with no sample logs for their log source, or no attack samples for their CVEs, were shown as 'Not tested'
or '0/0' (live run, 3 Nov 2026). guard now writes a sample brief per log source. The agent writes labelled events
from the CVE's public write-up into <run>/samples/, code checks them, and the report says they are agent-written.
A CVE no log can show (a CPU side channel) is recorded as not loggable instead of getting web-shell rules."""
import json
from dataclasses import replace
from datetime import date
from pathlib import Path

from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.guard.convert import convert_rule
from exception_guardian.guard.logtest import score_rule
from exception_guardian.guard.run import run_guard
from exception_guardian.guard.samples import load_agent_events, load_not_loggable

AV = Path("src/exception_guardian/data/sigmahq/av_exploit_cve_2021_34527_print_nightmare.yml")
SRC = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"


def _write(p: Path, events):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(e if isinstance(e, str) else json.dumps(e) for e in events) + "\n")


def test_agent_events_are_checked_and_marked(tmp_path):
    good = {"_logsource": "antivirus", "_label": "attack", "_attack": ["CVE-2021-34527"], "_source": SRC,
            "_note": "AV flags a dropped driver", "Filename": "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\a.dll"}
    benign = {"_logsource": "antivirus", "_label": "benign", "_note": "routine adware hit", "Filename": "C:\\a.exe"}
    _write(tmp_path / "samples/antivirus.jsonl", [
        good, benign, "{not json",
        {**good, "_source": "made up"},                       # an attack must cite a write-up
        {**good, "_attack": ["Log4Shell"]},                   # CVE ids only
        {**good, "_label": "maybe"},
        {**good, "_origin": "curated"},                       # the agent cannot claim to be curated data
    ])
    events, errors = load_agent_events(tmp_path / "samples")
    assert [e["_label"] for e in events] == ["attack", "benign"]
    assert all(e["_origin"] == "agent" for e in events)
    assert [e.split(": ", 1)[0] for e in errors] == [f"antivirus.jsonl line {n}" for n in (3, 4, 5, 6, 7)]
    assert "_source must be the http(s) URL of a public write-up" in errors[1]


def test_agent_sample_files_are_capped(tmp_path):
    ev = {"_logsource": "antivirus", "_label": "benign", "_note": "n", "Filename": "x"}
    _write(tmp_path / "samples/a.jsonl", [ev] * 600)
    events, errors = load_agent_events(tmp_path / "samples")
    assert len(events) == 500 and errors == ["a.jsonl: more than 500 events, so the rest were not read"]


def test_score_says_how_many_samples_the_agent_wrote():
    ev = [{"_logsource": "antivirus", "_label": "attack", "_attack": ["CVE-2021-34527"], "_origin": "agent",
           "Filename": "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\new\\x.dll", "Signature": "x"},
          {"_logsource": "antivirus", "_label": "benign", "_origin": "agent", "Filename": "C:\\Users\\a\\b.exe"}]
    t = score_rule(AV.read_text(), ev, ("CVE-2021-34527",))
    assert t["tested"] and t["agent_events"] == 2 and t["attack_total"] == 1


def test_generic_rules_score_on_every_attack_of_their_log_source():
    rule = Path("src/exception_guardian/data/sigmahq/proc_creation_lnx_webshell_detection.yml")
    ev = [{"_logsource": "process_creation/linux", "_label": "attack", "_attack": ["CVE-2099-0001"],
           "ParentImage": "/usr/sbin/apache2", "Image": "/usr/bin/whoami", "CommandLine": "whoami"}]
    assert score_rule(rule.read_text(), ev, ())["attack_total"] == 0
    t = score_rule(rule.read_text(), ev, (), any_attack=True)
    assert t["attack_total"] == 1 and t["attack_scope"] == "any CVE"


def test_not_loggable_is_checked(tmp_path):
    d = tmp_path / "drafts"; d.mkdir()
    (d / "not-loggable.json").write_text(json.dumps({
        "CVE-2017-5715": "CPU side channel (Spectre v2): it reads memory through cache timing\nand writes no log",
        "spectre": "not a CVE", "CVE-2018-3639": ""}))
    got, errors = load_not_loggable(d)
    assert got == {"CVE-2017-5715": "CPU side channel (Spectre v2): it reads memory through cache timing and writes no log"}
    assert len(errors) == 2


def _find(tmp_path):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))


def test_guard_writes_a_sample_brief_without_the_rules_logic(tmp_path):
    _find(tmp_path)
    logs = tmp_path / "logs"; logs.mkdir()  # no curated logs at all
    g = run_guard(tmp_path, Path("samples/golden/drafts"), replace(load_config("guardian.yaml"), sample_logs_dir=str(logs)))
    needs = g["R-CRUSH-003"]["needs_samples"]
    assert needs and needs[0]["logsource"] == "process_creation/windows" and needs[0]["cves"] == ["CVE-2025-31161"]
    brief = (tmp_path / needs[0]["brief"]).read_text()
    rule = (tmp_path / "rules/R-CRUSH-003" / g["R-CRUSH-003"]["rules"][0]["file"]).read_text()
    assert "CVE-2025-31161" in brief and "process_creation/windows" in brief and "ParentImage" in brief
    assert "crushftpservice.exe" not in brief.lower() and "crushftpservice.exe" in rule.lower()
    assert "samples/process_creation-windows.jsonl" in (tmp_path / "handoff-guard.md").read_text()


def test_guard_scores_rules_on_the_agents_samples(tmp_path):
    _find(tmp_path)
    logs = tmp_path / "logs"; logs.mkdir()
    _write(tmp_path / "samples/process_creation-windows.jsonl", [
        {"_logsource": "process_creation/windows", "_label": "attack", "_attack": ["CVE-2025-31161"],
         "_source": "https://www.crushftp.com/crush11wiki/Wiki.jsp?page=Update", "_note": "service spawns a shell",
         "ParentImage": "C:\\Program Files\\CrushFTP\\crushftpservice.exe", "Image": "C:\\Windows\\System32\\cmd.exe",
         "CommandLine": "cmd.exe /c whoami"},
        {"_logsource": "process_creation/windows", "_label": "benign", "_note": "admin opens notepad",
         "ParentImage": "C:\\Windows\\explorer.exe", "Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad"}])
    g = run_guard(tmp_path, Path("samples/golden/drafts"), replace(load_config("guardian.yaml"), sample_logs_dir=str(logs)))
    t = g["R-CRUSH-003"]["rules"][0]["tested"]
    assert t["tested"] and t["agent_events"] == 2 and t["attack_total"] == 1
    assert g["R-CRUSH-003"]["needs_samples"] == []


def test_not_loggable_cves_get_no_generic_rules(tmp_path):
    _find(tmp_path)
    d = tmp_path / "drafts"; d.mkdir()
    (d / "not-loggable.json").write_text(json.dumps({"CVE-2025-62593": "test: nothing in a log shows it"}))
    g = run_guard(tmp_path, d, load_config("guardian.yaml"))
    e = g["R-RAY-002"]
    assert e["missing_drafts"] == [] and e["rules"] == []
    assert e["not_loggable"] == [{"cve": "CVE-2025-62593", "reason": "test: nothing in a log shows it"}]


def test_report_says_who_wrote_the_samples_and_what_is_not_loggable(tmp_path):
    from exception_guardian.html_report import _hunt, _tested
    t = {"tested": True, "attack_hits": 1, "attack_total": 1, "benign_hits": 0, "benign_total": 1,
         "benign_hit_notes": [], "logsource": "antivirus", "agent_events": 2}
    assert "Agent-written samples from public write-ups, not real logs." in _tested(t)
    g = {"attack_total": 2, "attack_hits": 1, "benign_hits": 0, "benign_total": 3, "tested": True,
         "benign_hit_notes": [], "logsource": "x", "attack_scope": "any CVE"}
    assert "Attack samples caught (any CVE)" in _tested(g)
    f = {"exception": {"rule_id": "R1", "cves": ["CVE-2017-5715"], "rule_type": "accept", "targets": ["h"], "raw": {}},
         "grade": "REVOKE", "triggers": []}
    html = _hunt(tmp_path, {"R1": {"rules": [], "not_loggable": [{"cve": "CVE-2017-5715", "reason": "CPU side channel"}]}}, [f])
    assert "No log can show <code>CVE-2017-5715</code>: CPU side channel. Patch or mitigate it instead." in html


def test_no_query_messages_are_plain():
    web = Path("src/exception_guardian/data/sigmahq/web_cve_2021_41773_apache_path_traversal.yml")
    r = convert_rule(web.read_text(), ("sentinel",))["sentinel"]
    assert not r.ok and r.error.startswith("unsupported: Sentinel (ASIM) has no field for cs")
    task = Path("src/exception_guardian/data/sigmahq/win_security_apt_diamond_sleet_scheduled_task.yml")
    r = convert_rule(task.read_text(), ("sentinel",))["sentinel"]
    assert r.error == "unsupported: Sentinel has no field for TaskName, in ASIM or in the SecurityEvent table"


def test_a_security_rule_asim_lacks_a_field_for_falls_back_to_security_event():
    """Live run 4 Nov 2026: the PrintNightmare IPC rule had no Sentinel query (ASIM has no ShareName)."""
    ipc = Path("src/exception_guardian/data/sigmahq/win_security_exploit_cve_2021_1675_printspooler_security.yml")
    r = convert_rule(ipc.read_text(), ("sentinel",))["sentinel"]
    assert r.ok and r.query.startswith("SecurityEvent") and "ShareName" in r.query
    rpc = next(Path("src/exception_guardian/data/sigmahq").glob("rpc_firewall_printing*")).read_text()
    assert convert_rule(rpc, ("sentinel",))["sentinel"].error == \
        "unsupported: Sentinel (ASIM) has no table for application/rpc_firewall logs"


def test_service_based_rules_match_samples_named_as_their_brief():
    """windows/security and zeek/dce_rpc rules have no category: samples named as the brief names them must count."""
    zl = Path("src/exception_guardian/data/sigmahq/win_security_exploit_cve_2020_1472.yml").read_text()
    ev = [{"_logsource": "windows/security", "_label": "benign", "EventID": 4742, "SubjectUserName": "admin",
           "TargetUserName": "WS1$", "PasswordLastSet": "x"}]
    t = score_rule(zl, ev, ("CVE-2020-1472",))
    assert t["tested"] and t["benign_total"] == 1


def test_placeholders_match_any_value_in_sample_tests_as_in_queries():
    zl = Path("src/exception_guardian/data/sigmahq/win_security_exploit_cve_2020_1472.yml").read_text()
    ev = [{"_logsource": "windows/security", "_label": "attack", "_attack": ["CVE-2020-1472"], "EventID": 4742,
           "SubjectUserName": "ANONYMOUS LOGON", "TargetUserName": "DC01$", "PasswordLastSet": "x"}]
    t = score_rule(zl, ev, ("CVE-2020-1472",))
    assert t["tested"], t
