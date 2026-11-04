"""Fixes from the 3 Nov quality review of the detection side (guard)."""
import json
from dataclasses import replace
from datetime import date
from pathlib import Path

from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.guard.logtest import score_rule

CRUSH = Path("src/exception_guardian/data/sigmahq/proc_creation_win_crushftp_susp_child_processes.yml")
SRC = "https://example.com/advisory"


def _rule(detection, logsource="  category: process_creation\n  product: windows", tags=""):
    return (f"title: t\nid: 11111111-2222-3333-4444-555555555555\nstatus: test\n{tags}logsource:\n{logsource}\n"
            f"detection:\n{detection}\nlevel: high\n")


def _ev(label, **f):
    return {"_logsource": "process_creation/windows", "_label": label, **f}


def test_regex_rules_are_scored_not_a_crash():
    r = _rule("  sel:\n    CommandLine|re: 'who.mi'\n  condition: sel")
    t = score_rule(r, [_ev("attack", _attack=["CVE-2021-1"], CommandLine="whoami"), _ev("benign", CommandLine="ls")],
                   ("CVE-2021-1",))
    assert t["tested"] and t["attack_hits"] == 1 and t["benign_hits"] == 0


def test_regex_flags_are_honoured():
    r = _rule("  sel:\n    CommandLine|re|i: 'WHOAMI'\n  condition: sel")
    t = score_rule(r, [_ev("attack", _attack=["CVE-2021-1"], CommandLine="whoami")], ("CVE-2021-1",))
    assert t["attack_hits"] == 1


def test_cased_strings_match_case_sensitively():
    r = _rule("  sel:\n    CommandLine|cased: 'whoami'\n  condition: sel")
    t = score_rule(r, [_ev("attack", _attack=["CVE-2021-1"], CommandLine="WHOAMI")], ("CVE-2021-1",))
    assert t["attack_hits"] == 0


def test_any_evaluator_error_marks_the_rule_untested_instead_of_stopping_guard():
    r = _rule("  sel:\n    CommandLine|re: '('\n  condition: sel")
    t = score_rule(r, [_ev("attack", _attack=["CVE-2021-1"], CommandLine="x")], ("CVE-2021-1",))
    assert t["tested"] is False


def test_a_rule_with_a_service_scores_only_on_that_service():
    r = _rule("  sel:\n    EventID: 4624\n  condition: sel", logsource="  product: windows\n  service: security")
    other = {"_logsource": "windows/system", "_label": "benign", "EventID": 4624}
    own = {"_logsource": "windows/security", "_label": "benign", "EventID": 4624}
    t = score_rule(r, [other, own], ())
    assert t["benign_total"] == 1


def test_a_draft_scores_only_on_its_own_cve(tmp_path):
    from exception_guardian.guard.run import run_guard
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    d = tmp_path / "drafts"; d.mkdir()
    # filed for the Ray CVE, but tagged and written for CrushFTP, whose samples it would borrow
    text = CRUSH.read_text().replace("459628e3-1b00-4e9b-9e5b-7da8961aea35", "aaaaaaaa-1b00-4e9b-9e5b-7da8961aea35")
    (d / "CVE-2025-62593.yml").write_text(text)
    g = run_guard(tmp_path, d, load_config("guardian.yaml"))
    e = g["R-RAY-002"]
    assert any(x["file"] == "CVE-2025-62593.yml" and "CVE-2025-62593" in " ".join(x["errors"]) for x in e["dropped"])
    assert not any(r["origin"] == "drafted" for r in e["rules"])


def test_a_draft_cannot_replace_a_sigmahq_rule_by_reusing_its_id(tmp_path):
    from exception_guardian.guard.run import run_guard
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    d = tmp_path / "drafts"; d.mkdir()
    fake = CRUSH.read_text().replace("CommandLine|contains", "CommandLine|endswith").replace("ParentImage|endswith",
                                                                                              "ParentImage|startswith")
    (d / "CVE-2025-31161.yml").write_text(fake)
    g = run_guard(tmp_path, d, load_config("guardian.yaml"))
    e = g["R-CRUSH-003"]
    assert [r["origin"] for r in e["rules"]][0] == "sigmahq"
    assert any(x["file"] == "CVE-2025-31161.yml" and "id" in " ".join(x["errors"]) for x in e["dropped"])


def test_a_long_log_source_name_gets_a_short_brief_file(tmp_path):
    from exception_guardian.guard.samples import brief_path, samples_file, write_briefs
    ls = "x" * 300
    write_briefs(tmp_path, {ls: {"cves": set(), "fields": []}})
    assert len(Path(brief_path(ls)).name) < 120 and (tmp_path / brief_path(ls)).is_file()
    assert len(Path(samples_file(ls)).name) < 120


def test_agent_sample_files_are_read_with_byte_and_error_caps(tmp_path):
    from exception_guardian.guard import samples
    d = tmp_path / "samples"; d.mkdir()
    (d / "a.jsonl").write_text("{bad\n" * 5000)
    events, errors = samples.load_agent_events(d)
    assert events == [] and len(errors) <= samples.MAX_ERRORS + 1
    (d / "a.jsonl").write_bytes(b'{"x": "' + b"y" * (samples.MAX_BYTES + 10) + b'"}\n')
    _, errors = samples.load_agent_events(d)
    assert any("larger than" in e for e in errors)


def test_not_loggable_reason_is_escaped_in_the_guard_handoff(tmp_path):
    from exception_guardian.guard.run import run_guard
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    d = tmp_path / "drafts"; d.mkdir()
    (d / "not-loggable.json").write_text(json.dumps({"CVE-2025-62593": "<img src=x onerror=alert(1)> [x](javascript:1)"}))
    run_guard(tmp_path, d, load_config("guardian.yaml"))
    text = (tmp_path / "handoff-guard.md").read_text()
    import re
    assert not re.search(r"(?<!\\)<img", text) and not re.search(r"(?<!\\)\](?<!\\)\(javascript", text)


def test_no_valid_draft_matches_the_whole_cve_not_a_prefix():
    from exception_guardian.guard.run import _draft_of
    assert _draft_of("CVE-2025-1234.yml", "CVE-2025-1234") and _draft_of("CVE-2025-1234-web.yml", "CVE-2025-1234")
    assert not _draft_of("CVE-2025-12345.yml", "CVE-2025-1234")


def test_placeholder_note_names_only_real_placeholders():
    from exception_guardian.guard.convert import convert_rule
    text = Path("src/exception_guardian/data/sigmahq/web_cve_2014_6287_hfs_rce.yml").read_text()
    for res in convert_rule(text, ("splunk",)).values():
        assert "Placeholder" not in (res.note or "")


def test_new_kev_listing_for_a_second_cve_counts_as_new_evidence():
    from exception_guardian.changes import compare_runs

    def f(kev):
        return {"grade": "REVOKE", "exception": {"rule_id": "R1", "source": "tenable-vm", "rule_type": "accept"},
                "triggers": [{"code": "KEV", "now": f"{c} in KEV since 2026-01-01", "source": "CISA KEV"} for c in kev]}
    ch = compare_runs({"today": "2026-11-01", "findings": [f(["CVE-2025-1111"])]},
                      {"today": "2026-11-03", "findings": [f(["CVE-2025-1111", "CVE-2025-2222"])]})
    assert len(ch["new_evidence"]) == 1 and ch["unchanged"] == 0


def test_sigmahq_winrar_typo_tag_scores_on_the_real_cve():
    """SigmaHQ tags its CVE-2023-38831 WinRAR rules cve.2023-38331 (a typo: the file names and references say
    38831). Attack samples for the real CVE must count."""
    r = Path("src/exception_guardian/data/sigmahq/proc_creation_win_exploit_cve_2023_38831_winrar_child_proc.yml")
    ev = {"_logsource": "process_creation/windows", "_label": "attack", "_attack": ["CVE-2023-38831"],
          "ParentImage": "C:\\Program Files\\WinRAR\\WinRAR.exe", "Image": "C:\\Windows\\System32\\cmd.exe",
          "CommandLine": "cmd.exe /c a.cmd"}
    assert score_rule(r.read_text(), [ev], ("CVE-2023-38831",))["attack_total"] == 1
