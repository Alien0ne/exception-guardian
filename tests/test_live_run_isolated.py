"""Manual live test (4 Nov 2026), /eg-run in a clean Claude Code with no user settings, report read by a person.
The exposure warning said only "set exposure" and /eg-run skipped the step that maps it; three SigmaHQ rules whose
filter needs the DC addresses gave no query at all; the CPU side-channel rule marked 4 of its 13 CVEs as not
loggable and called the other 9 "below the EPSS line"; Claude wrote all sample logs in one script and a safety
classifier stopped it, so no rule was tested; guard.json's shape was guessed; the approval rows ran the rule name
into its source and said "the rest need a ticket" when none did. The key hooks blocked `ls -la .env` (it reads no
key) and let `echo "${!v}"` through (it prints one)."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(".claude/hooks").resolve()))
import guardrails  # noqa: E402

from exception_guardian.assets import parse_assets
from exception_guardian.config import ExposureConfig
from exception_guardian.exposure import apply_exposure
from exception_guardian.guard.convert import convert_rule
from exception_guardian.guard.logtest import score_rule
from exception_guardian.guard import run as guard_run
from exception_guardian.guard.samples import write_briefs
from exception_guardian.html_report import _plan, render_html


# --- key hooks ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "ls -la .env 2>&1",
    "ls .env",
    "stat .env",
    'for v in TENABLE_ACCESS_KEY TENABLE_SECRET_KEY; do [ -n "${!v}" ] && echo "$v set" || echo "$v unset"; done; '
    "ls -la .env 2>&1",
    "ls .env placeholders.local.yaml 2>&1; ls out 2>&1",   # a later live run
    "ls -la guardian.live.yaml .env",
])
def test_checking_that_a_key_exists_is_not_blocked(cmd):
    assert guardrails.check("Bash", {"command": cmd}) is None, cmd


@pytest.mark.parametrize("cmd", [
    'v=TENABLE_SECRET_KEY; echo "${!v}"',
    'for v in TENABLE_SECRET_KEY; do printf %s "${!v}"; done',
    "ls -la .env && cat .env",
    "ls .env | xargs cat",
    "stat .env; head .env",
    "ls .env placeholders.local.yaml | xargs cat",
    "ls .env $(cat .env)",
])
def test_reading_a_key_stays_blocked(cmd):
    assert guardrails.check("Bash", {"command": cmd}), cmd


# --- exposure ----------------------------------------------------------------------------------------------------

def test_the_exposure_warning_counts_public_ips_and_points_at_step_1b():
    assets = parse_assets([{"id": "a1", "hostname": ["web1"], "ipv4": ["8.8.4.4"]},
                           {"id": "a2", "hostname": ["db1"], "ipv4": ["10.0.0.5"]}])
    _, notes = apply_exposure(assets, ExposureConfig())
    text = " ".join(notes)
    assert "1 asset has a public IP" in text and "exposure-candidates.json" in text and "Step 1b" in text


def test_eg_run_asks_about_mapping_exposure_instead_of_skipping_it():
    text = Path(".claude/commands/eg-run.md").read_text()
    assert "Step 1b" in text and "ask" in text.lower() and "without stopping to ask" not in text


# --- placeholders in a filter ------------------------------------------------------------------------------------

DEAD = Path("src/exception_guardian/data/sigmahq/win_security_dc_machine_account_logon_non_dc_ip.yml").read_text()


def test_an_unset_filter_placeholder_still_gives_a_query_that_says_it_is_noisy():
    out = convert_rule(DEAD, ("splunk", "sentinel"))
    for t in ("splunk", "sentinel"):
        assert out[t].ok, (t, out[t].error)
        assert "SET_dc_ip_addresses" in out[t].query
        assert "%dc_ip_addresses%" in out[t].note and "excludes nothing" in out[t].note


def test_the_log_test_runs_on_a_rule_with_an_unset_filter_placeholder():
    ev = {"_logsource": "windows/security", "_label": "attack", "_attack": ["CVE-2020-1472"], "EventID": 4624,
          "TargetUserName": "DC01$", "IpAddress": "192.0.2.9", "LogonType": 3}
    res = score_rule(DEAD, [ev], ("CVE-2020-1472",), any_attack=True)
    assert res["tested"] is True, res


# --- CVEs no log can show ----------------------------------------------------------------------------------------

def _guard_entry():
    return {"rules": [], "conversions": {}, "dropped": [], "missing_drafts": [], "no_valid_draft": [],
            "not_drafted": ["CVE-2018-12126", "CVE-2018-12127", "CVE-2019-11135"],
            "not_loggable": [{"cve": "CVE-2017-5715", "reason": "CPU side channel: writes no log"}],
            "needs_samples": [], "coverage_gaps": []}


def test_guard_asks_to_check_the_other_cves_of_an_exception_with_unloggable_ones():
    notes = guard_run.other_cves_notes("a1b2c3d4", _guard_entry())
    assert notes and "CVE-2018-12126" in notes[0] and "not-loggable.json" in notes[0]


def test_no_such_ask_without_unloggable_cves():
    e = _guard_entry()
    e["not_loggable"] = []
    assert guard_run.other_cves_notes("x", e) == []


def test_the_page_names_the_cves_that_got_no_rule(tmp_path):
    f = {"exception": {"source": "tenable-vm", "rule_id": "a1b2c3d4", "rule_type": "accept", "name": "blanket",
                       "cves": ["CVE-2017-5715", "CVE-2018-12126", "CVE-2018-12127", "CVE-2019-11135"],
                       "plugin_ids": [], "targets": ["*"], "created": "2026-11-03", "expires": None,
                       "justification": "", "status": "enabled", "revised_findings": 7, "owner": None},
         "grade": "REVOKE", "triggers": [{"code": "EPSS_HIGH", "grade": "REVOKE", "then": None, "now": "x",
                                          "source": "s"}], "assets": [], "intel": [], "notes": []}
    (tmp_path / "findings.json").write_text(json.dumps({"today": "2026-11-04", "partial": False, "warnings": [],
                                                        "findings": [f]}))
    (tmp_path / "guard.json").write_text(json.dumps({"a1b2c3d4": _guard_entry()}))
    page = render_html(tmp_path)
    assert "CVE-2018-12126" in page.split("other CVEs")[1][:600]


# --- sample logs and the guard skill -----------------------------------------------------------------------------

def test_sample_briefs_ask_for_one_log_per_write_and_log_fields_only(tmp_path):
    write_briefs(tmp_path, {"windows/security": {"cves": {"CVE-2020-1472"}, "fields": ["EventID"]}})
    brief = (tmp_path / "sample-briefs" / "windows-security.md").read_text()
    assert "this file only" in brief and "Write tool" in brief
    assert "what the log records" in brief


def test_guard_skill_describes_guard_json_and_how_to_write_samples():
    skill = Path("skills/exception-guardian-guard/SKILL.md").read_text()
    assert "keyed by" in skill and "rule id" in skill
    assert "one log at a time" in skill
    assert "other CVEs" in skill and "same kind" in skill


# --- approval plan on the page -----------------------------------------------------------------------------------

def _rev(rid, source="tenable-vm"):
    return {"exception": {"source": source, "rule_id": rid, "rule_type": "accept", "name": "Accepting CVE-2021-34527",
                          "cves": [], "targets": [], "revised_findings": 1}, "grade": "REVOKE"}


def test_plan_rows_keep_the_source_apart_from_the_name():
    html = _plan(Path("out/live"), [_rev("r1")])
    assert "Accepting CVE-2021-34527 tenable-vm" not in html
    assert '<span class="src">tenable-vm</span>' in html


def test_plan_says_no_ticket_when_every_rule_is_auto():
    assert "The rest need a ticket" not in _plan(Path("out/live"), [_rev("r1")])
    assert "need a ticket" in _plan(Path("out/live"), [_rev("r1"), _rev("r2", "tenable-sc")])


def test_the_stand_in_warning_shows_on_the_rule_card_not_only_inside_the_query(tmp_path):
    from exception_guardian.html_report import _hunt
    note = ("%dc_ip_addresses% is not set, so the filter uses the stand-in SET_dc_ip_addresses and excludes nothing: "
            "expect the events it was meant to drop too. Set it under placeholders: in the config to cut them.")
    conv = {t: {"ok": True, "file": f"r.{t}.txt", "error": None, "note": note} for t in ("splunk", "sentinel")}
    rule = {"file": "r.yml", "origin": "sigmahq", "title": "DC Machine Account Logon", "url": None, "tested": {},
            "conversions": conv}
    f = {"exception": {"source": "tenable-vm", "rule_id": "R1", "rule_type": "accept", "name": "x", "cves": [],
                       "targets": []}, "grade": "REVOKE", "triggers": []}
    html = _hunt(tmp_path, {"R1": {"rules": [rule]}}, [f])
    card = html.split('<div class="targets">')[0]
    assert "excludes nothing" in card and card.count("excludes nothing") == 1


def test_exposure_guide_says_the_cli_reads_the_shodan_key_itself():
    """Second isolated run: Claude tried `grep -q SHODAN_API_KEY .env` (rightly blocked) to see if it could claim."""
    text = Path("references/exposure.md").read_text()
    assert "reads `SHODAN_API_KEY` from `.env` itself" in text and "never check" in text.lower()


def test_find_takes_the_run_s_exposure_evidence_without_a_config_edit(tmp_path):
    """/eg-run runs a fresh clone's committed config, so the evidence from Step 1b must reach find by flag."""
    from exception_guardian.cli import main
    r0 = tmp_path / "r0"
    assert main(["find", "--offline", "--out", str(r0), "--today", "2026-11-02"]) == 0
    d = json.loads((r0 / "findings.json").read_text())
    ftp = next(a for f in d["findings"] for a in f["assets"] if a["name"] == "ftp-01")
    ev = tmp_path / "exposure-evidence.json"
    ev.write_text(json.dumps({"verified": [{"asset_id": ftp["id"], "kind": "seen_open", "value": "192.0.2.30",
                                            "evidence": "seen open from the internet on 2026-10-30: ports 21 "
                                                        "(agent-found, verified 2026-11-02)"}], "rejected": []}))
    r1 = tmp_path / "r1"
    assert main(["find", "--offline", "--out", str(r1), "--today", "2026-11-02", "--exposure-claims", str(ev)]) == 0
    d = json.loads((r1 / "findings.json").read_text())
    assert any(t["code"] == "INTERNET_FACING" and "agent-found, verified" in t["source"]
               for f in d["findings"] for t in f["triggers"])


def test_eg_run_reruns_find_with_verified_exposure_evidence_before_guard():
    text = Path(".claude/commands/eg-run.md").read_text()
    assert "--exposure-claims" in text and "before guard" in text
    assert "--exposure-claims" in Path("SKILL.md").read_text()
    assert "--exposure-claims" in Path("references/exposure.md").read_text()


# --- KQL for logs with no ASIM table ------------------------------------------------------------------------------
# Second isolated run (4 Nov 2026): the reader found "no query" for Sentinel and Defender on the PrintNightmare
# antivirus and image-load rules. Both products do have those events, in Defender XDR's Device* tables.

SIGMAHQ = Path("src/exception_guardian/data/sigmahq")


def _rule(name):
    return (SIGMAHQ / name).read_text()


def test_antivirus_rules_query_defender_antivirus_detections():
    out = convert_rule(_rule("av_exploit_cve_2021_34527_print_nightmare.yml"), ("defender", "sentinel"))
    for t in ("defender", "sentinel"):
        assert out[t].ok, (t, out[t].error)
        q = out[t].query
        assert q.startswith("DeviceEvents") and 'ActionType =~ "AntivirusDetection"' in q and "FolderPath" in q, q
        assert 'not(* has "File submitted to Symantec")' in q and 'not("' not in q, q
    assert "Defender XDR connector" in out["sentinel"].note


def test_sentinel_uses_defender_tables_when_asim_has_none():
    out = convert_rule(_rule("image_load_exploit_cve_2021_1675_spoolsv_dll_load.yml"), ("sentinel",))
    assert out["sentinel"].ok, out["sentinel"].error
    assert out["sentinel"].query.startswith("DeviceImageLoadEvents")
    assert "DeviceImageLoadEvents" in out["sentinel"].note and "Defender XDR connector" in out["sentinel"].note


@pytest.mark.parametrize("name", ["rpc_firewall_printing_lateral_movement.yml",
                                  "zeek_dce_rpc_exploit_cve_2021_1675_printnightmare_print_driver_install.yml"])
def test_logs_neither_product_stores_still_say_so(name):
    out = convert_rule(_rule(name), ("defender", "sentinel"))
    assert not out["defender"].ok and not out["sentinel"].ok
    assert "has no table" in out["sentinel"].error


# --- an internet tag the config does not list ---------------------------------------------------------------------

def test_the_warning_names_an_internet_tag_the_config_does_not_list():
    """Second isolated run: the tenant tags its host Exposure:Internet, but the live config named no tag."""
    assets = parse_assets([{"id": "a1", "hostname": ["web1"], "ipv4": ["10.0.0.4"],
                            "tags": [{"tag_key": "Exposure", "tag_value": "Internet"}]},
                           {"id": "a2", "hostname": ["db1"], "ipv4": ["10.0.0.5"]}])
    _, notes = apply_exposure(assets, ExposureConfig())
    text = " ".join(notes)
    assert "Exposure:Internet" in text and "exposure.internet_tags" in text and "1 asset" in text


def test_the_live_config_lists_the_lab_s_internet_tag():
    import yaml
    cfg = yaml.safe_load(Path("guardian.live.yaml").read_text())
    assert "Exposure:Internet" in cfg["exposure"]["internet_tags"]


# --- placeholder values kept out of the repo ----------------------------------------------------------------------

def test_placeholder_values_can_come_from_a_git_ignored_file(tmp_path):
    """The DC addresses are the user's, not the repo's: the tracked config points at a local file."""
    from exception_guardian.config import load_config
    (tmp_path / "placeholders.local.yaml").write_text("dc_ip_addresses: [192.0.2.10]\nDC-MACHINE-NAME: DC1$\n")
    (tmp_path / "g.yaml").write_text("placeholders:\n  known_cdcs: [CA1$]\n  DC-MACHINE-NAME: [OLD$]\n"
                                     "placeholders_file: placeholders.local.yaml\n")
    ph = load_config(tmp_path / "g.yaml").placeholders
    assert ph == {"known_cdcs": ("CA1$",), "DC-MACHINE-NAME": ("DC1$",), "dc_ip_addresses": ("192.0.2.10",)}


def test_a_missing_placeholders_file_leaves_the_stand_ins(tmp_path):
    from exception_guardian.config import load_config
    (tmp_path / "g.yaml").write_text("placeholders_file: placeholders.local.yaml\n")
    assert load_config(tmp_path / "g.yaml").placeholders == {}


def test_local_placeholder_files_are_git_ignored_and_the_live_config_uses_one():
    import subprocess
    import yaml
    assert subprocess.run(["git", "check-ignore", "-q", "placeholders.local.yaml"]).returncode == 0
    assert yaml.safe_load(Path("guardian.live.yaml").read_text())["placeholders_file"] == "placeholders.local.yaml"


def test_guard_uses_the_config_find_ran_with(tmp_path, monkeypatch):
    """Second isolated run: guard ran without --config and read the sample guardian.yaml, not the live config."""
    import shutil
    from exception_guardian import cli
    cfg = tmp_path / "mine.yaml"
    shutil.copy("guardian.yaml", cfg)
    cfg.write_text(cfg.read_text().replace("samples/", str(Path("samples").resolve()) + "/"))
    run = tmp_path / "r"
    assert cli.main(["find", "--offline", "--config", str(cfg), "--out", str(run), "--today", "2026-11-02"]) == 0
    assert json.loads((run / "findings.json").read_text())["config"] == str(cfg.resolve())
    seen = []
    real = cli.load_config
    monkeypatch.setattr(cli, "load_config", lambda p: seen.append(str(p)) or real(p))
    cli.main(["guard", "--run", str(run)])
    assert seen == [str(cfg.resolve())]


# --- the exposure warning is decided once, over every asset list ---------------------------------------------------

def test_no_exposure_warning_once_any_asset_is_internet_facing():
    """Third isolated run: INTERNET_FACING fired on web-host-01 (tag Exposure:Internet), yet the page still said no
    asset is marked internet-facing: one asset list (SC hosts, untagged) had none."""
    from dataclasses import replace as _r
    from exception_guardian.exposure import NO_EXPOSURE_NOTE
    from exception_guardian.find import drop_stale_exposure_notes
    vm = parse_assets([{"id": "a1", "hostname": ["web1"], "ipv4": ["8.8.4.4"]}])
    vm = [_r(vm[0], internet_facing=True, exposure_reason="tag Exposure:Internet")]
    sc = parse_assets([{"id": "s1", "hostname": ["db1"], "ipv4": ["10.0.0.5"]}])
    warnings = ["source x failed: y", NO_EXPOSURE_NOTE,
                "exposure: 13 assets have a public IP. `exposure-candidates.json` in this run lists every asset",
                "exposure: 2 assets carry the tag Zone:External, which reads like an internet tag."]
    assert drop_stale_exposure_notes(warnings, vm, sc) == ["source x failed: y"]
    assert drop_stale_exposure_notes(warnings, sc) == warnings


def test_a_generic_rule_is_not_called_weak_for_missing_other_cves_attacks():
    """Third isolated run: the web-shell rule (generic) showed "Catches some" at 1/15: the 15 were attacks of other
    CVEs, which it is not meant to catch."""
    from exception_guardian.html_report import _tested
    t = {"tested": True, "attack_hits": 1, "attack_total": 15, "benign_hits": 0, "benign_total": 15,
         "benign_hit_notes": [], "attack_scope": "any CVE", "agent_events": 40,
         "attack_missed_notes": ["IE spawned a shell"]}
    html = _tested(t)
    assert "Catches some" not in html and "Misses all" not in html
    assert "Fires on 1 attack sample" in html and "what any exploit does next" in html
    t0 = {**t, "attack_hits": 0}
    assert "Misses all" not in _tested(t0) and "Fired on no attack sample" in _tested(t0)


def test_preflight_says_not_to_check_the_keys():
    """A live run looped over the key names with [ -n "${!v}" ] and saw every one unset: the keys sit in .env (or the file
    EG_ENV_FILE names), which only exception-guardian reads."""
    pre = Path("SKILL.md").read_text().split("Preflight", 1)[1].split("\n## Step 1", 1)[0].lower()
    assert "never check whether a key is set" in pre.replace("\n", " ")
    assert "find says so itself" in pre.replace("\n", " ")


def test_step_1_says_find_can_outlast_a_short_timeout():
    """A live run: find read asset context for a large asset list at about 160 a minute and Claude gave it a 5-minute limit."""
    step1 = Path("SKILL.md").read_text().split("## Step 1:", 1)[1].split("\n## ", 1)[0].replace("\n", " ")
    assert "10 minutes" in step1 and "background" in step1
