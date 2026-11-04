import json
from dataclasses import replace
from datetime import date
from pathlib import Path

from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.guard.run import run_guard
from exception_guardian.guard.validate import validate_rule

GOLDEN = Path("samples/golden/drafts")


def _find(tmp_path):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))


def test_golden_drafts_valid():
    files = sorted(GOLDEN.glob("*.yml"))
    assert [f.name for f in files] == ["CVE-2025-54068-web.yml", "CVE-2025-54068.yml", "CVE-2025-62593.yml"]
    for f in files:
        assert validate_rule(f.read_text(), drafted=True) == [], f


def test_guard_on_sample_run(tmp_path):
    _find(tmp_path)
    g = run_guard(tmp_path, GOLDEN, load_config("guardian.yaml"))
    hero = g["R-HERO-001"]
    assert any(r["origin"] == "drafted" for r in hero["rules"]) and hero["missing_drafts"] == []
    assert any(r["origin"] == "generic" for r in hero["rules"])
    assert (tmp_path / "rules/R-HERO-001/CVE-2025-54068.splunk.txt").exists()
    assert (tmp_path / "rules/R-HERO-001/CVE-2025-54068.sentinel.txt").exists()
    web = next(r for r in hero["rules"] if r["file"] == "CVE-2025-54068-web.yml")
    assert web["conversions"]["splunk"]["ok"] and not web["conversions"]["defender"]["ok"]
    assert any(r["origin"] == "sigmahq" for r in g["R-CRUSH-003"]["rules"])
    assert "R-OK-004" not in g
    assert json.loads((tmp_path / "guard.json").read_text()) == g
    assert (tmp_path / "handoff-guard.md").exists()


def test_invalid_draft_dropped(tmp_path):
    _find(tmp_path)
    d = tmp_path / "drafts"; d.mkdir()
    (d / "CVE-2025-54068.yml").write_text("title: [broken")
    g = run_guard(tmp_path, d, load_config("guardian.yaml"))
    assert g["R-HERO-001"]["dropped"] and not (tmp_path / "rules/R-HERO-001/CVE-2025-54068.yml").exists()
    assert "CVE-2025-54068" in g["R-HERO-001"]["missing_drafts"]


def test_missing_draft_reported(tmp_path):
    _find(tmp_path)
    g = run_guard(tmp_path, tmp_path / "nodrafts", load_config("guardian.yaml"))
    assert "CVE-2025-54068" in g["R-HERO-001"]["missing_drafts"]
    assert "CVE-2025-31161" not in g["R-CRUSH-003"]["missing_drafts"]


def test_hunt_brief_window_and_escaping(tmp_path):
    _find(tmp_path)
    run_guard(tmp_path, GOLDEN, load_config("guardian.yaml"))
    brief = (tmp_path / "hunt-briefs/R-INJECT-007.md").read_text()
    assert "2026-04-01" in brief and "2026-11-02" in brief and "<script>" not in brief
    assert "CVE-2025-54068.splunk.txt" in brief


def test_rule_id_cannot_escape_run_dir(tmp_path):
    _find(tmp_path)
    data = json.loads((tmp_path / "findings.json").read_text())
    data["findings"][0]["exception"]["rule_id"] = "../../evil"
    (tmp_path / "findings.json").write_text(json.dumps(data))
    run_guard(tmp_path, GOLDEN, load_config("guardian.yaml"))
    assert not (tmp_path.parent / "evil").exists()
    assert all(p.resolve().is_relative_to(tmp_path.resolve()) for p in tmp_path.rglob("*"))


def test_hunt_brief_links_intact_and_errors_short(tmp_path):
    _find(tmp_path)
    run_guard(tmp_path, GOLDEN, load_config("guardian.yaml"))
    brief = (tmp_path / "hunt-briefs/R-HERO-001.md").read_text()
    assert "rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml" in brief
    unsupported = [l for l in brief.splitlines() if "unsupported:" in l]
    assert unsupported and all(len(l) <= 120 for l in unsupported)


def test_drafted_rules_labelled_untested_without_sample_logs(tmp_path):
    _find(tmp_path)
    run_guard(tmp_path, GOLDEN, replace(load_config("guardian.yaml"), sample_logs_dir=str(tmp_path / "no-logs")))
    brief = (tmp_path / "hunt-briefs/R-HERO-001.md").read_text()
    assert "drafted — validated for syntax and conversion, not tested against logs" in brief


def test_all_drafts_dropped_says_generic_attached(tmp_path):
    _find(tmp_path)
    d = tmp_path / "drafts"; d.mkdir()
    (d / "CVE-2025-54068.yml").write_text("title: [broken")
    run_guard(tmp_path, d, load_config("guardian.yaml"))
    brief = (tmp_path / "hunt-briefs/R-HERO-001.md").read_text()
    handoff = (tmp_path / "handoff-guard.md").read_text()
    for text in (brief, handoff):
        assert "CVE-2025-54068: no valid rule drafted, so generic behaviour rules are attached" in text
