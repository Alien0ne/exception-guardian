"""Hardcoded-values sweep (4 Nov 2026): values that ignored the company's own config or the run's own data."""
import json
from datetime import date
from pathlib import Path

import pytest

from exception_guardian.assets import parse_assets
from exception_guardian.cli import main
from exception_guardian.config import Config, ExposureConfig, load_config
from exception_guardian.intel import build_intel

CVES = {"CVE-2021-44228": [date(2026, 1, 5)]}


def _fetch(url):
    if "known_exploited" in url:
        return {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}
    return {"data": [{"cve": "CVE-2021-44228", "epss": "0.94", "date": "2026-11-03"}]}


def test_an_online_run_needs_no_snapshot_folder(tmp_path):
    cfg = Config(intel_snapshot_dir=str(tmp_path / "none"))
    intel, warnings = build_intel(CVES, cfg, fetch=_fetch)
    assert intel[("CVE-2021-44228", date(2026, 1, 5))].in_kev and warnings == []


def test_a_failed_fetch_without_a_snapshot_says_there_is_none(tmp_path):
    def down(url):
        raise ConnectionError("no route")
    _, warnings = build_intel(CVES, Config(intel_snapshot_dir=str(tmp_path / "none")), fetch=down)
    assert any("no snapshot" in w for w in warnings)


def test_offline_without_a_snapshot_is_a_clear_error(tmp_path):
    with pytest.raises(ValueError, match="intel_snapshot_dir"):
        build_intel(CVES, Config(offline=True, intel_snapshot_dir=str(tmp_path / "none")))


def test_the_asset_parser_does_not_decide_exposure_from_a_fixed_tag():
    a = parse_assets([{"id": "a", "hostname": ["h"], "tags": [{"tag_key": "Exposure", "tag_value": "Internet"}]}])[0]
    assert not a.internet_facing and a.exposure_reason == ""


def test_no_internet_tag_is_assumed_by_default(tmp_path):
    assert ExposureConfig().internet_tags == ()
    p = tmp_path / "g.yaml"
    p.write_text("sources: [{name: csv, path: x.csv}]\n")
    assert load_config(p).sample_logs_dir == ""


def _demo(tmp_path):
    run = tmp_path / "demo"
    assert main(["demo", "--out", str(run)]) == 0
    return run


def test_the_apply_command_in_the_report_uses_the_configured_url(tmp_path):
    run = _demo(tmp_path)
    page = (run / "report.html").read_text()
    assert "https://cloud.tenable.com" not in page and "--base-url &lt;your Tenable VM URL&gt;" in page
    meta = json.loads((run / "findings.json").read_text())
    meta["tenable_vm_base_url"] = "https://fedcloud.tenable.example"
    (run / "findings.json").write_text(json.dumps(meta))
    assert main(["html", "--run", str(run)]) == 0
    assert "--base-url https://fedcloud.tenable.example" in (run / "report.html").read_text()


def test_assets_not_checked_names_no_source_it_did_not_use():
    from exception_guardian.grading import grade  # noqa: F401
    src = Path("src/exception_guardian/grading.py").read_text()
    assert "the asset list is from Tenable VM" not in src


def test_exposure_checks_use_the_runs_own_date(tmp_path, monkeypatch):
    from exception_guardian import exposure_claims as ec
    run = _demo(tmp_path)
    seen = {}
    monkeypatch.setattr(ec, "verify_claims", lambda c, f, today, **kw: (seen.__setitem__("d", today), ([], [], []))[1])
    (run / "c.json").write_text("[]")
    try:
        ec.run_exposure(run, run / "c.json")
    except Exception:
        pass
    assert seen["d"] == date.fromisoformat(json.loads((run / "findings.json").read_text())["today"])
