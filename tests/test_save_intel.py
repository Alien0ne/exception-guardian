"""An offline run used to grade on the small KEV/EPSS snapshot shipped with the repo, dated 2 Nov 2026. Now an
online run can save the intel it just fetched (`find --save-intel <dir>`), and an offline run pointed at that
folder grades on it: an air-gapped site carries a fresh snapshot in instead of trusting a stale one."""
import json
from dataclasses import replace
from datetime import date
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from exception_guardian import intel as intel_mod
from exception_guardian.cli import main
from exception_guardian.config import Config
from exception_guardian.exploits import load_exploits
from exception_guardian.intel import build_intel, write_snapshot
from exception_guardian.models import CveIntel
from test_exploits import TODAY, _fetch

D = date(2025, 3, 1)
LIVE = {("CVE-2024-0001", D): CveIntel("CVE-2024-0001", True, date(2026, 8, 17), True, 0.91, 0.02, "live"),
        ("CVE-2024-0001", date(2025, 6, 1)): CveIntel("CVE-2024-0001", True, date(2026, 8, 17), True, 0.91, 0.05, "live"),
        ("CVE-2024-0002", D): CveIntel("CVE-2024-0002", False, None, False, None, None, "live"),
        ("CVE-2024-0009", D): CveIntel("CVE-2024-0009", True, date(2026, 1, 1), False, 0.5, 0.1, "snapshot:2026-11-02")}


def test_a_saved_snapshot_gives_an_offline_run_the_same_intel(tmp_path):
    write_snapshot(LIVE, tmp_path, TODAY)
    cfg = Config(offline=True, intel_snapshot_dir=str(tmp_path), exploit_feeds=())
    wanted = {"CVE-2024-0001": [D, date(2025, 6, 1)], "CVE-2024-0002": [D]}
    got, warn = build_intel(wanted, cfg)
    assert warn == []
    for key in wanted and [k for k in LIVE if k[0] != "CVE-2024-0009"]:
        assert replace(got[key], source="live") == LIVE[key], key
        assert got[key].source == "snapshot:2026-11-02"


def test_intel_that_was_itself_from_a_snapshot_is_not_saved_as_fresh(tmp_path):
    write_snapshot(LIVE, tmp_path, TODAY)
    kev = json.loads((tmp_path / "kev.json").read_text())
    assert [v["cveID"] for v in kev["vulnerabilities"]] == ["CVE-2024-0001"]
    assert "CVE-2024-0009" not in json.loads((tmp_path / "epss.json").read_text())["now"]


def test_exploit_entries_are_saved_and_read_back_offline(tmp_path):
    raw = {}
    live, _, _ = load_exploits(["CVE-2024-0001"], Config(intel_cache_dir="off"), TODAY, fetch=_fetch(), raw=raw)
    write_snapshot(LIVE, tmp_path, TODAY, exploits=raw)
    back, where, _ = load_exploits(["CVE-2024-0001"], Config(offline=True, intel_snapshot_dir=str(tmp_path)), TODAY)
    assert back == live and live and where == "snapshot:2026-11-02"
    saved = json.loads((tmp_path / "exploits.json").read_text())["index"]
    assert set(saved) == {"CVE-2024-0001"}  # only the run's CVEs, not the whole feed


def _fake_feeds(monkeypatch):
    kev = json.loads(Path("samples/intel/kev.json").read_text())
    epss = json.loads(Path("samples/intel/epss.json").read_text())

    def get(url):
        if "known_exploited" in url:
            return kev
        q = parse_qs(urlsplit(url).query)
        day = q.get("date", [None])[0]
        rows = [{"cve": c, "epss": str(epss["history"].get(c, {}).get(day) if day else epss["now"].get(c)), "date": day or "2026-11-02"}
                for c in q["cve"][0].split(",")]
        return {"data": [r for r in rows if r["epss"] != "None"]}
    monkeypatch.setattr(intel_mod, "_http_get", get)


def test_find_save_intel_then_an_offline_run_on_it_grades_the_same(tmp_path, monkeypatch, capsys):
    _fake_feeds(monkeypatch)
    snap = tmp_path / "intel"
    assert main(["find", "--config", "guardian.yaml", "--out", str(tmp_path / "a"), "--today", "2026-11-02",
                 "--save-intel", str(snap)]) == 0
    assert "intel snapshot:" in capsys.readouterr().out
    cfg = tmp_path / "g.yaml"
    cfg.write_text(Path("guardian.yaml").read_text().replace("intel_snapshot_dir: samples/intel", f"intel_snapshot_dir: {snap}")
                   .replace("samples/", f"{Path.cwd()}/samples/").replace("maps/", f"{Path.cwd()}/maps/"))
    assert main(["find", "--config", str(cfg), "--out", str(tmp_path / "b"), "--today", "2026-11-02", "--offline"]) == 0
    a, b = (json.loads((tmp_path / x / "findings.json").read_text())["findings"] for x in "ab")
    assert [(f["exception"]["rule_id"], f["grade"], [t["code"] for t in f["triggers"]]) for f in a] == \
           [(f["exception"]["rule_id"], f["grade"], [t["code"] for t in f["triggers"]]) for f in b]
    assert any(t["source"].endswith("(snapshot:2026-11-02)") or "snapshot" in t["source"] for f in b for t in f["triggers"])


def test_save_intel_on_an_offline_run_is_a_usage_error(tmp_path, capsys):
    assert main(["find", "--config", "guardian.yaml", "--out", str(tmp_path / "a"), "--offline",
                 "--save-intel", str(tmp_path / "s")]) == 2
    assert "--save-intel" in capsys.readouterr().err and not (tmp_path / "s").exists()


@pytest.mark.parametrize("name", ["kev.json", "epss.json"])
def test_snapshot_files_are_written_whole(tmp_path, name):
    write_snapshot(LIVE, tmp_path, TODAY)
    assert json.loads((tmp_path / name).read_text())
    assert not list(tmp_path.glob("*.tmp"))
