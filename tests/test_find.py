import json
import subprocess
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

from exception_guardian.config import SourceConfig, load_config
from exception_guardian.find import load_findings, run_find
from exception_guardian.models import Grade


def test_find_writes_outputs_and_sorts(tmp_path):
    cfg = replace(load_config("guardian.yaml"), offline=True)
    res = run_find(cfg, tmp_path, date(2026, 11, 2))
    assert res[0].grade is Grade.REVOKE and res[0].exception.rule_id == "R-HERO-001"
    assert [g.grade.rank for g in res] == sorted((g.grade.rank for g in res), reverse=True)
    data = json.loads((tmp_path / "findings.json").read_text())
    assert {f["exception"]["source"] for f in data["findings"]} >= {"tenable-vm", "tenable-sc", "csv:other-scanner"}
    assert data["today"] == "2026-11-02" and any("row 4" in w for w in data["warnings"])
    assert (tmp_path / "report.md").exists() and (tmp_path / "handoff-find.md").exists()
    assert load_findings(tmp_path / "findings.json")[0]["exception"]["rule_id"] == "R-HERO-001"


def test_partial_run_labelled(tmp_path):
    cfg = replace(load_config("guardian.yaml"), offline=True,
                  sources=load_config("guardian.yaml").sources + (SourceConfig("tenable-sc", {"fixture_dir": "nope"}),))
    run_find(cfg, tmp_path, date(2026, 11, 2))
    assert "PARTIAL RUN" in (tmp_path / "report.md").read_text()


def test_cli_find(tmp_path):
    exe = Path(sys.executable).parent / "exception-guardian"
    r = subprocess.run([str(exe), "find", "--config", "guardian.yaml", "--out", str(tmp_path), "--today", "2026-11-02", "--offline"], capture_output=True, text=True)
    assert r.returncode == 0 and "REVOKE" in r.stdout and "report.md" in r.stdout
