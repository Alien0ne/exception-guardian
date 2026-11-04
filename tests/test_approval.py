import subprocess
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest
import requests

from exception_guardian.approval import apply, write_plan
from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.mock_tenable import serve
from exception_guardian.readers import get_reader
from exception_guardian.tenable_client import TenableVMClient


@pytest.fixture
def mock(tmp_path):
    srv, url = serve(Path("samples/tenable_vm"))
    yield TenableVMClient(url, "a", "s")
    srv.shutdown()


def _find(tmp_path):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))


def test_plan_lists_revokes(tmp_path):
    _find(tmp_path)
    md = write_plan(tmp_path).read_text()
    assert "R-HERO-001" in md and "EXCL-001" in md and "manual" in md and "R-OK-004" not in md
    assert "Revoke risk exception R-HERO-001" in md  # ticket text


def test_apply_yes_disables_and_verifies(tmp_path, mock):
    _find(tmp_path)
    diffs = []
    out = apply(tmp_path, mock, confirm=lambda diff: diffs.append(diff) or "R-HERO-001" in diff)
    res = {o["rule_id"]: o["result"] for o in out}
    assert res["R-HERO-001"] == "disabled (verified)" and res["R-RAY-002"] == "declined"
    assert "EXCL-001" not in res and "CSV-Q-201" not in res  # manual only
    assert mock.get_rule("R-HERO-001")["status"] in ("disabled", "DISABLED")
    assert any("status: enabled -> disabled" in d for d in diffs)
    log = (tmp_path / "applied-changes.log").read_text()
    assert "R-HERO-001 disabled (verified)" in log and "R-RAY-002 declined" in log


def test_apply_already_disabled_no_write(tmp_path, mock):
    _find(tmp_path)
    apply(tmp_path, mock, confirm=lambda d: True)
    again = {o["rule_id"]: o["result"] for o in apply(tmp_path, mock, confirm=lambda d: pytest.fail("asked twice"))}
    assert again["R-HERO-001"] == "already disabled"


def test_disable_keeps_rule_content(mock):
    before = mock.get_rule("R-HERO-001")
    mock.disable_rule("R-HERO-001")
    after = mock.get_rule("R-HERO-001")
    assert after["filter"] == before["filter"] and after["rule_value"] == before["rule_value"]
    assert after["disabled_details"]["disabled"] is True


def test_vm_reader_live_via_mock(mock, monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "a"); monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    ex = get_reader("tenable-vm")({"base_url": mock.base_url})
    assert "R-HERO-001" in {e.rule_id for e in ex} and "EXCL-001" in {e.rule_id for e in ex}


def test_assets_live_via_mock(mock, monkeypatch):
    from exception_guardian.assets import load_assets
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "a"); monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    assert "web-portal-01" in {a.name for a in load_assets({"base_url": mock.base_url})}


def test_search_paginates(mock):
    mock.page_size = 3
    assert len(mock.search_rules()) == 8


def test_mock_rejects_missing_api_keys(mock):
    r = requests.get(mock.base_url + "/v1/recast/rules/R-HERO-001", timeout=5)
    assert r.status_code == 401


def test_from_env_names_missing_var(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False); monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    with pytest.raises(RuntimeError, match="TENABLE_ACCESS_KEY"):
        TenableVMClient.from_env("http://x.example")


def test_retries_then_succeeds(monkeypatch):
    calls, sleeps = [], []

    class R:
        def __init__(self, code): self.status_code = code
        def raise_for_status(self):
            if self.status_code >= 400: raise requests.HTTPError(str(self.status_code))
        def json(self): return {"rule_id": "X"}

    seq = [429, 503, 200]
    c = TenableVMClient("http://x.example", "a", "s", sleep=sleeps.append)
    monkeypatch.setattr(c.session, "request", lambda *a, **k: calls.append(a) or R(seq.pop(0)))
    assert c.get_rule("X")["rule_id"] == "X" and sleeps == [1, 2] and len(calls) == 3


def test_cli_apply_refuses_without_tty(tmp_path):
    _find(tmp_path)
    exe = Path(sys.executable).parent / "exception-guardian"
    r = subprocess.run([str(exe), "approve", "--run", str(tmp_path), "--apply", "--base-url", "http://127.0.0.1:9"],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert r.returncode != 0 and "TTY" in r.stderr


def test_cli_plan(tmp_path):
    _find(tmp_path)
    exe = Path(sys.executable).parent / "exception-guardian"
    r = subprocess.run([str(exe), "approve", "--run", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 0 and (tmp_path / "approval-plan.md").exists()


def test_plan_singular_finding(tmp_path):
    _find(tmp_path)
    md = write_plan(tmp_path).read_text()
    assert "1 findings" not in md and "re-surfaces: 1 finding" in md


def test_ticket_uses_run_date(tmp_path):
    _find(tmp_path)
    assert "graded REVOKE by Exception Guardian on 2026-11-02" in write_plan(tmp_path).read_text()


def test_apply_log_and_rule_name_the_person(tmp_path, mock, monkeypatch):
    _find(tmp_path)
    reasons = []
    real = mock.disable_rule
    monkeypatch.setattr(mock, "disable_rule", lambda rid, reason="", expected=None: reasons.append(reason) or real(rid, reason, expected))
    apply(tmp_path, mock, confirm=lambda d: "R-HERO-001" in d, operator="analyst.a")
    log = (tmp_path / "applied-changes.log").read_text()
    assert "R-HERO-001 disabled (verified) by analyst.a" in log and "R-RAY-002 declined by analyst.a" in log
    # the run folder, never a home path: this text is stored in Tenable
    assert reasons == [f"revoked via Exception Guardian by analyst.a (plan {tmp_path.name}/approval-plan.md)"]


def test_apply_log_keeps_one_line_per_rule(tmp_path, mock):
    """Review of src, 4 Nov 2026: the audit log wrote the rule id raw, so an id holding a line break could add a
    forged line such as '... R-X disabled (verified) by admin' to applied-changes.log."""
    import json
    _find(tmp_path)
    p = tmp_path / "findings.json"
    data = json.loads(p.read_text())
    hero = next(f for f in data["findings"] if f["exception"]["rule_id"] == "R-HERO-001")
    hero["exception"]["rule_id"] = "R-HERO-001\n2026-11-04T00:00:00+00:00 R-FAKE disabled (verified) by admin"
    p.write_text(json.dumps(data))
    out = apply(tmp_path, mock, confirm=lambda d: False, operator="analyst.a")
    lines = (tmp_path / "applied-changes.log").read_text().splitlines()
    assert len(lines) == len(out)
    assert not any(line.split(" ", 1)[1].startswith("R-FAKE") for line in lines)
