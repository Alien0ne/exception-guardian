"""approve --undo re-enables what apply disabled. Before this the only way back was the Tenable UI (the live run,
4 Nov 2026, needed a manual switch-back), so "nothing is lost" depended on a person finding the rule by hand."""
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from exception_guardian.approval import apply, undo
from exception_guardian.cli import main
from exception_guardian.config import load_config
from exception_guardian.find import run_find
from exception_guardian.mock_tenable import serve
from exception_guardian.tenable_client import TenableVMClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".claude" / "hooks"))
import block_apply  # noqa: E402


@pytest.fixture
def mock():
    srv, url = serve(Path("samples/tenable_vm"))
    yield TenableVMClient(url, "a", "s")
    srv.shutdown()


@pytest.fixture
def applied(tmp_path, mock):
    """A run where apply disabled R-HERO-001 and the person declined the rest."""
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    apply(tmp_path, mock, confirm=lambda d: "R-HERO-001" in d, operator="alice")
    assert mock.get_rule("R-HERO-001")["status"] == "disabled"
    return tmp_path


def test_undo_re_enables_and_verifies(applied, mock):
    asked = []
    out = undo(applied, mock, confirm=lambda d: asked.append(d) or True, operator="alice")
    assert out == [{"rule_id": "R-HERO-001", "result": "re-enabled (verified)"}]
    assert mock.get_rule("R-HERO-001")["status"] == "enabled"
    assert "status: disabled -> enabled" in asked[0] and "hides again" in asked[0]
    assert "R-HERO-001 re-enabled (verified) by alice" in (applied / "applied-changes.log").read_text()


def test_undo_keeps_rule_content(applied, mock):
    before = mock.get_rule("R-HERO-001")
    undo(applied, mock, confirm=lambda d: True)
    after = mock.get_rule("R-HERO-001")
    assert after["filter"] == before["filter"] and after["rule_value"] == before["rule_value"]


def test_undo_offers_only_rules_this_run_disabled(applied, mock):
    """R-RAY-002 was declined at apply; someone then disabled it in Tenable for their own reason."""
    mock.disable_rule("R-RAY-002", reason="disabled by the owner")
    out = undo(applied, mock, confirm=lambda d: True)
    assert [o["rule_id"] for o in out] == ["R-HERO-001"]
    assert mock.get_rule("R-RAY-002")["status"] == "disabled"


def test_undo_declined_changes_nothing(applied, mock):
    out = undo(applied, mock, confirm=lambda d: False)
    assert out == [{"rule_id": "R-HERO-001", "result": "undo declined"}]
    assert mock.get_rule("R-HERO-001")["status"] == "disabled"


def test_undo_twice_asks_once(applied, mock):
    undo(applied, mock, confirm=lambda d: True)
    assert undo(applied, mock, confirm=lambda d: pytest.fail("asked twice")) == []


def test_undo_skips_a_rule_already_enabled_by_someone(applied, mock):
    mock.enable_rule("R-HERO-001")
    out = undo(applied, mock, confirm=lambda d: pytest.fail("nothing to ask"))
    assert out == [{"rule_id": "R-HERO-001", "result": "already enabled"}]


def test_undo_skips_a_rule_that_changed_since_the_run(applied, mock):
    rule = mock._call("GET", "/v1/recast/rules/R-HERO-001")
    body = {k: rule[k] for k in ("resource_type", "rule_value", "filter", "rule_name") if rule.get(k) is not None}
    mock._call("PUT", "/v1/recast/rules/R-HERO-001", json={**body, "expires_at": "2030-01-01T00:00:00Z",
                                                            "disabled_details": rule["disabled_details"]})
    out = undo(applied, mock, confirm=lambda d: pytest.fail("must not offer a changed rule"))
    assert out[0]["result"].startswith("skipped: the live rule changed")


def test_undo_skips_a_rule_someone_else_disabled_again(applied, mock):
    """Re-enabled by hand, then disabled by another person: that second decision is not ours to reverse."""
    mock.enable_rule("R-HERO-001")
    mock.disable_rule("R-HERO-001", reason="owner retired it")
    out = undo(applied, mock, confirm=lambda d: pytest.fail("not ours"))
    assert out[0]["result"].startswith("skipped: it was not disabled by Exception Guardian")


def test_nothing_to_undo_without_a_log(tmp_path, mock):
    run_find(replace(load_config("guardian.yaml"), offline=True), tmp_path, date(2026, 11, 2))
    assert undo(tmp_path, mock, confirm=lambda d: pytest.fail("no log")) == []


@pytest.mark.parametrize("var", ["CLAUDECODE", "EG_HARNESS"])
def test_undo_refuses_in_an_agent_session(applied, mock, monkeypatch, var):
    monkeypatch.setenv(var, "1")
    with pytest.raises(RuntimeError, match="agent session"):
        undo(applied, mock, confirm=lambda d: True)
    assert mock.get_rule("R-HERO-001")["status"] == "disabled"


def test_cli_undo_refuses_in_an_agent_shell(applied, monkeypatch, capsys):
    monkeypatch.setenv("CLAUDECODE", "1")
    assert main(["approve", "--run", str(applied), "--undo", "--base-url", "http://x.example"]) == 2
    assert "refusing --undo" in capsys.readouterr().err


def test_cli_undo_needs_a_terminal(applied, capsys):
    assert main(["approve", "--run", str(applied), "--undo", "--base-url", "http://x.example"]) == 2
    assert "interactive" in capsys.readouterr().err


def test_cli_apply_and_undo_together_is_refused(applied, capsys):
    with pytest.raises(SystemExit):
        main(["approve", "--run", str(applied), "--apply", "--undo", "--base-url", "http://x.example"])


@pytest.mark.parametrize("cmd", [
    "exception-guardian approve --run out --undo --base-url https://cloud.tenable.com",
    "exception-guardian approve --undo --run out",
    "U=--undo; exception-guardian approve --run out $U",
    "exception-guardian approve --run o --un$(echo do)",
    "python3 -c 'from exception_guardian.approval import undo; undo(\"o\", c, lambda d: True)'",
    "python3 -c \"from exception_guardian.cli import main; main(['approve','--run','o','--undo'])\"",
])
def test_hook_blocks_undo_like_apply(cmd):
    assert block_apply.blocked(cmd)


@pytest.mark.parametrize("cmd", ["exception-guardian approve --run out", "exception-guardian find --config g.yaml",
                                 "git commit -m 'undo the change'"])
def test_hook_still_lets_ordinary_commands_run(cmd):
    assert not block_apply.blocked(cmd)
