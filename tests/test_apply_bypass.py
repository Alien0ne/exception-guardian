"""Code audit (4 Nov 2026): --apply could be reached around the hook by shell expansion, or by importing apply()
from Python, and the CLI's agent check could be dropped with `env -u CLAUDECODE`. Each layer now holds alone."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".claude" / "hooks"))
import block_apply  # noqa: E402

from exception_guardian import approval  # noqa: E402


@pytest.mark.parametrize("cmd", [
    "exception-guardian $(echo approve) --run out --apply",
    "A=--apply; exception-guardian approve --run out $A",
    "cmd=exception-guardian; $cmd approve --run o --apply",
    "exception-guardian `echo approve` --run o --ap",
    "exception-guardian appr$(echo ove) --run o --a$(echo p)ply",
    "yes | script -qc 'env -u CLAUDECODE exception-guardian $(echo approve) --run o --apply' /dev/null",
    "python3 -c \"from exception_guardian.cli import main; main(['approve','--run','o','--apply'])\"",
    "python3 -c 'from exception_guardian.approval import apply; apply(\"o\", c, lambda d: True)'",
    "python3 -c 'import exception_guardian.approval as a; a.apply(\"o\", c, lambda d: True)'",
])
def test_expansion_and_python_routes_to_apply_are_blocked(cmd):
    assert block_apply.blocked(cmd), cmd


@pytest.mark.parametrize("cmd", [
    "env -u CLAUDECODE exception-guardian approve --run o",
    "unset CLAUDECODE; exception-guardian find --out o",
    "CLAUDECODE= exception-guardian approve --run o",
    "env -u EG_HARNESS bash",
    "export EG_HARNESS=",
])
def test_dropping_the_agent_markers_is_blocked(cmd):
    assert block_apply.blocked(cmd), cmd


@pytest.mark.parametrize("cmd", [
    "exception-guardian approve --run out/demo",
    "exception-guardian demo --out out/demo",
    "grep -n apply src/exception_guardian/approval.py",
    "exception-guardian guard --run out/demo --drafts out/demo/drafts",
    "echo $HOME; exception-guardian find --config guardian.yaml --out out/x",
])
def test_ordinary_commands_still_run(cmd):
    assert not block_apply.blocked(cmd), cmd


@pytest.mark.parametrize("var", ["CLAUDECODE", "EG_HARNESS"])
def test_apply_itself_refuses_in_an_agent_session(tmp_path, monkeypatch, var):
    monkeypatch.setenv(var, "1")
    with pytest.raises(RuntimeError, match="agent"):
        approval.apply(tmp_path, client=object(), confirm=lambda d: True)
