"""Code audit (4 Nov 2026): ways to read .env that the hook missed. Each blocked form has an everyday
neighbour that must stay allowed, so the guardrail does not get in the way of ordinary work."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".claude" / "hooks"))
import guardrails  # noqa: E402


@pytest.fixture(autouse=True)
def _not_harness(monkeypatch):
    monkeypatch.delenv("EG_HARNESS", raising=False)


@pytest.mark.parametrize("cmd", [
    "cat .e*", "cat .en?", "cat ./.e[n]v", "head .[e]nv", "cat .env.local", "less .env.production",
    "python3 -c \"print(open('.e'+'nv').read())\"", "python3 -c 'open(\".en\" + \"v\")'",
    "grep -r KEY .", "grep -rn TENABLE", "grep -R secret ./", "egrep -ri key *",
    "rg -uu KEY", "rg --no-ignore KEY", "rg --hidden -u KEY .",
])
def test_blocked(cmd):
    assert guardrails.check("Bash", {"command": cmd}), cmd


@pytest.mark.parametrize("cmd", [
    "grep -rn KEY src", "grep -r KEY src tests", "grep -n KEY README.md", "rg KEY", "rg KEY src",
    "cat .env.example", "ls -la", "grep -E 'a.*b' notes.md",
    "python3 -c \"print('a' + 'b')\"", "git grep KEY", "test -f .env && echo yes",
])
def test_allowed(cmd):
    assert guardrails.check("Bash", {"command": cmd}) is None, cmd


@pytest.mark.parametrize("tool,inp", [
    ("Read", {"file_path": ".env.local"}), ("Read", {"file_path": "/repo/.env.production"}),
    ("Grep", {"pattern": "KEY", "glob": ".env*"}), ("Grep", {"pattern": "KEY", "path": ".env.local"}),
    ("Glob", {"pattern": "**/.env*"}),
])
def test_file_tools_blocked(tool, inp):
    assert guardrails.check(tool, inp), (tool, inp)


@pytest.mark.parametrize("tool,inp", [
    ("Read", {"file_path": ".env.example"}), ("Grep", {"pattern": "KEY", "path": "src"}),
    ("Glob", {"pattern": "**/*.py"}), ("Read", {"file_path": "src/exception_guardian/config.py"}),
])
def test_file_tools_allowed(tool, inp):
    assert guardrails.check(tool, inp) is None, (tool, inp)
