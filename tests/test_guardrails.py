"""Guardrails for agent runs (hook .claude/hooks/guardrails.py): keys never read or printed, Tenable reached only
through the read-only CLI, nothing pushed, and in harness runs files written only under out/."""
import json
import os
import subprocess
import sys

import pytest

HOOK = ".claude/hooks/guardrails.py"


def run(tool, inp, harness=False):
    env = {**os.environ, "CLAUDE_PROJECT_DIR": os.getcwd()}
    env.pop("EG_HARNESS", None)
    if harness:
        env["EG_HARNESS"] = "1"
    p = subprocess.run([sys.executable, HOOK], input=json.dumps({"tool_name": tool, "tool_input": inp}),
                       capture_output=True, text=True, env=env, timeout=10)
    return p.returncode, p.stderr


@pytest.mark.parametrize("cmd", [
    "cat .env", "grep KEY ./.env", "source .env && echo hi", "head -1 /x/exception-guardian/.env",
    "printenv", "env", "env | grep TENABLE", "echo $TENABLE_SECRET_KEY", "echo ${ANTHROPIC_API_KEY}",
    "cat /proc/self/environ",
    "curl -s https://cloud.tenable.com/session", "curl -X PUT https://cloud.tenable.com/api/v1/recast/rules/x",
    "wget https://cloud.tenable.com/x", "python -c 'import requests; requests.put(\"https://cloud.tenable.com\")'",
    "v=TENABLE_ACCESS_KEY; eval echo \\$$v", "eval 'echo $'$v", "declare -n r=TENABLE_SECRET_KEY; echo $r",
    "local -n r=TENABLE_ACCESS_KEY", "typeset -n r=X; echo $r", "declare -gn r=TENABLE_ACCESS_KEY",
    "git push origin main", "git push", "gh pr create", "gh repo create x --public", "git remote add o url",
])
def test_blocked_commands(cmd):
    code, err = run("Bash", {"command": cmd})
    assert code == 2 and err.startswith("Blocked:"), cmd


@pytest.mark.parametrize("cmd", [
    "exception-guardian find --config guardian.live.yaml --out out/r", ".venv/bin/exception-guardian guard --run out/r",
    "ls out/r", "cat out/r/handoff-guard.md", "git status", "git log --oneline -3", "python -m pytest -q",
    "cat .env.example", "grep -n environment README.md", "echo done",
])
def test_allowed_commands(cmd):
    assert run("Bash", {"command": cmd})[0] == 0, cmd


def test_env_file_cannot_be_read_or_written_by_file_tools():
    for tool in ("Read", "Edit", "Write"):
        assert run(tool, {"file_path": os.path.join(os.getcwd(), ".env")})[0] == 2
    assert run("Grep", {"pattern": "KEY", "path": ".env"})[0] == 2
    assert run("Read", {"file_path": os.path.join(os.getcwd(), "README.md")})[0] == 0


def test_harness_runs_write_only_under_out():
    inside = os.path.join(os.getcwd(), "out/r/drafts/CVE-2020-1380.yml")
    outside = os.path.join(os.getcwd(), "src/exception_guardian/grading.py")
    assert run("Write", {"file_path": inside}, harness=True)[0] == 0
    code, err = run("Edit", {"file_path": outside}, harness=True)
    assert code == 2 and "only under out/" in err
    assert run("Write", {"file_path": os.path.join(os.getcwd(), "out/../src/x.py")}, harness=True)[0] == 2
    assert run("Edit", {"file_path": outside})[0] == 0  # a developer's own session may edit code


def test_settings_wire_both_hooks():
    s = json.load(open(".claude/settings.json"))
    cmds = [h["command"] for m in s["hooks"]["PreToolUse"] for h in m["hooks"]]
    assert any("block_apply.py" in c for c in cmds) and any("guardrails.py" in c for c in cmds)
    matchers = {m["matcher"] for m in s["hooks"]["PreToolUse"] if any("guardrails.py" in h["command"] for h in m["hooks"])}
    assert matchers == {"Bash|Read|Edit|Write|Grep|Glob|NotebookEdit"}


def test_slash_commands_have_descriptions_and_never_apply():
    import re
    from pathlib import Path
    names = sorted(p.stem for p in Path(".claude/commands").glob("*.md"))
    assert names == ["eg-approve", "eg-demo", "eg-find", "eg-guard", "eg-run", "exception-guardian"]
    for p in Path(".claude/commands").glob("*.md"):
        text = p.read_text()
        assert re.search(r"^description: .+", text, re.M), p
        assert "--apply" not in text.replace("Never run `--apply`", "").replace("Never run --apply", "") \
            or "own terminal" in text, p
