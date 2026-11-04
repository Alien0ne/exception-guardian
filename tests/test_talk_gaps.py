"""Fail loudly on a partial run, install the skills with one command, and keep Claude itself from applying."""
import json
import subprocess
import sys
from pathlib import Path

from exception_guardian.cli import main


def _broken(tmp_path):
    cfg = tmp_path / "broken.yaml"
    cfg.write_text(Path("guardian.yaml").read_text().replace("fixture_dir: samples/tenable_vm",
                                                             f"fixture_dir: {tmp_path / 'missing'}"))
    return cfg


def test_partial_run_exits_3_and_says_so(tmp_path, capsys):
    rc = main(["find", "--config", str(_broken(tmp_path)), "--offline", "--out", str(tmp_path / "r"),
               "--today", "2026-11-02"])
    assert rc == 3
    err = capsys.readouterr().err
    assert "PARTIAL RUN" in err and "source tenable-vm failed" in err
    assert json.loads((tmp_path / "r/findings.json").read_text())["partial"] is True


def test_full_run_still_exits_0(tmp_path):
    assert main(["find", "--offline", "--out", str(tmp_path / "r"), "--today", "2026-11-02"]) == 0


def test_install_skills_one_command(tmp_path):
    dest = tmp_path / "skills"
    subprocess.run([sys.executable, "scripts/install_skills.py", str(dest)], check=True, capture_output=True)
    assert (dest / "exception-guardian/SKILL.md").read_text() == Path("SKILL.md").read_text()
    assert (dest / "exception-guardian/references/grades.md").is_file()
    for sub in ("exception-guardian-find", "exception-guardian-guard"):
        assert (dest / sub / "SKILL.md").read_text() == Path(f"skills/{sub}/SKILL.md").read_text()
    # running it again refreshes, never fails on existing folders
    subprocess.run([sys.executable, "scripts/install_skills.py", str(dest)], check=True, capture_output=True)


HOOK = Path(".claude/hooks/block_apply.py")


def _hook(command):
    p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": command}}), capture_output=True, text=True)
    return p.returncode, p.stderr


def test_hook_blocks_claude_from_applying():
    for cmd in ("exception-guardian approve --run out/demo --apply --base-url https://cloud.tenable.com",
                ".venv/bin/exception-guardian approve --apply --run out/x",
                "python -m exception_guardian approve --run out/x --apply",
                "cd x && exception-guardian  approve --run out/x --base-url u --apply"):
        rc, err = _hook(cmd)
        assert rc == 2 and "--apply" in err, cmd


def test_hook_allows_everything_else():
    for cmd in ("exception-guardian approve --run out/demo", "exception-guardian find --out out/x",
                "grep -- --apply README.md", "exception-guardian guard --run out/applyme"):
        assert _hook(cmd)[0] == 0, cmd


def test_project_settings_wire_the_hook_and_deny_rule():
    s = json.loads(Path(".claude/settings.json").read_text())
    hooks = s["hooks"]["PreToolUse"]
    assert any(h["matcher"] == "Bash" and "block_apply.py" in h["hooks"][0]["command"] for h in hooks)
    assert any("--apply" in r for r in s["permissions"]["deny"])
