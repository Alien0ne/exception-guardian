"""Guardrail fixes from the cross-model red-team review (Haiku, Opus, Fable, 3 Nov 2026): cloud and remote tools,
deny rules for environment dumps, quote-aware command splitting and block messages that name every rule."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".claude" / "hooks"))
import guardrails  # noqa: E402
from shellwords import commands  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


# cloud and remote-login tools stay out of harness runs (EG_HARNESS=1)
@pytest.mark.parametrize("cmd", ["aws sts get-caller-identity", "gcloud auth list", "az account show", "terraform plan",
                                 "ssh build-host", "scp a build-host:", "kubectl get pods", "ls; aws s3 ls"])
def test_harness_blocks_cloud_and_remote_tools(cmd, monkeypatch):
    monkeypatch.setenv("EG_HARNESS", "1")
    assert guardrails.check("Bash", {"command": cmd})


# a second layer under the hook: deny rules in .claude/settings.json
def test_settings_deny_env_dumps_and_reading_env_with_cat():
    deny = json.loads((ROOT / ".claude" / "settings.json").read_text())["permissions"]["deny"]
    for rule in ("Bash(printenv*)", "Bash(env)", "Bash(cat .env*)", "Read(**/.env)"):
        assert rule in deny


# splitting follows bash quoting
@pytest.mark.parametrize("cmd,progs", [
    ('grep -nE "github|gh |push" notes.md', ["grep"]),
    ("echo 'a | gh pr list; git push'", ["echo"]),
    ('echo "x" | gh pr list', ["echo", "gh"]),
    ('echo "$(gh pr list)"', ["echo", "gh"]),
    ('echo "`gh pr list`"', ["echo", "gh"]),
    ('bash -c "ls; gh pr list"', ["ls", "gh"]),
    ('echo "a\\" | gh x"', ["echo"]),
])
def test_commands_split_like_bash(cmd, progs):
    assert [w[0] for w in commands(cmd)] == progs


# one block names every rule the command breaks
def test_block_message_names_every_rule(monkeypatch):
    monkeypatch.delenv("EG_HARNESS", raising=False)
    why = guardrails.check("Bash", {"command": "cat .env && gh pr list"})
    assert ".env" in why and "GitHub" in why
