"""Manual live test (4 Nov 2026): /eg-run said "Run the playbook in `SKILL.md`" with no path, and Claude Code
searched the whole disk (find / -name SKILL.md) for an eg-run skill before starting. Every slash command that
points at the playbook says it is the repo-root SKILL.md."""
import re
from pathlib import Path

CMDS = sorted(Path(".claude/commands").glob("*.md"))


def test_every_command_that_names_the_playbook_says_where_it_is():
    assert CMDS
    for p in CMDS:
        text = p.read_text()
        bare = re.findall(r"(?<![/\w-])`SKILL\.md`", text)
        if bare:
            assert "repo-root `SKILL.md`" in text, f"{p.name}: says `SKILL.md` without saying it is at the repo root"
