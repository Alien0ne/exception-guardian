#!/usr/bin/env python3
"""Install the playbook's three skills where Claude Code looks for them, in one command.

    python scripts/install_skills.py            # this project: .claude/skills/
    python scripts/install_skills.py --global   # every project: ~/.claude/skills/
    python scripts/install_skills.py <dir>      # anywhere else

Run it again after pulling changes: it replaces the installed copies."""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def install(dest: Path) -> None:
    main = dest / "exception-guardian"
    main.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "SKILL.md", main / "SKILL.md")
    shutil.copytree(ROOT / "references", main / "references", dirs_exist_ok=True)
    for sub in ("exception-guardian-find", "exception-guardian-guard"):
        shutil.copytree(ROOT / "skills" / sub, dest / sub, dirs_exist_ok=True)
    print(f"installed 3 skills in {dest}")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    install(Path.home() / ".claude/skills" if arg == "--global" else Path(arg) if arg else ROOT / ".claude/skills")
