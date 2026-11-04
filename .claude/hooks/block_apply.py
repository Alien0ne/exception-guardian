#!/usr/bin/env python3
"""Claude Code PreToolUse hook: Claude may plan approvals but never apply them.

`exception-guardian approve --apply` disables rules in Tenable. Only a person, in their own terminal, runs it.
The CLI already refuses --apply without a TTY; this hook stops the attempt before it starts.
Exit 2 blocks the tool call and shows stderr to Claude."""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shellwords import commands  # noqa: E402

TOOL = re.compile(r"exception[-_]guardian")
APPLY = re.compile(r"^--ap(p(l(y)?)?)?(=|$)")  # --apply and every abbreviation argparse would once have taken


# the CLI refuses --apply while these are set; a command that names them is trying to unset or fake them
MARKERS = re.compile(r"\b(CLAUDECODE|EG_HARNESS)\b")
EXPANDS = re.compile(r"[$`]|\beval\b")
# exit statuses expand to a number, so they cannot build --apply: `approve --run x; echo $?` is safe (live run, 4 Nov 2026)
STATUS = re.compile(r"\$\?|\$\{PIPESTATUS(\[\d+\])?\}|\$PIPESTATUS\b")
IMPORTS = re.compile(r"\bimport\b[^;\n]*exception_guardian|exception_guardian[^;\n]*\bimport\b")


def _raw(command: str) -> bool:
    """Checks on the text as written, before any splitting: a word built by expansion ($A, $(echo approve),
    `...`) is not a word the splitter can see, so a command that names the tool must not hold a piece of
    --apply, build its words by expansion near "approve", or import the package and call apply."""
    if MARKERS.search(command):
        return True
    if not TOOL.search(command):
        return False
    if "--ap" in command:
        return True
    if EXPANDS.search(STATUS.sub("", command)) and re.search(r"appr|--a", command):
        return True
    return bool(IMPORTS.search(command) and re.search(r"\bapply\b", command))


def blocked(command: str) -> bool:
    if _raw(command):
        return True
    for words in commands(command):
        tool = next((i for i, w in enumerate(words) if TOOL.search(w)), None)
        if tool is None:
            continue
        rest = words[tool + 1:]
        if "approve" in rest and any(APPLY.match(w) for w in rest):
            return True
    return False


def main() -> int:
    try:
        data = json.load(sys.stdin)
        command = str((data.get("tool_input") or {}).get("command", ""))
        hit = blocked(command)
    except Exception as exc:  # a hook that cannot read its input must not wave the call through
        print(f"Blocked: the --apply hook could not read this tool call ({type(exc).__name__}).", file=sys.stderr)
        return 2
    if hit:
        print("Blocked: `exception-guardian approve --apply` changes Tenable rules, and so does any way around it "
              "(expansion, importing apply, unsetting CLAUDECODE). Write the plan without --apply and ask the person "
              "to run --apply themselves, in their own terminal.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
