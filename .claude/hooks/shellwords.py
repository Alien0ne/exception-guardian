"""Split a shell command into the commands it runs, the way the guardrail hooks need to see them.

`bash -c '…'`, `sh -c`, `eval`, `script -c`, `sudo`, `env X=1`, `command`, `exec`, `nohup`, `time`, a leading
backslash and a full path (`/usr/bin/gh`) are all looked through, so a blocked command cannot be dressed up as
something else. This is a guardrail against mistakes and prompt injection, not a sandbox: the harness also limits
which commands are allowed at all."""
from __future__ import annotations

import os
import re
import shlex

_OPS = ("&&", "||", "$(", ";", "|", "&", "\n", "`", ")")


def _split(command: str) -> list[str]:
    """The simple commands in a line, split the way bash reads it: nothing inside single quotes splits, and inside
    double quotes only a command substitution (`$(…)`, backticks) does, because bash runs those."""
    parts, cur, quote, i, subs = [], [], None, 0, []
    while i < len(command):
        ch = command[i]
        if ch == "\\" and quote != "'" and i + 1 < len(command):
            cur.append(command[i:i + 2])
            i += 2
            continue
        if quote == "'":
            quote = None if ch == "'" else quote
            cur.append(ch)
            i += 1
            continue
        if ch in "'\"" and (quote is None or quote == ch):
            if ch == "'" and quote is None:
                quote = "'"
            else:
                quote = None if quote == '"' else '"'
            cur.append(ch)
            i += 1
            continue
        op = next((o for o in _OPS if command.startswith(o, i)), None)
        if op and (quote is None or op in ("$(", "`")):
            parts.append("".join(cur))
            cur = []
            if op == "$(" or (op == "`" and not (subs and subs[-1][0] == "`")):
                subs.append((op, quote))  # a substitution: quoting starts afresh inside it
                quote = None
            elif op in (")", "`") and subs and subs[-1][0] == ("$(" if op == ")" else "`"):
                quote = subs.pop()[1]     # back in the quoting the substitution sat in
            i += len(op)
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p for p in parts if p.strip(" \t\"'")]  # a bare closing quote left after a substitution
_WRAPPERS = {"sudo", "command", "exec", "nohup", "time", "builtin", "nice", "stdbuf", "timeout", "xargs", "doas"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _words(part: str) -> list[str]:
    try:
        return shlex.split(part)
    except ValueError:
        return part.split()


def commands(command: str, depth: int = 0) -> list[list[str]]:
    """Each simple command as words, with wrappers removed and the program reduced to its base name."""
    out: list[list[str]] = []
    for part in _split(command):
        words = _words(part)
        saw_env = False
        while words:
            w = words[0].lstrip("\\")
            base = os.path.basename(w)
            saw_env = saw_env or base == "env"
            if _ASSIGN.match(w) or base in _WRAPPERS:
                words = words[1:]
                while words and base in ("sudo", "timeout", "nice", "env") and words[0].startswith("-"):
                    words = words[1:]
                if base == "timeout" and words and re.match(r"^\d", words[0]):
                    words = words[1:]
                continue
            if base == "env":
                words = words[1:]
                while words and words[0].startswith("-"):  # env -0, env -i, env -u NAME
                    words = words[2:] if words[0] in ("-u", "--unset", "-C", "--chdir") else words[1:]
                continue
            break
        if not words:
            if saw_env:  # a bare `env` prints the environment: it is the command, not a wrapper
                out.append(["env"])
            continue
        prog = os.path.basename(words[0].lstrip("\\"))
        inner = None
        if prog in _SHELLS and "-c" in words[1:]:
            i = words.index("-c")
            inner = words[i + 1] if i + 1 < len(words) else ""
        elif prog == "script" and any(w in ("-c", "-qc", "-cq") for w in words):
            i = next(i for i, w in enumerate(words) if w in ("-c", "-qc", "-cq"))
            inner = words[i + 1] if i + 1 < len(words) else ""
        elif prog == "eval":
            inner = " ".join(words[1:])
        if inner is not None and depth < 4:
            out += commands(inner, depth + 1)
            continue
        out.append([prog, *words[1:]])
    return out


_REDIRECT = re.compile(r"^(\d*|&)>>?(?!&)(.*)$")
_TARGET_LAST = {"cp", "mv", "install", "rsync", "scp"}
_TARGET_ALL = {"tee", "touch", "rm", "rmdir", "truncate", "chmod", "chown", "shred", "unlink"}
INLINE = {"python", "python3", "perl", "node", "ruby", "php", "lua", "awk", "gawk"}


def write_targets(words: list[str]) -> list[str] | None:
    """Paths a simple command writes to (redirections included), or None when its writes cannot be told apart:
    inline interpreter code, `ln`, `dd` without `of=`. Used only in harness runs."""
    prog, args = words[0], words[1:]
    out: list[str] = []
    rest: list[str] = []
    i = 0
    while i < len(args):
        m = _REDIRECT.match(args[i])
        if m:
            if m.group(2):
                out.append(m.group(2))
            elif i + 1 < len(args):
                out.append(args[i + 1])
                i += 1
        else:
            rest.append(args[i])
        i += 1
    plain = [a for a in rest if not a.startswith("-")]
    if prog in INLINE and any(a.startswith("-") and set(a[1:]) & set("ceE") for a in rest) or prog == "ln":
        return None
    if prog in INLINE and prog in ("awk", "gawk") and any("print" in a and ">" in a for a in rest):
        return None
    if prog == "dd":
        of = [a[3:] for a in rest if a.startswith("of=")]
        return out + of
    if prog == "sed" and any(a.startswith("-i") or a == "--in-place" for a in rest):
        out += plain[1:] if not any(a in ("-e", "-f") for a in rest) else plain
    elif prog in _TARGET_LAST and plain:
        out.append(plain[-1])
    elif prog in _TARGET_ALL:
        out += plain
    return out
