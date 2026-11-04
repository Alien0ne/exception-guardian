#!/usr/bin/env python3
"""Claude Code PreToolUse hook: guardrails for any agent run of the playbook.

- Keys stay secret: no reading `.env` or a process environment, no printing the environment or a key variable.
  Checking that a key is set (`[ -n "$TENABLE_ACCESS_KEY" ]`, `test -f .env`) is fine.
- Tenable is reached only through `exception-guardian`, whose live calls are reads (GET, or a search POST).
  A direct network call to a Tenable host or a Security Center API path (`/rest/`) is blocked. In a harness run
  every direct network tool is blocked: the agent researches with WebFetch and WebSearch.
- Nothing is published: no `git push`, no `gh`, no new remotes, however the command is wrapped.
- In a harness run (EG_HARNESS=1) file tools stay inside the repo, and the agent writes only its own inputs under
  `out/` (drafts, samples, claims). The graded outputs are written by code, never by the agent.
- Input the hook cannot read is blocked, not waved through.

Exit 2 blocks the tool call and shows stderr to Claude. `block_apply.py` separately blocks `approve --apply`."""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shellwords import commands, write_targets  # noqa: E402

SECRET_VARS = r"(TENABLE|ANTHROPIC|SC)_\w*(KEY|SECRET|HOST)\w*|ANTHROPIC_API_KEY"
# A test of whether a key or the .env file exists shows nothing: removed before the checks below.
# `[ -n "${!v}" ]` (a loop over key names) only asks whether each is set. `ls -l .env` and `stat .env` show the
# file's size and date, never its contents, unless piped into something that reads it.
_HARMLESS = re.compile(r"""(\[\[?|\btest)\s+(-[nz]\s+["']?\$\{?(""" + SECRET_VARS + r""")\}?["']?|-[nz]\s+["']?\$\{![A-Za-z_]\w*\}["']?|-[efsr]\s+["']?(\./)?\.env["']?)"""
                       r"""|\b(ls|stat)\s+(-[A-Za-z]+\s+)*([\w./-]+\s+)*["']?(\./)?\.env["']?(\s+[\w./-]+)*"""
                       r"""(?=\s*(2>&1|2>\s*/dev/null)?\s*($|;|&&|\|\||\)))""")
_NET_TOOLS = r"curl|wget|Invoke-WebRequest|iwr|requests\.|urllib|httpx|http\.client|aiohttp|socket\.|nc|ncat|telnet|openssl\s+s_client"
BASH_RULES = [
    (re.compile(r"(^|[\s/'\"=<>(:])\.env(\s|$|['\");|&>])"),
     "the .env file holds API keys. Use the keys only through exception-guardian, which reads them itself"),
    # .env.local, .env.production: the same keys under another name (.env.example and friends hold none)
    (re.compile(r"(^|[\s/'\"=<>(:])\.env\.(?!(example|sample|template|dist)\b)\w"),
     "the .env file holds API keys, under any suffix"),
    # a glob that expands to .env: .e*, .en?, .[e]nv
    (re.compile(r"(^|[\s/'\"=<>(:])\.(\[|e[*?\[]|en[*?\[]|env[*?\[])"),
     "that pattern expands to the .env file, which holds API keys"),
    (re.compile(r"(^|[;&|(`]\s*)(printenv|env|set|export\s+-p|declare\s+-p|compgen\s+-v)\s*($|[;&|)`])"),
     "printing the environment would show API keys"),
    (re.compile(r"\$\{?!?(" + SECRET_VARS + r")"), "a command that names a key variable could show or send an API key. Use the keys only through exception-guardian, which reads them itself"),
    # ${!v} with v=TENABLE_SECRET_KEY is the key itself: echo "${!v}" prints it
    (re.compile(r"\$\{![A-Za-z_]"), "an indirect expansion (${!name}) can print an API key. Check a key only with "
     '[ -n "${!name}" ]'),
    # the same indirection by other means: eval re-reads `\$$v` as `$TENABLE_SECRET_KEY`; a nameref (declare -n)
    # makes `$r` the key
    (re.compile(r"(^|[;&|(`]\s*|\s)eval\s+[^;&|]*\$"), "eval of a variable can print an API key"),
    (re.compile(r"\b(declare|local|typeset)\s+-[A-Za-z]*n"), "a nameref (declare -n) can print an API key"),
    (re.compile(r"/proc/\S*(environ|cmdline)|os\.environ|getenv|process\.env|ENV\["),
     "process environments hold API keys"),
    (re.compile(r"\b(" + _NET_TOOLS + r")\b.*(tenable|/rest/)|(tenable|/rest/).*\b(" + _NET_TOOLS + r")\b", re.I),
     "call Tenable and Security Center only through exception-guardian, whose live calls are read-only"),
]
_HARNESS_NET = re.compile(r"\b(" + _NET_TOOLS + r")\b", re.I)
_GRADED = re.compile(r"(^|/)(findings\.json|guard\.json|report\.(html|md)|approval-plan\.md|changes\.(json|md)|"
                     r"applied-changes\.log|exposure-evidence\.json|exposure-drafted-hosts\.csv|handoff-\w+\.md|"
                     r"dc-candidates\.json|placeholders\.found\.yaml)$|"
                     r"(^|/)(rules|hunt-briefs|sample-briefs|previous)/")
_WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
_FILE_TOOLS = _WRITE_TOOLS + ("Read", "Grep", "Glob", "LS")


def _git_sub(words: list[str]) -> list[str]:
    """git's subcommand and its arguments, past global options (-C dir, -c k=v, --git-dir=…)."""
    i = 1
    while i < len(words) and words[i].startswith("-"):
        i += 2 if words[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") else 1
    return words[i:]


def _publishes(command: str) -> str | None:
    for words in commands(command):
        if words[0] == "gh":
            return "GitHub actions are the owner's step, not the agent's"
        if words[0] == "git":
            sub = _git_sub(words)
            if sub[:1] == ["push"] or (sub[:1] == ["remote"] and sub[1:2] and sub[1] in ("add", "set-url")):
                return "publishing is the owner's step, not the agent's"
    return None


_SAFE_SINKS = {"/dev/null", "/dev/stdout", "/dev/stderr"}


def _shell_paths(command: str) -> str | None:
    """In a harness run a shell command names no path outside the repo, and expands nothing that could hide one."""
    if "$" in command or "`" in command:
        return "a harness run does not expand variables or command substitutions. Name files under the repo directly"
    root = os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    for words in commands(command):
        for w in words[1:] + ([words[0]] if "/" in words[0] else []):
            for part in re.split(r"[=:]", w) if w.startswith("-") else [w]:
                part = _REDIRECT_PREFIX.sub("", part)
                if not (part.startswith(("/", "~")) or ".." in part.split("/")):
                    continue
                if part in _SAFE_SINKS:
                    continue
                target = os.path.realpath(os.path.join(root, os.path.expanduser(part)))
                if target != root and not target.startswith(root + os.sep):
                    return "a harness run works inside the repo only"
    return None


_REDIRECT_PREFIX = re.compile(r"^\d*>>?")


def _shell_writes(command: str) -> str | None:
    """In a harness run a shell command writes only the agent's own inputs under out/, like the file tools."""
    root = os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    out = os.path.join(root, "out") + os.sep
    for words in commands(command):
        targets = write_targets(words)
        if targets is None:
            return ("a harness run does not run inline interpreter code, links or raw copies. Use the file tools to "
                    "write drafts, samples or claims under out/")
        for t in targets:
            if t in _SAFE_SINKS:
                continue
            target = os.path.realpath(os.path.join(root, os.path.expanduser(t)))
            if not target.startswith(out):
                return "a harness run writes only under out/ (drafts, samples, claims), never the code or config"
            if _GRADED.search(target[len(out):]) and words[0] != "exception-guardian":
                return ("the code writes the graded outputs (findings, guard, rules, briefs, plan, report). Write "
                        "drafts, samples or claims and rerun the step instead")
    return None


def _prints_env(command: str) -> str | None:
    for words in commands(command):
        prog = words[0]
        if (prog in ("env", "printenv") or (prog == "set" and len(words) == 1)
                or (prog in ("export", "declare", "typeset") and "-p" in words) or (prog == "compgen" and "-v" in words)):
            return "printing the environment would show API keys"
    return None


# Cloud and remote-login tools: the playbook never needs them, and a harness run has no business with the
# user's cloud accounts or other machines.
_REMOTE = {"aws", "gcloud", "gsutil", "bq", "az", "terraform", "tofu", "pulumi", "kubectl", "helm",
           "ssh", "scp", "sftp", "rsync", "doctl", "flyctl", "vercel", "wrangler", "cloudflared", "heroku"}


def _remote_tools(command: str) -> str | None:
    for words in commands(command):
        if words[0] in _REMOTE:
            return "a harness run does not use cloud or remote-login tools"
    return None


_ENV_SAFE = (".env.example", ".env.sample", ".env.template", ".env.dist")


def _is_env_file(path: str) -> bool:
    """.env and every variant (.env.local, .env.production); the example files hold no keys."""
    name = os.path.basename(str(path or ""))
    return (name == ".env" or name.startswith(".env.")) and name not in _ENV_SAFE


# Public vulnerability data the playbook reads (NVD, CISA KEV, FIRST EPSS). NVD's API path has /rest/ in it, which
# the Security Center rule above would otherwise catch (live run, 4 Nov 2026). The host must end at / : ? or a quote,
# so nvd.nist.gov.evil.example and nvd.nist.gov@other-host are not taken for it.
_PUBLIC_URL = re.compile(r"""https?://(?:[\w-]+\.)*(?:nvd\.nist\.gov|cisa\.gov|first\.org)(?=[/?"'\s]|$)[^\s"'@]*""", re.I)
# echo or printf of plain text (no $, no backtick) writes only to the screen, unless piped or redirected into
# something: "echo '.env present'" names no file. A pipe or redirect after it keeps the text in view.
_ECHO_TEXT = re.compile(r"""\b(echo|printf)((?:\s+(?:'[^'$`]*'|"[^"$`\\]*"|[^\s;&|<>'"$`\\]+))+)(?=\s*(?:;|&&|\|\||\n|$))""")


def _plain(command: str) -> str:
    """The command with the parts that cannot touch a key or Tenable taken out: public intel URLs, echoed text."""
    return _ECHO_TEXT.sub(r"\1", _PUBLIC_URL.sub("", command))


# 'a' + 'b' between quotes: a name built from pieces, as in open('.e'+'nv')
_JOINED = re.compile(r"""['"]\s*\+\s*['"]""")
_ROOTS = {".", "./", "*", ".*", "..", "../", "~", "~/", "/"}


def _searches_env(command: str) -> str | None:
    """A recursive grep over the repo root reads .env too; ripgrep skips it unless told to read ignored or hidden
    files. Searching a named folder (src, tests) or tracked files (git grep) is fine."""
    for words in commands(command):
        prog = os.path.basename(words[0]) if words else ""
        flags = [w for w in words[1:] if w.startswith("-")]
        if prog in ("grep", "egrep", "fgrep"):
            recursive = any(f in ("--recursive", "--dereference-recursive") or
                            (not f.startswith("--") and set("rR") & set(f[1:])) for f in flags)
            if not recursive or any(f.startswith("--include") for f in flags):
                continue
            args = [w for w in words[1:] if not w.startswith("-")]
            paths = args if any(f == "-e" or f.startswith("--regexp") for f in flags) else args[1:]
            if not paths or any(p.rstrip("/") + ("/" if p.endswith("/") else "") in _ROOTS or p in _ROOTS
                                for p in paths):
                return "a recursive grep over the whole repo reads the .env file. Search a folder (src, tests) or use git grep"
        if prog == "rg" and any(f in ("--no-ignore", "--hidden", "-u", "-uu", "-uuu", "--unrestricted") or
                                (f.startswith("-u") and set(f[1:]) == {"u"}) for f in flags):
            return "ripgrep reading ignored or hidden files reads the .env file. Drop -u, --hidden and --no-ignore"
    return None


def check(tool: str, inp: dict) -> str | None:
    harness = os.environ.get("EG_HARNESS") == "1"
    if tool == "Bash":
        # every rule the command breaks, in one message, so a model is not led to strip one part per retry
        command = str(inp.get("command", ""))
        visible = _HARMLESS.sub(" ", _plain(command))
        joined = _JOINED.sub("", visible)  # '.e'+'nv' reads as .env
        whys = [why for rule, why in BASH_RULES if rule.search(visible) or rule.search(joined)]
        whys += [_publishes(command), _prints_env(command), _searches_env(command)]
        if harness:
            whys += ["a harness run reaches the web only through WebFetch and WebSearch"
                     if _HARNESS_NET.search(command) else None, _remote_tools(command),
                     _shell_paths(command), _shell_writes(command)]
        whys = list(dict.fromkeys(w for w in whys if w))
        return ". Also: ".join(whys) or None
    if tool not in _FILE_TOOLS:
        return None
    path = str(inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or "")
    if _is_env_file(path):
        return "the .env file holds API keys"
    pattern = str(inp.get("glob") or "") + " " + (str(inp.get("pattern") or "") if tool == "Glob" else "")
    if re.search(r"(^|[\s/{,])\.(e|en|env)?[*?\[]|(^|[\s/{,])\.env(\.|\b)", pattern) and \
            not any(pattern.strip().endswith(s) for s in _ENV_SAFE):
        return "that pattern matches the .env file, which holds API keys"
    root = os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    target = os.path.realpath(os.path.join(root, path)) if path else root
    if target == "/proc" or target.startswith("/proc/"):
        return "process environments hold API keys"
    if not harness:
        return None
    if target != root and not target.startswith(root + os.sep):
        return "a harness run works inside the repo only"
    if tool in _WRITE_TOOLS:
        out = os.path.join(root, "out") + os.sep
        if not target.startswith(out):
            return "a harness run writes only under out/ (drafts, samples, claims), never the code or config"
        if _GRADED.search(target[len(out):]):
            return ("the code writes the graded outputs (findings, guard, rules, briefs, plan, report). Write drafts, "
                    "samples or claims and rerun the step instead")
    return None


def main() -> int:
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            raise ValueError("not an object")
        why = check(str(data.get("tool_name", "")), data.get("tool_input") or {})
    except Exception as exc:  # a hook that cannot read its input must not wave the call through
        print(f"Blocked: the guardrail hook could not read this tool call ({type(exc).__name__}).", file=sys.stderr)
        return 2
    if why:
        print(f"Blocked: {why}.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
