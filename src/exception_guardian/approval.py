"""Approval: a written plan for every REVOKE, and an opt-in, per-rule confirmed apply for Tenable VM rules."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Callable

from .find import load_findings
from .guard.hunt import TEMPLATES
from .report import BIDI, md_escape
from .tenable_client import rule_fingerprint

AUTO_TYPES = {"accept", "recast"}


def _revokes(run_dir: Path) -> list[dict]:
    return [f for f in load_findings(Path(run_dir) / "findings.json") if f["grade"] == "REVOKE"]


def is_auto(f: dict) -> bool:
    e = f["exception"]
    return e["source"] == "tenable-vm" and e["rule_type"] in AUTO_TYPES


def _resurfaces(e: dict) -> str:
    n = e.get("revised_findings")
    if n is not None:
        if e.get("revised_findings_capped"):
            return f"at least {n} findings"
        if n == 0:
            return "0 findings (the rule matches nothing today)"
        return f"{n} finding" + ("" if n == 1 else "s")
    return "unknown number of findings (source does not report it)"


def _one_line(v) -> str:
    """Source text inside a ticket or the confirm prompt: one line with no control characters, so a value cannot
    add lines of its own or move the terminal cursor."""
    return " ".join(BIDI.sub("", re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(v))).split())


def shown(run_dir: Path) -> str:
    """The run folder as it goes into a ticket or Tenable: relative to where you ran it, never a home path."""
    run_dir = Path(run_dir).resolve()
    try:
        return str(run_dir.relative_to(Path.cwd().resolve()))
    except ValueError:
        return run_dir.name


def _brief(run_dir: Path, e: dict) -> str:
    """The hunt brief guard wrote for this exception (guard.json names its folder), else the run folder."""
    from .guard.run import safe_name
    sid = safe_name(e["rule_id"])
    try:
        guard = json.loads((Path(run_dir) / "guard.json").read_text())
    except (OSError, ValueError):
        guard = {}
    for g in guard.values() if isinstance(guard, dict) else ():
        if isinstance(g, dict) and g.get("dir") and (g.get("source"), g.get("rule_type"), g.get("rule_id")) == (
                e["source"], e["rule_type"], e["rule_id"]):
            sid = safe_name(g["dir"])
            break
    brief = Path(run_dir) / "hunt-briefs" / f"{sid}.md"
    return f"{shown(run_dir)}/hunt-briefs/{brief.name}" if brief.is_file() else shown(run_dir)


def preflight(client) -> str:
    """Before any change: can this key change rules at all? Raises when it surely cannot, and returns what the
    check found, so the person confirming each change knows when only Tenable can tell."""
    check = getattr(client, "can_edit_rules", None)
    if check is None:
        return ""
    ok, why = check()
    if not ok:
        raise RuntimeError(f"cannot change rules: {why}. Ask the tenant admin for a role that can manage "
                           "recast/accept rules, or raise the tickets in approval-plan.md instead")
    return why


def write_plan(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    ticket = Template((TEMPLATES / "ticket.md").read_text())
    today = json.loads((run_dir / "findings.json").read_text())["today"]
    lines = ["# Approval plan", "", "Nothing below has been changed. `approve --apply` disables only the rules marked",
             "**auto**, one at a time, after you confirm each one. Rules marked **manual** need a ticket.", ""]
    revokes = list(_revokes(run_dir))
    if not revokes:
        grades = [f["grade"] for f in json.loads((run_dir / "findings.json").read_text())["findings"]]
        lines += ["No exception is graded REVOKE, so there is nothing to disable.",
                  f"{grades.count('REVIEW')} graded REVIEW and {grades.count('OK')} graded OK: REVIEW ones need a "
                  "person to decide (see `report.md`), and apply mode never touches them.", ""]
    for f in revokes:
        e = f["exception"]
        mode = "auto (Tenable VM rule, apply mode can disable it)" if is_auto(f) else "manual (raise the ticket below)"
        text = ticket.substitute(
            rule_id=_one_line(e["rule_id"]), source=_one_line(e["source"]), rule_type=e["rule_type"], today=today,
            triggers=", ".join(dict.fromkeys(t["code"] for t in f["triggers"])), cves=", ".join(e["cves"]) or "none",
            targets=_one_line(", ".join(e["targets"])) or "none", owner=_one_line(e.get("owner") or "unknown"),
            resurfaces=_resurfaces(e), run_dir=_brief(run_dir, e))
        lines += [f"## {md_escape(_one_line(e['rule_id']))} ({md_escape(e['source'])}, {e['rule_type']})", "",
                  f"- Mode: {mode}", f"- Disabling re-surfaces: {_resurfaces(e)}", "", "Ticket text:", "", "```text",
                  text.replace("```", "'''").rstrip(), "```", ""]
    path = run_dir / "approval-plan.md"
    path.write_text("\n".join(lines) + "\n")
    return path


def apply(run_dir: Path, client, confirm: Callable[[str], bool], operator: str | None = None) -> list[dict]:
    """Disable confirmed auto rules. `operator` (default: the signed-in OS user) is written to every log line and
    to the rule's disabled reason in Tenable, so each change names the person who confirmed it."""
    import os
    agent = [v for v in ("CLAUDECODE", "EG_HARNESS") if os.environ.get(v)]
    if agent:  # the CLI checks this too; apply() holds it alone, so importing it does not get around the check
        raise RuntimeError(f"refusing to apply: this is an agent session ({', '.join(agent)} is set). Only a person, "
                           "in their own terminal, applies changes")
    run_dir = Path(run_dir)
    if operator is None:
        import getpass
        operator = getpass.getuser()
    log = run_dir / "applied-changes.log"
    out: list[dict] = []
    if json.loads((run_dir / "findings.json").read_text()).get("partial"):
        raise RuntimeError("refusing to apply: this run is partial (a source failed), so its grades may be incomplete. "
                           "Fix the source and run find again")

    def record(rid: str, result: str) -> None:
        out.append({"rule_id": rid, "result": result})
        with log.open("a") as fh:
            # one line per rule: an id or error text holding a line break must not add a line of its own
            fh.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {_one_line(rid)} {_one_line(result)} "
                     f"by {_one_line(operator)}\n")

    for f in _revokes(run_dir):
        if not is_auto(f):
            continue
        e = f["exception"]
        rid = e["rule_id"]
        try:
            current = client.get_rule(rid)
        except Exception as exc:
            record(rid, f"skipped: could not read the live rule ({type(exc).__name__}: {exc})")
            continue
        raw = e.get("raw") or {}
        if "filter" not in raw:
            record(rid, "skipped: the run has no copy of this rule, so apply cannot tell whether it changed")
            continue
        if rule_fingerprint(current) != rule_fingerprint(raw):
            record(rid, "skipped: the live rule changed since the run (filter, action, severity or expiry), "
                        "so grade it again first")
            continue
        if current["status"] == "disabled":
            record(rid, "already disabled")
            continue
        live_action = (current.get("rule_value") or {}).get("action")
        if live_action not in ("ACCEPT", "RECAST"):
            record(rid, f"skipped: live rule action is {live_action!r}, not ACCEPT/RECAST")
            continue
        diff = (f"Tenable VM rule {_one_line(rid)} — live: {_one_line(current.get('rule_name') or rid)}, "
                f"action {_one_line(live_action)}\n"
                f"  graded: {e['rule_type']}, CVEs {', '.join(e['cves']) or 'none'}\n"
                f"  status: enabled -> disabled\n  re-surfaces: {_resurfaces(e)}\n"
                f"  triggers: {', '.join(dict.fromkeys(t['code'] for t in f['triggers']))}")
        if not confirm(diff):
            record(rid, "declined")
            continue
        try:
            client.disable_rule(rid, reason=f"revoked via Exception Guardian by {operator} "
                                            f"(plan {shown(run_dir)}/approval-plan.md)",
                                expected=rule_fingerprint(current))
        except Exception as exc:  # logged, and the next rule is still offered
            record(rid, f"failed: {type(exc).__name__}: {exc}")
            continue
        try:
            after = client.get_rule(rid)["status"]
        except Exception as exc:  # the change went through: it must reach the log before anything else
            record(rid, f"disabled, not verified (could not read it back: {type(exc).__name__}: {exc})")
            raise RuntimeError(f"{rid} was disabled but not verified ({type(exc).__name__}), so apply stopped. "
                               "Check the rule in Tenable") from exc
        if after != "disabled":
            record(rid, "verify failed")
            raise RuntimeError(f"verify failed for {rid}")
        record(rid, "disabled (verified)")
    return out
