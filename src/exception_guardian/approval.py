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
REASON = "revoked via Exception Guardian"  # how apply signs the disabled reason; undo re-enables only what carries it


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


#: Security Center rule fields kept in sc-rule-backups.json: what a person needs to create the rule again.
SC_KEPT = ("id", "plugin", "hostType", "hostValue", "port", "protocol", "repository", "organization", "comments",
           "expires", "newSeverity", "severity", "user", "createdTime", "modifiedTime")
SC_NOTE = ("Security Center has no way to disable a rule: revoking this one means deleting it there. A copy of the "
           "rule as graded is in sc-rule-backups.json in the run folder, to create it again if the removal was a mistake.")


def write_plan(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    ticket = Template((TEMPLATES / "ticket.md").read_text())
    today = json.loads((run_dir / "findings.json").read_text())["today"]
    lines = ["# Approval plan", "", "Nothing below has been changed. `approve --apply` disables only the rules marked",
             "**auto**, one at a time, after you confirm each one. Rules marked **manual** need a ticket.", ""]
    revokes = list(_revokes(run_dir))
    tickets: list[dict] = []
    sc_copies: list[dict] = []
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
        is_sc = e["source"] == "tenable-sc"
        if is_sc:
            text = text.rstrip() + "\n\n" + SC_NOTE + "\n"
            raw = e.get("raw") if isinstance(e.get("raw"), dict) else {}
            sc_copies.append({"rule_id": e["rule_id"], "rule_type": e["rule_type"],
                              "rule": {k: raw[k] for k in SC_KEPT if k in raw}})
        tickets.append({"kind": "revoke", "title": text.strip().splitlines()[0], "owner": _one_line(e.get("owner") or "unknown"),
                        "rule_ids": [_one_line(e["rule_id"])], "mode": "auto" if is_auto(f) else "manual",
                        "body": text.strip()})
        lines += [f"## {md_escape(_one_line(e['rule_id']))} ({md_escape(e['source'])}, {e['rule_type']})", "",
                  f"- Mode: {mode}", f"- Disabling re-surfaces: {_resurfaces(e)}", "", "Ticket text:", "", "```text",
                  text.replace("```", "'''").rstrip(), "```", ""]
    if write_review_plan(run_dir, tickets) is not None:
        lines += ["REVIEW rules are not in this plan: `review-plan.md` lists what each owner has to do about theirs.", ""]
    backups = run_dir / "sc-rule-backups.json"
    if sc_copies:
        backups.write_text(json.dumps({"today": today, "rules": sc_copies}, indent=2) + "\n")
    else:
        backups.unlink(missing_ok=True)
    # the same ticket text as data, for a script that files tickets (Jira, ServiceNow): nothing here files one
    (run_dir / "tickets.json").write_text(json.dumps({"today": today, "tickets": tickets}, indent=2) + "\n")
    path = run_dir / "approval-plan.md"
    path.write_text("\n".join(lines) + "\n")
    return path


REVIEW_LISTED = 25  # rules listed per owner and tier; the rest are counted (findings.json has every one)


def _review_action(t: dict) -> str:
    """What the owner does about one REVIEW trigger. Fixed wording per code; then/now are quoted as graded."""
    then, now = _one_line(t.get("then") or ""), _one_line(t.get("now") or "")
    return {
        "JUSTIFICATION_CONTRADICTED": f"the reason no longer matches the asset ({now}): re-justify it or retire it",
        "EXPLOIT_PUBLIC": f"{now}: confirm the risk is still acceptable now that exploit code is public",
        "NEW_ASSETS": f"{now}: confirm the acceptance was meant to cover them, or narrow the rule",
        "EPSS_ROSE": f"EPSS rose from {then or 'unknown'} to {now}: confirm the risk is still acceptable",
        "PUBLIC_IP": "an asset has a public IP: confirm whether it faces the internet",
        "PATH_CVE_ELSEWHERE": "an attack path elsewhere uses this CVE: confirm these assets are not reachable the same way",
        "EXPIRED_STILL_ENABLED": f"{now}: disable it or set a new expiry",
        "NO_EXPIRY": "set an expiry date",
        "TOO_OLD": f"{now}: re-confirm it or retire it",
        "NO_JUSTIFICATION": "write the reason it was accepted",
        "BLANKET": "it covers every asset: narrow it to the assets that need it",
    }.get(t["code"], f"{t['code']}: review")


def write_review_plan(run_dir: Path, tickets: list[dict] | None = None) -> Path | None:
    """review-plan.md: per owner, the REVIEW rules and the action each trigger asks for. Never applied by code.
    `tickets` collects one entry per owner for tickets.json."""
    run_dir = Path(run_dir)
    reviews = [f for f in load_findings(run_dir / "findings.json") if f["grade"] == "REVIEW"]
    path = run_dir / "review-plan.md"
    if not reviews:
        path.unlink(missing_ok=True)
        return None
    today = json.loads((run_dir / "findings.json").read_text())["today"]
    owners: dict[str, dict[str, list[dict]]] = {}
    for f in reviews:
        tier = "now" if f.get("review_tier") == "now" else "housekeeping"
        owners.setdefault(_one_line(f["exception"].get("owner") or "") or "unknown", {"now": [], "housekeeping": []})[tier].append(f)
    lines = ["# Review plan", "", "Nothing below has been changed, and apply mode never touches a REVIEW rule: each one "
             "needs its owner to decide.", "Send each owner their section. Rule ids, owners and CVEs are quoted data from "
             "the source systems.", ""]
    for owner, tiers in sorted(owners.items(), key=lambda kv: (-len(kv[1]["now"]), -len(kv[1]["housekeeping"]), kv[0])):
        body = [f"Risk exceptions to review, graded by Exception Guardian on {today}.", f"Owner: {owner}"]
        for tier, title in (("now", "Review now"), ("housekeeping", "Housekeeping")):
            fs = tiers[tier]
            if not fs:
                continue
            body += ["", f"{title} ({len(fs)}):"]
            for f in fs[:REVIEW_LISTED]:
                e = f["exception"]
                acts = list(dict.fromkeys(_review_action(t) for t in f["triggers"]))
                body.append(f"- {_one_line(e['rule_id'])} ({_one_line(e['source'])}, CVEs "
                            f"{_one_line(', '.join(e['cves'][:3])) or 'none'}{' and more' if len(e['cves']) > 3 else ''})")
                body += [f"    - {a}" for a in acts]
            if len(fs) > REVIEW_LISTED:
                body.append(f"- and {len(fs) - REVIEW_LISTED} more (every rule is in findings.json)")
        if tickets is not None:
            n = len(tiers["now"]) + len(tiers["housekeeping"])
            tickets.append({"kind": "review", "title": f"Review {n} risk exception{'' if n == 1 else 's'} ({owner})",
                            "owner": owner, "mode": "manual", "body": "\n".join(body),
                            "rule_ids": [_one_line(f["exception"]["rule_id"]) for t in ("now", "housekeeping") for f in tiers[t]]})
        lines += [f"## {md_escape(owner)}", "", f"- Review now: {len(tiers['now'])} · Housekeeping: {len(tiers['housekeeping'])}",
                  "", "Ticket text:", "", "```text", "\n".join(body).replace("```", "'''"), "```", ""]
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
            client.disable_rule(rid, reason=f"{REASON} by {operator} "
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


_DISABLED = ("disabled (verified)", "disabled, not verified")
_ENABLED = ("re-enabled (verified)", "re-enabled, not verified")


def _disabled_by_run(run_dir: Path, rule_ids: list[str]) -> list[str]:
    """Rule ids whose latest change in this run's applied-changes.log is a disable. Ids come from findings.json and
    are matched against each line, so a log line cannot name a rule the run never graded."""
    try:
        rows = [ln.split(" ", 1)[1] for ln in (Path(run_dir) / "applied-changes.log").read_text().splitlines() if " " in ln]
    except OSError:
        return []
    out = []
    for rid in rule_ids:
        state = None
        for row in rows:
            head = _one_line(rid) + " "
            if row.startswith(head):
                rest = row[len(head):]
                state = (True if rest.startswith(_DISABLED) else False if rest.startswith(_ENABLED) else state)
        if state:
            out.append(rid)
    return out


def undo(run_dir: Path, client, confirm: Callable[[str], bool], operator: str | None = None) -> list[dict]:
    """Re-enable the rules this run's apply disabled, one at a time, after the person confirms each. A rule is
    offered only if the log says this run disabled it, it still carries apply's disabled reason, and what it hides
    has not changed since the run. Every outcome is appended to applied-changes.log."""
    import os
    agent = [v for v in ("CLAUDECODE", "EG_HARNESS") if os.environ.get(v)]
    if agent:
        raise RuntimeError(f"refusing to undo: this is an agent session ({', '.join(agent)} is set). Only a person, "
                           "in their own terminal, applies changes")
    run_dir = Path(run_dir)
    if operator is None:
        import getpass
        operator = getpass.getuser()
    log = run_dir / "applied-changes.log"
    out: list[dict] = []

    def record(rid: str, result: str) -> None:
        out.append({"rule_id": rid, "result": result})
        with log.open("a") as fh:
            fh.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {_one_line(rid)} {_one_line(result)} "
                     f"by {_one_line(operator)}\n")

    autos = {f["exception"]["rule_id"]: f for f in _revokes(run_dir) if is_auto(f)}
    for rid in _disabled_by_run(run_dir, list(autos)):
        e = autos[rid]["exception"]
        try:
            current = client.get_rule(rid)
        except Exception as exc:
            record(rid, f"skipped: could not read the live rule ({type(exc).__name__}: {exc})")
            continue
        if current["status"] != "disabled":
            record(rid, "already enabled")
            continue
        reason = str((current.get("disabled_details") or {}).get("disabled_reason") or "")
        if not reason.startswith(REASON):
            record(rid, "skipped: it was not disabled by Exception Guardian (someone disabled it again since), "
                        "so it is not this run's change to undo")
            continue
        if rule_fingerprint(current) != rule_fingerprint(e.get("raw") or {}):
            record(rid, "skipped: the live rule changed since the run (filter, action, severity or expiry), "
                        "so re-enable it in Tenable if you still want it")
            continue
        diff = (f"Tenable VM rule {_one_line(rid)} — live: {_one_line(current.get('rule_name') or rid)}\n"
                f"  graded: {e['rule_type']}, CVEs {', '.join(e['cves']) or 'none'}\n"
                f"  status: disabled -> enabled\n  re-enabling hides again: {_resurfaces(e)}\n"
                f"  it was graded REVOKE on: {', '.join(dict.fromkeys(t['code'] for t in autos[rid]['triggers']))}")
        if not confirm(diff):
            record(rid, "undo declined")
            continue
        try:
            client.enable_rule(rid, expected=rule_fingerprint(current))
        except Exception as exc:
            record(rid, f"undo failed: {type(exc).__name__}: {exc}")
            continue
        try:
            after = client.get_rule(rid)["status"]
        except Exception as exc:
            record(rid, f"re-enabled, not verified (could not read it back: {type(exc).__name__}: {exc})")
            raise RuntimeError(f"{rid} was re-enabled but not verified ({type(exc).__name__}), so undo stopped. "
                               "Check the rule in Tenable") from exc
        if after != "enabled":
            record(rid, "undo verify failed")
            raise RuntimeError(f"verify failed for {rid}")
        record(rid, "re-enabled (verified)")
    return out
