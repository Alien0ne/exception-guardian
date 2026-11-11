"""A short message about a run for the team's chat webhook (Slack and Teams both take {"text": ...}). It carries
counts, rule ids, CVE ids and trigger codes only: never a justification or any other free text from the source
system, so nothing a rule's author wrote can reach a channel as a mention, a link or an instruction."""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

LISTED = 10  # rules named per section; the rest are counted
_SAFE = re.compile(r"[^A-Za-z0-9 ._:/#()\-]")  # what a rule id may show as in a chat message


def _id(v) -> str:
    """A rule id as plain text: one line, no markup, mention or link characters."""
    return _SAFE.sub("", " ".join(str(v).split()))[:80] or "?"


def _codes(triggers: list[dict]) -> str:
    return ", ".join(dict.fromkeys(c for t in triggers if re.fullmatch(r"[A-Z_]{2,40}", c := str(t.get("code", "")))))


def _cves(cves) -> str:
    good = [c for c in cves or [] if re.fullmatch(r"CVE-\d{4}-\d{4,7}", str(c))]
    return ", ".join(good[:3]) + (f" and {len(good) - 3} more" if len(good) > 3 else "")


def _some(lines: list[str]) -> list[str]:
    return lines[:LISTED] + ([f"  and {len(lines) - LISTED} more"] if len(lines) > LISTED else [])


def build_message(run_dir: Path) -> str:
    run = Path(run_dir)
    d = json.loads((run / "findings.json").read_text())
    fs = d["findings"]
    n = {g: sum(1 for f in fs if f["grade"] == g) for g in ("REVOKE", "REVIEW", "OK")}
    now = sum(1 for f in fs if f.get("review_tier") == "now")
    day = date.fromisoformat(d["today"])
    out = [f"Exception Guardian, {day.day} {day:%b %Y}: {len(fs)} risk exceptions graded",
           f"{n['REVOKE']} to revoke, {n['REVIEW']} to review ({now} now, {n['REVIEW'] - now} housekeeping), {n['OK']} OK"]
    if d.get("partial"):
        out.insert(1, "PARTIAL RUN: a source failed, so some exceptions may be missing")
    try:
        ch = json.loads((run / "changes.json").read_text())
    except (OSError, ValueError):
        ch = None
    if ch:
        prev = str(ch.get("previous_today", ""))
        prev = prev if re.fullmatch(r"\d{4}-\d{2}-\d{2}", prev) else "the last run"
        out += ["", f"Since {prev}: {len(ch['escalated'])} got worse, {len(ch['new_evidence'])} gained evidence, "
                    f"{len(ch['new'])} new, {len(ch['eased'])} eased, {len(ch['gone'])} gone"]
        worse = [f"- {_id(e['rule_id'])}: {e.get('was') or 'new'} to {e['now']} ({_codes(e.get('new_triggers') or [])})"
                 for e in ch["escalated"] if re.fullmatch(r"[A-Z]+", str(e.get("now", "")))
                 and re.fullmatch(r"[A-Z]*", str(e.get("was") or ""))]
        if worse:
            out += ["Got worse:"] + _some(worse)
    revokes = [f"- {_id(f['exception']['rule_id'])}: {_cves(f['exception'].get('cves')) or 'no CVE'} "
               f"({_codes(f['triggers'])})" for f in fs if f["grade"] == "REVOKE"]
    if revokes:
        out += ["", "To revoke:"] + _some(revokes)
    out += ["", "Full report: report.html in the run folder. Nothing was changed in the scanner."]
    return "\n".join(out)


def _send(url: str, body: dict) -> int:
    import requests
    resp = requests.post(url, json=body, timeout=15)
    resp.raise_for_status()
    return resp.status_code


def post(run_dir: Path, url: str) -> None:
    """Post the run's message to an https webhook. Errors never repeat the URL: a webhook URL is a secret."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise RuntimeError("the webhook URL must be an https:// address")
    try:
        _send(url, {"text": build_message(run_dir)})
    except Exception as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        raise RuntimeError(f"the webhook did not take the message ({type(exc).__name__}"
                           + (f", HTTP {status}" if status else "") + ")") from None
