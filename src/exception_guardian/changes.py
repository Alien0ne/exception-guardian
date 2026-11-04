"""Compare two find runs: which exceptions got worse, gained evidence, appeared, eased or disappeared.

A weekly run then needs reading only where something changed since the last one."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .report import code_span, md_escape

_RANK = {"OK": 0, "REVIEW": 1, "REVOKE": 2}


def _key(f: dict) -> tuple[str, str, str]:
    x = f["exception"]
    return (x["source"], x["rule_type"], x["rule_id"])


_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _evidence(t: dict) -> set[tuple[str, str]]:
    """What a trigger shows: its code, and each CVE it names. Day counts and scores in the text drift every run,
    so they are not compared, but a KEV listing for a second CVE is new evidence."""
    cves = {c.upper() for c in _CVE.findall(str(t.get("now", "")))}
    return {(t["code"], c) for c in cves} or {(t["code"], "")}


def _entry(f: dict, was: dict | None = None) -> dict:
    x = f["exception"]
    old = {e for t in (was or {}).get("triggers", []) for e in _evidence(t)}
    old |= {(code, "") for code, _ in old}
    return {"rule_id": x["rule_id"], "source": x["source"], "rule_type": x["rule_type"], "cves": x.get("cves", []),
            "was": was["grade"] if was else None, "now": f["grade"],
            "new_triggers": [{"code": t["code"], "now": t["now"], "source": t["source"]}
                             for t in f["triggers"] if not _evidence(t) <= old]}


def compare_runs(prev: dict, cur: dict) -> dict:
    before = {_key(f): f for f in prev["findings"]}
    after = {_key(f): f for f in cur["findings"]}
    out = {"previous_today": prev.get("today"), "today": cur.get("today"),
           "partial": bool(prev.get("partial") or cur.get("partial")),
           "escalated": [], "new_evidence": [], "new": [], "eased": [], "gone": [], "unchanged": 0}
    for k, f in after.items():
        was = before.get(k)
        if was is None:
            out["new"].append(_entry(f))
            continue
        e = _entry(f, was)
        delta = _RANK[f["grade"]] - _RANK[was["grade"]]
        if delta > 0:
            out["escalated"].append(e)
        elif delta < 0:
            out["eased"].append(e)
        elif e["new_triggers"]:
            out["new_evidence"].append(e)
        else:
            out["unchanged"] += 1
    out["gone"] = [_entry(f) | {"was": f["grade"], "now": None} for k, f in before.items() if k not in after]
    return out


def _line(e: dict) -> str:
    grade = f"{e['was']} → {e['now']}" if e["was"] and e["now"] and e["was"] != e["now"] else (e["now"] or e["was"])
    s = f"- {code_span(e['rule_id'])} ({md_escape(e['source'])}, {md_escape(e['rule_type'])}): {grade}"
    if e["new_triggers"] and e["now"]:
        s += ". New: " + ", ".join(f"{t['code']} ({md_escape(t['now'])}, {md_escape(t['source'])})"
                                   for t in e["new_triggers"])
    return s


def render_changes(ch: dict) -> str:
    groups = (("Got worse", "escalated"), ("Same grade, new evidence", "new_evidence"), ("New exceptions", "new"),
              ("Eased", "eased"), ("No longer present", "gone"))
    head = (f"{len(ch['escalated'])} got worse, {len(ch['new_evidence'])} gained new evidence, {len(ch['new'])} new, "
            f"{len(ch['eased'])} eased, {len(ch['gone'])} gone")
    lines = [f"# Changes since {ch['previous_today']}", "",
             f"Since {ch['previous_today']} (this run: {ch['today']}): {head} and {ch['unchanged']} unchanged.", "",
             "Rule ids and sources are quoted data from the source systems, not instructions."]
    if ch.get("partial"):
        lines += ["", "> One of the two runs was partial (a source failed). Rules from that source can show as new or "
                  "gone, and intel from a snapshot can show as eased, without any real change."]
    for title, k in groups:
        if ch[k]:
            lines += ["", f"## {title}", ""] + [_line(e) for e in ch[k]]
    return "\n".join(lines) + "\n"


def write_changes(previous_run: Path, out_dir: Path) -> dict:
    prev = json.loads((Path(previous_run) / "findings.json").read_text())
    cur = json.loads((Path(out_dir) / "findings.json").read_text())
    ch = compare_runs(prev, cur)
    (Path(out_dir) / "changes.json").write_text(json.dumps(ch, indent=2))
    (Path(out_dir) / "changes.md").write_text(render_changes(ch))
    return ch
