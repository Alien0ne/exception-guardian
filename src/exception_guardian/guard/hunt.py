"""Hunt briefs: one per REVOKE exception, built from findings.json data with string.Template."""
from __future__ import annotations

from datetime import date
from pathlib import Path
from string import Template

from ..report import LIST_SHOWN, code_span, md_escape

HOSTS_LISTED = 50  # host lines in a brief; a blanket rule can cover thousands
SHORT_WINDOW = 30  # days: a window this short is only the exception's age, not how long the hosts were exposed

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"


def _template(name: str) -> Template:
    return Template((TEMPLATES / name).read_text())


def _short(msg: str | None, limit: int = 90) -> str:
    msg = (msg or "").split(". ")[0]
    return msg if len(msg) <= limit else msg[:limit - 1] + "…"


_ORIGIN = {"drafted": "drafted", "sigmahq": "SigmaHQ rule", "generic": "generic SigmaHQ rule"}


def tested_label(r: dict) -> str:
    """How a rule did on the labelled sample logs, or why it could not be tested."""
    t = r.get("tested") or {}
    name = _ORIGIN.get(r["origin"], r["origin"])
    if not t.get("tested"):
        if r["origin"] == "drafted":
            why = f" ({md_escape(t['reason'])})" if t.get("reason") else ""
            return f"drafted — validated for syntax and conversion, not tested against logs{why}"
        return f"{name}, not tested: {md_escape(t.get('reason', 'no sample logs'))}" if t else name
    where = "agent-written sample logs" if t.get("agent_events") else "synthetic sample logs"
    s = (f"{name}, tested on {where}: fires on {t['attack_hits']} of {t['attack_total']} attack samples, "
         f"{t['benign_hits']} of {t['benign_total']} benign")
    if t["benign_hit_notes"]:
        s += " (" + ", ".join(md_escape(n) for n in t["benign_hit_notes"]) + ")"
    return s


def no_valid_draft_notes(entry: dict) -> list[str]:
    """Notes for CVEs whose drafts were all dropped, and for CVEs no log can show."""
    return ([f"{c}: no valid rule drafted, so generic behaviour rules are attached" for c in entry.get("no_valid_draft", [])]
            + [f"{n['cve']}: no log can show it ({n['reason']}). Patch or mitigate it instead."
               for n in entry.get("not_loggable", [])])


def _host(a: dict) -> str:
    ips = ", ".join(a.get("ips") or [])
    return f"- {md_escape(a['name'])} ({md_escape(a.get('os') or 'unknown OS')}" + (f", IPs {md_escape(ips)})" if ips else ")")


def _infra(items: list[dict]) -> tuple[str, str]:
    """The Known infrastructure section and the prompt line: the DCs the detections treat as yours."""
    if not items:
        return "", ""
    lines = []
    for i in items:
        if i["values"]:
            vals = ", ".join(code_span(v) for v in i["values"])
            lines.append(f"- {i['label']} (`%{i['name']}%`, from {i['source']}): {vals}")
        else:
            lines.append(f"- {i['label']} (`%{i['name']}%`): not set, so its filter excludes nothing and the "
                         "detections flag your real DCs too. Run `exception-guardian dcs --run <run>` to find them, "
                         "or set it in `placeholders.local.yaml`")
    section = ("\n## Known infrastructure\n\nThe detections below treat these as your domain controllers. Activity "
               "by the DC accounts from the DC addresses is expected; the same accounts from any other address are "
               "what the rules look for.\n\n" + "\n".join(lines) + "\n")
    accounts = next((i["values"] for i in items if "accounts" in i["label"] and i["values"]), [])
    ips = next((i["values"] for i in items if i["name"] == "dc_ip_addresses" and i["values"]), [])
    prompt = ""
    if accounts:
        prompt = (f"\n> Known DCs: {', '.join(md_escape(a) for a in accounts)}"
                  + (f" at {', '.join(md_escape(x) for x in ips)}" if ips else "")
                  + ". Their own activity is expected; the same accounts from any other address are the attack.")
    return section, prompt


def render_hunt_brief(finding: dict, rules: list[dict], lookback_start: date, today: date | None = None,
                      notes: list[str] | None = None, unloggable: bool = False, infra: list[dict] | None = None) -> str:
    """unloggable: no log can show any CVE that needs a rule, so the brief asks for a patch instead of a hunt."""
    exc = finding["exception"]
    today = today or date.today()
    assets = finding.get("assets") or []
    hosts = [a["name"] for a in assets] or list(exc.get("targets", []))
    lines = [_host(a) for a in assets[:HOSTS_LISTED]] or [f"- {md_escape(t)} (not in asset inventory)"
                                                          for t in hosts[:HOSTS_LISTED]]
    if len(hosts) > HOSTS_LISTED:
        lines.append(f"- and {len(hosts) - HOSTS_LISTED:,} more (every one is in findings.json)")
    host_lines = "\n".join(lines) or "- none"
    more = len(hosts) - LIST_SHOWN
    hosts_text = ", ".join(hosts[:LIST_SHOWN]) + (f" and {more:,} more" if more > 0 else "")
    evidence = "\n".join(
        f"| {t['code']} | {md_escape(t['then']) if t.get('then') else '—'} | {md_escape(t['now'])} | {md_escape(t['source'])} |"
        for t in finding.get("triggers", []))
    det: list[str] = []
    for r in rules:
        origin = tested_label(r) if r.get("file") else r["origin"]
        line = f"- {md_escape(r['title'])} ({origin}"
        line += f", {r['url']})" if r.get("url") else ")"  # pinned URL from the bundled index: trusted
        if r.get("file") is None:
            line += " — SigmaHQ rule not bundled, so fetch it from the link"
        det.append(line)
        for target, c in sorted(r.get("conversions", {}).items()):
            det.append((f"  - {target}: `{c['file']}`" + (f" ({md_escape(c['note'])})" if c.get("note") else ""))
                       if c["ok"] else f"  - {target}: {md_escape(_short(c['error']))}")
    all_cves = list(exc.get("cves", []))
    more_cves = len(all_cves) - LIST_SHOWN
    cves = md_escape(", ".join(all_cves[:LIST_SHOWN]) + (f" and {more_cves:,} more" if more_cves > 0 else "")
                     or "no CVE (exclusion)")
    days = (today - lookback_start).days
    window_note = ("" if days >= SHORT_WINDOW else
                   f" That is only the exception's age ({days} day{'s' if days != 1 else ''}). The hosts were exposed "
                   "before the exception hid the finding, so widen the window back to when Tenable first found it.")
    infra_section, infra_prompt = _infra(infra or [])
    return _template("hunt_brief_nolog.md" if unloggable else "hunt_brief.md").substitute(
        infra_section=infra_section, infra_prompt=infra_prompt,
        rule_id=md_escape(exc["rule_id"]), rule_code=code_span(exc["rule_id"]), source=md_escape(exc["source"]), rule_type=md_escape(exc["rule_type"]),
        cves=cves, hosts=md_escape(hosts_text or "unknown hosts"), host_lines=host_lines, window_note=window_note,
        evidence_rows=evidence or "| — | — | — | — |", window_start=lookback_start.isoformat(),
        window_end=today.isoformat(),
        detection_lines="\n".join(det + [f"- {md_escape(n)}" for n in notes or []]) or "- none available")
