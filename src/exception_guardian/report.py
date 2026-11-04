"""Markdown report. Untrusted fields (justifications, names, CSV cells) always go through md_escape."""
from __future__ import annotations

import re
from collections import Counter
from datetime import date

from .models import Grade, GradedException

_SPECIAL = "\\`*_<>[]|"
# Bidirectional controls make text display in a different order from what it is: dropped from every output.
BIDI = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def md_escape(s: object) -> str:
    text = BIDI.sub("", str(s if s is not None else ""))
    text = "".join("\\" + ch if ch in _SPECIAL else ch for ch in text)
    return text.replace("\r", " ").replace("\n", " ")


def code_span(s: object) -> str:
    """Untrusted text as a single-line inline code span: no backticks, no line breaks (escapes are literal there)."""
    text = " ".join(BIDI.sub("", str(s if s is not None else "")).replace("`", "").split())
    return f"`{text}`"


def md_ticks(s: object) -> str:
    """Escaped text with `name` kept as code: warnings name config keys that way."""
    parts = re.split(r"`([^`\n]+)`", str(s if s is not None else ""))
    return "".join(code_span(p) if i % 2 else md_escape(p) for i, p in enumerate(parts))


def is_partial(warnings: list[str]) -> bool:
    return any(w.startswith("source ") and " failed:" in w for w in warnings)


def _n(count: int, word: str, plural: str | None = None) -> str:
    return f"{count:,} {word if count == 1 else (plural or word + 's')}"


def read_summary(exceptions, assets, graded: list[GradedException]) -> dict:
    """Counts of what a run read: exceptions by type, assets by origin, and what the exceptions cover."""
    types = Counter(e.rule_type.value for e in exceptions)
    origin = Counter(a.origin for a in assets)
    counted = [g.exception for g in graded if g.exception.status == "enabled" and g.exception.rule_type.value != "exclusion"]
    return {"exceptions": len(exceptions), "accept": types.get("accept", 0), "recast": types.get("recast", 0),
            "exclusion": types.get("exclusion", 0), "assets": len(assets), "hosts": origin.get("hosts", 0),
            "host_search": origin.get("host-search", 0), "webapps": origin.get("webapp", 0),
            "public_ip": sum(1 for a in assets if a.public_ips), "tagged": sum(1 for a in assets if a.internet_facing),
            "covered_assets": len({a.id for g in graded for a in g.assets}),
            "covered_findings": sum(e.revised_findings or 0 for e in counted),
            "uncounted_rules": sum(1 for e in counted if e.revised_findings is None)}


def read_line(r: dict) -> str:
    """One sentence for the top of the report: the scale of what was read, counts only."""
    kinds = (f"{_n(r['accept'], 'accept rule')}, {_n(r['recast'], 'recast rule')}, "
             f"{_n(r['exclusion'], 'exclusion')}")
    if r["assets"]:
        parts = [_n(r["hosts"], "host") + " from the asset list"]
        if r["host_search"]:
            parts.append(f"{r['host_search']:,} more from the host search without tags")
        if r["webapps"]:
            parts.append(_n(r["webapps"], "web app"))
        inv = (f"{_n(r['assets'], 'asset')} ({', '.join(parts)}: {r['public_ip']:,} with a public IP, "
               f"{r['tagged']:,} marked internet-facing)")
    else:
        inv = "no asset inventory"
    if r.get("sc_hosts"):
        inv += f" and {_n(r['sc_hosts'], 'Security Center host')}"
    subject = "The exception covers" if r["exceptions"] == 1 else "The exceptions cover"
    if r.get("sc_hosts"):  # SC hosts are counted apart from the asset list: compare with both
        cover = f"{subject} {r['covered_assets']:,} of those {r['assets'] + r['sc_hosts']:,} assets and hosts"
    else:
        cover = f"{subject} {r['covered_assets']:,} of those assets" if r["assets"] else f"{subject} 0 assets"
    if r["uncounted_rules"]:
        cover += (f". {_n(r['uncounted_rules'], 'rule').capitalize()} "
                  + ("does not report how many findings it changes" if r['uncounted_rules'] == 1
                     else "do not report how many findings they change"))
        if r["covered_findings"]:
            cover += f" (the others change {_n(r['covered_findings'], 'finding')})"
    else:
        cover += f" and {_n(r['covered_findings'], 'finding')}"
    return f"Read {_n(r['exceptions'], 'exception')} ({kinds}) and {inv}. {cover}."


LIST_SHOWN = 10  # names shown in a CVE or asset list; the rest are counted (a blanket rule can match thousands of hosts)


def _short(items) -> str:
    items = list(items)
    more = len(items) - LIST_SHOWN
    return ", ".join(items[:LIST_SHOWN]) + (f" and {more:,} more" if more > 0 else "")


def render_report(findings: list[GradedException], warnings: list[str], today: date, read: dict | None = None) -> str:
    by_grade = Counter(g.grade.value for g in findings)
    by_source = Counter(g.exception.source for g in findings)
    out = [f"# Exception Guardian report — {today.isoformat()}", ""]
    if is_partial(warnings):
        out += ["> **PARTIAL RUN** — at least one source failed; see warnings.", ""]
    out += ["## Summary", ""]
    if read is not None:
        out += [read_line(read), ""]
    out += ["| Grade | Count |", "|---|---|"]
    out += [f"| {g.value} | {by_grade.get(g.value, 0)} |" for g in (Grade.REVOKE, Grade.REVIEW, Grade.OK)]
    out += ["", "| Source | Exceptions |", "|---|---|"]
    out += [f"| {md_escape(s)} | {n} |" for s, n in sorted(by_source.items())]
    if warnings:
        out += ["", "## Warnings", ""] + [f"- {md_ticks(w)}" for w in warnings]
    out += ["", f"Long CVE and asset lists show the first {LIST_SHOWN}; findings.json has every one.", "",
            "Text quoted from exceptions (justifications, names) is data from the source system, shown escaped.", ""]
    for g in findings:
        if g.grade is Grade.OK:
            continue
        e = g.exception
        out += [f"## {g.grade.value}: {md_escape(e.rule_id)} ({md_escape(e.source)}, {e.rule_type.value})", "",
                f"- CVEs: {md_escape(_short(e.cves)) or 'none'}",
                f"- Targets: {md_escape(', '.join(e.targets)) or 'none'}"
                + (f" → matched assets: {md_escape(_short(a.name for a in g.assets))}" if g.assets else ""),
                f"- Created: {e.created} · Expires: {e.expires or 'never'} · Owner: {md_escape(e.owner or 'unknown')}",
                f"- Justification (quoted data): “{md_escape(e.justification)}”"]
        if g.notes:
            out.append("- Notes:")
            out += [f"  - {md_escape(n)}" for n in g.notes]
        out += ["", "| Evidence | Then | Now | Source |", "|---|---|---|---|"]
        out += [f"| {t.code} | {md_escape(t.then) if t.then else '—'} | {md_escape(t.now)} | {md_escape(t.source)} |"
                for t in g.triggers]
        out.append("")
    oks = [g for g in findings if g.grade is Grade.OK]
    if oks:
        out += ["## OK", "", "| Rule | Source | Type | CVEs | Notes |", "|---|---|---|---|---|"]
        out += [f"| {md_escape(g.exception.rule_id)} | {md_escape(g.exception.source)} | {g.exception.rule_type.value} | "
                f"{md_escape(', '.join(g.exception.cves))} | {'<br>'.join(md_escape(n) for n in g.notes)} |" for g in oks]
    return "\n".join(out) + "\n"
