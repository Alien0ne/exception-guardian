"""One self-contained HTML page for a run: the lead exception, what changed, every exception, hunt queries, the plan.

Every value from a source system (rule ids, names, justifications, owners, query text) is untrusted: it is escaped
with html.escape and never used in an id, class or URL. Styles are inlined from templates/report.css and the
Geologica typeface is embedded, so the page makes no request.
"""
from __future__ import annotations

import base64
import json
import re
from datetime import date
from html import escape
from pathlib import Path

from .approval import _resurfaces, is_auto, shown
from .report import BIDI, _n, read_line
from .guard.convert import LABEL as SIEM  # one label map for every page and handoff
from .guard.run import needs_rule, safe_name

CSS = Path(__file__).parent / "templates" / "report.css"
GRADE_WORD = {"REVOKE": "Revoke", "REVIEW": "Review", "OK": '<abbr title="no trigger fired">OK</abbr>'}
# Geologica (SIL OFL 1.1, templates/geologica-OFL.txt), Latin subset, inside the page: opening a report makes
# no request, so it reads the same offline and tells no font server that a report was opened
FONT = ("<style>@font-face { font-family: \"Geologica\"; font-style: normal; font-weight: 200 600; "
        "font-display: swap; src: url(data:font/woff2;base64,"
        + base64.b64encode((CSS.parent / "geologica-latin.woff2").read_bytes()).decode() + ") format('woff2'); }</style>")
HL_HEAD = "<script>document.documentElement.classList.add('js-hl')</script>"
HL_JS = """<script>
(() => {
  // replays: a phrase fills once it is fully in view and resets once it has fully left, so it behaves the same
  // scrolling down or up; the top bar's height counts as out of view while the bar is pinned
  const marks = [...document.querySelectorAll('.hl')];
  if (!('IntersectionObserver' in window)) { marks.forEach((m) => m.classList.add('is-active')); return; }
  const bar = document.querySelector('.topbar');
  const top = bar && getComputedStyle(bar).position === 'sticky' ? bar.offsetHeight : 0;
  const io = new IntersectionObserver((entries) => entries.forEach((en) => {
    if (en.intersectionRatio >= 0.9) en.target.classList.add('is-active');
    else if (!en.isIntersecting) en.target.classList.remove('is-active');
  }), { threshold: [0, 0.9], rootMargin: `-${top}px 0px 0px 0px` });
  marks.forEach((m) => io.observe(m));
})();
</script>"""
SHOWALL_JS = """<script>
// the asset table starts with its worst ten; the rest are in the same table (visible without script)
document.querySelectorAll('.show-all').forEach((b) => {
  const rows = b.closest('section').querySelectorAll('tr.extra');
  const label = b.textContent;
  rows.forEach((r) => { r.hidden = true; });
  b.hidden = false;
  b.setAttribute('aria-expanded', 'false');
  b.addEventListener('click', () => {
    const open = b.getAttribute('aria-expanded') !== 'true';
    rows.forEach((r) => { r.hidden = !open; });
    b.setAttribute('aria-expanded', String(open));
    b.textContent = open ? 'Show the worst ten only' : label;
  });
});
</script>"""
COPY_JS = """<script>
document.querySelectorAll('.copy').forEach((b) => {
  b.hidden = false;
  b.addEventListener('click', async () => {
    const text = b.parentElement.querySelector('pre').innerText;
    b.disabled = true;
    try { await navigator.clipboard.writeText(text); b.textContent = 'Copied'; }
    catch { b.textContent = 'Select and copy'; }
    setTimeout(() => { b.textContent = 'Copy'; b.disabled = false; }, 1600);
  });
});
</script>"""


def _hl(text: str) -> str:
    """A marked phrase, one span per word: lit by default; with script, its words light up in turn as it comes into view."""
    words = text.split(" ")
    spans = "".join(f'<span class="w" style="--i: {i}">{e(w)}{" " if i < len(words) - 1 else ""}</span>'
                    for i, w in enumerate(words))
    return f'<mark class="hl">{spans}</mark>'


def e(s: object) -> str:
    return escape(BIDI.sub("", str(s if s is not None else "")), quote=True)


def _ticks(s: object) -> str:
    """Escaped text with `name` shown as code: warnings are written once for report.md and the page."""
    return re.sub(r"`([^`<>]+)`", r"<code>\1</code>", e(s))


def _code(s: object) -> str:
    return f"<code>{e(s)}</code>"


def _trig(code: str) -> str:
    """A trigger name that may wrap only after an underscore: JUSTIFICATION_ / CONTRADICTED, never mid-word."""
    return f'<code class="trig">{e(code).replace("_", "_<wbr>")}</code>'


SECTIONS = (("lead-h", "Revoke first"), ("changes-h", "Changes"), ("ctx-h", "Assets"), ("all-h", "All exceptions"),
            ("hunt-h", "Hunt queries"), ("plan-h", "Plan"), ("next-h", "Next step"))
SOURCE_NAME = {"tenable-vm": "Tenable VM", "tenable-sc": "Tenable SC"}
ACCORDION_JS = """<script>
// one exception open at a time: details name=... does it natively. ACCORDION_FALLBACK closes the others in a
// browser without it. Closing a row above moves the page, so the row just opened is brought back into view
(() => {
  const native = 'name' in HTMLDetailsElement.prototype;
  document.addEventListener('toggle', (ev) => {
    const d = ev.target;
    if (!(d instanceof HTMLDetailsElement) || !d.open || !d.getAttribute('name')) return;
    if (!native) {  // ACCORDION_FALLBACK
      document.querySelectorAll(`details[name="${CSS.escape(d.getAttribute('name'))}"][open]`).forEach((o) => {
        if (o !== d) o.open = false;
      });
    }
    const top = d.querySelector('summary').getBoundingClientRect().top;
    if (top < 0 || top > innerHeight) d.querySelector('summary').scrollIntoView({ block: 'start' });
  }, true);
})();
</script>"""

SPY_JS = """<script>
(() => {
  // current = the last section whose top has passed the line; at the very bottom, the last section
  const links = [...document.querySelectorAll('.sections a')];
  const secs = links.map((a) => document.getElementById(a.hash.slice(1))?.closest('section'));
  if (!links.length || secs.some((x) => !x)) return;
  const pick = () => {
    // a link click parks its heading at the page's scroll padding, so the line sits just below that
    const line = (parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) || 0) + 8;
    let cur = -1;
    secs.forEach((x, i) => { if (x.getBoundingClientRect().top <= line) cur = i; });
    if (innerHeight + scrollY >= document.documentElement.scrollHeight - 2) cur = secs.length - 1;
    links.forEach((a, i) => (i === cur ? a.setAttribute('aria-current', 'true') : a.removeAttribute('aria-current')));
  };
  let queued = false;
  addEventListener('scroll', () => { if (!queued) { queued = true; requestAnimationFrame(() => { queued = false; pick(); }); } }, { passive: true });
  addEventListener('resize', pick);
  pick();
})();
</script>"""


def _source_name(src: str) -> str:
    return f"CSV: {src[4:]}" if src.startswith("csv:") else SOURCE_NAME.get(src, src)


def _intel_chip(text: str) -> str:
    """'CISA KEV (snapshot:2026-11-02)' -> name plus a quieter 'snapshot 2 Nov 2026'."""
    m = re.match(r"^(.*?) \((\w+):(\d{4}-\d{2}-\d{2})\)$", text)
    if not m:
        return f'<li class="chip">{e(text)}</li>'
    return f'<li class="chip">{e(m[1])} <span>{e(m[2])} {e(_day(m[3]))}</span></li>'


def _day(s: str) -> str:
    d = date.fromisoformat(s)
    return f"{d.day} {d:%b %Y}"


def _grade(g: str) -> str:
    cls = g.lower() if g in GRADE_WORD else "unknown"  # a class name only from the known grades
    return f'<span class="grade {cls}">{GRADE_WORD.get(g, e(g))}</span>'


def _short(err: str | None) -> str:
    text = (err or "").removeprefix("unsupported: ")
    first = text.split(". ")[0].split(":  ")[0]
    return first if len(first) <= 110 else first[:107] + "…"


_UNREADABLE = re.compile(r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d+)$", re.I)


def rule_title(x: dict) -> str:
    """A readable name for a rule. Ids people chose (R-HERO-001) stay; a UUID or a bare number gets the rule's own
    name (Tenable VM rule_name) or one built from its CVE or plugin and its targets. The id stays in the facts."""
    rid = str(x["rule_id"])
    if not _UNREADABLE.match(rid):
        return rid
    name = str((x.get("raw") or {}).get("rule_name") or "").strip()
    if name and "<" not in name:
        return name
    what = (x["cves"][0] if len(x["cves"]) == 1 else f"plugin {x['plugin_ids'][0]}" if x.get("plugin_ids")
            else f"{len(x['cves'])} CVEs" if x["cves"] else "rule")
    targets = x.get("targets") or []
    where = "all assets" if "*" in targets else ", ".join(targets[:2]) + (" and more" if len(targets) > 2 else "")
    return f"{x['rule_type']} {what} on {where or 'unknown targets'}"


def owner_name(owner: str | None) -> str:
    """A Tenable user UUID is unreadable: 'user abcd1234'. Names and emails stay as given."""
    if not owner:
        return "an unknown owner"
    return f"user {owner[:8]}" if _UNREADABLE.match(owner) and "-" in owner else owner


CVE_SHOWN = 6  # past this, the lead and ledger rows say "and N more"; the row's facts keep every CVE


_STAND_IN = re.compile(r"%[^%\s]+%(, %[^%\s]+%)* (is|are) not set, so the filter uses the stand-in.*")


def _cves(cves: list, n: int = CVE_SHOWN, none: str = "none") -> str:
    shown = ", ".join(_code(c) for c in cves[:n]) or none
    return shown + (f" and {len(cves) - n} more" if len(cves) > n else "")


def _reason(x: dict) -> str:
    j = (x.get("justification") or "").strip()
    return (f'<span class="quote">&ldquo;{e(j)}&rdquo;</span>' if j
            else '<span class="noreason">No reason was given</span>')


def _evidence(triggers: list[dict]) -> str:
    rows = "".join(
        f'<tr><td data-label="Evidence">{_trig(t["code"])}</td><td class="then" data-label="Then">'
        f'{e(t.get("then") or "not recorded")}</td><td class="now" data-label="Now">{e(t["now"])}</td>'
        f'<td class="src" data-label="Source">{e(t["source"])}</td></tr>' for t in triggers)
    return ('<div class="scroll"><table class="stack"><thead><tr><th scope="col">Evidence</th><th scope="col">Then</th>'
            f'<th scope="col">Now</th><th scope="col">Source</th></tr></thead><tbody>{rows}</tbody></table></div>')


def _facts(x: dict) -> str:
    items = [("Rule", e(rule_title(x))), ("Rule id", _code(x["rule_id"])),
             ("Source", f'{e(x["source"])}, {e(x["rule_type"])}'),
             ("CVEs", ", ".join(_code(c) for c in x["cves"]) or "none"),
             ("Targets", ", ".join(e(t) for t in x["targets"]) or "none"),
             ("Accepted", e(x.get("created") or "unknown")), ("Owner", e(owner_name(x.get("owner")))),
             ("Justification", _reason(x))]
    if rule_title(x) == x["rule_id"]:
        items = items[:1] + items[2:]
        items[0] = ("Rule", _code(x["rule_id"]))
    return '<dl class="facts">' + "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in items) + "</dl>"


def _measure(f: dict) -> str:
    """The lead exception's one figure: its EPSS now against when it was accepted (the hero's dark block)."""
    x = f["exception"]
    epss = next((t for t in f["triggers"] if t["code"] in ("EPSS_HIGH", "EPSS_ROSE")), None)
    kev = sorted((i for i in f.get("intel") or [] if i.get("in_kev") and i.get("kev_date_added")),
                 key=lambda i: (not i.get("kev_ransomware"), i["kev_date_added"]))
    cve = x["cves"][0] if x["cves"] else None
    if epss and ": " in epss["now"]:  # multi-CVE rule: the row reads "CVE-…: 0.9"
        cve = epss["now"].split(": ", 1)[0]
        epss = {**epss, "now": epss["now"].split(": ", 1)[1],
                "then": (epss.get("then") or "").split(": ", 1)[-1] or None}
    if epss and epss.get("then") == epss["now"] and kev:
        epss = None  # accepted on today's score: nothing moved, so lead with the stronger fact
    if not epss and kev:
        i = kev[0]
        when = (f'Already in the list when the rule was accepted on {e(_day(x["created"]))}'
                if x.get("created") and x["created"] >= i["kev_date_added"] else "Added after the rule was accepted")
        body = (f'<p class="label">{_code(i["cve"])} has been in CISA&rsquo;s Known Exploited Vulnerabilities '
                f'list since</p><p class="figure">{e(_day(i["kev_date_added"]))}</p>'
                f'<p class="was">{"Used in ransomware. " if i.get("kev_ransomware") else ""}{when}</p>')
    elif epss:
        body = (f'<p class="label">Chance {_code(cve) if cve else "it"} is exploited in the next 30 '
                f'days (<abbr title="Exploit Prediction Scoring System">EPSS</abbr>), today</p>'
                f'<p class="figure">{e(epss["now"])}</p>'
                f'<p class="was">{e(epss.get("then") or "unknown")} when {e(rule_title(x))} was accepted</p>')
    else:
        body = (f'<p class="label">Evidence against {e(rule_title(x))}</p>'
                f'<p class="figure">{len(f["triggers"])}</p><p class="was">triggers fired</p>')
    return f'<div class="measure" data-theme="dark">{body}{_impact(f)}</div>'


def _impact(f: dict) -> str:
    """What the rule does today, in one or two sentences: what it hides, where, for how long, and how exposed."""
    x = f["exception"]
    n = x.get("revised_findings")
    hidden = "its findings" if n is None else f"{n} finding{'' if n == 1 else 's'}"
    targets = x.get("targets") or []
    where = ("all assets" if "*" in targets else ", ".join(targets[:3]) + (f" and {len(targets) - 3} more"
             if len(targets) > 3 else "")) or "its targets"
    out = [f"This rule hides {hidden} on {where} from the queue" + (", and it never expires" if not x.get("expires")
                                                                     else "") + "."]
    by = {t["code"]: t for t in f["triggers"]}
    path = by.get("ATTACK_PATH_CVE")
    if path and "attack path: " in path["now"]:
        steps = path["now"].split("attack path: ", 1)[1].split(" (priority")[0]
        cve = path["now"].split(" is used in", 1)[0] if " is used in" in path["now"] else "it"  # often not the lead CVE
        out.append(f"Tenable One shows an attack path using {cve}: {steps}.")
    if "INTERNET_FACING" in by:
        out.append(f"A covered asset is internet-facing now ({by['INTERNET_FACING']['source']}).")
    return f'<p class="impact">{e(" ".join(out))}</p>'


def _lead(f: dict) -> str:
    x = f["exception"]
    title = rule_title(x)
    named = title != x["rule_id"]
    facts = [(k, v) for k, v in (("Rule id" if named else "Rule", _code(x["rule_id"])),
             ("Source", f'{e(x["source"])}, {e(x["rule_type"])}'),
             ("CVEs", _cves(x["cves"])),
             ("Targets", ", ".join(e(t) for t in x["targets"]) or "none"))]
    dl = '<dl class="facts">' + "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in facts) + "</dl>"
    who = f'{e(x.get("created") or "an unknown date")} by {e(owner_name(x.get("owner")))}'
    j = (x.get("justification") or "").strip()
    quote = (f'<figure class="said"><blockquote><p>&ldquo;{e(j)}&rdquo;</p></blockquote>'
             f'<figcaption>The reason given on {who}</figcaption></figure>' if j else
             f'<figure class="said"><p class="noreason">No reason was given</p>'
             f'<figcaption>Accepted on {who} without a justification</figcaption></figure>')
    name = e(title) if named else _code(title)
    return (f'<section aria-labelledby="lead-h"><div class="section-head"><h2 id="lead-h">The exception to {_hl("revoke first")}'
            f'</h2><p>{_grade(f["grade"])} {name}: accepted '
            f'{"on the reasoning below" if j else "with no reason given"}. This is what the evidence says now.</p></div><div class="lead-grid">{dl}{quote}</div>{_evidence(f["triggers"])}</section>')


def _changes(ch: dict) -> str:
    groups = [("Got worse", ch["escalated"]), ("Same grade, new evidence", ch["new_evidence"]),
              ("New exceptions", ch["new"]), ("Eased", ch["eased"]), ("No longer present", ch["gone"])]
    rows = ""
    for label, items in groups:
        for c in items:
            moved = (f'{_grade(c["was"])} to {_grade(c["now"])}' if c.get("was") and c.get("now") and c["was"] != c["now"]
                     else _grade(c.get("now") or c.get("was") or ""))
            new = ", ".join(f'{_trig(t["code"])} {e(t["now"])}' for t in c.get("new_triggers", [])) or "none"
            rows += (f'<tr><td data-label="Change">{label}</td><td data-label="Rule">{_code(c["rule_id"])}</td>'
                     f'<td class="nowrap" data-label="Source">{e(c["source"])}</td><td class="nowrap" '
                     f'data-label="Grade">{moved}</td><td data-label="New evidence">{new}</td></tr>')
    counts = (f'{len(ch["escalated"])} got worse, {len(ch["new_evidence"])} gained new evidence, {len(ch["new"])} new, '
              f'{len(ch["eased"])} eased, {len(ch["gone"])} gone and {ch["unchanged"]} unchanged.')
    n_worse = len(ch["escalated"])
    worse = f"{n_worse} got worse" if n_worse else "nothing got worse"
    body = (('<div class="scroll"><table class="stack"><thead><tr><th scope="col">Change</th><th scope="col">Rule</th>'
             '<th scope="col">Source</th><th scope="col">Grade</th><th scope="col">New evidence</th></tr></thead>'
             f'<tbody>{rows}</tbody></table></div>') if rows else
            '<div class="empty"><p>Nothing changed since the last run.</p></div>')
    return (f'<section aria-labelledby="changes-h"><div class="section-head"><h2 id="changes-h">Since the last run, '
            f'{_hl(worse)}</h2><p>Compared with the run on {e(_day(ch["previous_today"]))}: {counts}</p></div>'
            f'{body}</section>')


CTX_ROWS = 10  # assets shown before "N more"; worst first (attack paths, then ACR, then AES)


def _context(findings: list[dict]) -> str:
    """What Tenable One (or the VM asset) says about each covered asset, visible without opening a row."""
    seen: dict[str, dict] = {}
    for f in findings:
        for a in f.get("assets") or []:
            if a.get("context_source") and a["id"] not in seen:
                seen[a["id"]] = a
    if not seen:
        return ""

    def score(v, top):
        return "not scored" if v is None else f"{v:g} of {top}"

    def paths(a):
        n = a.get("attack_paths")
        if n is None:
            return "not scored"
        if n == 0:
            return "none"
        return e(n) + (f" ({e(a['critical_paths'])} critical)" if a.get("critical_paths") else "")

    def row(a, extra=False):
        return (f'<tr{" class=\"extra\"" if extra else ""}><th scope="row">{e(a["name"])}</th>'
                f'<td data-label="ACR">{score(a.get("acr"), 10)}</td><td data-label="AES">{score(a.get("aes"), 1000)}'
                f'</td><td data-label="Attack paths">{paths(a)}</td><td data-label="Source">{e(a["context_source"])}'
                f'</td></tr>')

    def num(v):  # findings.json is a file: a value that is not a number sorts last instead of breaking the page
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) else 0

    ranked = sorted(seen.values(), key=lambda a: (-num(a.get("attack_paths")), -num(a.get("acr")),
                                                   -num(a.get("aes")), str(a["name"])))
    head = ('<thead><tr><th scope="col">Asset</th><th scope="col">ACR</th><th scope="col">AES</th>'
            '<th scope="col">Attack paths</th><th scope="col">Source</th></tr></thead>')
    rows = "".join(row(a) for a in ranked[:CTX_ROWS]) + "".join(row(a, extra=True) for a in ranked[CTX_ROWS:])
    more = (f'<p class="actions"><button type="button" class="btn btn--quiet show-all" hidden>Show all '
            f'{len(ranked)} assets</button></p>' if len(ranked) > CTX_ROWS else "")
    return (f'<section aria-labelledby="ctx-h"><div class="section-head"><h2 id="ctx-h">What Tenable One says about '
            f'{_hl("the covered assets")}</h2><p>Criticality (ACR), exposure (AES) and attack paths for every asset an '
            f'exception covers, worst first. An ACR at or above <code>critical_acr</code> (9 by default) or any attack path grades REVOKE.</p></div>'
            f'<div class="scroll"><table class="stack">{head}<tbody>{rows}</tbody></table></div>{more}</section>')


GROUP_MIN = 8  # this many non-REVOKE rules with the same source and evidence are shown as one group
GROUP_ROWS = 50


def _row(f: dict) -> str:
    x = f["exception"]
    n = len(f["triggers"])
    body = (_evidence(f["triggers"]) if f["triggers"] else '<p class="muted">No trigger fired.</p>')
    checked = ("(Tenable One inventory)", "(Tenable VM asset)")
    notes = "".join(f'<li>{"Checked: " if note.endswith(checked) else ""}{e(note)}</li>' for note in f.get("notes") or [])
    body += f'<ul class="notes">{notes}</ul>' if notes else ""
    title = rule_title(x)
    name = _code(title) if title == x["rule_id"] else e(title)
    return (f'<details name="exceptions"><summary>{_grade(f["grade"])}<span>{name}</span>'
            f'<span class="hide-s">{e(x["source"])}, {e(x["rule_type"])}</span>'
            f'<span class="hide-s">{_cves(x["cves"], none="no CVE")}</span>'
            f'<span class="n hide-s">{n}</span><span class="plus" aria-hidden="true"></span></summary>'
            f'<div class="body">{_facts(x)}{body}</div></details>')


def _group_key(f: dict):
    return (f["grade"], f["exception"]["source"], tuple(sorted({t["code"] for t in f["triggers"]})))


def _group_cves(fs: list[dict]) -> str:
    """The group's CVEs, or how few rules name any: one CVE must not stand for 14 rules when 13 have none."""
    cves = list(dict.fromkeys(c for f in fs for c in f["exception"]["cves"]))
    named = sum(1 for f in fs if f["exception"]["cves"])
    if named in (0, len(fs)):
        return _cves(cves, none="no CVE")
    return f'{len(cves)} CVE{"s" if len(cves) != 1 else ""} in {named} of {len(fs)} rules'


def _group(fs: list[dict]) -> str:
    """Many rules saying the same thing: one row with their shared evidence, then a short table of the rules."""
    first = fs[0]
    codes = sorted({t["code"] for t in first["triggers"]})
    src = _source_name(first["exception"]["source"])
    rows = "".join(f'<tr><th scope="row">{e(rule_title(f["exception"]))}</th>'
                   f'<td>{", ".join(_code(c) for c in f["exception"]["cves"]) or "none"}</td>'
                   f'<td>{e(f["exception"].get("created") or "unknown")}</td>'
                   f'<td>{_reason(f["exception"])}</td></tr>' for f in fs[:GROUP_ROWS])
    more = (f'<p class="muted">And {len(fs) - GROUP_ROWS} more. Every rule is in <code>findings.json</code> and '
            f'<code>report.md</code>.</p>' if len(fs) > GROUP_ROWS else "")
    shared = _evidence([{**t, "now": t["now"] if t["code"] != "TOO_OLD" else "older than the age limit"}
                        for t in {t["code"]: t for t in first["triggers"]}.values()])
    return (f'<details class="group" name="exceptions"><summary>{_grade(first["grade"])}<span>{len(fs)} {e(src)} rules with the '
            f'same evidence</span><span class="hide-s">{e(first["exception"]["source"])}</span>'
            f'<span class="hide-s">{_group_cves(fs)}</span>'
            f'<span class="n hide-s">{len(codes)}</span><span class="plus" aria-hidden="true"></span></summary>'
            f'<div class="body"><p>Each of these rules fired the same triggers:</p>{shared}'
            f'<div class="scroll"><table class="stack"><thead><tr><th scope="col">Rule</th><th scope="col">CVEs</th>'
            f'<th scope="col">Accepted</th><th scope="col">Justification</th></tr></thead><tbody>{rows}</tbody>'
            f'</table></div>{more}</div></details>')


def _ledger(findings: list[dict]) -> str:
    groups: dict = {}
    for f in findings:
        if f["grade"] != "REVOKE":
            groups.setdefault(_group_key(f), []).append(f)
    big = {k for k, v in groups.items() if len(v) >= GROUP_MIN}
    rows, done = "", set()
    for f in findings:
        k = _group_key(f)
        if k in big:
            if k not in done:
                rows += _group(groups[k])
                done.add(k)
            continue
        rows += _row(f)
    return (f'<section aria-labelledby="all-h"><div class="section-head"><h2 id="all-h">Every exception, '
            f'{_hl("worst first")}</h2><p>Open a row for its evidence.</p></div><div class="ledger"><div class="head" '
            f'aria-hidden="true"><span>Grade</span><span>Rule</span><span>Source</span><span>CVEs</span>'
            f'<span class="n">Triggers</span><span></span></div>{rows}</div></section>')


ORIGIN = {"drafted": ("Drafted for this CVE", " drafted"), "sigmahq": ("SigmaHQ", ""), "generic": ("Generic SigmaHQ", "")}


def _tested(t: dict | None) -> str:
    """The rule's result on the synthetic sample logs: a verdict, two scores and a bar of the share caught."""
    if not t or not t.get("tested"):
        why = e((t or {}).get("reason") or "no sample logs")
        return f'<div class="score"><p class="verdict none">Not tested</p><p class="muted">{why}.</p></div>'
    hits, total, bh, bt = t["attack_hits"], t["attack_total"], t["benign_hits"], t["benign_total"]
    anycve = t.get("attack_scope") == "any CVE"
    if total and anycve:  # it watches what any exploit does next: most of the CVEs' own attacks are not its job
        verdict = ("watch", f"Fires on {hits} attack sample{'' if hits == 1 else 's'}" if hits
                   else "Fired on no attack sample")
    elif not total:
        verdict = ("none", "No attack samples for its log source")
    elif hits == total:
        verdict = ("catch", "Catches all")
    elif hits:
        verdict = ("some", "Catches some")
    else:
        verdict = ("miss", "Misses all")
    share = hits / total if total else 0
    notes = "".join(f"<li>{e(n)}</li>" for n in t["benign_hit_notes"])
    scope = " (any CVE)" if t.get("attack_scope") == "any CVE" else ""
    if not scope:  # a rule watching for any CVE's aftermath is expected to miss most; its misses are no news
        notes += "".join(f"<li>Missed: {e(n)}</li>" for n in t.get("attack_missed_notes") or [])
        if t.get("attack_missed_notes") and t.get("agent_events"):
            notes += ("<li>Claude wrote these samples, so a miss can be the sample's fault: check the sample against "
                      "its write-up before you trust or drop the rule.</li>")
    if anycve:
        notes += ("<li>A generic rule watches for what any exploit does next (a web server starting a shell), so it "
                  "is not expected to catch each CVE's own attack samples.</li>")
    who = ('<p class="muted">Agent-written samples from public write-ups, not real logs.</p>'
           if t.get("agent_events") else "")
    return (f'<div class="score"><p class="verdict {verdict[0]}">{verdict[1]}</p><dl>'
            f'<div><dt>Attack samples caught{scope}</dt><dd><b>{hits}</b>/{total}</dd></div>'
            f'<div><dt>Benign events flagged</dt><dd{" class=\"warn\"" if bh else ""}><b>{bh}</b>/{bt}</dd></div></dl>'
            f'<span class="bar" role="img" aria-label="caught {hits} of {total} attack samples" '
            f'style="--p: {share:.2f}"></span>'
            + (f'<ul class="notes">{notes}</ul>' if notes else "") + who + "</div>")


def _target(run: Path, sid: str, name: str, c: dict) -> str:
    label, lang = SIEM.get(name, (name, ""))
    if c["ok"] and c.get("file"):
        folder = (run / "rules" / safe_name(sid)).resolve()
        q = (folder / str(c["file"])).resolve()
        # guard.json is a file in the run folder: a name pointing anywhere else is not read into the page
        text = q.read_text(errors="replace") if q.parent == folder and q.is_file() else ""
        return (f'<details class="target" name="q-{e(safe_name(sid))}"><summary><span>{e(label)}</span><span class="lang">{e(lang)}</span>'
                f'<span class="plus" aria-hidden="true"></span></summary><div class="query"><pre><code>{e(text)}'
                f'</code></pre><button type="button" class="copy" hidden>Copy</button></div>'
                + (f'<p class="muted qnote">{e(c["note"])}</p>' if c.get("note") else "") + '</details>')
    return (f'<div class="target off"><span>{e(label)}</span><span class="lang">no query: '
            f'{e(_short(c.get("error")))}</span></div>')


def _together(rules: list[dict]) -> str:
    """What a card's rules cover as a set: one rule's "no query for Sentinel" is no gap when another has one."""
    written = [r for r in rules if r.get("file")]
    if len(written) < 2:
        return ""
    names = list(dict.fromkeys(t for r in written for t in r["conversions"]))
    counts = [(SIEM.get(t, (t, ""))[0], sum(1 for r in written if (r["conversions"].get(t) or {}).get("ok")))
              for t in names]
    parts = [f"{label} ({n}{' rule' + ('s' if n != 1 else '') if i == 0 else ''})" for i, (label, n) in enumerate(counts)]
    none = [label for label, n in counts if n == 0]
    tested = [r["tested"] for r in written if (r.get("tested") or {}).get("tested") and r["tested"].get("attack_total")]
    caught = sum(1 for t in tested if t.get("attack_hits"))
    text = f"Together, {len(written)} rules give queries for {', '.join(parts)}"
    text += (f". No rule converts to {' or '.join(none)}" if none else "")
    text += (f". {caught} of {len(tested)} tested rules catch attack samples." if tested else ".")
    return f'<p class="together">{e(text)}</p>'


def _hunt_sum(rules: list[dict], not_loggable=None) -> str:
    n = len(rules)
    if not n:
        return "No log can show it" if not_loggable else "No rule yet"
    full = sum(1 for r in rules if (r.get("tested") or {}).get("attack_total")
               and r["tested"]["attack_hits"] == r["tested"]["attack_total"])
    caught = {0: "none catches", 1: "1 catches"}.get(full, f"{full} catch")
    return f'{n} rule{"" if n == 1 else "s"}, {caught} all attack samples'


def _hunt(run: Path, guard: dict, findings: list[dict] | None = None) -> str:
    """One block per exception, each opened by a dark numbered header; ids are positions, never source text."""
    by_key = {}
    for f in findings or []:
        x = f["exception"]
        by_key.setdefault((x.get("source"), x.get("rule_type"), x["rule_id"]), f)
        by_key.setdefault(x["rule_id"], f)
    arts, jump, total = "", "", len(guard)
    for i, (rid, entry) in enumerate(guard.items(), 1):
        f = by_key.get((entry.get("source"), entry.get("rule_type"), entry.get("rule_id"))) or by_key.get(rid)
        folder = str(entry.get("dir") or safe_name(rid))  # the folder guard wrote; older runs did not record it
        if f:
            key = needs_rule(f)
            ordered = sorted(f["exception"]["cves"], key=lambda c: c not in key)  # the CVEs behind the REVOKE first
            tags = (_grade(f["grade"]) + "".join(f" {_code(c)}" for c in ordered[:CVE_SHOWN])
                    + (f" and {len(ordered) - CVE_SHOWN} more" if len(ordered) > CVE_SHOWN else ""))
        else:
            tags = ""
        title = rule_title(f["exception"]) if f else rid
        name = _code(rid) if title == rid else e(title)
        head = (f'<header class="hunt-head" data-theme="dark"><p class="pos">{i} of {total}</p>'
                f'<h3 id="hunt-{i}-h">{name}</h3><p class="tags">{tags}</p>'
                f'<p class="sum">{e(_hunt_sum(entry.get("rules", []), entry.get("not_loggable")))}</p></header>')
        jump += f'<li><a href="#hunt-{i}">{name}</a></li>'
        rules = _together(entry.get("rules", []))
        for r in entry.get("rules", []):
            origin, cls = ORIGIN.get(r["origin"], (r["origin"], ""))
            link = (f'<a href="{e(r["url"])}">SigmaHQ source</a>' if str(r.get("url") or "").startswith(
                "https://github.com/") else "")
            targets = "".join(_target(run, folder, n, c) for n, c in r["conversions"].items())
            # an unset filter value (stand-in): the query runs but is noisy, which the reader must see unopened
            noisy = next((m.group(0) for c in r["conversions"].values()
                          if (m := _STAND_IN.search(c.get("note") or ""))), "")
            rules += (f'<div class="rule"><div class="rule-text"><span class="origin{cls}">{e(origin)}</span>'
                      f'<h4>{e(r["title"])}</h4>{f"<p class=\"meta\">{link}</p>" if link else ""}'
                      f'{f"<p class=\"muted\">{e(noisy)}</p>" if noisy else ""}</div>'
                      f'{_tested(r.get("tested"))}<div class="targets">{targets}</div></div>')
        nolog = "".join(f'<li>No log can show <code>{e(n["cve"])}</code>: {e(n["reason"].rstrip("."))}. '
                        'Patch or mitigate it instead.</li>' for n in entry.get("not_loggable") or [])
        rules += f'<ul class="nolog">{nolog}</ul>' if nolog else ""
        for g in entry.get("coverage_gaps") or []:
            rules += (f'<p class="muted">SigmaHQ leaves a gap for {_code(g["cve"])}: {e(g["reason"].replace("; ", ", and "))}. '
                      'Claude is asked to draft one rule that closes it.</p>')
        missing = entry.get("missing_drafts") or []
        if missing:
            rules += f'<p class="muted">Still no rule for {_cves(missing)}.</p>'
        quiet = entry.get("not_drafted") or []
        if quiet:
            rules += (f'<p class="muted">{len(quiet)} other CVE{"s" if len(quiet) != 1 else ""} in this rule '
                      f'({_cves(quiet)}) {"are" if len(quiet) != 1 else "is"} not in KEV, below the EPSS line and on '
                      f'no attack path, so no rule was drafted for {"them" if len(quiet) != 1 else "it"}.</p>')
        arts += (f'<article id="hunt-{i}" aria-labelledby="hunt-{i}-h">{head}<div class="hunt-body">'
                 f'{rules or "<p class=\"muted\">No rule for this exception.</p>"}</div></article>')
    nav = (f'<nav class="jump" aria-label="Exceptions with hunt queries"><ul>{jump}</ul></nav>' if total > 1 else "")
    return (f'<section aria-labelledby="hunt-h"><div class="section-head"><h2 id="hunt-h">Hunt queries for '
            f'{_hl("the accepted window")}</h2><p>For each exception to revoke: look back over the time it was accepted. Review drafted rules '
            f'before you run them.</p></div>{nav}<div class="hunt">{arts}</div></section>')


def _plan(run: Path, findings: list[dict], base_url: str | None = None) -> str:
    items = ""
    tickets = 0
    for f in findings:
        if f["grade"] != "REVOKE":
            continue
        x = f["exception"]
        tickets += not is_auto(f)
        mode = ('<span class="mode auto">auto</span>' if is_auto(f) else '<span class="mode">ticket</span>')
        title = rule_title(x)
        items += (f'<li><span>{_code(title) if title == x["rule_id"] else e(title)} <span class="src">'
                  f'{e(x["source"])}</span></span>{mode}<span class="why">disabling '
                  f're-surfaces {e(_resurfaces(x))}</span></li>')
    rest = ("The rest need a ticket (text in <code>approval-plan.md</code>)." if tickets else
            "None needs a ticket; the ticket text is in <code>approval-plan.md</code> all the same.")
    return (f'<section aria-labelledby="plan-h"><div class="section-head"><h2 id="plan-h">Approval plan, '
            f'{_hl("nothing changed yet")}</h2><p>Nothing has been changed. Apply mode disables only the rules marked auto, one at a time, after you confirm '
            f'each. {rest}</p></div><div class="plan"><ul>'
            f'{items}</ul></div><pre class="cmd"><code>exception-guardian approve --run {e(shown(run))} --apply --base-url '
            f'{e(base_url or "<your Tenable VM URL>")}</code></pre></section>')


def _nothing_to_revoke(findings: list[dict]) -> str:
    review = sum(1 for f in findings if f["grade"] == "REVIEW")
    which = (f"The {_n(review, 'exception')} graded REVIEW {'needs' if review == 1 else 'need'} a person to decide. "
             "Apply mode never touches them."
             if review else "Every exception passed its checks.")
    return (f'<section aria-labelledby="next-h"><div class="section-head"><h2 id="next-h">Nothing to revoke, so '
            f'nothing to hunt or apply</h2></div><div class="empty"><p>No exception is graded REVOKE, so guard wrote no '
            f'hunt queries and the plan disables nothing. {e(which)}</p></div></section>')


def _next_step(run: Path) -> str:
    return (f'<section aria-labelledby="next-h"><div class="section-head"><h2 id="next-h">Detections and the plan'
            f'</h2></div><div class="empty"><p>Guard has not run on this report yet. It writes hunt queries for each '
            f'exception to revoke, and approve writes the plan.</p><pre class="cmd"><code>exception-guardian guard '
            f'--run {e(shown(run))}\nexception-guardian approve --run {e(shown(run))}</code></pre></div></section>')


def render_html(run_dir: Path) -> str:
    run = Path(run_dir)
    data = json.loads((run / "findings.json").read_text())
    findings = data["findings"]
    counts = {g: sum(1 for f in findings if f["grade"] == g) for g in ("REVOKE", "REVIEW", "OK")}
    revoke_phrase = f"{counts['REVOKE']} to revoke" if counts["REVOKE"] else "none to revoke"
    sources = sorted({f["exception"]["source"] for f in findings})
    intel = sorted({t["source"] for f in findings for t in f["triggers"]
                    if t["source"].startswith(("CISA KEV", "FIRST EPSS"))})
    parts = []
    banner = ""
    if data.get("partial"):
        warns = "".join(f"<li>{_ticks(w)}</li>" for w in data.get("warnings", []))
        banner = (f'<div class="banner" role="alert"><p><b>Partial run.</b> A source failed, so some exceptions '
                  f'may be missing from this report.</p><ul>{warns}</ul></div>')
    elif data.get("warnings"):  # not a failed source, but still a gap in what this run could see (report.md lists them)
        warns = "".join(f"<li>{_ticks(w)}</li>" for w in data["warnings"])
        banner = (f'<div class="notice"><p><b>Before you read the grades.</b> This run could not check everything:'
                  f'</p><ul>{warns}</ul></div>')
    lead = next((f for f in findings if f["grade"] == "REVOKE"), None)
    guarded = (run / "guard.json").is_file()
    if not findings:
        actions = ""
    elif guarded:
        actions = ('<a class="btn" href="#hunt-h">Open the hunt queries</a>'
                   + ('<a class="btn btn--quiet" href="#plan-h">Review the plan</a>'
                      if (run / "approval-plan.md").is_file() else ""))
    else:
        actions = '<a class="btn" href="#next-h">See the next step</a>'
    actions = f'<p class="actions">{actions}</p>' if actions else ""
    stats = "".join(f'<div><dt>{label}</dt><dd data-count="{g}"{" class=\"revoke\"" if g == "REVOKE" and counts["REVOKE"] else ""}>'
                    f'{counts.get(g, len(findings))}</dd></div>'
                    for g, label in (("ALL", "Exceptions graded"), ("REVOKE", "Revoke"), ("REVIEW", "Review"),
                                     ("OK", "OK")))
    failed = sum(1 for w in data.get("warnings", []) if w.startswith("source ") and " failed: " in w)
    if data.get("partial"):    # a failed source means the count is incomplete: never an all-clear in the highlight
        tail = f"{failed or 'a'} source{'' if failed == 1 else 's'} could not be read"
        head = (f"{len(findings)} risk exception{'' if len(findings) == 1 else 's'} read, "
                + (f"{_hl(revoke_phrase)}, " if counts["REVOKE"] else "") + e(tail))
    else:
        head = f'{len(findings)} risk exception{"" if len(findings) == 1 else "s"}, {_hl(revoke_phrase)}'
    read_p = f'<p class="read">{e(read_line(data["read"]))}</p>' if data.get("read") else ""
    hero_text = (f'<div class="hero-text"><h1 id="top-h">{head}</h1>'
                 f'<p class="lead-in">Every accepted risk, recast rule and scan exclusion, graded again on '
                 f'today&rsquo;s exploitation data and exposure.</p><p>Run on {e(_day(data["today"]))}. Grades come '
                 f'from fixed rules, and each one cites its source.</p>{read_p}{actions}</div>')
    parts.append(f'{banner}<section class="hero{" hero--split" if lead else ""}" aria-labelledby="top-h">'
                 f'{hero_text}{_measure(lead) if lead else ""}<dl class="stats">{stats}</dl></section>')
    if not findings:
        if data.get("partial"):
            parts.append('<section aria-labelledby="none-h"><div class="empty"><h2 id="none-h">No risk exceptions '
                         'could be read</h2><p>A source failed (see the warning above), so this run says nothing about '
                         'its exceptions. Fix the source, then run find again.</p></div></section>')
        else:
            parts.append('<section aria-labelledby="none-h"><div class="empty"><h2 id="none-h">No risk exceptions were '
                         'found</h2><p>No source in the config returned an exception. Check the sources in '
                         '<code>guardian.yaml</code>, then run find again.</p></div></section>')
    else:
        if lead:
            parts.append(_lead(lead))
        if (run / "changes.json").is_file():
            parts.append(_changes(json.loads((run / "changes.json").read_text())))
        parts.append(_context(findings))
        parts.append(_ledger(findings))
        if guarded and not any(f["grade"] == "REVOKE" for f in findings):
            parts.append(_nothing_to_revoke(findings))
        elif guarded:
            parts.append(_hunt(run, json.loads((run / "guard.json").read_text()), findings))
            if (run / "approval-plan.md").is_file():
                parts.append(_plan(run, findings, data.get("tenable_vm_base_url")))
        else:
            parts.append(_next_step(run))
    body = "".join(parts)
    nav = "".join(f'<li><a href="#{sid}">{label}</a></li>' for sid, label in SECTIONS if f'id="{sid}"' in body)
    src_chips = "".join(f'<li class="chip">{e(_source_name(x))}</li>' for x in sources) or '<li class="chip">none</li>'
    intel_chips = "".join(_intel_chip(x) for x in intel) or '<li class="chip">none used</li>'
    strip = (f'<div class="runstrip"><div class="container"><dl>'
             f'<div><dt>Run</dt><dd>{e(_day(data["today"]))}</dd></div>'
             f'<div><dt>Sources</dt><dd><ul>{src_chips}</ul></dd></div>'
             f'<div><dt>Intel</dt><dd><ul>{intel_chips}</ul></dd></div></dl></div></div>')
    # bands alternate: a light hero, then dark and light in turn
    bands = "".join(f'<div class="band" data-theme="{"light" if i % 2 == 0 else "dark"}"><div class="container">'
                    f'{p}</div></div>' for i, p in enumerate(parts))
    css = CSS.read_text()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exception Guardian report, {e(data["today"])}</title>
<meta name="description" content="Risk exceptions graded again on current exploitation data, with evidence, hunt queries and an approval plan.">
{FONT}
{HL_HEAD}
<style>
{css}
</style>
</head>
<body>
<header class="topbar" data-theme="dark"><div class="container"><a class="wordmark" href="#top-h">Exception Guardian</a>{f'<nav class="sections" aria-label="Report sections"><ul>{nav}</ul></nav>' if nav else ""}</div></header>
{strip}
<main>
{bands}
</main>
<footer class="band" data-theme="dark"><div class="container">
<p>Grades come from deterministic code. No model graded anything. Rule ids, names, owners and justifications are quoted data from the source systems and are shown as text.</p>
<p>Exploitation data: CISA Known Exploited Vulnerabilities and FIRST EPSS. Detection rules: SigmaHQ (Detection Rule License) and drafts. Built by team wh0-Kn0w5 for SWARM Global 2026. It is not a Tenable product. Typeface: Geologica (SIL Open Font License).</p>
</div></footer>
{HL_JS}
{SPY_JS}
{ACCORDION_JS}
{SHOWALL_JS}
{COPY_JS}
</body>
</html>
"""


def write_html(run_dir: Path) -> Path:
    path = Path(run_dir) / "report.html"
    path.write_text(render_html(run_dir))
    return path
