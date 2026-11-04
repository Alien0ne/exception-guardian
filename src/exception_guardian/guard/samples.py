"""Agent-written sample logs and not-loggable CVEs: the agent's input to guard, checked before guard uses it.

When the curated sample logs have nothing for a rule's log source, or no attack on the rule's CVEs, guard writes a
sample brief: the log source, the CVEs, and the field names that log has. It never holds the rule's detection
logic, so the agent writes events from the CVE's public write-up, not to fit the rule. The agent saves them to
`<run>/samples/*.jsonl`. Every attack event must cite that write-up in `_source`. Code marks each event
`_origin: agent`, so a score built on them always says so.

A CVE that no log can show (a CPU side channel such as Spectre) goes in `<drafts>/not-loggable.json` with the
reason, instead of getting generic web-shell rules that can never fire on it."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from ..cves import is_cve

MAX_EVENTS = 500  # per file: an agent's sample file is evidence, not a data dump
MAX_REASON = 300
MAX_BYTES = 2_000_000  # per file, read before parsing: a huge file is refused, not loaded
MAX_ERRORS = 50  # per file: past this, one line says how many more were rejected
_URL = re.compile(r"^https?://[^\s/$.?#][^\s]*$")


def _check(ev) -> str | None:
    if not isinstance(ev, dict):
        return "not a JSON object"
    if not isinstance(ev.get("_logsource"), str) or not ev["_logsource"]:
        return "_logsource is missing"
    if ev.get("_label") not in ("attack", "benign"):
        return "_label must be attack or benign"
    if "_origin" in ev:
        return "_origin is set by guard, not by the sample file"
    if ev["_label"] == "attack":
        cves = ev.get("_attack")
        if not isinstance(cves, list) or not cves or not all(isinstance(c, str) and is_cve(c) for c in cves):
            return "_attack must list the CVE ids the event exploits"
        if not isinstance(ev.get("_source"), str) or not _URL.match(ev["_source"]):
            return "_source must be the http(s) URL of a public write-up"
    fields = {k: v for k, v in ev.items() if not k.startswith("_")}
    if not fields:
        return "no log fields"
    for k, v in fields.items():
        if not isinstance(v, (str, int, float, bool, list)) or (isinstance(v, list) and
                                                               not all(isinstance(x, (str, int, float)) for x in v)):
            return f"field {k} must be text, a number or a list of them"
    return None


def load_agent_events(samples_dir: Path) -> tuple[list[dict], list[str]]:
    """(checked events, each marked _origin=agent; one error line per rejected event or file)."""
    events: list[dict] = []
    errors: list[str] = []
    d = Path(samples_dir)
    if not d.is_dir():
        return events, errors
    for p in sorted(d.glob("*.jsonl")):
        kept = 0
        if not p.is_file():
            continue
        if p.stat().st_size > MAX_BYTES:
            errors.append(f"{p.name}: larger than {MAX_BYTES:,} bytes, so it was not read. Keep sample files short")
            continue
        start = len(errors)
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if len(errors) - start >= MAX_ERRORS:
                errors.append(f"{p.name}: more than {MAX_ERRORS} rejected lines, so the rest were not read")
                break
            if not line.strip():
                continue
            if kept >= MAX_EVENTS:
                errors.append(f"{p.name}: more than {MAX_EVENTS} events, so the rest were not read")
                break
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{p.name} line {n}: not JSON ({exc.msg})")
                continue
            why = _check(ev)
            if why:
                errors.append(f"{p.name} line {n}: {why}")
                continue
            events.append({**ev, "_origin": "agent"})
            kept += 1
    return events, errors


def load_not_loggable(drafts_dir: Path) -> tuple[dict[str, str], list[str]]:
    """{CVE: one-line reason} from <drafts>/not-loggable.json, and errors for entries that were dropped."""
    p = Path(drafts_dir) / "not-loggable.json"
    if not p.is_file():
        return {}, []
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        return {}, [f"not-loggable.json: not JSON ({exc.msg})"]
    if not isinstance(data, dict):
        return {}, ["not-loggable.json: must map CVE ids to reasons"]
    out, errors = {}, []
    for cve, why in data.items():
        reason = " ".join(str(why or "").split())[:MAX_REASON]
        if not is_cve(str(cve)):
            errors.append(f"not-loggable.json: {str(cve)[:40]!r} is not a CVE id")
        elif not reason:
            errors.append(f"not-loggable.json: {cve} has no reason")
        else:
            out[str(cve).upper()] = reason
    return out, errors


def _slug(logsource: str) -> str:
    """A file name for a log source. Ordinary names (process_creation/windows) keep their plain form. A name that
    is too long or had characters replaced gets a short hash, so it stays short and two names never share a file."""
    plain = logsource.replace("/", "-")
    slug = re.sub(r"[^A-Za-z0-9_-]", "-", plain) or "unknown"
    if slug == plain and len(slug) <= 80:
        return slug
    return f"{slug[:60]}-{hashlib.sha256(logsource.encode()).hexdigest()[:10]}"


def detection_fields(yaml_text: str) -> list[str]:
    """Field names a rule reads (names only: never values or conditions)."""
    import yaml
    try:
        det = (yaml.safe_load(yaml_text) or {}).get("detection") or {}
    except yaml.YAMLError:
        return []
    names: list[str] = []
    for k, group in det.items():  # a group is a map of fields, or a list of such maps (or of keywords)
        if k == "condition":
            continue
        for item in (group if isinstance(group, list) else [group]):
            if isinstance(item, dict):
                for f in item:
                    f = str(f).split("|")[0]
                    if f and f not in names:
                        names.append(f)
    return names


#: the DCs of the sample world. Sample events use example names only, so a rule whose DC filter holds your real DCs
#: is scored with these instead, and the sample brief tells the writer to use them. The SIEM queries keep your values.
SAMPLE_DCS = {"dc_machine_accounts": ["DC-01$", "DC-02$"], "DC-MACHINE-NAME": ["DC-01$", "DC-02$"],
              "dc_ip_addresses": ["192.0.2.10", "192.0.2.11"],
              "known_cdcs": ["dc-01.corp.example.com", "dc-02.corp.example.com", "192.0.2.10", "192.0.2.11"],
              "legit_ips": ["192.0.2.10", "192.0.2.11"]}


def write_briefs(run_dir: Path, needs: dict[str, dict]) -> None:
    """One brief per log source: {logsource: {"cves": set, "fields": list}} → <run>/sample-briefs/<slug>.md."""
    d = Path(run_dir) / "sample-briefs"
    for ls, need in sorted(needs.items()):
        d.mkdir(exist_ok=True)
        slug = _slug(ls)
        cves = sorted(need["cves"])
        lines = [f"# Sample brief: {ls}", "",
                 f"Write labelled events for the `{ls}` log to `samples/{slug}.jsonl` in this run, one JSON object per "
                 "line, then run guard again. Write this file only, with the Write tool: one log at a time, never one "
                 "script that writes every brief's file.", "",
                 f"- Attack events for: {', '.join(cves) if cves else 'any web-shell or post-exploitation behaviour'}",
                 f"- Field names this log has: {', '.join(need['fields']) or 'see the Sigma taxonomy for this log'}",
                 "",
                 "Rules:", "",
                 "- Work from the CVE's public write-up (vendor advisory, CISA, a research post), not from a rule. "
                 "Put its URL in `_source` on every attack event.",
                 "- `_logsource` is `" + ls + "`. `_label` is `attack` or `benign`. Attack events list their CVEs in "
                 "`_attack`. `_note` says what the event is.",
                 "- Write what the log records after the exploit runs (a process, a file, a logon, a request), as a "
                 "defender reads it. `_note` says what the log shows (\"spooler loaded a driver from the spool "
                 "folder\"), never how to attack. No working payload, exploit code or attack command lines.",
                 "- Write at least as many benign events as attack events: ordinary activity on the same log that a "
                 "careless rule could trip on.",
                 "- Hosts, users and addresses come from documentation ranges (192.0.2.0/24, 198.51.100.0/24) and "
                 "example names, never from the real tenant.", ""]
        if need.get("dcs"):
            lines[-1:] = ["- The domain controllers of the sample world are "
                          f"{', '.join(SAMPLE_DCS['dc_machine_accounts'])} at {', '.join(SAMPLE_DCS['dc_ip_addresses'])}"
                          " (the rules are scored with these). Events from a DC's machine account use these names; "
                          "normal DC activity comes from these addresses, an attack from any other.", ""]
        (d / f"{slug}.md").write_text("\n".join(lines))


def brief_path(logsource: str) -> str:
    return f"sample-briefs/{_slug(logsource)}.md"


def samples_file(logsource: str) -> str:
    return f"samples/{_slug(logsource)}.jsonl"
