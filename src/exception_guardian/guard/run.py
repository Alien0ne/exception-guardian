"""guard: for each REVOKE finding, gather detections (SigmaHQ, drafted, generic), validate, convert, write briefs."""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
from dataclasses import replace
from datetime import date
from pathlib import Path

import yaml

from ..config import Config
from ..cves import is_cve
from ..find import load_findings
from ..report import code_span, md_escape
from .convert import LABEL, convert_rule
from .hunt import no_valid_draft_notes, render_hunt_brief
from .logtest import TAG_TYPOS, load_events, score_rule
from .samples import SAMPLE_DCS, brief_path, detection_fields, load_agent_events, load_not_loggable, samples_file, write_briefs
from .sigmahq import SigmaRef, generic_rules, rules_for_cve
from .validate import validate_rule


_SIGNAL = ("KEV", "EPSS_HIGH", "ATTACK_PATH_CVE")
_CVE_IN = re.compile(r"CVE-\d{4}-\d{4,}")


def needs_rule(f: dict) -> set[str]:
    """The CVEs worth a detection: those behind the REVOKE (in KEV, EPSS at or above the line, or used in an
    attack path). A rule with one CVE, or whose CVEs carry no such signal, keeps all of them. A Windows rollup
    of dozens of CVEs accepted for one KEV CVE should not ask for a draft per CVE."""
    cves = list(f["exception"].get("cves") or [])
    if len(cves) <= 1:
        return set(cves)
    named = {c for t in f.get("triggers") or [] if t["code"] in _SIGNAL for c in _CVE_IN.findall(t["now"])}
    return (named & set(cves)) or set(cves)


def safe_name(rule_id: str) -> str:
    """Rule ids come from source systems: make them a single, harmless path component."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", str(rule_id)).lstrip(".")
    return name or "_"


def _rule_id(text: str) -> str | None:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return str(doc.get("id")) if isinstance(doc, dict) and doc.get("id") else None


def _draft_of(file_name: str, cve: str) -> bool:
    """Is this draft file filed for this CVE (CVE-….yml or CVE-…-<suffix>.yml), not one that only starts the same?"""
    return file_name == f"{cve}.yml" or (file_name.startswith(f"{cve}-") and file_name.endswith(".yml"))


def _draft_tag_errors(text: str, cve: str) -> list[str]:
    """A draft is filed under one CVE: its cve. tags must name it, or it would be scored on another CVE's samples."""
    try:
        tags = [str(t).lower() for t in (yaml.safe_load(text) or {}).get("tags") or []]
    except (yaml.YAMLError, AttributeError):
        return []
    own = {"CVE-" + t[4:].upper() for t in tags if t.startswith("cve.")}
    if own and cve.upper() not in own:
        return [f"filed as {cve} but tagged {', '.join(sorted(own))}. Tag it cve.{cve[4:].lower()} or file it "
                "under its own CVE"]
    return []


def _drafts_for(cve: str, drafts_dir: Path) -> list[Path]:
    if not drafts_dir.is_dir():
        return []
    return sorted({*drafts_dir.glob(f"{cve}.yml"), *drafts_dir.glob(f"{cve}-*.yml")})


SIEM_LABEL = {t: v[0] for t, v in LABEL.items()}


def coverage_gaps(rules: list[dict], by_cve: dict[str, set[str]], wanted: set[str], targets) -> list[dict]:
    """A SigmaHQ rule existing is not coverage. For each CVE behind the REVOKE that only SigmaHQ covers: is there
    a query for every SIEM, and does a rule catch the CVE's attack samples (once samples exist)? A CVE with a
    valid draft is left out, so the agent is asked once, never in a loop."""
    out = []
    for cve in sorted(c for c in by_cve if c in wanted and by_cve[c]):
        rs = [r for r in rules if r.get("file") in by_cve[cve]]
        if not rs:
            continue
        no_query = [t for t in targets if not any((r["conversions"].get(t) or {}).get("ok") for r in rs)]
        tested = [r["tested"] for r in rs if r["tested"].get("tested") and r["tested"].get("attack_total")]
        caught = any(t.get("attack_hits") for t in tested) if tested else None
        why = (["no rule catches its attack samples"] if caught is False else []) + (
            [f"no query for {', '.join(SIEM_LABEL.get(t, t) for t in no_query)}"] if no_query else [])
        if why:
            out.append({"cve": cve, "no_query": no_query, "caught": caught, "reason": "; ".join(why)})
    return out


def _clear(folder: Path) -> None:
    """Empty a folder guard writes. A link is removed, never followed: it could point out of the run."""
    if folder.is_symlink() or folder.is_file():
        folder.unlink()
    elif folder.is_dir():
        shutil.rmtree(folder)


def other_cves_notes(rid: str, entry: dict) -> list[str]:
    """An exception with CVEs no log can show often holds more of the same kind (a CPU side-channel accept lists
    Spectre, Meltdown, MDS and L1TF together), but only the ones with KEV, EPSS or attack-path signals were checked
    (otherwise most were called "below the EPSS line")."""
    rest = entry.get("not_drafted") or []
    if not entry.get("not_loggable") or not rest:
        return []
    return [f"{code_span(rid)} has CVEs no log can show. Check its {len(rest)} other CVEs ({', '.join(rest)}): "
            "add each one of the same kind to `not-loggable.json` with its reason, then rerun guard"]


FOUND_PLACEHOLDERS = "placeholders.found.yaml"


def placeholders_for_run(run_dir: Path, cfg: Config) -> dict:
    """The config's placeholder values, plus the DC values `dcs --use` wrote for this run for any the config leaves
    unset (the config is the person's own word, so it wins)."""
    f = Path(run_dir) / FOUND_PLACEHOLDERS
    if not f.is_file():
        return dict(cfg.placeholders)
    found = yaml.safe_load(f.read_text()) or {}
    if not isinstance(found, dict):
        return dict(cfg.placeholders)
    extra = {str(k): [str(x) for x in (v if isinstance(v, list) else [v])] for k, v in found.items() if v}
    return {**extra, **cfg.placeholders}


#: placeholders that hold addresses. Windows logs Kerberos addresses (4768, 4769) as ::ffff:a.b.c.d
_ADDRESS_PLACEHOLDERS = ("dc_ip_addresses", "known_cdcs", "legit_ips")


def with_mapped_ipv4(values: dict) -> dict:
    """Add the ::ffff: form of every IPv4 address, so a DC filter also matches how Kerberos events log it."""
    out = dict(values)
    for k in _ADDRESS_PLACEHOLDERS:
        if not isinstance(out.get(k), (list, tuple)):
            continue
        vals = list(out[k])
        for v in list(vals):
            try:
                if isinstance(ipaddress.ip_address(str(v)), ipaddress.IPv4Address) and f"::ffff:{v}" not in vals:
                    vals.append(f"::ffff:{v}")
            except ValueError:
                pass
        out[k] = vals
    return out


_PH = re.compile(r"%([A-Za-z0-9_-]+)%")
#: the SigmaHQ placeholders that describe your domain controllers, and how a hunt brief names each
DC_PLACEHOLDERS = {"dc_machine_accounts": "DC machine accounts", "DC-MACHINE-NAME": "DC machine accounts",
                   "dc_ip_addresses": "DC addresses", "known_cdcs": "known DC names and addresses",
                   "legit_ips": "addresses the certificate server may contact"}


def sample_world(values: dict) -> dict:
    """The placeholders to score sample events with: each DC value you set becomes the sample world's."""
    return with_mapped_ipv4({**values, **{k: v for k, v in SAMPLE_DCS.items() if values.get(k)}})


def known_infrastructure(used: set, values: dict, own: dict) -> list[dict]:
    """For a hunt brief: each DC placeholder its rules use, its values and where they came from (or that it is
    unset). Two placeholders with the same values (DC-MACHINE-NAME, dc_machine_accounts) are listed once."""
    out, seen = [], set()
    for name, label in DC_PLACEHOLDERS.items():
        if name not in used:
            continue
        vals = list(values.get(name) or [])
        key = (label, tuple(vals))
        if key in seen:
            continue
        seen.add(key)
        src = "your config" if name in own else ("this run's DC lookup (scan evidence, approved by a person)"
                                                 if vals else "")
        out.append({"name": name, "label": label, "values": vals, "source": src})
    return out


def run_guard(run_dir: Path, drafts_dir: Path, cfg: Config) -> dict:
    run_dir, drafts_dir = Path(run_dir), Path(drafts_dir)
    config_ph = dict(cfg.placeholders)  # the person's own values, named as such in the hunt briefs
    cfg = replace(cfg, placeholders=placeholders_for_run(run_dir, cfg))
    meta = json.loads((run_dir / "findings.json").read_text())
    today = date.fromisoformat(meta["today"])
    targets = tuple(cfg.siem_targets)
    logs_dir = Path(cfg.sample_logs_dir) if cfg.sample_logs_dir else None  # "" is no folder, not the current one
    events = load_events(logs_dir) if logs_dir and logs_dir.is_dir() else []
    agent_events, sample_errors = load_agent_events(run_dir / "samples")  # written by the agent from sample briefs
    events = events + agent_events
    not_loggable, nl_errors = load_not_loggable(drafts_dir)
    briefs: dict[str, dict] = {}
    out: dict = {}
    _clear(run_dir / "rules")  # every pass writes the whole set; a rule the last pass wrote may be dropped now
    revokes = [f for f in load_findings(run_dir / "findings.json") if f["grade"] == "REVOKE"]
    id_counts: dict[str, int] = {}
    for f in revokes:
        id_counts[f["exception"]["rule_id"]] = id_counts.get(f["exception"]["rule_id"], 0) + 1
    used_names: set[str] = set()
    for f in revokes:
        exc = f["exception"]
        # rule ids are only unique within a source (SC numbers accept and recast rules separately)
        rid = exc["rule_id"] if id_counts[exc["rule_id"]] == 1 else f"{exc['source']}:{exc['rule_type']}:{exc['rule_id']}"
        sid, n = safe_name(rid), 2
        while sid.lower() in used_names:
            sid, n = f"{safe_name(rid)}-{n}", n + 1
        used_names.add(sid.lower())
        rule_dir = run_dir / "rules" / sid
        seen: set[str] = set()
        entry: dict = {"dir": sid, "rule_id": exc["rule_id"], "source": exc.get("source"), "rule_type": exc.get("rule_type"),
                       "rules": [], "conversions": {}, "dropped": [], "missing_drafts": [], "no_valid_draft": [],
                       "not_drafted": [], "not_loggable": [], "needs_samples": [], "coverage_gaps": []}
        by_cve: dict[str, set[str]] = {}  # CVE -> files of the SigmaHQ rules written for it
        drafted_cves: set[str] = set()
        wanted = needs_rule(f)
        candidates: list[tuple[str, SigmaRef | None, Path | None, str | None]] = []  # (origin, ref, local path, own CVE)

        for cve in exc.get("cves", []):
            if not is_cve(cve):  # untrusted text: never let it reach a glob or a file name
                continue
            refs = rules_for_cve(cve)
            good_drafts = 0
            candidates += [("sigmahq", r, r.bundled_path, None) for r in refs]  # vetted rules first
            by_cve[cve] = {r.bundled_path.name for r in refs if r.bundled_path}
            for p in _drafts_for(cve, drafts_dir):
                text = p.read_text()
                errors = validate_rule(text, drafted=True) or _draft_tag_errors(text, cve)
                if errors:
                    entry["dropped"].append({"file": p.name, "errors": errors})
                else:
                    candidates.append(("drafted", None, p, cve))
                    good_drafts += 1
                    drafted_cves.add(cve)
            if not any(r.bundled_path for r in refs) and not good_drafts:  # a link alone gives no queries
                if cve.upper() in not_loggable:  # the agent says no log can show it (a CPU side channel)
                    entry["not_loggable"].append({"cve": cve, "reason": not_loggable[cve.upper()]})
                    continue
                if cve not in wanted:
                    entry["not_drafted"].append(cve)  # no KEV, EPSS or attack-path signal: not worth a draft
                    continue
                entry["missing_drafts"].append(cve)
                if any(_draft_of(d["file"], cve) for d in entry["dropped"]):
                    entry["no_valid_draft"].append(cve)
        # The generic rule watches for web shells: a fallback when SigmaHQ has no rule written for these CVEs, not
        # an extra next to specific ones (on a print spooler or Netlogon CVE it would point the hunt the wrong way)
        unloggable = {n["cve"] for n in entry["not_loggable"]}
        if (not any(origin == "sigmahq" and path for origin, _, path, _ in candidates)
                and not (wanted and wanted <= unloggable)):  # web-shell rules cannot fire on a CPU side channel
            for os_name in sorted({a.get("os") for a in f.get("assets", []) if a.get("os")}):
                candidates += [("generic", r, r.bundled_path, None) for r in generic_rules(os_name)]

        for origin, ref, path, own_cve in candidates:
            if path is None:  # SigmaHQ index hit without a bundled copy: link only
                key = ref.url
                if key in seen:
                    continue
                seen.add(key)
                entry["rules"].append({"file": None, "origin": origin, "title": ref.title, "author": ref.author,
                                       "url": ref.url, "conversions": {}})
                continue
            text = path.read_text()
            key = _rule_id(text) or path.name
            if key in seen:
                if origin == "drafted":  # never let a draft stand in for a vetted rule by reusing its id
                    entry["dropped"].append({"file": path.name, "errors": [
                        f"its id {key} is already used by a rule attached to this exception. Give the draft a new id"]})
                continue
            seen.add(key)
            if origin != "drafted" and validate_rule(text, drafted=False):
                entry.setdefault("skipped_bundled", []).append(path.name)  # pinned and tested, so this is a bug
                continue
            doc = yaml.safe_load(text)
            rule_dir.mkdir(parents=True, exist_ok=True)
            (rule_dir / path.name).write_text(text)
            entry.setdefault("_placeholders", set()).update(_PH.findall(text))
            convs = {}
            for target, res in convert_rule(text, targets, with_mapped_ipv4(cfg.placeholders)).items():
                qfile = None
                if res.ok:
                    qfile = f"{path.stem}.{target}.txt"
                    (rule_dir / qfile).write_text(res.query + "\n")
                convs[target] = {"ok": res.ok, "file": qfile, "error": res.error, "note": res.note}
                tally = entry["conversions"].setdefault(target, {"ok": 0, "unsupported": 0})
                tally["ok" if res.ok else "unsupported"] += 1
            tested = score_rule(text, events, (own_cve,) if own_cve else tuple(sorted(wanted)),
                                any_attack=origin == "generic", own_cves_only=bool(own_cve),
                                placeholders=sample_world(cfg.placeholders))
            if not tested.get("tested") and str(tested.get("reason", "")).startswith("no sample logs") \
                    or tested.get("tested") and not tested.get("attack_total"):
                ls = tested.get("logsource") or "unknown"
                own = sorted({TAG_TYPOS.get(c.upper(), c.upper())
                              for c in _CVE_IN.findall(str(doc.get("tags") or "").replace("cve.", "CVE-"))})
                need = briefs.setdefault(ls, {"cves": set(), "fields": []})
                need["cves"] |= set() if origin == "generic" else set(own or wanted)
                need["fields"] += [x for x in detection_fields(text) if x not in need["fields"]]
                need["dcs"] = need.get("dcs") or any(cfg.placeholders.get(k) for k in set(_PH.findall(text))
                                                     & set(SAMPLE_DCS))
                if ls not in {n["logsource"] for n in entry["needs_samples"]}:
                    entry["needs_samples"].append({"logsource": ls, "cves": sorted(set() if origin == "generic"
                                                                                   else set(own or wanted)),
                                                   "brief": brief_path(ls), "file": samples_file(ls)})
            entry["rules"].append({"file": path.name, "origin": origin, "title": str(doc.get("title", "")),
                                   "author": str(doc.get("author", "")), "url": ref.url if ref else None,
                                   "conversions": convs, "tested": tested})

        entry["coverage_gaps"] = coverage_gaps(entry["rules"], by_cve, wanted - unloggable - drafted_cves, targets)
        brief_dir = run_dir / "hunt-briefs"
        brief_dir.mkdir(exist_ok=True)
        created = date.fromisoformat(exc["created"])
        infra = known_infrastructure(entry.pop("_placeholders", set()), cfg.placeholders, config_ph)
        (brief_dir / f"{sid}.md").write_text(render_hunt_brief(f, entry["rules"], created, today, no_valid_draft_notes(entry),
                                                                unloggable=not entry["rules"] and bool(entry["not_loggable"]),
                                                                infra=infra))
        out[rid] = entry

    write_briefs(run_dir, briefs)
    (run_dir / "guard.json").write_text(json.dumps(out, indent=2))
    lines = ["# Handoff: guard → hunt / approve", "",
             f"Run: `{run_dir}` · REVOKE exceptions guarded: {len(out)}", ""]
    for rid, e in out.items():
        lines.append(f"- {code_span(rid)}: {sum(1 for r in e['rules'] if r['file'])} rules written, "
                     f"{len(e['dropped'])} drafts dropped, missing drafts: {', '.join(e['missing_drafts']) or 'none'}")
        lines += [f"  - {md_escape(n)}" for n in no_valid_draft_notes(e)]
    for rid, e in out.items():
        if notes := other_cves_notes(rid, e):
            lines += ["", *notes]
    missing = sorted({c for e in out.values() for c in e["missing_drafts"]})
    gaps = {g["cve"]: g["reason"] for e in out.values() for g in e["coverage_gaps"]}
    if gaps:
        lines += ["", f"Close the gaps SigmaHQ leaves: {', '.join(sorted(gaps))}. Its rules exist, but "
                  + "; ".join(f"{c}: {r}" for c, r in sorted(gaps.items()))
                  + ". Draft one rule per CVE on a log source those SIEMs have (`<run>/drafts/<CVE>.yml`), then "
                  "rerun guard. One draft ends the ask"]
    if missing:
        lines += ["", f"Draft Sigma rules for: {', '.join(missing)} (save as `<run>/drafts/<CVE>.yml`, then rerun guard)"]
    if briefs:
        lines += ["", "Rules with no samples to test on. Write labelled events from each brief, then rerun guard:"]
        lines += [f"- `{brief_path(ls)}` → `{samples_file(ls)}`" for ls in sorted(briefs)]
    if agent_events:
        lines += ["", f"Agent-written samples used: {len(agent_events)} events from `{run_dir / 'samples'}`"]
    if sample_errors or nl_errors:
        lines += ["", "Rejected agent input (fix and rerun guard):"] + [f"- {md_escape(x)}" for x in sample_errors + nl_errors]
    lines += ["", f"Hunt briefs: `{run_dir / 'hunt-briefs'}`"]
    (run_dir / "handoff-guard.md").write_text("\n".join(lines) + "\n")
    return out
