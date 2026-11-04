"""exception-guardian command line."""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from dataclasses import replace
from datetime import date
from pathlib import Path

import yaml

from .config import load_config


def load_env_file(path: str | Path | None = None) -> None:
    """Load KEY=VALUE lines from a git-ignored .env (or the file EG_ENV_FILE names, so a harness can keep keys
    out of the agent's own environment); variables already set in the environment win."""
    p = Path(path or os.environ.get("EG_ENV_FILE") or ".env")
    if not p.is_file():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key, val = key.removeprefix("export ").strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        os.environ.setdefault(key, val)


def _refresh_html(run: Path) -> None:
    """Every step rewrites the run's report.html, so any run ends with the same page, whatever steps it took."""
    from .html_report import write_html
    print(f"report.html: {write_html(run)}")


def _today(s: str | None) -> date:
    return date.fromisoformat(s) if s else date.today()


class UsageError(Exception):
    """A mistake the user can fix: printed as one line, never a traceback."""


def _iso_day(s: str) -> str:
    try:
        date.fromisoformat(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{s!r} is not a date: use YYYY-MM-DD") from None
    return s


def _run_dir(path: str, what: str = "run") -> Path:
    run = Path(path)
    if not (run / "findings.json").is_file():
        raise UsageError(f"{run} is not a run folder (it has no findings.json). Run `exception-guardian find --out "
                         f"{run}` first" if what == "run" else f"--previous {run} is not a run folder (it has no "
                         "findings.json). Give an earlier `find --out` folder")
    return run


def cmd_find(a) -> int:
    from .find import run_find
    cfg = load_config(a.config)
    if a.previous:
        _run_dir(a.previous, "previous")
    if a.offline:
        cfg = replace(cfg, offline=True)
    if a.exposure_claims:
        _evidence = Path(a.exposure_claims)
        if not _evidence.is_file():
            raise UsageError(f"--exposure-claims {_evidence} is not a file")
        cfg = replace(cfg, exposure=replace(cfg.exposure, claims_file=str(_evidence)))
    res = run_find(cfg, Path(a.out), _today(a.today), previous=Path(a.previous) if a.previous else None)
    fj = Path(a.out) / "findings.json"  # guard reads the same config (placeholders) unless told otherwise
    fj.write_text(json.dumps({**json.loads(fj.read_text()), "config": str(Path(a.config).resolve())}, indent=2))
    counts = {g: sum(1 for r in res if r.grade.value == g) for g in ("REVOKE", "REVIEW", "OK")}
    print(f"report: {Path(a.out) / 'report.md'}")
    print(" · ".join(f"{k} {v}" for k, v in counts.items()))
    if a.previous:
        print(f"changes: {Path(a.out) / 'changes.md'} ({_changes_summary(Path(a.out))})")
    _refresh_html(Path(a.out))
    warned = json.loads((Path(a.out) / "findings.json").read_text()).get("warnings") or []
    skipped = sum(1 for w in warned if " skipped:" in w)
    if skipped:
        print(f"warning: {skipped} row{'s' if skipped != 1 else ''} skipped (see Warnings in report.md)", file=sys.stderr)
    if not res:
        print("warning: no exception was read from any source, so there is nothing to grade. Check the config's "
              "sources", file=sys.stderr)
    return _partial_exit(Path(a.out))


EXIT_PARTIAL = 3


def _partial_exit(run: Path) -> int:
    """A run with a failed source still writes its report, but must not look like success to a script or CI."""
    d = json.loads((run / "findings.json").read_text())
    if not d.get("partial"):
        return 0
    from .report import is_partial
    failed = [w for w in d.get("warnings", []) if is_partial([w])]
    print("PARTIAL RUN: at least one source failed, so grades cover only what was read:", file=sys.stderr)
    for w in failed:
        print(f"  - {w}", file=sys.stderr)
    return EXIT_PARTIAL


def _changes_summary(run: Path) -> str:
    ch = json.loads((run / "changes.json").read_text())
    return (f"since {ch['previous_today']}: {len(ch['escalated'])} got worse, {len(ch['new_evidence'])} new evidence, "
            f"{len(ch['new'])} new, {len(ch['eased'])} eased, {len(ch['gone'])} gone")


def cmd_guard(a) -> int:
    from .guard.run import run_guard
    run = _run_dir(a.run)
    config = a.config
    if not config:
        used = json.loads((run / "findings.json").read_text()).get("config")
        config = used if used and Path(used).is_file() else "guardian.yaml"
        print(f"config: {config} (the one find used)" if config == used else f"config: {config}")
    g = run_guard(run, Path(a.drafts) if a.drafts else run / "drafts", load_config(config))
    written = sum(1 for e in g.values() for r in e["rules"] if r["file"])
    dropped = sum(len(e["dropped"]) for e in g.values())
    missing = sorted({c for e in g.values() for c in e["missing_drafts"]})
    print(f"guarded {len(g)} REVOKE exceptions: {written} rules written, {dropped} drafts dropped, "
          f"missing drafts: {', '.join(missing) or 'none'}")
    print(f"hunt briefs: {run / 'hunt-briefs'}")
    _refresh_html(run)
    drafts = Path(a.drafts) if a.drafts else run / "drafts"
    gaps = sorted({x["cve"] for e in g.values() for x in e.get("coverage_gaps", [])})
    briefs = sum(len(e.get("needs_samples", [])) for e in g.values())
    if missing or gaps or dropped:
        todo = ([f"draft a Sigma rule for each missing CVE ({', '.join(missing)})"] if missing else []) + (
            [f"close the gaps SigmaHQ leaves ({', '.join(gaps)})"] if gaps else []) + (
            ["fix the dropped drafts (errors in guard.json)"] if dropped else [])
        print(f"next: {'; '.join(todo)}, as {drafts}/<CVE>.yml, then run guard again. In Claude Code, "
              f"/eg-guard {run} does this for you (see handoff-guard.md)")
    elif briefs:
        print(f"next: write sample logs from the {briefs} briefs in {run / 'sample-briefs'}, then run guard again "
              f"(/eg-guard {run} in Claude Code)")
    else:
        print(f"next: exception-guardian approve --run {run}")
    return 0


AGENT_VARS = ("CLAUDECODE", "EG_HARNESS")  # set in every Claude Code shell, and in harness runs


def cmd_approve(a) -> int:
    from .approval import apply, write_plan
    run = _run_dir(a.run)
    agent = [v for v in AGENT_VARS if os.environ.get(v)]
    if a.apply and agent:
        print(f"refusing --apply: this shell belongs to an agent session ({', '.join(agent)} is set). Run --apply "
              "yourself, in your own terminal", file=sys.stderr)
        return 2
    plan = write_plan(run)
    print(f"approval plan: {plan}")
    _refresh_html(run)
    if not a.apply:
        return 0
    if not a.base_url:
        print("--apply needs --base-url", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("refusing --apply: it asks you to confirm each rule, so it needs an interactive TTY", file=sys.stderr)
        return 2
    from .tenable_client import TenableVMClient
    client = TenableVMClient.from_env(a.base_url)
    from .approval import preflight
    try:
        access = preflight(client)  # read-only: can this key change rules at all?
    except RuntimeError as exc:
        print(f"refusing --apply: {exc}", file=sys.stderr)
        return 2
    if access and "Tenable decides" in access:
        print(f"note: {access}. A refused change is logged and the next rule is offered.", file=sys.stderr)

    def confirm(diff: str) -> bool:
        print("\n" + diff)
        return input("Disable this rule? [y/N] ").strip().lower() in ("y", "yes")

    try:
        outcomes = apply(run, client, confirm)
    except RuntimeError as exc:  # a partial run, or a rule that did not verify: stop, say why, keep the log
        print(str(exc), file=sys.stderr)
        log = run / "applied-changes.log"
        if log.is_file():
            print(f"log: {log}")
        return 2 if "partial" in str(exc) else 1
    for o in outcomes:
        print(f"{o['rule_id']}: {o['result']}")
    print(f"log: {run / 'applied-changes.log'}")
    return 0


def cmd_mock(a) -> int:
    from .mock_tenable import serve
    srv, url = serve(Path(a.fixtures), a.port)
    print(f"mock Tenable VM at {url} (Ctrl-C to stop)", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


def cmd_demo(a) -> int:
    """The sample config and fixtures use paths relative to the repo, so run there and write --out where asked."""
    import contextlib
    out, config = Path(a.out).resolve(), a.config
    if Path("samples/golden/drafts").is_dir():
        return _demo(out, config)
    root = Path(__file__).resolve().parents[2]
    if not (root / "samples" / "golden" / "drafts").is_dir():
        print("demo needs the repo's samples/ folder: run it from the exception-guardian repo", file=sys.stderr)
        return 2
    if Path(config).is_file():
        config = str(Path(config).resolve())
    with contextlib.chdir(root):
        return _demo(out, config)


def _demo(out: Path, config: str) -> int:
    import shutil
    from .approval import write_plan
    from .find import run_find
    from .guard.run import run_guard, safe_name
    cfg = replace(load_config(config), offline=True)
    # Last week's run on the sample tenant, before web-portal-01 went on the internet (2026-10-28).
    run_find(replace(load_config("samples/history/2026-10-26/guardian.yaml"), offline=True),
             out / "previous", date(2026, 10, 26))
    res = run_find(cfg, out, date(2026, 11, 2), previous=out / "previous")
    drafts = out / "drafts"
    shutil.copytree("samples/golden/drafts", drafts, dirs_exist_ok=True)
    g = run_guard(out, drafts, cfg)
    plan = write_plan(out)
    from .html_report import write_html
    page = write_html(out)
    counts = {k: sum(1 for r in res if r.grade.value == k) for k in ("REVOKE", "REVIEW", "OK")}
    hero = res[0]
    print("Exception Guardian demo (offline, sample data, today 2026-11-02): " + " · ".join(f"{k} {v}" for k, v in counts.items()))
    ch = json.loads((out / "changes.json").read_text())
    print(f"\nSince the last run ({ch['previous_today']}): {len(ch['escalated'])} got worse, "
          f"{len(ch['new_evidence'])} gained new evidence, {ch['unchanged']} unchanged")
    for e in ch["escalated"] + ch["new_evidence"]:
        moved = f"{e['was']} → {e['now']}" if e["was"] != e["now"] else e["now"]
        print(f"  {e['rule_id']}: {moved}, new: {', '.join(t['code'] for t in e['new_triggers'])}")
    print(f"\n{hero.grade.value}: {hero.exception.rule_id} ({hero.exception.source}) — {', '.join(hero.exception.cves)}")
    print(f"{'Evidence':28} {'Then':16} {'Now':40} Source")
    for t in hero.triggers:
        print(f"{t.code:28} {(t.then or '—'):16} {t.now:40} {t.source}")
    hero_dir = out / "rules" / safe_name(hero.exception.rule_id)
    print("\nQueries for the hero:")
    for r in g.get(hero.exception.rule_id, {}).get("rules", []):
        for target in cfg.siem_targets:
            c = r["conversions"].get(target)
            if c and c["ok"]:
                print(f"  {target:9} {hero_dir / c['file']}")
    print(f"\nreport: {out / 'report.md'}\nchanges: {out / 'changes.md'}\nhunt briefs: {out / 'hunt-briefs'}\napproval plan: {plan} (nothing applied)\nhtml report: {page}")
    return 0


def cmd_exposure(a) -> int:
    from .exposure_claims import run_exposure
    run = Path(a.run)
    claims = Path(a.claims) if a.claims else run / "exposure-claims.json"
    if not claims.exists():
        print(f"no claims file: {claims} (Claude writes it in the map-exposure step)", file=sys.stderr)
        return 2
    n = run_exposure(run, claims)
    print(f"exposure: {n['verified']} verified, {n['drafted']} drafted for a person to approve, "
          f"{n['rejected']} rejected")
    print(f"evidence: {run / 'exposure-evidence.json'}  (re-run find with --exposure-claims set to it, or set exposure.claims_file)")
    print(f"draft host list: {run / 'exposure-drafted-hosts.csv'}  (a person checks it before it becomes "
          "exposure.internet_hosts_file)")
    return 0


def cmd_dcs(a) -> int:
    """Find the DCs in the scan evidence (read-only) for the SigmaHQ DC placeholders; --use writes this run's values
    from the proven ones, after the person said yes."""
    from .dcs import PLACEHOLDER_NAMES, find_dcs, placeholders_from
    from .guard.run import FOUND_PLACEHOLDERS
    run = _run_dir(a.run)
    cand = run / "dc-candidates.json"
    if a.use:
        dcs = json.loads(cand.read_text()).get("dcs", []) if cand.is_file() else []
        ph = placeholders_from(dcs)
        if not ph:
            print(f"no proven DC in {cand}: nothing written, the DC rules keep their stand-ins", file=sys.stderr)
            return 2
        (run / FOUND_PLACEHOLDERS).write_text(
            "# DC values found in this run's scan evidence (exception-guardian dcs), used by guard for this run only.\n"
            + yaml.safe_dump(ph, sort_keys=False))
        print(f"wrote {run / FOUND_PLACEHOLDERS}: {', '.join(ph['dc_machine_accounts'])}. Guard uses them for any "
              "placeholder your config leaves unset. To keep them for later runs, copy the file to "
              "placeholders.local.yaml beside your config (git-ignored).")
        return 0
    used = json.loads((run / "findings.json").read_text()).get("config")
    cfg = load_config(used if used and Path(used).is_file() else "guardian.yaml")
    if cfg.offline:
        print("dcs: offline config, nothing looked up (the DC rules use your placeholders or stand-ins)")
        return 0
    base = next((s.params.get("base_url") for s in cfg.sources if s.name == "tenable-vm" and s.params.get("base_url")), None)
    if not base:
        print("dcs: the config has no tenable-vm source with a base_url, nothing looked up")
        return 0
    from .tenable_client import TenableVMClient
    dcs = find_dcs(TenableVMClient.from_env(base))
    cand.write_text(json.dumps({"dcs": dcs}, indent=2))
    proven = [d for d in dcs if d["confirmed"]]
    unset = [n for n in PLACEHOLDER_NAMES if n not in cfg.placeholders]
    print(f"dcs: {len(proven)} proven domain controller(s), {len(dcs) - len(proven)} unproven (Kerberos and LDAP "
          f"only, never used). Evidence: {cand}")
    for d in proven:
        print(f"  {d['account']:16} {', '.join(d['ips']):32} {d['dns_host_name']}")
    if proven and unset:
        print(f"placeholders your config leaves unset: {', '.join(unset)}. If the person says these are your DCs: "
              f"exception-guardian dcs --run {run} --use")
    elif proven:
        print("your config already sets every DC placeholder: nothing to add")
    return 0


def cmd_html(a) -> int:
    _refresh_html(_run_dir(a.run))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="exception-guardian", allow_abbrev=False)  # --appl must never mean --apply
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("find", allow_abbrev=False, help="grade every exception and write the report")
    f.add_argument("--config", default="guardian.yaml")
    f.add_argument("--out", required=True)
    f.add_argument("--today", type=_iso_day, help="grade as of this day (YYYY-MM-DD); default today")
    f.add_argument("--offline", action="store_true", help="no network: use the intel snapshot")
    f.add_argument("--previous", help="an earlier find output directory: also write changes.md (what got worse since)")
    f.add_argument("--exposure-claims", help="an exposure-evidence.json from the exposure command: use its verified "
                                             "claims (overrides exposure.claims_file)")
    f.set_defaults(fn=cmd_find)
    g = sub.add_parser("guard", allow_abbrev=False, help="detections, SIEM queries and hunt briefs for REVOKE exceptions")
    g.add_argument("--run", required=True, help="a find output directory")
    g.add_argument("--drafts", help="drafted Sigma rules (default: <run>/drafts)")
    g.add_argument("--config", help="default: the config find used for this run")
    g.set_defaults(fn=cmd_guard)
    ap = sub.add_parser("approve", allow_abbrev=False, help="write the approval plan; --apply disables confirmed Tenable VM rules")
    ap.add_argument("--run", required=True)
    ap.add_argument("--apply", action="store_true", help="opt-in: disable rules after per-rule confirmation")
    ap.add_argument("--base-url", help="Tenable VM API base URL, e.g. https://cloud.tenable.com")
    ap.set_defaults(fn=cmd_approve)
    d = sub.add_parser("dcs", allow_abbrev=False, help="find the domain controllers in the scan evidence (read-only) "
                                                       "for the SigmaHQ DC placeholders")
    d.add_argument("--run", required=True, help="a find output directory")
    d.add_argument("--use", action="store_true", help="after a person's yes: write this run's values from the "
                                                      "proven DCs (placeholders.found.yaml), which guard uses")
    d.set_defaults(fn=cmd_dcs)
    m = sub.add_parser("mock-tenable", allow_abbrev=False, help="serve a local mock of the Tenable VM API from fixtures")
    m.add_argument("--fixtures", default="samples/tenable_vm")
    m.add_argument("--port", type=int, default=8765)
    m.set_defaults(fn=cmd_mock)
    h = sub.add_parser("html", allow_abbrev=False, help="write report.html for a run (one self-contained page)")
    h.add_argument("--run", required=True, help="a find output directory")
    h.set_defaults(fn=cmd_html)
    e = sub.add_parser("exposure", allow_abbrev=False, help="verify Claude's exposure claims for a run: DNS and internet scans "
                                        "re-checked; document claims become a draft host list")
    e.add_argument("--run", required=True, help="a find output directory")
    e.add_argument("--claims", help="claims file (default <run>/exposure-claims.json)")
    e.set_defaults(fn=cmd_exposure)
    d = sub.add_parser("demo", allow_abbrev=False, help="offline end-to-end run on the samples: find -> guard -> approve (plan only)")
    d.add_argument("--out", default="out/demo")
    d.add_argument("--config", default="guardian.yaml")
    d.set_defaults(fn=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_env_file()
    try:
        return args.fn(args)
    # every RuntimeError raised here is a message written for the person (missing keys, a refused apply)
    except (UsageError, OSError, ValueError, RuntimeError, yaml.YAMLError) as exc:
        if os.environ.get("EG_DEBUG"):
            raise
        if isinstance(exc, FileNotFoundError) and exc.filename:
            msg = f"no such file or folder: {exc.filename}"
        elif isinstance(exc, yaml.YAMLError):  # a YAML file other than the config (the CSV column map)
            msg = f"a YAML file is not valid: {exc}"
        else:
            msg = str(exc)
        print(f"error: {msg}", file=sys.stderr)
        print("(set EG_DEBUG=1 to see the traceback)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
