"""Tenable Security Center: accept-risk and recast-risk rules (pyTenable sc.accept_risks / sc.recast_risks)."""
from __future__ import annotations

import json
import os
from datetime import date, datetime, timezone
from pathlib import Path

from ..cves import find_cves, split_cves
from ..models import Asset, RiskException, RuleType
from . import register


def _epoch(v) -> date | None:
    if v in (None, ""):
        return None
    n = int(float(v))
    if n <= 0:  # Security Center writes 0 or -1 for "never expires"; read as 1970 it looked long expired
        return None
    return datetime.fromtimestamp(n, tz=timezone.utc).date()


def _need(d: date | None) -> date:
    if d is None:
        raise ValueError("missing created date")
    return d


def _name(v):
    return v.get("name") if isinstance(v, dict) else v


def parse(rules: list[dict], rtype: RuleType) -> list[RiskException]:
    out = []
    for r in rules:
        try:
            out.append(_one(r, rtype))
        except Exception as exc:  # one malformed rule must not sink every other rule
            LAST_WARNINGS.append(f"source tenable-sc failed: rule {str(r.get('id', '?'))[:60]} skipped "
                                 f"({type(exc).__name__}: {exc})")
    return out


def _one(r: dict, rtype: RuleType) -> RiskException:
    plugin = r.get("plugin") or {}
    return RiskException(
        source="tenable-sc", rule_id=str(r["id"]), rule_type=rtype,
        cves=split_cves(r.get("x_cves") or [])[0], plugin_ids=(str(plugin["id"]),) if plugin.get("id") else (),
        targets=("*",) if r.get("hostType") == "all" else
        tuple(t.strip() for t in str(r.get("hostValue", "")).split(",") if t.strip()),
        original_severity=_name(r.get("severity")),
        new_severity=_name(r.get("newSeverity")) if rtype is RuleType.RECAST else None,
        owner=(r.get("user") or {}).get("username"),
        created=_need(_epoch(r["createdTime"])), updated=_epoch(r.get("modifiedTime")), expires=_epoch(r.get("expires")),
        justification=str(r.get("comments") or ""), status="enabled", revised_findings=None, raw=r)


def _num(v) -> float | None:
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def parse_hosts(rows: list[dict], critical_acr: float = 9) -> list[Asset]:
    """SC hosts from the vulnerability analysis tool `sumip`: one row per IP and repository."""
    from ..assets import _public
    out = []
    for r in rows:
        ip = str(r.get("ip") or "").strip()
        if not ip:
            continue
        repo = str((r.get("repository") or {}).get("id") or "")
        dns = str(r.get("dnsName") or "").strip()
        acr = _num(r.get("acrScore"))
        out.append(Asset(id=f"sc:{repo}:{ip}", name=dns or str(r.get("netbiosName") or "").strip() or ip, os=None,
                         ips=(ip,), fqdns=(dns,) if dns else (), tags=(f"repository:{repo}",) if repo else (),
                         internet_facing=False, exposure_since=None,
                         critical=(acr >= critical_acr) if acr is not None else None, on_attack_path=None,
                         public_ips=_public([ip]), origin="sc", acr=acr, aes=_num(r.get("assetExposureScore")),
                         context_source="Tenable SC host summary"))
    return out


#: SC hosts read with the rules (live: analysis tool sumip; samples: hosts.json); find grades SC rules on them.
LAST_HOSTS: list[dict] = []


def cves_from_xrefs(xrefs: str) -> tuple[str, ...]:
    """SC plugin xrefs look like 'CVE:CVE-2025-22868, BID:1234'."""
    return find_cves(xrefs)


#: Fields asked for on the live list (SC returns only a short default set otherwise).
FIELDS = ("id", "createdTime", "modifiedTime", "expires", "comments", "hostType", "hostValue", "plugin", "user",
          "port", "protocol", "repository", "status")

#: Warnings from the last live read (plugin lookups that failed); read_all collects them.
LAST_WARNINGS: list[str] = []


def _env(var: str) -> str:
    """A key from the environment, named when missing (as the VM client does), never shown."""
    if not os.environ.get(var):
        raise RuntimeError(f"environment variable {var} is not set")
    return os.environ[var]


@register("tenable-sc")
def read(params: dict) -> list[RiskException]:
    LAST_WARNINGS.clear()
    LAST_HOSTS.clear()
    if "fixture_dir" in params:
        d = Path(params["fixture_dir"])
        if (d / "hosts.json").exists():
            LAST_HOSTS[:] = json.loads((d / "hosts.json").read_text())["hosts"]
        accept = json.loads((d / "accept_risks.json").read_text())["rules"]
        recast = json.loads((d / "recast_risks.json").read_text())["rules"]
    else:
        from tenable.sc import TenableSC  # live mode only
        host = params.get("host") or _env("TENABLE_SC_HOST")
        from .. import __version__
        # Tenable asks integrations to identify themselves (User-Agent), as the VM client does
        # keys go to the constructor: built without them, pyTenable warns "Starting an unauthenticated session" on
        # every run before login() (a live user's agent stopped to ask whether the read had failed, 4 Nov 2026)
        sc = TenableSC(host, access_key=_env("TENABLE_SC_ACCESS_KEY"), secret_key=_env("TENABLE_SC_SECRET_KEY"),
                       vendor="wh0-Kn0w5", product="Exception Guardian", build=__version__)
        # the list call returns a short default field set; name every field the parser reads
        accept = list(sc.accept_risks.list(fields=list(FIELDS)))
        recast = list(sc.recast_risks.list(fields=list(FIELDS + ("newSeverity", "severity"))))
        from . import enrich_plugin_cves
        rules, warn = enrich_plugin_cves(parse(accept, RuleType.ACCEPT) + parse(recast, RuleType.RECAST),
                                         lambda pid: cves_from_xrefs(sc.plugins.details(int(pid), fields=["xrefs"]).get("xrefs", "")))
        LAST_WARNINGS.extend(warn)
        try:  # read-only: the host summary the rules apply to (capped; the cap is reported)
            import itertools
            cap = int(params.get("max_hosts", 50000))
            LAST_HOSTS[:] = list(itertools.islice(sc.analysis.vulns(tool="sumip"), cap + 1))
            if len(LAST_HOSTS) > cap:
                del LAST_HOSTS[cap:]
                LAST_WARNINGS.append(f"source tenable-sc hosts: read the first {cap:,} only, so SC rules were "
                                     "matched to those hosts")
        except Exception as exc:
            LAST_WARNINGS.append(f"source tenable-sc hosts failed: not read ({type(exc).__name__}: {exc}), so SC rules "
                                 "were graded without host context")
        return rules
    return parse(accept, RuleType.ACCEPT) + parse(recast, RuleType.RECAST)
