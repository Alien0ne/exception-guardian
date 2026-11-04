"""Which assets face the internet, from what the company actually has: its own tag names, internet ranges, a host
list (a firewall, load-balancer, CMDB or attack-surface export) and verified agent claims. Each marks
internet_facing and records why, so the report can cite it. Problems here are notes, not failed sources."""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from dataclasses import replace
from pathlib import Path

from .assets import tag_key
from .config import ExposureConfig
from .models import Asset

_INTERNET_WORD = re.compile(r"internet|external|public|dmz|perimeter", re.I)  # only names a tag; never marks one
NO_EXPOSURE_NOTE = ("exposure: no asset is marked internet-facing by a tag, an internet range or a host list, so "
                    "INTERNET_FACING cannot fire and public IPs are hints only (PUBLIC_IP). Set `exposure` in the "
                    "config to say what faces the internet.")


def _ips(a: Asset):
    for i in a.ips:
        try:
            yield ipaddress.ip_address(i)
        except ValueError:
            pass


def _read_hosts(path: Path) -> dict[str, str]:
    """host (name, FQDN or IP) → where the company says it came from."""
    out: dict[str, str] = {}
    with path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            host = str(row.get("host") or "").strip().lower()
            if host:
                out[host] = str(row.get("source") or "").strip()
    return out


def apply_exposure(assets: list[Asset], ex: ExposureConfig) -> tuple[list[Asset], list[str]]:
    notes: list[str] = []
    tags = {tag_key(t) for t in ex.internet_tags}
    nets = []
    for r in ex.internet_ranges:
        try:
            nets.append((r, ipaddress.ip_network(r, strict=False)))
        except ValueError:
            notes.append(f"exposure: internet range {r!r} is not a CIDR range, so it is ignored")
    hosts: dict[str, str] = {}
    hosts_name = ""
    if ex.internet_hosts_file:
        p = Path(ex.internet_hosts_file)
        hosts_name = p.name
        try:
            hosts = _read_hosts(p)
        except (OSError, csv.Error) as exc:
            notes.append(f"source exposure failed: host list {p} could not be read ({exc}), so its hosts are not marked")
    seen_open: dict[str, str] = {}
    dns: dict[str, list[str]] = {}
    if ex.claims_file:
        try:
            for v in json.loads(Path(ex.claims_file).read_text()).get("verified") or []:
                if v.get("kind") == "seen_open":
                    seen_open.setdefault(str(v["asset_id"]), str(v["evidence"]))
                elif v.get("kind") == "public_dns":
                    dns.setdefault(str(v["asset_id"]), []).append(str(v["value"]))
        except (OSError, ValueError, KeyError, AttributeError) as exc:
            notes.append(f"source exposure failed: evidence file {ex.claims_file} could not be read ({exc}), so it is not used")
    out = []
    for a in assets:
        why = next((f"tag {t}" for t in a.tags if tag_key(t) in tags), "")
        if not why:
            why = next((f"internet range {r}" for r, n in nets for ip in _ips(a) if ip in n), "")
        if not why and hosts:
            for key in (a.name, *a.fqdns, *a.ips, a.id):
                src = hosts.get(str(key).lower())
                if src is not None:
                    why = f"host list {hosts_name}" + (f" ({src})" if src else "")
                    break
        if not why and a.id in seen_open:
            why = seen_open[a.id]
        out.append(replace(a, internet_facing=bool(why), exposure_reason=why,
                           public_dns=tuple(dns.get(a.id, ())) or a.public_dns))
    if assets and not any(a.internet_facing for a in out):
        notes.append(NO_EXPOSURE_NOTE)
        looks = _INTERNET_WORD
        seen: dict[str, int] = {}
        for a in out:
            for t in dict.fromkeys(a.tags):
                if looks.search(t):
                    seen[t] = seen.get(t, 0) + 1
        for t, n in sorted(seen.items(), key=lambda kv: -kv[1])[:3]:
            notes.append(f"exposure: {n:,} asset{' carries' if n == 1 else 's carry'} the tag {t}, which reads like "
                         "an internet tag. If it means internet-facing, add it to `exposure.internet_tags` in the "
                         "config.")
        public = sum(1 for a in out if a.public_ips)
        if public:
            notes.append(f"exposure: {public:,} asset{' has' if public == 1 else 's have'} a public IP. "
                         "`exposure-candidates.json` in this run lists every asset, and Step 1b (map exposure) can "
                         "draft a host list for `exposure.internet_hosts_file` from public records, for you to review.")
    return out, notes
