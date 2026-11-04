"""Asset context: exposure, criticality, attack path; matching exception targets to assets."""
from __future__ import annotations

import ipaddress
import json
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import urlparse

from .models import Asset


def _first(v):
    return v[0] if isinstance(v, list) and v else (v or None)


def _public(ips) -> tuple[str, ...]:
    out = []
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).is_global:
                out.append(ip)
        except ValueError:
            pass
    return tuple(out)


def parse_assets(rows: list[dict]) -> list[Asset]:
    out = []
    for r in rows:
        ips = tuple(r.get("ipv4") or []) + tuple(r.get("ipv6") or [])
        tags = tuple(f"{t['tag_key']}:{t['tag_value']}" for t in r.get("tags") or [])
        since = r.get("x_exposure_since")
        out.append(Asset(
            id=str(r["id"]), name=str(_first(r.get("hostname")) or _first(r.get("netbios_name")) or r["id"]),
            os=_first(r.get("operating_system")), ips=ips, fqdns=tuple(r.get("fqdn") or []), tags=tags,
            # Exposure comes from the config's tags, ranges and host list (exposure.py), never a fixed tag name. A
            # public IP alone is a hint (PUBLIC_IP, REVIEW): some switches carry 128.0.0.x as internal routing.
            internet_facing=False, public_ips=_public(ips), exposure_reason="",
            exposure_since=date.fromisoformat(since) if since else None,
            critical=r.get("x_critical"), on_attack_path=r.get("x_on_attack_path")))
    return out


def parse_webapps(rows: list[dict]) -> list[Asset]:
    """Web app assets (POST /api/v3/assets/webapp/search). They carry no exposure tag here, so exposure comes
    only from a public IP, as a hint (PUBLIC_IP)."""
    out = []
    for r in rows:
        ips = tuple(r.get("ipv4_addresses") or []) + tuple(r.get("ipv6_addresses") or [])
        host = urlparse(r["url"]).hostname if r.get("url") else None
        fqdns = tuple(dict.fromkeys(x.lower() for x in (r.get("domain"), host) if x))
        name = str(r.get("name") or "").strip() or (host or str(r["id"]))
        out.append(Asset(id=str(r["id"]), name=name, os=None, ips=ips, fqdns=fqdns, tags=(), internet_facing=False,
                         exposure_since=None, critical=None, on_attack_path=None, public_ips=_public(ips),
                         origin="webapp"))
    return out


def parse_v3_hosts(rows: list[dict]) -> list[Asset]:
    """Hosts from the v3 host search: name and addresses only, no tags, so only PUBLIC_IP can fire on them."""
    out = []
    for r in rows:
        ips = tuple(r.get("ipv4_addresses") or []) + tuple(r.get("ipv6_addresses") or [])
        out.append(Asset(id=str(r["id"]), name=str(r.get("name") or r.get("host_name") or r["id"]), os=None, ips=ips,
                         fqdns=(), tags=(), internet_facing=False, exposure_since=None, critical=None,
                         on_attack_path=None, public_ips=_public(ips), origin="host-search",
                         tenable_public=r.get("is_public")))
    return out


#: Warnings from the last live asset read (the web app list failed); run_find adds them to the run.
LAST_WARNINGS: list[str] = []


def load_assets(params: dict) -> list[Asset]:
    LAST_WARNINGS.clear()
    if "fixture" in params:
        return parse_assets(json.loads(Path(params["fixture"]).read_text())["assets"])
    if "base_url" in params:
        from .tenable_client import TenableVMClient
        client = TenableVMClient.from_env(params["base_url"])
        rows, total = client.list_assets_with_total()
        hosts = parse_assets(rows)
        at_cap = len(rows) >= client.ASSET_LIST_CAP or (total is not None and total > len(rows))
        try:
            v3, capped = client.list_hosts_v3()
            seen = {a.id for a in hosts}
            extra = [a for a in parse_v3_hosts(v3) if a.id not in seen]
            hosts += extra
            if at_cap:
                LAST_WARNINGS.append(
                    f"source assets (tags) failed: the asset list stops at 5,000, so {len(extra)} more hosts came from "
                    "the host search without tags, so INTERNET_FACING cannot fire for them (PUBLIC_IP still can)")
            if capped:
                LAST_WARNINGS.append("source assets (host search) failed: stopped at 50,000 hosts, and the rest were not read")
        except Exception as exc:
            if at_cap:
                LAST_WARNINGS.append(f"source assets failed: the asset list stops at 5,000 and the host search failed "
                                     f"({exc}), so hosts past the first 5,000 are missing")
            else:
                LAST_WARNINGS.append(f"asset host search failed (hosts not seen in 90 days were not read): {exc}")
        try:
            return hosts + parse_webapps(client.list_webapps())
        except Exception as exc:  # hosts still count; web app targets show ASSET_UNKNOWN and the run is partial
            LAST_WARNINGS.append(f"source assets (web apps) failed: {exc}")
            return hosts
    return []


ALL_ASSETS = "*"


def covers(assets_cfg: dict, source: str) -> bool:
    """Whether the configured asset list holds the hosts an exception from `source` refers to. A live Tenable VM
    list covers Tenable VM and file exports, not Security Center, whose rules name SC repository hosts.
    `for_sources: [...]` in the assets config overrides this; sample data covers every source."""
    if "for_sources" in assets_cfg:
        return source in assets_cfg["for_sources"]
    return not ("base_url" in assets_cfg and source == "tenable-sc")


def _ip_set(target: str):
    """A CIDR ('10.0.0.0/24') or range ('10.0.0.5-10.0.0.9') target as a membership test, else None."""
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return lambda ip: ip in net
        if "-" in target:
            lo, hi = (ipaddress.ip_address(x.strip()) for x in target.split("-", 1))
            return lambda ip: lo <= ip <= hi if ip.version == lo.version else False
    except ValueError:
        return None
    return None


def match(targets: tuple[str, ...], assets: list[Asset]) -> list[Asset]:
    """Assets an exception covers. '*' = every asset; 'tag:<key>:<value>'; CIDR and IP ranges; else id/name/IP/FQDN.
    '!x' excludes what x matches (a 'not equal' filter: every asset except x when nothing else is named);
    '?prop=v' is a scope we cannot evaluate, so it matches nothing (the grader notes it)."""
    neg = tuple(t[1:] for t in targets if t.startswith("!"))
    pos = tuple(t for t in targets if not t.startswith(("!", "?")))
    if neg:
        base = _match(pos, assets) if pos else ([] if any(t.startswith("?") for t in targets) else list(assets))
        drop = {id(a) for a in _match(neg, assets)}
        return [a for a in base if id(a) not in drop]
    return _match(pos, assets)


def tag_key(t: str) -> str:
    """A tag as key:value, trimmed and lower case: "Zone : DMZ" and "zone:dmz" are the same tag."""
    k, _, v = str(t).partition(":")
    return f"{k.strip().lower()}:{v.strip().lower()}"


def _match(targets: tuple[str, ...], assets: list[Asset]) -> list[Asset]:
    if ALL_ASSETS in targets:
        return list(assets)
    wanted = {t.lower() for t in targets}
    tags = {t[4:].lower() for t in wanted if t.startswith("tag:")}
    # "prod-*" or "tag:env:prod*": a wildcard filter means a pattern, never the literal text
    globs = [t for t in wanted if "*" in t and not t.startswith("tag:")]
    tag_globs = [t for t in tags if "*" in t]
    ranges = [r for r in (_ip_set(t) for t in targets) if r]
    hits = []
    for a in assets:
        keys = {a.id.lower(), a.name.lower(), *(i.lower() for i in a.ips), *(f.lower() for f in a.fqdns)}
        ips = []
        for i in a.ips:
            try:
                ips.append(ipaddress.ip_address(i))
            except ValueError:
                pass
        own_tags = {tag_key(t) for t in a.tags}
        if (keys & wanted or tags & own_tags or any(r(ip) for r in ranges for ip in ips)
                or any(fnmatchcase(k, g) for g in globs for k in keys)
                or any(fnmatchcase(t, g) for g in tag_globs for t in own_tags)):
            hits.append(a)
    return hits
