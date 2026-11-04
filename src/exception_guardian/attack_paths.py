"""Tenable One attack paths (Attack Path Analysis, top-attack-paths search) and which exceptions they touch.

An exception hides a CVE. If Tenable One shows an attack path that uses that CVE on the asset itself, or across a
network the asset sits in, the "accepted" risk is a step an attacker can take now: REVOKE. The same CVE in a path
elsewhere in the tenant is a REVIEW hint. Read-only: one search, paged."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass

from .models import Asset

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
MIN_PREFIX = {4: 16, 6: 48}  # a path through a wider network (0.0.0.0/0, a /8) says nothing about one host
LAST_SKIPPED = 0  # paths dropped by the last parse_paths (malformed)


@dataclass(frozen=True)
class AttackPath:
    name: str
    priority: float | None
    steps: tuple[str, ...]  # node names, first to last
    cves: tuple[str, ...]
    asset_ids: tuple[str, ...]
    networks: tuple[str, ...]  # nodes that are an IP network (CIDR)
    from_internet: bool

    def line(self) -> str:
        prio = f" (priority {self.priority:g})" if self.priority is not None else ""
        return " → ".join(self.steps) + prio


def _network(name: str):
    try:
        return ipaddress.ip_network(name, strict=False) if "/" in name else None
    except ValueError:
        return None


def parse_paths(raw: list[dict]) -> list[AttackPath]:
    global LAST_SKIPPED
    out, LAST_SKIPPED = [], 0
    for p in raw or []:
        try:
            out.append(_path(p))
        except Exception:  # one malformed path must not drop the others
            LAST_SKIPPED += 1
    return out


def _path(p: dict) -> AttackPath:
    nodes = p.get("nodes") or []
    cves = tuple(dict.fromkeys(c.upper() for c in _CVE.findall(json.dumps(p.get("techniques") or []))))
    names = tuple(str(n.get("name") or "?") for n in nodes)
    return AttackPath(
        name=str(p.get("name") or " to ".join(names[:1] + names[-1:])),
        priority=float(p["priority"]) if p.get("priority") is not None else None,
        steps=names, cves=cves, asset_ids=tuple(str(n["asset_id"]) for n in nodes if n.get("asset_id")),
        networks=tuple(n for n in names if _network(n)),
        from_internet=bool(nodes) and "Internet" in (nodes[0].get("labels") or []))


def links(path: AttackPath, assets) -> list[str]:
    """How a path touches the covered assets: 'the path reaches X' or 'X (ip) is on net'."""
    out = []
    for a in assets:
        if a.id in path.asset_ids:
            out.append(f"the path reaches {a.name}")
            continue
        for net in path.networks:
            n = _network(net)
            if n.prefixlen < MIN_PREFIX[n.version]:
                continue
            ip = next((i for i in a.ips if _in(i, n)), None)
            if ip:
                out.append(f"{a.name} ({ip}) is on {net}")
                break
    return out


def _in(ip: str, net) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def touching(cves, assets: list[Asset], paths: list[AttackPath]):
    """(linked, elsewhere): paths using one of `cves` that touch the assets, and those that do not."""
    want = set(cves)
    linked, elsewhere = [], []
    for p in sorted(paths, key=lambda p: -(p.priority or 0)):
        hit = want.intersection(p.cves)
        if not hit:
            continue
        how = links(p, assets)
        (linked if how else elsewhere).append((p, sorted(hit), how))
    return linked, elsewhere


def load_paths(assets_cfg: dict, client) -> tuple[list[AttackPath], list[str]]:
    """Paths from `assets.attack_paths` (a sample file) or, for a live Tenable VM list, from Tenable One. A tenant
    without Tenable One, or a failed read, is a note: grading goes on without paths."""
    if "attack_paths" in assets_cfg:
        from pathlib import Path
        return parse_paths(json.loads(Path(assets_cfg["attack_paths"]).read_text())["paths"]), []
    if "base_url" not in assets_cfg or client is None:
        return [], []
    try:
        got = client.attack_paths()
    except Exception as exc:
        return [], [f"source attack paths failed: not read ({exc}), so grading used path counts only"]
    if got is None:
        return [], ["attack paths: not read (no Tenable One on this tenant)"]
    raw, capped = got
    paths = parse_paths(raw)
    notes = [f"attack paths: read the top {len(raw)} only"] if capped else []
    if LAST_SKIPPED:
        notes.append(f"attack paths: {LAST_SKIPPED} could not be read, so they were skipped")
    return paths, notes
