"""Map exposure: Claude proposes exposure claims for covered assets that have no exposure evidence; this module
verifies them. Claims are untrusted (Claude read untrusted text to make them), so nothing in a claim is believed:
a DNS claim counts only if we resolve the name ourselves to a public address of that asset; an internet-scan claim
only if we fetch the scan ourselves and it is recent; a document claim (a firewall or CMDB line) can't be checked
by code, so it becomes a row in a draft host list for a person to approve, never evidence by itself."""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import socket
from datetime import date
from pathlib import Path
from typing import Callable

_HOST = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
KINDS = ("dns", "internet_scan", "document")
MAX_AGE_DAYS = 90


def candidates(findings: dict) -> list[dict]:
    """Covered assets with no exposure evidence: what Claude is asked to look into."""
    seen: dict[str, dict] = {}
    for f in findings["findings"]:
        for a in f.get("assets", []):
            if not a.get("internet_facing") and a["id"] not in seen:
                seen[a["id"]] = {k: a.get(k) for k in ("id", "name", "ips", "fqdns", "public_ips",
                                                       "tenable_public", "internet_facing", "origin")}
    return list(seen.values())


def resolve_dns(name: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(name, None)})
    except OSError:
        return []


def shodan_lookup(ip: str) -> dict | None:
    """Shodan's record for an IP (ports, last_update), with SHODAN_API_KEY. Passive: Shodan's own scan data."""
    import requests
    # Shodan takes its key in the URL, and requests puts the URL in its errors: never let one through
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": os.environ["SHODAN_API_KEY"],
                                                                           "minify": "true"}, timeout=20)
    except requests.RequestException as exc:
        raise RuntimeError(f"Shodan could not be reached ({type(exc).__name__})") from None
    if r.status_code == 404:
        return None
    if r.status_code >= 400:
        raise RuntimeError(f"Shodan answered {r.status_code} {r.reason or ''}".rstrip())
    try:
        return r.json()
    except ValueError:
        raise RuntimeError("Shodan sent a reply that is not JSON") from None


def _global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def verify_claims(claims, findings: dict, today: date, resolve: Callable = resolve_dns,
                  internet_scan: Callable | None = None) -> tuple[list[dict], list[dict], list[dict]]:
    assets = {c["id"]: c for c in candidates(findings)}
    verified, drafted, rejected = [], [], []
    stamp = f"agent-found, verified {today.isoformat()}"
    for c in claims if isinstance(claims, list) else []:
        def reject(reason):
            rejected.append({"claim": c if isinstance(c, dict) else str(c)[:200], "reason": reason})
        if not isinstance(c, dict) or c.get("kind") not in KINDS:
            reject("not a claim: needs asset_id, kind (dns, internet_scan, document), value, source"); continue
        a = assets.get(str(c.get("asset_id")))
        if a is None:
            reject("unknown asset: not a covered asset without exposure evidence"); continue
        value, source = str(c.get("value") or "").strip(), " ".join(str(c.get("source") or "").split())[:300]
        if c["kind"] == "document":
            # the draft list is opened in a spreadsheet: a cell starting = + - @ would run as a formula
            if not value or len(value) > 253 or any(ch in value for ch in ",\n\r\"") or value[0] in "=+-@":
                reject("document claim needs a host name, FQDN or IP as value"); continue
            drafted.append({"host": value, "source": source}); continue
        if c["kind"] == "dns":
            if not _HOST.match(value):
                reject("not a DNS name"); continue
            ips = resolve(value)
            mine = [i for i in ips if i in (a.get("ips") or [])]
            if not mine:
                reject("does not resolve to this asset"); continue
            public = [i for i in mine if _global(i)]
            if not public:
                reject(f"resolves only to private addresses ({', '.join(mine)})"); continue
            verified.append({"asset_id": a["id"], "kind": "public_dns", "value": value,
                             "evidence": f"public DNS name {value} resolves to {', '.join(public)} ({stamp})"})
            continue
        # internet_scan
        if value not in (a.get("ips") or []) or not _global(value):
            reject("not a public address of this asset"); continue
        if internet_scan is None:
            reject("cannot verify: no internet scan source (set SHODAN_API_KEY)"); continue
        try:
            rec = internet_scan(value)
            ports = sorted({int(p) for p in (rec or {}).get("ports") or []})
            seen = date.fromisoformat(str((rec or {}).get("last_update", ""))[:10]) if ports else None
        except Exception as exc:  # one bad scan record or a failed lookup rejects this claim, not the whole step
            reject(f"cannot verify: the internet scan could not be read ({type(exc).__name__}: {str(exc)[:120]})")
            continue
        if not ports:
            reject("the internet scan shows no open ports"); continue
        if (today - seen).days > MAX_AGE_DAYS:
            reject(f"last seen {seen}, more than {MAX_AGE_DAYS} days ago"); continue
        verified.append({"asset_id": a["id"], "kind": "seen_open", "value": value,
                         "evidence": f"seen open from the internet on {seen}: ports {', '.join(map(str, ports))} ({stamp})"})
    return verified, drafted, rejected


def run_exposure(run: Path, claims_path: Path, today: date | None = None) -> dict:
    findings = json.loads((run / "findings.json").read_text())
    claims = json.loads(claims_path.read_text())
    scan = shodan_lookup if os.environ.get("SHODAN_API_KEY") else None
    today = today or date.fromisoformat(findings["today"])  # the run's own date, as grading used
    v, d, r = verify_claims(claims, findings, today, resolve=resolve_dns, internet_scan=scan)
    (run / "exposure-evidence.json").write_text(json.dumps({"verified": v, "rejected": r}, indent=2))
    with (run / "exposure-drafted-hosts.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["host", "source"])
        w.writeheader()
        w.writerows(d)
    return {"verified": len(v), "drafted": len(d), "rejected": len(r)}
