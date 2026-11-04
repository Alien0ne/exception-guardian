"""KEV + EPSS enrichment: live feeds when online, a dated snapshot when offline or when a fetch fails."""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Callable

from .config import Config
from .models import CveIntel

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_HISTORY_START = date(2021, 4, 14)  # FIRST keeps EPSS scores from this day on
BATCH = 100


def _http_get(url: str) -> dict:
    import requests
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()


class _Skipped(Exception):
    """A live request not tried because an earlier one could not reach the server."""


def _unreachable(err: Exception) -> bool:
    """A connection error or timeout (the network is down), not an HTTP error from a server that answered."""
    if isinstance(err, (ConnectionError, TimeoutError)):
        return True
    return any(n in type(c).__name__ for c in type(err).__mro__ for n in ("ConnectionError", "Timeout"))


def _kev_index(data: dict) -> dict[str, dict]:
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def _epss_latest(data: dict) -> date | None:
    days = [r["date"] for r in data.get("data", []) if r.get("date")]
    return date.fromisoformat(max(days)) if days else None


def _epss_scores(data: dict) -> dict[str, float]:
    return {r["cve"]: float(r["epss"]) for r in data.get("data", [])}


def build_intel(created_by_cve: dict[str, list[date]], cfg: Config,
                fetch: Callable[[str], dict] | None = None) -> tuple[dict[tuple[str, date], CveIntel], list[str]]:
    snap_dir = Path(cfg.intel_snapshot_dir)
    try:  # the snapshot is the offline source and the fallback: an online run works without one
        snap_kev = _kev_index(json.loads((snap_dir / "kev.json").read_text()))
        snap_epss = json.loads((snap_dir / "epss.json").read_text())
    except FileNotFoundError:
        if cfg.offline:
            raise ValueError(f"offline: no KEV/EPSS snapshot (kev.json, epss.json) in {snap_dir}. Set "
                             "intel_snapshot_dir to one, or set offline: false") from None
        snap_kev, snap_epss = {}, {"snapshot_date": None, "now": {}, "history": {}}
    snap_tag = f"snapshot:{snap_epss['snapshot_date']}"
    warnings: list[str] = []
    snapped: set[str] = set()  # CVEs whose KEV entry or EPSS today came from the snapshot
    then_snapped: set[tuple[str, date]] = set()  # (CVE, day) whose EPSS at acceptance came from the snapshot
    latest: date | None = None  # FIRST's newest published day: later acceptance days have no history yet
    down = False  # after a connection error or timeout, the rest of the run uses the snapshot without waiting

    def fail(err: Exception) -> None:
        nonlocal down
        down = down or _unreachable(err)
        msg = (f"source KEV/EPSS failed: live fetch failed ({type(err).__name__}: {err}), so the snapshot from "
               f"{snap_epss['snapshot_date']} is used" if snap_epss["snapshot_date"] else
               f"source KEV/EPSS failed: live fetch failed ({type(err).__name__}: {err}) and there is no snapshot in "
               f"{snap_dir}, so those CVEs have no KEV or EPSS data")
        if msg not in warnings:
            warnings.append(msg)

    def get(url: str) -> dict:
        if down:
            raise _Skipped()
        return fetch(url)

    cves = sorted(created_by_cve)
    if cfg.offline:
        kev, now = snap_kev, dict(snap_epss["now"])
        snapped.update(cves)
    else:
        fetch = fetch or _http_get
        try:
            kev = _kev_index(get(KEV_URL))
        except Exception as err:
            fail(err); kev = snap_kev; snapped.update(cves)
        now: dict[str, float] = {}
        for i in range(0, len(cves), BATCH):
            chunk = cves[i:i + BATCH]
            try:
                page = get(f"{EPSS_URL}?cve={','.join(chunk)}")
                now.update(_epss_scores(page))
                day = _epss_latest(page)
                latest = max(latest, day) if latest and day else latest or day
            except Exception as err:
                if not isinstance(err, _Skipped):
                    fail(err)
                snapped.update(chunk)
                now.update({c: snap_epss["now"][c] for c in chunk if c in snap_epss["now"]})

    # EPSS on each acceptance date: one request per date and batch of CVEs, none before FIRST's history starts
    then: dict[tuple[str, date], float] = {}
    if not cfg.offline:
        by_day: dict[date, list[str]] = {}
        for cve in cves:
            for created in created_by_cve[cve]:
                if latest and created > latest:  # accepted after FIRST's newest scores: those are the score then
                    if cve in now and cve not in snapped:
                        then[(cve, created)] = now[cve]
                elif created >= EPSS_HISTORY_START:
                    by_day.setdefault(created, []).append(cve)
        for day, day_cves in sorted(by_day.items()):
            for i in range(0, len(day_cves), BATCH):
                chunk = day_cves[i:i + BATCH]
                try:
                    got = _epss_scores(get(f"{EPSS_URL}?cve={','.join(chunk)}&date={day.isoformat()}"))
                    then.update({(c, day): got[c] for c in chunk if c in got})
                except Exception as err:
                    if not isinstance(err, _Skipped):
                        fail(err)
                    then_snapped.update((c, day) for c in chunk)
                    then.update({(c, day): v for c in chunk
                                 if (v := snap_epss["history"].get(c, {}).get(day.isoformat())) is not None})

    out: dict[tuple[str, date], CveIntel] = {}
    for cve in cves:
        k = kev.get(cve)
        for created in created_by_cve[cve]:
            at = (snap_epss["history"].get(cve, {}).get(created.isoformat()) if cfg.offline
                  else then.get((cve, created)))
            out[(cve, created)] = CveIntel(
                cve=cve, in_kev=k is not None,
                kev_date_added=date.fromisoformat(k["dateAdded"]) if k else None,
                kev_ransomware=bool(k) and k.get("knownRansomwareCampaignUse") == "Known",
                epss_now=now.get(cve), epss_at_created=at,
                source="live")
    return {key: replace(v, source=snap_tag) if key[0] in snapped
            else replace(v, epss_then_source=snap_tag) if key in then_snapped else v
            for key, v in out.items()}, warnings
