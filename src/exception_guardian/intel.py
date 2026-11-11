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


RETRY_CODES = (429, 500, 502, 503, 504)
BACKOFF = (1.0, 3.0)  # waits before the second and third try
MAX_WAIT = 30.0  # a Retry-After longer than this is not waited out


def _sleep(seconds: float) -> None:
    import time
    time.sleep(seconds)


def _http_get(url: str) -> dict:
    """One live GET. A busy server (429, 5xx) is tried three times; a network that is down is not retried, so an
    offline machine falls back to the snapshot at once."""
    import requests
    for attempt in range(len(BACKOFF) + 1):
        resp = requests.get(url, timeout=10)
        if resp.status_code in RETRY_CODES and attempt < len(BACKOFF):
            try:
                wait = float(resp.headers.get("Retry-After", ""))
            except (TypeError, ValueError):
                wait = BACKOFF[attempt]
            _sleep(min(max(wait, 0.0), MAX_WAIT))
            continue
        resp.raise_for_status()
        return resp.json()
    raise AssertionError("unreachable")


CACHE_FILE = "epss-history.json"
_OFF = ("off", "none", "false", "no", "0")


def cache_dir(cfg: Config) -> Path | None:
    """Where EPSS history is kept: `intel_cache_dir`, else $EG_CACHE_DIR, else the user's cache folder. "off"
    switches it off."""
    import os
    chosen = cfg.intel_cache_dir or os.environ.get("EG_CACHE_DIR") or ""
    if chosen.strip().lower() in _OFF:
        return None
    if chosen:
        return Path(chosen).expanduser()
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "exception-guardian"


def _cache_key(cve: str, day: date) -> str:
    return f"{cve}|{day.isoformat()}"


def _load_cache(folder: Path | None) -> dict[str, float | None]:
    """EPSS on a past day never changes, so it is kept for good. The file is data from disk: anything that is not a
    score between 0 and 1 (or null, "no score that day") is dropped and asked for again."""
    if folder is None:
        return {}
    try:
        raw = json.loads((folder / CACHE_FILE).read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if v is None or
            (isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1)}


def _save_cache(folder: Path | None, cache: dict) -> None:
    if folder is None:
        return
    import os
    try:
        folder.mkdir(parents=True, exist_ok=True)
        tmp = folder / f"{CACHE_FILE}.{os.getpid()}.tmp"
        tmp.write_text(json.dumps(cache, sort_keys=True))
        tmp.replace(folder / CACHE_FILE)  # whole file or nothing: a second run never reads half a write
    except OSError:
        pass  # a cache that cannot be written costs requests next time, never a wrong grade


def write_snapshot(intel: dict, out_dir: Path, today: date, exploits: dict | None = None) -> Path:
    """Save the intel a run fetched live as a dated snapshot (kev.json, epss.json, exploits.json) that an offline run
    reads through intel_snapshot_dir. Only live values are saved: a value that itself came from an older snapshot
    would be passed off as fresh. `exploits` is the raw feed index ({feed: {cve: entry}})."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    kev: dict[str, dict] = {}
    now: dict[str, float] = {}
    history: dict[str, dict[str, float]] = {}
    for (cve, created), v in sorted(intel.items()):
        if v.source != "live":
            continue
        if v.in_kev and v.kev_date_added:
            kev[cve] = {"cveID": cve, "dateAdded": v.kev_date_added.isoformat(),
                        "knownRansomwareCampaignUse": "Known" if v.kev_ransomware else "Unknown"}
        if v.epss_now is not None:
            now[cve] = v.epss_now
        if v.epss_at_created is not None and v.epss_then_source is None:
            history.setdefault(cve, {})[created.isoformat()] = v.epss_at_created
    live = {cve for (cve, _), v in intel.items() if v.source == "live"}
    index: dict[str, dict] = {}
    for feed, entries in (exploits or {}).items():
        for cve in live & set(entries):
            index.setdefault(cve, {})[feed] = entries[cve]
    day = today.isoformat()
    files = {"kev.json": {"title": "CISA KEV entries for this run's CVEs", "_source": f"{KEV_URL} (subset, fetched {day})",
                          "count": len(kev), "vulnerabilities": list(kev.values())},
             "epss.json": {"snapshot_date": day, "_source": f"{EPSS_URL} (fetched {day})", "now": now, "history": history},
             "exploits.json": {"snapshot_date": day, "index": dict(sorted(index.items()))}}
    for name, data in files.items():
        tmp = out_dir / f"{name}.tmp"
        tmp.write_text(json.dumps(data, indent=1) + "\n")
        tmp.replace(out_dir / name)
    return out_dir


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
        folder = cache_dir(cfg)
        cache = _load_cache(folder)
        fresh = False
        for day, day_cves in sorted(by_day.items()):
            known = [c for c in day_cves if _cache_key(c, day) in cache]
            then.update({(c, day): v for c in known if (v := cache[_cache_key(c, day)]) is not None})
            day_cves = [c for c in day_cves if _cache_key(c, day) not in cache]
            for i in range(0, len(day_cves), BATCH):
                chunk = day_cves[i:i + BATCH]
                try:
                    got = _epss_scores(get(f"{EPSS_URL}?cve={','.join(chunk)}&date={day.isoformat()}"))
                    then.update({(c, day): got[c] for c in chunk if c in got})
                    cache.update({_cache_key(c, day): got.get(c) for c in chunk})  # None: no score that day
                    fresh = True
                except Exception as err:
                    if not isinstance(err, _Skipped):
                        fail(err)
                    then_snapped.update((c, day) for c in chunk)
                    then.update({(c, day): v for c in chunk
                                 if (v := snap_epss["history"].get(c, {}).get(day.isoformat())) is not None})

        if fresh:
            _save_cache(folder, cache)

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
