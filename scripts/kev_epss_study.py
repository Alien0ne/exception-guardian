"""How low was a CVE's EPSS before CISA added it to KEV?

A risk is often accepted because its EPSS is low. This study takes every CVE CISA added to KEV in the last year
and looks up its EPSS score 30, 90 and 180 days before that date: the scores a team would have seen when it
accepted the risk. Public data only (CISA KEV feed, FIRST EPSS API, which serves past scores by date); read-only.

    python3 scripts/kev_epss_study.py [--end 2026-11-02] [--out docs/evidence]

Writes kev-epss-study.json (every score) and kev-epss-study.md (the summary). A CVE with no EPSS score on a date
(not yet published, or not yet scored) is counted as "not scored" and left out of the percentages.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
OFFSETS = (30, 90, 180)
BATCH = 100
PAUSE = 0.5  # seconds between EPSS calls: be polite to a free API


def kev_in_window(kev: dict, start: date, end: date) -> dict[str, date]:
    out = {}
    for v in kev.get("vulnerabilities", []):
        d = date.fromisoformat(v["dateAdded"])
        if start <= d <= end:
            out[v["cveID"]] = d
    return out


def lookups(added: dict[str, date], offsets) -> dict[date, list[str]]:
    plan: dict[date, list[str]] = defaultdict(list)
    for cve, d in sorted(added.items()):
        for off in offsets:
            plan[d - timedelta(days=off)].append(cve)
    return dict(plan)


def fetch_scores(added, offsets, get, sleep=time.sleep) -> dict[tuple[str, int], float]:
    """EPSS per (cve, offset). One call per date and batch of 100 CVEs."""
    scores: dict[tuple[str, int], float] = {}
    for off in offsets:
        by_day: dict[date, list[str]] = defaultdict(list)
        for cve, d in added.items():
            by_day[d - timedelta(days=off)].append(cve)
        for day, cves in sorted(by_day.items()):
            for i in range(0, len(cves), BATCH):
                part = cves[i:i + BATCH]
                data = get(EPSS_URL, {"cve": ",".join(part), "date": day.isoformat()})
                for row in data.get("data") or []:
                    scores[(row["cve"], off)] = float(row["epss"])
                sleep(PAUSE)
    return scores


def summarize(added, scores, offsets) -> dict[int, dict]:
    out = {}
    for off in offsets:
        vals = [scores[(c, off)] for c in added if (c, off) in scores]
        out[off] = {"total": len(added), "scored": len(vals), "not_scored": len(added) - len(vals),
                    "below_0.01": sum(v < 0.01 for v in vals), "below_0.1": sum(v < 0.1 for v in vals),
                    "below_0.5": sum(v < 0.5 for v in vals),
                    "median": round(statistics.median(vals), 5) if vals else None}
    return out


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}%" if d else "n/a"


def render(summary: dict[int, dict], start: date, end: date, kev_version: str, fetched: str) -> str:
    lines = ["# How low was EPSS before a CVE was added to CISA KEV?", "",
             f"Every CVE CISA added to KEV from {start} to {end}, with its FIRST EPSS score on the day 30, 90 and "
             "180 days before it was added: the score a team would have seen when it accepted the risk.", "",
             "| Days before KEV | CVEs scored | EPSS below 0.01 | below 0.1 | below 0.5 | median EPSS |",
             "|---|---|---|---|---|---|"]
    for off, s in summary.items():
        n = s["scored"]
        lines.append(f"| {off} | {n} of {s['total']} | {s['below_0.01']} ({_pct(s['below_0.01'], n)}) | "
                     f"{s['below_0.1']} ({_pct(s['below_0.1'], n)}) | {s['below_0.5']} ({_pct(s['below_0.5'], n)}) | "
                     f"{s['median']} |")
    lines += ["", "A CVE with no score on that day (not yet published or scored) is left out of the percentages.",
              "", f"Sources: CISA KEV catalog version {kev_version}; FIRST EPSS API (`{EPSS_URL}`, `date=` "
              f"parameter). Fetched {fetched}. Re-run: `python3 scripts/kev_epss_study.py --end {end}`.", ""]
    return "\n".join(lines)


def main() -> None:
    import requests
    ap = argparse.ArgumentParser()
    ap.add_argument("--end", default=date.today().isoformat())
    ap.add_argument("--out", default="docs/evidence")
    a = ap.parse_args()
    end = date.fromisoformat(a.end)
    start = end - timedelta(days=365)
    session = requests.Session()
    session.headers["User-Agent"] = "exception-guardian kev-epss-study (github.com/Alien0ne/exception-guardian)"

    def get(url, params=None):
        r = session.get(url, params=params, timeout=60)
        r.raise_for_status()
        return r.json()
    kev = get(KEV_URL)
    added = kev_in_window(kev, start, end)
    scores = fetch_scores(added, OFFSETS, get)
    summary = summarize(added, scores, OFFSETS)
    fetched = date.today().isoformat()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "kev-epss-study.json").write_text(json.dumps({
        "window": [start.isoformat(), end.isoformat()], "kev_catalog_version": kev.get("catalogVersion"),
        "fetched": fetched, "summary": summary,
        "cves": {c: {"kev_added": d.isoformat(), **{f"epss_{o}d_before": scores.get((c, o)) for o in OFFSETS}}
                 for c, d in sorted(added.items())}}, indent=1))
    (out / "kev-epss-study.md").write_text(render(summary, start, end, kev.get("catalogVersion", "?"), fetched))
    print((out / "kev-epss-study.md").read_text())


if __name__ == "__main__":
    main()
