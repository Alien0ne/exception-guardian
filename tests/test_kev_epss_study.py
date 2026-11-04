"""The KEV/EPSS study: how low was EPSS before a CVE was added to KEV? Pure parts only; the fetch is injected."""
import importlib.util
from datetime import date
from pathlib import Path

spec = importlib.util.spec_from_file_location("study", Path("scripts/kev_epss_study.py"))
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)

KEV = {"vulnerabilities": [
    {"cveID": "CVE-1", "dateAdded": "2026-06-01"},
    {"cveID": "CVE-2", "dateAdded": "2026-06-01"},
    {"cveID": "CVE-3", "dateAdded": "2026-09-15"},
    {"cveID": "CVE-OLD", "dateAdded": "2024-01-01"},  # outside the window
]}


def test_window_and_lookup_plan():
    added = study.kev_in_window(KEV, date(2025, 11, 3), date(2026, 11, 2))
    assert added == {"CVE-1": date(2026, 6, 1), "CVE-2": date(2026, 6, 1), "CVE-3": date(2026, 9, 15)}
    plan = study.lookups(added, (30, 90))
    assert plan[date(2026, 5, 2)] == ["CVE-1", "CVE-2"] and plan[date(2026, 6, 17)] == ["CVE-3"]
    assert len(plan) == 4


def test_summary_excludes_cves_not_yet_scored():
    added = {"CVE-1": date(2026, 6, 1), "CVE-2": date(2026, 6, 1), "CVE-3": date(2026, 9, 15)}
    scores = {(c, 90): v for c, v in (("CVE-1", 0.004), ("CVE-2", 0.2))}   # CVE-3 had no score yet
    s = study.summarize(added, scores, (90,))[90]
    assert s == {"total": 3, "scored": 2, "not_scored": 1, "below_0.01": 1, "below_0.1": 1, "below_0.5": 2,
                 "median": 0.102}


def test_fetch_batches_and_paces():
    calls = []
    def get(url, params):
        calls.append(params)
        return {"data": [{"cve": c, "epss": "0.5"} for c in params["cve"].split(",")]}
    added = {f"CVE-{i}": date(2026, 6, 1) for i in range(150)}
    got = study.fetch_scores(added, (30,), get=get, sleep=lambda s: None)
    assert len(calls) == 2 and all(len(p["cve"].split(",")) <= 100 for p in calls)
    assert calls[0]["date"] == "2026-05-02" and got[("CVE-0", 30)] == 0.5
