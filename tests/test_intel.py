from datetime import date

import pytest

from exception_guardian.config import Config
from exception_guardian.intel import build_intel


def test_offline_uses_snapshot_values():
    cfg = Config(offline=True)
    intel, warn = build_intel({"CVE-2025-54068": [date(2025, 9, 1)]}, cfg, fetch=lambda u: pytest.fail("network"))
    i = intel[("CVE-2025-54068", date(2025, 9, 1))]
    assert i.in_kev and i.kev_date_added == date(2026, 3, 20)
    assert i.epss_now == 0.96284 and i.epss_at_created == 0.00145 and i.source == "snapshot:2026-11-02"
    assert warn == []


def test_live_failure_falls_back_with_warning():
    def boom(url): raise ConnectionError("down")
    intel, warn = build_intel({"CVE-2025-54068": [date(2025, 9, 1)]}, Config(), fetch=boom)
    assert intel[("CVE-2025-54068", date(2025, 9, 1))].source == "snapshot:2026-11-02"
    assert "so the snapshot from 2026-11-02 is used" in warn[0]


def test_live_partial_failure_marks_only_affected():
    def half(url):
        if "date=" in url: raise TimeoutError("slow")
        if "cisa" in url: return {"vulnerabilities": []}
        return {"data": [{"cve": "CVE-1", "epss": "0.70"}]}
    intel, warn = build_intel({"CVE-1": [date(2025, 1, 1)]}, Config(), fetch=half)
    i = intel[("CVE-1", date(2025, 1, 1))]
    # only the value at acceptance came from the snapshot: KEV and today's EPSS stay labelled live
    assert i.epss_now == 0.70 and i.source == "live" and i.epss_then_source == "snapshot:2026-11-02" and warn


def test_after_a_connection_error_no_more_live_requests_are_tried():
    calls = []

    def down(url):
        calls.append(url)
        if len(calls) > 50:
            raise AssertionError("still fetching")  # bounded: never loops
        raise ConnectionError("no route to host")
    created = {f"CVE-2025-{i:05d}": [date(2025, 1, 1 + i % 28)] for i in range(250)}
    intel, warn = build_intel(created, Config(), fetch=down)
    assert len(calls) == 1 and len(warn) == 1
    assert all(v.source.startswith("snapshot:") for v in intel.values())


def test_an_http_error_on_one_batch_does_not_stop_the_others():
    calls = []

    def flaky(url):
        calls.append(url)
        if "cisa" in url: return {"vulnerabilities": []}
        if len(calls) == 2: raise ValueError("HTTP 500")
        return {"data": []}
    build_intel({f"CVE-2025-{i:05d}": [] for i in range(150)}, Config(), fetch=flaky)
    assert len(calls) == 3


def test_epss_trigger_names_a_snapshot_value_at_acceptance():
    from exception_guardian.models import CveIntel
    i = CveIntel("CVE-1", False, None, False, 0.9, 0.01, "live", epss_then_source="snapshot:2026-11-02")
    from exception_guardian.grading import epss_source
    assert epss_source(i) == "FIRST EPSS (live, value at acceptance from snapshot:2026-11-02)"
    assert epss_source(CveIntel("CVE-1", False, None, False, 0.9, 0.01, "live")) == "FIRST EPSS (live)"


def test_live_success_marks_live():
    def fake(url):
        if "cisa" in url: return {"vulnerabilities": [{"cveID": "CVE-1", "dateAdded": "2026-01-01", "knownRansomwareCampaignUse": "Known"}]}
        if "date=" in url: return {"data": [{"cve": "CVE-1", "epss": "0.01"}]}
        return {"data": [{"cve": "CVE-1", "epss": "0.70"}]}
    intel, _ = build_intel({"CVE-1": [date(2025, 1, 1)]}, Config(), fetch=fake)
    i = intel[("CVE-1", date(2025, 1, 1))]
    assert (i.in_kev, i.kev_ransomware, i.epss_now, i.epss_at_created, i.source) == (True, True, 0.70, 0.01, "live")


def test_epss_now_batched_by_100():
    urls = []
    def fake(url):
        urls.append(url)
        return {"vulnerabilities": []} if "cisa" in url else {"data": []}
    build_intel({f"CVE-2025-{i:05d}": [] for i in range(150)}, Config(), fetch=fake)
    now_calls = [u for u in urls if "first.org" in u and "date=" not in u]
    assert len(now_calls) == 2


def test_unknown_cve_not_in_snapshot():
    intel, _ = build_intel({"CVE-1999-0001": [date(2025, 1, 1)]}, Config(offline=True))
    i = intel[("CVE-1999-0001", date(2025, 1, 1))]
    assert not i.in_kev and i.epss_now is None


def test_failure_on_second_date_marks_only_that_value_at_acceptance():
    def fake(url):
        if "cisa" in url: return {"vulnerabilities": []}
        if "date=2025-02-02" in url: raise TimeoutError("slow")
        return {"data": [{"cve": "CVE-1", "epss": "0.10"}]}
    intel, _ = build_intel({"CVE-1": [date(2025, 1, 1), date(2025, 2, 2)]}, Config(), fetch=fake)
    assert {i.source for i in intel.values()} == {"live"}
    assert intel[("CVE-1", date(2025, 1, 1))].epss_then_source is None
    assert intel[("CVE-1", date(2025, 2, 2))].epss_then_source == "snapshot:2026-11-02"


def test_a_rule_accepted_after_firsts_latest_scores_uses_the_latest_score():
    """A live run: rules created that day asked FIRST for date=2026-11-04, and FIRST answers 422 for a
    day it has not published yet. The score at acceptance is then the latest score, with no history request."""
    urls = []

    def fake(url):
        urls.append(url)
        if "cisa" in url: return {"vulnerabilities": []}
        if "date=2026-11-04" in url: raise RuntimeError("422 Client Error")
        if "date=" in url: return {"data": [{"cve": "CVE-1", "epss": "0.01", "date": "2026-10-01"}]}
        return {"data": [{"cve": "CVE-1", "epss": "0.70", "date": "2026-11-03"}]}
    intel, warn = build_intel({"CVE-1": [date(2026, 11, 4), date(2026, 10, 1)]}, Config(), fetch=fake)
    assert warn == [] and not any("date=2026-11-04" in u for u in urls)
    assert intel[("CVE-1", date(2026, 11, 4))].epss_at_created == 0.70
    assert intel[("CVE-1", date(2026, 11, 4))].source == "live"
    assert intel[("CVE-1", date(2026, 10, 1))].epss_at_created == 0.01
