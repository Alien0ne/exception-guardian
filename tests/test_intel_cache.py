"""EPSS on an acceptance date never changes, so it is fetched once and kept on disk. The live run (4 Nov 2026) had
315 rules with their own dates: hundreds of requests on every run, and one timeout dropped them to the snapshot."""
import json
from datetime import date

import pytest
import requests

from exception_guardian import intel as intel_mod
from exception_guardian.config import Config, load_config
from exception_guardian.intel import build_intel

DAY = date(2025, 1, 1)


def _fetch(calls, then="0.01"):
    def fetch(url):
        calls.append(url)
        if "cisa" in url:
            return {"vulnerabilities": []}
        if "date=" in url:
            return {"data": [{"cve": "CVE-1", "epss": then, "date": "2025-01-01"}]}
        return {"data": [{"cve": "CVE-1", "epss": "0.70", "date": "2026-11-01"}]}
    return fetch


def test_second_run_does_not_ask_for_history_again(tmp_path):
    cfg, calls = Config(intel_cache_dir=str(tmp_path)), []
    first, _ = build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls))
    assert sum("date=" in u for u in calls) == 1
    calls.clear()
    second, warn = build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls, then="0.99"))
    assert not any("date=" in u for u in calls) and warn == []
    assert second[("CVE-1", DAY)].epss_at_created == first[("CVE-1", DAY)].epss_at_created == 0.01
    assert second[("CVE-1", DAY)].source == "live" and second[("CVE-1", DAY)].epss_then_source is None


def test_todays_scores_and_kev_are_never_cached(tmp_path):
    cfg, calls = Config(intel_cache_dir=str(tmp_path)), []
    build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls))
    calls.clear()
    build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls))
    assert len(calls) == 2 and "cisa" in calls[0] and "date=" not in calls[1]


def test_a_cve_with_no_score_that_day_is_remembered_too(tmp_path):
    cfg, calls = Config(intel_cache_dir=str(tmp_path)), []
    build_intel({"CVE-1": [DAY], "CVE-2": [DAY]}, cfg, fetch=_fetch(calls))
    calls.clear()
    got, _ = build_intel({"CVE-1": [DAY], "CVE-2": [DAY]}, cfg, fetch=_fetch(calls))
    assert not any("date=" in u for u in calls) and got[("CVE-2", DAY)].epss_at_created is None


def test_only_the_missing_cves_are_asked_for(tmp_path):
    cfg, calls = Config(intel_cache_dir=str(tmp_path)), []
    build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls))
    calls.clear()
    build_intel({"CVE-1": [DAY], "CVE-9": [DAY]}, cfg, fetch=_fetch(calls))
    asked = [u for u in calls if "date=" in u]
    assert len(asked) == 1 and "CVE-9" in asked[0] and "CVE-1" not in asked[0]


def test_a_failed_request_is_not_cached(tmp_path):
    def half(url):
        if "date=" in url: raise TimeoutError("slow")
        return {"vulnerabilities": []} if "cisa" in url else {"data": []}
    cfg, calls = Config(intel_cache_dir=str(tmp_path)), []
    build_intel({"CVE-1": [DAY]}, cfg, fetch=half)
    build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls))
    assert sum("date=" in u for u in calls) == 1


def test_a_broken_cache_file_is_ignored_and_rewritten(tmp_path):
    (tmp_path / "epss-history.json").write_text("{not json")
    cfg, calls = Config(intel_cache_dir=str(tmp_path)), []
    got, warn = build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls))
    assert got[("CVE-1", DAY)].epss_at_created == 0.01 and warn == []
    assert json.loads((tmp_path / "epss-history.json").read_text()) == {"CVE-1|2025-01-01": 0.01}


def test_a_cache_value_that_is_not_a_score_is_asked_for_again(tmp_path):
    (tmp_path / "epss-history.json").write_text(json.dumps({"CVE-1|2025-01-01": "9; rm -rf", "CVE-2|2025-01-01": 7}))
    cfg, calls = Config(intel_cache_dir=str(tmp_path)), []
    got, _ = build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls))
    assert sum("date=" in u for u in calls) == 1 and got[("CVE-1", DAY)].epss_at_created == 0.01


def test_cache_can_be_switched_off(tmp_path, monkeypatch):
    monkeypatch.setenv("EG_CACHE_DIR", str(tmp_path))
    cfg, calls = Config(intel_cache_dir="off"), []
    build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls))
    build_intel({"CVE-1": [DAY]}, cfg, fetch=_fetch(calls))
    assert sum("date=" in u for u in calls) == 2 and not list(tmp_path.iterdir())


def test_default_cache_folder_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("EG_CACHE_DIR", str(tmp_path / "c"))
    build_intel({"CVE-1": [DAY]}, Config(), fetch=_fetch([]))
    assert (tmp_path / "c" / "epss-history.json").is_file()


def test_offline_never_reads_or_writes_the_cache(tmp_path):
    build_intel({"CVE-2025-54068": [date(2025, 9, 1)]}, Config(offline=True, intel_cache_dir=str(tmp_path)),
                fetch=lambda u: pytest.fail("network"))
    assert not list(tmp_path.iterdir())


def test_config_key_is_read(tmp_path):
    p = tmp_path / "g.yaml"
    p.write_text("intel_cache_dir: /somewhere/cache\n")
    assert load_config(p).intel_cache_dir == "/somewhere/cache"


class _Resp:
    def __init__(self, code, headers=None):
        self.status_code, self.headers = code, headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")

    def json(self):
        return {"ok": True}


def test_live_get_retries_a_busy_server_then_succeeds(monkeypatch):
    seen, slept = [], []
    replies = [_Resp(429, {"Retry-After": "2"}), _Resp(503), _Resp(200)]
    monkeypatch.setattr(requests, "get", lambda url, timeout: seen.append(url) or replies[len(seen) - 1])
    monkeypatch.setattr(intel_mod, "_sleep", slept.append)
    assert intel_mod._http_get("https://x.example") == {"ok": True}
    assert len(seen) == 3 and slept == [2.0, 3.0]


def test_live_get_gives_up_after_three_tries(monkeypatch):
    seen = []
    monkeypatch.setattr(requests, "get", lambda url, timeout: seen.append(url) or _Resp(500))
    monkeypatch.setattr(intel_mod, "_sleep", lambda s: None)
    with pytest.raises(requests.HTTPError):
        intel_mod._http_get("https://x.example")
    assert len(seen) == 3


def test_live_get_does_not_retry_when_the_network_is_down(monkeypatch):
    seen = []

    def down(url, timeout):
        seen.append(url)
        raise requests.ConnectionError("no route")
    monkeypatch.setattr(requests, "get", down)
    monkeypatch.setattr(intel_mod, "_sleep", lambda s: pytest.fail("waited"))
    with pytest.raises(requests.ConnectionError):
        intel_mod._http_get("https://x.example")
    assert len(seen) == 1


def test_a_long_retry_after_is_capped(monkeypatch):
    slept, n = [], []
    monkeypatch.setattr(requests, "get", lambda url, timeout: n.append(1) or (_Resp(429, {"Retry-After": "86400"}) if len(n) == 1 else _Resp(200)))
    monkeypatch.setattr(intel_mod, "_sleep", slept.append)
    intel_mod._http_get("https://x.example")
    assert slept == [30.0]
