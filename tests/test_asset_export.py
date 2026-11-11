"""Tenants past the asset list's 5,000 cap: the bulk asset export returns every host with its tags, so exposure
tags keep working on a big tenant. Before this the extra hosts came from the host search without tags, and
INTERNET_FACING could not fire for them."""
import pytest

from exception_guardian import assets as m
from exception_guardian.report import is_partial
from exception_guardian.tenable_client import TenableVMClient

V2 = {"id": "x1", "network": {"hostnames": ["big-1"], "fqdns": ["big-1.example.com"], "ipv4s": ["8.8.8.8"],
                              "ipv6s": [], "netbios_names": ["BIG1"]},
      "operating_systems": ["Linux"], "tags": [{"uuid": "u", "key": "Exposure", "value": "Internet", "added_by": "x"}]}
V1 = {"id": "x2", "hostnames": [], "netbios_names": ["OLD2"], "fqdns": [], "ipv4s": ["10.0.0.2"], "ipv6s": [],
      "operating_systems": [], "tags": []}


def test_parse_export_reads_both_shapes_with_tags():
    a, b = m.parse_export([V2, V1, {"id": "gone", "timestamps": {"deleted_at": "2026-01-01T00:00:00Z"}},
                           {"id": "term", "terminated_at": "2026-01-01T00:00:00Z"}, {"no": "id"}, "junk"])
    assert (a.id, a.name, a.os, a.tags, a.fqdns) == ("x1", "big-1", "Linux", ("Exposure:Internet",), ("big-1.example.com",))
    assert a.public_ips == ("8.8.8.8",) and a.origin == "hosts"
    assert (b.name, b.tags, b.public_ips) == ("OLD2", (), ())


def _client(script):
    """A client whose _call answers from `script` ({(method, path): reply or [replies]}), recording each call."""
    c = TenableVMClient("https://t.example", "a", "s", sleep=lambda s: c.slept.append(s))
    c.slept, c.calls = [], []

    def call(method, path, **kw):
        c.calls.append((method, path, kw.get("json")))
        r = script[(method, path)]
        r = r.pop(0) if isinstance(r, list) else r
        if isinstance(r, Exception):
            raise r
        return r
    c._call = call
    return c


def test_export_requests_polls_and_reads_every_chunk():
    c = _client({("POST", "/assets/v2/export"): {"export_uuid": "E1"},
                 ("GET", "/assets/export/E1/status"): [{"status": "QUEUED"}, {"status": "PROCESSING", "chunks_available": [2]},
                                                       {"status": "FINISHED", "chunks_available": [2, 1]}],
                 ("GET", "/assets/export/E1/chunks/1"): [[V2]], ("GET", "/assets/export/E1/chunks/2"): [[V1]]})
    rows = c.export_assets()
    assert [r["id"] for r in rows] == ["x1", "x2"] and len(c.slept) == 2
    assert c.calls[0][2]["chunk_size"] == 1000


@pytest.mark.parametrize("status", ["ERROR", "CANCELLED"])
def test_a_failed_export_raises(status):
    c = _client({("POST", "/assets/v2/export"): {"export_uuid": "E1"},
                 ("GET", "/assets/export/E1/status"): {"status": status, "reason": "boom"}})
    with pytest.raises(RuntimeError, match=status):
        c.export_assets()


def test_an_export_that_never_finishes_times_out():
    c = _client({("POST", "/assets/v2/export"): {"export_uuid": "E1"},
                 ("GET", "/assets/export/E1/status"): {"status": "PROCESSING"}})
    with pytest.raises(RuntimeError, match="not finished"):
        c.export_assets(max_wait=30)
    assert sum(c.slept) >= 30


def test_a_hostile_export_id_never_reaches_the_path():
    c = _client({("POST", "/assets/v2/export"): {"export_uuid": "../../rules"}})
    with pytest.raises(RuntimeError, match="export id"):
        c.export_assets()


FULL = ([{"id": f"a{i}", "hostname": [f"h{i}"]} for i in range(5000)], 5000)


def _at_cap(monkeypatch, export):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "a"); monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    monkeypatch.setattr(TenableVMClient, "list_assets_with_total", lambda self: FULL)
    monkeypatch.setattr(TenableVMClient, "list_hosts_v3", lambda self, max_pages=250: ([{"id": "x1", "name": "big-1"}], False))
    monkeypatch.setattr(TenableVMClient, "list_webapps", lambda self: [])
    monkeypatch.setattr(TenableVMClient, "export_assets", export)


def test_at_the_cap_the_export_supplies_tagged_hosts_and_the_run_is_whole(monkeypatch):
    _at_cap(monkeypatch, lambda self: [V2, V1])
    got = {a.id: a for a in m.load_assets({"base_url": "https://t.example"})}
    assert got["x1"].tags == ("Exposure:Internet",) and len(got) == 5002
    assert not is_partial(m.LAST_WARNINGS) and m.LAST_WARNINGS == []


def test_export_failure_at_the_cap_falls_back_and_says_why(monkeypatch):
    def boom(self):
        raise RuntimeError("HTTP 403")
    _at_cap(monkeypatch, boom)
    got = {a.id: a for a in m.load_assets({"base_url": "https://t.example"})}
    assert got["x1"].tags == () and is_partial(m.LAST_WARNINGS)
    assert "asset export failed (RuntimeError: HTTP 403)" in m.LAST_WARNINGS[0]


def test_under_the_cap_no_export_is_started(monkeypatch):
    _at_cap(monkeypatch, lambda self: pytest.fail("export started"))
    monkeypatch.setattr(TenableVMClient, "list_assets_with_total", lambda self: ([{"id": "a1", "hostname": ["h1"]}], 1))
    m.load_assets({"base_url": "https://t.example"})


def test_export_can_be_switched_off(monkeypatch):
    _at_cap(monkeypatch, lambda self: pytest.fail("export started"))
    m.load_assets({"base_url": "https://t.example", "export": False})
    assert is_partial(m.LAST_WARNINGS)


def test_export_always_reads_tags_for_hosts_the_list_leaves_out(monkeypatch):
    _at_cap(monkeypatch, lambda self: [V2])
    monkeypatch.setattr(TenableVMClient, "list_assets_with_total", lambda self: ([{"id": "a1", "hostname": ["h1"]}], 1))
    got = {a.id: a for a in m.load_assets({"base_url": "https://t.example", "export": "always"})}
    assert got["x1"].tags == ("Exposure:Internet",) and m.LAST_WARNINGS == []
