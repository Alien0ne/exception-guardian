"""NEW_ASSETS: a rule keeps matching hosts that did not exist (as far as Tenable knew) when the risk was accepted.
Nobody accepted the risk for those hosts. Tenable records the day it first saw each asset; a covered asset first
seen after the rule was created fires this REVIEW trigger."""
import json
from datetime import date

from exception_guardian import assets as m
from exception_guardian.approval import _review_action
from exception_guardian.cli import main
from exception_guardian.config import Config
from exception_guardian.grading import grade, review_tier
from exception_guardian.models import RiskException, RuleType
from exception_guardian.tenable_client import TenableVMClient

TODAY = date(2026, 11, 2)


def _rule(targets=("web-*",), created=date(2026, 3, 1)):
    return RiskException(source="tenable-vm", rule_id="R1", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=(),
                         targets=targets, original_severity=None, new_severity=None, owner="a", created=created,
                         updated=None, expires=date(2027, 1, 1), justification="Accepted by CAB for the web tier",
                         status="enabled", revised_findings=1)


def _hosts(*days, prefix="web-"):
    return m.parse_assets([{"id": str(i), "hostname": [f"{prefix}{i}"], **({"first_seen": d} if d else {})}
                           for i, d in enumerate(days, 1)])


def _trigger(g):
    return next((t for t in g.triggers if t.code == "NEW_ASSETS"), None)


def test_every_asset_reader_keeps_the_first_seen_day():
    assert _hosts("2026-06-01T10:00:00.000Z")[0].first_seen == date(2026, 6, 1)
    assert _hosts(None)[0].first_seen is None and _hosts("garbage")[0].first_seen is None
    v2, v1 = m.parse_export([{"id": "x1", "timestamps": {"first_seen": "2025-02-03T00:00:00Z"}},
                             {"id": "x2", "first_seen": "2026-07-08T00:00:00Z"}])
    assert (v2.first_seen, v1.first_seen) == (date(2025, 2, 3), date(2026, 7, 8))
    assert m.parse_v3_hosts([{"id": "h", "name": "h", "first_observed": "2026-09-09T01:02:03.000Z"}])[0].first_seen \
        == date(2026, 9, 9)


def test_assets_first_seen_after_the_rule_fire_a_review_trigger():
    g = grade(_rule(), _hosts("2025-01-10T00:00:00Z", "2026-02-28T00:00:00Z", "2026-06-01T00:00:00Z",
                              "2026-10-20T00:00:00Z"), {}, Config(), TODAY)
    t = _trigger(g)
    assert (t.grade.name, t.then) == ("REVIEW", "covered 2 assets")
    assert t.now == "covers 4: 2 first seen since (latest 2026-10-20)"
    assert t.source == "Tenable first-seen date: web-3, web-4"
    assert g.grade.name == "REVIEW" and review_tier(g) == "now"


def test_one_new_asset_reads_in_the_singular():
    t = _trigger(grade(_rule(), _hosts("2025-01-10T00:00:00Z", "2026-06-01T00:00:00Z"), {}, Config(), TODAY))
    assert (t.then, t.now) == ("covered 1 asset", "covers 2: 1 first seen since (2026-06-01)")


def test_assets_seen_before_or_on_the_day_of_the_rule_do_not_fire():
    g = grade(_rule(), _hosts("2025-01-10T00:00:00Z", "2026-03-01T23:00:00Z"), {}, Config(), TODAY)
    assert _trigger(g) is None and g.grade.name == "OK"


def test_assets_without_a_date_are_counted_out_loud_and_then_is_left_blank():
    t = _trigger(grade(_rule(), _hosts("2026-06-01T00:00:00Z", None, None), {}, Config(), TODAY))
    assert t.then is None
    assert t.now == "covers 3: 1 first seen since (2026-06-01), 2 with no first-seen date"
    assert _trigger(grade(_rule(), _hosts(None, None), {}, Config(), TODAY)) is None


def test_many_new_assets_are_named_briefly():
    t = _trigger(grade(_rule(), _hosts(*["2026-06-01T00:00:00Z"] * 40), {}, Config(), TODAY))
    assert t.now.startswith("covers 40: 40 first seen since") and len(t.source) < 200 and "more" in t.source


def test_on_a_blanket_rule_new_assets_are_expected_so_it_stays_housekeeping():
    g = grade(_rule(targets=("*",)), _hosts("2025-01-10T00:00:00Z", "2026-06-01T00:00:00Z"), {}, Config(), TODAY)
    assert _trigger(g) is not None and {t.code for t in g.triggers} >= {"BLANKET", "NEW_ASSETS"}
    assert review_tier(g) == "housekeeping"


def test_the_review_plan_tells_the_owner_what_to_do():
    line = _review_action({"code": "NEW_ASSETS", "then": "covered 2 assets", "now": "covers 4: 2 first seen since"})
    assert line == "covers 4: 2 first seen since: confirm the acceptance was meant to cover them, or narrow the rule"


def test_a_live_read_fills_first_seen_for_listed_hosts_from_the_host_search(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "a")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    monkeypatch.setattr(TenableVMClient, "list_assets_with_total",
                        lambda self: ([{"id": "a1", "hostname": ["h1"]}, {"id": "a2", "hostname": ["h2"]}], 2))
    monkeypatch.setattr(TenableVMClient, "list_hosts_v3", lambda self, max_pages=250: ([
        {"id": "a1", "name": "h1", "first_observed": "2026-05-05T00:00:00Z"},
        {"id": "x9", "name": "h9", "first_observed": "2026-06-06T00:00:00Z"}], False))
    monkeypatch.setattr(TenableVMClient, "list_webapps", lambda self: [])
    got = {a.id: a for a in m.load_assets({"base_url": "https://t.example"})}
    assert got["a1"].first_seen == date(2026, 5, 5) and got["a1"].origin == "hosts"
    assert got["a2"].first_seen is None and got["x9"].first_seen == date(2026, 6, 6)


def test_the_sample_run_shows_the_trigger_end_to_end(tmp_path):
    assert main(["find", "--offline", "--out", str(tmp_path), "--today", "2026-11-02"]) == 0
    d = json.loads((tmp_path / "findings.json").read_text())
    hit = [f for f in d["findings"] if any(t["code"] == "NEW_ASSETS" for t in f["triggers"])]
    assert hit and all(a.get("first_seen") for f in hit for a in f["assets"][:1])
    assert "NEW_ASSETS" in (tmp_path / "report.md").read_text()


def test_a_rule_whose_every_asset_is_new_says_so():
    t = _trigger(grade(_rule(), _hosts("2026-06-01T00:00:00Z"), {}, Config(), TODAY))
    assert t.then == "covered no asset Tenable had seen yet"
