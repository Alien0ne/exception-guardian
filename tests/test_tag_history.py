"""The "then" side of INTERNET_FACING used to be blank on a live tenant: it needed an exposure-since date that only
the samples carry. Tenable records when each tag was added to an asset, so when the exposure tag was added after the
rule was created, the report now says so: the rule was accepted before the asset carried that tag."""
from dataclasses import replace
from datetime import date

from exception_guardian import assets as m
from exception_guardian.config import Config, ExposureConfig
from exception_guardian.context import enrich_context
from exception_guardian.exposure import apply_exposure
from exception_guardian.grading import grade
from exception_guardian.models import RiskException, RuleType
from exception_guardian.tenable_client import TenableVMClient

EX = ExposureConfig(internet_tags=("Exposure:Internet",))


def _rule(created):
    return RiskException(source="tenable-vm", rule_id="R1", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=(),
                         targets=("*",), original_severity=None, new_severity=None, owner="a", created=created,
                         updated=None, expires=date(2027, 1, 1), justification="Accepted by CAB for the internal app",
                         status="enabled", revised_findings=1)


def _then(assets, created=date(2026, 1, 1)):
    g = grade(_rule(created), assets, {}, Config(), date(2026, 11, 2))
    return next(t for t in g.triggers if t.code == "INTERNET_FACING").then


def test_the_asset_list_and_the_export_keep_when_each_tag_was_added():
    a = m.parse_assets([{"id": "1", "hostname": ["h"], "tags": [
        {"tag_key": "Exposure", "tag_value": "Internet", "added_at": "2026-06-01T10:00:00.000Z"},
        {"tag_key": "App", "tag_value": "X", "added_at": "garbage"}, {"tag_key": "Old", "tag_value": "Y"}]}])[0]
    assert a.tag_dates == (("Exposure:Internet", date(2026, 6, 1)),)
    b = m.parse_export([{"id": "2", "tags": [{"key": "Exposure", "value": "Internet", "added_at": "2026-07-02T00:00:00Z"}]}])[0]
    assert b.tag_dates == (("Exposure:Internet", date(2026, 7, 2)),)


def test_a_tag_added_after_the_rule_gives_the_then_side():
    a = m.parse_assets([{"id": "1", "hostname": ["h"], "tags": [
        {"tag_key": "exposure", "tag_value": "internet", "added_at": "2026-06-01T10:00:00.000Z"}]}])
    facing, _ = apply_exposure(a, EX)
    assert facing[0].internet_facing and facing[0].exposure_tag_since == date(2026, 6, 1)
    assert _then(facing) == "not tagged internet-facing until 2026-06-01"


def test_a_tag_older_than_the_rule_or_undated_leaves_then_blank():
    a = m.parse_assets([{"id": "1", "hostname": ["h"], "tags": [
        {"tag_key": "Exposure", "tag_value": "Internet", "added_at": "2025-06-01T10:00:00.000Z"}]}])
    assert _then(apply_exposure(a, EX)[0]) is None
    b = m.parse_assets([{"id": "1", "hostname": ["h"], "tags": [{"tag_key": "Exposure", "tag_value": "Internet"}]}])
    assert _then(apply_exposure(b, EX)[0]) is None


def test_every_facing_asset_must_be_newly_tagged_and_the_earliest_date_is_shown():
    rows = [{"id": str(i), "hostname": [f"h{i}"], "tags": [{"tag_key": "Exposure", "tag_value": "Internet", "added_at": d}]}
            for i, d in enumerate(["2026-06-01T00:00:00Z", "2026-03-05T00:00:00Z"])]
    assert _then(apply_exposure(m.parse_assets(rows), EX)[0]) == "not tagged internet-facing until 2026-03-05"
    rows[1]["tags"][0]["added_at"] = "2025-03-05T00:00:00Z"
    assert _then(apply_exposure(m.parse_assets(rows), EX)[0]) is None


def test_an_exposure_since_date_still_reads_internal():
    a = replace(apply_exposure(m.parse_assets([{"id": "1", "hostname": ["h"], "x_exposure_since": "2026-10-28", "tags": [
        {"tag_key": "Exposure", "tag_value": "Internet", "added_at": "2026-06-01T00:00:00Z"}]}]), EX)[0][0])
    assert _then([a]) == "internal"


def test_exposure_from_a_range_claims_no_tag_date():
    a = m.parse_assets([{"id": "1", "hostname": ["h"], "ipv4": ["8.8.8.8"], "tags": [
        {"tag_key": "App", "tag_value": "X", "added_at": "2026-06-01T00:00:00Z"}]}])
    facing, _ = apply_exposure(a, ExposureConfig(internet_ranges=("8.8.8.0/24",)))
    assert facing[0].internet_facing and facing[0].exposure_tag_since is None and _then(facing) is None


def test_tags_read_from_the_single_asset_record_carry_their_dates(monkeypatch):
    c = TenableVMClient("https://t.example", "a", "s")
    c._call = lambda method, path, **kw: {"info": {"tags": [
        {"tag_key": "Exposure", "tag_value": "Internet", "added_at": "2026-06-01T10:00:00.000Z"}]}}
    c.asset_context = lambda aid: None
    tags = c.asset_tags("1")
    assert tags == ["Exposure:Internet"] and tags.added == {"Exposure:Internet": date(2026, 6, 1)}
    bare = m.parse_assets([{"id": "1", "hostname": ["h"]}])
    out, _ = enrich_context(bare, [_rule(date(2026, 1, 1))], c, 9, 10, ("Exposure:Internet",))
    assert out[0].internet_facing and out[0].exposure_tag_since == date(2026, 6, 1)
    assert _then(out) == "not tagged internet-facing until 2026-06-01"
