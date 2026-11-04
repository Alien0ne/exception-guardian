"""Exposure without the Exposure:Internet tag: company tags, internet ranges, a host list, Tenable's is_public flag,
and a note when nothing marks any asset internet-facing."""
from datetime import date

from exception_guardian.assets import parse_assets, parse_v3_hosts
from exception_guardian.config import Config, ExposureConfig, load_config
from exception_guardian.exposure import NO_EXPOSURE_NOTE, apply_exposure
from exception_guardian.grading import grade
from exception_guardian.models import RiskException, RuleType

TODAY = date(2026, 11, 2)


def _assets(*rows):
    return parse_assets([{"id": n, "hostname": [n], "ipv4": ips, "fqdn": fq, "tags": [
        {"tag_key": k, "tag_value": v} for k, v in tags]} for n, ips, fq, tags in rows])


def _grade(assets, cfg=Config(offline=True)):
    exc = RiskException(source="t", rule_id="R1", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=(),
                        targets=tuple(a.name for a in assets), original_severity=None, new_severity=None,
                        owner=None, created=date(2026, 10, 1), updated=None, expires=date(2027, 1, 1),
                        justification="", status="enabled", revised_findings=None)
    return {t.code: t for t in grade(exc, assets, {}, cfg, TODAY).triggers}


def test_config_reads_the_exposure_section(tmp_path):
    f = tmp_path / "g.yaml"
    f.write_text("exposure:\n  internet_tags: ['Zone: DMZ', Environment:External]\n"
                 "  internet_ranges: [198.51.100.0/24]\n  internet_hosts_file: hosts.csv\n")
    ex = load_config(f).exposure
    assert ex.internet_tags == ("Zone: DMZ", "Environment:External")
    assert ex.internet_ranges == ("198.51.100.0/24",) and ex.internet_hosts_file == str(tmp_path / "hosts.csv")
    assert load_config("guardian.yaml").exposure.internet_tags == ("Exposure:Internet",)


def test_company_tag_marks_internet_facing_and_names_the_tag():
    a = _assets(("dmz-01", ["10.1.0.5"], [], [("Zone", "DMZ")]))
    out, notes = apply_exposure(a, ExposureConfig(internet_tags=("zone: dmz",)))
    assert out[0].internet_facing and out[0].exposure_reason == "tag Zone:DMZ" and notes == []
    t = _grade(out)
    assert t["INTERNET_FACING"].source == "tag Zone:DMZ: dmz-01"


def test_a_configured_tag_names_itself_as_the_source():
    out, _ = apply_exposure(_assets(("web", ["192.0.2.1"], [], [("Exposure", "Internet")])), ExposureConfig(internet_tags=("Exposure:Internet",)))
    t = _grade(out)
    assert t["INTERNET_FACING"].now == "internet-facing" and t["INTERNET_FACING"].source == "tag Exposure:Internet: web"


def test_a_private_host_behind_nat_is_caught_by_the_host_list(tmp_path):
    hosts = tmp_path / "hosts.csv"
    hosts.write_text("host,source\nshop.example.net,load balancer export 2026-10-30\n")
    a = _assets(("app-7", ["10.2.0.7"], ["shop.example.net"], []))
    out, _ = apply_exposure(a, ExposureConfig(internet_hosts_file=str(hosts)))
    assert out[0].internet_facing
    assert out[0].exposure_reason == "host list hosts.csv (load balancer export 2026-10-30)"


def test_internet_range_marks_assets_inside_it_only():
    a = _assets(("in", ["198.51.100.20"], [], []), ("out", ["10.0.0.1"], [], []))
    out, _ = apply_exposure(a, ExposureConfig(internet_ranges=("198.51.100.0/24",)))
    assert [x.internet_facing for x in out] == [True, False]
    assert out[0].exposure_reason == "internet range 198.51.100.0/24"


def test_bad_range_and_missing_host_list_are_warnings_not_crashes(tmp_path):
    out, notes = apply_exposure(_assets(("a", ["10.0.0.1"], [], [])),
                                ExposureConfig(internet_ranges=("not-a-range",),
                                               internet_hosts_file=str(tmp_path / "nope.csv")))
    assert any("not-a-range" in n for n in notes) and any("nope.csv" in n for n in notes)
    # a bad range is a note, but a configured host list that cannot be read leaves hosts unmarked: the run is partial
    assert not any(n.startswith("source ") for n in notes if "not-a-range" in n)
    assert any(n.startswith("source exposure failed: ") for n in notes if "nope.csv" in n)


def test_no_exposure_note_when_nothing_is_internet_facing():
    out, notes = apply_exposure(_assets(("a", ["10.0.0.1"], [], [])), ExposureConfig())
    assert NO_EXPOSURE_NOTE in notes
    out, notes = apply_exposure(_assets(("w", ["10.0.0.1"], [], [("Exposure", "Internet")])), ExposureConfig(internet_tags=("Exposure:Internet",)))
    assert NO_EXPOSURE_NOTE not in notes
    out, notes = apply_exposure(_assets(("w", ["10.0.0.1"], [], [("Exposure", "Internet")])), ExposureConfig())
    assert NO_EXPOSURE_NOTE in notes  # no tag name is assumed: a company that sets none is told so


def test_tenable_is_public_flag_is_a_review_hint():
    (h,) = parse_v3_hosts([{"id": "1", "name": "cloud-1", "ipv4_addresses": ["10.0.0.8"], "is_public": True}])
    assert h.public_ips == () and h.tenable_public is True and not h.internet_facing
    t = _grade([h])
    assert "INTERNET_FACING" not in t
    assert t["PUBLIC_IP"].now == "Tenable marks it public, but it is not marked internet-facing"


def test_public_ip_and_tenable_flag_together():
    (h,) = parse_v3_hosts([{"id": "1", "name": "c", "ipv4_addresses": ["9.9.9.9"], "is_public": True}])
    assert _grade([h])["PUBLIC_IP"].now == "has a public IP (9.9.9.9) and Tenable marks it public, but it is not marked internet-facing"


def test_find_applies_exposure_and_reports_the_note(tmp_path):
    import json
    from dataclasses import replace
    from exception_guardian.find import run_find
    cfg = replace(load_config("guardian.yaml"), offline=True, exposure=ExposureConfig(internet_tags=("Zone:DMZ",)))
    run_find(cfg, tmp_path, TODAY)   # the sample only uses Exposure:Internet, so nothing is internet-facing now
    d = json.loads((tmp_path / "findings.json").read_text())
    assert NO_EXPOSURE_NOTE in d["warnings"] and d["partial"] is False
    assert not any(t["code"] == "INTERNET_FACING" for f in d["findings"] for t in f["triggers"])
    assert "no asset is marked internet-facing" in (tmp_path / "report.md").read_text()
