"""Fixes from the 3 Nov quality review of the Tenable-side code."""
from datetime import date

import pytest

from exception_guardian.models import Asset, RiskException, RuleType
from exception_guardian.report import is_partial


def _exc(**kw):
    base = dict(source="tenable-vm", rule_id="R1", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=("12345",),
                targets=("h1",), original_severity=None, new_severity=None, owner=None, created=date(2026, 10, 1),
                updated=None, expires=None, justification="", status="enabled", revised_findings=None)
    return RiskException(**{**base, **kw})


def _a(name="h1"):
    return Asset(id=name, name=name, os=None, ips=("10.1.1.1",), fqdns=(), tags=(), internet_facing=False,
                 exposure_since=None, critical=None, on_attack_path=None)


def test_a_failed_plugin_cve_lookup_marks_the_run_partial():
    from exception_guardian.readers import enrich_plugin_cves

    def boom(pid):
        raise RuntimeError("HTTP 503")
    _, warn = enrich_plugin_cves([_exc()], boom)
    assert is_partial(warn) and "12345" in warn[0]


def test_a_rule_with_no_creation_date_is_skipped_not_the_whole_source():
    from exception_guardian.readers import tenable_sc, tenable_vm
    tenable_vm.LAST_WARNINGS.clear()
    good = {"rule_id": "ok", "rule_value": {"action": "ACCEPT"}, "filter": {}, "created_at": "2026-10-01T00:00:00Z"}
    out = tenable_vm.parse_rules([good, {**good, "rule_id": "nodate", "created_at": None},
                                  {**good, "rule_id": "blank", "created_at": ""}])
    assert [r.rule_id for r in out] == ["ok"] and len(tenable_vm.LAST_WARNINGS) == 2
    assert all("missing created date" in w for w in tenable_vm.LAST_WARNINGS)
    tenable_sc.LAST_WARNINGS.clear()
    sc = {"id": "7", "createdTime": "", "plugin": {"id": "1"}, "hostType": "all", "repository": {"id": "1"}}
    assert tenable_sc.parse([sc], RuleType.ACCEPT) == [] and is_partial(tenable_sc.LAST_WARNINGS)


def test_every_context_lookup_failing_marks_the_run_partial():
    from exception_guardian.context import enrich_context

    class Down:
        def asset_context(self, aid):
            raise RuntimeError("HTTP 500")
    _, notes = enrich_context([_a("h1"), _a("h2")], [_exc(targets=("*",))], Down(), critical_acr=9)
    assert is_partial(notes)


def test_context_values_that_are_not_numbers_are_dropped():
    from exception_guardian.context import enrich_context

    class Odd:
        def asset_context(self, aid):
            return {"acr": "9", "aes": True, "paths": 3, "critical_paths": "<img src=x onerror=alert(1)>",
                    "source": "Tenable One inventory"}
    out, _ = enrich_context([_a()], [_exc(targets=("*",))], Odd(), critical_acr=9)
    assert (out[0].acr, out[0].aes, out[0].attack_paths, out[0].critical_paths) == (9.0, None, 3, None)


def test_a_failed_attack_path_read_is_partial_but_no_tenable_one_is_not():
    from exception_guardian.attack_paths import load_paths

    class Fails:
        def attack_paths(self, *a, **k):
            raise RuntimeError("HTTP 500")

    class NoOne:
        def attack_paths(self, *a, **k):
            return None
    assert is_partial(load_paths({"base_url": "x"}, Fails())[1])
    assert not is_partial(load_paths({"base_url": "x"}, NoOne())[1])


def test_one_bad_internet_scan_record_rejects_that_claim_only():
    from exception_guardian.exposure_claims import verify_claims
    findings = {"findings": [{"assets": [{"id": "a1", "name": "web-01", "ips": ["9.9.9.9"], "fqdns": [],
                                          "internet_facing": False}]}]}

    def scan(ip):
        return {"ip_str": ip, "ports": [443], "last_update": ""}
    claims = [{"asset_id": "a1", "kind": "internet_scan", "value": "9.9.9.9", "source": "Shodan"}]
    try:
        v, _, rej = verify_claims(claims, findings, date(2026, 11, 3), resolve=lambda n: [], internet_scan=scan)
    except ValueError as exc:
        pytest.fail(f"crashed: {exc}")
    assert v == [] and len(rej) == 1


def test_two_security_center_sources_are_refused_with_a_reason(tmp_path):
    from exception_guardian.config import load_config
    p = tmp_path / "g.yaml"
    p.write_text("sources:\n  - name: tenable-sc\n    host: a\n  - name: tenable-sc\n    host: b\n")
    with pytest.raises(ValueError, match="one Security Center source"):
        load_config(str(p))
