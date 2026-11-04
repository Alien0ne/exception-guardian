"""Code audit (4 Nov 2026): asset context lookups. A failed tag read must not throw away good Tenable One data,
the lookup cap must go to the assets that matter, and a tag read per asset counts the company's own tag names."""
from datetime import date

from exception_guardian.assets import parse_assets
from exception_guardian.context import enrich_context
from exception_guardian.models import RiskException, RuleType


def _exc(rid, targets, status="enabled"):
    return RiskException(source="tenable-vm", rule_id=rid, rule_type=RuleType.ACCEPT, cves=("CVE-2021-44228",),
                         plugin_ids=(), targets=targets, original_severity=None, new_severity=None, owner=None,
                         created=date(2026, 1, 1), updated=None, expires=None, justification="x", status=status,
                         revised_findings=None)


def _assets(n):
    return parse_assets([{"id": f"a{i}", "hostname": [f"h{i}"], "ipv4": [f"10.0.{i // 250}.{i % 250 + 1}"]}
                         for i in range(n)])


class _Client:
    def __init__(self, tags=None, tags_fail=False):
        self.looked, self.tags, self.tags_fail = [], tags or {}, tags_fail

    def asset_context(self, aid):
        self.looked.append(aid)
        return {"acr": 10, "aes": 900, "paths": 3, "critical_paths": 1, "source": "Tenable One inventory"}

    def asset_tags(self, aid):
        if self.tags_fail:
            raise RuntimeError("404 asset not in VM")
        return self.tags.get(aid, [])


def test_a_failed_tag_read_keeps_the_assets_context():
    out, notes = enrich_context(_assets(1), [_exc("r", ("h0",))], _Client(tags_fail=True), 9)
    assert out[0].acr == 10 and out[0].attack_paths == 3 and out[0].critical
    assert any("tag" in n for n in notes)


def test_the_cap_goes_to_specific_enabled_rules_before_blanket_or_disabled_ones():
    assets = _assets(300)
    rules = [_exc("blanket", ("*",)), _exc("off", ("h298",), status="disabled"), _exc("named", ("h299",))]
    c = _Client()
    enrich_context(assets, rules, c, 9, max_lookups=10)
    assert "a299" in c.looked and "a298" not in c.looked and len(c.looked) == 10


def test_a_companys_own_internet_tag_read_per_asset_marks_it_facing():
    c = _Client(tags={"a0": ["Zone : DMZ"]})
    out, _ = enrich_context(_assets(1), [_exc("r", ("h0",))], c, 9, internet_tags=("zone:dmz",))
    assert out[0].internet_facing and out[0].exposure_reason == "tag Zone:DMZ"
