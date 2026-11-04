"""Two weak rules seen on a real tenant (4 Nov 2026): an accept with no reason at all, and an accept that covers
every asset. Neither is proof of risk on its own, so both are REVIEW: a person should look."""
from datetime import date

import pytest

from exception_guardian.config import Config
from exception_guardian.grading import grade
from exception_guardian.models import Asset, Grade, RiskException, RuleType

TODAY = date(2026, 11, 4)


def _exc(**kw):
    base = dict(source="tenable-vm", rule_id="R1", rule_type=RuleType.ACCEPT, cves=(), plugin_ids=("132101",),
                targets=("h1",), original_severity=None, new_severity=None, owner=None, created=date(2026, 11, 1),
                updated=None, expires=date(2026, 12, 1), justification="Patch due in the November window",
                status="enabled", revised_findings=None)
    return RiskException(**{**base, **kw})


def _a(name="h1"):
    return Asset(id=name, name=name, os=None, ips=("10.1.1.1",), fqdns=(), tags=(), internet_facing=False,
                 exposure_since=None, critical=None, on_attack_path=None)


def _codes(exc):
    g = grade(exc, [_a(), _a("h2")], {}, Config(offline=True), TODAY)
    return g, {t.code: t for t in g.triggers}


def test_a_clean_rule_fires_neither():
    g, codes = _codes(_exc())
    assert g.grade is Grade.OK and not {"NO_JUSTIFICATION", "BLANKET"} & set(codes)


@pytest.mark.parametrize("reason", ["", "   ", "-", "n/a", "N/A", "none", "TBD", "todo", "test", "...", "x"])
def test_a_rule_with_no_real_reason_is_reviewed(reason):
    g, codes = _codes(_exc(justification=reason))
    t = codes["NO_JUSTIFICATION"]
    assert g.grade is Grade.REVIEW and t.grade is Grade.REVIEW
    assert t.now == "no reason given" and t.source == "rule metadata"


@pytest.mark.parametrize("reason", ["Lab", "Temporary", "Accepted by CAB", "Vendor patch pending"])
def test_a_short_real_reason_is_not_flagged(reason):
    assert "NO_JUSTIFICATION" not in _codes(_exc(justification=reason))[1]


def test_a_rule_on_every_asset_is_reviewed_and_says_how_many_it_covers():
    g, codes = _codes(_exc(targets=("*",)))
    t = codes["BLANKET"]
    assert g.grade is Grade.REVIEW and t.grade is Grade.REVIEW
    assert t.now == "every asset (2 today)" and t.source == "rule metadata"


def test_an_all_assets_rule_with_exceptions_carved_out_is_still_blanket():
    assert "BLANKET" in _codes(_exc(targets=("*", "!h2")))[1]


def test_a_rule_on_named_assets_or_a_tag_is_not_blanket():
    for targets in (("h1", "h2"), ("tag:Env:Prod",)):
        assert "BLANKET" not in _codes(_exc(targets=targets))[1]


def test_the_real_example_fires_both():
    """'Example blanket accept': plugin 132101 on all assets, a 7-day expiry, no description and no comment."""
    g, codes = _codes(_exc(targets=("*",), justification=""))
    assert {"NO_JUSTIFICATION", "BLANKET"} <= set(codes) and g.grade is Grade.REVIEW


def test_both_apply_to_scan_exclusions_too():
    _, codes = _codes(_exc(rule_type=RuleType.EXCLUSION, targets=("*",), justification=""))
    assert {"NO_JUSTIFICATION", "BLANKET"} <= set(codes)


def test_neither_can_make_a_revoke_on_its_own():
    g, _ = _codes(_exc(targets=("*",), justification=""))
    assert g.grade is not Grade.REVOKE
