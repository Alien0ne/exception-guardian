from dataclasses import replace
from datetime import date

import pytest

from exception_guardian.config import Config
from exception_guardian.grading import grade
from exception_guardian.models import Grade

EXPECTED = {
    "R-HERO-001": Grade.REVOKE, "R-RAY-002": Grade.REVOKE, "R-CRUSH-003": Grade.REVOKE, "R-OK-004": Grade.OK,
    "R-REVIEW-005": Grade.REVIEW, "R-EXPIRED-006": Grade.REVIEW, "R-INJECT-007": Grade.REVOKE,
    "R-RAISE-008": Grade.OK, "EXCL-001": Grade.REVOKE, "SC-AR-101": Grade.REVIEW, "SC-RR-102": Grade.OK,
    "CSV-Q-201": Grade.REVOKE, "CSV-Q-202": Grade.OK,
}


def test_fixture_set_is_complete(graded):
    assert set(graded) == set(EXPECTED)


@pytest.mark.parametrize("rule_id,expected", sorted(EXPECTED.items()))
def test_expected_grade(graded, rule_id, expected):
    assert graded[rule_id].grade is expected, graded[rule_id].triggers


def test_hero_evidence(graded):
    g = graded["R-HERO-001"]
    codes = {t.code for t in g.triggers}
    assert {"KEV", "EPSS_HIGH", "INTERNET_FACING", "JUSTIFICATION_CONTRADICTED", "NO_EXPIRY", "TOO_OLD"} <= codes
    kev = next(t for t in g.triggers if t.code == "KEV")
    assert kev.then == "not in KEV" and "2026-03-20" in kev.now
    epss = next(t for t in g.triggers if t.code == "EPSS_HIGH")
    assert (epss.then, epss.now) == ("0.00145", "0.96284")
    net = next(t for t in g.triggers if t.code == "INTERNET_FACING")
    assert (net.then, net.now) == ("internal", "internet-facing")


def test_kev_before_acceptance_wording(graded):
    kev = next(t for t in graded["R-CRUSH-003"].triggers if t.code == "KEV")
    assert kev.then == "already in KEV when accepted" and "ransomware use" in kev.now


def test_injection_text_does_not_change_grade(graded):
    """The README says a test proves the injection-style justification changes nothing: grade the same rule with a
    plain justification and compare grade and triggers."""
    from conftest import TODAY, _inputs
    cfg, exceptions, assets, intel = _inputs()
    rule = next(e for e in exceptions if e.rule_id == "R-INJECT-007")
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in rule.justification
    plain = grade(replace(rule, justification="Vendor patch pending"), assets, intel, cfg, TODAY)
    injected = graded["R-INJECT-007"]
    assert injected.grade is plain.grade is Grade.REVOKE
    assert [(t.code, t.then, t.now) for t in injected.triggers] == [(t.code, t.then, t.now) for t in plain.triggers]


def test_unknown_asset_note(graded):
    assert "ASSET_UNKNOWN" in graded["CSV-Q-202"].notes and graded["CSV-Q-202"].grade is Grade.OK


def test_exclusion_only_asset_and_age_triggers(graded):
    g = graded["EXCL-001"]
    assert {t.code for t in g.triggers} <= {"INTERNET_FACING", "ATTACK_PATH", "NO_EXPIRY", "TOO_OLD"}
    assert "no CVE intel" in g.notes


def test_recast_raise_is_ok(graded):
    g = graded["R-RAISE-008"]
    assert g.triggers == () and "recast raises severity, so it hides nothing" in g.notes


def test_expired_still_enabled(graded):
    assert "EXPIRED_STILL_ENABLED" in {t.code for t in graded["R-EXPIRED-006"].triggers}


def test_thresholds_from_config(hero_inputs):
    exc, assets, intel = hero_inputs
    g = grade(exc, assets, intel, Config(offline=True, revoke_epss=0.99), date(2026, 11, 2))
    assert "EPSS_HIGH" not in {t.code for t in g.triggers} and g.grade is Grade.REVOKE  # KEV still fires
    g2 = grade(exc, assets, intel, Config(offline=True, review_max_age_days=1000), date(2026, 11, 2))
    assert "TOO_OLD" not in {t.code for t in g2.triggers}


def test_disabled_rule_is_ok(hero_inputs):
    exc, assets, intel = hero_inputs
    g = grade(replace(exc, status="disabled"), assets, intel, Config(offline=True), date(2026, 11, 2))
    assert g.grade is Grade.OK and g.triggers == () and "rule disabled" in g.notes
